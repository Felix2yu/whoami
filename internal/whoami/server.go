package whoami

import (
	"crypto/rand"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Config 是服务的装配参数，由 cmd/whoami 从 flag/env 填入。
type Config struct {
	// Addr 监听地址。
	Addr string
	// ReadTimeout 等超时按真实量级给：本页只处理小 body 的 JSON 回报，
	// 15s 足够覆盖慢速访客，又能尽快回收连接。
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	// MaxHeaderBytes 上限 64KiB：畸形或超长 UA 也容得下，又不至于被头放大打穿。
	MaxHeaderBytes int
	// MaxPostBytes 是 JS 回报的体积上限，实际 payload 2–4KB。
	MaxPostBytes int64
	// TrustedProxies 是受信反向代理的 CIDR 列表。默认为空 = 不信任任何代理头，
	// 只有直连地址落在这些网段内才会去读 X-Forwarded-For。
	TrustedProxies []string
	// IPDictPath 是访客 IP 归属字典（`CIDR,标签`）的路径，留空表示不标注归属。
	IPDictPath string
	// FrameAncestors 是允许用 iframe 嵌入本页的来源白名单。
	// 留空输出 `frame-ancestors *`：这个页面本来就要嵌进别的页面。
	FrameAncestors []string
	// LogDir 是访问日志目录，留空表示不落盘。
	LogDir string
	// LogKeepDays 是启动时清理超期日志的天数，0 表示不清理。
	LogKeepDays int
	// StatsReplayDays 与 StatsReplayBytes 限定启动回放的范围。
	StatsReplayDays  int
	StatsReplayBytes int64
	// AnonymizeIP 是日志与统计里的地址脱敏方式：off|last-octet|full。
	AnonymizeIP string
	// StatsToken 是 /stats 与 /api/stats 的访问口令，留空表示不校验。
	// 统计页会暴露访客分布，暴露到不可信网络时应配置它。
	StatsToken string
	// RulesPath 是外部规则 JSON 文件路径，同 ID 覆盖内置规则。
	RulesPath string
	// GeoEndpoint 是 IP 归属查询接口，留空表示不外呼。
	// 注意：启用它意味着把访客 IP 交给第三方，默认关闭。
	GeoEndpoint string
	GeoFields   []string
}

func DefaultConfig() Config {
	return Config{
		Addr:              "127.0.0.1:8080",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		MaxPostBytes:      32 << 10,
		LogDir:            "data/logs",
		LogKeepDays:       90,
		StatsReplayDays:   7,
		StatsReplayBytes:  20 << 20,
		AnonymizeIP:       "off",
	}
}

// Server 持有各子模块，实现 http.Handler。
type Server struct {
	cfg       Config
	ancestors []string
	trusted   []*netip.Prefix
	dict      *IPDict
	detector  *Detector
	tmpl      *template.Template
	assets    map[string]staticAsset
	log       *AccessLog
	stats     *Stats
	geo       IPInfoProvider
	rulesFrom RulesSource
	anonSalt  []byte
	statsRL   *rateLimiter

	// recent 缓存最近几条完整结果，供 /api/record/{id} 按 ID 反查。
	// ID 是 crypto/rand 的 16 位十六进制，不可枚举；容量封顶防内存增长。
	recentMu   sync.Mutex
	recent     map[string]Result
	recentKeys []string

	mux *http.ServeMux
}

func NewServer(cfg Config) (*Server, error) {
	trusted, err := ParseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("WHOAMI_TRUSTED_PROXIES: %w", err)
	}
	builtin := BuiltinRules()
	external, err := LoadRules(cfg.RulesPath)
	if err != nil {
		return nil, err
	}
	merged, replaced := mergeRules(builtin, external)
	detector, err := NewDetector(merged)
	if err != nil {
		return nil, fmt.Errorf("规则表无效: %w", err)
	}
	rulesFrom := RulesSource{
		Builtin: len(builtin), External: len(external), Replaced: replaced,
		Total: len(merged), Path: cfg.RulesPath,
	}
	tmpl, err := loadTemplates()
	if err != nil {
		return nil, fmt.Errorf("页面模板无效: %w", err)
	}
	assets, err := loadAssets()
	if err != nil {
		return nil, fmt.Errorf("静态资源无效: %w", err)
	}

	for _, a := range cfg.FrameAncestors {
		if err := ValidFrameAncestor(a); err != nil {
			return nil, fmt.Errorf("WHOAMI_FRAME_ANCESTORS: %w", err)
		}
	}
	switch cfg.AnonymizeIP {
	case "", "off", "last-octet", "full":
	default:
		return nil, fmt.Errorf("WHOAMI_ANONYMIZE_IP=%q 不合法，可选 off|last-octet|full", cfg.AnonymizeIP)
	}

	accessLog, err := NewAccessLog(cfg.LogDir, cfg.LogKeepDays)
	if err != nil {
		return nil, fmt.Errorf("打开日志目录失败: %w", err)
	}
	stats := NewStats()
	if n, err := stats.Replay(accessLog, cfg.StatsReplayDays, cfg.StatsReplayBytes); err != nil {
		slog.Warn("日志回放失败，统计从零开始", "err", err, "dir", accessLog.Dir())
	} else if n > 0 {
		stats.ReplayDone(n)
		slog.Info("stats replayed", "records", n, "days", cfg.StatsReplayDays)
	}

	geo := IPInfoProvider(noopProvider{})
	if cfg.GeoEndpoint != "" {
		g := DefaultGeoConfig()
		g.Endpoint = cfg.GeoEndpoint
		if len(cfg.GeoFields) > 0 {
			g.Fields = cfg.GeoFields
		}
		geo, err = NewHTTPGeoProvider(g)
		if err != nil {
			return nil, fmt.Errorf("WHOAMI_IP_GEO_ENDPOINT: %w", err)
		}
	}

	salt, err := loadOrCreateSalt(cfg.LogDir)
	if err != nil {
		return nil, fmt.Errorf("生成脱敏盐值失败: %w", err)
	}

	s := &Server{
		cfg: cfg, ancestors: cfg.FrameAncestors, trusted: trusted, dict: NewIPDict(cfg.IPDictPath),
		detector: detector, tmpl: tmpl, assets: assets,
		log: accessLog, stats: stats, geo: geo, rulesFrom: rulesFrom, anonSalt: salt,
		statsRL: newRateLimiter(statsRateLimit, statsRateWindow), mux: http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

// loadOrCreateSalt 返回脱敏哈希用的盐。开启日志落盘时把它持久化到日志目录：
// 日志里存的是哈希结果，重启后必须用同一把盐，同一访客才会哈希成同一个标识，
// 否则「独立 IP」计数会跨重启翻倍。未落盘时没有跨重启的真源，每次启动生成即可。
func loadOrCreateSalt(logDir string) ([]byte, error) {
	var salt [16]byte
	if logDir == "" {
		if _, err := rand.Read(salt[:]); err != nil {
			return nil, err
		}
		return salt[:], nil
	}
	path := filepath.Join(logDir, ".anon-salt")
	if b, err := os.ReadFile(path); err == nil && len(b) >= 16 {
		return b[:16], nil
	}
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		// 并发启动时别人先建好了：读它的，保证大家用同一把盐。
		b, err := os.ReadFile(path)
		if err != nil || len(b) < 16 {
			return nil, fmt.Errorf("读取 %s 失败或内容过短", path)
		}
		return b[:16], nil
	}
	defer f.Close()
	if _, err := f.Write(salt[:]); err != nil {
		return nil, err
	}
	return salt[:], nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) Addr() string { return s.cfg.Addr }

// TrustedProxies 返回已解析的受信代理网段数量之外的细节，供启动日志与排障使用。
func (s *Server) TrustedProxies() []*netip.Prefix { return s.trusted }

// RulesSource 说明生效规则表的组成，供启动日志与 /api/rules 使用。
func (s *Server) RulesSource() RulesSource { return s.rulesFrom }

// Stats 暴露统计聚合，供 /stats、/api/stats 与测试使用。
func (s *Server) Stats() *Stats { return s.stats }

// Close 关闭日志文件，进程退出时调用。
func (s *Server) Close() error { return s.log.Close() }

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok\n"))
}

// handleServerInfo 返回服务进程自身的身份信息（主机名/OS/架构/Go 版本/构建信息）。
// 与 /healthz 同口径：开放、无鉴权、不加 CSP 类安全头。
func (s *Server) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.ServerInfo())
}

// HTTPServer 把超时配置落到 http.Server 上。
func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s,
		ReadHeaderTimeout: s.cfg.ReadHeaderTimeout,
		ReadTimeout:       s.cfg.ReadTimeout,
		WriteTimeout:      s.cfg.WriteTimeout,
		IdleTimeout:       s.cfg.IdleTimeout,
		MaxHeaderBytes:    s.cfg.MaxHeaderBytes,
	}
}
