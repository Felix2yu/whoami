package whoami

import (
	"crypto/rand"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
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
	anonSalt  []byte
	mux       *http.ServeMux
}

func NewServer(cfg Config) (*Server, error) {
	trusted, err := ParseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("WHOAMI_TRUSTED_PROXIES: %w", err)
	}
	detector, err := NewDetector(BuiltinRules())
	if err != nil {
		return nil, fmt.Errorf("规则表无效: %w", err)
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

	var salt [8]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, fmt.Errorf("生成脱敏盐值失败: %w", err)
	}

	s := &Server{
		cfg: cfg, ancestors: cfg.FrameAncestors, trusted: trusted, dict: NewIPDict(cfg.IPDictPath),
		detector: detector, tmpl: tmpl, assets: assets,
		log: accessLog, stats: stats, anonSalt: salt[:], mux: http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) Addr() string { return s.cfg.Addr }

// Stats 暴露统计聚合，供 /stats、/api/stats 与测试使用。
func (s *Server) Stats() *Stats { return s.stats }

// Close 关闭日志文件，进程退出时调用。
func (s *Server) Close() error { return s.log.Close() }

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok\n"))
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
