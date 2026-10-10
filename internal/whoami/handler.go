package whoami

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"whoami/internal/web"
)

// 页面渲染需要的模板集合。新增页面只要往这里加一个文件。
var templateFiles = []string{"templates/index.html.tmpl", "templates/stats.html.tmpl"}

type staticAsset struct {
	data []byte
	etag string
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	s.mux.HandleFunc("GET /api/whoami", s.handleAPI)
	s.mux.HandleFunc("POST /api/whoami", s.handleReportJSON)
	s.mux.HandleFunc("POST /report", s.handleReportFragment)
	s.mux.HandleFunc("GET /static/", s.handleStatic)
	s.mux.HandleFunc("GET /api/rules", s.handleRules)
	s.mux.HandleFunc("GET /stats", s.handleStats)
	s.mux.HandleFunc("GET /api/stats", s.handleStatsAPI)
	s.mux.HandleFunc("GET /api/record/{id}", s.handleRecord)
}

// record 落一条访问日志并计入统计。日志里的地址按配置脱敏，
// 页面上访客仍然看到自己的真实 IP。
func (s *Server) record(kind string, res Result) {
	rec := LogRecord{Kind: kind, Result: res}
	rec.Client.IP = AnonymizeIP(res.Client.addr, s.cfg.AnonymizeIP, s.anonSalt)
	if err := s.log.Write(rec); err != nil {
		slog.Warn("access log write failed", "err", err, "id", res.ID)
	}
	s.stats.Observe(rec)
	s.remember(res)
}

// maxRecentRecords 限制按 ID 反查的缓存条数：结果约 3–8KB，
// 512 条约几 MB 封顶，够排障回溯又不会随流量增长。
const maxRecentRecords = 512

// remember 保存最近的结果供 /api/record/{id} 反查，FIFO 淘汰最旧的。
func (s *Server) remember(res Result) {
	s.recentMu.Lock()
	defer s.recentMu.Unlock()
	if s.recent == nil {
		s.recent = make(map[string]Result, 64)
	}
	if _, dup := s.recent[res.ID]; !dup {
		s.recentKeys = append(s.recentKeys, res.ID)
	}
	s.recent[res.ID] = res
	for len(s.recentKeys) > maxRecentRecords {
		delete(s.recent, s.recentKeys[0])
		s.recentKeys = s.recentKeys[1:]
	}
}

// handleRecord 按页面页脚展示的记录 ID 反查完整结果，供工单里回溯一次检测。
func (s *Server) handleRecord(w http.ResponseWriter, r *http.Request) {
	s.securityHeaders(w)
	s.recentMu.Lock()
	res, ok := s.recent[r.PathValue("id")]
	s.recentMu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "记录不存在或已超出缓存范围"})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleRules 导出当前真正生效的规则表：内置 + 外部覆盖后的结果。
// 补 token 前先在这里看清结构和字段，不用读源码。
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	s.securityHeaders(w)
	writeJSON(w, http.StatusOK, map[string]any{
		"source": s.rulesFrom,
		"rules":  s.detector.Rules(),
	})
}

func (s *Server) statsView() StatsView {
	return s.stats.Snapshot(s.log.Dir())
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeStats(w, r) {
		return
	}
	s.securityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.tmpl.ExecuteTemplate(w, "stats.html.tmpl", s.statsView()); err != nil {
		slog.Error("render stats failed", "err", err)
	}
}

func (s *Server) handleStatsAPI(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeStats(w, r) {
		return
	}
	s.securityHeaders(w)
	writeJSON(w, http.StatusOK, s.statsView())
}

// 统计接口的限流参数：每 IP 每分钟 60 次，够人正常刷新页面，
// 又能把脚本扫目录或刷爆统计的代价抬高。
const (
	statsRateLimit  = 60
	statsRateWindow = time.Minute
)

// authorizeStats 守住 /stats 与 /api/stats：配了 token 必须出示
// （?token= 或 X-Stats-Token 头），并按客户端 IP 限流。
// 未配 token 时限流仍然生效，避免默认部署下统计页被无差别抓取。
func (s *Server) authorizeStats(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.StatsToken != "" {
		got := r.URL.Query().Get("token")
		if got == "" {
			got = r.Header.Get("X-Stats-Token")
		}
		if got != s.cfg.StatsToken {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "stats token 无效"})
			return false
		}
	}
	ip, _ := ResolveClientIP(r, s.trusted)
	if !s.statsRL.allow(ip.IP, time.Now()) {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "请求过于频繁"})
		return false
	}
	return true
}

// rateLimiter 是按 key 的固定窗口限流器，只服务统计接口这一个低频场景。
type rateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string]*rlEntry
}

type rlEntry struct {
	count int
	reset time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, entries: map[string]*rlEntry{}}
}

func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	// key 来自客户端地址，条目数必须封顶：超限时整体重开窗口，
	// 宁可放行一个窗口，也不让伪造地址把内存吃光。
	if len(l.entries) > 4096 {
		l.entries = map[string]*rlEntry{}
	}
	e := l.entries[key]
	if e == nil || now.After(e.reset) {
		l.entries[key] = &rlEntry{count: 1, reset: now.Add(l.window)}
		return true
	}
	e.count++
	return e.count <= l.limit
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	res := s.detectRequest(r)
	s.record(KindPage, res)
	view := BuildView(res).applyFraming(framingOf(r))

	s.securityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.tmpl.ExecuteTemplate(w, "index.html.tmpl", view); err != nil {
		slog.Error("render index failed", "err", err, "id", res.ID)
	}
}

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	res := s.detectRequest(r)
	s.record(KindAPI, res)
	s.securityHeaders(w)
	writeJSON(w, http.StatusOK, res)
}

// securityHeaders 只锁「谁能嵌我」，不设 X-Frame-Options 与 COEP/CORP：
// 前者会被 CSP 取代，后者会让跨源 iframe 直接白屏。
func (s *Server) securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", frameAncestorsDirective(s.ancestors))
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	asset, ok := s.assets[name]
	if !ok || name == "" || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	s.securityHeaders(w)
	w.Header().Set("Content-Type", contentType(name))
	w.Header().Set("ETag", asset.etag)
	// no-cache 而不是 max-age：detect.js 的修正必须立刻到客户端，
	// 否则旧 JS 会在部署后继续跑最长一小时（P0 那类开关丢失就会复现）。
	// 配合 ETag 每次只多一轮 304 协商，没有实际体积代价。
	w.Header().Set("Cache-Control", "no-cache")
	if r.Header.Get("If-None-Match") == asset.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(asset.data)
}

func contentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		return "text/javascript; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

// handleReportJSON 接收浏览器端回报，返回合并后的完整结论。
func (s *Server) handleReportJSON(w http.ResponseWriter, r *http.Request) {
	res, err := s.detectWithReport(w, r)
	if err != nil {
		slog.Warn("client report rejected", "err", err, "remote", r.RemoteAddr)
		writeJSON(w, reportStatus(err), map[string]string{"error": err.Error()})
		return
	}
	s.record(KindReport, res)
	s.securityHeaders(w)
	writeJSON(w, http.StatusOK, res)
}

// handleReportFragment 接收同一份回报，返回渲染好的 HTML 片段。
// 页面拿片段替换 #report，判定文案就仍然只有服务端一套实现。
func (s *Server) handleReportFragment(w http.ResponseWriter, r *http.Request) {
	res, err := s.detectWithReport(w, r)
	if err != nil {
		slog.Warn("client report rejected", "err", err, "remote", r.RemoteAddr)
		http.Error(w, "", reportStatus(err))
		return
	}
	s.record(KindReport, res)
	view := BuildView(res).applyFraming(framingOf(r))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	s.securityHeaders(w)
	if err := s.tmpl.ExecuteTemplate(w, "content", view); err != nil {
		slog.Error("render fragment failed", "err", err, "id", res.ID)
	}
}

// reportStatus 区分「体积超限」和「内容不合法」，两者在 F12 里看的现象不同，
// 状态码也不该混用。
func reportStatus(err error) int {
	var maxBytes *http.MaxBytesError
	if errors.As(err, &maxBytes) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

// detectWithReport 把回报里的客户端信号并入同一套判定管线。
func (s *Server) detectWithReport(w http.ResponseWriter, r *http.Request) (Result, error) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxPostBytes)
	rep, err := DecodeBrowserReport(r.Body)
	if err != nil {
		return Result{}, err
	}
	ss, ev, ip := s.collect(r)
	jsSignals, jsEvidence := rep.signals()
	res := s.detector.Detect(append(ss, jsSignals...), append(ev, jsEvidence...), ip)
	res.ID = NewID()
	res.Browser = rep.facts()
	// 收到回报本身就证明浏览器端跑起来了，即使回报里一个字段都没取到
	// （禁用 CH、禁用 WebGL 的管控环境就是这么回的）。
	res.HasJS = true
	if !containsStr(res.Sources, SourceJS) {
		res.Sources = append(res.Sources, SourceJS)
	}
	// navigator.userAgent 与本次请求头对照：正常情况必然一致，
	// 不一致说明中间有代理改写 UA、或其中一侧被伪造，必须写在结论旁。
	if hua, jsa := strings.TrimSpace(r.Header.Get("User-Agent")), strings.TrimSpace(rep.UserAgent); hua != "" && jsa != "" && hua != jsa {
		res.Verdict.Limits = append(res.Verdict.Limits,
			"浏览器端 UA 与请求头不一致：可能被代理改写或伪造，UA 相关结论需人工核对")
	}
	s.attachGeo(r, &res)
	s.decorate(&res, r)
	return res, nil
}

// detectRequest 是「请求 → 结论」的纯服务端管线，页面、GET JSON 与日志共用。
func (s *Server) detectRequest(r *http.Request) Result {
	ss, ev, ip := s.collect(r)
	res := s.detector.Detect(ss, ev, ip)
	res.ID = NewID()
	s.attachGeo(r, &res)
	s.decorate(&res, r)
	return res
}

// decorate 记录嵌入上下文，统计页按它区分「直接访问」与「iframe 嵌入」。
func (s *Server) decorate(res *Result, r *http.Request) {
	f := framingOf(r)
	res.Embedded = f.Embedded
	res.Host = hostOf(f.Referer)
}

func (s *Server) collect(r *http.Request) (Signals, []Evidence, IPInfo) {
	ss, ev := Collect(r)
	ip, ipEv := ResolveClientIP(r, s.trusted)
	ev = append(ev, ipEv...)

	s.dict.MaybeReload()
	if label, cidr := s.dict.Lookup(ip.addr); label != "" {
		key := "ip.dict"
		ip.Label = label
		ev = append(ev, truncateEvidence(key, cidr+" → "+label, SourceIP))
		ss = append(ss, Signal{Field: FieldIPLabel, Value: label, Source: SourceIP, EvidenceKey: key})
	}

	// 归属信息默认不查：noop provider 在这里一次外呼都不发。
	return ss, ev, ip
}

// attachGeo 把外部归属接口的结果并入结果集，失败只降级不影响主判定。
func (s *Server) attachGeo(r *http.Request, res *Result) {
	if s.geo == nil || !s.geo.Enabled() {
		return
	}
	geo, note := lookupGeo(r.Context(), s.geo, res.Client.addr)
	res.Geo = geo
	res.GeoProvider = s.geo.Name()
	if note != "" {
		res.GeoNote = note
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	// 输出上限 1MiB：正常结果约 3–8KB，超限说明信号集异常，宁可报错也不放大内存。
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		slog.Error("json encode failed", "err", err)
		http.Error(w, `{"error":"encode failed"}`, http.StatusInternalServerError)
		return
	}
	if buf.Len() > 1<<20 {
		http.Error(w, `{"error":"result too large"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, buf.String())
}

// NewID 是每条检测记录的短标识，用于日志排查与访客复现同一次结果。
func NewID() string {
	var b [8]byte
	// crypto/rand 在受支持平台上不会失败。
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func loadTemplates() (*template.Template, error) {
	return template.ParseFS(web.Static, templateFiles...)
}

func loadAssets() (map[string]staticAsset, error) {
	dir, err := fs.ReadDir(web.Static, "static")
	if err != nil {
		return nil, err
	}
	assets := make(map[string]staticAsset, len(dir))
	for _, d := range dir {
		if d.IsDir() {
			continue
		}
		b, err := web.Static.ReadFile("static/" + d.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		assets[d.Name()] = staticAsset{data: b, etag: `"` + hex.EncodeToString(sum[:6]) + `"`}
	}
	return assets, nil
}
