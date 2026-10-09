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

	"whoami/internal/web"
)

// 页面渲染需要的模板集合。新增页面只要往这里加一个文件。
var templateFiles = []string{"templates/index.html.tmpl"}

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
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	res := s.detectRequest(r)
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
	w.Header().Set("Cache-Control", "public, max-age=3600")
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
	s.decorate(&res, r)
	return res, nil
}

// detectRequest 是「请求 → 结论」的纯服务端管线，页面、GET JSON 与日志共用。
func (s *Server) detectRequest(r *http.Request) Result {
	ss, ev, ip := s.collect(r)
	res := s.detector.Detect(ss, ev, ip)
	res.ID = NewID()
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

	return ss, ev, ip
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
