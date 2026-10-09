package whoami

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	s.mux.HandleFunc("GET /static/", s.handleStatic)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	res := s.detectRequest(r)
	view := BuildView(res)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.tmpl.ExecuteTemplate(w, "index.html.tmpl", view); err != nil {
		slog.Error("render index failed", "err", err, "id", res.ID)
	}
}

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	res := s.detectRequest(r)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	asset, ok := s.assets[name]
	if !ok || name == "" || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
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

// detectRequest 是「请求 → 结论」的唯一管线，页面、JSON 端点与日志共用。
func (s *Server) detectRequest(r *http.Request) Result {
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

	res := s.detector.Detect(ss, ev, ip)
	res.ID = NewID()
	return res
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
