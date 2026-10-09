package whoami

import (
	"net/http"
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
	}
}

// Server 持有各子模块，实现 http.Handler。
type Server struct {
	cfg Config
	mux *http.ServeMux
}

func NewServer(cfg Config) *Server {
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) Addr() string { return s.cfg.Addr }

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
