package whoami

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// newTestServer 默认关掉日志落盘，测试不往仓库里写文件。
func newTestServer(t *testing.T) *Server {
	t.Helper()
	return newLoggingTestServer(t, "")
}

func newLoggingTestServer(t *testing.T, dir string) *Server {
	t.Helper()
	cfg := DefaultConfig()
	cfg.LogDir = dir
	if dir == "" {
		cfg.LogDir = ""
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestNewServerRejectsBadTrustedProxies(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrustedProxies = []string{"10.0.0.0/8", "not-a-cidr"}
	if _, err := NewServer(cfg); err == nil {
		t.Fatal("want error for invalid CIDR, got nil")
	}
	cfg.TrustedProxies = []string{"10.0.0.0/8", "", " ::1/128 "}
	if _, err := NewServer(cfg); err != nil {
		t.Fatalf("NewServer: %v", err)
	}
}

func do(s *Server, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestHealthz(t *testing.T) {
	rec := do(newTestServer(t), http.MethodGet, "/healthz")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "ok\n" {
		t.Fatalf("body = %q, want %q", got, "ok\n")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache-control = %q, want no-store", got)
	}
}

func TestRouteMethodMatching(t *testing.T) {
	s := newTestServer(t)
	if rec := do(s, http.MethodPost, "/healthz"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /healthz status = %d, want 405", rec.Code)
	}
	if rec := do(s, http.MethodGet, "/nope"); rec.Code != http.StatusNotFound {
		t.Fatalf("GET /nope status = %d, want 404", rec.Code)
	}
}

func TestDefaultTimeoutsAreSizedForSmallJSONPayloads(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ReadHeaderTimeout > cfg.ReadTimeout || cfg.ReadTimeout > cfg.WriteTimeout {
		t.Fatalf("timeout ordering wrong: header=%v read=%v write=%v",
			cfg.ReadHeaderTimeout, cfg.ReadTimeout, cfg.WriteTimeout)
	}
	if cfg.MaxHeaderBytes < 32<<10 {
		t.Fatalf("MaxHeaderBytes = %d, too small for long UA plus cookies", cfg.MaxHeaderBytes)
	}
	if cfg.MaxPostBytes < 8<<10 {
		t.Fatalf("MaxPostBytes = %d, real JS report payload is 2-4KB", cfg.MaxPostBytes)
	}
}

func TestHTTPServerCarriesConfig(t *testing.T) {
	cfg := DefaultConfig()
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hs := s.HTTPServer()
	if hs.Addr != cfg.Addr || hs.ReadHeaderTimeout != cfg.ReadHeaderTimeout ||
		hs.ReadTimeout != cfg.ReadTimeout || hs.WriteTimeout != cfg.WriteTimeout ||
		hs.IdleTimeout != cfg.IdleTimeout || hs.MaxHeaderBytes != cfg.MaxHeaderBytes {
		t.Fatalf("http.Server does not mirror Config: %+v", hs)
	}
}

// 回归：-anonymize-ip full 的盐必须跨重启复用。
// 日志里存的是哈希结果，换盐后同一访客会得到新标识，「独立 IP」计数会翻倍。
func TestAnonSaltPersistsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	ip := mustAddr(t, "203.0.113.9")

	first := newLoggingTestServer(t, dir)
	second := newLoggingTestServer(t, dir)
	if len(first.anonSalt) < 16 {
		t.Fatalf("盐长度 %d 过短", len(first.anonSalt))
	}
	if AnonymizeIP(ip, "full", first.anonSalt) != AnonymizeIP(ip, "full", second.anonSalt) {
		t.Fatal("同一日志目录重启后盐应一致，full 模式的独立 IP 计数才能跨重启正确")
	}

	info, err := os.Stat(filepath.Join(dir, ".anon-salt"))
	if err != nil {
		t.Fatalf("盐文件应落在日志目录: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("盐文件权限 = %o，应为 600", perm)
	}

	// 未开启落盘时没有跨重启的真源，每次启动给随机盐即可。
	if off := newTestServer(t); len(off.anonSalt) == 0 {
		t.Error("关闭落盘时也应生成盐")
	}
}
