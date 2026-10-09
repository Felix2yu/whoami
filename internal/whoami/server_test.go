package whoami

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(DefaultConfig())
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
	hs := NewServer(cfg).HTTPServer()
	if hs.Addr != cfg.Addr || hs.ReadHeaderTimeout != cfg.ReadHeaderTimeout ||
		hs.ReadTimeout != cfg.ReadTimeout || hs.WriteTimeout != cfg.WriteTimeout ||
		hs.IdleTimeout != cfg.IdleTimeout || hs.MaxHeaderBytes != cfg.MaxHeaderBytes {
		t.Fatalf("http.Server does not mirror Config: %+v", hs)
	}
}
