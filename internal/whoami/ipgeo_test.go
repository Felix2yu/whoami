package whoami

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

func TestDefaultConfigurationNeverLeavesTheBox(t *testing.T) {
	s := newTestServer(t)
	if s.geo.Enabled() {
		t.Fatal("默认必须是不外呼的 noop provider")
	}
	if name := s.geo.Name(); name != "未启用" {
		t.Errorf("name = %q", name)
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	r.Header.Set("User-Agent", uaLoongArch)
	s.ServeHTTP(rec, r)

	var res Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Geo) != 0 || res.GeoProvider != "" {
		t.Errorf("默认不该有归属信息：%+v", res)
	}
	joined := strings.Join(res.Verdict.Limits, "|")
	if strings.Contains(joined, "外部接口") {
		t.Errorf("未启用接口却提示外呼风险：%s", joined)
	}
}

func TestHTTPGeoProviderMapsFieldsAndOrder(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"city":"上海","isp":"电信 ","country":"CN","asn":4808,
			"unknown_field":"x","empty":"","noise":"unknown"}`))
	}))
	defer srv.Close()

	cfg := DefaultGeoConfig()
	cfg.Endpoint = srv.URL + "/?q={ip}"
	cfg.Fields = []string{"country", "city", "isp", "asn", "noise", "missing"}
	p, err := NewHTTPGeoProvider(cfg)
	if err != nil {
		t.Fatalf("NewHTTPGeoProvider: %v", err)
	}

	geo, err := p.Lookup(context.Background(), addr(t, "203.0.113.9"))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	want := []string{"country=CN", "city=上海", "isp=电信", "asn=4808"}
	if got := render(geo); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("geo = %v, want %v（空值、unknown 与被忽略的字段都不该出现）", got, want)
	}
	if calls.Load() != 1 {
		t.Errorf("calls = %d", calls.Load())
	}

	// 命中缓存：同一地址再来一次不该再打接口。
	if _, err := p.Lookup(context.Background(), addr(t, "203.0.113.9")); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Errorf("缓存未生效，calls = %d", calls.Load())
	}
	if _, err := p.Lookup(context.Background(), addr(t, "203.0.113.10")); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Errorf("换地址应重新查询，calls = %d", calls.Load())
	}
}

func render(g Geo) []string {
	var out []string
	for _, v := range g {
		out = append(out, v.Key+"="+v.Value)
	}
	return out
}

func TestGeoProviderEndpointShapes(t *testing.T) {
	cfg := DefaultGeoConfig()
	cfg.Endpoint = "https://example.internal/geo"
	p, _ := NewHTTPGeoProvider(cfg)
	if got := p.url(addr(t, "203.0.113.9")); got != "https://example.internal/geo?203.0.113.9" {
		t.Errorf("裸追加 = %q", got)
	}
	if got := p.url(addr(t, "2001:db8::1")); got != "https://example.internal/geo?[2001:db8::1]" {
		t.Errorf("IPv6 需要方括号 = %q", got)
	}
	cfg.Endpoint = "https://example.internal/geo?a=1&ip="
	p2, _ := NewHTTPGeoProvider(cfg)
	if got := p2.url(addr(t, "203.0.113.9")); got != "https://example.internal/geo?a=1&ip=203.0.113.9" {
		t.Errorf("已有查询串时应改用 & = %q", got)
	}
	cfg.Endpoint = "https://example.internal/geo/{ip}/detail"
	p3, _ := NewHTTPGeoProvider(cfg)
	if got := p3.url(addr(t, "203.0.113.9")); got != "https://example.internal/geo/203.0.113.9/detail" {
		t.Errorf("{ip} 占位替换 = %q", got)
	}
	// 地址来自校验过的 netip.Addr，不可能塞进路径分隔符去改写目标主机。
	if got := p3.url(addr(t, "2001:db8::1")); !strings.HasPrefix(got, "https://example.internal/geo/2001:db8::1/detail") {
		t.Errorf("IPv6 直接嵌入 = %q", got)
	}
	if _, err := NewHTTPGeoProvider(GeoConfig{Endpoint: ""}); err == nil {
		t.Error("空 endpoint 应拒绝")
	}
}

func TestGeoProviderDegradesOnBadUpstream(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := DefaultGeoConfig()
	cfg.Endpoint = srv.URL + "/{ip}"
	p, _ := NewHTTPGeoProvider(cfg)

	if _, err := p.Lookup(context.Background(), addr(t, "203.0.113.9")); err == nil {
		t.Fatal("5xx 应报错")
	}
	if _, err := p.Lookup(context.Background(), addr(t, "203.0.113.9")); err == nil {
		t.Fatal("失败结果应被短缓存并继续降级")
	}
	if calls.Load() != 1 {
		t.Errorf("失败后不该反复敲门，calls = %d", calls.Load())
	}

	// 非扁平 JSON 与超时都不能挂住请求。
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[1,2,3]`))
	}))
	defer bad.Close()
	cfg.Endpoint = bad.URL + "/{ip}"
	p2, _ := NewHTTPGeoProvider(cfg)
	if _, err := p2.Lookup(context.Background(), addr(t, "1.1.1.1")); err == nil {
		t.Error("数组响应应被拒绝")
	}

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`{"city":"上海"}`))
	}))
	defer slow.Close()
	cfg.Endpoint = slow.URL + "/{ip}"
	cfg.Timeout = 50 * time.Millisecond
	p3, _ := NewHTTPGeoProvider(cfg)
	start := time.Now()
	if _, err := p3.Lookup(context.Background(), addr(t, "1.1.1.2")); err == nil {
		t.Error("超时应报错")
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Errorf("超时没有生效，耗时 %v", elapsed)
	}
}

func TestGeoProviderCacheIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"city":"x"}`))
	}))
	defer srv.Close()

	cfg := DefaultGeoConfig()
	cfg.Endpoint = srv.URL + "/{ip}"
	cfg.Size = 2
	p, _ := NewHTTPGeoProvider(cfg)
	for i := range 8 {
		if _, err := p.Lookup(context.Background(), addr(t, "203.0.113."+string(rune('0'+i%8)))); err != nil {
			t.Fatal(err)
		}
	}
	p.mu.Lock()
	size := len(p.items)
	p.mu.Unlock()
	if size > cfg.Size {
		t.Errorf("缓存 %d 条，超过上限 %d", size, cfg.Size)
	}
}

func TestGeoClipsRunawayValues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"isp":"` + strings.Repeat("Y", 500) + `"}`))
	}))
	defer srv.Close()

	cfg := DefaultGeoConfig()
	cfg.Endpoint = srv.URL
	p, _ := NewHTTPGeoProvider(cfg)
	geo, err := p.Lookup(context.Background(), addr(t, "203.0.113.9"))
	if err != nil {
		t.Fatal(err)
	}
	if len(geo) != 1 || len(geo[0].Value) != maxGeoValue {
		t.Errorf("geo = %+v", geo)
	}
}

func TestServerRendersGeoWhenProviderEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"city":"上海","isp":"电信"}`))
	}))
	defer srv.Close()

	fake := &countingGeo{n: &atomic.Int64{}}
	s := newTestServer(t)
	s.geo = fake

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("User-Agent", uaLoongArch)
	r.Header.Set("Accept", "text/html")
	s.ServeHTTP(rec, r)
	body := rec.Body.String()

	if fake.n.Load() == 0 {
		t.Error("启用接口后应发起查询")
	}
	if !strings.Contains(body, "归属 · city") || !strings.Contains(body, "上海") {
		t.Errorf("页面缺少归属行：%s", body)
	}
	if !strings.Contains(body, "来自外部接口 test-provider") {
		t.Error("最小视图也必须明示外呼行为")
	}

	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/?detail=1", nil)
	r.Header.Set("User-Agent", uaLoongArch)
	r.Header.Set("Accept", "text/html")
	s.ServeHTTP(rec, r)
	if !strings.Contains(rec.Body.String(), "已把访客 IP 交给该接口") {
		t.Error("?detail=1 应展开外呼的完整说明")
	}

	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/?hide=geo", nil)
	r.Header.Set("User-Agent", uaLoongArch)
	r.Header.Set("Accept", "text/html")
	s.ServeHTTP(rec, r)
	if strings.Contains(rec.Body.String(), "归属 · city") {
		t.Error("hide=geo 应收起归属行")
	}
}

type countingGeo struct {
	n *atomic.Int64
}

func (c *countingGeo) Name() string  { return "test-provider" }
func (c *countingGeo) Enabled() bool { return true }
func (c *countingGeo) Lookup(context.Context, netip.Addr) (Geo, error) {
	c.n.Add(1)
	return Geo{{Key: "city", Value: "上海"}, {Key: "isp", Value: "电信"}}, nil
}

func TestLookupGeoNoopsWithoutProvider(t *testing.T) {
	if geo, note := lookupGeo(context.Background(), nil, addr(t, "1.1.1.1")); geo != nil || note != "" {
		t.Errorf("nil provider = %v %q", geo, note)
	}
	if geo, _ := lookupGeo(context.Background(), noopProvider{}, addr(t, "1.1.1.1")); geo != nil {
		t.Error("noop 不该产出任何归属")
	}
	if geo, note := lookupGeo(context.Background(), noopProvider{}, netip.Addr{}); geo != nil || note != "" {
		t.Error("无效地址不该触发查询")
	}
}
