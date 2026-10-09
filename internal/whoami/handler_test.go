package whoami

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func getPage(t *testing.T, ua string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	newTestServer(t).ServeHTTP(rec, r)
	return rec
}

const loongArchUA = "Mozilla/5.0 (X11; Linux loongarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36"

func TestIndexRendersXinchuangVerdict(t *testing.T) {
	rec := getPage(t, loongArchUA, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"信创终端", "龙芯 LoongArch", "确认", "原始证据", "loongarch64", "判定分 100"} {
		if !strings.Contains(body, want) {
			t.Errorf("页面缺少 %q", want)
		}
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("content-type = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("页面不该被缓存：%q", got)
	}
}

func TestIndexShowsIPAndInternalMark(t *testing.T) {
	body := getPage(t, "Mozilla/5.0 (X11; Linux x86_64) Chrome/120", nil).Body.String()
	if !strings.Contains(body, "192.0.2.1") {
		t.Error("页面应显示访客 IP")
	}
	if !strings.Contains(body, "IPV4") {
		t.Errorf("应标注地址族：%s", body)
	}
}

func TestUnknownVerdictExplainsItself(t *testing.T) {
	body := getPage(t, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36", nil).Body.String()
	if !strings.Contains(body, "无法判定") {
		t.Error("通用 UA 应给出「无法判定」")
	}
	if !strings.Contains(body, "不等于不是信创") {
		t.Error("无法判定时必须解释清楚边界")
	}
	if strings.Contains(body, "非信创") && !strings.Contains(body, "不等于不是信创") {
		t.Error("不得出现否定断言")
	}
	if !strings.Contains(body, "仅服务端信号") {
		t.Error("未收到 JS 回报时应明示")
	}
}

func TestEmptyFieldsRenderNoRow(t *testing.T) {
	// curl 没有平台/架构/浏览器信息：这些卡片整行都不该出现，而不是排一行空的。
	rec := getPage(t, "curl/8.4.0", nil)
	body := rec.Body.String()
	for _, absent := range []string{`<span class="k">CPU 架构</span>`, `<span class="k">发行版</span>`, `<span class="k">浏览器</span>`} {
		if strings.Contains(body, absent) {
			t.Errorf("空值不应占位：%s", absent)
		}
	}
	if n := strings.Count(body, `<article class="card">`); n != 1 {
		t.Errorf("卡片行数 = %d, want 1（只有 IP）\n%s", n, body)
	}
	if strings.Contains(body, `<td></td>`) {
		t.Error("证据表里出现空单元格")
	}
}

func TestEvidenceDetailsAreListed(t *testing.T) {
	body := getPage(t, loongArchUA, map[string]string{"Accept-Language": "zh-CN,zh;q=0.9", "Referer": "http://127.0.0.1:9099/"}).Body.String()
	for _, want := range []string{"header.user-agent", "header.accept-language", "header.referer", "conn.remote_addr"} {
		if !strings.Contains(body, want) {
			t.Errorf("原始证据缺少 %s", want)
		}
	}
}

func TestAPIWhoamiJSONShape(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; UOS; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36")
	rec := httptest.NewRecorder()
	newTestServer(t).ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var res Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v\n%s", err, rec.Body.String())
	}
	if res.ID == "" || len(res.ID) != 16 {
		t.Errorf("id = %q", res.ID)
	}
	if res.Client.IP != "192.0.2.1" || res.Client.Source != "conn" {
		t.Errorf("client = %+v", res.Client)
	}
	if res.Verdict.Status != "confirmed" {
		t.Errorf("verdict = %+v", res.Verdict)
	}
	if res.HasJS {
		t.Error("GET 不应带 JS 回报")
	}
	for _, key := range []string{"id", "client", "findings", "verdict", "evidence", "signals", "sources"} {
		if !strings.Contains(rec.Body.String(), `"`+key+`"`) {
			t.Errorf("JSON 缺少字段 %s", key)
		}
	}
	if !strings.Contains(rec.Body.String(), "统信 UOS") {
		t.Errorf("统信标识未体现：%s", rec.Body.String())
	}
}

func TestStaticAssetsAreCachedAndImmutable(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/app.css", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Errorf("content-type = %q", ct)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" || rec.Header().Get("Cache-Control") != "public, max-age=3600" {
		t.Errorf("etag=%q cache=%q", etag, rec.Header().Get("Cache-Control"))
	}

	rec = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/static/app.css", nil)
	r.Header.Set("If-None-Match", etag)
	s.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
		t.Fatalf("If-None-Match 应 304，实际 %d / %d bytes", rec.Code, rec.Body.Len())
	}
}

func TestStaticRejectsMissingAndTraversal(t *testing.T) {
	s := newTestServer(t)
	for _, path := range []string{"/static/nope.css", "/static/", "/static/../go.mod", "/static/%2e%2e/web/web.go", "/static/./app.css"} {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		// ServeMux 会先把带 .. 的路径 307 规范化；两种情况都必须拿不到仓库源码。
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusTemporaryRedirect {
			t.Errorf("%s status = %d, want 404/307", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "module whoami") || strings.Contains(rec.Body.String(), "go:embed") {
			t.Errorf("%s 泄漏了仓库源码", path)
		}
	}
}

func TestBuildViewBannerAndStatus(t *testing.T) {
	d := builtinDetector(t)
	ss, ev := Collect(reqWith(map[string]string{"User-Agent": "Mozilla/5.0 (X11; UOS; Linux x86_64) Chrome/120"}))
	res := d.Detect(ss, ev, IPInfo{IP: "1.2.3.4", Family: "ipv4", Source: "conn"})

	v := BuildView(res)
	if v.Banner.Status != "confirmed" || v.Banner.Title != "信创终端" {
		t.Errorf("banner = %+v", v.Banner)
	}
	if v.Banner.Caveat != "" {
		t.Error("确认结论不需要 caveat")
	}
	if !v.HasContent() {
		t.Fatal("视图没有内容")
	}
	if len(v.Cards) == 0 || v.Cards[0].Key != "ip" {
		t.Errorf("cards = %+v", v.Cards)
	}
	for _, c := range append(v.Cards, v.Extras...) {
		if c.Value == "" {
			t.Errorf("卡片 %s 值为空，不应进入视图", c.Title)
		}
	}
	if !strings.Contains(v.JSStatus, "仅服务端信号") {
		t.Errorf("jsStatus = %q", v.JSStatus)
	}

	res.HasJS = true
	if v2 := BuildView(res); !strings.Contains(v2.JSStatus, "跨源交叉验证") {
		t.Errorf("jsStatus = %q", v2.JSStatus)
	}
}

func TestBuildViewIPCardCombinesLabelAndNotes(t *testing.T) {
	res := Result{Client: IPInfo{
		IP: "2.46.0.7", Family: "ipv4", Source: "x-forwarded-for", Label: "三分局出口",
		Note: "转发链上的地址全部属于受信网段",
	}, Evidence: []Evidence{{Key: "header.x-forwarded-for", Raw: "2.46.0.7", Source: SourceIP}}}
	card := ipCard(res, res.Evidence)

	if !strings.Contains(card.Value, "三分局出口") || !strings.Contains(card.Value, "2.46.0.7") {
		t.Errorf("value = %q", card.Value)
	}
	if !strings.Contains(card.Detail, "X-Forwarded-For") {
		t.Errorf("detail = %q", card.Detail)
	}
	if len(card.Notes) != 1 || len(card.Evidence) != 1 {
		t.Errorf("notes=%v evidence=%v", card.Notes, card.Evidence)
	}
}

func TestDetectRequestIsIndependentPerRequest(t *testing.T) {
	s := newTestServer(t)
	a := s.detectRequest(httptest.NewRequest(http.MethodGet, "/", nil))
	b := s.detectRequest(httptest.NewRequest(http.MethodGet, "/", nil))
	if a.ID == b.ID {
		t.Fatal("每次记录应有独立 ID")
	}
	if a.Verdict.Status != b.Verdict.Status {
		t.Fatalf("同输入应同结论：%s vs %s", a.Verdict.Status, b.Verdict.Status)
	}
}
