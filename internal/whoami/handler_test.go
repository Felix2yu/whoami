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
	if !strings.Contains(body, "不等于不是信创") && !strings.Contains(body, "不代表机器不是信创") {
		t.Error("无法判定时必须解释清楚边界")
	}
	if strings.Contains(body, "非信创") &&
		!strings.Contains(body, "不等于不是信创") && !strings.Contains(body, "不代表机器不是信创") {
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

func TestStaticAssetsAreRevalidatedWithETag(t *testing.T) {
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
	// no-cache：JS 修正必须立刻到客户端，靠 ETag 走 304 而不是强缓存一小时。
	if etag == "" || rec.Header().Get("Cache-Control") != "no-cache" {
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

	// 只置 HasJS、没有 js 信号（等价于空回报）：只能说「收到了但没法交叉验证」，
	// 不得宣称已交叉印证。
	res.HasJS = true
	v2 := BuildView(res)
	if !strings.Contains(v2.JSStatus, "已收到浏览器端回报") || strings.Contains(v2.JSStatus, "交叉印证") {
		t.Errorf("jsStatus = %q", v2.JSStatus)
	}
}

func TestCardDetailKeepsShortValuesOnly(t *testing.T) {
	long := strings.Repeat("m", maxDetailValue+1)
	fs := []Finding{{
		RuleIDs: []string{"cpu-loongarch64"}, Name: "龙芯 LoongArch", Domain: "CPU 架构", Category: CatCPU,
		Xinchuang: true, Sources: []string{SourceHeader}, Values: []string{"loongarch64", long},
		Confidence: 100, Ceiling: 100, Score: 100,
	}}
	cards := findingCards(fs, nil)
	if len(cards) != 1 {
		t.Fatalf("cards = %+v", cards)
	}
	if strings.Contains(cards[0].Detail, long) {
		t.Errorf("摘要行回显了超长值：%q", cards[0].Detail)
	}
	if !strings.Contains(cards[0].Detail, "loongarch64") || !strings.Contains(cards[0].Detail, " · 信创判定分 100/100") {
		t.Errorf("detail = %q，应有短值与分隔符", cards[0].Detail)
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

func TestRecordLookupByID(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/whoami", nil))
	var res Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}

	got := httptest.NewRecorder()
	s.ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/api/record/"+res.ID, nil))
	if got.Code != http.StatusOK {
		t.Fatalf("反查 status = %d body=%s", got.Code, got.Body.String())
	}
	var back Result
	if err := json.Unmarshal(got.Body.Bytes(), &back); err != nil || back.ID != res.ID {
		t.Errorf("反查结果 = %+v err=%v", back.ID, err)
	}

	miss := httptest.NewRecorder()
	s.ServeHTTP(miss, httptest.NewRequest(http.MethodGet, "/api/record/0000000000000000", nil))
	if miss.Code != http.StatusNotFound {
		t.Errorf("未知 ID status = %d, want 404", miss.Code)
	}
}

func TestStatsRequiresTokenAndRateLimits(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LogDir = ""
	cfg.StatsToken = "s3cret"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer s.Close()

	// 配了口令就必须出示：查询参数与请求头两种方式都认。
	for _, path := range []string{"/stats", "/api/stats"} {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s 无 token status = %d, want 403", path, rec.Code)
		}
	}
	ok := httptest.NewRecorder()
	s.ServeHTTP(ok, httptest.NewRequest(http.MethodGet, "/api/stats?token=s3cret", nil))
	if ok.Code != http.StatusOK {
		t.Errorf("query token status = %d", ok.Code)
	}
	hdr := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	hdr.Header.Set("X-Stats-Token", "s3cret")
	ok2 := httptest.NewRecorder()
	s.ServeHTTP(ok2, hdr)
	if ok2.Code != http.StatusOK {
		t.Errorf("header token status = %d", ok2.Code)
	}

	// 同一地址连打超出窗口配额：必须出现 429，而不是一直放行。
	var limited bool
	for i := 0; i < statsRateLimit+10; i++ {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/stats?token=s3cret", nil))
		if rec.Code == http.StatusTooManyRequests {
			limited = true
			if rec.Header().Get("Retry-After") == "" {
				t.Error("429 应带 Retry-After")
			}
			break
		}
	}
	if !limited {
		t.Errorf("连续 %d 次请求未触发限流", statsRateLimit+10)
	}
}

// UA 必须两端一致：请求头 UA 和 navigator.userAgent 正常情况下必然相同，
// 不一致说明有代理改写或伪造，结论页必须提示人工核对。
func TestReportFlagsUAMismatch(t *testing.T) {
	s := newTestServer(t)
	const headerUA = "Mozilla/5.0 (X11; UOS; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0"

	post := func(body string) Result {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/api/whoami", strings.NewReader(body))
		r.Header.Set("User-Agent", headerUA)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("report status = %d body=%s", rec.Code, rec.Body.String())
		}
		var res Result
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		return res
	}

	mismatch := post(`{"userAgent":"Evil-UA/1.0"}`)
	if !strings.Contains(strings.Join(mismatch.Verdict.Limits, "|"), "UA 与请求头不一致") {
		t.Errorf("UA 不一致应写进 Limits：%+v", mismatch.Verdict.Limits)
	}

	match := post(`{"userAgent":"` + headerUA + `"}`)
	for _, l := range match.Verdict.Limits {
		if strings.Contains(l, "UA 与请求头不一致") {
			t.Errorf("UA 一致时不该提示：%s", l)
		}
	}
}
