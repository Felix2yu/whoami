package whoami

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func getPage(t *testing.T, ua string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	return getPagePath(t, "/", ua, headers)
}

func TestServerInfoIsServerIdentityNotClient(t *testing.T) {
	// 服务器调用（curl 默认 Accept */*，不含 text/html）→ 根路径返回服务器身份 JSON。
	rec := getPagePath(t, "/", "", map[string]string{"Accept": "application/json"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q", ct)
	}

	var info ServerInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("响应不是合法 JSON: %v body=%s", err, rec.Body.String())
	}
	if info.OS != runtime.GOOS {
		t.Errorf("os = %q, want %q", info.OS, runtime.GOOS)
	}
	if info.Arch != runtime.GOARCH {
		t.Errorf("arch = %q, want %q", info.Arch, runtime.GOARCH)
	}
	if want, err := os.Hostname(); err == nil && info.Hostname != want {
		t.Errorf("hostname = %q, want %q", info.Hostname, want)
	}
	// 开放口径：不应带 CSP 类安全头（与 /healthz 一致）。
	if got := rec.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("/ 的 JSON 分支不该设 CSP：%q", got)
	}
}

func TestIndexServesHTMLToBrowser(t *testing.T) {
	// 浏览器（Accept 含 text/html）→ 根路径仍返回访客检测页，行为不变。
	rec := getPagePath(t, "/", "", map[string]string{"Accept": "text/html"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}
	// 页面应仍含信创判定表，证明访客检测逻辑未被内容协商破坏。
	if !strings.Contains(rec.Body.String(), "是否信创") {
		t.Errorf("访客检测页缺少「是否信创」")
	}
}

func getPagePath(t *testing.T, path, ua string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	// 真实浏览器总在 Accept 里带 text/html；测试默认也带，避免被内容协商判成 JSON 分支。
	// 需要 JSON 的调用（如服务器身份测试）显式传 Accept: application/json 即可覆盖。
	if _, ok := headers["Accept"]; !ok {
		r.Header.Set("Accept", "text/html")
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
	for _, want := range []string{"是否信创", `<span class="v" title="是">是</span>`, "龙芯 LoongArch", "loongarch64"} {
		if !strings.Contains(body, want) {
			t.Errorf("页面缺少 %q", want)
		}
	}
	// 默认视图只有结果表：判定分、依据说明、边界提示与原始证据都要 ?detail=1 才给。
	for _, absent := range []string{"判定分", "原始证据", "LoongArch 自研指令集", "仅服务端信号", "不作为准入依据"} {
		if strings.Contains(body, absent) {
			t.Errorf("最小视图不该出现 %q", absent)
		}
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("content-type = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("页面不该被缓存：%q", got)
	}
}

func TestDetailParamExpandsReasoning(t *testing.T) {
	body := getPagePath(t, "/?detail=1", loongArchUA, nil).Body.String()
	for _, want := range []string{"判定分 100/100", "原始证据", "header.user-agent", "仅服务端信号", "不作为准入依据"} {
		if !strings.Contains(body, want) {
			t.Errorf("?detail=1 页面缺少 %q", want)
		}
	}
	if !strings.Contains(body, "LoongArch") {
		t.Errorf("?detail=1 应展开结论依据：%s", body)
	}
	// ?detail=0 必须回到最小视图，不能把「写了参数」一律当成开启。
	if min := getPagePath(t, "/?detail=0", loongArchUA, nil).Body.String(); strings.Contains(min, "原始证据") {
		t.Error("?detail=0 不该展开原始证据")
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
	// 通用 Linux x86_64：这才是真的判不出来（海光/兆芯与 Intel/AMD 无法区分）。
	const ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
	min := getPage(t, ua, nil).Body.String()
	if !strings.Contains(min, `<span class="v" title="未知">未知</span>`) {
		t.Error("判不出来的通用 UA 应给「未知」")
	}
	if strings.Contains(min, "不代表机器不是信创") {
		t.Error("最小视图不铺陈边界说明")
	}
	detail := getPagePath(t, "/?detail=1", ua, nil).Body.String()
	if !strings.Contains(detail, "不等于不是信创") && !strings.Contains(detail, "不代表机器不是信创") {
		t.Error("?detail=1 时无法判定必须解释清楚边界")
	}
	for _, body := range []string{min, detail} {
		if strings.Contains(body, "非信创") &&
			!strings.Contains(body, "不等于不是信创") && !strings.Contains(body, "不代表机器不是信创") {
			t.Error("不得出现否定断言")
		}
	}
	if !strings.Contains(detail, "仅服务端信号") {
		t.Error("?detail=1 且未收到 JS 回报时应明示")
	}
}

func TestForeignPlatformRendersDefiniteNegative(t *testing.T) {
	const macUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
	body := getPage(t, macUA, nil).Body.String()
	if !strings.Contains(body, `<span class="v" title="不是">不是</span>`) {
		t.Errorf("macOS 应直接给「不是」：%s", body)
	}
	if strings.Contains(body, "未发现信创特征") {
		t.Error("已经判定的事不该再挂「未发现特征」的兜底说明")
	}
}

// rowLabelRe 只匹配行首标签：最小视图里没有嵌套表，第一个 </table> 就是结果表的结尾。
var rowLabelRe = regexp.MustCompile(`<th>([^<]+)</th>`)

func mainRowLabels(t *testing.T, body string) []string {
	t.Helper()
	start := strings.Index(body, `<table class="kv rows">`)
	if start < 0 {
		t.Fatalf("页面缺少结果表：%s", body)
	}
	end := strings.Index(body[start:], "</table>")
	if end < 0 {
		t.Fatal("结果表没有闭合")
	}
	var out []string
	for _, m := range rowLabelRe.FindAllStringSubmatch(body[start:start+end], -1) {
		out = append(out, m[1])
	}
	return out
}

func TestRowsAreGroupedByRelevance(t *testing.T) {
	const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	payload := `{"userAgent":"` + ua + `","platform":"macOS","platformVersion":"14.4.0","architecture":"arm64","bitness":"64",` +
		`"cores":8,"memory":8,"timezone":"Asia/Shanghai","screen":{"width":1512,"height":982,"dpr":2},` +
		`"gpu":{"vendor":"Apple","renderer":"Apple M2"}}`
	labels := mainRowLabels(t, postReport(t, "/report", ua, payload).Body.String())

	pos := func(name string) int {
		t.Helper()
		for i, l := range labels {
			if l == name {
				return i
			}
		}
		t.Fatalf("缺少行 %q，实际 %v", name, labels)
		return -1
	}

	if labels[0] != "是否信创" || labels[1] != "IP 地址" {
		t.Errorf("结论与 IP 必须打头：%v", labels)
	}
	// 强关联的行必须相邻：系统家族↔系统版本（中间最多夹一个发行版）、
	// CPU 架构↔核心数↔内存、GPU 结论↔GPU 原始串。
	if d := pos("系统版本") - pos("系统家族"); d < 1 || d > 2 {
		t.Errorf("系统家族与系统版本被拆开了：%v", labels)
	}
	if pos("逻辑核心数") != pos("CPU 架构")+1 || pos("设备内存") != pos("逻辑核心数")+1 {
		t.Errorf("CPU 与容量类字段没有连着排：%v", labels)
	}
	if pos("时区") < pos("屏幕") {
		t.Errorf("展示类字段的顺序不稳定：%v", labels)
	}
}

// GPU 的结论行与 WebGL 原始串是一组，必须挨着；只有原始串时也不该把结论行挤到别处。
func TestGPUConclusionSitsNextToRawString(t *testing.T) {
	const ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	payload := `{"userAgent":"` + ua + `","gpu":{"vendor":"Jingjia Micro","renderer":"JM910"}}`
	labels := mainRowLabels(t, postReport(t, "/report", ua, payload).Body.String())

	var gpu, raw = -1, -1
	for i, l := range labels {
		switch l {
		case "GPU":
			gpu = i
		case "GPU 原始串":
			raw = i
		}
	}
	if gpu < 0 || raw != gpu+1 {
		t.Errorf("GPU 两行应相邻：%v", labels)
	}
	if labels[0] != "是否信创" {
		t.Errorf("结论行必须打头：%v", labels)
	}
}

func TestEmptyFieldsRenderNoRow(t *testing.T) {
	// curl 没有平台/架构/浏览器信息：这些行整行都不该出现，而不是排一行空的。
	rec := getPage(t, "curl/8.4.0", nil)
	body := rec.Body.String()
	for _, absent := range []string{`<th>CPU 架构</th>`, `<th>发行版</th>`, `<th>浏览器</th>`} {
		if strings.Contains(body, absent) {
			t.Errorf("空值不应占位：%s", absent)
		}
	}
	// 只剩「是否信创」与「IP 地址」两行。
	if n := strings.Count(body, "<tr>\n    <th>"); n != 2 {
		t.Errorf("结果表行数 = %d, want 2\n%s", n, body)
	}
	if strings.Contains(body, `<td></td>`) {
		t.Error("证据表里出现空单元格")
	}
}

func TestEvidenceDetailsAreListed(t *testing.T) {
	body := getPagePath(t, "/?detail=1", loongArchUA, map[string]string{
		"Accept-Language": "zh-CN,zh;q=0.9", "Referer": "http://127.0.0.1:9099/",
	}).Body.String()
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

func TestBuildViewVerdictRowAndStatus(t *testing.T) {
	d := builtinDetector(t)
	ss, ev := Collect(reqWith(map[string]string{"User-Agent": "Mozilla/5.0 (X11; UOS; Linux x86_64) Chrome/120"}))
	res := d.Detect(ss, ev, IPInfo{IP: "1.2.3.4", Family: "ipv4", Source: "conn"})

	v := BuildView(res)
	if len(v.Cards) == 0 || v.Cards[0].Key != KeyVerdict {
		t.Fatalf("首行应是「是否信创」：%+v", v.Cards)
	}
	if got := v.Cards[0].Value; got != "是" {
		t.Errorf("verdict = %q, want 是", got)
	}
	if !strings.Contains(strings.Join(v.Cards[0].Notes, "|"), "判定分") {
		t.Errorf("判定分应作为 detail 说明：%v", v.Cards[0].Notes)
	}
	if len(v.Cards) < 2 || v.Cards[1].Key != "ip" {
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

func TestVerdictCardCarriesReasonsAndLimits(t *testing.T) {
	res := Result{Verdict: Verdict{
		Status: "unknown", Reasons: []string{"未发现信创特征"}, Limits: []string{"没有 GPU 信号"},
	}}
	c := verdictCard(res)
	if c.Value != "未知" {
		t.Errorf("value = %q", c.Value)
	}
	joined := strings.Join(c.Notes, "|")
	if !strings.Contains(joined, "未发现信创特征") || !strings.Contains(joined, "没有 GPU 信号") {
		t.Errorf("notes = %v，理由与边界都要能展开", c.Notes)
	}
	if strings.Contains(joined, "判定分") {
		t.Error("未知结论没有判定分可言，不该出现分数")
	}

	// excluded 同样是 0 分：说了「不是」再挂一个判定分 0/100 只会让人以为还有别的信息。
	ex := verdictCard(Result{Verdict: Verdict{Status: "excluded", Reasons: []string{"macOS 不在信创目录内"}}})
	if ex.Value != "不是" || strings.Contains(strings.Join(ex.Notes, "|"), "判定分") {
		t.Errorf("excluded 行 = %+v", ex)
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
	if cards[0].Detail != "loongarch64" {
		t.Errorf("detail = %q，只应回显短值", cards[0].Detail)
	}
	if len(cards[0].Notes) == 0 || cards[0].Notes[0] != "信创判定分 100/100" {
		t.Errorf("notes = %v，判定分应留给 ?detail=1", cards[0].Notes)
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
