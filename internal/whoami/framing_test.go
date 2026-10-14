package whoami

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"whoami/internal/web"
)

func frameRequest(query string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/"+"?"+query, nil)
	if _, ok := headers["Accept"]; !ok {
		r.Header.Set("Accept", "text/html")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestFramingAutoDetectsIframe(t *testing.T) {
	cases := []struct {
		name  string
		query string
		dest  string
		want  bool
	}{
		{"iframe 无参数自动紧凑", "", "iframe", true},
		{"frame 也算嵌入", "", "frame", true},
		{"顶层文档不紧凑", "", "document", false},
		{"?embed=0 强制完整版", "embed=0", "iframe", false},
		{"?embed=1 强制紧凑", "embed=1", "", true},
		{"无 dest 无参数", "", "", false},
	}
	for _, c := range cases {
		f := framingOf(frameRequest(c.query, map[string]string{"Sec-Fetch-Dest": c.dest}))
		if f.Embedded != c.want {
			t.Errorf("%s: embedded = %v, want %v", c.name, f.Embedded, c.want)
		}
	}
}

func TestHideAndOnlyAreCardSwitches(t *testing.T) {
	f := framingOf(frameRequest("", nil))
	if len(f.Hidden) != 0 {
		t.Fatalf("默认不该隐藏任何卡片：%v", f.Hidden)
	}

	f = framingOf(frameRequest("hide=ip,evidence", nil))
	if !f.Hidden["ip"] || !f.Hidden["evidence"] || f.Hidden[CatCPU] {
		t.Fatalf("hide = %v", f.Hidden)
	}

	// 「是否信创」也是一行，开关口径与其它行一致。
	if !framingOf(frameRequest("hide=verdict", nil)).Hidden[KeyVerdict] {
		t.Error("hide=verdict 应关掉「是否信创」行")
	}
	if !framingOf(frameRequest("only=ip", nil)).Hidden[KeyVerdict] {
		t.Error("only=ip 应连带关掉「是否信创」行")
	}

	// ?only=ip 时其余卡片全部不渲染，hide 仍可叠加。
	f = framingOf(frameRequest("only=ip", nil))
	for _, k := range allCardKeys() {
		if k == "ip" {
			continue
		}
		if !f.Hidden[k] {
			t.Errorf("only=ip 应隐藏 %s", k)
		}
	}

	f = framingOf(frameRequest("only=ip,cpu&hide=cpu", nil))
	if f.Hidden["ip"] || !f.Hidden["cpu"] || !f.Hidden[CatBrowser] {
		t.Fatalf("only+hide 组合异常：%v", f.Hidden)
	}
}

func TestDetailSwitchParsesQuery(t *testing.T) {
	cases := []struct {
		query string
		want  bool
	}{
		{"", false},
		{"detail=1", true},
		{"detail=TRUE", true},
		{"detail=on", true},
		{"detail=0", false},
		{"detail=no", false},
		{"detail", false},
	}
	for _, c := range cases {
		f := framingOf(frameRequest(c.query, nil))
		if got := f.Detail; got != c.want {
			t.Errorf("?%s: detail = %v, want %v", c.query, got, c.want)
		}
	}
	got := View{}.applyFraming(framingOf(frameRequest("detail=1", nil)))
	if !got.Detail {
		t.Error("applyFraming 应把 detail 落到视图上")
	}
}

func TestApplyFramingFiltersCards(t *testing.T) {
	v := View{
		Cards:    []Card{{Key: "ip", Value: "1.2.3.4"}, {Key: CatCPU, Value: "龙芯 LoongArch"}},
		Extras:   []Card{{Key: CatPlatform, Value: "Linux"}},
		Evidence: []Evidence{{Key: "header.user-agent", Raw: "x"}},
	}
	f := framingOf(frameRequest("hide=ip,evidence", map[string]string{"Sec-Fetch-Dest": "iframe"}))
	got := v.applyFraming(f)

	if len(got.Cards) != 1 || got.Cards[0].Key != CatCPU {
		t.Errorf("cards = %+v", got.Cards)
	}
	if len(got.Extras) != 1 {
		t.Errorf("extras 不该被动到：%+v", got.Extras)
	}
	if len(got.Evidence) != 0 {
		t.Errorf("hide=evidence 应收起证据区：%+v", got.Evidence)
	}
	if !got.Compact {
		t.Error("应进入紧凑模式")
	}
}

func TestFrameAncestorsDirective(t *testing.T) {
	if got := frameAncestorsDirective(nil); got != "frame-ancestors *" {
		t.Errorf("default = %q", got)
	}
	got := frameAncestorsDirective([]string{"http://127.0.0.1:9099", "https://intra.example.com"})
	if got != "frame-ancestors http://127.0.0.1:9099 https://intra.example.com" {
		t.Errorf("got = %q", got)
	}
}

func TestFrameAncestorValidationBlocksHeaderInjection(t *testing.T) {
	for _, bad := range []string{"", "http://a; script-src 'none'", "http://a\nX-Evil: 1", "http://a b", "javascript:alert(1)"} {
		if err := ValidFrameAncestor(bad); err == nil {
			t.Errorf("应拒绝 %q", bad)
		}
	}
	for _, ok := range []string{"*", "'self'", "https://example.com:8443", "http://127.0.0.1:9099", "https://*.example.com"} {
		if err := ValidFrameAncestor(ok); err != nil {
			t.Errorf("应放行 %q: %v", ok, err)
		}
	}

	cfg := DefaultConfig()
	cfg.FrameAncestors = []string{"http://ok.example.com", "bad; token"}
	if _, err := NewServer(cfg); err == nil {
		t.Fatal("NewServer 应拒绝非法来源，而不是把注入拼进响应头")
	}
}

func TestIndexSecurityHeadersAllowEmbedding(t *testing.T) {
	rec := getPage(t, "Mozilla/5.0 (X11; Linux loongarch64) Chrome/102", map[string]string{
		"Sec-Fetch-Dest": "iframe",
		"Sec-Fetch-Site": "cross-site",
		"Referer":        "http://127.0.0.1:9099/dashboard",
	})

	if got := rec.Header().Get("Content-Security-Policy"); got != "frame-ancestors *" {
		t.Errorf("csp = %q", got)
	}
	for _, must := range []string{"X-Frame-Options", "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy", "Require-Cross-Origin-Resource-Policy"} {
		if rec.Header().Get(must) != "" {
			t.Errorf("%s 会让 iframe 白屏，绝不能设置", must)
		}
	}
	if !strings.Contains(rec.Body.String(), `<body class="compact">`) {
		t.Error("iframe 请求应渲染紧凑版式")
	}
}

func TestConfiguredAncestorsAppearInHeader(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FrameAncestors = []string{"http://127.0.0.1:9099"}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, frameRequest("", map[string]string{"Sec-Fetch-Dest": "document"}))
	if got := rec.Header().Get("Content-Security-Policy"); got != "frame-ancestors http://127.0.0.1:9099" {
		t.Errorf("csp = %q", got)
	}
	if strings.Contains(rec.Body.String(), `class="compact"`) {
		t.Error("顶层文档不该走紧凑版式")
	}
}

// 回归：JS 回报片段必须同样遵守 ?hide=/?only=，
// 否则首屏隐藏的卡片会在回报替换 #report 后重新出现。
func TestReportFragmentKeepsHideParam(t *testing.T) {
	const ua = "Mozilla/5.0 (X11; Linux loongarch64) Chrome/102"
	if body := postReport(t, "/report", ua, `{}`).Body.String(); !strings.Contains(body, "IP 地址") {
		t.Fatal("无参数回报片段应有 IP 行")
	}

	rec := postReport(t, "/report?hide=ip", ua, `{}`)
	if strings.Contains(rec.Body.String(), `<th>IP 地址</th>`) {
		t.Error("回报片段应遵守 ?hide=ip，IP 行整行消失")
	}
	if !strings.Contains(rec.Body.String(), "龙芯 LoongArch") {
		t.Error("其它结论行不应受 hide=ip 影响")
	}
}

// 回报片段替换整块结果，?detail=1 展开的依据与证据必须在替换后仍然在。
func TestReportFragmentKeepsDetailParam(t *testing.T) {
	const ua = "Mozilla/5.0 (X11; Linux loongarch64) Chrome/102"
	if body := postReport(t, "/report", ua, `{}`).Body.String(); strings.Contains(body, "原始证据") {
		t.Error("默认回报片段不该带原始证据")
	}
	body := postReport(t, "/report?detail=1", ua, `{}`).Body.String()
	if !strings.Contains(body, "原始证据") || !strings.Contains(body, "判定分 100/100") {
		t.Errorf("?detail=1 回报片段应展开依据：%s", body)
	}
	// detail 模式下的证据同样受 hide=evidence 约束。
	if b := postReport(t, "/report?detail=1&hide=evidence", ua, `{}`).Body.String(); strings.Contains(b, "header.user-agent") {
		t.Error("hide=evidence 应在 detail 模式下摘掉行内证据")
	}
}

// 守卫根因：detect.js 用相对路径请求 /report 时必须带上 location.search，
// 丢掉 query 就会让上面的服务端开关全部失效。
func TestDetectJSPassesQueryToReport(t *testing.T) {
	b, err := web.Static.ReadFile("static/detect.js")
	if err != nil {
		t.Fatalf("read detect.js: %v", err)
	}
	if !strings.Contains(string(b), "'report' + location.search") {
		t.Error("detect.js 请求 /report 必须拼接 location.search，否则 ?hide=?only=?embed= 在回报后丢失")
	}
}

// 守卫根因：「复制结论」是从渲染好的 DOM 里读文本的，
// 模板改了类名或表格结构，剪贴板内容会静默变成空串或重复值。
func TestDetectJSSelectorsMatchTemplate(t *testing.T) {
	js, err := web.Static.ReadFile("static/detect.js")
	if err != nil {
		t.Fatalf("read detect.js: %v", err)
	}
	tmpl, err := web.Static.ReadFile("templates/index.html.tmpl")
	if err != nil {
		t.Fatalf("read index.html.tmpl: %v", err)
	}
	page, fragment := string(js), string(tmpl)
	for _, want := range []string{"main table.rows > tbody > tr", "'.v'", "muted"} {
		if !strings.Contains(page, want) {
			t.Errorf("detect.js 缺少选择器 %s", want)
		}
	}
	for _, want := range []string{`<table class="kv rows">`, `<span class="v"`, `<span class="muted">`} {
		if !strings.Contains(fragment, want) {
			t.Errorf("模板缺少 DOM 约定 %s", want)
		}
	}
}

func TestHideParamRemovesWholeRow(t *testing.T) {
	const ua = "Mozilla/5.0 (X11; Linux loongarch64) Chrome/102"
	if body := getPage(t, ua, nil).Body.String(); !strings.Contains(body, "IP 地址") {
		t.Fatal("基线页面应有 IP 行")
	}

	rec := httptest.NewRecorder()
	newTestServer(t).ServeHTTP(rec, frameRequest("hide=ip", map[string]string{"User-Agent": ua}))
	if strings.Contains(rec.Body.String(), `<th>IP 地址</th>`) {
		t.Error("hide=ip 后 IP 行应整行消失")
	}
	if !strings.Contains(rec.Body.String(), "龙芯 LoongArch") {
		t.Error("其它结论行不应受影响")
	}
}
