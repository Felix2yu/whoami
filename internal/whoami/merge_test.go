package whoami

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postReport(t *testing.T, target string, ua string, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	r.Header.Set("User-Agent", ua)
	rec := httptest.NewRecorder()
	newTestServer(t).ServeHTTP(rec, r)
	return rec
}

const uaLoongArch = "Mozilla/5.0 (X11; Linux loongarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36"

func TestReportEscalatesByCrossSourceAgreement(t *testing.T) {
	// UA 说 loongarch64，Client Hints 也说 loongarch/64：两条独立链路同一结论。
	rec := postReport(t, "/api/whoami", uaLoongArch,
		`{"platform":"Linux","architecture":"loongarch","bitness":"64","brands":[{"brand":"Chromium","version":"102"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var res Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !res.HasJS {
		t.Fatal("应标记已合并浏览器端回报")
	}
	if res.Verdict.Status != "confirmed" {
		t.Errorf("verdict = %+v", res.Verdict)
	}
	var arch *Finding
	for i := range res.Findings {
		if res.Findings[i].Category == CatCPU {
			arch = &res.Findings[i]
		}
	}
	if arch == nil || len(arch.Sources) != 2 {
		t.Fatalf("架构结论应跨源，实际 %+v", arch)
	}
	for _, l := range res.Verdict.Limits {
		if strings.Contains(l, "没有可用于交叉验证的信号") {
			t.Error("已收到回报却仍提示未交叉验证")
		}
	}
	if !containsStr(res.Sources, SourceJS) {
		t.Errorf("sources = %v", res.Sources)
	}
	// 架构结论 header+js 双源：JSStatus 应点名交叉印证的结论数，而非笼统宣称。
	if js := BuildView(res).JSStatus; !strings.Contains(js, "项结论经浏览器端与服务端交叉印证") {
		t.Errorf("jsStatus = %q", js)
	}
}

func TestReportGPUAddsXinchuangEvidence(t *testing.T) {
	// 只有 WebGL 能给出国产 GPU；纯 x86_64 请求头原本判不出来。
	body := `{"gpu":{"vendor":"Jingjia Micro","renderer":"JM910"},"platform":"Linux","architecture":"x86","bitness":"64"}`
	rec := postReport(t, "/api/whoami", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120", body)
	var res Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v\n%s", err, rec.Body)
	}
	// 景嘉微 GPU 的 Ceiling 是 90：JS 报出厂商串已足够定论，但留了被伪造的余量。
	if res.Verdict.Status != "confirmed" || res.Verdict.Score != 85 {
		t.Errorf("verdict = %+v, want confirmed/85", res.Verdict)
	}
	var gpu *Finding
	for i := range res.Findings {
		if res.Findings[i].Category == CatGPU {
			gpu = &res.Findings[i]
		}
	}
	if gpu == nil || gpu.Name != "景嘉微 GPU" {
		t.Fatalf("GPU 结论缺失：%+v", res.Findings)
	}
	for _, l := range res.Verdict.Limits {
		if strings.Contains(l, "没有 GPU 信号") {
			t.Error("已有 GPU 信号却仍提示缺失")
		}
	}
}

func TestSoftwareRendererIsNotEvidenceAgainstXinchuang(t *testing.T) {
	rec := postReport(t, "/api/whoami", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120",
		`{"gpu":{"vendor":"Google Inc.","renderer":"Google SwiftShader"}}`)
	var res Result
	json.Unmarshal(rec.Body.Bytes(), &res)
	for _, f := range res.Findings {
		if f.Category == CatGPU && f.Xinchuang {
			t.Errorf("软件渲染被判成国产 GPU：%+v", f)
		}
	}
	if rec.Body.String() != "" && res.Verdict.Status != "unknown" {
		t.Errorf("软件渲染不该改变结论：%+v", res.Verdict)
	}
}

func TestReportRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"不是 JSON", `not json at all`, http.StatusBadRequest},
		{"截断的 JSON", `{"platform":`, http.StatusBadRequest},
		{"顶层是数组", `[{"platform":"Linux"}]`, http.StatusBadRequest},
		{"未知字段", `{"platform":"Linux","evil":1}`, http.StatusBadRequest},
		{"类型不对", `{"cores":"many"}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		rec := postReport(t, "/api/whoami", uaLoongArch, c.body)
		if rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d（body=%s）", c.name, rec.Code, c.want, rec.Body.String())
		}
	}
}

func TestReportRejectsOversizedBody(t *testing.T) {
	// 真实回报 2–4KB；构造 64KB 的 renderer 字符串必须被挡住，而不是被读进内存。
	huge := `{"gpu":{"renderer":"` + strings.Repeat("A", 64*1024) + `"}}`
	rec := postReport(t, "/api/whoami", uaLoongArch, huge)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413（body=%s）", rec.Code, rec.Body.String())
	}

	ok := postReport(t, "/api/whoami", uaLoongArch, `{"gpu":{"renderer":"`+strings.Repeat("A", 4096)+`"}}`)
	if ok.Code != http.StatusOK {
		t.Fatalf("4KB 回报应正常接收，status = %d", ok.Code)
	}
	var res Result
	json.Unmarshal(ok.Body.Bytes(), &res)
	// 超长的单个字段在入口就被削到 maxReportString，证据与匹配都用削后的值，
	// 页面和日志不可能被一条 4KB 的厂商串撑爆。
	found := false
	for _, e := range res.Evidence {
		if e.Key == "js.gpu" {
			found = true
			if len(e.Raw) > 2*maxReportString {
				t.Errorf("js.gpu 证据未削短：%d bytes", len(e.Raw))
			}
		}
	}
	if !found {
		t.Error("缺少 js.gpu 证据")
	}
}

func TestReportValuesAreEscapedInHTML(t *testing.T) {
	payload := `{"model":"<script>alert(1)</script>","gpu":{"renderer":"<img src=x onerror=alert(2)>"}}`
	rec := postReport(t, "/report", uaLoongArch, payload)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") || strings.Contains(body, "<img src=x onerror") {
		t.Fatalf("回报内容被当成标记注入页面了：%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("应以转义形式显示")
	}
}

func TestReportFragmentReusesServerRendering(t *testing.T) {
	rec := postReport(t, "/report", uaLoongArch, `{"platform":"Linux","cores":16,"memory":8,"timezone":"Asia/Shanghai","screen":{"width":2560,"height":1440,"dpr":2}}`)
	body := rec.Body.String()
	if strings.Contains(body, "<!doctype html>") {
		t.Error("片段不该包含整页骨架")
	}
	for _, want := range []string{`<section class="banner b-confirmed">`, "龙芯 LoongArch", "逻辑核心数", "16", "2560×1440 @2x", "Asia/Shanghai", "已合并浏览器端回报"} {
		if !strings.Contains(body, want) {
			t.Errorf("片段缺少 %q", want)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}
}

func TestNormalizeClientHintValues(t *testing.T) {
	for _, c := range []struct{ arch, bits, want string }{
		{"x86", "64", "x86_64"},
		{"x86", "32", "x86_32"},
		{"Arm", "64", "aarch64"},
		{"arm", "32", "arm"},
		{"loongarch", "64", "loongarch64"},
		{"MIPS", "64", "mips64"},
		{"riscv", "64", "riscv64"},
		{"x86", "", "x86"},
		{"", "64", ""},
		{"unknown", "64", ""},
	} {
		if got := normalizeArch(c.arch, c.bits); got != c.want {
			t.Errorf("normalizeArch(%q,%q) = %q, want %q", c.arch, c.bits, got, c.want)
		}
	}

	for _, c := range []struct{ in, want string }{
		{"Windows", "windows"}, {"macOS", "macos"}, {"Chrome OS", "chromeos"},
		{"Linux", "linux"}, {"Android", "android"}, {"unknown", ""}, {"", ""},
	} {
		if got := normalizePlatform(c.in); got != c.want {
			t.Errorf("normalizePlatform(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	for _, b := range []string{"Chromium", "  Not_A Brand", "", "not?A_Brand"} {
		if got := normalizeBrand(b); (b == "Chromium") != (got != "") {
			t.Errorf("normalizeBrand(%q) = %q", b, got)
		}
	}
}

func TestReportClipsRunawayStrings(t *testing.T) {
	long := strings.Repeat("B", 4096)
	rep, err := DecodeBrowserReport(strings.NewReader(`{"model":"` + long + `","platform":"` + long + `"}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rep.Model) != maxReportString || len(rep.Platform) != maxReportString {
		t.Errorf("model=%d platform=%d, want %d", len(rep.Model), len(rep.Platform), maxReportString)
	}
	// 越界数字一律清零，避免统计与页面被假数值污染。
	rep2, err := DecodeBrowserReport(strings.NewReader(`{"cores":999999,"memory":-4,"screen":{"width":100000,"height":8,"dpr":99},"touchPoints":-1}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rep2.Cores != 0 || rep2.Memory != 0 || rep2.Screen.Width != 0 || rep2.Screen.DPR != 0 || rep2.TouchPoints != 0 {
		t.Errorf("越界值未清零：%+v", rep2)
	}
}

func TestEmptyReportIsStillUseful(t *testing.T) {
	// JS 起来但什么都取不到（禁用 CH、禁用 WebGL）：仍然是一次有效的客户端在场证明。
	rec := postReport(t, "/api/whoami", uaLoongArch, `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var res Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.HasJS {
		t.Error("有回报即算客户端在场")
	}
	// HasJS 只看信号来源，空回报不应把 GPU 缺失的提示抹掉。
	joined := strings.Join(res.Verdict.Limits, "|")
	if !strings.Contains(joined, "没有 GPU 信号") {
		t.Errorf("空回报时仍应说明 GPU 缺位：%s", joined)
	}
	// 空回报时文案不得自相矛盾、也不得宣称交叉印证。
	if strings.Contains(joined, "没有收到浏览器端回报") {
		t.Errorf("已收到空回报却说没收到：%s", joined)
	}
	if js := BuildView(res).JSStatus; !strings.Contains(js, "已收到浏览器端回报") || strings.Contains(js, "交叉印证") {
		t.Errorf("空回报的 JSStatus = %q", js)
	}
	if res.Browser != (BrowserFacts{}) {
		t.Errorf("空回报不该有展示事实：%+v", res.Browser)
	}
}

func TestDecodeRejectsUnlimitedReaderSafely(t *testing.T) {
	if _, err := DecodeBrowserReport(strings.NewReader("")); err == nil {
		t.Error("空 body 应报错")
	}
	if _, err := DecodeBrowserReport(io.LimitReader(strings.NewReader(`{"platform":"x"`), 8)); err == nil {
		t.Error("截断的 body 应报错")
	}
}
