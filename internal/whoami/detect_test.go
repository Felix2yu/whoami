package whoami

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

func uaSignals(ua string) Signals {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", ua)
	ss, _ := Collect(r)
	return ss
}

func sig(field, value, source string) Signal {
	return Signal{Field: field, Value: value, Source: source, EvidenceKey: "test." + source + "." + field}
}

func verdictOf(t *testing.T, ua string) (Verdict, []Finding) {
	t.Helper()
	fs, v := builtinDetector(t).score(uaSignals(ua))
	return v, fs
}

func TestVerdictCorpus(t *testing.T) {
	cases := loadVerdictCases(t)
	d := builtinDetector(t)
	for _, tc := range cases {
		fs, v := d.score(uaSignals(tc.ua))
		if v.Status != tc.status {
			t.Errorf("%s: status = %s(score %d), want %s；findings = %s",
				tc.id, v.Status, v.Score, tc.status, findingsString(fs))
		}
		if tc.topXc == "-" {
			for _, f := range fs {
				if f.Xinchuang && f.Score >= ConfidenceSuspect {
					t.Errorf("%s: 期望没有信创结论，但出现 %s(%d)", tc.id, f.Name, f.Score)
				}
			}
			continue
		}
		if len(v.Reasons) == 0 || !strings.Contains(v.Reasons[0], tc.topXc) {
			t.Errorf("%s: 最高分结论应含 %q，实际 %v", tc.id, tc.topXc, v.Reasons)
		}
	}
}

func TestCeilingBeatsCrossSourceAgreement(t *testing.T) {
	d := builtinDetector(t)
	// 架构信号跨源一致，但 aarch64 本身推不出信创机型：一致只能确认「这是 ARM」，
	// 不能确认「这是飞腾/鲲鹏」，所以判定分仍被 Ceiling 压在疑似。
	ss := Signals{
		sig(FieldArch, "aarch64", SourceHeader),
		sig(FieldArch, "aarch64", SourceJS),
		sig(FieldPlatform, "linux", SourceHeader),
	}
	fs, v := d.score(ss)
	var arm *Finding
	for i := range fs {
		if fs[i].RuleIDs[0] == "cpu-aarch64" {
			arm = &fs[i]
		}
	}
	if arm == nil {
		t.Fatalf("cpu-aarch64 未命中: %s", findingsString(fs))
	}
	if arm.Confidence < ConfidenceConfirmed {
		t.Errorf("跨源一致应把证据强度抬到确认区间，实际 confidence = %d", arm.Confidence)
	}
	if arm.Score != 50 || v.Status != "suspect" {
		t.Errorf("score = %d status = %s, want 50/suspect（天花板压住）", arm.Score, v.Status)
	}
	if len(v.Limits) == 0 {
		t.Error("天花板压住时必须给出 Limits 说明，页面不能只报疑似")
	}
}

func TestHardArchConfirmsAcrossSources(t *testing.T) {
	d := builtinDetector(t)
	ss := Signals{
		sig(FieldArch, "loongarch64", SourceHeader),
		sig(FieldArch, "loongarch64", SourceJS),
	}
	_, v := d.score(ss)
	if v.Status != "confirmed" || v.Score != 100 {
		t.Errorf("verdict = %+v, want confirmed/100", v)
	}
	if !strings.Contains(v.Reasons[0], "header+js") {
		t.Errorf("reason 应写明交叉来源，实际 %v", v.Reasons)
	}
}

func TestConflictingXinchuangConclusionsBothDemoted(t *testing.T) {
	d := builtinDetector(t)
	// 统信与麒麟两个发行版标识同时出现，说明 UA 被改过或规则误伤，只能算疑似。
	ss := Signals{
		sig(FieldUA, "Mozilla/5.0 (X11; UOS; Linux x86_64; Kylin) Chrome/120", SourceHeader),
	}
	fs, v := d.score(ss)
	if v.Status != "suspect" {
		t.Errorf("status = %s(score %d), want suspect；%s", v.Status, v.Score, findingsString(fs))
	}
	var conflicted int
	for _, f := range fs {
		for _, n := range f.Notes {
			if strings.Contains(n, "互斥的信创结论") {
				conflicted++
			}
		}
	}
	if conflicted != 2 {
		t.Errorf("应有两条信创结论被冲突降级，实际 %d 条：%s", conflicted, findingsString(fs))
	}
}

func TestSameFactIsNotAConflict(t *testing.T) {
	d := builtinDetector(t)
	// ARM 32/64 并存、Chrome 与 Edge 内核 token 并存都是常见事实，不能被冲突逻辑打回疑似。
	ss := Signals{
		sig(FieldArch, "aarch64", SourceHeader),
		sig(FieldArch, "arm", SourceCH),
		sig(FieldUA, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0", SourceHeader),
		sig(FieldBrand, "microsoft edge", SourceCH),
	}
	fs, _ := d.score(ss)
	for _, f := range fs {
		for _, n := range f.Notes {
			if strings.Contains(n, "互斥的信创结论") {
				t.Fatalf("不该触发冲突降级：%s", findingsString(fs))
			}
		}
	}
	var engine *Finding
	for i := range fs {
		if fs[i].Name == "Microsoft Edge" {
			engine = &fs[i]
		}
	}
	if engine == nil || len(engine.Sources) != 2 {
		t.Fatalf("Edge 应由 UA 与 CH 交叉确认：%+v", engine)
	}
}

// UA 被冻结成 x86_64、Client Hints 说出 loongarch 是真机上常见的组合：
// 结论应该跟更硬的信号走，但矛盾必须写在页面上。
func TestHarderSignalWinsButDisagreementIsNoted(t *testing.T) {
	d := builtinDetector(t)
	ss := Signals{
		sig(FieldUA, "Mozilla/5.0 (X11; Linux x86_64) Chrome/120", SourceHeader),
		sig(FieldArch, "x86_64", SourceHeader),
		sig(FieldArch, "loongarch64", SourceJS),
	}
	fs, v := d.score(ss)
	if v.Status != "confirmed" || v.Score != 100 {
		t.Errorf("龙芯信号应压过被冻结的 UA：%+v", v)
	}
	var noted bool
	for _, f := range fs {
		if f.Name == "龙芯 LoongArch" {
			for _, n := range f.Notes {
				if strings.Contains(n, "不一致的信号") && strings.Contains(n, "x86") {
					noted = true
				}
			}
		}
	}
	if !noted {
		t.Errorf("矛盾没写进页面：%+v", fs)
	}
}

func TestPlatformSuppressionBlocksArmFalsePositive(t *testing.T) {
	d := builtinDetector(t)
	// 安卓机上报 ARM：平台规则应压制 ARM 的信创含义。
	ss := Signals{
		sig(FieldPlatform, "android", SourceHeader),
		sig(FieldArch, "aarch64", SourceJS),
	}
	fs, v := d.score(ss)
	if v.Status != "unknown" {
		t.Errorf("安卓 ARM 被判成信创：%+v %s", v, findingsString(fs))
	}
	for _, f := range fs {
		if f.Name == "ARM 64 位" && f.Xinchuang {
			t.Error("抑制后 ARM 结论不应再参与信创判定")
		}
	}
}

func TestMacAndWindowsArmAreNotXinchuang(t *testing.T) {
	// Apple Silicon 与 Windows on ARM 同样上报 aarch64，平台规则必须压掉信创含义，
	// 否则 M 系列 Mac 会被判成 50 分疑似信创。
	for _, tc := range []struct{ name, platform, ua string }{
		{"Apple Silicon", "macos",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) TRAESOLOCN/1.107.1 Chrome/142.0.7444.235 Electron/39.2.7 Safari/537.36"},
		{"Windows on ARM", "windows",
			"Mozilla/5.0 (Windows NT 10.0; ARM64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
	} {
		d := builtinDetector(t)
		ss := Signals{
			sig(FieldUA, tc.ua, SourceHeader),
			sig(FieldPlatform, tc.platform, SourceHeader),
			sig(FieldArch, "aarch64", SourceJS),
			sig(FieldArch, "aarch64", SourceCH),
		}
		fs, v := d.score(ss)
		if v.Status == "suspect" || v.Status == "confirmed" {
			t.Errorf("%s 被判成信创：%+v %s", tc.name, v, findingsString(fs))
		}
		for _, f := range fs {
			if f.Name == "ARM 64 位" && f.Xinchuang {
				t.Errorf("%s：抑制后 ARM 结论不应再参与信创判定", tc.name)
			}
		}
	}
}

func TestUnknownNeverClaimsNonXinchuang(t *testing.T) {
	// 通用 Linux x86_64：海光/兆芯与 Intel/AMD 在 HTTP 信号上无法区分，只能判不出，绝不能说「不是」。
	v, _ := verdictOf(t, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
	if v.Status != "unknown" {
		t.Fatalf("status = %s", v.Status)
	}
	joined := strings.Join(v.Reasons, "|") + strings.Join(v.Limits, "|")
	if strings.Contains(joined, "不是信创终端") {
		t.Errorf("判不出来不得输出否定断言：%s", joined)
	}
	if !strings.Contains(joined, "冻结") {
		t.Errorf("unknown 要解释 UA 可能被策略冻结：%s", joined)
	}
}

func TestForeignPlatformIsADefiniteNegative(t *testing.T) {
	// macOS / Windows：信创终端的前提是跑国产操作系统，境外系统本身就是证据，
	// 再报「未知」等于把能确定的事说成不确定。
	for _, ua := range []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
	} {
		v, fs := verdictOf(t, ua)
		if v.Status != "excluded" {
			t.Errorf("status = %s，want excluded；%s", v.Status, findingsString(fs))
			continue
		}
		if !strings.Contains(strings.Join(v.Reasons, "|"), "不是信创终端") {
			t.Errorf("否定结论要写清楚：%v", v.Reasons)
		}
		if len(v.Limits) != 0 {
			t.Errorf("已经判定的事不必再挂缺信号提示：%v", v.Limits)
		}
	}
}

// WebGL 串不受 https 限制，但只有 Apple 显卡能定整机；
// Intel/NVIDIA/虚拟显卡都可能出现在国产整机上，说「不是」就是误伤。
func TestOnlyAppleGPUCanNegate(t *testing.T) {
	d := builtinDetector(t)
	// 政企冻结串：UA 里没有系统家族信息，只剩架构。
	base := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
	score := func(gpu string) (Verdict, []Finding) {
		t.Helper()
		fs, v := d.score(Signals{
			sig(FieldUA, base, SourceHeader),
			sig(FieldGPU, gpu, SourceJS),
		})
		return v, fs
	}
	for _, apple := range []string{
		"Apple M1, or similar Apple", // Firefox 降熵后的写法
		"ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version) Google Inc. (Apple)",
		"Apple GPU Apple Inc.", // Safari / iOS
	} {
		v, fs := score(apple)
		if v.Status != "excluded" {
			t.Errorf("%q 应判「不是」，实际 %s：%s", apple, v.Status, findingsString(fs))
		}
	}
	for _, gpu := range []string{
		"ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11) NVIDIA",
		"ANGLE (Intel, Intel(R) UHD Graphics 630, Direct3D11) Intel",
		"ANGLE (Microsoft, Microsoft Basic Render Driver) Microsoft",
		"ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device)) Google",
	} {
		if v, _ := score(gpu); v.Status != "unknown" {
			t.Errorf("%q 不该给否定结论，实际 %s", gpu, v.Status)
		}
	}
	// 信创信号仍然优先：龙芯机器 + 伪造的 Apple 显卡串，判「是」不判「不是」。
	_, v := d.score(Signals{
		sig(FieldArch, "loongarch64", SourceHeader),
		sig(FieldGPU, "Apple M1 Apple", SourceJS),
	})
	if v.Status != "confirmed" {
		t.Errorf("信创信号应压过境外显卡，实际 %s", v.Status)
	}
}

func TestForeignYieldsToXinchuangEvidenceAndStaysQuietOnAndroid(t *testing.T) {
	// 麒麟浏览器 + Windows：信创信号优先，仍是疑似，不能说「不是」——
	// 奇安信浏览器本身也有 Windows 版，谁更硬要交给打分而不是系统家族。
	v, _ := verdictOf(t, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124 QaxBrowser/1.0.0.20 Safari/537.36")
	if v.Status != "suspect" {
		t.Errorf("status = %s, want suspect", v.Status)
	}
	// 安卓与鸿蒙同理不给否定：国产平板和鸿蒙兼容层一样报 Android。
	for _, ua := range []string{
		"Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Phone; HarmonyOS 4.0) AppleWebKit/537.36 Chrome/114.0.0.0 Mobile Safari/537.36",
	} {
		if v, _ := verdictOf(t, ua); v.Status != "unknown" {
			t.Errorf("%s: status = %s, want unknown", ua, v.Status)
		}
	}
}

func TestLimitsMentionMissingClientReport(t *testing.T) {
	d := builtinDetector(t)
	_, v := d.score(uaSignals("Mozilla/5.0 (X11; Linux loongarch64) Chrome/102"))
	joined := strings.Join(v.Limits, "|")
	if !strings.Contains(joined, "没有可用于交叉验证的信号") {
		t.Errorf("仅有服务端信号时应提示未经交叉验证：%s", joined)
	}

	ss := append(uaSignals("Mozilla/5.0 (X11; Linux loongarch64) Chrome/102"), sig(FieldGPU, "Jingjia Micro JM9", SourceJS))
	_, v2 := d.score(ss)
	joined2 := strings.Join(v2.Limits, "|")
	if strings.Contains(joined2, "没有可用于交叉验证的信号") {
		t.Errorf("已收到 JS 回报后不该再出现该提示：%s", joined2)
	}
	if strings.Contains(joined2, "没有 GPU 信号") {
		t.Errorf("已有 GPU 信号：%s", joined2)
	}
}

func TestMergedFindingUnionsSameConclusion(t *testing.T) {
	d := builtinDetector(t)
	ss := Signals{
		sig(FieldUA, "Mozilla/5.0 (X11; Linux x86_64; UOS; uniontech) Chrome/120", SourceHeader),
	}
	fs, _ := d.score(ss)
	var uos *Finding
	for i := range fs {
		if fs[i].Name == "统信 UOS" {
			uos = &fs[i]
		}
	}
	if uos == nil {
		t.Fatalf("统信 UOS 未命中：%s", findingsString(fs))
	}
	if len(uos.RuleIDs) != 2 {
		t.Errorf("os-uos 与 os-uniontech 应合并成一条结论，实际 %v", uos.RuleIDs)
	}
	if len(uos.Notes) != 2 {
		t.Errorf("两条规则的说明都应保留，实际 %v", uos.Notes)
	}
	// 同一来源的多个 token 不算跨源，不能凭此升级。
	if len(uos.Sources) != 1 {
		t.Errorf("sources = %v, want [header]", uos.Sources)
	}
}

func TestDetectAssemblesResult(t *testing.T) {
	d := builtinDetector(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux loongarch64; Kylin) Chrome/102")
	ss, ev := Collect(r)
	ip, ipEv := ResolveClientIP(r, nil)
	res := d.Detect(append(ss, sig(FieldIPLabel, "测试网", SourceIP)), append(ev, ipEv...), ip)

	if want := len(ev) + len(ipEv); len(res.Evidence) != want {
		t.Fatalf("evidence = %d, want %d", len(res.Evidence), want)
	}
	if len(res.Findings) == 0 {
		t.Fatal("没有 findings")
	}
	if !containsStr(res.Sources, SourceHeader) || !containsStr(res.Sources, SourceConn) || !containsStr(res.Sources, SourceIP) {
		t.Errorf("sources = %v", res.Sources)
	}
	if res.HasJS {
		t.Error("本轮没有 JS 回报")
	}
	if res.Verdict.Status != "confirmed" {
		t.Errorf("verdict = %+v", res.Verdict)
	}
	if res.Time.IsZero() {
		t.Error("result 应带时间戳")
	}
	if _, err := json.Marshal(res); err != nil {
		t.Fatalf("result 必须可 JSON 序列化: %v", err)
	}
}

func TestScoreIsDeterministicAndConcurrencySafe(t *testing.T) {
	d := builtinDetector(t)
	ss := uaSignals("Mozilla/5.0 (X11; Linux aarch64; Kylin) AppleWebKit/537.36 (KHTML, like Gecko) Kylinbrowser/1.2.1 Chrome/78 Safari/537.36")
	snapshot := func() string {
		fs, v := d.score(ss)
		b, err := json.Marshal(struct {
			Findings []Finding
			Verdict  Verdict
		}{fs, v})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	want := snapshot()
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := snapshot(); got != want {
				t.Errorf("并发打分结果不一致：\n%s\n%s", got, want)
			}
		}()
	}
	wg.Wait()
}

func findingsString(fs []Finding) string {
	var parts []string
	for _, f := range fs {
		parts = append(parts, fmt.Sprintf("%s(%d/%d,xc=%v,sources=%v)",
			f.Name, f.Confidence, f.Score, f.Xinchuang, f.Sources))
	}
	return strings.Join(parts, " ")
}

type verdictCase struct {
	id     string
	status string
	topXc  string
	ua     string
}

func loadVerdictCases(t *testing.T) []verdictCase {
	t.Helper()
	b, err := os.ReadFile("testdata/verdict_cases.tsv")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var out []verdictCase
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 4 {
			t.Fatalf("判定语料应为 4 列：%q", line)
		}
		out = append(out, verdictCase{id: f[0], status: f[1], topXc: f[2], ua: f[3]})
	}
	if len(out) < 12 {
		t.Fatalf("判定语料只有 %d 条", len(out))
	}
	return out
}
