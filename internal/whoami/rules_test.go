package whoami

import (
	"bufio"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func builtinDetector(t *testing.T) *Detector {
	t.Helper()
	d, err := NewDetector(BuiltinRules())
	if err != nil {
		t.Fatalf("NewDetector: %v", err)
	}
	return d
}

// uaRules 只喂 UA，用来单测 UA 相关规则，不掺入 CH/JS 信号。
func uaRules(t *testing.T, d *Detector, ua string) map[string]bool {
	t.Helper()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", ua)
	ss, _ := Collect(r)
	matched := map[string]bool{}
	for _, f := range d.MatchRules(ss) {
		for _, id := range f.RuleIDs {
			matched[id] = true
		}
	}
	return matched
}

func TestBuiltinRulesAreWellFormed(t *testing.T) {
	rules := BuiltinRules()
	if len(rules) < 40 {
		t.Fatalf("规则表缩水到 %d 条，种子数据应该覆盖架构/发行版/浏览器/GPU", len(rules))
	}
	seen := map[string]bool{}
	for _, ru := range rules {
		if seen[ru.ID] {
			t.Errorf("规则 ID 重复：%s", ru.ID)
		}
		seen[ru.ID] = true
		if ru.Field == "" {
			t.Errorf("规则 %s 缺少 Field", ru.ID)
		} else if !strings.HasPrefix(ru.Field, "ua") && ru.Field != FieldArch && ru.Field != FieldPlatform &&
			ru.Field != FieldBrand && ru.Field != FieldGPU && ru.Field != FieldLang && ru.Field != FieldIPLabel {
			t.Errorf("规则 %s 引用了未知字段 %q", ru.ID, ru.Field)
		}
		if ru.Xinchuang && ru.Ceiling < ConfidenceSuspect {
			t.Errorf("规则 %s 标了信创但 Ceiling=%d 低于疑似阈值，等于永远不参与判定", ru.ID, ru.Ceiling)
		}
	}
}

func TestDetectorRejectsBadTables(t *testing.T) {
	base := BuiltinRules()
	cases := []struct {
		name   string
		mutate func([]Rule) []Rule
	}{
		{"重复 ID", func(rs []Rule) []Rule { return append(rs, rs[0]) }},
		{"缺 ID", func(rs []Rule) []Rule {
			cp := append([]Rule(nil), rs...)
			cp[0].ID = ""
			return append(rs, cp[0])
		}},
		{"缺 Name", func(rs []Rule) []Rule {
			ru := rs[0]
			ru.ID, ru.Name = "tmp-name", ""
			return append(rs, ru)
		}},
		{"权重越界", func(rs []Rule) []Rule {
			ru := rs[0]
			ru.ID, ru.Weight = "tmp-weight", 120
			return append(rs, ru)
		}},
		{"天花板越界", func(rs []Rule) []Rule {
			ru := rs[0]
			ru.ID, ru.Ceiling = "tmp-ceiling", -5
			return append(rs, ru)
		}},
		{"坏正则", func(rs []Rule) []Rule {
			ru := rs[0]
			ru.ID, ru.Match = "tmp-regex", Match{Regex: []string{`((`}}
			return append(rs, ru)
		}},
		{"抑制目标不存在", func(rs []Rule) []Rule {
			ru := rs[0]
			ru.ID, ru.Suppresses = "tmp-suppress", []string{"no-such-rule"}
			return append(rs, ru)
		}},
	}
	for _, c := range cases {
		if _, err := NewDetector(c.mutate(base)); err == nil {
			t.Errorf("%s: 应该报错但通过了", c.name)
		}
	}
}

type uaCase struct {
	id     string
	expect []string
	forbid []string
	ua     string
}

func loadUACases(t *testing.T) []uaCase {
	t.Helper()
	f, err := os.Open("testdata/ua_cases.tsv")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	var out []uaCase
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Fatalf("fixture 行应为 4 列：%q", line)
		}
		split := func(v string) []string {
			if v == "-" {
				return nil
			}
			return strings.Split(v, ",")
		}
		out = append(out, uaCase{id: fields[0], expect: split(fields[1]), forbid: split(fields[2]), ua: fields[3]})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	if len(out) < 15 {
		t.Fatalf("fixture 只有 %d 条，信创语料至少要有 15 条", len(out))
	}
	return out
}

func TestUACorpusHitsExpectedRules(t *testing.T) {
	d := builtinDetector(t)
	for _, tc := range loadUACases(t) {
		matched := uaRules(t, d, tc.ua)
		for _, id := range tc.expect {
			if !matched[id] {
				t.Errorf("%s: 期望命中 %s，实际命中 %v", tc.id, id, keys(matched))
			}
		}
		for _, id := range tc.forbid {
			if matched[id] {
				t.Errorf("%s: 期望不命中 %s，实际命中 %v", tc.id, id, keys(matched))
			}
		}
	}
}

func TestMatchedFindingCarriesSourceAndEvidence(t *testing.T) {
	d := builtinDetector(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux loongarch64) Chrome/102.0.0.0")
	r.Header.Set("Sec-CH-UA-Arch", `"loongarch"`)
	ss, ev := Collect(r)

	findings := d.MatchRules(ss)
	var loong *Finding
	for i := range findings {
		if findings[i].RuleIDs[0] == "cpu-loongarch64" {
			loong = &findings[i]
		}
	}
	if loong == nil {
		t.Fatalf("cpu-loongarch64 未命中，findings = %+v", findings)
	}
	if !loong.Xinchuang {
		t.Error("龙芯应标为信创")
	}
	// UA 与 Client Hints 两个来源各说一次，是后续跨源一致的原料。
	if len(loong.Sources) != 2 {
		t.Errorf("sources = %v, want [header ch]", loong.Sources)
	}
	if len(loong.EvidenceKeys) == 0 {
		t.Error("finding 必须能展开出原始证据")
	}
	for _, key := range loong.EvidenceKeys {
		if !hasEvidence(ev, key) {
			t.Errorf("证据 %s 不在证据集里", key)
		}
	}
}

// 追加 token 只动数据，不动逻辑：这是规则表存在的意义。
func TestAppendingRuleNeedsNoCodeChange(t *testing.T) {
	d := builtinDetector(t)
	const novel = "Mozilla/5.0 (X11; Linux x86_64; fangde-desktop) Chrome/120"
	if matched := uaRules(t, d, novel); matched["os-fangde"] {
		t.Skip("种子表已覆盖该 token")
	}

	extra := Rule{ID: "os-fangde-desktop", Field: FieldUA, Match: Match{Contains: []string{"fangde-desktop"}, CaseFold: true},
		Name: "中科方德 NFS", Domain: "发行版", Category: CatOS, Domestic: true, Xinchuang: true,
		Weight: 70, Ceiling: 60, Verified: false, Note: "预留条目实测后转正"}
	d2, err := NewDetector(append(BuiltinRules(), extra))
	if err != nil {
		t.Fatalf("NewDetector: %v", err)
	}
	if matched := uaRules(t, d2, novel); !matched["os-fangde-desktop"] {
		t.Fatalf("追加规则未生效，命中 %v", keys(matched))
	}
	if matched := uaRules(t, d2, "Mozilla/5.0 (X11; UOS) Chrome/120"); !matched["os-uos"] {
		t.Fatal("追加规则不应影响原有命中")
	}
}

// TestEveryRuleHitsItsProbe 给每条规则一份「包含它所有 token」的探针语料，
// 保证规则表里不会躺着写错大小写、写错字段或永远命中不了的死条目。
func TestEveryRuleHitsItsProbe(t *testing.T) {
	d := builtinDetector(t)
	probes := map[string][]string{
		FieldUA:       {"Mozilla/5.0 (X11; UOS; Linux loongarch64; Kylin; deepin; uniontech; kylinos; openEuler; Anolis; fangde; pvdrvos; OpenKylin; UbuntuKylin; Loongnix; honglian; Kylinbrowser/1.2; QaxBrowser/1.0; UOSBrowser/2.1; 360SE; 360EE; QQBrowser/13.8; MQQBrowser/13.8; MetaSr/1.0; SogouMobileBrowser/5.23; SogouMSE; UCBrowser/13.4; UCWEB; UBrowser/6.2; Maxthon/5.2; LBBROWSER; liebaofast/5.21; 2345Chrome; TencentTraveler/9.0; HuaweiBrowser/14.0; MiuiBrowser/14.0; HeyTapBrowser/40.0; OppoBrowser/10.5; VivoBrowser/22.0; Quark/10.18; QuarkPC/1.0; HonorBrowser/8.2; baiduboxapp/13.8; LCTE; OPR/105.0; Vivaldi/6.5; Ubuntu; Kubuntu; Lubuntu; Fedora; Debian; CentOS; Red Hat; openSUSE; Arch Linux; Gentoo; Linux Mint; FreeBSD; Chrome/120.0.0.0; Edge/120.0.0.0; Firefox/121.0; Version/17.4 Safari/605.1.15) AppleWebKit/537.36"},
		FieldArch:     {"loongarch64", "sw_64", "mips64", "mips", "aarch64", "arm64", "riscv64", "arm", "ppc64", "x86_64", "x86_32"},
		FieldPlatform: {"linux", "windows", "macos", "android", "ios", "chromeos", "harmonyos", "freebsd", "openbsd", "netbsd"},
		FieldBrand:    {"google chrome", "chromium", "microsoft edge", "firefox", "kylin", "uos", "qaxbrowser"},
		FieldGPU:      {"Jingjia Micro JM910", "Moore Threads MTT S80", "Loongson 7A", "Innosilicon IDX", "Google Inc. (Intel) SwiftShader", "llvmpipe"},
	}
	unverified := 0
	for _, ru := range d.Rules() {
		ps, ok := probes[ru.Field]
		if !ok {
			t.Errorf("规则 %s 的字段 %q 没有探针语料", ru.ID, ru.Field)
			continue
		}
		hit := false
		for _, p := range ps {
			if ru.Match.Hit(p) {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("规则 %s 在所有探针上都不命中，token 或字段可能写错了", ru.ID)
		}
		if !ru.Verified {
			unverified++
		}
	}
	// 预留条目允许存在，但必须是有上限的少数，否则规则表就是在猜。
	// 10 条 = 既有 7 条 + openKylin/优麒麟/Loongnix 三个待实测的信创发行版。
	if unverified > 10 {
		t.Errorf("待实测规则 %d 条，超过 10 条说明语料验证没跟上", unverified)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
