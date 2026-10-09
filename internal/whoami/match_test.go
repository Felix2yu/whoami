package whoami

import (
	"regexp"
	"testing"
)

func TestMatchAndAcrossClausesOrWithinThem(t *testing.T) {
	m := Match{Contains: []string{"uos", "kylin"}, Regex: []string{`chrome/[\d.]`}, CaseFold: true}

	if !m.Hit("Mozilla/5.0 (X11; UOS) Chrome/120.0.0.0") {
		t.Fatal("should hit: 第一个 Contains 成立且正则成立")
	}
	if !m.Hit("Mozilla/5.0 (X11; Kylin) Chrome/120.0.0.0") {
		t.Fatal("should hit: Contains 列表内是或")
	}
	if m.Hit("Mozilla/5.0 (X11; UOS) Safari/605.1.15") {
		t.Fatal("should not hit: 子句之间是与，缺 Chrome token 就不命中")
	}
	if m.Hit("Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0") {
		t.Fatal("should not hit: 两个 Contains 都不成立")
	}
}

func TestEmptyMatchNeverHits(t *testing.T) {
	// 漏写字段的规则不能变成「命中所有人」。
	for _, v := range []string{"", "Mozilla/5.0 (X11; UOS) Chrome/120", "anything"} {
		if (&Match{}).Hit(v) {
			t.Fatalf("empty Match hit %q", v)
		}
	}
	var nilMatch *Match
	if nilMatch.Hit("Mozilla/5.0") {
		t.Fatal("nil Match should never hit")
	}
}

func TestCaseFoldOffIsByteExact(t *testing.T) {
	fold := Match{Contains: []string{"uos"}, CaseFold: true}
	strict := Match{Contains: []string{"uos"}}

	if !fold.Hit("X11; UOS; Linux") {
		t.Fatal("CaseFold 应命中大写 UOS")
	}
	if strict.Hit("X11; UOS; Linux") {
		t.Fatal("未开 CaseFold 时不该命中大写")
	}
	if !strict.Hit("X11; uos; Linux") {
		t.Fatal("未开 CaseFold 时小写原样命中")
	}
}

func TestWordBoundaries(t *testing.T) {
	cases := []struct {
		value, word string
		want        bool
	}{
		{"Mozilla/5.0 (X11; UOS; Linux x86_64)", "uos", true},
		{"Mozilla/5.0 (X11; UOS)", "uos", true},
		{"Mozilla/5.0 (Linux; UOS)", "uos", true},
		{"Mozilla/5.0 (X11; UOS-Browser/2.1)", "uos", true},
		{"continuous improvement", "uos", false}, // 词内不算整词
		{"KYLINOS/10", "kylin", false},           // 粘连写法要另列 token
		{"Mozilla/5.0 (X11; Kylin) Chrome/78", "kylin", true},
		{"mips64", "mips", false},
		{"", "uos", false},
		{"uos", "uos", true},
		{"1uos2", "uos", false},
	}
	for _, c := range cases {
		got := hasWord(c.value, c.word, true)
		if got != c.want {
			t.Errorf("hasWord(%q, %q) = %v, want %v", c.value, c.word, got, c.want)
		}
	}
	if hasWord("abc", "", true) {
		t.Error("empty word must not match")
	}
}

func TestNotClause(t *testing.T) {
	m := Match{Contains: []string{"chrome"}, Not: &Match{Contains: []string{"qaxbrowser"}}, CaseFold: true}
	if !m.Hit("Mozilla/5.0 Chrome/120") {
		t.Fatal("should hit")
	}
	if m.Hit("Mozilla/5.0 Chrome/120 QaxBrowser/1.0") {
		t.Fatal("Not 命中应整体不命中")
	}
	// Not 自身可以是复合条件。
	m2 := Match{Word: []string{"kylin"}, Regex: []string{`chrome/`}, CaseFold: true,
		Not: &Match{Word: []string{"browser"}}}
	// 继承 CaseFold 后，Not 子句同样不区分大小写。
	if !m2.Hit("X11; Kylin; Chrome/78") {
		t.Fatal("Not 未命中时不应排除")
	}
	if m2.Hit("X11; Kylin Browser Chrome/78") {
		t.Fatal("Not 命中（大写 Browser）时应排除，CaseFold 没继承下去")
	}
}

func TestRegexIsCaseFoldedWhenRequested(t *testing.T) {
	m := Match{Regex: []string{`(uos|uniontech)[ _-]?browser`}, CaseFold: true}
	for _, v := range []string{"UOSBrowser/2.1", "uos-browser/1.0", "UnionTech Browser"} {
		if !m.Hit(v) {
			t.Errorf("should hit %q", v)
		}
	}
	if m.Hit("Safari/537.36") {
		t.Error("should not hit")
	}
}

func TestInvalidRegexReportedAtStartupAndIgnoredAtRuntime(t *testing.T) {
	bad := Match{Regex: []string{`chrome/((`}, CaseFold: true}
	if err := bad.Valid(); err == nil {
		t.Fatal("Valid should reject broken pattern")
	}
	if bad.Hit("Chrome/120") {
		t.Fatal("runtime should treat uncompilable pattern as no-hit, never panic")
	}
	if err := (*Match)(nil).Valid(); err != nil {
		t.Fatalf("nil Match is valid: %v", err)
	}
}

func TestRegexCompilationIsShared(t *testing.T) {
	p := `jingjia|景嘉微|\bjm[0-9]`
	re1, err := compileRegex(p, true)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	re2, _ := compileRegex(p, true)
	if re1 != re2 {
		t.Fatal("相同 pattern 应复用同一编译结果")
	}
	if !re1.MatchString("JingJia Micro JM9") {
		t.Fatal("regex 语义回归")
	}
	if _, err := regexp.Compile(`(?i)\bjm[0-9]`); err != nil {
		t.Fatalf("(?i) 前缀不该破坏 pattern: %v", err)
	}
}
