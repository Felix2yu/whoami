package whoami

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func reqWith(headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := headers["Accept"]; !ok {
		r.Header.Set("Accept", "text/html")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func fieldValues(ss Signals, field string) []string { return ss.Values(field) }

func TestCollectCarriesUAArchAndPlatform(t *testing.T) {
	ss, ev := Collect(reqWith(map[string]string{"User-Agent": "Mozilla/5.0 (X11; Linux loongarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36"}))

	if got := fieldValues(ss, FieldUA); len(got) != 1 {
		t.Fatalf("ua signals = %v", got)
	}
	if got := fieldValues(ss, FieldArch); len(got) != 1 || got[0] != "loongarch64" {
		t.Fatalf("arch = %v, want [loongarch64]", got)
	}
	if got := fieldValues(ss, FieldPlatform); len(got) != 1 || got[0] != "linux" {
		t.Fatalf("platform = %v, want [linux]", got)
	}
	if len(ev) != 1 || ev[0].Key != "header.user-agent" || ev[0].Source != SourceHeader {
		t.Fatalf("evidence = %+v", ev)
	}
	for _, s := range ss {
		if s.EvidenceKey == "" {
			t.Fatalf("signal %+v has no evidence key", s)
		}
	}
}

func TestArchFromUA(t *testing.T) {
	cases := []struct{ ua, want string }{
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36", "x86_64"},
		{"Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36", "aarch64"},
		{"Mozilla/5.0 (X11; Linux loongarch64) Chrome/102", "loongarch64"},
		{"Mozilla/5.0 (X11; Linux sw_64) Chrome/92", "sw_64"},
		{"Mozilla/5.0 (X11; Linux mips64; deepin)", "mips64"},
		{"Mozilla/5.0 (X11; Linux riscv64)", "riscv64"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "x86_64"},
		{"Mozilla/5.0 (Windows NT 10.0; WOW64)", "x86_32"},
		{"Mozilla/5.0 (X11; Linux armv7l)", "arm"},
		// Apple Silicon 的 Safari 也写 Intel，绝不能据此报 x86。
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15", ""},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)", ""},
		{"curl/8.4.0", ""},
	}
	for _, c := range cases {
		if got := ArchFromUA(c.ua); got != c.want {
			t.Errorf("ArchFromUA(%q) = %q, want %q", c.ua, got, c.want)
		}
	}
}

func TestPlatformFromUA(t *testing.T) {
	cases := []struct{ ua, want string }{
		{"Mozilla/5.0 (Linux; Android 13; SM-G991B)", "android"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)", "ios"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "macos"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows"},
		{"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0)", "chromeos"},
		{"Mozilla/5.0 (X11; Linux x86_64)", "linux"},
		{"Mozilla/5.0 (compatible; Googlebot/2.1)", ""},
	}
	for _, c := range cases {
		if got := PlatformFromUA(c.ua); got != c.want {
			t.Errorf("PlatformFromUA(%q) = %q, want %q", c.ua, got, c.want)
		}
	}
}

func TestCollectMergesClientHintsAcrossSources(t *testing.T) {
	r := reqWith(map[string]string{
		"User-Agent":                 "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
		"Sec-CH-UA-Platform":         `"Windows"`,
		"Sec-CH-UA-Arch":             `"x86"`,
		"Sec-CH-UA-Model":            `""`,
		"Sec-CH-UA-Platform-Version": `"15.0.0"`,
		"Sec-CH-UA":                  `"Chromium";v="120", "Google Chrome";v="120", "Not_A Brand";v="8"`,
		"Sec-CH-UA-Mobile":           "?0",
		"Accept-Language":            "zh-CN,zh;q=0.9",
		"Referer":                    "http://127.0.0.1:9099/",
		"Sec-Fetch-Dest":             "iframe",
		"X-Forwarded-For":            "2.46.0.1",
		"X-Forwarded-Proto":          "https",
		"Forwarded":                  `for=198.51.100.7;by=10.0.0.1;proto=https`,
		"Accept-Encoding":            "gzip",
		"Cookie":                     "a=1",
		"Content-Type":               "text/html",
		"Dnt":                        "1",
		"Upgrade-Insecure-Requests":  "1",
	})

	ss, ev := Collect(r)

	if got := fieldValues(ss, FieldPlatform); len(got) != 2 || got[0] != "linux" || got[1] != "windows" {
		t.Fatalf("platform = %v, want [linux windows] in header-then-ch order", got)
	}
	if got := ss.Sources(FieldPlatform); len(got) != 2 || got[0] != SourceHeader || got[1] != SourceCH {
		t.Fatalf("platform sources = %v, want [header ch]", got)
	}
	if got := fieldValues(ss, FieldBrand); len(got) != 2 || got[0] != "chromium" || got[1] != "google chrome" {
		t.Fatalf("brands = %v", got)
	}
	if got := fieldValues(ss, FieldLang); len(got) != 1 || got[0] != "zh-cn,zh;q=0.9" {
		t.Fatalf("lang = %v", got)
	}
	// Sec-CH-UA-Model 的空引号值不构成信号，页面不会渲染一行空 model。
	for _, s := range ss {
		if s.Field == FieldModel {
			t.Fatalf("model signal should be dropped, got %+v", s)
		}
	}
	for _, key := range []string{"header.referer", "header.sec-fetch-dest", "header.sec-ch-ua-mobile"} {
		if !hasEvidence(ev, key) {
			t.Fatalf("missing evidence %s in %+v", key, keysOf(ev))
		}
	}
}

func TestCollectTruncatesLongEvidence(t *testing.T) {
	long := "Mozilla/5.0 (X11; Linux x86_64) " + strings.Repeat("A", maxEvidenceRaw)
	_, ev := Collect(reqWith(map[string]string{"User-Agent": long}))
	if len(ev) != 1 {
		t.Fatalf("evidence = %+v", ev)
	}
	if len(ev[0].Raw) != maxEvidenceRaw || !ev[0].Truncated {
		t.Fatalf("raw len = %d truncated = %v, want %d/true", len(ev[0].Raw), ev[0].Truncated, maxEvidenceRaw)
	}
	// 截断只作用于展示用的 Raw；规则匹配仍看到全量值，否则尾部 token 会漏检。
	ss, _ := Collect(reqWith(map[string]string{"User-Agent": long}))
	if len(ss.Values(FieldUA)) != 1 || len(ss.Values(FieldUA)[0]) != len(long) {
		t.Fatalf("ua signal should keep full value, got %d bytes", len(ss.Values(FieldUA)[0]))
	}
}

func TestCollectIgnoresUnrelatedHeaders(t *testing.T) {
	ss, ev := Collect(reqWith(map[string]string{"X-Forwarded-For": "1.2.3.4", "Cookie": "a=1"}))
	if len(ss) != 0 || len(ev) != 0 {
		t.Fatalf("expected no signals/evidence, got %v / %v", ss, ev)
	}
}

func TestCollectDedupesEvidenceKeyPerRequest(t *testing.T) {
	// 同一个 UA 派生出 ua/arch/platform 三条信号，但只应有一条原始证据。
	_, ev := Collect(reqWith(map[string]string{"User-Agent": "Mozilla/5.0 (X11; Linux sw_64) Chrome/92"}))
	if len(ev) != 1 {
		t.Fatalf("evidence = %+v, want 1", ev)
	}
}

func hasEvidence(ev []Evidence, key string) bool {
	for _, e := range ev {
		if e.Key == key {
			return true
		}
	}
	return false
}

func keysOf(ev []Evidence) []string {
	out := make([]string, 0, len(ev))
	for _, e := range ev {
		out = append(out, e.Key)
	}
	return out
}
