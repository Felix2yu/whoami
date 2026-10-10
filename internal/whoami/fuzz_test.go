package whoami

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzMatcher 用任意字节流喂整条判定链：正则匹配、打分、视图构建都不许 panic，
// 也不许把一个畸形 UA 变成无限循环。Go 的 RE2 没有回溯爆炸，这一条是结构保证，
// 这里测的是我们自己的代码在没有 X-Forwarded 之类校验时会不会崩。
func FuzzMatcher(f *testing.F) {
	seeds := []string{
		"",
		"Mozilla/5.0",
		uaLoongArch,
		"Mozilla/5.0 (X11; UOS; Linux x86_64; Kylin) Chrome/120",
		"\x00\xffMozilla/5.0 (X11; Linux mips64",
		strings.Repeat("a", 700) + "Chrome/1.0",
		"Mozilla/5.0 (X11; Linux loongarch64) Chrome/102 QaxBrowser/1.0 360SE MetaSr UCBrowser",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	d := func(t *testing.T) *Detector {
		det, err := NewDetector(BuiltinRules())
		if err != nil {
			t.Fatal(err)
		}
		return det
	}

	f.Fuzz(func(t *testing.T, ua string) {
		det := d(t)
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("User-Agent", ua)
		r.Header.Set("Sec-CH-UA", fuzzBrands(ua))
		r.Header.Set("Accept-Language", ua[:min(len(ua), 64)])

		ss, ev := Collect(r)
		res := det.Detect(ss, ev, IPInfo{IP: "203.0.113.9", Family: "ipv4", Source: "conn"})
		view := BuildView(res)

		if len(view.Cards) > 16 {
			t.Fatalf("卡片数失控：%d", len(view.Cards))
		}
		for _, c := range append(view.Cards, view.Extras...) {
			if c.Value == "" {
				t.Fatalf("视图里出现空值卡片 %s", c.Title)
			}
		}
		for _, e := range res.Evidence {
			if len(e.Raw) > maxEvidenceRaw {
				t.Fatalf("证据 %s 未截断：%d", e.Key, len(e.Raw))
			}
		}
		if res.Verdict.Status != "confirmed" && res.Verdict.Status != "suspect" && res.Verdict.Status != "unknown" {
			t.Fatalf("非法状态 %q", res.Verdict.Status)
		}
	})
}

func fuzzBrands(ua string) string {
	if len(ua)%3 == 0 {
		return `"Chromium";v="120", "Not_A Brand";v="8"`
	}
	return `""`
}

// FuzzBrowserReport 覆盖回报解析：任意 body 都不能 panic，也不能产出越界的值。
func FuzzBrowserReport(f *testing.F) {
	f.Add(`{"platform":"Linux"}`)
	f.Add(`{"navigatorPlatform":"MacIntel"}`)
	f.Add(`{"gpu":{"renderer":"` + strings.Repeat("A", 200) + `"}}`)
	f.Add(`{"cores":99999,"memory":-1}`)
	f.Add(`{"model":"<script>alert(1)</script>"}`)
	f.Add(`{`)
	f.Add(`[]`)

	det := func(t *testing.T) *Detector {
		d, err := NewDetector(BuiltinRules())
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	f.Fuzz(func(t *testing.T, body string) {
		rep, err := DecodeBrowserReport(strings.NewReader(body))
		if err != nil {
			return
		}
		if len(rep.Model) > maxReportString || len(rep.Platform) > maxReportString {
			t.Fatalf("字段未削短：%+v", rep)
		}
		if rep.Cores > 1024 || rep.Memory > 1024 {
			t.Fatalf("数值未夹紧：%+v", rep)
		}
		// 跑两遍：请求头没说系统家族时 navigator.platform 来兜底，
		// 已经说了安卓时它必须闭嘴（否则 Linux 会把 Android 挤掉）。
		for _, known := range [][]string{nil, {"android"}} {
			ss, ev := rep.signals(known)
			res := det(t).Detect(ss, ev, IPInfo{IP: "1.1.1.1", Family: "ipv4", Source: "conn"})
			res.Browser = rep.facts()
			BuildView(res)
		}
	})
}
