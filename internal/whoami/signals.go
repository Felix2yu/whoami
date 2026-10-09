package whoami

import (
	"net/http"
	"strings"
)

// signalSet 在一次请求内收集信号与证据，保证同一 header 只记一条证据。
type signalSet struct {
	signals  Signals
	evidence []Evidence
	idx      map[string]int
}

func newSignalSet() *signalSet {
	return &signalSet{idx: make(map[string]int, 8)}
}

// evidenceOf 记录（或复用）一条原始证据，返回它的 key。空值不记录，
// 页面就不可能出现一行空证据。
func (ss *signalSet) evidenceOf(key, raw, source string) string {
	if raw == "" {
		return key
	}
	if _, ok := ss.idx[key]; ok {
		return key
	}
	ss.idx[key] = len(ss.evidence)
	ss.evidence = append(ss.evidence, truncateEvidence(key, raw, source))
	return key
}

func (ss *signalSet) add(field, value, source, evidenceKey string) {
	if value == "" {
		return
	}
	ss.signals = append(ss.signals, Signal{Field: field, Value: value, Source: source, EvidenceKey: evidenceKey})
}

func truncateEvidence(key, raw, source string) Evidence {
	truncated := false
	if len(raw) > maxEvidenceRaw {
		raw = raw[:maxEvidenceRaw]
		truncated = true
	}
	return Evidence{Key: key, Raw: raw, Source: source, Truncated: truncated}
}

// Collect 从请求里抽取服务端可见的全部信号：连接层 + 请求头 + Client Hints。
// IP 相关证据由 ResolveClientIP 另加，因为它需要受信代理判定。
func Collect(r *http.Request) (Signals, []Evidence) {
	ss := newSignalSet()

	ua := r.Header.Get("User-Agent")
	uaKey := ss.evidenceOf("header.user-agent", ua, SourceHeader)
	ss.add(FieldUA, ua, SourceHeader, uaKey)
	if arch := ArchFromUA(ua); arch != "" {
		ss.add(FieldArch, arch, SourceHeader, uaKey)
	}
	if p := PlatformFromUA(ua); p != "" {
		ss.add(FieldPlatform, p, SourceHeader, uaKey)
	}

	if v := r.Header.Get("Sec-CH-UA-Platform"); v != "" {
		k := ss.evidenceOf("header.sec-ch-ua-platform", v, SourceCH)
		ss.add(FieldPlatform, normalizeHeaderValue(v), SourceCH, k)
	}
	if v := r.Header.Get("Accept-Language"); v != "" {
		k := ss.evidenceOf("header.accept-language", v, SourceHeader)
		ss.add(FieldLang, normalizeHeaderValue(v), SourceHeader, k)
	}
	if v := r.Header.Get("Sec-CH-UA-Mobile"); v != "" {
		ss.evidenceOf("header.sec-ch-ua-mobile", v, SourceCH)
	}

	if v := r.Header.Get("Sec-CH-UA"); v != "" {
		k := ss.evidenceOf("header.sec-ch-ua", v, SourceCH)
		for _, b := range parseCHBrands(v) {
			ss.add(FieldBrand, b, SourceCH, k)
		}
	}
	if v := r.Header.Get("Sec-CH-UA-Arch"); v != "" {
		k := ss.evidenceOf("header.sec-ch-ua-arch", v, SourceCH)
		ss.add(FieldArch, normalizeHeaderValue(v), SourceCH, k)
	}
	if v := r.Header.Get("Sec-CH-UA-Model"); v != "" {
		k := ss.evidenceOf("header.sec-ch-ua-model", v, SourceCH)
		ss.add(FieldModel, normalizeHeaderValue(v), SourceCH, k)
	}
	if v := r.Header.Get("Sec-CH-UA-Platform-Version"); v != "" {
		k := ss.evidenceOf("header.sec-ch-ua-platform-version", v, SourceCH)
		ss.add(FieldPlatformV, normalizeHeaderValue(v), SourceCH, k)
	}

	for _, h := range []string{"referer", "origin", "sec-fetch-site", "sec-fetch-dest"} {
		if v := r.Header.Get(h); v != "" {
			ss.evidenceOf("header."+h, v, SourceHeader)
		}
	}

	return ss.signals, ss.evidence
}

func sourceForHeader(key string) string {
	if strings.HasPrefix(key, "header.sec-ch-ua") {
		return SourceCH
	}
	return SourceHeader
}

// normalizeHeaderValue 去掉 Client Hints 的引号并小写，便于规则表用不区分大小写的 token。
func normalizeHeaderValue(v string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(v), `"`))
}

// parseCHBrands 解析 `Sec-CH-UA: "Chromium";v="120", "Not_A Brand";v="8"` 里的品牌名，
// 跳过 GREASE 用的假品牌。
func parseCHBrands(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		name, _, ok := strings.Cut(strings.TrimSpace(part), ";")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.Trim(strings.TrimSpace(name), `"`))
		if name == "" || strings.HasPrefix(name, "not") {
			continue
		}
		out = append(out, name)
	}
	return out
}

// archPatterns 按特异性排序：先 loongarch/sw/mips 这类强信号，再 arm64，最后泛化 token。
// "Intel Mac OS X" 故意不产生架构——Apple Silicon 的 Safari UA 也写 Intel，会误判。
var archPatterns = []struct{ token, arch string }{
	{"loongarch", "loongarch64"},
	{"sw_64", "sw_64"},
	{"sw64", "sw_64"},
	{"mips64", "mips64"},
	{"mipsel", "mips"},
	{"mips", "mips"},
	{"riscv64", "riscv64"},
	{"riscv", "riscv64"},
	{"aarch64", "aarch64"},
	{"arm64", "aarch64"},
	{"armv8", "aarch64"},
	{"armv7", "arm"},
	{"armv6", "arm"},
	{"ppc64", "ppc64"},
	{"x86_64", "x86_64"},
	{"amd64", "x86_64"},
	{"win64", "x86_64"},
	{"x64", "x86_64"},
	{"i686", "x86_32"},
	{"i386", "x86_32"},
	{"wow64", "x86_32"},
}

func ArchFromUA(ua string) string {
	lower := strings.ToLower(ua)
	for _, p := range archPatterns {
		if strings.Contains(lower, p.token) {
			return p.arch
		}
	}
	return ""
}

// platformPatterns 顺序敏感：Android 含 "linux"，iPhone 含 "mac os x"。
var platformPatterns = []struct{ token, platform string }{
	{"android", "android"},
	{"harmonyos", "harmonyos"},
	{"iphone", "ios"},
	{"ipad", "ios"},
	{"cros", "chromeos"},
	{"macintosh", "macos"},
	{"mac os x", "macos"},
	{"windows nt", "windows"},
	{"wow64", "windows"},
	{"x11", "linux"},
	{"linux", "linux"},
	{"freebsd", "freebsd"},
}

func PlatformFromUA(ua string) string {
	lower := strings.ToLower(ua)
	for _, p := range platformPatterns {
		if strings.Contains(lower, p.token) {
			return p.platform
		}
	}
	return ""
}
