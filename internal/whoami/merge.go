package whoami

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// 客户端回报的字段上限：浏览器给出的都是短字符串，
// 放宽到几百字节足够，同时挡住被改过的浏览器把回报撑爆。
const (
	maxReportString = 256
	maxReportBrands = 32
	maxReportLangs  = 16
)

// Brand 是 Client Hints 的品牌与版本。
type Brand struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

// GPUReport 是 WebGL 报出的厂商与渲染器。
type GPUReport struct {
	Vendor   string `json:"vendor"`
	Renderer string `json:"renderer"`
	Error    string `json:"error"`
}

// ScreenReport 是屏幕尺寸与像素比。
type ScreenReport struct {
	Width  int `json:"width"`
	Height int `json:"height"`
	DPR    int `json:"dpr"`
}

// BrowserReport 是 detect.js 回报的全部内容。
type BrowserReport struct {
	Platform         string       `json:"platform"`
	PlatformVersion  string       `json:"platformVersion"`
	Architecture     string       `json:"architecture"`
	Bitness          string       `json:"bitness"`
	Model            string       `json:"model"`
	Brands           []Brand      `json:"brands"`
	GPU              GPUReport    `json:"gpu"`
	Cores            int          `json:"cores"`
	Memory           float64      `json:"memory"`
	Languages        []string     `json:"languages"`
	Timezone         string       `json:"timezone"`
	Screen           ScreenReport `json:"screen"`
	TouchPoints      int          `json:"touchPoints"`
	UserAgent        string       `json:"userAgent"`
	HintsUnavailable bool         `json:"hintsUnavailable"`
	// NavigatorPlatform 是 navigator.platform 的原值。它不受安全上下文限制，
	// 是 http 部署下唯一还能说出系统家族的浏览器字段——代价是它已被 W3C 标为
	// 弃用，且安卓会报 Linux、iPadOS 桌面模式会报 MacIntel，采信规则见 signals。
	NavigatorPlatform string `json:"navigatorPlatform"`
}

// BrowserFacts 是页面上直接展示、但不参与规则匹配的客户端事实。
type BrowserFacts struct {
	Model           string  `json:"model,omitempty"`
	PlatformVersion string  `json:"platformVersion,omitempty"`
	Cores           int     `json:"cores,omitempty"`
	Memory          float64 `json:"memory,omitempty"`
	Timezone        string  `json:"timezone,omitempty"`
	Screen          string  `json:"screen,omitempty"`
	TouchPoints     int     `json:"touchPoints,omitempty"`
	GPU             string  `json:"gpu,omitempty"`
	HintsSource     string  `json:"hintsSource,omitempty"`
}

// DecodeBrowserReport 解析回报体。调用方必须已经用 MaxBytesReader 限过体积。
func DecodeBrowserReport(r io.Reader) (BrowserReport, error) {
	var rep BrowserReport
	dec := json.NewDecoder(r)
	// 回报来自访客浏览器，属于不可信输入：未知字段直接报错，
	// 免得以后加字段时被静默吞掉的键掩盖问题。
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		return rep, fmt.Errorf("回报不是合法 JSON: %w", err)
	}
	rep.sanitize()
	return rep, nil
}

func (b *BrowserReport) sanitize() {
	b.Platform = clip(b.Platform)
	b.PlatformVersion = clip(b.PlatformVersion)
	b.Architecture = clip(b.Architecture)
	b.Bitness = clip(b.Bitness)
	b.Model = clip(b.Model)
	b.UserAgent = clip(b.UserAgent)
	b.NavigatorPlatform = clip(b.NavigatorPlatform)
	b.GPU.Vendor = clip(b.GPU.Vendor)
	b.GPU.Renderer = clip(b.GPU.Renderer)
	b.GPU.Error = clip(b.GPU.Error)
	for i := range b.Brands {
		if i >= maxReportBrands {
			b.Brands = b.Brands[:maxReportBrands]
			break
		}
		b.Brands[i].Brand = clip(b.Brands[i].Brand)
		b.Brands[i].Version = clip(b.Brands[i].Version)
	}
	if len(b.Languages) > maxReportLangs {
		b.Languages = b.Languages[:maxReportLangs]
	}
	for i, l := range b.Languages {
		b.Languages[i] = clip(l)
	}
	if b.Cores < 0 || b.Cores > 1024 {
		b.Cores = 0
	}
	if b.Memory < 0 || b.Memory > 1024 {
		b.Memory = 0
	}
	if b.TouchPoints < 0 || b.TouchPoints > 32 {
		b.TouchPoints = 0
	}
	if b.Screen.Width < 0 || b.Screen.Width > 65535 {
		b.Screen.Width = 0
	}
	if b.Screen.Height < 0 || b.Screen.Height > 65535 {
		b.Screen.Height = 0
	}
	if b.Screen.DPR < 0 || b.Screen.DPR > 32 {
		b.Screen.DPR = 0
	}
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxReportString {
		return s[:maxReportString]
	}
	return s
}

// signals 把回报变成可与请求头交叉验证的信号集。
// knownPlatforms 是请求头侧（UA 与 Sec-CH-UA-*）已经说出的系统家族，
// 用来决定要不要采信 navigator.platform。
func (b BrowserReport) signals(knownPlatforms []string) (Signals, []Evidence) {
	var ss Signals
	var ev []Evidence
	var claimed []string
	if p := normalizePlatform(b.Platform); p != "" {
		ev = append(ev, truncateEvidence("js.platform", b.Platform, SourceJS))
		ss = append(ss, Signal{Field: FieldPlatform, Value: p, Source: SourceJS, EvidenceKey: "js.platform"})
		claimed = append(claimed, p)
	}
	claimed = append(claimed, knownPlatforms...)
	if np := navigatorPlatformFamily(b.NavigatorPlatform); np != "" {
		ev = append(ev, truncateEvidence("js.navigatorPlatform", b.NavigatorPlatform, SourceJS))
		// 没人说过系统家族时它来兜底；说过了就只在与它一致时追加为第二来源。
		if len(claimed) == 0 || containsStr(claimed, np) {
			ss = append(ss, Signal{Field: FieldPlatform, Value: np, Source: SourceJS, EvidenceKey: "js.navigatorPlatform"})
		}
	}
	if a := normalizeArch(b.Architecture, b.Bitness); a != "" {
		ev = append(ev, truncateEvidence("js.architecture", b.Architecture+"/"+b.Bitness, SourceJS))
		ss = append(ss, Signal{Field: FieldArch, Value: a, Source: SourceJS, EvidenceKey: "js.architecture"})
	}
	for _, br := range b.Brands {
		name := normalizeBrand(br.Brand)
		if name == "" {
			continue
		}
		ss = append(ss, Signal{Field: FieldBrand, Value: name, Source: SourceJS, EvidenceKey: "js.brands"})
	}
	if len(b.Brands) > 0 {
		var parts []string
		for _, br := range b.Brands {
			parts = append(parts, br.Brand+" "+br.Version)
		}
		ev = append(ev, truncateEvidence("js.brands", strings.Join(parts, ", "), SourceJS))
	}

	if g := strings.TrimSpace(b.GPU.Renderer + " " + b.GPU.Vendor); g != "" {
		ev = append(ev, truncateEvidence("js.gpu", g, SourceJS))
		ss = append(ss, Signal{Field: FieldGPU, Value: g, Source: SourceJS, EvidenceKey: "js.gpu"})
	}
	if len(b.Languages) > 0 {
		joined := strings.ToLower(strings.Join(b.Languages, ","))
		ev = append(ev, truncateEvidence("js.languages", joined, SourceJS))
		ss = append(ss, Signal{Field: FieldLang, Value: joined, Source: SourceJS, EvidenceKey: "js.languages"})
	}
	if b.Model != "" {
		ev = append(ev, truncateEvidence("js.model", b.Model, SourceJS))
	}
	if b.PlatformVersion != "" {
		ev = append(ev, truncateEvidence("js.platformVersion", b.PlatformVersion, SourceJS))
	}
	if b.Cores > 0 {
		ev = append(ev, truncateEvidence("js.cores", strconv.Itoa(b.Cores), SourceJS))
	}
	if b.Memory > 0 {
		ev = append(ev, truncateEvidence("js.memory", strconv.FormatFloat(b.Memory, 'f', -1, 64)+" GB", SourceJS))
	}
	if b.Timezone != "" {
		ev = append(ev, truncateEvidence("js.timezone", b.Timezone, SourceJS))
	}
	if b.Screen.Width > 0 && b.Screen.Height > 0 {
		ev = append(ev, truncateEvidence("js.screen", screenString(b.Screen), SourceJS))
	}
	if b.TouchPoints > 0 {
		ev = append(ev, truncateEvidence("js.touchPoints", strconv.Itoa(b.TouchPoints), SourceJS))
	}
	if b.UserAgent != "" {
		ev = append(ev, truncateEvidence("js.userAgent", b.UserAgent, SourceJS))
	}
	if b.HintsUnavailable {
		ev = append(ev, truncateEvidence("js.hintsUnavailable", "navigator.userAgentData 不可用或被非安全上下文限制", SourceJS))
	}
	return ss, ev
}

// facts 是页面上直接显示的客户端事实。
func (b BrowserReport) facts() BrowserFacts {
	f := BrowserFacts{
		Model:       b.Model,
		Cores:       b.Cores,
		Memory:      b.Memory,
		Timezone:    b.Timezone,
		TouchPoints: b.TouchPoints,
	}
	f.PlatformVersion = b.PlatformVersion
	var gpu []string
	if b.GPU.Renderer != "" {
		gpu = append(gpu, b.GPU.Renderer)
	}
	if b.GPU.Vendor != "" {
		gpu = append(gpu, b.GPU.Vendor)
	}
	f.GPU = strings.Join(gpu, " · ")
	if b.GPU.Error != "" {
		f.GPU = "WebGL 不可用：" + b.GPU.Error
	}
	if b.Screen.Width > 0 && b.Screen.Height > 0 {
		f.Screen = screenString(b.Screen)
	}
	switch {
	case b.HintsUnavailable:
		f.HintsSource = "Client Hints 不可用"
	case len(b.Brands) > 0 || b.Architecture != "":
		f.HintsSource = "Client Hints 高熵值已取到"
	}
	return f
}

func screenString(s ScreenReport) string {
	out := strconv.Itoa(s.Width) + "×" + strconv.Itoa(s.Height)
	if s.DPR > 1 {
		out += " @" + strconv.Itoa(s.DPR) + "x"
	}
	return out
}

var platformAliases = map[string]string{
	"windows": "windows", "macos": "macos", "os x": "macos",
	"linux": "linux", "chrome os": "chromeos", "chromos": "chromeos",
	"cros": "chromeos", "android": "android", "ios": "ios",
	"openbsd": "openbsd", "freebsd": "freebsd", "netbsd": "netbsd",
	"harmonyos": "harmonyos", "openharmony": "harmonyos",
}

func normalizePlatform(p string) string {
	key := strings.ToLower(strings.TrimSpace(p))
	if v, ok := platformAliases[key]; ok {
		return v
	}
	if key == "" || key == "unknown" {
		return ""
	}
	return key
}

// navigatorPlatformFamily 把 navigator.platform 的老式词表归到系统家族。
// 只认能确定的前缀，认不出的（BlackBerry 之类）一律不产出信号：
// 这个字段是来补 UA 盲区的，不能反过来给它编一个家族。
func navigatorPlatformFamily(p string) string {
	k := strings.ToLower(strings.TrimSpace(p))
	switch {
	case strings.HasPrefix(k, "mac"):
		return "macos"
	case strings.HasPrefix(k, "win"):
		return "windows"
	case strings.HasPrefix(k, "linux"):
		return "linux"
	case strings.HasPrefix(k, "iphone"), strings.HasPrefix(k, "ipad"), strings.HasPrefix(k, "ipod"):
		return "ios"
	}
	return ""
}

// normalizeArch 把 Client Hints 的 architecture+bitness 还原成与 UA 同一套词表，
// 否则「x86 + 64」与 UA 的「x86_64」会被当成两个不同结论。
func normalizeArch(architecture, bitness string) string {
	a := strings.ToLower(strings.TrimSpace(architecture))
	if a == "" || a == "unknown" {
		return ""
	}
	switch strings.TrimSpace(bitness) {
	case "64":
		switch a {
		case "x86":
			return "x86_64"
		case "arm":
			return "aarch64"
		case "loongarch":
			return "loongarch64"
		case "mips":
			return "mips64"
		case "riscv":
			return "riscv64"
		case "ppc":
			return "ppc64"
		}
	case "32":
		switch a {
		case "x86":
			return "x86_32"
		case "arm":
			return "arm"
		}
	}
	// bitness 缺失或被策略抹平时，只能给出家族名，规则表按家族名匹配。
	return a
}

func normalizeBrand(b string) string {
	b = strings.ToLower(strings.TrimSpace(b))
	if b == "" || strings.HasPrefix(b, "not") {
		return ""
	}
	return b
}
