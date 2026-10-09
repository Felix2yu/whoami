package whoami

import "time"

// Signal 来源标签，用于跨源交叉验证：同一事实被几个独立来源说出，可信度不同。
const (
	SourceConn   = "conn"   // 连接层：RemoteAddr
	SourceHeader = "header" // 请求头：User-Agent 等
	SourceCH     = "ch"     // Sec-CH-UA-* Client Hints 请求头
	SourceJS     = "js"     // 浏览器 JS 回报
	SourceIP     = "ip"     // IP 链与 IP 字典
)

// 证据字段名，规则表用 Rule.Field 引用它们。
const (
	FieldUA        = "ua"
	FieldPlatform  = "platform" // 归一后的平台：windows|macos|linux|android|ios|chromeos
	FieldArch      = "arch"     // 归一后的 CPU 架构：x86_64|aarch64|loongarch64|sw_64|mips64|riscv64|...
	FieldBrand     = "brand"    // 浏览器品牌 token（CH brands 与 UA 里的厂商串）
	FieldModel     = "model"    // CH model
	FieldLang      = "lang"     // 语言
	FieldGPU       = "gpu"      // WebGL UNMASKED_RENDERER/VENDOR
	FieldPlatformV = "platformV"
	FieldCores     = "cores"
	FieldMemory    = "memory"
	FieldIPLabel   = "ipLabel" // IP 字典命中的归属标签
)

// maxEvidenceRaw 决定单条证据在原值展示时的截断长度。
// 定 512B 的依据：常见浏览器 UA 实测 100–300B，统信/麒麟的定制构建会再长几十 B，
// 512B 不会截断任何合法 UA，同时能把一行日志和一次 JSON 输出控制住。
const maxEvidenceRaw = 512

// Evidence 是一条可展示的原始证据：访客看到的「我凭什么这么判」。
type Evidence struct {
	Key       string `json:"key"`
	Raw       string `json:"raw"`
	Source    string `json:"source"`
	Truncated bool   `json:"truncated,omitempty"`
}

// Signal 是喂给规则表的一条归一化信号。Value 保留原值不截断，匹配用全量。
type Signal struct {
	Field  string `json:"field"`
	Value  string `json:"value"`
	Source string `json:"source"`
	// EvidenceKey 指回 Evidence，让 Finding 能展开出原始来源。
	EvidenceKey string `json:"evidenceKey"`
}

// Signals 是一组信号。同一个 Field 可以由多个来源各贡献一条，
// 这正是跨源一致/冲突判定的原料。
type Signals []Signal

func (ss Signals) Values(field string) []string {
	out := make([]string, 0, 4)
	for _, s := range ss {
		if s.Field == field {
			out = append(out, s.Value)
		}
	}
	return out
}

// Sources 返回某字段上贡献过信号的独立来源，len()>1 即跨源。
func (ss Signals) Sources(field string) []string {
	var seen []string
	for _, s := range ss {
		if s.Field != field {
			continue
		}
		if !containsStr(seen, s.Source) {
			seen = append(seen, s.Source)
		}
	}
	return seen
}

func containsStr(hay []string, needle string) bool {
	for _, v := range hay {
		if v == needle {
			return true
		}
	}
	return false
}

// removeSignalField 从信号集中剔除某字段，供回报合并时以新值覆盖旧派生值。
func removeSignalField(ss Signals, field string) Signals {
	out := ss[:0:0]
	for _, s := range ss {
		if s.Field != field {
			out = append(out, s)
		}
	}
	return out
}

// Finding 是一条规则（或若干条同结论规则合并后）的命中结果。
type Finding struct {
	RuleIDs   []string `json:"ruleIds"`
	Name      string   `json:"name"`
	Domain    string   `json:"domain"`
	Category  string   `json:"category"`
	Domestic  bool     `json:"domestic"`
	Xinchuang bool     `json:"xinchuang"`

	// Sources 是说出这件事的独立来源，len>1 即跨源一致。
	Sources      []string `json:"sources"`
	Values       []string `json:"values,omitempty"`
	EvidenceKeys []string `json:"evidenceKeys"`

	Confidence int      `json:"confidence"` // 证据强度：跨源一致会抬升，冲突会压低
	Ceiling    int      `json:"ceiling"`    // 该类信号单独能把信创判定推到的上限
	Score      int      `json:"score"`      // 信创判定分 = min(Confidence, Ceiling)，非信创信号为 0
	Notes      []string `json:"notes,omitempty"`
	Verified   bool     `json:"verified"`
}

// Verdict 是对「这台机器是不是信创」的三态回答。
type Verdict struct {
	Status  string   `json:"status"` // confirmed|suspect|unknown
	Score   int      `json:"score"`
	Reasons []string `json:"reasons"`
	Limits  []string `json:"limits"`
}

// Result 是一次检测的完整输出：JSON 端点与页面渲染共用同一个结构。
type Result struct {
	ID       string     `json:"id"`
	Time     time.Time  `json:"time"`
	Client   IPInfo     `json:"client"`
	Findings []Finding  `json:"findings"`
	Verdict  Verdict    `json:"verdict"`
	Evidence []Evidence `json:"evidence"`
	Signals  Signals    `json:"signals"`
	// Sources 是本次参与判定的来源集合，页面据此提示「仅服务端信号」。
	Sources []string `json:"sources"`
	HasJS   bool     `json:"hasJs"`
	// Browser 是浏览器端回报的展示事实，未收到回报时全部字段为空。
	Browser BrowserFacts `json:"browser"`
	// Embedded 说明本次请求是被别的页面用 iframe 嵌入发起的。
	Embedded bool   `json:"embedded,omitempty"`
	Host     string `json:"host,omitempty"`
	// Geo 是外部归属接口的结果，未启用接口时为空。
	Geo         Geo    `json:"geo,omitempty"`
	GeoProvider string `json:"geoProvider,omitempty"`
	GeoNote     string `json:"geoNote,omitempty"`
}
