package whoami

import (
	"fmt"
	"sort"
	"strings"
)

// KeyVerdict 是「是否信创」这一行的开关名，和卡片一起受 ?hide= / ?only= 管。
const KeyVerdict = "verdict"

// Card 是结果表里的一行。最小视图只渲染 Title 与 Value（外加短值 Detail）；
// Sources / Notes / Evidence 是判定材料，只有 ?detail=1 才展开。Value 为空的行不会被构建。
type Card struct {
	Key      string
	Title    string
	Value    string
	Detail   string
	Sources  []string
	Notes    []string
	Evidence []Evidence
}

// View 是模板渲染所需的全部内容。
type View struct {
	Result Result
	// Cards 是判定行（「是否信创」打头，其后是 IP 与各类别结论），Extras 是展示行，
	// 两组合并成页面上的同一张表，见 Rows。
	Cards    []Card
	Extras   []Card
	Evidence []Evidence
	// JSStatus 说明浏览器端回报状态；未回报时必须明示置信度上限。
	JSStatus string
	// Compact 是嵌入到别的页面 iframe 里时的紧凑模式。
	Compact bool
	// Detail 是 ?detail=1：把判定理由、边界提示与原始证据放回页面。
	Detail bool
	// Hidden 是 ?hide= 的卡片白名单，供「只让谁显示」的通用开关。
	Hidden map[string]bool
}

// Rows 把判定行和展示行并成一张表，并按 rowOrder 重排：
// 页面不再区分「结论卡片」与「其它信号」，强关联的行必须挨在一起。
func (v View) Rows() []Card {
	rows := make([]Card, 0, len(v.Cards)+len(v.Extras))
	rows = append(rows, v.Cards...)
	rows = append(rows, v.Extras...)
	sort.SliceStable(rows, func(i, j int) bool { return rowRank(rows[i].Key) < rowRank(rows[j].Key) })
	return rows
}

// rowOrder 是行序表：结论 → 网络与归属 → 系统 → CPU 与内存 → GPU → 浏览器 → 其它展示。
var rowOrder = map[string]int{
	KeyVerdict: 0,
	"ip":       10, "geo": 11,
	CatPlatform: 20, CatOS: 21, "platformV": 22,
	CatCPU: 30, "cores": 31, "memory": 32,
	CatGPU: 40, "gpuRaw": 41,
	CatBrowser: 50, CatEngine: 51, "hints": 52,
	"model": 60, "screen": 61, "timezone": 62,
}

// rowRank 给没登记的新键一个统一的末位，避免它插进已有分组中间。
func rowRank(key string) int {
	if n, ok := rowOrder[key]; ok {
		return n
	}
	return len(rowOrder)
}

func StatusLabel(status string) string {
	switch status {
	case "confirmed":
		return "确认"
	case "suspect":
		return "疑似"
	case "excluded":
		return "不是"
	default:
		return "未知"
	}
}

// verdictAnswer 是「是否信创」这一行的取值。判不出来才说「未知」：
// macOS/Windows 这类确证信号给「不是」，别把有证据的否定也一并含糊掉。
func verdictAnswer(status string) string {
	switch status {
	case "confirmed":
		return "是"
	case "suspect":
		return "疑似"
	case "excluded":
		return "不是"
	default:
		return "未知"
	}
}

// BuildView 把 Result 变成页面视图。
func BuildView(res Result) View {
	v := View{Result: res, Evidence: res.Evidence, Hidden: map[string]bool{}}

	src := append([]Card{verdictCard(res), ipCard(res, res.Evidence)}, findingCards(res.Findings, res.Evidence)...)
	for _, c := range src {
		if c.Value != "" {
			v.Cards = append(v.Cards, c)
		}
	}
	for _, c := range extraCards(res.Findings, res.Evidence) {
		if c.Value != "" {
			v.Extras = append(v.Extras, c)
		}
	}
	for _, c := range browserCards(res.Browser) {
		if c.Value != "" {
			v.Extras = append(v.Extras, c)
		}
	}
	v.Extras = append(v.Extras, geoCards(res)...)

	// JSStatus 按回报的实际参与程度分档陈述，避免过度承诺：
	// 收到回报 ≠ 有可用于判定的字段 ≠ 结论真的被跨源印证过，三件事分开说。
	switch {
	case !res.HasJS:
		v.JSStatus = "仅服务端信号，未做跨源交叉验证"
	case !containsSignalsSource(res.Signals, SourceJS):
		// 回报里只有时区/屏幕这类展示字段，没进判定管线，
		// 此时宣称「已交叉验证」会和 Limits 里的缺信号提示自相矛盾。
		v.JSStatus = "已收到浏览器端回报，但其中没有可用于交叉验证的字段，结论未经跨源交叉验证"
	default:
		if n := jsAgreedFindings(res.Findings); n > 0 {
			v.JSStatus = fmt.Sprintf("已合并浏览器端回报（Client Hints / WebGL），%d 项结论经浏览器端与服务端交叉印证", n)
		} else {
			v.JSStatus = "已合并浏览器端回报，但回报信号与服务端没有相互印证的结论"
		}
	}
	return v
}

// jsAgreedFindings 统计真正被浏览器端与服务端同时印证的结论数：
// 只有 Sources 里既有 js 又有其它来源的结论才计入，单源结论不算交叉验证。
func jsAgreedFindings(fs []Finding) int {
	n := 0
	for _, f := range fs {
		if len(f.Sources) > 1 && containsStr(f.Sources, SourceJS) {
			n++
		}
	}
	return n
}

// verdictCard 是「是否信创」这一行。最小视图只给三态短答，判定分、依据和
// 边界提示都放进 Notes，只有 ?detail=1 才展开——顶部不再挂一条强调结论的横幅。
func verdictCard(res Result) Card {
	c := Card{Key: KeyVerdict, Title: "是否信创", Value: verdictAnswer(res.Verdict.Status)}
	if res.Verdict.Score > 0 {
		c.Notes = append(c.Notes, fmt.Sprintf("判定分 %d/100", res.Verdict.Score))
	}
	c.Notes = append(c.Notes, res.Verdict.Reasons...)
	c.Notes = append(c.Notes, res.Verdict.Limits...)
	return c
}

func ipCard(res Result, ev []Evidence) Card {
	c := Card{Key: "ip", Title: "IP 地址", Value: "未取得", Evidence: evidenceFor(ev, SourceConn, SourceIP)}
	if res.Client.IP == "" {
		return c
	}
	c.Value = res.Client.IP

	var bits []string
	if res.Client.Family != "" {
		bits = append(bits, strings.ToUpper(res.Client.Family))
	}
	if res.Client.Internal {
		bits = append(bits, "内网/保留地址")
	}
	switch res.Client.Source {
	case "conn":
		bits = append(bits, "连接层 RemoteAddr")
	case "x-forwarded-for":
		bits = append(bits, "受信代理转发的 X-Forwarded-For")
	case "x-real-ip":
		bits = append(bits, "受信代理转发的 X-Real-IP")
	case "forwarded":
		bits = append(bits, "受信代理转发的 Forwarded")
	}
	c.Detail = strings.Join(bits, " · ")
	if res.Client.Label != "" {
		c.Value += "（归属：" + res.Client.Label + "）"
	}
	if res.Client.Note != "" {
		c.Notes = append(c.Notes, res.Client.Note)
	}
	if res.GeoProvider != "" {
		c.Notes = append(c.Notes,
			"归属信息来自外部接口 "+res.GeoProvider+"，启用它意味着已把访客 IP 交给该接口")
	}
	if res.GeoNote != "" {
		c.Notes = append(c.Notes, res.GeoNote)
	}
	return c
}

var cardCategories = []string{CatOS, CatCPU, CatBrowser, CatGPU}

// findingCards 每个类别出一行，取该类别证据强度最高的一条结论。
func findingCards(fs []Finding, ev []Evidence) []Card {
	var out []Card
	for _, cat := range cardCategories {
		best := bestInCategory(fs, cat)
		if best == nil {
			continue
		}
		out = append(out, cardOf(*best, ev))
	}
	return out
}

func extraCards(fs []Finding, ev []Evidence) []Card {
	var out []Card
	for _, f := range fs {
		if containsStr(cardCategories, f.Category) {
			continue
		}
		if c := cardOf(f, ev); c.Value != "" {
			out = append(out, c)
		}
	}
	return out
}

func cardOf(f Finding, ev []Evidence) Card {
	c := Card{
		Key:      f.Category,
		Title:    categoryLabel(f.Category),
		Value:    f.Name,
		Sources:  f.Sources,
		Evidence: evidenceByKeys(ev, f.EvidenceKeys),
	}
	if f.Xinchuang {
		c.Notes = append(c.Notes, fmt.Sprintf("信创判定分 %d/100", f.Score))
	}
	c.Notes = append(c.Notes, f.Notes...)
	// 只回显短值（架构名、GPU 串），UA 整条已经在原始证据里，摘要行不放。
	var short []string
	for _, v := range f.Values {
		if len(v) <= maxDetailValue {
			short = append(short, v)
		}
	}
	if len(short) > 0 {
		c.Detail = strings.Join(short, "、")
	}
	return c
}

// maxDetailValue 限定摘要行回显的值长度，UA 这类长值一律留给原始证据区。
const maxDetailValue = 48

// browserCards 是纯展示事实：取到才成行，取不到整行不渲染，不留占位。
func browserCards(b BrowserFacts) []Card {
	return []Card{
		{Key: "cores", Title: "逻辑核心数", Value: intString(b.Cores)},
		{Key: "memory", Title: "设备内存", Value: floatString(b.Memory) + memoryUnit(b.Memory)},
		{Key: "screen", Title: "屏幕", Value: b.Screen},
		{Key: "timezone", Title: "时区", Value: b.Timezone},
		{Key: "model", Title: "机型", Value: b.Model},
		{Key: "platformV", Title: "系统版本", Value: b.PlatformVersion},
		{Key: "gpuRaw", Title: "GPU 原始串", Value: b.GPU},
		{Key: "hints", Title: "Client Hints", Value: b.HintsSource},
	}
}

// geoCards 是外部归属接口的结果，一个字段一行，取不到就不排。
func geoCards(res Result) []Card {
	var out []Card
	for _, g := range res.Geo {
		if g.Value == "" {
			continue
		}
		out = append(out, Card{
			Key: "geo", Title: "归属 · " + g.Key, Value: g.Value,
			// 外呼来源必须留在最小视图里：这是隐私边界，不能等 ?detail=1 才说。
			Detail: "来自外部接口 " + res.GeoProvider,
		})
	}
	return out
}

func intString(v int) string {
	if v <= 0 {
		return ""
	}
	return fmt.Sprint(v)
}

func floatString(v float64) string {
	if v <= 0 {
		return ""
	}
	return fmt.Sprint(v)
}

func memoryUnit(v float64) string {
	if v <= 0 {
		return ""
	}
	return " GB"
}

func bestInCategory(fs []Finding, cat string) *Finding {
	var best *Finding
	for i := range fs {
		f := &fs[i]
		if f.Category != cat {
			continue
		}
		if best == nil || f.Confidence > best.Confidence ||
			(f.Confidence == best.Confidence && f.Score > best.Score) {
			best = f
		}
	}
	return best
}

func evidenceFor(ev []Evidence, sources ...string) []Evidence {
	var out []Evidence
	for _, e := range ev {
		if containsStr(sources, e.Source) {
			out = append(out, e)
		}
	}
	return out
}

func evidenceByKeys(ev []Evidence, keys []string) []Evidence {
	var out []Evidence
	for _, key := range keys {
		for _, e := range ev {
			if e.Key == key {
				out = append(out, e)
				break
			}
		}
	}
	return out
}
