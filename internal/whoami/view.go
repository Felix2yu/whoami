package whoami

import (
	"fmt"
	"strings"
)

// Banner 是页面顶部的信创结论条。
type Banner struct {
	Status  string
	Label   string
	Title   string
	Score   int
	Reasons []string
	Limits  []string
	// Caveat 在「无法判定」时说明为什么判不出来，不能只留一句未知。
	Caveat string
}

// Card 是页面上的一行结论。Value 为空的卡片不会被构建，页面也就不会出现占位空行。
type Card struct {
	Key      string
	Title    string
	Value    string
	Status   string
	Label    string
	Detail   string
	Sources  []string
	Evidence []Evidence
	Notes    []string
}

// View 是模板渲染所需的全部内容。
type View struct {
	Result   Result
	Banner   Banner
	Cards    []Card
	Extras   []Card
	Evidence []Evidence
	// JSStatus 说明浏览器端回报状态；未回报时必须明示置信度上限。
	JSStatus string
	// Compact 是嵌入到别的页面 iframe 里时的紧凑模式。
	Compact bool
	// Hidden 是 ?hide= 的卡片白名单，供「只让谁显示」的通用开关。
	Hidden map[string]bool
}

// HasContent 判断视图是否有可渲染内容，模板据此避免空壳。
func (v View) HasContent() bool { return len(v.Cards) > 0 || len(v.Extras) > 0 }

func StatusLabel(status string) string {
	switch status {
	case "confirmed":
		return "确认"
	case "suspect":
		return "疑似"
	default:
		return "未知"
	}
}

// BuildView 把 Result 变成页面视图。
func BuildView(res Result) View {
	v := View{Result: res, Evidence: res.Evidence, Hidden: map[string]bool{}}

	v.Banner = Banner{
		Status:  res.Verdict.Status,
		Label:   StatusLabel(res.Verdict.Status),
		Score:   res.Verdict.Score,
		Reasons: res.Verdict.Reasons,
		Limits:  res.Verdict.Limits,
	}
	switch res.Verdict.Status {
	case "confirmed":
		v.Banner.Title = "信创终端"
	case "suspect":
		v.Banner.Title = "疑似信创终端"
	default:
		v.Banner.Title = "无法判定"
		v.Banner.Caveat = "未发现信创特征不等于不是信创：UA 可被企业策略冻结，海光/兆芯这类国产 x86 也无法从 HTTP 信号区分。"
	}

	for _, c := range append([]Card{ipCard(res, res.Evidence)}, findingCards(res.Findings, res.Evidence)...) {
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

	if res.HasJS {
		v.JSStatus = "已合并浏览器端回报（Client Hints / WebGL），结论经过跨源交叉验证"
	} else {
		v.JSStatus = "仅服务端信号，未做跨源交叉验证"
	}
	return v
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
	status := "unknown"
	switch {
	case f.Confidence >= ConfidenceConfirmed:
		status = "confirmed"
	case f.Confidence >= ConfidenceSuspect:
		status = "suspect"
	}
	c := Card{
		Key:      f.Category,
		Title:    categoryLabel(f.Category),
		Value:    f.Name,
		Status:   status,
		Label:    StatusLabel(status),
		Sources:  f.Sources,
		Notes:    f.Notes,
		Evidence: evidenceByKeys(ev, f.EvidenceKeys),
	}
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
	if f.Xinchuang {
		if c.Detail != "" {
			c.Detail += " · "
		}
		c.Detail += fmt.Sprintf("信创判定分 %d/100", f.Score)
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
		{Key: "gpuRaw", Title: "GPU", Value: b.GPU},
		{Key: "hints", Title: "Client Hints", Value: b.HintsSource},
	}
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
