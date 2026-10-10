package whoami

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Detector 是规则表的执行器：把信号集变成命中列表。
// 它不做打分，打分规则见 scoreResult，这样追加规则时不用碰判定逻辑。
type Detector struct {
	rules []Rule
	byID  map[string]Rule
}

func NewDetector(rules []Rule) (*Detector, error) {
	d := &Detector{rules: append([]Rule(nil), rules...), byID: make(map[string]Rule, len(rules))}
	for i, ru := range d.rules {
		switch {
		case ru.ID == "":
			return nil, fmt.Errorf("规则 #%d 缺少 ID", i)
		case ru.Name == "":
			return nil, fmt.Errorf("规则 %s 缺少 Name", ru.ID)
		case ru.Category == "":
			return nil, fmt.Errorf("规则 %s 缺少 Category", ru.ID)
		case d.byID[ru.ID].ID != "":
			return nil, fmt.Errorf("规则 ID 重复：%s", ru.ID)
		case ru.Weight < 0 || ru.Weight > 100:
			return nil, fmt.Errorf("规则 %s 的 Weight=%d 超出 0-100", ru.ID, ru.Weight)
		case ru.Ceiling < 0 || ru.Ceiling > 100:
			return nil, fmt.Errorf("规则 %s 的 Ceiling=%d 超出 0-100", ru.ID, ru.Ceiling)
		}
		if err := ru.Match.Valid(); err != nil {
			return nil, fmt.Errorf("规则 %s：%w", ru.ID, err)
		}
		d.byID[ru.ID] = ru
	}
	for _, ru := range d.rules {
		for _, id := range ru.Suppresses {
			if _, ok := d.byID[id]; !ok {
				return nil, fmt.Errorf("规则 %s 引用了不存在的抑制目标 %s", ru.ID, id)
			}
		}
	}
	return d, nil
}

// Rules 返回当前生效的规则表，/api/rules 用它做导出。
func (d *Detector) Rules() []Rule { return append([]Rule(nil), d.rules...) }

// MatchRules 把每条命中的规则变成一个 Finding（同结论的合并留到打分阶段）。
func (d *Detector) MatchRules(ss Signals) []Finding {
	var out []Finding
	for _, ru := range d.rules {
		var sources, keys, values []string
		for _, s := range ss {
			if s.Field != ru.Field || !ru.Match.Hit(s.Value) {
				continue
			}
			if !containsStr(sources, s.Source) {
				sources = append(sources, s.Source)
			}
			if s.EvidenceKey != "" && !containsStr(keys, s.EvidenceKey) {
				keys = append(keys, s.EvidenceKey)
			}
			if !containsStr(values, strings.ToLower(s.Value)) {
				values = append(values, strings.ToLower(s.Value))
			}
		}
		if len(sources) == 0 {
			continue
		}
		out = append(out, Finding{
			RuleIDs: []string{ru.ID}, Name: ru.Name, Domain: ru.Domain, Category: ru.Category,
			Domestic: ru.Domestic, Xinchuang: ru.Xinchuang,
			Sources: sources, Values: values, EvidenceKeys: keys,
			Confidence: ru.Weight, Verified: ru.Verified,
		})
	}
	return out
}

// agreementBonus 是跨源一致的提升幅度：UA 说 loongarch64、JS 也说 loongarch，
// 两条独立链路同时造假的可能性远低于单条。
const agreementBonus = 40

// conflictCap 是同类别出现两个不同信创结论时的分数上限，落在「疑似」区间。
const conflictCap = 60

// Detect 完成从信号到结论的全流程，不产生任何副作用，可以并发调用。
func (d *Detector) Detect(ss Signals, ev []Evidence, ip IPInfo) Result {
	findings, verdict := d.score(ss)
	// 来源集合取「证据 + 信号」两条链路，页面据此说明结论建立在哪些通道上。
	var sources []string
	for _, e := range ev {
		if !containsStr(sources, e.Source) {
			sources = append(sources, e.Source)
		}
	}
	for _, s := range ss {
		if !containsStr(sources, s.Source) {
			sources = append(sources, s.Source)
		}
	}
	if ip.Source != "" && !containsStr(sources, SourceIP) {
		sources = append(sources, SourceIP)
	}
	return Result{
		Time:     time.Now().UTC(),
		Client:   ip,
		Findings: findings,
		Verdict:  verdict,
		Evidence: ev,
		Signals:  ss,
		Sources:  sources,
		HasJS:    containsStr(sources, SourceJS),
	}
}

// score 是打分与交叉验证的唯一入口，规则见 README。
func (d *Detector) score(ss Signals) ([]Finding, Verdict) {
	merged := mergeFindings(d.MatchRules(ss), d.byID)
	applySuppressions(merged, d.byID)
	detectConflicts(merged)
	for i := range merged {
		f := &merged[i]
		if len(f.Sources) > 1 {
			f.Confidence = min(f.Confidence+agreementBonus, 100)
			f.Notes = append(f.Notes, fmt.Sprintf("%s 与 %s 两条独立链路给出同一结论", f.Sources[0], f.Sources[1]))
		}
		if !f.Verified {
			f.Notes = append(f.Notes, "该 token 是预留条目，尚未在真实语料里证实")
		}
		f.Score = 0
		if f.Xinchuang {
			f.Score = min(f.Confidence, f.Ceiling)
		}
	}
	sortFindings(merged)
	return merged, buildVerdict(merged, ss)
}

// mergeFindings 把「同一类别、同一结论」的多条命中并成一条，
// 例如 UA 里的 UOS 整词与 uniontech 域名指向同一个统信 UOS。
func mergeFindings(raw []Finding, byID map[string]Rule) []Finding {
	index := map[string]int{}
	var out []Finding
	for _, f := range raw {
		key := f.Category + "\x00" + f.Name
		i, ok := index[key]
		if !ok {
			i = len(out)
			index[key] = i
			f.Ceiling = ceilingOf(f.RuleIDs, byID)
			f.Notes = notesOf(f.RuleIDs, byID)
			out = append(out, f)
			continue
		}
		m := &out[i]
		m.RuleIDs = union(m.RuleIDs, f.RuleIDs)
		m.Sources = union(m.Sources, f.Sources)
		m.Values = union(m.Values, f.Values)
		m.EvidenceKeys = union(m.EvidenceKeys, f.EvidenceKeys)
		m.Confidence = max(m.Confidence, f.Confidence)
		m.Ceiling = max(m.Ceiling, ceilingOf(f.RuleIDs, byID))
		m.Notes = union(m.Notes, notesOf(f.RuleIDs, byID))
		m.Domestic = m.Domestic || f.Domestic
		m.Xinchuang = m.Xinchuang || f.Xinchuang
		m.Verified = m.Verified || f.Verified
	}
	return out
}

func ceilingOf(ids []string, byID map[string]Rule) int {
	best := 0
	for _, id := range ids {
		if ru, ok := byID[id]; ok {
			best = max(best, ru.Ceiling)
		}
	}
	return best
}

func notesOf(ids []string, byID map[string]Rule) []string {
	var out []string
	for _, id := range ids {
		if ru, ok := byID[id]; ok && ru.Note != "" {
			out = append(out, ru.Note)
		}
	}
	return out
}

// applySuppressions 执行规则的互斥声明：安卓上报的 ARM 不该被当成飞腾/鲲鹏。
func applySuppressions(fs []Finding, byID map[string]Rule) {
	suppressed := map[string]bool{}
	for _, f := range fs {
		for _, id := range f.RuleIDs {
			for _, target := range byID[id].Suppresses {
				suppressed[target] = true
			}
		}
	}
	if len(suppressed) == 0 {
		return
	}
	for i := range fs {
		var kept []string
		for _, id := range fs[i].RuleIDs {
			if suppressed[id] {
				continue
			}
			kept = append(kept, id)
		}
		if len(kept) == len(fs[i].RuleIDs) {
			continue
		}
		fs[i].RuleIDs = kept
		fs[i].Xinchuang = false
		fs[i].Notes = append(fs[i].Notes, "与更具体的平台信号互斥，已降级为不参与信创判定")
	}
}

// detectConflicts 处理「同一类别出现不同结论」，分两档：
//   - 两个信创结论互斥（UA 里同时出现 UOS 与 Kylin）：双双降到疑似，两条都留着；
//   - 只有一个信创结论，另一个同类信号与它不一致（UA 报 x86_64、Client Hints 报 loongarch）：
//     不降分——更硬的架构信号本来就是用来纠正被冻结的 UA 的——但必须把矛盾写在页面上，
//     让人自己判断这是真机还是伪造。
//
// 同类别里 ARM 与 ARM32、Chrome 与 Edge 这类「没有信创结论参与」的并存不是矛盾，
// 无差别降权会把正常机器全判成疑似。
func detectConflicts(fs []Finding) {
	byCat := map[string][]int{}
	var cats []string
	for i, f := range fs {
		if _, seen := byCat[f.Category]; !seen {
			cats = append(cats, f.Category)
		}
		byCat[f.Category] = append(byCat[f.Category], i)
	}
	for _, cat := range cats {
		idx := byCat[cat]
		var names, xcNames []string
		for _, i := range idx {
			if !containsStr(names, fs[i].Name) {
				names = append(names, fs[i].Name)
			}
			if fs[i].Xinchuang && !containsStr(xcNames, fs[i].Name) {
				xcNames = append(xcNames, fs[i].Name)
			}
		}
		if len(names) < 2 || len(xcNames) == 0 {
			continue
		}
		hardConflict := len(xcNames) >= 2
		for _, i := range idx {
			if !fs[i].Xinchuang {
				continue
			}
			var others []string
			for _, n := range names {
				if n != fs[i].Name {
					others = append(others, n)
				}
			}
			if hardConflict {
				fs[i].Confidence = min(fs[i].Confidence, conflictCap)
				fs[i].Notes = append(fs[i].Notes,
					fmt.Sprintf("同类别同时出现互斥的信创结论（%s），两条都只能算疑似", strings.Join(xcNames, "、")))
				continue
			}
			fs[i].Notes = append(fs[i].Notes,
				fmt.Sprintf("同类别还有不一致的信号（%s），以更硬的信号为准，但值得你自己核一下", strings.Join(others, "、")))
		}
	}
}

func buildVerdict(fs []Finding, ss Signals) Verdict {
	var xc []Finding
	for _, f := range fs {
		if f.Xinchuang && f.Score > 0 {
			xc = append(xc, f)
		}
	}
	v := Verdict{}
	if len(xc) == 0 {
		v.Status = "unknown"
		v.Reasons = []string{"未发现信创特征。注意这不代表机器不是信创：企业策略常把 UA 冻结成通用 Chrome 串，" +
			"海光/兆芯的国产 x86 也无法从 HTTP 信号区分。"}
		v.Limits = genericLimits(ss, fs)
		return v
	}
	best := xc[0]
	for _, f := range xc[1:] {
		if f.Score > best.Score {
			best = f
		}
	}
	v.Score = best.Score
	v.Status = StatusFor(best.Score)
	for _, f := range xc {
		v.Reasons = append(v.Reasons, fmt.Sprintf("%s（%s，判定分 %d）",
			f.Name, strings.Join(f.Sources, "+"), f.Score))
	}
	for _, f := range xc {
		if f.Confidence > f.Ceiling {
			v.Limits = append(v.Limits, fmt.Sprintf("「%s」这类信号单独最高只能到 %d 分：%s",
				f.Name, f.Ceiling, firstNonEmpty(f.Notes, "该方法在此信号上的分辨能力有限")))
		}
	}
	v.Limits = append(v.Limits, genericLimits(ss, fs)...)
	return v
}

// genericLimits 说明本轮判定缺少的交叉验证。
func genericLimits(ss Signals, fs []Finding) []string {
	var out []string
	// 措辞只谈信号、不谈「是否收到回报」：空回报（HasJS=true 但无 js 信号）时
	// 也要成立，否则会和 JSStatus 的「已收到浏览器端回报」自相矛盾。
	if !containsSignalsSource(ss, SourceJS) {
		out = append(out, "浏览器端没有可用于交叉验证的信号，全部结论只来自请求头，未经跨源交叉验证")
	}
	if !containsSignalsSource(ss, FieldGPU) && !hasCategory(fs, CatGPU) {
		out = append(out, "没有 GPU 信号：WebGL 被禁用或浏览器未上报时，无法验证景嘉微/摩尔线程这类国产显卡")
	}
	return out
}

func StatusFor(score int) string {
	switch {
	case score >= ConfidenceConfirmed:
		return "confirmed"
	case score >= ConfidenceSuspect:
		return "suspect"
	default:
		return "unknown"
	}
}

func containsSignalsSource(ss Signals, source string) bool {
	for _, s := range ss {
		if s.Source == source {
			return true
		}
	}
	return false
}

func hasCategory(fs []Finding, cat string) bool {
	for _, f := range fs {
		if f.Category == cat {
			return true
		}
	}
	return false
}

func firstNonEmpty(ss []string, fallback string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return fallback
}

func sortFindings(fs []Finding) {
	// 信创在前、分数高的在前，其余按类别与名字稳定排序，保证同样输入出同样页面。
	catOrder := map[string]int{CatOS: 0, CatCPU: 1, CatBrowser: 2, CatGPU: 3, CatPlatform: 4, CatEngine: 5}
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Xinchuang != b.Xinchuang {
			return a.Xinchuang
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		ca, cb := catOrder[a.Category], catOrder[b.Category]
		if ca != cb {
			return ca < cb
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		return a.Name < b.Name
	})
}

func union(a, b []string) []string {
	out := append([]string(nil), a...)
	for _, v := range b {
		if !containsStr(out, v) {
			out = append(out, v)
		}
	}
	return out
}
