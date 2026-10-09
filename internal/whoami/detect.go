package whoami

import (
	"fmt"
	"strings"
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
