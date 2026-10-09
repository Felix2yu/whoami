package whoami

import (
	"encoding/json"
	"fmt"
	"os"
)

// ExternalRuleFile 是 -rules 指向的 JSON 文件结构。
// 直接给数组也接受，包一层只是为了能在文件里写注释性的说明字段。
type ExternalRuleFile struct {
	Rules []Rule `json:"rules"`
}

// LoadRules 读取外部规则文件。路径为空返回 nil；文件读不通或内容不合法都要报错，
// 因为「配了规则但没生效」比启动失败更难查。
func LoadRules(path string) ([]Rule, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取规则文件失败: %w", err)
	}
	var wrapped ExternalRuleFile
	if err := json.Unmarshal(b, &wrapped); err == nil && len(wrapped.Rules) > 0 {
		return wrapped.Rules, nil
	}
	var flat []Rule
	if err := json.Unmarshal(b, &flat); err != nil {
		return nil, fmt.Errorf("规则文件不是合法的 JSON（接受 `[{...}]` 或 `{\"rules\":[...]}`）: %w", err)
	}
	if len(flat) == 0 {
		return nil, fmt.Errorf("规则文件 %s 是空的", path)
	}
	return flat, nil
}

// mergeRules 合并内置与外部规则：同 ID 时外部覆盖内置，
// 这样改 token、调天花板都不用改代码重新编译。
func mergeRules(builtin, external []Rule) ([]Rule, int) {
	byID := map[string]int{}
	out := append([]Rule(nil), builtin...)
	for i, ru := range out {
		byID[ru.ID] = i
	}
	replaced := 0
	for _, ru := range external {
		if i, ok := byID[ru.ID]; ok {
			out[i] = ru
			replaced++
			continue
		}
		byID[ru.ID] = len(out)
		out = append(out, ru)
	}
	return out, replaced
}

// RulesSource 描述当前生效的规则表由哪几部分组成，/api/rules 用它自证。
type RulesSource struct {
	Builtin  int    `json:"builtin"`
	External int    `json:"external"`
	Replaced int    `json:"replaced"`
	Total    int    `json:"total"`
	Path     string `json:"path,omitempty"`
}
