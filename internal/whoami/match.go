package whoami

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Match 是规则表用的条件描述。语义：
//   - 同一子句内的列表是「或」，不同子句之间是「与」；
//   - Not 命中则整体不命中；
//   - 全空的条件永远不命中——避免漏写字段的规则误伤所有人。
type Match struct {
	Contains  []string `json:"contains,omitempty"`
	Word      []string `json:"word,omitempty"`
	HasPrefix []string `json:"prefix,omitempty"`
	Equals    []string `json:"equals,omitempty"`
	Regex     []string `json:"regex,omitempty"`
	Not       *Match   `json:"not,omitempty"`
	CaseFold  bool     `json:"caseFold,omitempty"`
}

var (
	regexMu    sync.Mutex
	regexCache = map[string]*regexp.Regexp{}
)

func compileRegex(pattern string, fold bool) (*regexp.Regexp, error) {
	key := pattern
	if fold {
		key = "(?i)" + pattern
	}
	regexMu.Lock()
	defer regexMu.Unlock()
	if re, ok := regexCache[key]; ok {
		return re, nil
	}
	re, err := regexp.Compile(key)
	if err != nil {
		return nil, err
	}
	regexCache[key] = re
	return re, nil
}

// Valid 在启动时把规则表里的正则全部编译一遍，坏 pattern 越早发现越好。
func (m *Match) Valid() error { return m.valid(false) }

func (m *Match) valid(inheritFold bool) error {
	if m == nil {
		return nil
	}
	fold := m.CaseFold || inheritFold
	for _, p := range m.Regex {
		if _, err := compileRegex(p, fold); err != nil {
			return fmt.Errorf("regex %q: %w", p, err)
		}
	}
	return m.Not.valid(fold)
}

// Hit 判断 value 是否满足条件。
func (m *Match) Hit(value string) bool { return m.hit(value, false) }

func (m *Match) hit(value string, inheritFold bool) bool {
	if m == nil {
		return false
	}
	fold := m.CaseFold || inheritFold
	if m.Not != nil && m.Not.hit(value, fold) {
		return false
	}
	clauses := 0
	if len(m.Contains) > 0 {
		clauses++
		if !anyFold(value, m.Contains, fold, strings.Contains) {
			return false
		}
	}
	if len(m.Word) > 0 {
		clauses++
		found := false
		for _, w := range m.Word {
			if hasWord(value, w, fold) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(m.HasPrefix) > 0 {
		clauses++
		if !anyFold(value, m.HasPrefix, fold, strings.HasPrefix) {
			return false
		}
	}
	if len(m.Equals) > 0 {
		clauses++
		if !anyFold(value, m.Equals, fold, func(a, b string) bool { return a == b }) {
			return false
		}
	}
	if len(m.Regex) > 0 {
		clauses++
		found := false
		for _, p := range m.Regex {
			re, err := compileRegex(p, fold)
			if err != nil {
				continue // 启动时已校验过；这里再出错只当不命中，不能让请求 panic
			}
			if re.MatchString(value) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return clauses > 0
}

func anyFold(value string, tokens []string, fold bool, cmp func(string, string) bool) bool {
	for _, t := range tokens {
		if fold {
			if cmp(strings.ToLower(value), strings.ToLower(t)) {
				return true
			}
			continue
		}
		if cmp(value, t) {
			return true
		}
	}
	return false
}

// hasWord 按「非字母数字即边界」判断整词出现：
// UOS 能命中 "X11; UOS; Linux x86_64"，但不会命中 continuous 里的 uos；
// 代价是 kylin 不会命中 kylinos，这类粘连写法要在规则里另列 token。
func hasWord(value, word string, fold bool) bool {
	if word == "" {
		return false
	}
	hay, needle := value, word
	if fold {
		hay, needle = strings.ToLower(value), strings.ToLower(word)
	}
	for i := 0; i+len(needle) <= len(hay); {
		j := strings.Index(hay[i:], needle)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(needle)
		if !isWordByte(before(hay, start)) && !isWordByte(after(hay, end)) {
			return true
		}
		i = end
	}
	return false
}

func before(s string, i int) byte {
	if i <= 0 {
		return 0
	}
	return s[i-1]
}

func after(s string, i int) byte {
	if i >= len(s) {
		return 0
	}
	return s[i]
}

func isWordByte(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}
