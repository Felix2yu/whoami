package whoami

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Framing 是一次请求的嵌入上下文。
type Framing struct {
	Embedded bool
	Site     string // Sec-Fetch-Site：cross-site / same-origin / same-site / none
	Dest     string // Sec-Fetch-Dest：iframe / document / ...
	Referer  string // 宿主页面地址，统计页按它归类嵌入来源
	Hidden   map[string]bool
}

var ancestorToken = regexp.MustCompile(`^[A-Za-z0-9*.:_/-]+$`)

// ValidFrameAncestor 校验 CSP frame-ancestors 的单个来源。
// 白名单校验而不是直接拼进响应头，是为了让配置里的换行/分号没法注入别的指令。
func ValidFrameAncestor(s string) error {
	if s == "" {
		return fmt.Errorf("来源为空")
	}
	if s == "'self'" || s == "'none'" {
		return nil // CSP 关键字，允许单引号写法
	}
	if !ancestorToken.MatchString(s) {
		return fmt.Errorf("非法来源 %q：只允许主机名、端口、通配符与路径", s)
	}
	return nil
}

// frameAncestorsDirective 组装 CSP 指令值。
// 默认为 * 是刻意的：这个页面本来就要嵌进别的页面，
// 而且它不含任何登录态与可操作动作，被恶意嵌套的后果只是「别人看到一个信息页」。
func frameAncestorsDirective(ancestors []string) string {
	if len(ancestors) == 0 {
		return "frame-ancestors *"
	}
	return "frame-ancestors " + strings.Join(ancestors, " ")
}

// framingOf 判定嵌入模式与卡片开关。
//
// 紧凑模式优先用 ?embed 显式控制，其次靠 Sec-Fetch-Dest 自动识别：
// 宿主页面不改一行代码就能拿到适合小 iframe 的版式。
func framingOf(r *http.Request) Framing {
	f := Framing{
		Site:    r.Header.Get("Sec-Fetch-Site"),
		Dest:    r.Header.Get("Sec-Fetch-Dest"),
		Referer: r.Header.Get("Referer"),
		Hidden:  map[string]bool{},
	}
	f.Embedded = f.Dest == "iframe" || f.Dest == "frame"

	q := r.URL.Query()
	if v := q.Get("embed"); v != "" {
		f.Embedded = v == "1" || strings.EqualFold(v, "true")
	}

	hidden := map[string]bool{}
	if only := q.Get("only"); only != "" {
		// ?only= 是白名单：没列出来的卡片全部不渲染。
		keep := map[string]bool{}
		for _, k := range splitKeys(only) {
			keep[k] = true
		}
		for _, k := range allCardKeys() {
			if !keep[k] {
				hidden[k] = true
			}
		}
	}
	for _, k := range splitKeys(q.Get("hide")) {
		hidden[k] = true
	}
	f.Hidden = hidden
	return f
}

func splitKeys(list string) []string {
	var out []string
	for _, k := range strings.Split(list, ",") {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			out = append(out, k)
		}
	}
	return out
}

// allCardKeys 是 ?hide=/?only= 能控制的开关集合。
func allCardKeys() []string {
	return []string{"ip", CatOS, CatCPU, CatBrowser, CatGPU, CatPlatform, CatEngine, "extras", "evidence"}
}

// applyFraming 把嵌入上下文落到视图上。
func (v View) applyFraming(f Framing) View {
	v.Compact = f.Embedded
	if f.Hidden["evidence"] {
		v.Evidence = nil
	}
	v.Cards = filterCards(v.Cards, f.Hidden)
	v.Extras = filterCards(v.Extras, f.Hidden)
	if f.Hidden["extras"] {
		v.Extras = nil
	}
	return v
}

func filterCards(cs []Card, hidden map[string]bool) []Card {
	if len(hidden) == 0 {
		return cs
	}
	out := make([]Card, 0, len(cs))
	for _, c := range cs {
		if hidden[c.Key] {
			continue
		}
		out = append(out, c)
	}
	return out
}
