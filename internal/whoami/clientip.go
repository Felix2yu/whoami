package whoami

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// IPInfo 是最终采用的访客 IP，以及「为什么采用它」的全部依据。
type IPInfo struct {
	IP       string   `json:"ip"`
	Family   string   `json:"family,omitempty"` // ipv4|ipv6
	Internal bool     `json:"internal"`
	Source   string   `json:"source"` // conn|x-forwarded-for|x-real-ip|forwarded
	Chain    []string `json:"chain"`  // 请求里出现的候选地址，原值顺序
	Proxy    bool     `json:"proxy"`  // RemoteAddr 是否属于受信代理网段
	Label    string   `json:"label"`  // IP 字典命中的归属标签
	Note     string   `json:"note,omitempty"`
	Hostname string   `json:"hostname,omitempty"` // 反查失败则不填
}

// 内网/保留段：不依赖外部字典也能判出来，页面据此说明「这不是公网 IP」。
var internalPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
	"100.64.0.0/10", // CGNAT，运营商内网出口常见
	"172.16.0.0/12", "192.168.0.0/16",
	"::1/128", "fc00::/7", "fe80::/10",
)

func mustPrefixes(cidrs ...string) []*netip.Prefix {
	out := make([]*netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			panic("whoami: bad built-in prefix " + c + ": " + err.Error())
		}
		out = append(out, &p)
	}
	return out
}

// ParseTrustedProxies 解析 CIDR 列表。默认空列表 = 不信任任何代理，
// 这是安全基线：没有显式配置就不采纳任何 XFF。
func ParseTrustedProxies(cidrs []string) ([]*netip.Prefix, error) {
	out := make([]*netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, err
		}
		np := p.Masked()
		out = append(out, &np)
	}
	return out, nil
}

func matchesAny(ps []*netip.Prefix, addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	for _, p := range ps {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// addrKey 把 IPv4-mapped IPv6 还原成 IPv4，字典与内网判定都要按真实族来比。
func addrKey(addr netip.Addr) netip.Addr {
	if addr.Is4In6() {
		return addr.Unmap()
	}
	return addr
}

// ResolveClientIP 决定访客 IP，并返回本轮新增的证据。
func ResolveClientIP(r *http.Request, trusted []*netip.Prefix) (IPInfo, []Evidence) {
	var ev []Evidence
	add := func(key, raw, source string) {
		if raw == "" {
			return
		}
		ev = append(ev, truncateEvidence(key, raw, source))
	}

	remote := ParseAddrFromHostPort(r.RemoteAddr)
	add("conn.remote_addr", r.RemoteAddr, SourceConn)
	proxyTrusted := matchesAny(trusted, remote)

	info := IPInfo{Proxy: proxyTrusted}

	if !proxyTrusted {
		// 直连场景：RemoteAddr 就是访客地址，任何 XFF 都可能是伪造，
		// 记录为证据但不采用。
		sawForwarded := false
		for _, h := range []string{"X-Forwarded-For", "X-Real-IP", "Forwarded"} {
			if v := r.Header.Get(h); v != "" {
				add("header."+strings.ToLower(h), v, SourceIP)
				sawForwarded = true
			}
		}
		if sawForwarded {
			info.Note = "请求带有转发头，但 RemoteAddr 不在受信代理网段内，已忽略其取值（标记为 untrusted_forged）"
		}
		info.IP = remote.String()
		info.Source = "conn"
		return finalizeIP(info, remote, ev)
	}

	// 受信代理场景：从右向左第一个非受信地址即为真实访客。
	// 三个头都记为证据，但只按一个来源取用：Forwarded 是标准头，优先于 XFF，
	// 否则会出现「采用值的 source 与实际不符」。
	var candidates []string
	if fwd := r.Header.Get("Forwarded"); fwd != "" {
		add("header.forwarded", fwd, SourceIP)
		if ips := parseRFC7239For(fwd); len(ips) > 0 {
			candidates = ips
			info.Source = "forwarded"
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		add("header.x-forwarded-for", xff, SourceIP)
		if len(candidates) == 0 {
			if ips := splitAddrList(xff); len(ips) > 0 {
				candidates = ips
				info.Source = "x-forwarded-for"
			}
		}
	}
	if xrr := r.Header.Get("X-Real-IP"); xrr != "" {
		add("header.x-real-ip", xrr, SourceIP)
		if len(candidates) == 0 {
			candidates = splitAddrList(xrr)
			info.Source = "x-real-ip"
		}
	}
	info.Chain = candidates

	for i := len(candidates) - 1; i >= 0; i-- {
		addr := ParseAddrLoose(candidates[i])
		if !addr.IsValid() || matchesAny(trusted, addr) {
			continue
		}
		return finalizeIP(info, addr, ev)
	}

	// 链上全是受信地址（或一个都解析不出来）：退回 RemoteAddr。
	info.Source = "conn"
	info.Note = "转发链上的地址全部属于受信网段，采用连接层地址"
	return finalizeIP(info, remote, ev)
}

func finalizeIP(info IPInfo, addr netip.Addr, ev []Evidence) (IPInfo, []Evidence) {
	addr = addrKey(addr)
	info.IP = addr.String()
	switch {
	case !addr.IsValid():
		info.IP = ""
		info.Family = ""
	case addr.Is4():
		info.Family = "ipv4"
	default:
		info.Family = "ipv6"
	}
	info.Internal = matchesAny(internalPrefixes, addr)
	return info, ev
}

// ParseAddrFromHostPort 处理 "1.2.3.4:5678"、"[::1]:5678"，以及无端口的裸地址。
func ParseAddrFromHostPort(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	if host, port, err := net.SplitHostPort(s); err == nil && port != "" {
		if a, err := netip.ParseAddr(host); err == nil {
			return a
		}
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a
	}
	return netip.Addr{}
}

// ParseAddrLoose 容忍转发头里的带括号 IPv6 与带端口写法。
func ParseAddrLoose(s string) netip.Addr {
	s = strings.TrimSpace(strings.Trim(s, `"`))
	if s == "" || strings.EqualFold(s, "unknown") {
		return netip.Addr{}
	}
	if i := strings.LastIndex(s, "%"); i > 0 && strings.Count(s, ":") > 1 {
		// fe80::1%eth0 之类带 zone 的写法，去掉 zone 再解析
		s = s[:i]
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return a
	}
	if host, port, err := net.SplitHostPort(s); err == nil && port != "" {
		if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			return a
		}
	}
	return netip.Addr{}
}

func splitAddrList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseRFC7239For 取 Forwarded: for=1.2.3.4, for="[::1]";by=...;proto=https 里的 for 值，
// 保持从左到右的顺序。
func parseRFC7239For(v string) []string {
	var out []string
	for _, element := range strings.Split(v, ",") {
		for _, pair := range strings.Split(strings.TrimSpace(element), ";") {
			k, val, ok := strings.Cut(pair, "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(k), "for") {
				continue
			}
			val = strings.Trim(strings.TrimSpace(val), `"`)
			if val != "" {
				out = append(out, val)
			}
		}
	}
	return out
}
