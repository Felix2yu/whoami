package whoami

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func ipRequest(remoteAddr string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	if _, ok := headers["Accept"]; !ok {
		r.Header.Set("Accept", "text/html")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func mustPrefixesT(t *testing.T, cidrs ...string) []*netip.Prefix {
	t.Helper()
	ps, err := ParseTrustedProxies(cidrs)
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	return ps
}

func TestDirectConnectionIgnoresForgedXFF(t *testing.T) {
	// 默认无受信代理：XFF 记为证据但不采用。
	info, ev := ResolveClientIP(ipRequest("203.0.113.9:5210", map[string]string{
		"X-Forwarded-For": "1.1.1.1, 8.8.8.8",
		"X-Real-IP":       "9.9.9.9",
	}), nil)

	if info.IP != "203.0.113.9" {
		t.Fatalf("IP = %q, want 203.0.113.9", info.IP)
	}
	if info.Source != "conn" || info.Proxy {
		t.Fatalf("source = %q proxy = %v", info.Source, info.Proxy)
	}
	if info.Note == "" || !strings.Contains(info.Note, "untrusted_forged") {
		t.Fatalf("note = %q, want untrusted_forged explanation", info.Note)
	}
	for _, key := range []string{"conn.remote_addr", "header.x-forwarded-for", "header.x-real-ip"} {
		if !hasEvidence(ev, key) {
			t.Fatalf("missing evidence %s, got %v", key, keysOf(ev))
		}
	}
}

func TestTrustedProxyTakesRightmostNonTrustedAddress(t *testing.T) {
	trusted := mustPrefixesT(t, "127.0.0.0/8", "10.0.0.0/8")

	// 链路：访客 203.0.113.9 -> 内部 10.1.1.1 -> 本机反代，从右往左第一个非受信是访客。
	info, _ := ResolveClientIP(ipRequest("127.0.0.1:443", map[string]string{
		"X-Forwarded-For": "203.0.113.9, 10.1.1.1",
	}), trusted)

	if info.IP != "203.0.113.9" {
		t.Fatalf("IP = %q, want 203.0.113.9", info.IP)
	}
	if !info.Proxy || info.Source != "x-forwarded-for" {
		t.Fatalf("proxy = %v source = %q", info.Proxy, info.Source)
	}
	if len(info.Chain) != 2 {
		t.Fatalf("chain = %v", info.Chain)
	}
}

func TestAllTrustedChainFallsBackToConnection(t *testing.T) {
	trusted := mustPrefixesT(t, "127.0.0.0/8", "10.0.0.0/8")
	info, _ := ResolveClientIP(ipRequest("127.0.0.1:443", map[string]string{
		"X-Forwarded-For": "10.1.1.1, 10.2.2.2",
	}), trusted)

	if info.IP != "127.0.0.1" {
		t.Fatalf("IP = %q, want 127.0.0.1", info.IP)
	}
	if info.Source != "conn" || info.Note == "" {
		t.Fatalf("source = %q note = %q", info.Source, info.Note)
	}
}

func TestRFC7239ForwardedPreferredOverXFF(t *testing.T) {
	trusted := mustPrefixesT(t, "127.0.0.0/8")
	info, ev := ResolveClientIP(ipRequest("127.0.0.1:443", map[string]string{
		"Forwarded":       `for=198.51.100.7;by=127.0.0.1;proto=https`,
		"X-Forwarded-For": "203.0.113.9",
	}), trusted)

	if info.IP != "198.51.100.7" || info.Source != "forwarded" {
		t.Fatalf("IP = %q source = %q, want 198.51.100.7/forwarded", info.IP, info.Source)
	}
	if !hasEvidence(ev, "header.forwarded") || !hasEvidence(ev, "header.x-forwarded-for") {
		t.Fatalf("both headers should be kept as evidence, got %v", keysOf(ev))
	}
}

func TestIPv6AndBareRemoteAddr(t *testing.T) {
	info, _ := ResolveClientIP(ipRequest("[2001:db8::1]:1234", nil), nil)
	if info.IP != "2001:db8::1" || info.Family != "ipv6" {
		t.Fatalf("info = %+v", info)
	}

	info, _ = ResolveClientIP(ipRequest("203.0.113.7", nil), nil)
	if info.IP != "203.0.113.7" {
		t.Fatalf("bare address without port: %+v", info)
	}

	info, _ = ResolveClientIP(ipRequest("[::ffff:203.0.113.7]:1", nil), nil)
	if info.IP != "203.0.113.7" || info.Family != "ipv4" {
		t.Fatalf("IPv4-mapped should unmap: %+v", info)
	}
}

func TestInternalAndReservedRanges(t *testing.T) {
	cases := []struct {
		remoteAddr   string
		wantInternal bool
	}{
		{"10.0.0.5:80", true},
		{"172.16.9.9:80", true},
		{"192.168.1.1:80", true},
		{"127.0.0.1:80", true},
		{"169.254.5.5:80", true},
		{"100.64.0.2:80", true}, // CGNAT
		{"[fc00::1]:80", true},
		{"[fe80::2]:80", true},
		{"[::1]:80", true},
		{"203.0.113.9:80", false},
		{"8.8.8.8:80", false},
		{"[2001:db8::1]:80", false},
	}
	for _, c := range cases {
		info, _ := ResolveClientIP(ipRequest(c.remoteAddr, nil), nil)
		if info.Internal != c.wantInternal {
			t.Errorf("%s internal = %v, want %v (ip=%q)", c.remoteAddr, info.Internal, c.wantInternal, info.IP)
		}
	}
}

func TestParseAddrLooseRejectsJunk(t *testing.T) {
	for _, s := range []string{"", "unknown", "US", "1.2.3", "999.1.1.1", "for=_"} {
		if a := ParseAddrLoose(s); a.IsValid() {
			t.Errorf("ParseAddrLoose(%q) = %v, want invalid", s, a)
		}
	}
	for s, want := range map[string]string{
		`"[2001:db8::1]:8443"`: "2001:db8::1",
		" 203.0.113.5 ":        "203.0.113.5",
		"2001:db8::1%eth0":     "2001:db8::1",
	} {
		if got := ParseAddrLoose(s).String(); got != want {
			t.Errorf("ParseAddrLoose(%q) = %q, want %q", s, got, want)
		}
	}
}

func TestXFFWinsOverXRealIPWhenBothPresent(t *testing.T) {
	trusted := mustPrefixesT(t, "127.0.0.0/8")
	info, _ := ResolveClientIP(ipRequest("127.0.0.1:443", map[string]string{
		"X-Forwarded-For": "203.0.113.9",
		"X-Real-IP":       "198.51.100.7",
	}), trusted)

	if info.IP != "203.0.113.9" || info.Source != "x-forwarded-for" {
		t.Fatalf("info = %+v, want 203.0.113.9 from x-forwarded-for", info)
	}
}

func TestEvidenceValuesAreTruncatedAtBound(t *testing.T) {
	long := strings.Repeat("203.0.113.9, ", 200)
	_, ev := ResolveClientIP(ipRequest("127.0.0.1:1", map[string]string{"X-Forwarded-For": long}),
		mustPrefixesT(t, "127.0.0.0/8"))
	for _, e := range ev {
		if len(e.Raw) > maxEvidenceRaw {
			t.Fatalf("evidence %s raw len = %d, exceeds bound %d", e.Key, len(e.Raw), maxEvidenceRaw)
		}
	}
}
