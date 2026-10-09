package whoami

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeDict(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ip.csv")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write dict: %v", err)
	}
	return path
}

func addrOf(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return a
}

func TestDictLongestPrefixWins(t *testing.T) {
	d := NewIPDict(writeDict(t, `
# 单位出口对照表
10.0.0.0/8,总部内网
10.1.0.0/16,三分局出口
`))

	if count, skipped := d.Stats(); count != 2 || len(skipped) != 0 {
		t.Fatalf("count = %d skipped = %v", count, skipped)
	}
	label, cidr := d.Lookup(addrOf(t, "10.1.2.3"))
	if label != "三分局出口" || cidr != "10.1.0.0/16" {
		t.Fatalf("lookup = %q/%q, want 三分局出口/10.1.0.0/16", label, cidr)
	}
	if label, _ := d.Lookup(addrOf(t, "10.9.9.9")); label != "总部内网" {
		t.Fatalf("lookup = %q, want 总部内网", label)
	}
	if label, cidr := d.Lookup(addrOf(t, "192.168.1.1")); label != "" || cidr != "" {
		t.Fatalf("unmatched lookup = %q/%q", label, cidr)
	}
	if label, _ := d.Lookup(netip.Addr{}); label != "" {
		t.Fatalf("invalid addr should not match, got %q", label)
	}
}

func TestDictBareIPAndIPv6(t *testing.T) {
	d := NewIPDict(writeDict(t, "1.2.3.4,张三的笔记本\n2001:db8::/32,测试网段\n"))

	if label, cidr := d.Lookup(addrOf(t, "1.2.3.4")); label != "张三的笔记本" || cidr != "1.2.3.4/32" {
		t.Fatalf("bare IPv4 = %q/%q", label, cidr)
	}
	// 双栈栈上常见的 IPv4-mapped 写法必须能命中同一条目。
	if label, _ := d.Lookup(addrOf(t, "::ffff:1.2.3.4")); label != "张三的笔记本" {
		t.Fatalf("IPv4-mapped = %q", label)
	}
	if label, _ := d.Lookup(addrOf(t, "2001:db8::dead")); label != "测试网段" {
		t.Fatalf("IPv6 = %q", label)
	}
	if label, _ := d.Lookup(addrOf(t, "2001:db9::1")); label != "" {
		t.Fatalf("out-of-range IPv6 = %q", label)
	}
}

func TestDictSkipsBadLinesWithoutDroppingGoodOnes(t *testing.T) {
	d := NewIPDict(writeDict(t, `1.0.0.0/24,好的
这一行没有逗号
999.1.1.1,不是合法 IP
2.0.0.0/8,
   # 缩进的注释行
3.0.0.0/8,也很好
`))

	if count, _ := d.Stats(); count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
	if label, _ := d.Lookup(addrOf(t, "1.0.0.5")); label != "好的" {
		t.Fatalf("good line before junk lost: %q", label)
	}
	if label, _ := d.Lookup(addrOf(t, "3.0.0.5")); label != "也很好" {
		t.Fatalf("good line after junk lost: %q", label)
	}
	_, skipped := d.Stats()
	joined := strings.Join(skipped, "|")
	for _, want := range []string{"第 2 行", "第 3 行", "第 4 行"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("skipped should mention %s, got %v", want, skipped)
		}
	}
}

func TestDictMissingFileIsUsable(t *testing.T) {
	d := NewIPDict(filepath.Join(t.TempDir(), "absent.csv"))
	if count, skipped := d.Stats(); count != 0 || len(skipped) != 0 {
		t.Fatalf("count = %d skipped = %v", count, skipped)
	}
	if label, _ := d.Lookup(addrOf(t, "1.1.1.1")); label != "" {
		t.Fatalf("unexpected label %q", label)
	}
	d.MaybeReload() // 不应 panic 或报错
}

func TestDictReloadsAfterThrottleWindow(t *testing.T) {
	path := writeDict(t, "1.0.0.0/8,第一版\n")
	d := NewIPDict(path)

	fake := time.Now()
	d.now = func() time.Time { return fake }

	if err := os.WriteFile(path, []byte("1.0.0.0/8,第二版\n"), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	// mtime 显式拉开，避免同一秒内写入导致 Equal 判定不可靠。
	if err := os.Chtimes(path, fake.Add(time.Hour), fake.Add(time.Hour)); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	d.MaybeReload() // 节流窗口内，不该重读
	if label, _ := d.Lookup(addrOf(t, "1.2.3.4")); label != "第一版" {
		t.Fatalf("reloaded too early: %q", label)
	}

	fake = fake.Add(reloadCheckInterval + time.Second)
	d.MaybeReload()
	if label, _ := d.Lookup(addrOf(t, "1.2.3.4")); label != "第二版" {
		t.Fatalf("did not reload: %q", label)
	}

	// 文件被删掉时保留上一份字典，不能把归属信息清空。
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	fake = fake.Add(reloadCheckInterval + time.Second)
	d.MaybeReload()
	if label, _ := d.Lookup(addrOf(t, "1.2.3.4")); label != "第二版" {
		t.Fatalf("dictionary lost after file removal: %q", label)
	}
}

func TestDictEntryCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.csv")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	w := bufio.NewWriter(f)
	for i := range maxDictEntries + 5 {
		// 100 005 个互不重复的 /32，确保真的撞到上限而不是靠重复覆盖。
		line := fmt.Sprintf("10.%d.%d.%d/32,条目%d\n", i/65536%256, i/256%256, i%256, i)
		if _, err := w.WriteString(line); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	f.Close()

	d := NewIPDict(path)
	count, skipped := d.Stats()
	if count > maxDictEntries {
		t.Fatalf("count = %d exceeds cap %d", count, maxDictEntries)
	}
	if !strings.Contains(strings.Join(skipped, "|"), "上限") {
		t.Fatalf("skipped should report the cap, got %v", skipped)
	}
}

func TestDictIsConcurrencySafe(t *testing.T) {
	d := NewIPDict(writeDict(t, "10.0.0.0/8,内网\n1.2.3.4,外网机器\n"))
	done := make(chan struct{})
	go func() {
		for range 64 {
			d.MaybeReload()
		}
		close(done)
	}()
	for range 64 {
		if label, _ := d.Lookup(addrOf(t, "10.1.1.1")); label != "内网" {
			t.Fatalf("lookup under concurrency = %q", label)
		}
	}
	<-done
}
