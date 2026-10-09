package whoami

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// reloadCheckInterval 是「文件是否被改过」的最小检查间隔。
// 定 10s 的依据：字典是给运维手写的，改完刷新页面就该生效；
// 而每次请求都 stat 会在统计页反复刷新时白白打文件系统。
const reloadCheckInterval = 10 * time.Second

// maxDictEntries 是字典条目上限。真实字典是「单位出口 / 机房 / 运营商」级别，
// 几百到几千条；10 万上限足够宽，又能挡住误把整份 IP 库塞进来的情况。
const maxDictEntries = 100_000

// IPDict 是访客 IP 的归属标签表：CIDR -> 标签，最长前缀匹配。
type IPDict struct {
	path string

	mu        sync.RWMutex
	v4        map[netip.Prefix]string
	v6        map[netip.Prefix]string
	count     int
	skipped   []string
	mtime     time.Time
	lastCheck time.Time

	now func() time.Time
}

func NewIPDict(path string) *IPDict {
	d := &IPDict{path: path, now: time.Now}
	d.reload()
	return d
}

// Path 返回字典文件路径，供页面与 /api/stats 展示「当前用的是哪份字典」。
func (d *IPDict) Path() string { return d.path }

// Stats 返回条目数与被跳过的非法行，页面如实显示。
func (d *IPDict) Stats() (int, []string) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.count, append([]string(nil), d.skipped...)
}

// Lookup 做最长前缀匹配，返回标签与命中的网段原文。
func (d *IPDict) Lookup(addr netip.Addr) (label, cidr string) {
	if !addr.IsValid() {
		return "", ""
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	table := d.v6
	bits := 128
	if addr.Is4() {
		table, bits = d.v4, 32
	}
	for prefix := bits; prefix >= 0; prefix-- {
		p := netip.PrefixFrom(addr, prefix).Masked()
		if v, ok := table[p]; ok {
			return v, p.String()
		}
	}
	return "", ""
}

// MaybeReload 在节流窗口内检查文件 mtime，变化则重新加载。
func (d *IPDict) MaybeReload() {
	if d.path == "" {
		return
	}
	d.mu.RLock()
	stale := d.now().Sub(d.lastCheck) >= reloadCheckInterval
	d.mu.RUnlock()
	if !stale {
		return
	}
	info, err := os.Stat(d.path)
	if err != nil || info.ModTime().Equal(d.mtimeSnapshot()) {
		d.markCheck()
		return
	}
	d.reload()
}

func (d *IPDict) mtimeSnapshot() time.Time {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.mtime
}

func (d *IPDict) markCheck() {
	d.mu.Lock()
	d.lastCheck = d.now()
	d.mu.Unlock()
}

func (d *IPDict) reload() {
	v4, v6, skipped, err := loadDict(d.path)
	newMtime := d.mtime
	if info, statErr := os.Stat(d.path); statErr == nil {
		newMtime = info.ModTime()
	}

	d.mu.Lock()
	if err != nil {
		// 文件不存在/读失败：保留上一份可用字典，不清空判定能力。
		d.lastCheck = d.now()
		d.mu.Unlock()
		return
	}
	d.v4, d.v6, d.count, d.skipped, d.mtime, d.lastCheck = v4, v6, len(v4)+len(v6), skipped, newMtime, d.now()
	d.mu.Unlock()
}

// loadDict 解析字典文件。行格式 `CIDR,标签` 或 `IP,标签`，# 起注释，空行忽略。
func loadDict(path string) (v4, v6 map[netip.Prefix]string, skipped []string, err error) {
	v4 = map[netip.Prefix]string{}
	v6 = map[netip.Prefix]string{}
	if path == "" {
		return v4, v6, nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return v4, v6, nil, nil
		}
		return nil, nil, nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		if i := strings.IndexByte(raw, '#'); i >= 0 {
			raw = raw[:i]
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		cidr, label, ok := strings.Cut(raw, ",")
		if !ok {
			skipped = append(skipped, fmt.Sprintf("第 %d 行缺少逗号分隔的标签：%q", lineNo, raw))
			continue
		}
		label = strings.TrimSpace(label)
		p, err := parseEntry(strings.TrimSpace(cidr))
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("第 %d 行 %v", lineNo, err))
			continue
		}
		if label == "" {
			skipped = append(skipped, fmt.Sprintf("第 %d 行标签为空", lineNo))
			continue
		}
		if len(v4)+len(v6) >= maxDictEntries {
			skipped = append(skipped, fmt.Sprintf("字典条目超过上限 %d，后续行被忽略", maxDictEntries))
			break
		}
		if p.Addr().Is4() {
			v4[p] = label
		} else {
			v6[p] = label
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, nil, err
	}
	return v4, v6, skipped, nil
}

// parseEntry 接受 CIDR，也接受裸 IP（自动补 /32 或 /128）。
func parseEntry(s string) (netip.Prefix, error) {
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("网段为空")
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q 既不是 CIDR 也不是 IP", s)
	}
	bits := 128
	if addr.Is4() || addr.Is4In6() {
		bits = 32
		addr = addr.Unmap()
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}
