package whoami

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Row 是统计表里的一行。
type Row struct {
	Key   string  `json:"key"`
	Count int64   `json:"count"`
	Pct   float64 `json:"pct"`
}

// DailyRow 是近 30 天序列里的一天。
type DailyRow struct {
	Date      string `json:"date"`
	Visits    int64  `json:"visits"`
	Confirmed int64  `json:"confirmed"`
	Suspect   int64  `json:"suspect"`
	Unknown   int64  `json:"unknown"`
}

// Counters 是一组分类计数。
type Counters struct {
	Status  map[string]int64
	Arch    map[string]int64
	OS      map[string]int64
	Browser map[string]int64
	Label   map[string]int64
	Host    map[string]int64
}

func newCounters() *Counters {
	return &Counters{
		Status: map[string]int64{}, Arch: map[string]int64{}, OS: map[string]int64{},
		Browser: map[string]int64{}, Label: map[string]int64{}, Host: map[string]int64{},
	}
}

// CountersView 是渲染用的排序结果。
type CountersView struct {
	Status  []Row `json:"status"`
	Arch    []Row `json:"arch"`
	OS      []Row `json:"os"`
	Browser []Row `json:"browser"`
	Label   []Row `json:"label"`
	Host    []Row `json:"host"`
}

// StatsView 是 /api/stats 与 /stats 页面的数据源。
type StatsView struct {
	GeneratedAt time.Time    `json:"generatedAt"`
	LogDir      string       `json:"logDir"`
	Enabled     bool         `json:"enabled"`
	Visits      int64        `json:"visits"`
	Reports     int64        `json:"reports"`
	UniqueIPs   int64        `json:"uniqueIps"`
	JSCoverage  float64      `json:"jsCoverage"`
	Replayed    int64        `json:"replayed"`
	Server      CountersView `json:"server"`
	Merged      CountersView `json:"merged"`
	Daily       []DailyRow   `json:"daily"`
}

// Stats 是内存聚合，进程重启靠日志回放重建，本身不落盘。
type Stats struct {
	mu        sync.Mutex
	visits    int64
	reports   int64
	uniqueIPs map[string]bool
	server    *Counters
	merged    *Counters
	daily     map[string]*DailyRow
	replayed  int64
}

func NewStats() *Stats {
	return &Stats{
		uniqueIPs: map[string]bool{},
		server:    newCounters(),
		merged:    newCounters(),
		daily:     map[string]*DailyRow{},
	}
}

// Observe 计入一条日志记录。页面请求与浏览器端回报分开统计：
// 一次访问可能同时产生两条，混在一起会把总访问量翻倍。
func (s *Stats) Observe(rec LogRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch rec.Kind {
	case KindReport:
		s.reports++
		countInto(s.merged, rec.Result)
	case KindPage:
		s.visits++
		if rec.Client.IP != "" {
			s.uniqueIPs[rec.Client.IP] = true
		}
		countInto(s.server, rec.Result)
		s.dayRow(rec.Time).bucket(rec.Result.Verdict.Status)
	}
}

func (s *Stats) dayRow(t time.Time) *DailyRow {
	if t.IsZero() {
		t = time.Now()
	}
	key := t.UTC().Format("2006-01-02")
	row, ok := s.daily[key]
	if !ok {
		row = &DailyRow{Date: key}
		s.daily[key] = row
	}
	return row
}

func (d *DailyRow) bucket(status string) {
	d.Visits++
	switch status {
	case "confirmed":
		d.Confirmed++
	case "suspect":
		d.Suspect++
	default:
		d.Unknown++
	}
}

func countInto(c *Counters, res Result) {
	c.Status[StatusLabel(res.Verdict.Status)]++
	if v := bestName(res.Findings, CatCPU); v != "" {
		c.Arch[v]++
	}
	name := bestName(res.Findings, CatOS)
	if name == "" {
		name = bestName(res.Findings, CatPlatform)
	}
	if name != "" {
		c.OS[name]++
	}
	b := bestName(res.Findings, CatBrowser)
	if b == "" {
		b = bestName(res.Findings, CatEngine)
	}
	if b != "" {
		c.Browser[b]++
	}
	label := res.Client.Label
	if label == "" {
		label = "无归属标注"
	}
	c.Label[label]++

	host := "直接访问"
	if res.Embedded {
		host = res.Host
		if host == "" {
			host = "来源未知"
		}
	}
	c.Host[host]++
}

// bestName 取该类别里证据强度最高的结论名。
func bestName(fs []Finding, cat string) string {
	var best *Finding
	for i := range fs {
		f := &fs[i]
		if f.Category != cat {
			continue
		}
		if best == nil || f.Confidence > best.Confidence ||
			(f.Confidence == best.Confidence && f.Name < best.Name) {
			best = f
		}
	}
	if best == nil {
		return ""
	}
	return best.Name
}

func (s *Stats) ReplayDone(n int64) {
	s.mu.Lock()
	s.replayed = n
	s.mu.Unlock()
}

const topNRows = 10

// Snapshot 出一份可渲染的统计视图。
func (s *Stats) Snapshot(logDir string) StatsView {
	s.mu.Lock()
	defer s.mu.Unlock()

	v := StatsView{
		GeneratedAt: time.Now().UTC(),
		LogDir:      logDir,
		Enabled:     logDir != "",
		Visits:      s.visits,
		Reports:     s.reports,
		UniqueIPs:   int64(len(s.uniqueIPs)),
		Replayed:    s.replayed,
		Server:      s.server.view(),
		Merged:      s.merged.view(),
	}
	if s.visits > 0 {
		v.JSCoverage = float64(s.reports) / float64(s.visits) * 100
	}
	for _, key := range sortedDayKeys(s.daily, 30) {
		v.Daily = append(v.Daily, *s.daily[key])
	}
	return v
}

func sortedDayKeys(m map[string]*DailyRow, limit int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > limit {
		keys = keys[len(keys)-limit:]
	}
	return keys
}

func (c *Counters) view() CountersView {
	return CountersView{
		Status:  rowsOf(c.Status),
		Arch:    rowsOf(c.Arch),
		OS:      rowsOf(c.OS),
		Browser: rowsOf(c.Browser),
		Label:   rowsOf(c.Label),
		Host:    rowsOf(c.Host),
	}
}

// rowsOf 按计数降序排列并截断到前 topNRows 行，其余并入「其它」。
func rowsOf(m map[string]int64) []Row {
	total := int64(0)
	for _, v := range m {
		total += v
	}
	type kv struct {
		key string
		n   int64
	}
	list := make([]kv, 0, len(m))
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].key < list[j].key
	})

	var out []Row
	var rest int64
	var restKeys []string
	for i, it := range list {
		if i >= topNRows {
			rest += it.n
			restKeys = append(restKeys, it.key)
			continue
		}
		out = append(out, Row{Key: it.key, Count: it.n, Pct: pct(it.n, total)})
	}
	if rest > 0 {
		out = append(out, Row{
			Key:   fmt.Sprintf("其它 %d 类", len(restKeys)),
			Count: rest,
			Pct:   pct(rest, total),
		})
	}
	return out
}

func pct(n, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}

// AnonymizeIP 按配置决定日志与统计里留下的地址形态。
// 访客 IP 属于个人信息，落盘前的这一步是唯一能合规回溯的开关。
func AnonymizeIP(addr netip.Addr, mode string, salt []byte) string {
	if !addr.IsValid() {
		return ""
	}
	switch mode {
	case "last-octet":
		// IPv4 归到 /24、IPv6 归到 /64：够定位到网段，又留不下具体主机。
		bits := 64
		if addr.Is4() {
			bits = 24
		}
		return netip.PrefixFrom(addr, bits).Masked().Addr().String()
	case "full":
		// 加盐哈希成一个稳定短标识：看不出原地址，但仍能按访客去重计数。
		sum := sha256.Sum256(append(append([]byte{}, salt...), addr.String()...))
		return "anon-" + hex.EncodeToString(sum[:6])
	default:
		return addr.String()
	}
}
