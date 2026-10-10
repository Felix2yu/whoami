package whoami

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func resultFor(t *testing.T, ua string) Result {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("User-Agent", ua)
	ss, ev := Collect(r)
	return builtinDetector(t).Detect(ss, ev, IPInfo{IP: "203.0.113.9", Family: "ipv4", Source: "conn"})
}

func pageRecord(t *testing.T, ua string, when time.Time) LogRecord {
	t.Helper()
	res := resultFor(t, ua)
	res.Time = when
	return LogRecord{Kind: KindPage, Result: res}
}

func TestAccessLogWritesDatedJSONL(t *testing.T) {
	dir := t.TempDir()
	l, err := NewAccessLog(dir, 0)
	if err != nil {
		t.Fatalf("NewAccessLog: %v", err)
	}
	defer l.Close()

	day := time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC)
	for range 3 {
		rec := pageRecord(t, "Mozilla/5.0 (X11; Linux loongarch64) Chrome/102", day)
		rec.Result.ID = NewID()
		if err := l.Write(rec); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	// 跨天必须滚文件，否则回放和清理都没法按天算。
	if err := l.Write(pageRecord(t, "Mozilla/5.0 (X11; UOS) Chrome/120", day.AddDate(0, 0, 1))); err != nil {
		t.Fatalf("write next day: %v", err)
	}
	l.Close()

	for _, name := range []string{"whoami-20261009.jsonl", "whoami-20261010.jsonl"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		want := 3
		if name[7:15] == "20261010" {
			want = 1
		}
		if len(lines) != want {
			t.Errorf("%s 有 %d 行，want %d", name, len(lines), want)
		}
		for _, line := range lines {
			var rec LogRecord
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("%s 里有非法 JSON 行: %v", name, err)
			}
			if rec.Kind != KindPage || rec.Result.Verdict.Status == "" {
				t.Errorf("记录不完整：%+v", rec)
			}
		}
	}
}

func TestAccessLogDisabledKeepsRepoClean(t *testing.T) {
	l, err := NewAccessLog("", 90)
	if err != nil || l != nil {
		t.Fatalf("空目录应关闭落盘，got %v err %v", l, err)
	}
	if err := l.Write(LogRecord{Kind: KindPage}); err != nil {
		t.Errorf("nil 日志写入应无副作用: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("nil 日志关闭应无副作用: %v", err)
	}
	if got := l.Dir(); got != "" {
		t.Errorf("dir = %q", got)
	}
}

func TestAccessLogPruneOnlyTouchesItsOwnFiles(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "whoami-19700101.jsonl")
	recent := filepath.Join(dir, "whoami-"+time.Now().UTC().AddDate(0, 0, -3).Format("20060102")+".jsonl")
	foreign := filepath.Join(dir, "notes.jsonl")
	other := filepath.Join(dir, "ip.csv")
	for _, p := range []string{old, recent, foreign, other} {
		if err := os.WriteFile(p, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := NewAccessLog(dir, 7); err != nil {
		t.Fatalf("NewAccessLog: %v", err)
	}
	for _, p := range []string{recent, foreign, other} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("不该删掉 %s", p)
		}
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("超期日志应被清理")
	}
}

func TestReplayRebuildsStatsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	l, err := NewAccessLog(dir, 0)
	if err != nil {
		t.Fatalf("NewAccessLog: %v", err)
	}
	base := time.Now().UTC().Add(-2 * time.Hour)
	uaKylin := "Mozilla/5.0 (X11; Linux aarch64; Kylin) AppleWebKit/537.36 Kylinbrowser/1.2 Chrome/78"
	uaWin := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"

	for i := range 4 {
		rec := pageRecord(t, uaKylin, base.Add(time.Duration(i)*time.Minute))
		if err := l.Write(rec); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 2 {
		rec := pageRecord(t, uaWin, base.Add(time.Duration(i)*time.Minute))
		if err := l.Write(rec); err != nil {
			t.Fatal(err)
		}
	}
	report := LogRecord{Kind: KindReport, Result: resultFor(t, uaWin)}
	report.Time = base
	if err := l.Write(report); err != nil {
		t.Fatal(err)
	}
	l.Close()

	stats := NewStats()
	n, err := stats.Replay(mustLog(t, dir), 7, 20<<20)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if n != 7 {
		t.Fatalf("回放 %d 条, want 7", n)
	}
	v := stats.Snapshot(dir)
	if v.Visits != 6 || v.Reports != 1 {
		t.Errorf("visits=%d reports=%d, want 6/1", v.Visits, v.Reports)
	}
	if v.Replayed != 0 {
		t.Errorf("ReplayDone 未调用时不该带计数：%d", v.Replayed)
	}
	totalStatus := int64(0)
	for _, row := range v.Server.Status {
		totalStatus += row.Count
	}
	if totalStatus != 6 {
		t.Errorf("状态分布合计 %d, want 6（回报不该混进页面访问的分布）", totalStatus)
	}
	if len(v.Merged.Status) == 0 {
		t.Error("回报的分布应单独成组")
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

func mustLog(t *testing.T, dir string) *AccessLog {
	t.Helper()
	l, err := NewAccessLog(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestReplayRespectsByteBudget(t *testing.T) {
	dir := t.TempDir()
	l := mustLog(t, dir)
	base := time.Now().UTC()
	for range 200 {
		rec := pageRecord(t, "Mozilla/5.0 (X11; Linux loongarch64) Chrome/102", base)
		if err := l.Write(rec); err != nil {
			t.Fatal(err)
		}
	}
	size := fileSize(t, filepath.Join(dir, "whoami-"+base.Format("20060102")+".jsonl"))
	l.Close()

	stats := NewStats()
	n, err := stats.Replay(mustLog(t, dir), 1, size/4)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if n >= 200 || n <= 0 {
		t.Errorf("字节预算下回放 %d 条，文件总大小 %d", n, size)
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func TestStatsObserveCounts(t *testing.T) {
	s := NewStats()
	uaKylin := "Mozilla/5.0 (X11; Linux aarch64; Kylin) AppleWebKit/537.36 Kylinbrowser/1.2 Chrome/78"
	page := pageRecord(t, uaKylin, time.Now().UTC())
	page.Client.IP = "203.0.113.9"
	page.Embedded = true
	page.Host = "intra.example.com"
	s.Observe(page)
	s.Observe(page)

	api := LogRecord{Kind: KindAPI, Result: resultFor(t, uaKylin)}
	s.Observe(api)

	report := LogRecord{Kind: KindReport, Result: resultFor(t, uaKylin)}
	s.Observe(report)

	v := s.Snapshot("data/logs")
	if v.Visits != 2 || v.Reports != 1 {
		t.Errorf("visits=%d reports=%d", v.Visits, v.Reports)
	}
	// API 调用单独计数：既不进访问量，也不进状态分布。
	if v.APICalls != 1 {
		t.Errorf("apiCalls=%d, want 1", v.APICalls)
	}
	total := int64(0)
	for _, r := range v.Server.Status {
		total += r.Count
	}
	if total != 2 {
		t.Errorf("server 分布合计 %d, want 2（API 调用不该进分布）", total)
	}
	if v.UniqueIPs != 1 {
		t.Errorf("unique=%d, want 1", v.UniqueIPs)
	}
	if v.JSCoverage != 50 {
		t.Errorf("coverage = %v, want 50", v.JSCoverage)
	}
	if len(v.Daily) != 1 || v.Daily[0].Visits != 2 {
		t.Errorf("daily = %+v", v.Daily)
	}
	var hostRow *Row
	for i := range v.Server.Host {
		if v.Server.Host[i].Key == "intra.example.com" {
			hostRow = &v.Server.Host[i]
		}
	}
	if hostRow == nil || hostRow.Count != 2 {
		t.Errorf("iframe 宿主统计 = %+v", v.Server.Host)
	}
	if v.Server.Status[0].Key != "确认" || v.Server.Status[0].Count != 2 {
		t.Errorf("status rows = %+v", v.Server.Status)
	}
}

// TestStatsUniqueIPsIsBounded 预填到容量上限：IP 由客户端伪造，
// 独立地址集合必须封顶，之后的新地址不再新增。
func TestStatsUniqueIPsIsBounded(t *testing.T) {
	s := NewStats()
	for i := 0; i < maxUniqueIPs; i++ {
		s.uniqueIPs[fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)] = true
	}
	rec := pageRecord(t, "Mozilla/5.0 (X11; UOS) Chrome/120", time.Now().UTC())
	rec.Client.IP = "203.0.113.9"
	s.Observe(rec)
	if got := s.Snapshot("").UniqueIPs; got != maxUniqueIPs {
		t.Errorf("unique = %d, want 封顶在 %d", got, maxUniqueIPs)
	}
}

func TestStatsEmbeddedHostFallback(t *testing.T) {
	s := NewStats()
	rec := pageRecord(t, "Mozilla/5.0 (X11; UOS) Chrome/120", time.Now().UTC())
	rec.Embedded = true
	rec.Host = ""
	s.Observe(rec)
	v := s.Snapshot("")
	if len(v.Server.Host) != 1 || v.Server.Host[0].Key != "来源未知" {
		t.Errorf("host = %+v", v.Server.Host)
	}
	if v.Server.Label[0].Key != "无归属标注" {
		t.Errorf("label = %+v", v.Server.Label)
	}
}

func TestRowsTopNAggregatesRest(t *testing.T) {
	m := map[string]int64{}
	for i := range topNRows + 5 {
		m[strings.Repeat("x", i+1)] = int64(i + 1)
	}
	rows := rowsOf(m)
	var total int64
	for _, r := range rows {
		total += r.Count
	}
	if len(rows) != topNRows+1 {
		t.Fatalf("行数 = %d, want %d（前 N 行 + 其它）", len(rows), topNRows+1)
	}
	if !strings.HasPrefix(rows[len(rows)-1].Key, "其它") {
		t.Errorf("末行应是聚合行：%+v", rows[len(rows)-1])
	}
	if total != sumMap(m) {
		t.Errorf("聚合后总数丢失：%d vs %d", total, sumMap(m))
	}
	if rows[0].Pct <= 0 || rows[0].Pct > 100 {
		t.Errorf("占比异常：%+v", rows[0])
	}
}

func sumMap(m map[string]int64) int64 {
	var t int64
	for _, v := range m {
		t += v
	}
	return t
}

func TestAnonymizeIPModes(t *testing.T) {
	salt := []byte("01234567")
	v4 := mustAddr(t, "203.0.113.9")
	v6 := mustAddr(t, "2001:db8::dead:beef")

	if got := AnonymizeIP(v4, "off", salt); got != "203.0.113.9" {
		t.Errorf("off = %q", got)
	}
	if got := AnonymizeIP(v4, "last-octet", salt); got != "203.0.113.0" {
		t.Errorf("last-octet v4 = %q", got)
	}
	if got := AnonymizeIP(v6, "last-octet", salt); got != "2001:db8::" {
		t.Errorf("last-octet v6 = %q", got)
	}
	full := AnonymizeIP(v4, "full", salt)
	if !strings.HasPrefix(full, "anon-") || strings.Contains(full, "203") {
		t.Errorf("full = %q", full)
	}
	if AnonymizeIP(v4, "full", salt) != full {
		t.Error("同一地址的哈希标识必须稳定，否则无法去重")
	}
	if AnonymizeIP(v4, "full", []byte("different")) == full {
		t.Error("换盐必须换标识")
	}
	if got := AnonymizeIP(mustAddr(t, "1.2.3.4"), "", salt); got != "1.2.3.4" {
		t.Errorf("未配置等价于 off：%q", got)
	}
}

func TestServerEndToEndLogAndStats(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.LogDir = dir
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ua := "Mozilla/5.0 (X11; Linux loongarch64; UOS) AppleWebKit/537.36 Chrome/102"
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("User-Agent", ua)
	s.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("index = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	pr := httptest.NewRequest(http.MethodPost, "/report", strings.NewReader(`{"platform":"Linux","architecture":"loongarch","bitness":"64"}`))
	pr.Header.Set("User-Agent", ua)
	s.ServeHTTP(rec, pr)
	if rec.Code != http.StatusOK {
		t.Fatalf("report = %d", rec.Code)
	}

	srv := httptest.NewRecorder()
	s.ServeHTTP(srv, httptest.NewRequest(http.MethodGet, "/api/stats", nil))
	var v StatsView
	if err := json.Unmarshal(srv.Body.Bytes(), &v); err != nil {
		t.Fatalf("stats decode: %v\n%s", err, srv.Body)
	}
	if v.Visits != 1 || v.Reports != 1 || v.UniqueIPs != 1 {
		t.Errorf("stats = %+v", v)
	}
	if v.LogDir != dir || !v.Enabled {
		t.Errorf("logDir=%q enabled=%v", v.LogDir, v.Enabled)
	}

	// 重启后靠日志回放重建同样的计数，这是不引入数据库的前提。
	s.Close()
	s2, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	defer s2.Close()
	rec = httptest.NewRecorder()
	s2.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("stats page = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "页面访问") {
		t.Errorf("统计页渲染异常：%s", rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "回放了") {
		t.Error("重启后应说明回放了多少条")
	}

	rec = httptest.NewRecorder()
	s2.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/stats", nil))
	var v2 StatsView
	json.Unmarshal(rec.Body.Bytes(), &v2)
	if v2.Visits != 1 || v2.Reports != 1 {
		t.Errorf("重启后 stats = %+v", v2)
	}
}

func TestStatsPageHidesEmptyGroups(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer(t).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "日志落盘未开启") {
		t.Error("未启用日志时应明说")
	}
	if strings.Contains(body, `<h2 class="section">合并浏览器端回报后的分布</h2>`) {
		t.Error("没有回报数据时不该排空表头")
	}
	if strings.Contains(body, `<tbody>\n  <tr><th></th>`) {
		t.Error("出现空表行")
	}
}

func TestStatsObserveIsConcurrencySafe(t *testing.T) {
	s := NewStats()
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Observe(pageRecord(t, "Mozilla/5.0 (X11; Linux sw_64) Chrome/92", time.Now().UTC()))
		}()
	}
	wg.Wait()
	if v := s.Snapshot(""); v.Visits != 32 {
		t.Errorf("visits = %d, want 32", v.Visits)
	}
}
