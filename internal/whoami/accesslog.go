package whoami

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// 记录类型：一次访客行为可能同时产生页面请求与浏览器端回报，
// 统计必须分得清「访问」和「回报」，否则总访问数会翻倍。
const (
	KindPage   = "page"
	KindReport = "report"
	KindAPI    = "api"
)

// logFilePattern 限定我们能安全删除的文件，只认自己写出的按天文件名。
var logFilePattern = regexp.MustCompile(`^whoami-(\d{8})\.jsonl$`)

// LogRecord 是一行 JSONL。Kind 平铺在结果之外，回放时按同样顺序解析。
type LogRecord struct {
	Kind string `json:"kind"`
	Result
}

// AccessLog 是追加式按天 JSONL 落盘。低流量场景每条同步写出，
// 不做缓冲聚合：宁可多一次 write 系统调用，也不要进程被杀时丢掉最后几条记录。
type AccessLog struct {
	dir      string
	keepDays int
	now      func() time.Time

	mu     sync.Mutex
	file   *os.File
	curDay string
}

func NewAccessLog(dir string, keepDays int) (*AccessLog, error) {
	if dir == "" {
		return nil, nil // 关闭落盘
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	l := &AccessLog{dir: dir, keepDays: keepDays, now: time.Now}
	if keepDays > 0 {
		l.prune()
	}
	return l, nil
}

func (l *AccessLog) Dir() string {
	if l == nil {
		return ""
	}
	return l.dir
}

// Write 追加一条记录，按天滚动文件。
func (l *AccessLog) Write(rec LogRecord) error {
	if l == nil {
		return nil
	}
	if rec.Time.IsZero() {
		rec.Time = l.now()
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	line := append(b, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	day := rec.Time.UTC().Format("20060102")
	if day != l.curDay || l.file == nil {
		if l.file != nil {
			l.file.Close()
		}
		f, err := os.OpenFile(filepath.Join(l.dir, "whoami-"+day+".jsonl"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		l.file, l.curDay = f, day
	}
	_, err = l.file.Write(line)
	return err
}

func (l *AccessLog) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// prune 删除超出保留天数的日志。只按 logFilePattern 命中的文件名动手，
// 目录里的其它文件一律不碰。
func (l *AccessLog) prune() {
	names, err := filepath.Glob(filepath.Join(l.dir, "whoami-*.jsonl"))
	if err != nil {
		return
	}
	cutoff := l.now().UTC().AddDate(0, 0, -l.keepDays).Format("20060102")
	for _, path := range names {
		m := logFilePattern.FindStringSubmatch(filepath.Base(path))
		if m == nil || m[1] >= cutoff {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("prune log failed", "path", path, "err", err)
		}
	}
}

// daysBack 返回最近 n 天的文件名（新→旧），存在的才返回。
func (l *AccessLog) daysBack(n int) []string {
	if l == nil {
		return nil
	}
	var out []string
	for i := range n {
		day := l.now().UTC().AddDate(0, 0, -i).Format("20060102")
		path := filepath.Join(l.dir, "whoami-"+day+".jsonl")
		if _, err := os.Stat(path); err == nil {
			out = append(out, path)
		}
	}
	return out
}

// Replay 从日志重建计数：日志是唯一真源，不引入第二份状态存储。
// 从最新一天往回扫，累计读取上限 maxBytes，避免启动被大日志拖住。
func (s *Stats) Replay(l *AccessLog, days int, maxBytes int64) (int64, error) {
	if l == nil || days <= 0 {
		return 0, nil
	}
	var scanned, lines int64
	for _, path := range l.daysBack(days) {
		if scanned >= maxBytes {
			break
		}
		f, err := os.Open(path)
		if err != nil {
			return lines, err
		}
		remaining := maxBytes - scanned
		dec := json.NewDecoder(io.LimitReader(f, remaining))
		for {
			var rec LogRecord
			if err := dec.Decode(&rec); err != nil {
				break
			}
			s.Observe(rec)
			lines++
		}
		info, statErr := f.Stat()
		if statErr == nil {
			scanned += info.Size()
		}
		f.Close()
	}
	return lines, nil
}
