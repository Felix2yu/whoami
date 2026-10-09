package whoami

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// GeoValue 是一条归属信息，保持接口字段的配置顺序。
type GeoValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Geo 是一次 IP 归属查询的结果。
type Geo []GeoValue

// maxGeoValue 限制单个归属值的长度：接口返回的运营商名称可能很长。
const maxGeoValue = 64

// IpInfoProvider 是 IP 归属信息的可插拔来源。
// 你那个老的 IP 服务如果有 JSON 接口，实现这个接口接进来即可，
// 判定与页面都不用改。
type IpInfoProvider interface {
	Name() string
	Enabled() bool
	Lookup(ctx context.Context, addr netip.Addr) (Geo, error)
}

// noopProvider 是默认实现：一次外部请求都不发。
// 默认不外呼的理由很实在——访客 IP 是个人信息，把它交给第三方有合规风险，
// 而且内网部署通常根本没有出口。
type noopProvider struct{}

func (noopProvider) Name() string  { return "未启用" }
func (noopProvider) Enabled() bool { return false }
func (noopProvider) Lookup(context.Context, netip.Addr) (Geo, error) {
	return nil, nil
}

// GeoConfig 描述一个通用 HTTP 归属接口。
type GeoConfig struct {
	// Endpoint 里的 {ip} 会被替换成查询地址；没有占位符时地址追加到末尾。
	Endpoint string
	Timeout  time.Duration
	// Fields 指定从响应 JSON 里取哪些键，顺序即页面显示顺序。
	Fields []string
	Cache  time.Duration
	Size   int
}

func DefaultGeoConfig() GeoConfig {
	return GeoConfig{
		Timeout: 2 * time.Second,
		Fields:  []string{"country", "province", "city", "isp", "asn"},
		Cache:   10 * time.Minute,
		Size:    1024,
	}
}

type httpGeoProvider struct {
	cfg  GeoConfig
	http *http.Client

	mu    sync.Mutex
	items map[string]geoCacheItem
}

type geoCacheItem struct {
	geo  Geo
	exp  time.Time
	fail bool
}

func NewHTTPGeoProvider(cfg GeoConfig) (*httpGeoProvider, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("endpoint 为空")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultGeoConfig().Timeout
	}
	if len(cfg.Fields) == 0 {
		cfg.Fields = DefaultGeoConfig().Fields
	}
	if cfg.Cache <= 0 {
		cfg.Cache = DefaultGeoConfig().Cache
	}
	if cfg.Size <= 0 {
		cfg.Size = DefaultGeoConfig().Size
	}
	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: cfg.Timeout}).DialContext,
		TLSHandshakeTimeout: cfg.Timeout,
	}
	return &httpGeoProvider{
		cfg:   cfg,
		http:  &http.Client{Timeout: cfg.Timeout, Transport: transport},
		items: map[string]geoCacheItem{},
	}, nil
}

func (p *httpGeoProvider) Name() string  { return p.cfg.Endpoint }
func (p *httpGeoProvider) Enabled() bool { return true }
func (p *httpGeoProvider) url(addr netip.Addr) string {
	s := addr.String()
	if strings.Contains(p.cfg.Endpoint, "{ip}") {
		return strings.ReplaceAll(p.cfg.Endpoint, "{ip}", s)
	}
	// 没有 {ip} 占位符时按查询参数追加：以 = 结尾的直接拼值，
	// 否则按 ? / & 的规则补一个键。
	if strings.HasSuffix(p.cfg.Endpoint, "=") {
		return p.cfg.Endpoint + s
	}
	if strings.ContainsAny(s, ":") {
		s = "[" + s + "]" // IPv6 进 URL 要带方括号
	}
	sep := "?"
	if strings.Contains(p.cfg.Endpoint, "?") {
		sep = "&"
	}
	return p.cfg.Endpoint + sep + s
}

// Lookup 取归属信息。响应必须是扁平 JSON 对象，只挑配置里点名的键。
func (p *httpGeoProvider) Lookup(ctx context.Context, addr netip.Addr) (Geo, error) {
	key := addr.String()
	now := time.Now()

	p.mu.Lock()
	if item, ok := p.items[key]; ok && now.Before(item.exp) {
		p.mu.Unlock()
		if item.fail {
			return nil, fmt.Errorf("该地址近期查询失败，按降级处理")
		}
		return item.geo, nil
	}
	p.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url(addr), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		p.put(key, geoCacheItem{geo: nil, exp: now.Add(p.failedTTL()), fail: true})
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		p.put(key, geoCacheItem{exp: now.Add(p.failedTTL()), fail: true})
		return nil, fmt.Errorf("接口返回 %d", resp.StatusCode)
	}

	// 归属接口的响应体也不可信：限 16KB，字段名与值都削短。
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("响应不是扁平 JSON 对象: %w", err)
	}
	var geo Geo
	for _, field := range p.cfg.Fields {
		v, ok := raw[field]
		if !ok {
			continue
		}
		str := strings.TrimSpace(fmt.Sprint(v))
		if str == "" || strings.EqualFold(str, "unknown") || str == "0" {
			continue
		}
		if len(str) > maxGeoValue {
			str = str[:maxGeoValue]
		}
		geo = append(geo, GeoValue{Key: field, Value: str})
	}
	p.put(key, geoCacheItem{geo: geo, exp: now.Add(p.cfg.Cache)})
	return geo, nil
}

// failedTTL 给失败结果一个短缓存，避免每个访客都去敲一个已经挂了的接口。
func (p *httpGeoProvider) failedTTL() time.Duration {
	if p.cfg.Cache > 30*time.Second {
		return 30 * time.Second
	}
	return p.cfg.Cache
}

func (p *httpGeoProvider) put(key string, item geoCacheItem) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.items) >= p.cfg.Size {
		p.evictLocked(time.Now())
	}
	p.items[key] = item
}

func (p *httpGeoProvider) evictLocked(now time.Time) {
	for k, v := range p.items {
		if now.After(v.exp) {
			delete(p.items, k)
		}
	}
	if len(p.items) < p.cfg.Size {
		return
	}
	// 全都新鲜（突发流量打到大量新地址）：扔掉最早过期的那批，保证有界。
	var oldest string
	var best time.Time
	for k, v := range p.items {
		if oldest == "" || v.exp.Before(best) {
			oldest, best = k, v.exp
		}
	}
	delete(p.items, oldest)
}

// lookupGeo 是唯一入口：未启用时零外呼，失败时静默降级并留一条警告。
func lookupGeo(ctx context.Context, p IpInfoProvider, addr netip.Addr) (Geo, string) {
	if p == nil || !p.Enabled() || !addr.IsValid() {
		return nil, ""
	}
	geo, err := p.Lookup(ctx, addr)
	if err != nil {
		slog.Warn("ip geo lookup failed", "err", err, "provider", p.Name())
		return nil, fmt.Sprintf("归属信息接口不可用：%v", err)
	}
	return geo, ""
}
