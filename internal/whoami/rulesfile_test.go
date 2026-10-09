package whoami

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRules(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	return path
}

func TestLoadRulesAcceptsBothShapes(t *testing.T) {
	const one = `[{"id":"os-hce","field":"ua","match":{"contains":["hce"],"caseFold":true},"name":"华为 HCE","domain":"发行版","category":"os","domestic":true,"xinchuang":true,"weight":80,"ceiling":90,"verified":false,"note":"预留条目"}]`

	flat, err := LoadRules(writeRules(t, one))
	if err != nil || len(flat) != 1 {
		t.Fatalf("数组形式: %d 条, err %v", len(flat), err)
	}
	wrapped, err := LoadRules(writeRules(t, `{"rules":`+one+`}`))
	if err != nil || len(wrapped) != 1 {
		t.Fatalf("包裹形式: %d 条, err %v", len(wrapped), err)
	}
	if flat[0].ID != "os-hce" || !flat[0].Match.Hit("Mozilla/5.0 (X11; Linux HCE) Chrome/120") {
		t.Errorf("外部规则没带出可用条件：%+v", flat[0])
	}
	if none, err := LoadRules(""); err != nil || none != nil {
		t.Errorf("未配置路径应为空：%v %v", none, err)
	}
}

func TestLoadRulesFailsLoudly(t *testing.T) {
	cases := []string{
		`{not json}`,
		`[]`,
		`[{"field":"ua","match":{"contains":["x"]}}]`, // 缺 ID，交给 NewDetector 拒绝
	}
	for _, body := range cases[:2] {
		if _, err := LoadRules(writeRules(t, body)); err == nil {
			t.Errorf("应拒绝 %s", body)
		}
	}
	if _, err := LoadRules(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("配了路径却读不到文件必须报错，不能静默当成没配")
	}

	// 缺 ID 的规则能被 LoadRules 收下来，但 NewServer 必须拒绝整张表。
	cfg := DefaultConfig()
	cfg.LogDir = ""
	cfg.RulesPath = writeRules(t, cases[2])
	if _, err := NewServer(cfg); err == nil || !strings.Contains(err.Error(), "缺少 ID") {
		t.Errorf("NewServer 应拒绝缺 ID 的外部规则，实际 %v", err)
	}
}

func TestExternalRuleAddsDetectionWithoutCodeChange(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LogDir = ""
	cfg.RulesPath = writeRules(t, `[{"id":"os-hce","field":"ua","match":{"contains":["hce"],"caseFold":true},
		"name":"华为 HCE","domain":"发行版","category":"os","domestic":true,"xinchuang":true,
		"weight":85,"ceiling":90,"verified":false,"note":"预留条目，实测后转正"}]`)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer s.Close()

	// 服务端不认这个 token，靠外部规则把它抬成信创结论。
	r := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; HCE) AppleWebKit/537.36 Chrome/120")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)
	var res Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Verdict.Status != "confirmed" || !strings.Contains(res.Verdict.Reasons[0], "华为 HCE") {
		t.Errorf("外部规则未生效：%+v", res.Verdict)
	}
	if src := s.RulesSource(); src.External != 1 || src.Replaced != 0 || src.Total != src.Builtin+1 {
		t.Errorf("rulesSource = %+v", src)
	}
}

func TestExternalRuleOverridesBuiltinSameID(t *testing.T) {
	// 同一个 ID：改天花板，而不是再堆一条重复规则。
	cfg := DefaultConfig()
	cfg.LogDir = ""
	cfg.RulesPath = writeRules(t, `[{"id":"cpu-aarch64","field":"arch","match":{"equals":["aarch64","arm64"],"caseFold":true},
		"name":"ARM 64 位（收紧）","domain":"CPU 架构","category":"cpu","domestic":false,"xinchuang":true,
		"weight":55,"ceiling":30,"verified":true,"note":"按单位口径不再算疑似"}]`)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer s.Close()

	r := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 Chrome/120")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)
	var res Result
	json.Unmarshal(rec.Body.Bytes(), &res)

	if res.Verdict.Status != "unknown" {
		t.Errorf("覆盖天花板后应退出疑似区间：%+v", res.Verdict)
	}
	var found bool
	for _, f := range res.Findings {
		if f.Name == "ARM 64 位（收紧）" {
			found = true
		}
		if f.Name == "ARM 64 位" {
			t.Error("同 ID 覆盖后不该保留内置那条")
		}
	}
	if !found {
		t.Error("覆盖后的规则未参与判定")
	}
	if src := s.RulesSource(); src.Replaced != 1 || src.Total != src.Builtin {
		t.Errorf("rulesSource = %+v", src)
	}
}

func TestRulesEndpointExportsEffectiveTable(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var payload struct {
		Source RulesSource `json:"source"`
		Rules  []Rule      `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Source.Builtin != len(BuiltinRules()) || payload.Source.Total != len(payload.Rules) {
		t.Errorf("source = %+v rules = %d", payload.Source, len(payload.Rules))
	}

	var hasXinchuangRule bool
	for _, ru := range payload.Rules {
		if ru.ID == "cpu-loongarch64" {
			hasXinchuangRule = ru.Xinchuang && ru.Ceiling == 100
		}
	}
	if !hasXinchuangRule {
		t.Error("导出内容应足以照着写外部规则")
	}
	// 导出的表能原样喂回给 -rules，这才是可用的追加入口。
	out, err := json.Marshal(payload.Rules)
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.LogDir = ""
	cfg.RulesPath = writeRules(t, string(out))
	reloaded, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("导出的规则表无法重新加载: %v", err)
	}
	reloaded.Close()
}

func TestMergeRulesIsIdempotent(t *testing.T) {
	builtin := BuiltinRules()
	extra := []Rule{{ID: "x", Field: FieldUA, Name: "X", Category: CatOS, Weight: 10, Ceiling: 10}}
	a, r1 := mergeRules(builtin, extra)
	b, r2 := mergeRules(builtin, append(append([]Rule{}, extra...), extra[0]))
	if r1 != 0 || r2 != 1 {
		t.Errorf("replaced = %d/%d", r1, r2)
	}
	if len(a) != len(b) {
		t.Errorf("重复条目应被合并：%d vs %d", len(a), len(b))
	}
	if len(builtin) != len(BuiltinRules()) {
		t.Error("merge 不该改动内置表")
	}
}
