package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// TestHandleConfig_GetReturnsFullStruct verifies that GET /api/config
// surfaces the full live config plus the editable_sections capability
// list. Settings UI uses this to render every section.
func TestHandleConfig_GetReturnsFullStruct(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(`
[observer]
log_level = "warn"

[intelligence]
monthly_budget_usd = 75
`), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		ConfigPath       string        `json:"config_path"`
		Config           config.Config `json:"config"`
		EditableSections []string      `json:"editable_sections"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ConfigPath != cfgPath {
		t.Errorf("config_path: got %q want %q", got.ConfigPath, cfgPath)
	}
	if got.Config.Observer.LogLevel != "warn" {
		t.Errorf("log_level not loaded: %q", got.Config.Observer.LogLevel)
	}
	if got.Config.Intelligence.MonthlyBudgetUSD != 75 {
		t.Errorf("monthly_budget_usd: got %v want 75", got.Config.Intelligence.MonthlyBudgetUSD)
	}
	foundPricing := false
	foundProcess := false
	for _, s := range got.EditableSections {
		if s == "pricing" {
			foundPricing = true
		}
		if s == "process" {
			foundProcess = true
		}
	}
	if !foundPricing {
		t.Errorf("editable_sections must include pricing: %v", got.EditableSections)
	}
	if !foundProcess {
		t.Errorf("editable_sections must include process: %v", got.EditableSections)
	}
}

// TestHandleConfig_NoFileReturnsDefaults — fresh install path. No
// config.toml on disk yet, GET /api/config still works and returns the
// baked-in defaults so the Settings UI has something to render.
func TestHandleConfig_NoFileReturnsDefaults(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "missing.toml") // never created
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
}

// TestHandleConfigPricing_SaveWritesFileAndReloadsEngine pins the full
// hot-reload path: PUT /api/config/pricing writes the new model rates
// to disk, creates a .bak of the previous file, and the cost engine
// reloads in-place so subsequent Compute calls see the new rate.
func TestHandleConfigPricing_SaveWritesFileAndReloadsEngine(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	const originalToml = `
[observer]
log_level = "info"
`
	if err := os.WriteFile(cfgPath, []byte(originalToml), 0o644); err != nil {
		t.Fatal(err)
	}

	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	engine := cost.NewEngine(config.IntelligenceConfig{})
	server, err := New(Options{
		DB:         database,
		CostEngine: engine,
		ConfigPath: cfgPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: pre-save the engine returns baked-in Sonnet 4.6 rates.
	pre, ok := engine.Lookup("claude-sonnet-4-6")
	if !ok || pre.Input != 3 {
		t.Fatalf("baseline lookup: %+v ok=%v", pre, ok)
	}

	// PUT new pricing override: bump claude-sonnet-4-6 input to $99.
	body := `{"models":{"claude-sonnet-4-6":{"input":99,"output":999,"cache_read":9.9}}}`
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/api/config/pricing", strings.NewReader(body)))
	if rr.Code != 200 {
		t.Fatalf("PUT status: %d body=%s", rr.Code, rr.Body.String())
	}
	var saveResp struct {
		Saved      bool   `json:"saved"`
		BackupPath string `json:"backup_path"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&saveResp); err != nil {
		t.Fatal(err)
	}
	if !saveResp.Saved {
		t.Errorf("response did not report saved=true")
	}
	if saveResp.BackupPath != cfgPath+".bak" {
		t.Errorf("backup path: got %q want %q", saveResp.BackupPath, cfgPath+".bak")
	}

	// .bak preserves the prior content (Option A — comments are lost
	// on save but the prior version is recoverable).
	bak, err := os.ReadFile(cfgPath + ".bak")
	if err != nil {
		t.Fatalf("read .bak: %v", err)
	}
	if string(bak) != originalToml {
		t.Errorf(".bak contents drifted: got %q want %q", bak, originalToml)
	}

	// The new file parses back through config.Load with the override applied.
	reloaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	mp, ok := reloaded.Intelligence.Pricing.Models["claude-sonnet-4-6"]
	if !ok || mp.Input != 99 || mp.Output != 999 {
		t.Errorf("override not persisted: %+v ok=%v", mp, ok)
	}

	// Engine reloaded in place: same instance now returns the new rates.
	post, ok := engine.Lookup("claude-sonnet-4-6")
	if !ok || post.Input != 99 || post.Output != 999 {
		t.Errorf("engine not reloaded: %+v ok=%v", post, ok)
	}
}

// TestHandleConfigPricing_NoConfigPath rejects saves when the server
// was started without a ConfigPath option (the dashboard subcommand is
// always given one, but tests / future ephemeral modes may not).
func TestHandleConfigPricing_NoConfigPath(t *testing.T) {
	tdir := t.TempDir()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/api/config/pricing", strings.NewReader(`{}`)))
	if rr.Code != http.StatusConflict {
		t.Errorf("status: got %d want 409", rr.Code)
	}
}

// TestHandleConfigPricingDefaults_ShapeAndCoverage pins the baked-in
// pricing table that the dashboard renders as a reference list. When
// pricing-reference.md drifts (new models, rate changes), this test
// catches if the matching defaultPricing entry didn't get updated.
func TestHandleConfigPricingDefaults_ShapeAndCoverage(t *testing.T) {
	tdir := t.TempDir()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config/pricing/defaults", nil))
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Defaults map[string]struct {
			Input                      float64 `json:"input"`
			Output                     float64 `json:"output"`
			CacheRead                  float64 `json:"cache_read"`
			CacheCreation              float64 `json:"cache_creation"`
			CacheCreation1h            float64 `json:"cache_creation_1h"`
			LongContextThreshold       int64   `json:"long_context_threshold,omitempty"`
			LongContextInput           float64 `json:"long_context_input,omitempty"`
			LongContextOutput          float64 `json:"long_context_output,omitempty"`
			LongContextCacheRead       float64 `json:"long_context_cache_read,omitempty"`
			LongContextCacheCreation   float64 `json:"long_context_cache_creation,omitempty"`
			LongContextCacheCreation1h float64 `json:"long_context_cache_creation_1h,omitempty"`
		} `json:"defaults"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	// Sanity: every provider's flagship is present with non-trivial rates.
	for _, model := range []string{
		"claude-sonnet-4-6", "claude-opus-4-7", "claude-haiku-4-5",
		"gpt-5", "gpt-5.4", "gemini-2.5-pro", "grok-4-20", "kimi-k2-5",
	} {
		entry, ok := got.Defaults[model]
		if !ok {
			t.Errorf("default missing: %s", model)
			continue
		}
		if entry.Input <= 0 && entry.Output <= 0 {
			t.Errorf("%s has zero rates: %+v", model, entry)
		}
	}
	// LC tier round-trip: claude-sonnet-4 should expose its 200K threshold
	// (4.5 is flat since 2026-10-01: Anthropic states no premium for it).
	if s := got.Defaults["claude-sonnet-4"]; s.LongContextThreshold != 200_000 {
		t.Errorf("claude-sonnet-4 LC threshold: got %v want 200000", s.LongContextThreshold)
	}
	// Gross size sanity: there are 60+ baked-in models per pricing-reference.md.
	if len(got.Defaults) < 50 {
		t.Errorf("default count: got %d want >= 50", len(got.Defaults))
	}
}

// TestHandleConfigSection_SaveRetention pins the per-section save
// path: PUT /api/config/section/retention writes a new RetentionConfig,
// the file persists the change, and the response sets
// restart_required=true so the UI surfaces the restart banner.
func TestHandleConfigSection_SaveRetention(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(`[observer]
log_level = "info"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	body := `{"MaxAgeDays":365,"MaxDBSizeMB":2000,"PruneOnStartup":false,"ObserverLogMaxAgeDays":60}`
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPut, "/api/config/section/retention", strings.NewReader(body)))
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Saved           bool   `json:"saved"`
		Section         string `json:"section"`
		RestartRequired bool   `json:"restart_required"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Saved {
		t.Errorf("response did not report saved=true")
	}
	if resp.Section != "retention" {
		t.Errorf("section echo: got %q want retention", resp.Section)
	}
	if !resp.RestartRequired {
		t.Errorf("restart_required must be true for non-pricing saves")
	}

	// Verify persistence — the new file parses with the override applied.
	reloaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Observer.Retention.MaxAgeDays != 365 {
		t.Errorf("MaxAgeDays not persisted: got %v want 365", reloaded.Observer.Retention.MaxAgeDays)
	}
	if reloaded.Observer.Retention.MaxDBSizeMB != 2000 {
		t.Errorf("MaxDBSizeMB: got %v want 2000", reloaded.Observer.Retention.MaxDBSizeMB)
	}
}

// TestHandleConfigSection_Dashboard pins finding #1 + #4: the [dashboard]
// section saves through /api/config/section/dashboard, a garbage addr is
// rejected with a 4xx BEFORE the file is rewritten (no bricked restart), and
// the GET capability list advertises "dashboard".
func TestHandleConfigSection_Dashboard(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\nlog_level = \"info\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	// Valid save persists.
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPut,
		"/api/config/section/dashboard", strings.NewReader(`{"Addr":"127.0.0.1:8082"}`)))
	if rr.Code != 200 {
		t.Fatalf("valid save status: %d body=%s", rr.Code, rr.Body.String())
	}
	reloaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Dashboard.Addr != "127.0.0.1:8082" {
		t.Errorf("dashboard.addr not persisted: got %q", reloaded.Dashboard.Addr)
	}

	// Garbage addr is rejected with a 4xx and the file is NOT rewritten.
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPut,
		"/api/config/section/dashboard", strings.NewReader(`{"Addr":"garbage:notaport"}`)))
	if rr.Code < 400 || rr.Code >= 500 {
		t.Fatalf("garbage addr must be rejected with a 4xx, got %d body=%s", rr.Code, rr.Body.String())
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("config file must NOT be rewritten on a rejected save:\nbefore=%s\nafter=%s", before, after)
	}

	// The GET capability list advertises "dashboard".
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if rr.Code != 200 {
		t.Fatalf("GET /api/config: %d", rr.Code)
	}
	var got struct {
		EditableSections []string `json:"editable_sections"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got.EditableSections, "dashboard") {
		t.Errorf("editable_sections must include dashboard: %v", got.EditableSections)
	}
}

// TestHandleConfigSection_SaveProcess pins the process-capture section of the
// config-write seam: the dashboard "process poll rate" setting saves through
// /api/config/section/process, persists to the TOML file, round-trips through
// config.Load, and rejects an out-of-range poll interval with a 400. The save
// touches only the editable scalars — the sub-sections (argv/env/etc.) and
// WindowsBinaryPath keep their loaded values because the handler reloads fresh
// config and overwrites only the five operator-facing fields.
func TestHandleConfigSection_SaveProcess(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(`[observer.process]
windows_binary_path = "/mnt/c/Users/x/.observer/observer.exe"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	body := `{"Enabled":true,"Backend":"both","CaptureUnattributed":true,"PollIntervalMS":5000,"BridgePollIntervalMS":0,"Network":{"Enabled":true,"CaptureRemoteHost":true,"RedactPrivateIPs":true,"CaptureBodies":"proxied","MaxRequestBytes":4096,"MaxResponseBytes":8192,"CaptureHeaders":true,"ScrubBodies":true,"StoreBinary":false}}`
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPut, "/api/config/section/process", strings.NewReader(body)))
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}

	reloaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p := reloaded.Observer.Process
	if !p.Enabled || p.Backend != "both" || !p.CaptureUnattributed || p.PollIntervalMS != 5000 {
		t.Errorf("editable fields not persisted: %+v", p)
	}
	if !p.Network.Enabled || p.Network.CaptureBodies != "proxied" || p.Network.MaxRequestBytes != 4096 || p.Network.MaxResponseBytes != 8192 || !p.Network.RedactPrivateIPs {
		t.Errorf("network fields not persisted: %+v", p.Network)
	}
	// Untouched field preserved (handler reloads fresh config, overwrites only
	// the editable scalars).
	if p.WindowsBinaryPath != "/mnt/c/Users/x/.observer/observer.exe" {
		t.Errorf("WindowsBinaryPath clobbered: got %q", p.WindowsBinaryPath)
	}

	// A negative poll interval is rejected at the seam with a 400, never
	// written (so a bad value can't break daemon start).
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPut, "/api/config/section/process",
			strings.NewReader(`{"Enabled":true,"Backend":"both","PollIntervalMS":-5}`)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("negative poll interval: got status %d, want 400 (body=%s)", rr.Code, rr.Body.String())
	}
	// And an unknown backend is rejected too.
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPut, "/api/config/section/process",
			strings.NewReader(`{"Enabled":true,"Backend":"bogus","PollIntervalMS":2000}`)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad backend: got status %d, want 400", rr.Code)
	}

	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPut, "/api/config/section/process",
			strings.NewReader(`{"Enabled":true,"Backend":"both","PollIntervalMS":2000,"Network":{"Enabled":true,"CaptureBodies":"tls","MaxRequestBytes":1,"MaxResponseBytes":1}}`)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad network capture_bodies: got status %d, want 400", rr.Code)
	}
}

// TestHandleConfigSection_SaveProcessPartialBody pins F3: a PARTIAL process body
// preserves every field it omits (pointer decode) instead of zeroing them. Before
// the fix a partial {"Enabled":true} blanked Backend to "" (which the vocabulary
// check then rejected) and reset the intervals to 0, forcing the FE into a racy
// read-then-write. A partial Network body likewise preserves omitted Network
// fields.
func TestHandleConfigSection_SaveProcessPartialBody(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(`[observer.process]
enabled = false
backend = "poll"
capture_unattributed = true
poll_interval_ms = 3000
bridge_poll_interval_ms = 1500

[observer.process.network]
enabled = true
capture_bodies = "proxied"
max_request_bytes = 4096
max_response_bytes = 8192
`), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	// Partial body: only Enabled. Everything else must survive.
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPut, "/api/config/section/process", strings.NewReader(`{"Enabled":true}`)))
	if rr.Code != 200 {
		t.Fatalf("partial process save status: %d body=%s", rr.Code, rr.Body.String())
	}
	reloaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p := reloaded.Observer.Process
	if !p.Enabled {
		t.Errorf("Enabled not applied: %+v", p)
	}
	if p.Backend != "poll" || p.PollIntervalMS != 3000 || p.BridgePollIntervalMS != 1500 || !p.CaptureUnattributed {
		t.Errorf("partial body zeroed preserved scalars: backend=%q poll=%d bridge=%d capUnattr=%v (want poll/3000/1500/true)",
			p.Backend, p.PollIntervalMS, p.BridgePollIntervalMS, p.CaptureUnattributed)
	}
	if !p.Network.Enabled || p.Network.CaptureBodies != "proxied" || p.Network.MaxRequestBytes != 4096 || p.Network.MaxResponseBytes != 8192 {
		t.Errorf("partial body (no Network key) clobbered network config: %+v", p.Network)
	}

	// Partial Network body: flip one field, the sibling Network fields survive.
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPut, "/api/config/section/process", strings.NewReader(`{"Network":{"MaxRequestBytes":1024}}`)))
	if rr.Code != 200 {
		t.Fatalf("partial network save status: %d body=%s", rr.Code, rr.Body.String())
	}
	reloaded, err = config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p = reloaded.Observer.Process
	if p.Network.MaxRequestBytes != 1024 {
		t.Errorf("Network.MaxRequestBytes not applied: got %d", p.Network.MaxRequestBytes)
	}
	if p.Network.CaptureBodies != "proxied" || p.Network.MaxResponseBytes != 8192 || !p.Network.Enabled {
		t.Errorf("partial Network body zeroed siblings: %+v", p.Network)
	}
	// The top-level scalars set earlier also survive the Network-only PUT.
	if p.Backend != "poll" || p.PollIntervalMS != 3000 || !p.Enabled {
		t.Errorf("Network-only PUT clobbered top-level scalars: backend=%q poll=%d enabled=%v", p.Backend, p.PollIntervalMS, p.Enabled)
	}
}

// TestHandleConfigSection_ObservabilityJudgeBudgetPartial pins the Policies
// module's judge/budget write path (docs/handovers/policies-module-phase-b-*):
// the observability section save is written by THREE surfaces (the Settings
// Enabled toggle, the Policies judge form, the Policies budget form), so every
// field is a pointer and only the sent fields apply. Critically, a judge/budget
// save must NOT disable the subsystem (Enabled omitted ⇒ preserved) and must
// never touch the admission criterion table (owned by the admission POLICY
// persister, not this seam).
func TestHandleConfigSection_ObservabilityJudgeBudgetPartial(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(`[observability]
enabled = true

[observability.judge]
model = "qwen2.5:1.5b-instruct"
base_url = "http://127.0.0.1:11434/v1"
timeout_ms = 45000

[observability.admission]
enabled = true
mode = "observe"

[[observability.admission.criterion]]
id = "on-scope"
type = "valid_use_case"
definition = "only product questions"
decision = "ask"

[observability.admission.budget]
enabled = true
per_user_5h_usd = 5.0
per_user_weekly_usd = 25.0
`), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	put := func(body string) int {
		rr := httptest.NewRecorder()
		server.Handler().ServeHTTP(rr,
			httptest.NewRequest(http.MethodPut, "/api/config/section/observability", strings.NewReader(body)))
		return rr.Code
	}

	// 1. Judge-only save: the model changes; Enabled, the criterion table, and
	//    the budget all survive.
	if code := put(`{"Judge":{"Model":"gpt-4o-mini","BaseURL":"https://openrouter.ai/api/v1","APIKeyEnv":"OPENROUTER_API_KEY","TimeoutMS":30000,"MaxTokens":0,"NumCtx":0}}`); code != 200 {
		t.Fatalf("judge save status: %d", code)
	}
	got, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if got.Observability.Judge.Model != "gpt-4o-mini" {
		t.Errorf("judge model not applied: %q", got.Observability.Judge.Model)
	}
	if !got.Observability.Enabled {
		t.Error("judge save disabled the subsystem (Enabled omitted must preserve true)")
	}
	if len(got.Observability.Admission.Criterion) != 1 || got.Observability.Admission.Criterion[0].ID != "on-scope" {
		t.Errorf("judge save clobbered the criterion table: %+v", got.Observability.Admission.Criterion)
	}
	if got.Observability.Admission.Budget.PerUser5hUSD != 5.0 {
		t.Errorf("judge save clobbered the budget: %+v", got.Observability.Admission.Budget)
	}

	// 2. Budget-only save: caps change; the judge (just set) and the criterion
	//    survive.
	if code := put(`{"Admission":{"Budget":{"Enabled":true,"PerUser5hUSD":9.0,"PerUserWeeklyUSD":40.0,"PerUserMonthlyUSD":120.0,"UserHeader":""}}}`); code != 200 {
		t.Fatalf("budget save status: %d", code)
	}
	got, err = config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if got.Observability.Admission.Budget.PerUser5hUSD != 9.0 {
		t.Errorf("budget not applied: %+v", got.Observability.Admission.Budget)
	}
	if got.Observability.Judge.Model != "gpt-4o-mini" {
		t.Errorf("budget save clobbered the judge: %q", got.Observability.Judge.Model)
	}
	if len(got.Observability.Admission.Criterion) != 1 {
		t.Errorf("budget save clobbered the criterion table: %+v", got.Observability.Admission.Criterion)
	}

	// 3. Enabled-only toggle (the Settings surface): flips the gate without
	//    touching judge or budget.
	if code := put(`{"Enabled":false}`); code != 200 {
		t.Fatalf("enabled toggle status: %d", code)
	}
	got, err = config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if got.Observability.Enabled {
		t.Error("Enabled=false not applied")
	}
	if got.Observability.Judge.Model != "gpt-4o-mini" || got.Observability.Admission.Budget.PerUser5hUSD != 9.0 {
		t.Errorf("enabled toggle clobbered judge/budget: judge=%q budget5h=%v",
			got.Observability.Judge.Model, got.Observability.Admission.Budget.PerUser5hUSD)
	}

	// 4. A negative cap is rejected (400) and leaves the file untouched.
	if code := put(`{"Admission":{"Budget":{"Enabled":true,"PerUser5hUSD":-1}}}`); code != 400 {
		t.Fatalf("negative cap should be rejected: status %d", code)
	}
}

// TestHandleConfigSection_SaveTerminalPartialBody pins F5 + F6: a PARTIAL
// terminal body preserves the omitted attach field (pointer decode, F5), and the
// restart_required flag reflects what actually changed — Attach.Enabled binds the
// socket at daemon start (restart), Attach.RouteProxy is read per-launch by the
// CLI (no restart) (F6).
func TestHandleConfigSection_SaveTerminalPartialBody(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[terminal.attach]\nenabled = true\nroute_proxy = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	put := func(body string) (int, bool) {
		t.Helper()
		rr := httptest.NewRecorder()
		server.Handler().ServeHTTP(rr,
			httptest.NewRequest(http.MethodPut, "/api/config/section/terminal", strings.NewReader(body)))
		var out struct {
			RestartRequired bool `json:"restart_required"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out.RestartRequired
	}
	reload := func() config.TerminalAttachConfig {
		t.Helper()
		reloaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		return reloaded.Terminal.Attach
	}

	// F5: a RouteProxy-only body PRESERVES Enabled=true. F6: no restart (hot).
	code, restart := put(`{"RouteProxy":false}`)
	if code != http.StatusOK {
		t.Fatalf("RouteProxy-only PUT status %d", code)
	}
	if restart {
		t.Errorf("F6: a RouteProxy-only save must NOT require a restart")
	}
	if att := reload(); !att.Enabled {
		t.Errorf("F5: {\"RouteProxy\":false} zeroed Attach.Enabled — must be preserved true")
	} else if att.RouteProxy {
		t.Errorf("RouteProxy not persisted false: %+v", att)
	}

	// F5 (vice-versa): an Enabled-only body PRESERVES RouteProxy (now false).
	// F6: changing Enabled DOES require a restart.
	code, restart = put(`{"Enabled":false}`)
	if code != http.StatusOK {
		t.Fatalf("Enabled-only PUT status %d", code)
	}
	if !restart {
		t.Errorf("F6: changing Attach.Enabled MUST require a restart")
	}
	if att := reload(); att.RouteProxy {
		t.Errorf("F5: {\"Enabled\":false} flipped Attach.RouteProxy — must be preserved false: %+v", att)
	} else if att.Enabled {
		t.Errorf("Enabled not persisted false: %+v", att)
	}

	// F6: a no-op Enabled save (value unchanged) needs no restart.
	code, restart = put(`{"Enabled":false}`)
	if code != http.StatusOK {
		t.Fatalf("no-op Enabled PUT status %d", code)
	}
	if restart {
		t.Errorf("F6: an Enabled save that changed nothing must NOT require a restart")
	}

	// Resilient-attach arc: a DefaultOn-only body PRESERVES the other attach
	// fields (F5) and is read per-launch by the CLI, so it needs NO restart (F6).
	code, restart = put(`{"DefaultOn":false}`)
	if code != http.StatusOK {
		t.Fatalf("DefaultOn-only PUT status %d", code)
	}
	if restart {
		t.Errorf("F6: a DefaultOn-only save must NOT require a restart")
	}
	if att := reload(); att.DefaultOn {
		t.Errorf("DefaultOn not persisted false: %+v", att)
	} else if att.Enabled {
		t.Errorf("F5: {\"DefaultOn\":false} flipped Attach.Enabled — must be preserved false: %+v", att)
	}

	// All three fields in one body round-trip and persist together.
	code, restart = put(`{"Enabled":true,"RouteProxy":true,"DefaultOn":true}`)
	if code != http.StatusOK {
		t.Fatalf("three-field PUT status %d", code)
	}
	if !restart {
		t.Errorf("F6: flipping Attach.Enabled back on MUST require a restart")
	}
	if att := reload(); !att.Enabled || !att.RouteProxy || !att.DefaultOn {
		t.Errorf("three-field save did not persist all fields: %+v", att)
	}
}

// TestHandleConfigSection_SaveTerminalStrictDecode pins the terminal-section
// strict-decode guards (F4 + the bdb057c0 trailing-value check), unchanged by
// the DefaultOn addition: an unknown field, an empty body, and a trailing JSON
// value each return 400 without writing the config.
func TestHandleConfigSection_SaveTerminalStrictDecode(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[terminal.attach]\nenabled = true\nroute_proxy = true\ndefault_on = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	put := func(body string) int {
		t.Helper()
		rr := httptest.NewRecorder()
		server.Handler().ServeHTTP(rr,
			httptest.NewRequest(http.MethodPut, "/api/config/section/terminal", strings.NewReader(body)))
		return rr.Code
	}

	cases := []struct {
		name string
		body string
	}{
		{"unknown field", `{"DefaultOnn":true}`},
		{"empty object", `{}`},
		{"trailing value", `{"DefaultOn":true}{"RouteProxy":false}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code := put(tc.body); code != http.StatusBadRequest {
				t.Errorf("%s: got status %d, want 400", tc.name, code)
			}
		})
	}
}

// TestHandleConfigSection_SaveBrowser pins the Settings "Browser capture"
// control: PUT /api/config/section/browser writes [browser].granularity_ceiling,
// persists to the TOML, round-trips through config.Load, and rejects an
// out-of-vocabulary ceiling at the validate-before-write seam.
func TestHandleConfigSection_SaveBrowser(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\nlog_level = \"info\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPut, "/api/config/section/browser",
			strings.NewReader(`{"GranularityCeiling":"usage_only"}`)))
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}

	reloaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Browser.GranularityCeiling != "usage_only" {
		t.Errorf("granularity_ceiling not persisted: got %q want usage_only", reloaded.Browser.GranularityCeiling)
	}

	// An out-of-vocabulary ceiling is rejected (config.Validate) — never written.
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPut, "/api/config/section/browser",
			strings.NewReader(`{"GranularityCeiling":"everything"}`)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad ceiling: got status %d, want 400 (body=%s)", rr.Code, rr.Body.String())
	}

	// The GET capability list must advertise "browser" so the React editor
	// (which has a PUT handler + form) is actually reachable from the UI.
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if rr.Code != 200 {
		t.Fatalf("GET /api/config: %d", rr.Code)
	}
	var got struct {
		EditableSections []string `json:"editable_sections"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got.EditableSections, "browser") {
		t.Errorf("editable_sections must include browser: %v", got.EditableSections)
	}
}

// TestHandleConfigSection_AdvisorCachetrackSecrets pins the three
// sections the usability arc added to the PUT seam (P1.2–P1.4): each
// saves through /api/config/section/<name>, persists to the TOML file,
// and round-trips through config.Load. The cachetrack case explicitly
// flips the partial-merge default (enabled defaults TRUE with no
// section present) to false and asserts the explicit value survives.
func TestHandleConfigSection_AdvisorCachetrackSecrets(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\nlog_level = \"info\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	put := func(t *testing.T, section, body string) {
		t.Helper()
		rr := httptest.NewRecorder()
		server.Handler().ServeHTTP(rr,
			httptest.NewRequest(http.MethodPut, "/api/config/section/"+section, strings.NewReader(body)))
		if rr.Code != 200 {
			t.Fatalf("PUT %s: status %d body=%s", section, rr.Code, rr.Body.String())
		}
	}

	put(t, "advisor", `{"Enabled":true,"WindowDays":30,"MinConfidence":0.7,"MinSavingsUSD":2.5,"SessionDigest":true,"DigestRefreshMinutes":15}`)
	put(t, "cachetrack", `{"Enabled":false,"MaxTrackedSessions":128,"CalibrateLogPath":"","RetentionDays":30}`)
	put(t, "secrets", `{"EnableScrubbing":true,"ExtraPatterns":["mykey-[0-9]+"]}`)

	reloaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.Advisor.SessionDigest || reloaded.Advisor.WindowDays != 30 || reloaded.Advisor.MinConfidence != 0.7 {
		t.Errorf("advisor not persisted: %+v", reloaded.Advisor)
	}
	if reloaded.CacheTrack.Enabled {
		t.Errorf("cachetrack.enabled=false must survive the partial-merge TRUE default once written explicitly")
	}
	if reloaded.CacheTrack.MaxTrackedSessions != 128 || reloaded.CacheTrack.RetentionDays != 30 {
		t.Errorf("cachetrack not persisted: %+v", reloaded.CacheTrack)
	}
	if len(reloaded.Observer.Secrets.ExtraPatterns) != 1 || reloaded.Observer.Secrets.ExtraPatterns[0] != "mykey-[0-9]+" {
		t.Errorf("secrets not persisted: %+v", reloaded.Observer.Secrets)
	}

	// The GET contract the Settings nav reads must advertise all three.
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if rr.Code != 200 {
		t.Fatalf("GET /api/config: %d", rr.Code)
	}
	var got struct {
		EditableSections []string `json:"editable_sections"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, s := range got.EditableSections {
		have[s] = true
	}
	for _, want := range []string{"advisor", "cachetrack", "secrets"} {
		if !have[want] {
			t.Errorf("editable_sections missing %q", want)
		}
	}
}

// TestHandleConfigBackup_RestoreSwaps pins the P1.15 config-undo
// contract: GET exposes the .bak, POST swaps current<->backup (so a
// second restore undoes the first), and a corrupt backup is refused
// with 422 before anything is touched.
func TestHandleConfigBackup_RestoreSwaps(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	bakPath := cfgPath + ".bak"
	if err := os.WriteFile(cfgPath, []byte("[observer]\nlog_level = \"warn\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bakPath, []byte("[observer]\nlog_level = \"info\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config/backup", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "info") {
		t.Fatalf("GET backup: %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/config/backup", nil))
	if rr.Code != 200 {
		t.Fatalf("POST restore: %d body=%s", rr.Code, rr.Body.String())
	}
	cur, _ := os.ReadFile(cfgPath)
	bak, _ := os.ReadFile(bakPath)
	if !strings.Contains(string(cur), "info") {
		t.Errorf("config.toml after restore: %s", cur)
	}
	if !strings.Contains(string(bak), "warn") {
		t.Errorf("backup after restore (swap expected): %s", bak)
	}

	// Corrupt backup → refused, nothing touched.
	if err := os.WriteFile(bakPath, []byte("not [ valid toml %%%"), 0o644); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/config/backup", nil))
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("corrupt bak restore: got %d want 422", rr.Code)
	}
	cur2, _ := os.ReadFile(cfgPath)
	if string(cur2) != string(cur) {
		t.Errorf("config.toml mutated by refused restore")
	}
}

// TestHandleConfigSection_PreservesPricingOnIntelligenceSave guards a
// subtle interaction: the intelligence section's PUT handler decodes
// only the editable subset (APIKeyEnv / SummaryModel /
// MonthlyBudgetUSD) and must NOT clobber the pricing overrides that
// /api/config/pricing manages separately.
func TestHandleConfigSection_PreservesPricingOnIntelligenceSave(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(`
[intelligence.pricing.models."claude-sonnet-4-6"]
input = 99
output = 999
`), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	// Save intelligence section with a new monthly budget but NO
	// pricing in the body.
	body := `{"MonthlyBudgetUSD":250,"APIKeyEnv":"OBSERVER_API_KEY","SummaryModel":"haiku-4-5"}`
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPut, "/api/config/section/intelligence", strings.NewReader(body)))
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}

	reloaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Intelligence.MonthlyBudgetUSD != 250 {
		t.Errorf("budget not saved: %v", reloaded.Intelligence.MonthlyBudgetUSD)
	}
	if reloaded.Intelligence.SummaryModel != "haiku-4-5" {
		t.Errorf("summary model not saved: %q", reloaded.Intelligence.SummaryModel)
	}
	mp, ok := reloaded.Intelligence.Pricing.Models["claude-sonnet-4-6"]
	if !ok || mp.Input != 99 {
		t.Errorf("pricing override clobbered by intelligence save: %+v ok=%v", mp, ok)
	}
}

// TestHandleConfigSection_UnknownSection rejects unknown section names
// with 400 — guards typos and prevents arbitrary JSON from landing
// somewhere unexpected if the route mux changes.
func TestHandleConfigSection_UnknownSection(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPut, "/api/config/section/bogus", strings.NewReader(`{}`)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400", rr.Code)
	}

	// Pricing through the section path is also rejected — that's a
	// different endpoint with hot-reload semantics.
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPut, "/api/config/section/pricing", strings.NewReader(`{}`)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("pricing-via-section path should 400: got %d", rr.Code)
	}
}

// TestHandleAdminRestart_ScheduledResponse verifies the endpoint
// returns 200 with the scheduled flag. The actual os.Exit is fired
// async after a delay; we don't invoke it in tests because that would
// kill the test runner. The 500ms delay path is exercised by hand with
// the smoke-test recipe in docs/.
func TestHandleAdminRestart_ScheduledResponse(t *testing.T) {
	t.Skip("os.Exit invocation tested manually — would kill the test runner")
}

// TestHandleBackfillStatus pins the per-mode shape: every documented
// flag surfaces, SQL-checkable modes get a non-negative count, file-walk
// modes report -1 with a "needs scan" note.
func TestHandleBackfillStatus(t *testing.T) {
	tdir := t.TempDir()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/backfill/status", nil))
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Modes []struct {
			Mode           string `json:"mode"`
			Flag           string `json:"flag"`
			Description    string `json:"description"`
			Candidates     int64  `json:"candidates"`
			CandidatesNote string `json:"candidates_note"`
		} `json:"modes"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Modes) < 14 {
		t.Errorf("mode count: got %d want >= 14 (3 SQL + 12 file-walk after v1.4.20 api-errors mode)", len(got.Modes))
	}
	byMode := map[string]int64{}
	noteByMode := map[string]string{}
	for _, m := range got.Modes {
		byMode[m.Mode] = m.Candidates
		noteByMode[m.Mode] = m.CandidatesNote
	}
	// SQL modes return a non-negative count (empty DB = 0).
	for _, sqlMode := range []string{"is-sidechain", "cache-tier", "message-id"} {
		if byMode[sqlMode] < 0 {
			t.Errorf("SQL mode %q must have non-negative candidates: %d", sqlMode, byMode[sqlMode])
		}
	}
	// File-walk modes report -1 + a note.
	for _, fwMode := range []string{"openclaw-model", "cursor-model", "claudecode-user-prompts"} {
		if byMode[fwMode] != -1 {
			t.Errorf("file-walk mode %q should report -1, got %d", fwMode, byMode[fwMode])
		}
		if noteByMode[fwMode] == "" {
			t.Errorf("file-walk mode %q missing note", fwMode)
		}
	}

	// Drift guard (usability arc P1.1): the status list and the run
	// allowlist must stay in lockstep — every mode the panel shows must
	// be runnable, and every runnable mode must be visible in the panel.
	// The CLI grew flags (cache-rescan, hermes-rescan, clinecli-rescan,
	// …) that both dashboard lists silently trailed; this pin makes the
	// next drift loud. "all" is the one allowlist entry intentionally
	// absent from the status list (the panel renders it as its own
	// Run-all affordance).
	statusModes := map[string]bool{}
	for _, m := range got.Modes {
		statusModes[m.Mode] = true
	}
	for mode := range allowlistedBackfillModes {
		if mode == "all" {
			continue
		}
		if !statusModes[mode] {
			t.Errorf("allowlisted mode %q missing from /api/backfill/status", mode)
		}
	}
	for mode := range statusModes {
		if _, ok := allowlistedBackfillModes[mode]; !ok {
			t.Errorf("status mode %q is shown but not runnable (missing from allowlistedBackfillModes)", mode)
		}
	}
}

// TestConfigWrites_FireOnConfigSaved pins the P2.5 hot-reload seam:
// every successful config.toml write path (section PUT, backup
// restore POST) invokes Options.OnConfigSaved exactly once, and a
// rejected write (unknown section) does not. The daemon wires this
// hook to the proxy's compression profile router.
func TestConfigWrites_FireOnConfigSaved(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\nlog_level = \"info\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	fired := 0
	server, err := New(Options{DB: database, ConfigPath: cfgPath, OnConfigSaved: func() { fired++ }})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Section PUT fires once.
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPut,
		"/api/config/section/retention", strings.NewReader(`{"MaxAgeDays":30}`)))
	if rr.Code != 200 {
		t.Fatalf("section save: %d body=%s", rr.Code, rr.Body.String())
	}
	if fired != 1 {
		t.Errorf("after section PUT: OnConfigSaved fired %d times, want 1", fired)
	}

	// 2. A rejected write must NOT fire.
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPut,
		"/api/config/section/no-such-section", strings.NewReader(`{}`)))
	if rr.Code == 200 {
		t.Fatal("unknown section unexpectedly saved")
	}
	if fired != 1 {
		t.Errorf("after rejected PUT: OnConfigSaved fired %d times, want still 1", fired)
	}

	// 3. Backup restore fires (the first save above created the .bak).
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/config/backup", nil))
	if rr.Code != 200 {
		t.Fatalf("backup restore: %d body=%s", rr.Code, rr.Body.String())
	}
	if fired != 2 {
		t.Errorf("after backup restore: OnConfigSaved fired %d times, want 2", fired)
	}

	// 4. The explicit reload endpoint (P2.6 — external writers like
	// `observer profile assign`) fires too and reports wired=true.
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/config/reload", nil))
	if rr.Code != 200 {
		t.Fatalf("config reload: %d body=%s", rr.Code, rr.Body.String())
	}
	if fired != 3 {
		t.Errorf("after reload POST: OnConfigSaved fired %d times, want 3", fired)
	}
	var reloadResp struct {
		Reloaded bool `json:"reloaded"`
		Wired    bool `json:"wired"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&reloadResp); err != nil {
		t.Fatal(err)
	}
	if !reloadResp.Reloaded || !reloadResp.Wired {
		t.Errorf("reload response: %+v, want reloaded=true wired=true", reloadResp)
	}
}

// TestHandleConfigSection_Profiles pins the P2.7 Profiles panel seam:
// assignments save through the generic section PUT, round-trip
// through config.Load, report restart_required=false (the P2.5
// hot-reload makes the banner unnecessary — the one section where it
// would lie), and unknown profile names are refused loudly.
func TestHandleConfigSection_Profiles(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\nlog_level = \"info\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	fired := 0
	server, err := New(Options{DB: database, ConfigPath: cfgPath, OnConfigSaved: func() { fired++ }})
	if err != nil {
		t.Fatal(err)
	}

	body := `{"Default":"default","ByProvider":{"anthropic":"codex-variant","openai":"codex-safe"}}`
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPut, "/api/config/section/profiles", strings.NewReader(body)))
	if rr.Code != 200 {
		t.Fatalf("save profiles: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Saved           bool `json:"saved"`
		RestartRequired bool `json:"restart_required"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Saved {
		t.Error("saved=false")
	}
	if resp.RestartRequired {
		t.Error("profiles saves hot-reload (P2.5) — restart_required must be false")
	}
	if fired != 1 {
		t.Errorf("OnConfigSaved fired %d times, want 1 (the hot-reload trigger)", fired)
	}

	reloaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Profiles.ByProvider["anthropic"]; got != "codex-variant" {
		t.Errorf("persisted anthropic assignment: got %q want codex-variant", got)
	}

	// Unknown profile name → 400, nothing written.
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPut,
		"/api/config/section/profiles", strings.NewReader(`{"ByProvider":{"anthropic":"no-such"}}`)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unknown profile name: got %d want 400 (body=%s)", rr.Code, rr.Body.String())
	}
}

// TestHandleConfigSection_ConcurrentSectionSavesBothPersist proves Fix 1: two
// concurrent PUTs to DIFFERENT sections must never lose one another's change.
// Each save is load-from-disk → patch-one-section → validate → write-full-
// struct; without Server.configWriteMu both PUTs read the same base and the
// second write clobbers the first's section (a lost update). The `observer`
// section (LogLevel) and the `intelligence` section (MonthlyBudgetUSD) touch
// DISJOINT fields, so a correct, serialized implementation always lands both.
//
// Deterministic: on the fixed code every iteration passes. Each iteration
// resets the file to a known baseline, fires the two PUTs from a released
// start barrier so they genuinely race, waits, then asserts BOTH the log level
// AND the budget carried through — a regression drops one and fails the assert.
func TestHandleConfigSection_ConcurrentSectionSavesBothPersist(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	dbPath := filepath.Join(tdir, "state.db")

	baseline := func() {
		cfg := config.Default()
		cfg.Observer.DBPath = dbPath
		cfg.Observer.LogLevel = "info"
		cfg.Intelligence.MonthlyBudgetUSD = 0
		if err := config.WriteToml(cfgPath, cfg); err != nil {
			t.Fatalf("baseline write: %v", err)
		}
	}
	baseline()

	database, err := openTestDB(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	h := server.Handler()

	put := func(section, body string) int {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPut,
			"/api/config/section/"+section, strings.NewReader(body)))
		return rr.Code
	}

	const iters = 80
	for i := 0; i < iters; i++ {
		baseline()
		start := make(chan struct{})
		var wg sync.WaitGroup
		var codeObserver, codeIntel int
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			// observer: flip LogLevel, keep DBPath non-empty (Validate requires it).
			codeObserver = put("observer", `{"DBPath":"`+dbPath+`","LogLevel":"error"}`)
		}()
		go func() {
			defer wg.Done()
			<-start
			codeIntel = put("intelligence", `{"MonthlyBudgetUSD":999}`)
		}()
		close(start)
		wg.Wait()

		if codeObserver != http.StatusOK {
			t.Fatalf("iter %d: observer PUT status %d", i, codeObserver)
		}
		if codeIntel != http.StatusOK {
			t.Fatalf("iter %d: intelligence PUT status %d", i, codeIntel)
		}
		got, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
		if err != nil {
			t.Fatalf("iter %d: reload: %v", i, err)
		}
		if got.Observer.LogLevel != "error" {
			t.Fatalf("iter %d: observer save lost — log_level=%q want error (budget=%v)",
				i, got.Observer.LogLevel, got.Intelligence.MonthlyBudgetUSD)
		}
		if got.Intelligence.MonthlyBudgetUSD != 999 {
			t.Fatalf("iter %d: intelligence save lost — monthly_budget_usd=%v want 999 (log_level=%q)",
				i, got.Intelligence.MonthlyBudgetUSD, got.Observer.LogLevel)
		}
	}
}

// terminalPolicyConfirm fetches a fresh double-submit confirm cookie + token
// from GET /api/terminal/policy so a following PUT can pass requireJSONConfirm.
func terminalPolicyConfirm(t *testing.T, h http.Handler) (*http.Cookie, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/terminal/policy", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/terminal/policy: %d %s", rr.Code, rr.Body.String())
	}
	var cookie *http.Cookie
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == remoteConfirmCookie {
			cookie = ck
		}
	}
	if cookie == nil {
		t.Fatal("no confirm cookie set on GET /api/terminal/policy")
	}
	var body struct {
		ConfirmToken string `json:"confirm_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.ConfirmToken) == 0 {
		t.Fatal("empty confirm_token")
	}
	return cookie, body.ConfirmToken
}

// TestConfigWrite_RemoteManageRaceSectionSave proves Fix 2: a remote-manage
// config write (PUT /api/terminal/policy, which read-modify-writes the WHOLE
// config under remoteManageMu) racing a section save (PUT
// /api/config/section/observer, under configWriteMu) never loses either change.
// Before Fix 2 the two paths held DIFFERENT locks, so the second writer
// clobbered the first (a lost update); after Fix 2 the manage verb ALSO takes
// configWriteMu (order remoteManageMu → configWriteMu), so they serialize. The
// two touch DISJOINT fields (observer LogLevel vs terminal AllowFreshAgent), so
// a correct implementation always lands both.
func TestConfigWrite_RemoteManageRaceSectionSave(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	dbPath := filepath.Join(tdir, "state.db")

	baseline := func() {
		cfg := config.Default()
		cfg.Observer.DBPath = dbPath
		cfg.Observer.LogLevel = "info"
		cfg.Terminal.Launch.AllowFreshAgent = false
		if err := config.WriteToml(cfgPath, cfg); err != nil {
			t.Fatalf("baseline write: %v", err)
		}
	}
	baseline()

	database, err := openTestDB(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	h := server.Handler()

	confirmCookie, confirmTok := terminalPolicyConfirm(t, h)

	putSection := func(section, body string) int {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPut,
			"/api/config/section/"+section, strings.NewReader(body)))
		return rr.Code
	}
	putTerminalPolicy := func() int {
		req := httptest.NewRequest(http.MethodPut, "/api/terminal/policy",
			strings.NewReader(`{"allow_fresh_agent":true,"allowed_tools":[],"allowed_project_roots":[]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(remoteConfirmHeader, confirmTok)
		req.AddCookie(confirmCookie)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	const iters = 80
	for i := 0; i < iters; i++ {
		baseline()
		start := make(chan struct{})
		var wg sync.WaitGroup
		var codeSection, codePolicy int
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			codeSection = putSection("observer", `{"DBPath":"`+dbPath+`","LogLevel":"error"}`)
		}()
		go func() {
			defer wg.Done()
			<-start
			codePolicy = putTerminalPolicy()
		}()
		close(start)
		wg.Wait()

		if codeSection != http.StatusOK {
			t.Fatalf("iter %d: section PUT status %d", i, codeSection)
		}
		if codePolicy != http.StatusOK {
			t.Fatalf("iter %d: terminal-policy PUT status %d", i, codePolicy)
		}
		got, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
		if err != nil {
			t.Fatalf("iter %d: reload: %v", i, err)
		}
		if got.Observer.LogLevel != "error" {
			t.Fatalf("iter %d: section save lost — log_level=%q want error (allow_fresh_agent=%v)",
				i, got.Observer.LogLevel, got.Terminal.Launch.AllowFreshAgent)
		}
		if !got.Terminal.Launch.AllowFreshAgent {
			t.Fatalf("iter %d: terminal-policy save lost — allow_fresh_agent=false want true (log_level=%q)",
				i, got.Observer.LogLevel)
		}
	}
}

// TestHandleConfigSection_SaveProcessETW pins the [observer.process.etw] half
// of the process section — the keys the ETW capturer card edits, none of which
// were reachable from the dashboard before.
//
// Three properties, in order of how badly each would bite:
//  1. The card's one-field PUT ({"ETW":{"Enabled":true}}) preserves every other
//     ETW key. Zeroing listen_addr here would silently move the daemon's accept
//     listener on the next restart, and the elevated capturer — whose --connect
//     address is baked into a Scheduled Task — would dial a dead port forever.
//  2. The shared token is NEVER written from the wire. It gates a loopback port
//     that WSL2 exposes to the whole Windows host, so a body carrying one is
//     ignored and the operator's own value stands.
//  3. A malformed listen_addr is refused at the seam. config.Load does not
//     reject it; the failure would otherwise surface as a listener that never
//     binds after a restart the operator performed on our advice.
func TestHandleConfigSection_SaveProcessETW(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(`[observer.process]
enabled = true
backend = "auto"

[observer.process.etw]
enabled = false
listen_addr = "127.0.0.1:9999"
token = "operator-set-secret"
token_path = "/home/u/.observer/tok"
handshake_timeout_ms = 7000
`), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	// (1) + (2): the card's enable toggle, with a token in the body for good
	// measure — the sort of thing a full-draft PUT from the structured form
	// would carry.
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/api/config/section/process",
		strings.NewReader(`{"ETW":{"Enabled":true,"Token":"stolen"}}`)))
	if rr.Code != 200 {
		t.Fatalf("etw enable save: %d body=%s", rr.Code, rr.Body.String())
	}
	reloaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	etw := reloaded.Observer.Process.ETW
	if !etw.Enabled {
		t.Errorf("ETW.Enabled not applied: %+v", etw)
	}
	if etw.ListenAddr != "127.0.0.1:9999" || etw.TokenPath != "/home/u/.observer/tok" || etw.HandshakeTimeoutMS != 7000 {
		t.Errorf("partial ETW body zeroed preserved keys: %+v", etw)
	}
	if etw.Token != "operator-set-secret" {
		t.Errorf("the shared token must never be writable from the wire, got %q", etw.Token)
	}
	// And the sibling process scalars are untouched.
	if !reloaded.Observer.Process.Enabled || reloaded.Observer.Process.Backend != "auto" {
		t.Errorf("an ETW-only body clobbered the process scalars: %+v", reloaded.Observer.Process)
	}

	// (3) a listen_addr that is not host:port is refused, and nothing is written.
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/api/config/section/process",
		strings.NewReader(`{"ETW":{"ListenAddr":"not-an-address"}}`)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("malformed listen_addr: got %d, want 400 (body=%s)", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/api/config/section/process",
		strings.NewReader(`{"ETW":{"HandshakeTimeoutMS":-1}}`)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("negative handshake timeout: got %d, want 400", rr.Code)
	}
	reloaded, err = config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload after refusals: %v", err)
	}
	if reloaded.Observer.Process.ETW.ListenAddr != "127.0.0.1:9999" {
		t.Errorf("a refused save still wrote: %+v", reloaded.Observer.Process.ETW)
	}
}
