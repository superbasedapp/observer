package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codexipc"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// captureCheckFixture builds a fully-formed test environment for the
// validateCaptureRate helper. Returns the configPath the test should
// pass and a cmdStart anchor.
type captureCheckFixture struct {
	t          *testing.T
	configPath string
	codexHome  string
	dbPath     string
	cmdStart   time.Time
}

func newCaptureCheckFixture(t *testing.T) *captureCheckFixture {
	t.Helper()
	base := t.TempDir()
	dbPath := filepath.Join(base, "obs.db")
	codexHome := filepath.Join(base, "codex_home")
	if err := os.MkdirAll(filepath.Join(codexHome, "sessions"), 0o755); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(base, "config.toml")
	configBody := fmt.Sprintf("[observer]\ndb_path = %q\n", dbPath)
	if err := os.WriteFile(configPath, []byte(configBody), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", codexHome)

	return &captureCheckFixture{
		t:          t,
		configPath: configPath,
		codexHome:  codexHome,
		dbPath:     dbPath,
		cmdStart:   time.Now(),
	}
}

// writeRollout drops a fake rollout-*.jsonl with one session_meta
// envelope carrying the given session UUID (codex 0.130+ shape) and
// `tokenCounts` event_msg/token_count envelopes. Returns the file
// path.
//
// Uses the modern session_meta + payload.id envelope shape verified
// against codex 0.130.0-alpha.5 rollouts (per
// docs/observer-platform-issues-v6.md §V6-1). The legacy
// session_configured + payload.session_id shape is covered by
// writeRolloutLegacy below.
func (f *captureCheckFixture) writeRollout(sessionID string, tokenCounts int) string {
	return f.writeRolloutShape(sessionID, tokenCounts, "session_meta", "id")
}

// writeRolloutLegacy is the v1.7.4 (pre-V6-1) shape: session_configured
// envelope + payload.session_id. Kept so the post-flight check's
// dual-tolerance is pinned by the table.
func (f *captureCheckFixture) writeRolloutLegacy(sessionID string, tokenCounts int) string {
	return f.writeRolloutShape(sessionID, tokenCounts, "session_configured", "session_id")
}

func (f *captureCheckFixture) writeRolloutShape(sessionID string, tokenCounts int, envelopeType, payloadIDKey string) string {
	f.t.Helper()
	path := filepath.Join(f.codexHome, "sessions", "rollout-"+sessionID+".jsonl")
	var b strings.Builder
	fmt.Fprintf(&b,
		`{"id":"sc","timestamp":"2026-05-28T12:00:00Z","type":%q,"payload":{%q:%q,"model":"gpt-5-codex"}}`+"\n",
		envelopeType, payloadIDKey, sessionID)
	for i := 0; i < tokenCounts; i++ {
		fmt.Fprintf(&b, `{"id":"tc%d","timestamp":"2026-05-28T12:00:%02dZ","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1,"output_tokens":1}}}}`+"\n", i, i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		f.t.Fatal(err)
	}
	// Bump ModTime forward to make sure it's after cmdStart even on
	// fast filesystems where Write completes < 1 ms after the stamp.
	bump := time.Now().Add(50 * time.Millisecond)
	if err := os.Chtimes(path, bump, bump); err != nil {
		f.t.Fatal(err)
	}
	return path
}

// insertAPITurns inserts `n` api_turns rows for sessionID with
// timestamps in the (cmdStart..cmdStart+1m) window so the helper's
// timestamp >= cmdStart filter catches them.
func (f *captureCheckFixture) insertAPITurns(sessionID string, n int) {
	f.t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: f.dbPath})
	if err != nil {
		f.t.Fatal(err)
	}
	defer database.Close()
	s := store.New(database)
	for i := 0; i < n; i++ {
		_, err := s.InsertAPITurn(ctx, models.APITurn{
			SessionID:    sessionID,
			Timestamp:    f.cmdStart.Add(time.Duration(i+1) * time.Second),
			Provider:     "openai",
			Model:        "gpt-5-codex",
			InputTokens:  100,
			OutputTokens: 50,
		})
		if err != nil {
			f.t.Fatal(err)
		}
	}
}

// TestValidateCaptureRate_AllCaptured pins the happy-path: jsonl_n ==
// proxy_n → no warning.
func TestValidateCaptureRate_AllCaptured(t *testing.T) {
	f := newCaptureCheckFixture(t)
	f.writeRollout("cx-allgood", 5)
	f.insertAPITurns("cx-allgood", 5)

	warn, err := validateCaptureRate(context.Background(), f.configPath, f.cmdStart, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if warn != "" {
		t.Errorf("expected silent success, got warning: %s", warn)
	}
}

// TestValidateCaptureRate_FullBypassWithPreflight pins the warning
// branch that fires when the JSONL has events but api_turns is empty
// AND pre-flight detected processes. The warning copy must reference
// "the shared app-server(s) above" since the operator already saw
// them in the pre-flight line.
func TestValidateCaptureRate_FullBypassWithPreflight(t *testing.T) {
	f := newCaptureCheckFixture(t)
	f.writeRollout("cx-bypassed", 21)
	// No api_turns inserted — proxy saw nothing.

	preflight := []codexipc.Process{{PID: 10072, Source: "vscode-extension"}}
	warn, err := validateCaptureRate(context.Background(), f.configPath, f.cmdStart, preflight)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(warn, "0 of 21") {
		t.Errorf("warn missing 0-of-21 phrasing: %s", warn)
	}
	if !strings.Contains(warn, "confirms V5-1 bypass") {
		t.Errorf("warn should cross-reference pre-flight: %s", warn)
	}
	if !strings.Contains(warn, "--exclusive") {
		t.Errorf("warn should recommend --exclusive: %s", warn)
	}
}

// TestValidateCaptureRate_FullBypassWithoutPreflight pins the
// "no shared app-server was detected" branch — the bypass happened but
// pre-flight saw nothing, so observer asks for a V5 follow-up report.
func TestValidateCaptureRate_FullBypassWithoutPreflight(t *testing.T) {
	f := newCaptureCheckFixture(t)
	f.writeRollout("cx-mystery", 7)

	warn, err := validateCaptureRate(context.Background(), f.configPath, f.cmdStart, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(warn, "0 of 7") {
		t.Errorf("warn missing 0-of-7 phrasing: %s", warn)
	}
	if !strings.Contains(warn, "no shared app-server was detected") {
		t.Errorf("warn should note pre-flight was clean: %s", warn)
	}
	if !strings.Contains(warn, "V5 follow-up") {
		t.Errorf("warn should ask for V5 follow-up: %s", warn)
	}
}

// TestValidateCaptureRate_LegacyEnvelopeStillWorks pins V6-1's
// dual-tolerance at the validateCaptureRate level — a rollout
// emitted by a pre-codex-0.130 build (session_configured + session_id
// shape) still gets cross-referenced against api_turns and surfaces
// the same warning when capture failed. Regression guard against any
// future change that accidentally drops the legacy branch from the
// envelope-type matcher.
func TestValidateCaptureRate_LegacyEnvelopeStillWorks(t *testing.T) {
	f := newCaptureCheckFixture(t)
	f.writeRolloutLegacy("cx-legacy-e2e", 5)
	// No api_turns inserted — proxy saw nothing → bypass warning.

	warn, err := validateCaptureRate(context.Background(), f.configPath, f.cmdStart, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(warn, "0 of 5") {
		t.Errorf("warn missing 0-of-5 phrasing for legacy rollout: %s", warn)
	}
}

// TestValidateCaptureRate_PartialBypass pins the partial-bypass
// branch: some turns captured, some not.
func TestValidateCaptureRate_PartialBypass(t *testing.T) {
	f := newCaptureCheckFixture(t)
	f.writeRollout("cx-partial", 21)
	f.insertAPITurns("cx-partial", 3)

	warn, err := validateCaptureRate(context.Background(), f.configPath, f.cmdStart, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(warn, "only 3 of 21") {
		t.Errorf("warn missing 3-of-21 phrasing: %s", warn)
	}
	if !strings.Contains(warn, "partial V5-1 bypass") {
		t.Errorf("warn should name partial bypass: %s", warn)
	}
}

// TestValidateCaptureRate_NoTokenCountEventsSilent pins that a rollout
// JSONL with only the session_configured envelope (codex aborted
// before any LLM call) produces no warning — there's nothing to
// validate.
func TestValidateCaptureRate_NoTokenCountEventsSilent(t *testing.T) {
	f := newCaptureCheckFixture(t)
	f.writeRollout("cx-empty", 0)

	warn, err := validateCaptureRate(context.Background(), f.configPath, f.cmdStart, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if warn != "" {
		t.Errorf("expected silent (0 token_count events), got warning: %s", warn)
	}
}

// TestValidateCaptureRate_OlderRolloutIgnored pins the cmdStart
// boundary: rollout files modified BEFORE cmdStart are not in this
// run's scope, so their bypass status doesn't trigger a warning here.
func TestValidateCaptureRate_OlderRolloutIgnored(t *testing.T) {
	f := newCaptureCheckFixture(t)
	path := f.writeRollout("cx-stale", 12)
	// Backdate ModTime to before cmdStart.
	old := f.cmdStart.Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	warn, err := validateCaptureRate(context.Background(), f.configPath, f.cmdStart, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if warn != "" {
		t.Errorf("expected silent (stale rollout), got warning: %s", warn)
	}
}

// TestParseRolloutForCapture_LegacySessionConfigured covers the
// pre-codex-0.130 envelope shape (session_configured + session_id).
// Pins the dual-tolerance the V6-1 fix introduced — older codex
// builds and any future flip-back must still parse cleanly.
func TestParseRolloutForCapture_LegacySessionConfigured(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "rollout-cx-legacy.jsonl")
	body := strings.Join([]string{
		`{"id":"a","timestamp":"2026-05-28T12:00:00Z","type":"session_configured","payload":{"session_id":"cx-legacy","model":"gpt-5"}}`,
		`{"id":"b","type":"event_msg","payload":{"type":"token_count","info":{}}}`,
		`{"id":"c","type":"event_msg","payload":{"type":"agent_message","message":"hi"}}`, // not token_count
		`{"id":"d","type":"event_msg","payload":{"type":"token_count","info":{}}}`,
		"", // empty line (must not crash)
		`{"id":"e","type":"event_msg","payload":{"type":"token_count"`, // partial trailing line (no newline)
	}, "\r\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	sid, n, err := parseRolloutForCapture(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sid != "cx-legacy" {
		t.Errorf("session_id: got %q, want cx-legacy", sid)
	}
	if n != 2 {
		t.Errorf("token_count: got %d, want 2 (partial last line must not count)", n)
	}
}

// TestParseRolloutForCapture_SessionMetaPrimary covers the codex
// 0.130+ envelope shape (session_meta + payload.id). This was the
// V6-1 regression: v1.7.4's parser only matched session_configured +
// session_id, silently dropped every real codex rollout, and
// suppressed the V6-2/V6-3 capture warnings.
func TestParseRolloutForCapture_SessionMetaPrimary(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "rollout-cx-meta.jsonl")
	body := strings.Join([]string{
		`{"id":"a","timestamp":"2026-05-28T21:53:51Z","type":"session_meta","payload":{"id":"019e6f66-3db5-7fa0-8b38-ad3de3d4ad2a","cwd":"/tmp","originator":"codex-cli","cli_version":"0.130.0-alpha.5"}}`,
		`{"id":"b","type":"event_msg","payload":{"type":"token_count","info":{}}}`,
		`{"id":"c","type":"event_msg","payload":{"type":"token_count","info":{}}}`,
		`{"id":"d","type":"event_msg","payload":{"type":"token_count","info":{}}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	sid, n, err := parseRolloutForCapture(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sid != "019e6f66-3db5-7fa0-8b38-ad3de3d4ad2a" {
		t.Errorf("session UUID: got %q, want 019e6f66-…", sid)
	}
	if n != 3 {
		t.Errorf("token_count: got %d, want 3", n)
	}
}

// TestParseRolloutForCapture_PrefersIDOverSessionID pins the
// dual-field tolerance when codex emits BOTH payload.id and
// payload.session_id (the codex adapter declares both — see
// internal/adapter/codex/adapter.go:161). Modern "id" wins.
func TestParseRolloutForCapture_PrefersIDOverSessionID(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "rollout-cx-dual.jsonl")
	body := `{"id":"a","type":"session_meta","payload":{"id":"modern-uuid","session_id":"legacy-uuid"}}` + "\n" +
		`{"id":"b","type":"event_msg","payload":{"type":"token_count"}}` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	sid, _, err := parseRolloutForCapture(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sid != "modern-uuid" {
		t.Errorf("session UUID: got %q, want modern-uuid (id field should win)", sid)
	}
}

// TestCodexHomeRoots_EnvWins pins that CODEX_HOME takes priority over
// the crossmount walk.
func TestCodexHomeRoots_EnvWins(t *testing.T) {
	t.Setenv("CODEX_HOME", "/some/explicit/path")
	roots := codexHomeRoots()
	if len(roots) != 1 || roots[0] != "/some/explicit/path" {
		t.Errorf("expected [/some/explicit/path], got %v", roots)
	}
}
