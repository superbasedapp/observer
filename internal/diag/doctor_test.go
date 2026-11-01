package diag

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/codextrust"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/mcp"
)

func newTestEnv(t *testing.T) (config.Config, *sql.DB, string, string) {
	t.Helper()
	home := t.TempDir()
	dbPath := filepath.Join(home, ".observer", "observer.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	cfg := config.Default()
	cfg.Observer.DBPath = dbPath
	cfg.Observer.Retention.MaxDBSizeMB = 500
	return cfg, d, home, "/usr/local/bin/observer"
}

func TestRun_AllOK_AfterInit(t *testing.T) {
	cfg, database, home, binary := newTestEnv(t)

	// Simulate `observer init` having registered MCP for all 3 tools so the
	// MCP check is OK rather than warn.
	registerJSON(t, filepath.Join(home, ".claude.json"), binary)
	registerJSON(t, filepath.Join(home, ".cursor", "mcp.json"), binary)
	registerTOML(t, filepath.Join(home, ".codex", "config.toml"), binary)

	// Simulate hook_checksums.json with a real config file matching it.
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	settingsBody := []byte(`{"hooks":{}}`)
	if err := os.WriteFile(settings, settingsBody, 0o600); err != nil {
		t.Fatal(err)
	}
	writeChecksums(t, home, map[string]checksumEntry{
		settings: hashOf(settingsBody, binary),
	})

	report := Run(context.Background(), DoctorOptions{
		Config:     cfg,
		DB:         database,
		HomeDir:    home,
		BinaryPath: binary,
	})

	for _, c := range report.Checks {
		if c.Status == StatusFail {
			t.Errorf("unexpected fail: %+v", c)
		}
	}
	if report.Failed() {
		t.Error("Failed() reported true")
	}
	// At least these three should be StatusOK.
	requireCheck(t, report, "db.schema", StatusOK)
	requireCheck(t, report, "db.integrity", StatusOK)
	requireCheck(t, report, "hooks.checksums", StatusOK)
	requireCheck(t, report, "mcp.registrations", StatusOK)
}

func TestRun_HookChecksumDriftWarns(t *testing.T) {
	cfg, database, home, binary := newTestEnv(t)
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(`{"original":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Record the original checksum then mutate the file to simulate drift.
	writeChecksums(t, home, map[string]checksumEntry{
		settings: hashOf([]byte(`{"original":true}`), binary),
	})
	if err := os.WriteFile(settings, []byte(`{"modified":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	report := Run(context.Background(), DoctorOptions{
		Config: cfg, DB: database, HomeDir: home, BinaryPath: binary,
	})
	requireCheck(t, report, "hooks.checksums", StatusWarn)
}

func TestRun_HookFileMissingFails(t *testing.T) {
	cfg, database, home, binary := newTestEnv(t)
	writeChecksums(t, home, map[string]checksumEntry{
		filepath.Join(home, ".claude", "settings.json"): hashOf([]byte(`x`), binary),
	})
	report := Run(context.Background(), DoctorOptions{
		Config: cfg, DB: database, HomeDir: home, BinaryPath: binary,
	})
	requireCheck(t, report, "hooks.checksums", StatusFail)
	if !report.Failed() {
		t.Error("expected report.Failed()")
	}
}

func TestRun_BinaryMismatchWarns(t *testing.T) {
	cfg, database, home, binary := newTestEnv(t)
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{}`)
	if err := os.WriteFile(settings, body, 0o600); err != nil {
		t.Fatal(err)
	}
	writeChecksums(t, home, map[string]checksumEntry{
		settings: {SHA256: hashOf(body, "/different/path").SHA256, BinaryPath: "/different/path"},
	})
	report := Run(context.Background(), DoctorOptions{
		Config: cfg, DB: database, HomeDir: home, BinaryPath: binary,
	})
	requireCheck(t, report, "hooks.binary", StatusWarn)
}

func TestRun_NoMCPYetWarns(t *testing.T) {
	cfg, database, home, binary := newTestEnv(t)
	report := Run(context.Background(), DoctorOptions{
		Config: cfg, DB: database, HomeDir: home, BinaryPath: binary,
	})
	requireCheck(t, report, "mcp.registrations", StatusWarn)
}

func TestRun_MCPBinaryMismatchWarns(t *testing.T) {
	cfg, database, home, binary := newTestEnv(t)
	registerJSON(t, filepath.Join(home, ".claude.json"), "/another/binary")
	report := Run(context.Background(), DoctorOptions{
		Config: cfg, DB: database, HomeDir: home, BinaryPath: binary,
	})
	requireCheck(t, report, "mcp.registrations", StatusWarn)
}

func TestRun_DBSizeAtCapFails(t *testing.T) {
	cfg, database, home, binary := newTestEnv(t)
	cfg.Observer.Retention.MaxDBSizeMB = 1
	// Inflate the DB to >1MB by inserting padded rows. The schema only has
	// projects + sessions populated by tests; inserting many sessions is
	// the simplest path to size growth.
	pid, err := upsertOneProject(database, "/r")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8000; i++ {
		_, _ = database.ExecContext(
			context.Background(),
			`INSERT INTO sessions (id, project_id, tool, started_at, metadata) VALUES (?, ?, ?, ?, ?)`,
			"sess-"+strings.Repeat("x", 50)+"-"+strconv.Itoa(i), pid, "claude-code", "2026-04-16T10:00:00Z",
			strings.Repeat("padding-padding-padding-padding-", 8),
		)
	}
	// Force a checkpoint so the actual file grows.
	_, _ = database.ExecContext(context.Background(), `PRAGMA wal_checkpoint(TRUNCATE)`)

	report := Run(context.Background(), DoctorOptions{
		Config: cfg, DB: database, HomeDir: home, BinaryPath: binary,
	})
	for _, c := range report.Checks {
		if c.Name == "db.size" && c.Status != StatusFail {
			t.Errorf("expected db.size fail at 1MB cap, got %+v", c)
		}
	}
}

func TestRun_ExtraChecksAppended(t *testing.T) {
	cfg, database, home, binary := newTestEnv(t)
	extra := []Check{
		{Name: "admission.judge", Status: StatusOK, Message: "reachable"},
		{Name: "admission.chain", Status: StatusOK, Message: "intact"},
	}
	report := Run(context.Background(), DoctorOptions{
		Config: cfg, DB: database, HomeDir: home, BinaryPath: binary,
		ExtraChecks: extra,
	})
	requireCheck(t, report, "admission.judge", StatusOK)
	requireCheck(t, report, "admission.chain", StatusOK)
	// Extra checks must be substring-filterable so `observer doctor admission`
	// scopes to exactly them.
	if got := report.Filter("admission"); len(got.Checks) != 2 {
		t.Errorf("Filter(admission) = %d checks, want 2: %+v", len(got.Checks), got.Checks)
	}
	// A failing extra check must flip the overall exit code.
	failReport := Run(context.Background(), DoctorOptions{
		Config: cfg, DB: database, HomeDir: home, BinaryPath: binary,
		ExtraChecks: []Check{{Name: "admission.chain", Status: StatusFail, Message: "broken"}},
	})
	if !failReport.Failed() {
		t.Error("a StatusFail extra check should make Failed() true")
	}
}

// --- helpers ---

func upsertOneProject(d *sql.DB, root string) (int64, error) {
	res, err := d.ExecContext(context.Background(),
		`INSERT INTO projects (root_path, created_at) VALUES (?, ?)`,
		root, "2026-04-16T10:00:00Z")
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

type checksumEntry struct {
	SHA256     string `json:"sha256"`
	BinaryPath string `json:"binary_path"`
}

func writeChecksums(t *testing.T, home string, entries map[string]checksumEntry) {
	t.Helper()
	dir := filepath.Join(home, ".observer")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(entries)
	if err := os.WriteFile(filepath.Join(dir, "hook_checksums.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func hashOf(body []byte, binary string) checksumEntry {
	return checksumEntry{
		SHA256:     sha256Hex(body),
		BinaryPath: binary,
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func registerJSON(t *testing.T, path, binary string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"mcpServers": map[string]any{
			mcp.ServerName: map[string]any{"command": binary, "args": []string{"serve"}},
		},
	}
	raw, _ := json.Marshal(body)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func registerTOML(t *testing.T, path, binary string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("[mcp_servers." + mcp.ServerName + "]\ncommand = \"" + binary + "\"\nargs = [\"serve\"]\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func requireCheck(t *testing.T, r Report, name string, want Status) {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			if c.Status != want {
				t.Errorf("check %s: status %s want %s - message %q", name, c.Status, want, c.Message)
			}
			return
		}
	}
	t.Errorf("check %s missing from report", name)
}

func TestCheckCodexHookTrust_NoCodex(t *testing.T) {
	home := t.TempDir()
	c := checkCodexHookTrust(home)
	if c.Status != StatusOK {
		t.Errorf("status=%s want OK (no codex installed)", c.Status)
	}
}

// codexHookTrustWriteHooks helper writes a fake observer-owned hooks.json
// with the given event names — minimum shape needed for the doctor check.
func codexHookTrustWriteHooks(t *testing.T, home string, events ...string) string {
	t.Helper()
	dir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	hooks := map[string]any{}
	for _, e := range events {
		hooks[e] = []any{
			map[string]any{
				"matcher": "*",
				"hooks": []any{
					map[string]any{"type": "command", "command": "/usr/local/bin/observer hook codex " + e},
				},
			},
		}
	}
	body, _ := json.Marshal(map[string]any{"hooks": hooks})
	path := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// tomlKeyPath escapes a filesystem path for embedding inside a TOML
// basic-string key. On Windows the path carries backslashes, which a TOML
// basic string reads as escape sequences (\U…, \h…) and rejects; doubling
// them keeps the PARSED key byte-identical to the original path, so
// checkCodexHookTrust's HasPrefix(key, hooksPath+":") match still holds.
// A no-op on POSIX paths (no backslashes).
func tomlKeyPath(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }

func TestCheckCodexHookTrust_RegisteredButNoConfigToml(t *testing.T) {
	home := t.TempDir()
	events := codexExpectedHookEvents()
	codexHookTrustWriteHooks(t, home, events...)
	c := checkCodexHookTrust(home)
	if c.Status != StatusFail {
		t.Errorf("status=%s want Fail (config.toml missing, all untrusted: the tool gate is off)", c.Status)
	}
	if !strings.Contains(c.Message, fmt.Sprintf("%d need approval", len(events))) || !strings.Contains(c.Message, "gate is OFF") {
		t.Errorf("message=%q want the %d count and the gate-off verdict", c.Message, len(events))
	}
	if len(c.Details) == 0 || !strings.HasPrefix(c.Details[0], "untrusted:") {
		t.Fatalf("first detail must name the untrusted events: %v", c.Details)
	}
	for _, e := range events {
		if !strings.Contains(c.Details[0], e) {
			t.Errorf("untrusted line misses %s: %q", e, c.Details[0])
		}
	}
}

// codexTrustConfig renders [hooks.state] entries for the given events
// with the given trusted_hash values.
func codexTrustConfig(hooksPath string, hashes map[string]string) string {
	var b strings.Builder
	for _, e := range sortedKeys(hashes) {
		fmt.Fprintf(&b, "[hooks.state.\"%s:%s:0:0\"]\ntrusted_hash = %q\n\n", hooksPath, codextrust.CamelToSnake(e), hashes[e])
	}
	return b.String()
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestCheckCodexHookTrust_AllTrusted(t *testing.T) {
	home := t.TempDir()
	events := codexExpectedHookEvents()
	hooksPath := tomlKeyPath(codexHookTrustWriteHooks(t, home, events...))
	hashes := map[string]string{}
	for _, e := range events {
		hashes[e] = "sha256:recorded-" + e // a Codex release whose hash we cannot reproduce
	}
	cfg := "personality = \"p\"\n\n" + codexTrustConfig(hooksPath, hashes)
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c := checkCodexHookTrust(home)
	if c.Status != StatusOK {
		t.Errorf("status=%s want OK (every event trusted), msg=%q details=%v", c.Status, c.Message, c.Details)
	}
	if !strings.Contains(c.Message, "could not be reproduced") {
		t.Errorf("unverifiable hashes must be named: %q", c.Message)
	}
}

func TestCheckCodexHookTrust_PartialTrust(t *testing.T) {
	home := t.TempDir()
	events := codexExpectedHookEvents()
	hooksPath := tomlKeyPath(codexHookTrustWriteHooks(t, home, events...))
	cfg := codexTrustConfig(hooksPath, map[string]string{"SessionStart": "sha256:abc"})
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c := checkCodexHookTrust(home)
	if c.Status != StatusFail {
		t.Fatalf("status=%s want Fail (PreToolUse, the tool gate, is untrusted)", c.Status)
	}
	if strings.Contains(c.Details[0], "SessionStart") {
		t.Errorf("SessionStart is trusted, not in the untrusted line: %q", c.Details[0])
	}
	for _, e := range []string{"PreToolUse", "Stop"} {
		if !strings.Contains(c.Details[0], e) {
			t.Errorf("%s should be in the untrusted line: %q", e, c.Details[0])
		}
	}
}

// TestCheckCodexHookTrust_ModifiedSinceTrusted: once one recorded hash
// reproduces, a hash that does not match its entry's body means the
// command changed after the user trusted it.
func TestCheckCodexHookTrust_ModifiedSinceTrusted(t *testing.T) {
	home := t.TempDir()
	events := codexExpectedHookEvents()
	rawPath := codexHookTrustWriteHooks(t, home, events...)
	star := "*"
	hashes := map[string]string{}
	for _, e := range events {
		cmd := "/usr/local/bin/observer hook codex " + e
		// SessionEnd (registered since hook-parity Lane C) defaults to
		// Codex's short 1 s hook timeout, every other event to 600 s.
		timeout := int64(600)
		if e == "SessionEnd" {
			timeout = 1
		}
		hashes[e] = codextrust.Hash(codextrust.CamelToSnake(e), &star, cmd, timeout, false, nil)
		if e == "UserPromptSubmit" || e == "Stop" {
			hashes[e] = codextrust.Hash(codextrust.CamelToSnake(e), nil, cmd, 600, false, nil)
		}
	}
	hashes["PreToolUse"] = "sha256:stale"
	cfg := codexTrustConfig(tomlKeyPath(rawPath), hashes)
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c := checkCodexHookTrust(home)
	if c.Status != StatusFail || c.Details[0] != "untrusted: PreToolUse" {
		t.Fatalf("status=%s details=%v, want Fail (gate off) with only PreToolUse blocked", c.Status, c.Details)
	}
	if !strings.Contains(strings.Join(c.Details, "\n"), "(re-trust in /hooks): PreToolUse") {
		t.Errorf("modified state not explained: %v", c.Details)
	}
}

// TestCheckCodexHookTrust_NewEventNotRegistered: an event the registry
// expects but hooks.json lacks is listed as not registered, and is not a
// capture-integrity trust risk.
func TestCheckCodexHookTrust_NewEventNotRegistered(t *testing.T) {
	home := t.TempDir()
	events := codexExpectedHookEvents()
	if len(events) < 2 {
		t.Skip("registry lists fewer than two codex events")
	}
	present := events[:len(events)-1]
	hooksPath := tomlKeyPath(codexHookTrustWriteHooks(t, home, present...))
	hashes := map[string]string{}
	for _, e := range present {
		hashes[e] = "sha256:x"
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(codexTrustConfig(hooksPath, hashes)), 0o600); err != nil {
		t.Fatal(err)
	}
	c := checkCodexHookTrust(home)
	want := "not registered: " + events[len(events)-1]
	if c.Status != StatusWarn || len(c.Details) == 0 || c.Details[0] != want {
		t.Fatalf("status=%s details=%v, want Warn with %q first", c.Status, c.Details, want)
	}
}

func TestCheckCodexHookTrust_IgnoresUserOwnedHooks(t *testing.T) {
	// hooks.json with a user-authored entry that's NOT routed through
	// observer should not contribute to the trust count.
	home := t.TempDir()
	dir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/my-policy"}]}]}}`)
	if err := os.WriteFile(filepath.Join(dir, "hooks.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	c := checkCodexHookTrust(home)
	if c.Status != StatusOK {
		t.Errorf("status=%s want OK (no observer-owned hooks)", c.Status)
	}
}
