package grokbot

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

const (
	testAccount = "auth0%7Cuser_00000000000000000000000000"
	testAgent   = "11111111-2222-3333-4444-555555555555"
)

func fixtureName(t *testing.T) string {
	t.Helper()
	return encodeBlobName("sand.client.slice.account." + testAccount + ".transcript.replicas." + testAgent)
}

// stageFixture copies the checked-in anonymized fixture into a temp
// sand-client-persistence directory and returns (root, fullPath).
func stageFixture(t *testing.T) (string, string) {
	t.Helper()
	name := fixtureName(t)
	src := filepath.Join("..", "..", "..", "testdata", "grokbot", name)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	root := filepath.Join(t.TempDir(), storeDirName)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dst := filepath.Join(root, name)
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return root, dst
}

func TestIsSessionFile(t *testing.T) {
	t.Parallel()
	root, path := stageFixture(t)
	a := NewWithOptions(nil, root)

	if !a.IsSessionFile(path) {
		t.Errorf("IsSessionFile(%q) = false, want true", path)
	}

	rosterName := encodeBlobName("sand.client.slice.account." + testAccount + "." + rosterSlice)
	cases := []struct{ name, path string }{
		{"roster slice (deliberately not ingested)", filepath.Join(root, rosterName)},
		{"tmp staging file", path + tmpSuffix},
		{"not a blob", filepath.Join(root, "notes.json")},
		{"undecodable name", filepath.Join(root, "not-base32!.blob")},
		{"right name, wrong directory", filepath.Join(filepath.Dir(root), fixtureName(t))},
	}
	for _, tc := range cases {
		if a.IsSessionFile(tc.path) {
			t.Errorf("IsSessionFile rejected nothing for %s: %q", tc.name, tc.path)
		}
	}
}

// TestOffLimitsFilesNeverDispatched pins the structural avoidance documented
// in doc.go: the credential/cookie/webview files that sit BESIDE the store
// must never be claimed by this adapter, even when they are inside the
// app directory tree.
func TestOffLimitsFilesNeverDispatched(t *testing.T) {
	t.Parallel()
	root, _ := stageFixture(t)
	appDir := filepath.Dir(root)
	a := NewWithOptions(nil, root)

	offLimits := []string{
		filepath.Join(appDir, "sand-secrets.json"),
		filepath.Join(appDir, "local-exec-daemon-credential.json"),
		filepath.Join(appDir, "local-exec-daemon-connection.json"),
		filepath.Join(appDir, "Local State"),
		filepath.Join(appDir, "Network", "Cookies"),
		filepath.Join(appDir, "Network", "Trust Tokens"),
		filepath.Join(appDir, "Partitions", "sand-forever-box", "Cache", "Cache_Data", "f_000001"),
		filepath.Join(appDir, "sand-statsig-bootstrap.json"),
		// The ~/.grokbot daemon-state directory is not read at all.
		filepath.Join(appDir, "..", ".grokbot", "local-exec-daemon.log"),
		filepath.Join(appDir, "..", ".grokbot", "local-exec-daemon-credential.json"),
	}
	for _, p := range offLimits {
		if a.IsSessionFile(p) {
			t.Errorf("IsSessionFile(%q) = true — this file is off-limits and must never be dispatched", p)
		}
	}
}

func parseFixture(t *testing.T, from int64) (events []models.ToolEvent, newOffset int64, retry bool) {
	t.Helper()
	root, path := stageFixture(t)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), path, from)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("emitted %d TokenEvents; grokbot has NO token data on disk and must emit zero", len(res.TokenEvents))
	}
	return res.ToolEvents, res.NewOffset, res.RetrySuggested
}

func TestParseSessionFileEmitsExpectedActions(t *testing.T) {
	t.Parallel()
	events, newOffset, retry := parseFixture(t, 0)

	// The fixture's last entry is in-flight (isStreaming), so the parser
	// must stop before it, hold the cursor AT it, and ask for a retry.
	if want := int64(14); newOffset != want {
		t.Errorf("NewOffset = %d, want %d (must stop at the in-flight entry)", newOffset, want)
	}
	if !retry {
		t.Error("RetrySuggested = false; stopping at an in-flight entry must request a retry")
	}

	byID := map[string]models.ToolEvent{}
	for _, e := range events {
		if _, dup := byID[e.SourceEventID]; dup {
			t.Errorf("duplicate SourceEventID %q", e.SourceEventID)
		}
		byID[e.SourceEventID] = e
	}

	// Entries that must NOT produce rows.
	for _, id := range []string{"t1s1" /*feedback*/, "t1s2" /*voice-call*/, "t1s3" /*in-flight*/} {
		if _, ok := byID[id]; ok {
			t.Errorf("entry %q produced an action row but must be skipped", id)
		}
	}

	want := []struct{ id, action, rawName string }{
		{"tbs0", models.ActionAssistantMessage, "assistant-message"},
		{"t0u", models.ActionUserPrompt, "user-message"},
		{"t0s0", models.ActionAssistantMessage, "assistant-message"},
		{"t0s1", models.ActionUnknown, "box-instruction"},
		{"t0s2", models.ActionAssistantMessage, "assistant-message:secret-request"},
		{"t0s3", models.ActionUnknown, "WebSearchToolCall"},
		{"t0s4", models.ActionUnknown, "BrowserOpenToolCall"},
		{"event-00000000-0000-4000-8000-000000000005", models.ActionUnknown, "event:automation-changed"},
		{"t0s5", models.ActionUnknown, "notice"},
		{"t0s6", models.ActionUnknown, "user-attachment"},
		{"t1u", models.ActionUserPrompt, "user-message"},
		{"t1s0", models.ActionAssistantMessage, "assistant-message"},
	}
	for _, w := range want {
		got, ok := byID[w.id]
		if !ok {
			t.Errorf("missing action for entry %q", w.id)
			continue
		}
		if got.ActionType != w.action {
			t.Errorf("%s: ActionType = %q, want %q", w.id, got.ActionType, w.action)
		}
		if got.RawToolName != w.rawName {
			t.Errorf("%s: RawToolName = %q, want %q", w.id, got.RawToolName, w.rawName)
		}
		if got.SessionID != testAgent {
			t.Errorf("%s: SessionID = %q, want %q", w.id, got.SessionID, testAgent)
		}
		if got.Tool != models.ToolGrokbot {
			t.Errorf("%s: Tool = %q, want %q", w.id, got.Tool, models.ToolGrokbot)
		}
		if got.ProjectRoot != syntheticRoot {
			t.Errorf("%s: ProjectRoot = %q, want %q", w.id, got.ProjectRoot, syntheticRoot)
		}
		// No model attribution exists anywhere on disk; fabricating one
		// from the Statsig flag config would be the exact honesty
		// violation the plan doc calls out.
		if got.Model != "" {
			t.Errorf("%s: Model = %q, want empty (no model data exists locally)", w.id, got.Model)
		}
		if got.Timestamp.IsZero() {
			t.Errorf("%s: zero Timestamp", w.id)
		}
	}

	// A failed tool-call is the only row that is not Success.
	if e := byID["t0s4"]; e.Success {
		t.Error("t0s4 (status=failed) must have Success=false")
	}
	if e := byID["t0s3"]; !e.Success {
		t.Error("t0s3 (settled tool-call) must have Success=true")
	}
}

// TestSecretRequestPayloadNeverDereferenced pins that a non-text
// send-message payload is recorded by TYPE only. secret-request in
// particular carries credential-request material we must not surface.
func TestSecretRequestPayloadNeverDereferenced(t *testing.T) {
	t.Parallel()
	events, _, _ := parseFixture(t, 0)
	for _, e := range events {
		if e.SourceEventID != "t0s2" {
			continue
		}
		if e.Target != "" {
			t.Errorf("secret-request Target = %q, want empty — the payload must never be dereferenced", e.Target)
		}
		if strings.Contains(e.Target, "EXAMPLE_SERVICE_TOKEN") {
			t.Error("the secret-request label leaked into the action target")
		}
		return
	}
	t.Fatal("no action emitted for entry t0s2")
}

// TestScrubsSecrets pins that free-text content passes through the scrubber.
func TestScrubsSecrets(t *testing.T) {
	t.Parallel()
	events, _, _ := parseFixture(t, 0)
	for _, e := range events {
		for _, secret := range []string{"sk-EXAMPLEEXAMPLEEXAMPLE0123456789", "ghp_EXAMPLEEXAMPLEEXAMPLE01234"} {
			if strings.Contains(e.Target, secret) {
				t.Fatalf("unscrubbed secret leaked into %s target: %q", e.SourceEventID, e.Target)
			}
		}
	}
	for _, e := range events {
		if e.SourceEventID == "t1u" {
			if !strings.Contains(e.Target, "REDACTED") {
				t.Errorf("t1u target %q shows no redaction marker; the scrubber did not run", e.Target)
			}
			return
		}
	}
	t.Fatal("no action emitted for entry t1u")
}

// TestRemoteBoxPathNeverBecomesProjectRoot pins the sharpest trap in this
// format: the roster's /home/box/... path (and the attachment paths that
// share it) must never be resolved into a ProjectRoot.
func TestRemoteBoxPathNeverBecomesProjectRoot(t *testing.T) {
	t.Parallel()
	events, _, _ := parseFixture(t, 0)
	for _, e := range events {
		if e.ProjectRoot != syntheticRoot {
			t.Errorf("%s: ProjectRoot = %q — the only valid root is %q; a /home/box path is REMOTE and must never be resolved",
				e.SourceEventID, e.ProjectRoot, syntheticRoot)
		}
	}
}

func TestTurnIndexTracking(t *testing.T) {
	t.Parallel()
	events, _, _ := parseFixture(t, 0)
	want := map[string]int{
		"tbs0": 0, // bootstrap, before any turn
		"t0u":  0,
		"t0s3": 0,
		"event-00000000-0000-4000-8000-000000000005": 0, // inherits running turn
		"t1u":  1,
		"t1s0": 1,
	}
	for _, e := range events {
		if w, ok := want[e.SourceEventID]; ok && e.TurnIndex != w {
			t.Errorf("%s: TurnIndex = %d, want %d", e.SourceEventID, e.TurnIndex, w)
		}
	}
}

// TestCursorIsEntryCountAndIdempotent pins the whole-file-rewrite cursor
// semantics: resuming from the persisted offset emits nothing new, and a
// shrunk transcript (an epoch reset) safely re-reads from the top.
func TestCursorIsEntryCountAndIdempotent(t *testing.T) {
	t.Parallel()

	full, off, _ := parseFixture(t, 0)
	if len(full) == 0 {
		t.Fatal("first parse emitted nothing")
	}

	resumed, off2, _ := parseFixture(t, off)
	if len(resumed) != 0 {
		t.Errorf("resuming at the persisted offset emitted %d events, want 0", len(resumed))
	}
	if off2 != off {
		t.Errorf("resumed NewOffset = %d, want %d", off2, off)
	}

	// A cursor beyond the entry count means the transcript shrank; re-read
	// from 0 rather than silently emitting nothing forever.
	reread, _, _ := parseFixture(t, 9999)
	if len(reread) != len(full) {
		t.Errorf("shrunk-transcript re-read emitted %d events, want a full re-read of %d", len(reread), len(full))
	}

	// Partial resume: from offset 3, everything before must be skipped.
	partial, _, _ := parseFixture(t, 3)
	for _, e := range partial {
		if e.SourceEventID == "tbs0" || e.SourceEventID == "t0u" {
			t.Errorf("resuming at offset 3 re-emitted %q", e.SourceEventID)
		}
	}
}

func TestMalformedBlobHoldsCursor(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), storeDirName)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(root, fixtureName(t))
	// A mid-rewrite read: valid prefix, truncated document.
	if err := os.WriteFile(path, []byte(`{"schemaVersion":1,"value":{"entries":[{"kind":"mess`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), path, 7)
	if err != nil {
		t.Fatalf("ParseSessionFile returned an error on a partial write: %v", err)
	}
	if res.NewOffset != 7 {
		t.Errorf("NewOffset = %d, want 7 (hold the cursor across a partial write)", res.NewOffset)
	}
	if !res.RetrySuggested {
		t.Error("RetrySuggested = false; a partial write must be retried")
	}
	if len(res.ToolEvents) != 0 {
		t.Errorf("emitted %d events from a truncated document", len(res.ToolEvents))
	}
}

func TestMissingFileIsNotAnError(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), storeDirName)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), filepath.Join(root, fixtureName(t)), 0)
	if err != nil {
		t.Fatalf("vanished file must not be an error, got %v", err)
	}
	if len(res.ToolEvents) != 0 {
		t.Errorf("emitted %d events for a missing file", len(res.ToolEvents))
	}
	// A deleted file will never read; retrying it forever would pin a dead
	// cursor on the poll loop.
	if res.RetrySuggested {
		t.Error("RetrySuggested = true for a nonexistent file; only transient errors (e.g. a write lock) may ask for a retry")
	}
}

// TestAppDataSpecIsOSShaped pins the per-OS root ladder against staged
// homes, so the assertion does not depend on which OS the test host
// runs. Before the 2026-09-03 root-hygiene ticket both shapes were
// emitted under EVERY home, which on a WSL2 daemon meant a
// "Library/Application Support" root under every Windows profile on the
// box — a path that cannot exist.
func TestAppDataSpecIsOSShaped(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		home crossmount.HomeRoot
		want []string
		why  string
	}{
		{
			name: "foreign windows home over /mnt/c",
			home: crossmount.HomeRoot{
				Path:   filepath.Join("/mnt/c/Users", "u"),
				OS:     crossmount.OSWindows,
				Origin: "wsl-mnt:u",
			},
			want: []string{filepath.Join("/mnt/c/Users", "u", "AppData", "Roaming", appDirName)},
			why:  "Windows shape only — no Application Support under a Windows profile",
		},
		{
			name: "darwin home",
			home: crossmount.HomeRoot{Path: filepath.Join("/Users", "u"), OS: crossmount.OSDarwin, Origin: "native"},
			want: []string{filepath.Join("/Users", "u", "Library", "Application Support", appDirName)},
			why:  "macOS shape only",
		},
		{
			name: "linux home",
			home: crossmount.HomeRoot{Path: filepath.Join("/home", "u"), OS: crossmount.OSLinux, Origin: "native"},
			want: nil,
			why:  "Grok Bot is not distributed for Linux; a ~/.config root would be invented",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := adapter.AppDataRoots(tc.home, appDataSpec)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%s\n got: %#v\nwant: %#v", tc.why, got, tc.want)
			}
		})
	}
}

// TestDefaultRootsShape pins what the LIVE root set looks like on
// whatever host runs the tests, per that host's OS: on Windows/macOS
// every root is the store directory. On native Linux (no mounted
// foreign Windows/macOS home) the set is legitimately empty, because
// Grok Bot is a Windows+macOS desktop app and does not ship a Linux
// build — TestAppDataSpecIsOSShaped pins that against staged homes;
// this test pins it against the LIVE host, so it must tolerate a WSL2
// dev box where crossmount surfaces a real mounted Windows home even
// though GOOS is "linux". Whatever roots ARE present, on any OS, must
// still satisfy the shape checks below.
func TestDefaultRootsShape(t *testing.T) {
	t.Parallel()
	roots := New().WatchPaths()
	if len(roots) == 0 {
		if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			t.Fatal("no default watch roots")
		}
		// Linux ships no Grok Bot build; an empty result is the
		// legitimate CI-runner case (no mounted foreign home).
		return
	}
	for _, r := range roots {
		n := filepath.ToSlash(r)
		if !strings.HasSuffix(n, "/"+storeDirName) {
			t.Errorf("root %q does not end in %q", r, storeDirName)
		}
		// Grok Bot is not distributed for Linux; inventing a
		// ~/.config root would be an ungrounded guess.
		if strings.Contains(n, "/.config/Grok Bot") {
			t.Errorf("root %q invents a Linux path Grok Bot does not ship", r)
		}
	}
}

func TestName(t *testing.T) {
	t.Parallel()
	if got := New().Name(); got != models.ToolGrokbot {
		t.Errorf("Name() = %q, want %q", got, models.ToolGrokbot)
	}
	if models.ToolGrokbot == models.ToolGrok {
		t.Fatal("grokbot and grok must be distinct tool constants")
	}
}
