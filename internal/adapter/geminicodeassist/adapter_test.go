package geminicodeassist

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// ---------------------------------------------------------------------
// Every JSON body in this file is SYNTHETIC. Nothing here was captured
// from a real Gemini Code Assist install: the four usageMetadata field
// names are the only bundle-grounded part, and the envelope around them
// is this package's own [UNVERIFIED] placeholder. These fixtures pin the
// skeleton's behaviour, NOT the vendor's format — when the P3 step-in
// lands a real spool file under testdata/geminicodeassist/, these move
// aside for it.
// ---------------------------------------------------------------------

// stageTree builds a fake Linux editor tree under t.TempDir() and
// returns the home path plus an adapter rooted at it.
func stageTree(t *testing.T) (string, *Adapter) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	roots := rootsForHomes([]crossmount.HomeRoot{linuxHome(home)})
	if len(roots) == 0 {
		t.Fatal("rootsForHomes produced no roots for a linux home")
	}
	return home, NewWithRoots(roots)
}

// codeGlobalStorage is the VS Code ("Code") product's globalStorage dir
// under a fake Linux home.
func codeGlobalStorage(home string) string {
	return filepath.Join(home, ".config", "Code", "User", "globalStorage")
}

func TestIsSessionFileMatrix(t *testing.T) {
	home, a := stageTree(t)
	gs := codeGlobalStorage(home)
	ext := filepath.Join(gs, extensionDirName)
	cursorGS := filepath.Join(home, ".config", "Cursor", "User", "globalStorage")

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "drained metrics spool json",
			path: filepath.Join(ext, metricsSpoolDirName, "0f4c8a1e-1111-2222-3333-444455556666.json"),
			want: true,
		},
		{
			name: "half-written metrics spool tmp is rejected",
			path: filepath.Join(ext, metricsSpoolDirName, "0f4c8a1e-1111-2222-3333-444455556666.tmp"),
			want: false,
		},
		{
			name: "checkpoint file with no extension",
			path: filepath.Join(ext, checkpointsDirName, "thread-a-checkpoint-0"),
			want: true,
		},
		{
			name: "checkpoint file nested a level deeper",
			path: filepath.Join(ext, checkpointsDirName, "thread-a", "0.json"),
			want: true,
		},
		{
			name: "vscode state.vscdb is claimed",
			path: filepath.Join(gs, stateDBFileName),
			want: true,
		},
		{
			name: "state.vscdb wal sidecar is not",
			path: filepath.Join(gs, stateDBFileName+"-wal"),
			want: false,
		},
		{
			name: "state.vscdb shm sidecar is not",
			path: filepath.Join(gs, stateDBFileName+"-shm"),
			want: false,
		},
		{
			name: "state.vscdb backup copy is not",
			path: filepath.Join(gs, stateDBFileName+".backup"),
			want: false,
		},
		{
			name: "cursor state.vscdb belongs to internal/adapter/cursor",
			path: filepath.Join(cursorGS, stateDBFileName),
			want: false,
		},
		{
			name: "windsurf state.vscdb belongs to internal/adapter/windsurf",
			path: filepath.Join(home, ".config", "Windsurf", "User", "globalStorage", stateDBFileName),
			want: false,
		},
		{
			name: "another extension's globalStorage subtree",
			path: filepath.Join(gs, "github.copilot-chat", "sessions", "x.json"),
			want: false,
		},
		{
			name: "agent mode transcript belongs to internal/adapter/gemini",
			path: filepath.Join(home, ".gemini", "tmp", "proj", "chats", "session-2026-09-03-abcd1234.jsonl"),
			want: false,
		},
		{
			name: "gemini oauth credentials are never claimed",
			path: filepath.Join(home, ".gemini", "oauth_creds.json"),
			want: false,
		},
		{
			name: "a spool-shaped path outside every watch root",
			path: filepath.Join(t.TempDir(), extensionDirName, metricsSpoolDirName, "x.json"),
			want: false,
		},
		{
			name: "empty path",
			path: "",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Errorf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// writeSpool stages one spool file under the VS Code product's spool
// root and returns its path.
func writeSpool(t *testing.T, home, name, body string) string {
	t.Helper()
	dir := filepath.Join(codeGlobalStorage(home), extensionDirName, metricsSpoolDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir spool dir: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write spool file: %v", err)
	}
	return path
}

// SYNTHETIC. Top-level OBJECT form: one event carrying usageMetadata
// nested one level down, with a model id beside it.
const synthSpoolObject = `{
  "event_name": "CHAT_STREAMING_OFFERED_CHUNK",
  "payload": {
    "model": "gemini-2.5-pro",
    "usageMetadata": {
      "promptTokenCount": 1200,
      "candidatesTokenCount": 340,
      "totalTokenCount": 1540,
      "cachedContentTokenCount": 900
    }
  }
}`

// SYNTHETIC. Top-level ARRAY form: three events, two of which carry
// usage; the third is a START record with no usageMetadata at all.
const synthSpoolArray = `[
  {"event_name":"CHAT_STREAMING_OFFERED_START","payload":{"threadId":"t-1"}},
  {"event_name":"CHAT_STREAMING_OFFERED_CHUNK","modelName":"gemini-2.5-flash",
   "usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15,"cachedContentTokenCount":0}},
  {"event_name":"CHAT_STREAMING_OFFERED_CHUNK",
   "usageMetadata":{"promptTokenCount":40,"candidatesTokenCount":7,"totalTokenCount":47,"cachedContentTokenCount":40}}
]`

func TestParseSpoolObjectFormNetsCachedInput(t *testing.T) {
	home, a := stageTree(t)
	path := writeSpool(t, home, "aaaa1111.json", synthSpoolObject)

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", res.Warnings)
	}
	if len(res.ToolEvents) != 0 {
		t.Errorf("skeleton must emit no ToolEvents, got %d", len(res.ToolEvents))
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1", len(res.TokenEvents))
	}

	te := res.TokenEvents[0]
	// promptTokenCount is GROSS: 1200 includes the 900 cached.
	if te.InputTokens != 300 {
		t.Errorf("InputTokens = %d, want 300 (1200 gross - 900 cached)", te.InputTokens)
	}
	if te.CacheReadTokens != 900 {
		t.Errorf("CacheReadTokens = %d, want 900", te.CacheReadTokens)
	}
	if te.OutputTokens != 340 {
		t.Errorf("OutputTokens = %d, want 340", te.OutputTokens)
	}
	if te.Model != "gemini-2.5-pro" {
		t.Errorf("Model = %q, want gemini-2.5-pro", te.Model)
	}
	if te.Tool != ToolName {
		t.Errorf("Tool = %q, want %q", te.Tool, ToolName)
	}
	if te.SessionID != "aaaa1111" {
		t.Errorf("SessionID = %q, want the spool file stem aaaa1111", te.SessionID)
	}
	if te.SourceEventID != "aaaa1111.json:usage:0" {
		t.Errorf("SourceEventID = %q, want aaaa1111.json:usage:0", te.SourceEventID)
	}
	if te.Source != models.TokenSourceJSONL {
		t.Errorf("Source = %q, want %q", te.Source, models.TokenSourceJSONL)
	}
	if te.Reliability != models.ReliabilityUnreliable {
		t.Errorf("Reliability = %q, want %q", te.Reliability, models.ReliabilityUnreliable)
	}
	if te.Timestamp.IsZero() {
		t.Error("Timestamp is zero; the spool file mtime should stand in")
	}
	if res.NewOffset != int64(len(synthSpoolObject)) {
		t.Errorf("NewOffset = %d, want %d", res.NewOffset, len(synthSpoolObject))
	}
}

func TestParseSpoolArrayFormEmitsOnePerUsageSite(t *testing.T) {
	home, a := stageTree(t)
	path := writeSpool(t, home, "bbbb2222.json", synthSpoolArray)

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", res.Warnings)
	}
	if len(res.TokenEvents) != 2 {
		t.Fatalf("TokenEvents = %d, want 2 (the START record carries no usage)", len(res.TokenEvents))
	}

	first, second := res.TokenEvents[0], res.TokenEvents[1]
	if first.InputTokens != 10 || first.OutputTokens != 5 || first.CacheReadTokens != 0 {
		t.Errorf("first event = (%d,%d,%d), want (10,5,0)", first.InputTokens, first.OutputTokens, first.CacheReadTokens)
	}
	if first.Model != "gemini-2.5-flash" {
		t.Errorf("first event Model = %q, want gemini-2.5-flash (the modelName spelling)", first.Model)
	}
	// 40 gross prompt, all of it cached ⇒ 0 net input.
	if second.InputTokens != 0 || second.CacheReadTokens != 40 {
		t.Errorf("second event = (input %d, cache %d), want (0, 40)", second.InputTokens, second.CacheReadTokens)
	}
	if second.Model != "" {
		t.Errorf("second event Model = %q, want empty (no model key beside usageMetadata)", second.Model)
	}
	if first.SourceEventID == second.SourceEventID {
		t.Errorf("SourceEventIDs collide: %q", first.SourceEventID)
	}
}

func TestParseSpoolEdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantEvents   int
		wantWarnings int
	}{
		{
			// The steady state of a telemetry spool. Zero events and
			// deliberately NO warning: an event without usage is
			// normal, not an anomaly.
			name:         "no usageMetadata anywhere",
			body:         `{"event_name":"CHAT_STREAMING_OFFERED_START","payload":{"threadId":"t-1"}}`,
			wantEvents:   0,
			wantWarnings: 0,
		},
		{
			name:         "usageMetadata present but structurally zero",
			body:         `{"usageMetadata":{"promptTokenCount":0,"candidatesTokenCount":0,"totalTokenCount":0,"cachedContentTokenCount":0}}`,
			wantEvents:   0,
			wantWarnings: 0,
		},
		{
			name:         "output only still emits",
			body:         `{"usageMetadata":{"candidatesTokenCount":12}}`,
			wantEvents:   1,
			wantWarnings: 0,
		},
		{
			name:         "usageMetadata is not an object",
			body:         `{"usageMetadata":"nope"}`,
			wantEvents:   0,
			wantWarnings: 0,
		},
		{
			name:         "usageMetadata counts are the wrong type",
			body:         `{"usageMetadata":{"promptTokenCount":"1200"}}`,
			wantEvents:   0,
			wantWarnings: 0,
		},
		{
			name:         "malformed JSON warns and does not error",
			body:         `{"event_name": "CHAT_STREAMING_OFFERED_CHUNK",`,
			wantEvents:   0,
			wantWarnings: 1,
		},
		{
			name:         "empty file warns",
			body:         ``,
			wantEvents:   0,
			wantWarnings: 1,
		},
		{
			name:         "top-level scalar decodes to no sites",
			body:         `42`,
			wantEvents:   0,
			wantWarnings: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home, a := stageTree(t)
			path := writeSpool(t, home, "cccc3333.json", tc.body)

			res, err := a.ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile returned an error, want warning-only: %v", err)
			}
			if len(res.TokenEvents) != tc.wantEvents {
				t.Errorf("TokenEvents = %d, want %d", len(res.TokenEvents), tc.wantEvents)
			}
			if len(res.Warnings) != tc.wantWarnings {
				t.Errorf("Warnings = %d (%v), want %d", len(res.Warnings), res.Warnings, tc.wantWarnings)
			}
		})
	}
}

// TestParseSpoolIsIdempotentAtCursor pins that a re-parse at the
// persisted offset yields nothing: a spool file is written once and
// never appended to.
func TestParseSpoolIsIdempotentAtCursor(t *testing.T) {
	home, a := stageTree(t)
	path := writeSpool(t, home, "dddd4444.json", synthSpoolObject)

	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	second, err := a.ParseSessionFile(context.Background(), path, first.NewOffset)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if len(second.TokenEvents) != 0 {
		t.Errorf("re-parse at the persisted offset emitted %d events, want 0", len(second.TokenEvents))
	}
	if second.NewOffset != first.NewOffset {
		t.Errorf("NewOffset moved on re-parse: %d → %d", first.NewOffset, second.NewOffset)
	}
}

// TestUngroundedStoresReturnOneWarning is the skeleton's core contract
// (plan §4 note 1): a store whose shape has never been observed yields
// an EMPTY result plus exactly one warning naming the fixture README.
func TestUngroundedStoresReturnOneWarning(t *testing.T) {
	home, a := stageTree(t)
	gs := codeGlobalStorage(home)

	checkpointDir := filepath.Join(gs, extensionDirName, checkpointsDirName)
	if err := os.MkdirAll(checkpointDir, 0o755); err != nil {
		t.Fatalf("mkdir checkpoints: %v", err)
	}
	checkpoint := filepath.Join(checkpointDir, "thread-a-checkpoint-0")
	if err := os.WriteFile(checkpoint, []byte("SYNTHETIC checkpoint body"), 0o600); err != nil {
		t.Fatalf("write checkpoint: %v", err)
	}

	// state.vscdb is NEVER opened — the file need not even be a valid
	// SQLite database for the contract to hold.
	stateDB := filepath.Join(gs, stateDBFileName)
	if err := os.WriteFile(stateDB, []byte("not a sqlite file"), 0o600); err != nil {
		t.Fatalf("write state.vscdb: %v", err)
	}

	for _, path := range []string{checkpoint, stateDB} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if !a.IsSessionFile(path) {
				t.Fatalf("IsSessionFile(%q) = false, want true", path)
			}
			res, err := a.ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 {
				t.Errorf("emitted %d tool / %d token events, want 0 / 0",
					len(res.ToolEvents), len(res.TokenEvents))
			}
			if len(res.Warnings) != 1 {
				t.Fatalf("Warnings = %d (%v), want exactly 1", len(res.Warnings), res.Warnings)
			}
			if !strings.Contains(res.Warnings[0], fixtureREADME) {
				t.Errorf("warning %q does not name %s", res.Warnings[0], fixtureREADME)
			}
			if res.NewOffset != 0 {
				t.Errorf("NewOffset = %d, want 0 — nothing was consumed", res.NewOffset)
			}
		})
	}
}

func TestParseSessionFileHonoursCancelledContext(t *testing.T) {
	home, a := stageTree(t)
	path := writeSpool(t, home, "eeee5555.json", synthSpoolObject)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := a.ParseSessionFile(ctx, path, 0)
	if err == nil {
		t.Fatal("ParseSessionFile with a cancelled context returned nil error")
	}
	if !strings.HasPrefix(err.Error(), "geminicodeassist.ParseSessionFile: ") {
		t.Errorf("error %q is not wrapped with the package prefix", err)
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("emitted %d token events on a cancelled context", len(res.TokenEvents))
	}
}

func TestParseSessionFileMissingSpoolFileErrors(t *testing.T) {
	home, a := stageTree(t)
	path := writeSpool(t, home, "ffff6666.json", synthSpoolObject)
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	// The spool is transient by design — a file drained between the
	// fsnotify event and the parse is normal. It surfaces as a wrapped
	// error the watcher already tolerates, not a panic.
	if _, err := a.ParseSessionFile(context.Background(), path, 0); err == nil {
		t.Fatal("missing spool file returned nil error")
	} else if !strings.HasPrefix(err.Error(), "geminicodeassist.ParseSessionFile: ") {
		t.Errorf("error %q is not wrapped with the package prefix", err)
	}
}

func TestNameAndDefaultConstruction(t *testing.T) {
	if got := New().Name(); got != ToolName {
		t.Errorf("Name() = %q, want %q", got, ToolName)
	}
	if got := NewWithRoots(nil); len(got.WatchPaths()) == 0 && len(defaultRoots()) != 0 {
		t.Error("NewWithRoots(nil) did not fall back to the platform defaults")
	}
}
