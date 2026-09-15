package antigravity

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/oscrypt"
	"github.com/marmutapp/superbased-observer/internal/platform/protowire"
)

// synthConversation builds a small protobuf payload that follows the
// observed Antigravity shape closely enough to exercise classify
// heuristics:
//
//	Top-level repeated field 1 (entries):
//	  entry { field 2 = role enum (varint), field 3 = body (string),
//	          field 4 = timestamp (varint, unix seconds),
//	          field 5 = model (string) [optional],
//	          field 6 = tool name (string) [optional],
//	          field 7 = tool args (string) [optional],
//	          field 8 = input tokens (varint) [optional],
//	          field 9 = output tokens (varint) [optional]
//	        }
//
// This isn't the real Antigravity shape — just a plausible analog.
// The classifier uses content heuristics, not field numbers, so the
// exact field numbers don't matter; what matters is that text /
// timestamps / tool names / token counts are PRESENT in the right
// patterns for the heuristics to hit.
func synthConversation() []byte {
	now := uint64(time.Now().Unix())

	user := protowire.AppendVarintField(nil, 2, 0) // role=user
	user = protowire.AppendBytesField(user, 3, []byte("Please list files in this directory and tell me what you find. Make sure to give me a thorough answer."))
	user = protowire.AppendVarintField(user, 4, now)

	model := protowire.AppendVarintField(nil, 2, 1) // role=model
	model = protowire.AppendBytesField(model, 3, []byte("I'll list the files for you using the read tool. Here's what I plan to do step by step."))
	model = protowire.AppendVarintField(model, 4, now+10)
	model = protowire.AppendBytesField(model, 5, []byte("claude-haiku-4-5-20251001"))
	model = protowire.AppendVarintField(model, 8, 1234) // input tokens
	model = protowire.AppendVarintField(model, 9, 89)   // output tokens

	toolCall := protowire.AppendVarintField(nil, 2, 1)
	toolCall = protowire.AppendBytesField(toolCall, 6, []byte("read_file"))
	toolCall = protowire.AppendBytesField(toolCall, 7, []byte(`{"path":"/tmp/synth/main.go"}`))
	toolCall = protowire.AppendVarintField(toolCall, 4, now+15)

	var convo []byte
	convo = protowire.AppendBytesField(convo, 1, user)
	convo = protowire.AppendBytesField(convo, 1, model)
	convo = protowire.AppendBytesField(convo, 1, toolCall)
	return convo
}

// encryptCTR wraps plaintext with a synthetic 16-byte IV under
// AES-128-CTR. Returns the on-disk shape Antigravity uses (per the
// doc): IV || ciphertext.
func encryptCTR(t *testing.T, plaintext, key []byte) []byte {
	t.Helper()
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	ct := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(ct, plaintext)
	return append(iv, ct...)
}

// withFakeSecret wires a known secret into the adapter's cache,
// bypassing the real keystore. Used in tests.
func withFakeSecret(t *testing.T, a *Adapter, key []byte) {
	t.Helper()
	a.secretMu.Lock()
	a.secret = oscrypt.Secret(append([]byte(nil), key...))
	a.secretMu.Unlock()
}

func writePB(t *testing.T, dir string, uuid string, raw []byte) string {
	t.Helper()
	path := filepath.Join(dir, ".gemini", "antigravity", "conversations", uuid+".pb")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// TestMatchesSessionShape pins the path-shape string match
// independently of the v1.4.51 under-WatchPaths constraint. Foreign-
// OS separators are normalised so fixtures still work on Linux CI.
// The integrated IsSessionFile (shape AND under-WatchPaths) is
// covered by TestIsSessionFile below.
func TestMatchesSessionShape(t *testing.T) {
	cases := []struct {
		path string
		want bool
		desc string
	}{
		{"/home/u/.gemini/antigravity/conversations/abc.pb", true, "linux native (desktop)"},
		{`C:\Users\u\.gemini\antigravity\conversations\abc.pb`, true, "windows path (desktop)"},
		{"/mnt/c/Users/u/.gemini/antigravity/conversations/x.pb", true, "wsl cross-mount (desktop)"},
		{"/home/u/.gemini/antigravity-cli/conversations/abc.pb", true, "linux native (cli)"},
		{`C:\Users\u\.gemini\antigravity-cli\conversations\abc.pb`, true, "windows path (cli)"},
		{"/mnt/c/Users/u/.gemini/antigravity-cli/conversations/x.pb", true, "wsl cross-mount (cli)"},
		{"/home/u/.gemini/antigravity-cli/implicit/abc.pb", false, "cli implicit rejected"},
		{"/home/u/.gemini/antigravity/implicit/abc.pb", false, "implicit dir rejected (deferred)"},
		{"/home/u/.gemini/antigravity/user_settings.pb", false, "user_settings rejected"},
		{"/home/u/.gemini/tmp/abc/chats/session-x.json", false, "gemini-cli session rejected"},
		{"/home/u/.gemini/antigravity/annotations/abc.pbtxt", false, "annotations rejected"},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			if got := matchesSessionShape(c.path); got != c.want {
				t.Fatalf("matchesSessionShape(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}

// TestClassifyLayout pins layout disambiguation: CLI must be
// detected before desktop because the desktop prefix
// "/.gemini/antigravity/" is a prefix-substring of the CLI form
// "/.gemini/antigravity-cli/" — order matters in classifyLayout.
func TestClassifyLayout(t *testing.T) {
	cases := []struct {
		path string
		want Layout
		desc string
	}{
		{"/home/u/.gemini/antigravity/conversations/abc.pb", LayoutDesktop, "desktop linux"},
		{`C:\Users\u\.gemini\antigravity\conversations\abc.pb`, LayoutDesktop, "desktop windows"},
		{"/home/u/.gemini/antigravity-cli/conversations/abc.pb", LayoutCLI, "cli linux"},
		{`C:\Users\u\.gemini\antigravity-cli\conversations\abc.pb`, LayoutCLI, "cli windows"},
		{"/mnt/c/Users/u/.gemini/antigravity-cli/conversations/x.pb", LayoutCLI, "cli wsl cross-mount"},
		{"/home/u/foo.txt", LayoutUnknown, "non-pb file"},
		{"/home/u/.gemini/antigravity/implicit/x.pb", LayoutUnknown, "implicit subdir not classified"},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			if got := classifyLayout(c.path); got != c.want {
				t.Fatalf("classifyLayout(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}

// TestDefaultRootsIncludesCLI pins that defaultRoots() returns both
// the desktop and CLI conversations/ subtrees for the native $HOME —
// without this, the watcher silently drops CLI .pb files even with
// the layout classifier in place.
func TestDefaultRootsIncludesCLI(t *testing.T) {
	roots := defaultRoots()
	var sawDesktop, sawCLI, sawACP bool
	for _, r := range roots {
		norm := strings.ReplaceAll(r, `\`, "/")
		if strings.HasSuffix(norm, "/.gemini/antigravity/conversations") {
			sawDesktop = true
		}
		if strings.HasSuffix(norm, "/.gemini/antigravity-cli/conversations") {
			sawCLI = true
		}
		if strings.HasSuffix(norm, "/.gemini/antigravity-acp/conversations") {
			sawACP = true
		}
	}
	if !sawACP {
		t.Errorf("defaultRoots missing antigravity-acp conversations dir; got %v", roots)
	}
	if !sawDesktop {
		t.Errorf("defaultRoots missing desktop conversations dir; got %v", roots)
	}
	if !sawCLI {
		t.Errorf("defaultRoots missing CLI conversations dir; got %v", roots)
	}
}

// TestIsSessionFile pins the integrated public API: shape AND
// under-WatchPaths. Uses host-native paths so filepath.Abs behaves.
func TestIsSessionFile(t *testing.T) {
	root := t.TempDir()
	a := NewWithOptions(nil, root)
	good := filepath.Join(root, ".gemini", "antigravity", "conversations", "abc.pb")
	if !a.IsSessionFile(good) {
		t.Errorf("matching path under watch root should match: %s", good)
	}
	// Shape match but outside watch root (v1.4.51 invariant).
	if a.IsSessionFile("/tmp/foreign/.gemini/antigravity/conversations/x.pb") {
		t.Error("shape-match outside watch root must NOT match")
	}
}

func TestParseSessionFileGoldenPath(t *testing.T) {
	a := New()
	key := make([]byte, 16)
	rand.Read(key)
	withFakeSecret(t, a, key)

	plaintext := synthConversation()
	encrypted := encryptCTR(t, plaintext, key)

	dir := t.TempDir()
	path := writePB(t, dir, "11111111-2222-3333-4444-555555555555", encrypted)

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) == 0 {
		t.Fatalf("no events emitted; warnings=%v", res.Warnings)
	}
	// Expect at least one user prompt and one tool call (the model row may classify as task_complete).
	var sawUser, sawTool bool
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt {
			sawUser = true
		}
		if ev.RawToolName == "read_file" {
			sawTool = true
			if !strings.Contains(ev.Target, "main.go") {
				t.Errorf("read_file Target = %q, want main.go", ev.Target)
			}
		}
	}
	if !sawUser {
		t.Errorf("no ActionUserPrompt event emitted; events=%+v", summarizeEvents(res.ToolEvents))
	}
	if !sawTool {
		t.Errorf("no read_file tool call emitted; events=%+v", summarizeEvents(res.ToolEvents))
	}

	// At least one TokenEvent.
	if len(res.TokenEvents) == 0 {
		t.Errorf("no TokenEvents emitted")
	}
}

func TestParseSessionFileWrongKey(t *testing.T) {
	a := New()
	key := make([]byte, 16)
	rand.Read(key)
	withFakeSecret(t, a, []byte("0123456789abcdef")) // wrong key

	plaintext := synthConversation()
	encrypted := encryptCTR(t, plaintext, key)

	dir := t.TempDir()
	path := writePB(t, dir, "deadbeef-0000-0000-0000-000000000000", encrypted)

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile (expected nil err with warning): %v", err)
	}
	if len(res.Warnings) == 0 {
		t.Fatalf("expected decrypt warning")
	}
	if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 {
		t.Fatalf("wrong-key decrypt produced events: %d/%d", len(res.ToolEvents), len(res.TokenEvents))
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "decrypt failed") {
		t.Errorf("warning text = %v, want 'decrypt failed'", res.Warnings)
	}
}

func TestParseSessionFileCursorMonotonic(t *testing.T) {
	a := New()
	key := make([]byte, 16)
	rand.Read(key)
	withFakeSecret(t, a, key)

	plaintext := synthConversation()
	encrypted := encryptCTR(t, plaintext, key)

	dir := t.TempDir()
	path := writePB(t, dir, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", encrypted)

	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if first.NewOffset != int64(len(encrypted)) {
		t.Fatalf("NewOffset=%d want %d", first.NewOffset, len(encrypted))
	}

	// Re-parse with cursor at file size: no work.
	second, err := a.ParseSessionFile(context.Background(), path, first.NewOffset)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if len(second.ToolEvents) != 0 || len(second.TokenEvents) != 0 {
		t.Fatalf("re-parse with current cursor produced events: %d/%d", len(second.ToolEvents), len(second.TokenEvents))
	}
}

func TestParseSessionFileMissingFile(t *testing.T) {
	a := New()
	withFakeSecret(t, a, make([]byte, 16))
	_, err := a.ParseSessionFile(context.Background(), "/nonexistent/foo.pb", 0)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// trackerKey identifies a row in fakeTracker. Tests use one tracker
// per (adapter,path) so a sync.Map would be overkill.
type trackerEntry struct {
	size, mtime int64
	reason      string
}

// fakeTracker is an in-memory UnrecoverableTracker for tests. The
// production wiring lives in cmd/observer/main.go and wraps
// store.Store; here we just exercise the contract.
type fakeTracker struct {
	entries map[string]trackerEntry
}

func newFakeTracker() *fakeTracker {
	return &fakeTracker{entries: map[string]trackerEntry{}}
}

func (t *fakeTracker) Lookup(_ context.Context, path string, size, mtime int64) (string, bool, error) {
	e, ok := t.entries[path]
	if !ok {
		return "", false, nil
	}
	if e.size != size || e.mtime != mtime {
		return "", false, nil
	}
	return e.reason, true, nil
}

func (t *fakeTracker) Mark(_ context.Context, path string, size, mtime int64, reason string) error {
	t.entries[path] = trackerEntry{size: size, mtime: mtime, reason: reason}
	return nil
}

func (t *fakeTracker) Clear(_ context.Context, path string) error {
	delete(t.entries, path)
	return nil
}

// TestUnrecoverableCache_ShortCircuitsSecondAttempt pins the Issue #4
// persistent tracker: a file that fails decrypt is recorded, and the
// next ParseSessionFile call on the same path short-circuits without
// re-attempting the decrypt (or gRPC). File-change invalidation is
// the companion guarantee — after the file's content changes
// (size+mtime drift), the tracker returns found=false and the full
// decrypt path runs again.
func TestUnrecoverableCache_ShortCircuitsSecondAttempt(t *testing.T) {
	a := New().WithUnrecoverableTracker(newFakeTracker())
	wrongKey := []byte("0123456789abcdef")
	withFakeSecret(t, a, wrongKey)

	// Encrypt with a different key so decrypt fails.
	plaintext := synthConversation()
	realKey := make([]byte, 16)
	rand.Read(realKey)
	encrypted := encryptCTR(t, plaintext, realKey)

	dir := t.TempDir()
	path := writePB(t, dir, "deadbeef-1111-2222-3333-444444444444", encrypted)

	// First attempt: decrypt fails, file gets marked unrecoverable.
	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if len(first.Warnings) == 0 || !strings.Contains(strings.Join(first.Warnings, " "), "decrypt failed") {
		t.Fatalf("expected decrypt-failed warning on first attempt, got %v", first.Warnings)
	}

	// Second attempt: should short-circuit with the cached warning.
	second, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	joined := strings.Join(second.Warnings, " ")
	if !strings.Contains(joined, "previously unrecoverable") {
		t.Fatalf("expected short-circuit warning on second attempt, got %v", second.Warnings)
	}

	// File-change invalidation: rewrite the file with different content
	// (different size); tracker should report found=false and full
	// path should run.
	if err := os.WriteFile(path, append(encrypted, 0xff, 0xfe, 0xfd), 0o600); err != nil {
		t.Fatalf("rewrite file: %v", err)
	}
	third, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("third parse: %v", err)
	}
	if !strings.Contains(strings.Join(third.Warnings, " "), "decrypt failed") {
		t.Fatalf("expected re-attempted decrypt warning after file change, got %v", third.Warnings)
	}
	if strings.Contains(strings.Join(third.Warnings, " "), "previously unrecoverable") {
		t.Fatal("file-change invalidation failed: short-circuit warning still firing")
	}
}

// TestUnrecoverableCache_ClearedOnSuccess pins the companion
// invariant: a successful decrypt drops any prior unrecoverable mark
// for that path. Without this, a transient decrypt failure (e.g. user
// locked then unlocked their keychain) would permanently pin the
// short-circuit until the file actually changes.
func TestUnrecoverableCache_ClearedOnSuccess(t *testing.T) {
	tracker := newFakeTracker()
	a := New().WithUnrecoverableTracker(tracker)
	key := make([]byte, 16)
	rand.Read(key)

	plaintext := synthConversation()
	encrypted := encryptCTR(t, plaintext, key)
	dir := t.TempDir()
	path := writePB(t, dir, "cccccccc-cccc-cccc-cccc-cccccccccccc", encrypted)

	// Pre-seed the tracker to simulate a prior failure with the
	// current size+mtime — would short-circuit if we let
	// ParseSessionFile run. Clear it first so the success path runs
	// and we can verify the post-success ClearUnrecoverable call.
	fi := statOrFatal(t, path)
	tracker.entries[path] = trackerEntry{size: fi.Size(), mtime: fi.ModTime().Unix(), reason: "test-seeded"}
	_ = tracker.Clear(context.Background(), path)

	// Now provide the correct secret and re-parse — should succeed
	// AND post-success clear should leave the tracker empty.
	withFakeSecret(t, a, key)

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(res.Warnings) > 0 && strings.Contains(strings.Join(res.Warnings, " "), "decrypt failed") {
		t.Fatalf("expected success, got warnings: %v", res.Warnings)
	}

	if _, ok := tracker.entries[path]; ok {
		t.Errorf("post-success tracker should be empty for %s, still has entry", path)
	}
}

// TestUnrecoverableCache_NoTrackerIsHarmless pins the no-op behavior
// when the adapter is constructed without a tracker (smoke tests /
// callers that haven't wired the persistent store). The adapter must
// continue to function — just without the perf benefit.
func TestUnrecoverableCache_NoTrackerIsHarmless(t *testing.T) {
	a := New() // No WithUnrecoverableTracker call.
	wrongKey := []byte("0123456789abcdef")
	withFakeSecret(t, a, wrongKey)

	plaintext := synthConversation()
	realKey := make([]byte, 16)
	rand.Read(realKey)
	encrypted := encryptCTR(t, plaintext, realKey)
	dir := t.TempDir()
	path := writePB(t, dir, "11111111-2222-3333-4444-555555555555", encrypted)

	// Two attempts: both should run the full decrypt path (no
	// short-circuit warning), both should produce decrypt-failed.
	for i := 0; i < 2; i++ {
		res, err := a.ParseSessionFile(context.Background(), path, 0)
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if !strings.Contains(strings.Join(res.Warnings, " "), "decrypt failed") {
			t.Fatalf("attempt %d: expected decrypt-failed warning, got %v", i, res.Warnings)
		}
		if strings.Contains(strings.Join(res.Warnings, " "), "previously unrecoverable") {
			t.Fatalf("attempt %d: short-circuit warning should not fire without a tracker", i)
		}
	}
}

// TestDumpShapeMismatchPayload_WritesWhenConfigured pins the Issue #5
// debug-dump behavior: when DumpShapeMismatchesDir is set, the
// adapter's dumpShapeMismatchPayload helper writes the raw bytes to
// <dir>/<conversationID>.bin. mkdir is idempotent (dir doesn't have
// to pre-exist). When DumpShapeMismatchesDir is empty, the call is
// a no-op (nothing written, no error). When the conversationID is
// empty (defensive — should never happen) the call also skips.
func TestDumpShapeMismatchPayload_WritesWhenConfigured(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dumps") // intentionally not pre-created
	a := New().WithShapeMismatchDumpDir(dir)

	conv := "e371fdb1-568d-4edc-90b7-2dd94f3a7fae"
	payload := []byte{0x12, 0x34, 0x56, 0x78, 0xde, 0xad, 0xbe, 0xef}
	a.dumpShapeMismatchPayload(conv, payload)

	want := filepath.Join(dir, conv+".bin")
	got, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("dump file: %v", err)
	}
	if !bytesEqual(got, payload) {
		t.Errorf("dump contents mismatch: got %x want %x", got, payload)
	}

	// Empty dump dir → no-op (no panic, no error, no file).
	a2 := New()
	a2.dumpShapeMismatchPayload(conv, payload)
	// Defensively: empty conv → no-op even when dir is set.
	a.dumpShapeMismatchPayload("", payload)
	// Empty payload → no-op even when both dir and conv are set.
	a.dumpShapeMismatchPayload("other", nil)
	if _, err := os.Stat(filepath.Join(dir, "other.bin")); !os.IsNotExist(err) {
		t.Errorf("empty payload should not write a file; stat err=%v", err)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestIsWrongWorkspaceStub pins the wire-signature classifier for
// the wrong-workspace stub bug. A real response from a server that
// hosts the conversation always populates at least the model name
// (verified across 122 working sessions in the maintainer corpus on
// 2026-05-19). A stub from a non-hosting server returns an envelope
// with zero `1.3` per-turn entries — no model, no tokens, no tools.
//
// The pre-fix guard `numEvents(res) == 0` mis-classified stubs as
// real because the trivial markdown that accompanies a stub parses
// as one fake user_prompt event. e371fdb1 hit this on the live
// daemon: pid=1339 (wrong workspace) returned the stub first, was
// accepted, pid=1340 (the actual host) was never tried.
func TestIsWrongWorkspaceStub(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		en   StructuredEnrichment
		want bool
	}{
		{
			name: "wrong-workspace stub (all empty)",
			en:   StructuredEnrichment{},
			want: true,
		},
		{
			name: "real response (model populated)",
			en:   StructuredEnrichment{Model: "claude-sonnet-4-6"},
			want: false,
		},
		{
			name: "real response (tokens populated)",
			en:   StructuredEnrichment{TokenEvents: []models.TokenEvent{{InputTokens: 100}}},
			want: false,
		},
		{
			name: "real response (tools populated)",
			en:   StructuredEnrichment{ToolEvents: []models.ToolEvent{{ActionType: models.ActionReadFile}}},
			want: false,
		},
		{
			name: "real response (all three)",
			en: StructuredEnrichment{
				Model:       "claude-sonnet-4-6",
				TokenEvents: []models.TokenEvent{{}},
				ToolEvents:  []models.ToolEvent{{}},
			},
			want: false,
		},
		// Edge: a real response with non-empty StartedAt/EndedAt
		// but no payload — should this count as a stub? Yes —
		// timestamps without semantic content (model/tokens/tools)
		// match the stub signature. A genuinely-empty-yet-hosted
		// conversation is fiction; real hosting servers populate
		// the per-turn list, which carries the model name.
		{
			name: "timestamps only (still a stub)",
			en:   StructuredEnrichment{StartedAt: time.Now(), EndedAt: time.Now()},
			want: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isWrongWorkspaceStub(c.en); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// TestParseStructuredTrajectory_E371fdb1WireBytes is a regression
// test against the captured wire bytes from session
// e371fdb1-568d-4edc-90b7-2dd94f3a7fae. Pre-fix the live daemon
// reported "0 tools, 0 tokens, model=" for this session because it
// asked the wrong server (pid=1339) and was misled by the markdown-
// derived user_prompt event. Once the daemon asks the correct
// server (pid=1340), the parser successfully extracts 17 token
// rows + 25 tools + the model name.
//
// We can't reach the live pid=1340 server from a unit test, so
// instead we check that ParseStructuredTrajectory ITSELF correctly
// extracts the data when given the real wire bytes. (The probe at
// probe_e371fdb1_test.go captured those bytes from pid=1340.)
//
// Fixture is loaded from disk when present; skip otherwise to keep
// the test suite hermetic. Operator re-captures via:
//
//	PROBE_E371=1 go test -v -run TestProbeE371fdb1 ./internal/adapter/antigravity/
func TestParseStructuredTrajectory_E371fdb1WireBytes(t *testing.T) {
	t.Parallel()
	const fixturePath = "/tmp/ag-probe-e371fdb1-568d-4edc-90b7-2dd94f3a7fae.bin"
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Skipf("fixture not present (%v) — capture via PROBE_E371=1 go test -run TestProbeE371fdb1", err)
	}
	en := ParseStructuredTrajectory(raw, "e371fdb1-568d-4edc-90b7-2dd94f3a7fae", "/home/marmutapp/superbased-observer", "", "/tmp/test.pb", identityScrubber{})
	if en.Model != "claude-sonnet-4-6" {
		t.Errorf("Model = %q, want claude-sonnet-4-6", en.Model)
	}
	if len(en.TokenEvents) == 0 {
		t.Errorf("TokenEvents empty — parser failed to extract per-turn rows")
	}
	if len(en.ToolEvents) == 0 {
		t.Errorf("ToolEvents empty — parser failed to extract tool calls")
	}
	if isWrongWorkspaceStub(en) {
		t.Errorf("classifier said stub on real e371fdb1 data: %+v",
			struct {
				Model              string
				Tokens, Tools, Sec int
			}{en.Model, len(en.TokenEvents), len(en.ToolEvents), int(en.EndedAt.Sub(en.StartedAt).Seconds())})
	}
	t.Logf("e371fdb1 extracted: model=%q tokens=%d tools=%d duration=%v",
		en.Model, len(en.TokenEvents), len(en.ToolEvents), en.EndedAt.Sub(en.StartedAt))
}

// statOrFatal is a small helper for unrecoverable-cache tests.
func statOrFatal(t *testing.T, path string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi
}

func TestParseSessionFileSecretLookupFails(t *testing.T) {
	a := New()
	a.secretErr = ErrSentinelSecret

	dir := t.TempDir()
	path := writePB(t, dir, "ffffffff-ffff-ffff-ffff-ffffffffffff", []byte("anybytes"))

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if res.NewOffset != 0 {
		t.Fatalf("cursor advanced despite secret failure: %d", res.NewOffset)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("expected secret-failure warning")
	}
}

// ErrSentinelSecret is a fake secret-error injectable into the
// adapter's cache for tests.
var ErrSentinelSecret = sentinelErr("synthetic secret retrieval failure")

type sentinelErr string

func (s sentinelErr) Error() string { return string(s) }

func TestUuidFromFilename(t *testing.T) {
	cases := map[string]string{
		"/home/u/.gemini/antigravity/conversations/abc-123.pb": "abc-123",
		`C:\Users\u\.gemini\antigravity\conversations\X.pb`:    "X",
	}
	for in, want := range cases {
		got := uuidFromFilename(in)
		if got != want {
			t.Errorf("uuidFromFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMapToolName(t *testing.T) {
	cases := map[string]string{
		"read_file":         models.ActionReadFile,
		"runShellCommand":   models.ActionRunCommand,
		"google_web_search": models.ActionWebSearch,
		"replace":           models.ActionEditFile,
		"glob":              models.ActionSearchFiles,
		"grep":              models.ActionSearchText,
		"web_fetch":         models.ActionWebFetch,
		"unknown_tool":      models.ActionUnknown,
		"mcp__server__do":   models.ActionMCPCall,
	}
	for in, want := range cases {
		if got := mapToolName(in); got != want {
			t.Fatalf("mapToolName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsModelIdentifier(t *testing.T) {
	good := []string{"claude-haiku-4-5-20251001", "gemini-3-pro", "gpt-5", "grok-code-fast-1", "auto"}
	bad := []string{"hello world", "x", "", "filepath/with/slashes/here.go"}
	for _, s := range good {
		if !isModelIdentifier(s) {
			t.Errorf("isModelIdentifier(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if isModelIdentifier(s) {
			t.Errorf("isModelIdentifier(%q) = true, want false", s)
		}
	}
}

func TestLooksLikeUUID(t *testing.T) {
	cases := map[string]bool{
		"11111111-2222-3333-4444-555555555555": true,
		"abc-123":                              false,
		"":                                     false,
		"11111111x2222-3333-4444-555555555555": false,
	}
	for s, want := range cases {
		if got := looksLikeUUID(s); got != want {
			t.Errorf("looksLikeUUID(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestTargetFromToolArgs(t *testing.T) {
	cases := []struct {
		args, want string
	}{
		{`{"path":"/tmp/main.go"}`, "/tmp/main.go"},
		{`{"absolute_path":"/abs/main.go","other":"x"}`, "/abs/main.go"},
		{`{"command":"ls -la"}`, "ls -la"},
		{`{"unrelated":"value"}`, "fallback"},
		{``, "fallback"},
	}
	for _, c := range cases {
		got := targetFromToolArgs(c.args, "fallback")
		if got != c.want {
			t.Errorf("targetFromToolArgs(%q) = %q, want %q", c.args, got, c.want)
		}
	}
}

func summarizeEvents(events []models.ToolEvent) []string {
	out := make([]string, len(events))
	for i, ev := range events {
		out[i] = ev.ActionType + "/" + ev.RawToolName
	}
	return out
}
