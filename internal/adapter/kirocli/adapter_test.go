package kirocli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// withHomes overrides the crossmount home enumeration for a test and
// restores it afterwards.
func withHomes(t *testing.T, homes []crossmount.HomeRoot) {
	t.Helper()
	prev := allHomesFunc
	allHomesFunc = func() []crossmount.HomeRoot { return homes }
	t.Cleanup(func() { allHomesFunc = prev })
}

// copyFixtureBundle copies a testdata flat bundle (all siblings sharing
// the stem) into dstDir under the destination session id.
func copyFixtureBundle(t *testing.T, stem, dstDir, dstID string) {
	t.Helper()
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, ext := range []string{".json", ".jsonl", ".history"} {
		src := filepath.Join("..", "..", "..", "testdata", "kirocli", stem+ext)
		body, err := os.ReadFile(src)
		if err != nil {
			continue // .history is optional
		}
		if err := os.WriteFile(filepath.Join(dstDir, dstID+ext), body, 0o644); err != nil {
			t.Fatalf("write %s: %v", ext, err)
		}
	}
}

func TestName(t *testing.T) {
	if got := New().Name(); got != models.ToolKiroCLI {
		t.Fatalf("Name() = %q, want %q", got, models.ToolKiroCLI)
	}
	if models.ToolKiroCLI != "kiro-cli" {
		t.Fatalf("tool constant drift: %q", models.ToolKiroCLI)
	}
}

func TestClassifyLayout(t *testing.T) {
	cases := []struct {
		path string
		want layout
	}{
		{"/home/u/.kiro/sessions/cli/abc.json", layoutFlat},
		{"/home/u/.kiro/sessions/cli/abc.jsonl", layoutFlat},
		{`C:\Users\u\.kiro\sessions\cli\abc.jsonl`, layoutFlat},
		{"/home/u/.kiro/sessions/cli/abc.history", layoutUnknown},
		{"/home/u/.kiro/sessions/cli/abc.lock", layoutUnknown},
		{"/home/u/.local/share/kiro-cli/data.sqlite3", layoutSQLite},
		{"/home/u/.local/share/kiro-cli/data.sqlite3-wal", layoutSQLite},
		{"/home/u/.local/share/kiro-cli/data.sqlite3-shm", layoutSQLite},
		{`C:\Users\u\AppData\Local\Kiro-Cli\data.sqlite3`, layoutSQLite},
		{"/home/u/other/data.sqlite3", layoutUnknown},
		{"/home/u/project/session.json", layoutUnknown},
	}
	for _, tc := range cases {
		if got := classifyLayout(tc.path); got != tc.want {
			t.Errorf("classifyLayout(%q) = %d, want %d", tc.path, got, tc.want)
		}
	}
}

func TestDefaultRootsOSShaped(t *testing.T) {
	withHomes(t, []crossmount.HomeRoot{
		{Path: "/home/dev", OS: crossmount.OSLinux, Origin: "native"},
		{Path: "/mnt/c/Users/win", OS: crossmount.OSWindows, Origin: "wsl-mnt:win"},
	})
	roots := defaultRoots()
	// The session root is the PARENT `.kiro/sessions` — it covers BOTH
	// the CLI's `cli/` flat bundles and the Kiro IDE's
	// `<bucket>/<sid>/` subtree, with no nested duplicate watch.
	want := []string{
		filepath.Clean("/home/dev/.kiro/sessions"),
		filepath.Clean("/home/dev/.local/share/kiro-cli"),
		filepath.Clean("/mnt/c/Users/win/.kiro/sessions"),
		filepath.Clean("/mnt/c/Users/win/AppData/Local/Kiro-Cli"),
	}
	if len(roots) != len(want) {
		t.Fatalf("roots = %v, want %v", roots, want)
	}
	for i := range want {
		if roots[i] != want[i] {
			t.Errorf("roots[%d] = %q, want %q", i, roots[i], want[i])
		}
	}
}

func TestIsSessionFileRootGated(t *testing.T) {
	a := NewWithOptions(nil, "/home/dev/.kiro/sessions/cli", "/home/dev/.local/share/kiro-cli")
	accept := []string{
		"/home/dev/.kiro/sessions/cli/abc.jsonl",
		"/home/dev/.kiro/sessions/cli/abc.json",
		"/home/dev/.local/share/kiro-cli/data.sqlite3",
		"/home/dev/.local/share/kiro-cli/data.sqlite3-wal",
	}
	for _, p := range accept {
		if !a.IsSessionFile(p) {
			t.Errorf("IsSessionFile(%q) = false, want true", p)
		}
	}
	reject := []string{
		"/tmp/foreign/.kiro/sessions/cli/abc.jsonl", // right shape, wrong root
		"/tmp/foreign/kiro-cli/data.sqlite3",
		"/home/dev/.kiro/sessions/cli/abc.history",
		"/home/dev/.kiro/sessions/cli/abc.lock",
	}
	for _, p := range reject {
		if a.IsSessionFile(p) {
			t.Errorf("IsSessionFile(%q) = true, want false", p)
		}
	}
}

func TestParseFlatWithMetadata(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".kiro", "sessions", "cli")
	id := "sess-flat-meta"
	copyFixtureBundle(t, "flat-with-metadata", dir, id)
	a := NewWithOptions(nil, dir)

	res, err := a.ParseSessionFile(context.Background(), filepath.Join(dir, id+".jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// Two tool events (user_prompt + assistant_message), one token event.
	var prompt, asst *models.ToolEvent
	for i := range res.ToolEvents {
		switch res.ToolEvents[i].ActionType {
		case models.ActionUserPrompt:
			prompt = &res.ToolEvents[i]
		case models.ActionAssistantMessage:
			asst = &res.ToolEvents[i]
		}
	}
	if prompt == nil || asst == nil {
		t.Fatalf("want user_prompt + assistant_message, got %+v", res.ToolEvents)
	}
	if prompt.SessionID != id {
		t.Errorf("SessionID = %q, want %q", prompt.SessionID, id)
	}
	if prompt.ProjectRoot != "/home/dev/project" {
		t.Errorf("ProjectRoot = %q, want /home/dev/project", prompt.ProjectRoot)
	}
	if prompt.Model != "auto" {
		t.Errorf("Model = %q, want auto", prompt.Model)
	}
	// Canonical SourceFile is the .jsonl even for events derived via the
	// .json sibling.
	if !strings.HasSuffix(prompt.SourceFile, id+".jsonl") {
		t.Errorf("SourceFile = %q, want *.jsonl", prompt.SourceFile)
	}
	// Scrubbing: the prompt carried a secret; it must be gone.
	if strings.Contains(prompt.Target, "sk-") {
		t.Errorf("prompt Target not scrubbed: %q", prompt.Target)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("want 1 token event, got %d", len(res.TokenEvents))
	}
	te := res.TokenEvents[0]
	if te.InputTokens != 0 || te.OutputTokens != 0 {
		t.Errorf("token counts = %d/%d, want 0/0 (honest zero)", te.InputTokens, te.OutputTokens)
	}
	if te.Reliability != "unreliable" {
		t.Errorf("Reliability = %q, want unreliable", te.Reliability)
	}
	if te.MessageID != "msg-asst-0001" {
		t.Errorf("token MessageID = %q, want msg-asst-0001", te.MessageID)
	}
}

func TestParseFlatLiveShapeNoTokens(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".kiro", "sessions", "cli")
	id := "sess-live"
	copyFixtureBundle(t, "flat-live-shape", dir, id)
	a := NewWithOptions(nil, dir)

	res, err := a.ParseSessionFile(context.Background(), filepath.Join(dir, id+".jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 0 {
		t.Fatalf("bare .json (no user_turn_metadatas) must emit no token events, got %d", len(res.TokenEvents))
	}
	if len(res.ToolEvents) != 2 {
		t.Fatalf("want prompt + assistant, got %d events", len(res.ToolEvents))
	}
}

func TestParseFlatMalformedAdvances(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".kiro", "sessions", "cli")
	id := "sess-bad"
	// The malformed fixture has no .json sibling; only the .jsonl.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "kirocli", "flat-malformed.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".jsonl"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), filepath.Join(dir, id+".jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile must not error on malformed line: %v", err)
	}
	// Two good lines parsed, one warning for the broken line.
	if len(res.ToolEvents) != 2 {
		t.Errorf("want 2 events past the malformed line, got %d", len(res.ToolEvents))
	}
	if len(res.Warnings) == 0 {
		t.Errorf("want a warning for the malformed line")
	}
}

func TestParseFlatJSONAndJSONLAgree(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".kiro", "sessions", "cli")
	id := "sess-agree"
	copyFixtureBundle(t, "flat-with-metadata", dir, id)
	a := NewWithOptions(nil, dir)

	viaJSONL, err := a.ParseSessionFile(context.Background(), filepath.Join(dir, id+".jsonl"), 0)
	if err != nil {
		t.Fatal(err)
	}
	viaJSON, err := a.ParseSessionFile(context.Background(), filepath.Join(dir, id+".json"), 0)
	if err != nil {
		t.Fatal(err)
	}
	// Both triggers emit the same canonical SourceFile + SourceEventIDs,
	// so the store's (source_file, source_event_id) dedup drops the
	// cross-trigger duplicates.
	keys := func(res []models.ToolEvent) []string {
		var out []string
		for _, e := range res {
			out = append(out, e.SourceFile+"|"+e.SourceEventID)
		}
		return out
	}
	a1, a2 := keys(viaJSONL.ToolEvents), keys(viaJSON.ToolEvents)
	if strings.Join(a1, ",") != strings.Join(a2, ",") {
		t.Fatalf("json vs jsonl trigger dedup keys differ:\n jsonl=%v\n json =%v", a1, a2)
	}
	for _, k := range a1 {
		if !strings.Contains(k, id+".jsonl|") {
			t.Errorf("dedup key does not use canonical .jsonl SourceFile: %q", k)
		}
	}
}

func TestReadTranscriptFlat(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".kiro", "sessions", "cli")
	id := "sess-tx"
	copyFixtureBundle(t, "flat-with-metadata", dir, id)
	a := NewWithOptions(nil, dir)
	msgs, err := a.ReadTranscript(context.Background(), models.Session{ID: id}, nil)
	if err != nil {
		t.Fatalf("ReadTranscript: %v", err)
	}
	if len(msgs) < 2 {
		t.Fatalf("want >=2 transcript messages, got %d", len(msgs))
	}
	if msgs[0].Role != models.TranscriptUser {
		t.Errorf("first message role = %v, want user", msgs[0].Role)
	}
	// Secret is scrubbed away by transcriptutil? No — transcript reads
	// raw; but the fixture secret is in the prompt, and handoff capping
	// happens downstream. Assert the READY reply is present.
	found := false
	for _, m := range msgs {
		if strings.Contains(m.Text, "READY") {
			found = true
		}
	}
	if !found {
		t.Errorf("assistant READY text not found in transcript")
	}
}
