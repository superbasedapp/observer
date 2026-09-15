package kirocrew

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// fixtureSlot is the anonymized chat-slot key shared by every fixture
// under testdata/kirocrew/.
const fixtureSlot = "dashboard_chat-2-1700000002"

// fixtureTwinSID is the driven kiro-cli session id the crew/ fixture's
// session_map.json resolves to.
const fixtureTwinSID = "sess0001-0000-4000-8000-000000000001"

func testdataDir(t *testing.T, rel string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata", "kirocrew", rel)
}

// fakeHomes overrides allHomesFunc for the duration of a test, restoring
// the original crossmount.AllHomes on cleanup. Mirrors the pattern used by
// internal/adapter/kirocli/roots_test.go and clinecli's env-root tests.
func fakeHomes(t *testing.T, homes ...crossmount.HomeRoot) {
	t.Helper()
	orig := allHomesFunc
	allHomesFunc = func() []crossmount.HomeRoot { return homes }
	t.Cleanup(func() { allHomesFunc = orig })
}

// --- roots -----------------------------------------------------------

func TestDefaultRoots_EnvOverrideFirst(t *testing.T) {
	fakeHomes(t, crossmount.HomeRoot{Path: filepath.Join("home", "other"), OS: "linux", Origin: "native"})

	custom := t.TempDir()
	t.Setenv(kirocrewHomeEnv, custom)

	roots := defaultRoots()
	if len(roots) == 0 {
		t.Fatalf("defaultRoots() returned no roots")
	}
	wantFirst := filepath.Clean(filepath.Join(custom, sessionsDir))
	if roots[0] != wantFirst {
		t.Errorf("roots[0] = %q, want env-derived root %q first", roots[0], wantFirst)
	}
}

func TestDefaultRoots_EnvOverrideIsMadeAbsolute(t *testing.T) {
	fakeHomes(t) // no crossmount homes
	t.Setenv(kirocrewHomeEnv, "relative-kirocrew-home")

	roots := defaultRoots()
	if len(roots) != 1 {
		t.Fatalf("defaultRoots() = %v, want exactly one env-derived root", roots)
	}
	if !filepath.IsAbs(roots[0]) {
		t.Errorf("roots[0] = %q, want an absolute path", roots[0])
	}
	if filepath.Base(roots[0]) != sessionsDir {
		t.Errorf("roots[0] = %q, want it to end in %q", roots[0], sessionsDir)
	}
}

// TestDefaultRoots_RealLayout pins the CORRECTION this commit makes: the
// watched directory is `<home>/.kiro/crew/sessions`, not the
// `<home>/.kiro/crew/conversations` the pre-grounding skeleton assumed
// from the vendor README. That directory does not exist on a live
// install.
func TestDefaultRoots_RealLayout(t *testing.T) {
	t.Setenv(kirocrewHomeEnv, "")
	home := filepath.Join("Users", "alice")
	fakeHomes(t, crossmount.HomeRoot{Path: home, OS: "windows", Origin: "native"})

	roots := defaultRoots()
	want := filepath.Clean(filepath.Join(home, ".kiro", "crew", "sessions"))
	if len(roots) != 1 || roots[0] != want {
		t.Fatalf("defaultRoots() = %v, want [%q]", roots, want)
	}
	for _, r := range roots {
		if strings.Contains(r, "conversations") {
			t.Errorf("root %q still points at the ungrounded conversations/ dir", r)
		}
	}
}

func TestDefaultRoots_PerHomeDedup(t *testing.T) {
	t.Setenv(kirocrewHomeEnv, "")
	home := filepath.Join("Users", "alice")
	fakeHomes(t,
		crossmount.HomeRoot{Path: home, OS: "windows", Origin: "native"},
		crossmount.HomeRoot{Path: home, OS: "windows", Origin: "crossmount"},
	)
	if roots := defaultRoots(); len(roots) != 1 {
		t.Errorf("defaultRoots() = %v, want one deduped root", roots)
	}
}

// TestRootsDoNotCollideWithKiroCLI pins the sibling-path property the
// package doc relies on: `<home>/.kiro/crew/sessions` and kiro-cli's
// `<home>/.kiro/sessions` are neither a prefix of the other, so
// adapter.UnderAnyWatchRoot can never cross-claim.
func TestRootsDoNotCollideWithKiroCLI(t *testing.T) {
	home := filepath.Join("Users", "alice")
	crew := filepath.Join(home, ".kiro", "crew", "sessions")
	cli := filepath.Join(home, ".kiro", "sessions")
	if strings.HasPrefix(crew, cli+string(filepath.Separator)) {
		t.Errorf("crew root %q is nested under the kiro-cli root %q", crew, cli)
	}
	if strings.HasPrefix(cli, crew+string(filepath.Separator)) {
		t.Errorf("kiro-cli root %q is nested under the crew root %q", cli, crew)
	}
}

// --- IsSessionFile ---------------------------------------------------

func TestIsSessionFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".kiro", "crew", "sessions")
	a := NewWithOptions(nil, root)

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"grounded dashboard chat", filepath.Join(root, fixtureSlot+".jsonl"), true},
		{"other source thread", filepath.Join(root, "slack_C123-1700000003.jsonl"), true},
		{"the .lock sibling", filepath.Join(root, fixtureSlot+".jsonl.lock"), false},
		{"a .json in the same dir", filepath.Join(root, "state.json"), false},
		{"nested one level down", filepath.Join(root, "archive", fixtureSlot+".jsonl"), false},
		{"security_events.jsonl at the crew root", filepath.Join(root, "..", "security_events.jsonl"), false},
		{"right shape, outside the watch root", filepath.Join(t.TempDir(), "sessions", fixtureSlot+".jsonl"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Errorf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestCursorSemanticsForIsNoActions(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".kiro", "crew", "sessions")
	a := NewWithOptions(nil, root)
	got := a.CursorSemanticsFor(filepath.Join(root, fixtureSlot+".jsonl"))
	if got.Kind != adapter.CursorNoActions {
		t.Errorf("CursorSemanticsFor kind = %v, want CursorNoActions", got.Kind)
	}
	if got.Detail == "" {
		t.Error("CursorNoActions declared with no Detail")
	}
	// A path this adapter does not claim gets the zero value.
	if got := a.CursorSemanticsFor(filepath.Join(root, "x.json")); got.Kind != adapter.CursorByteOffset {
		t.Errorf("unclaimed path kind = %v, want the zero value", got.Kind)
	}
}

// --- session-map / ownership -----------------------------------------

func TestMapKeyForFile(t *testing.T) {
	cases := []struct{ path, want string }{
		{filepath.Join("s", "dashboard_chat-2-1700000002.jsonl"), "dashboard:chat-2-1700000002"},
		{filepath.Join("s", "slack_C123-1.jsonl"), "slack:C123-1"},
		{filepath.Join("s", "noseparator.jsonl"), ""},
		{filepath.Join("s", "_leading.jsonl"), ""},
		{filepath.Join("s", "trailing_.jsonl"), ""},
	}
	for _, tc := range cases {
		if got := mapKeyForFile(tc.path); got != tc.want {
			t.Errorf("mapKeyForFile(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestResolveOwnership(t *testing.T) {
	cases := []struct {
		name    string
		dir     string
		wantOwn ownership
		wantSID string
	}{
		{"twin resolvable", "crew", ownedByKiroCLI, fixtureTwinSID},
		{"map present, key absent", "crew-no-twin", ownedBySelf, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := testdataDir(t, filepath.Join(tc.dir, "sessions", fixtureSlot+".jsonl"))
			own, sid := resolveOwnership(path)
			if own != tc.wantOwn || sid != tc.wantSID {
				t.Errorf("resolveOwnership = (%v, %q), want (%v, %q)", own, sid, tc.wantOwn, tc.wantSID)
			}
		})
	}

	t.Run("no session_map at all", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "sessions")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, fixtureSlot+".jsonl")
		if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if own, _ := resolveOwnership(p); own != ownershipUnresolved {
			t.Errorf("resolveOwnership with no map = %v, want ownershipUnresolved", own)
		}
	})
}

// --- parser ----------------------------------------------------------

func loadFixtureConversation(t *testing.T) conversation {
	t.Helper()
	body, err := os.ReadFile(testdataDir(t, filepath.Join("crew", "sessions", fixtureSlot+".jsonl")))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return parseConversation(body)
}

// TestParseConversation_RealFixture pins what the parser reads off the
// anonymized live capture: 1 user prompt, 5 assistant messages and 9
// UNIQUE tool calls merged from 17 tool lines.
func TestParseConversation_RealFixture(t *testing.T) {
	c := loadFixtureConversation(t)

	if c.meta.Title != "Hello World Python Project" {
		t.Errorf("title = %q", c.meta.Title)
	}
	if c.meta.Model != "" {
		t.Errorf("model = %q, want the empty string Crew actually writes", c.meta.Model)
	}
	if c.meta.MemoryMode != "persistent" {
		t.Errorf("memory_mode = %q", c.meta.MemoryMode)
	}
	if c.meta.Project == "" {
		t.Error("project is empty; it is the only project-root source")
	}
	if len(c.warnings) != 0 {
		t.Errorf("warnings = %v, want none on a clean fixture", c.warnings)
	}

	counts := map[string]int{}
	for _, e := range c.events {
		counts[e.kind]++
	}
	want := map[string]int{"user": 1, "assistant": 5, "tool": 9}
	for k, n := range want {
		if counts[k] != n {
			t.Errorf("%s events = %d, want %d", k, counts[k], n)
		}
	}
}

// TestParseConversation_ToolPairMerge pins mergeToolLines' grounded rules
// on the one case that exercises every branch: an `edit` whose CALL half
// carries a unified diff and whose COMPLETION half carries the structured
// JSON arguments.
func TestParseConversation_ToolPairMerge(t *testing.T) {
	c := loadFixtureConversation(t)

	var creates, edits, executes, reads int
	for _, e := range c.events {
		if e.kind != "tool" {
			continue
		}
		if e.tool.kind == "" {
			t.Errorf("tool %s merged with an empty kind (the completion half won)", e.tool.id)
		}
		if !e.tool.done {
			t.Errorf("tool %s not marked done", e.tool.id)
		}
		action, target, contentBytes := resolveTool(e.tool)
		switch action {
		case models.ActionReadFile:
			reads++
		case models.ActionWriteFile:
			creates++
			if contentBytes == 0 {
				t.Errorf("write %s reported 0 content bytes", e.tool.id)
			}
		case models.ActionEditFile:
			edits++
		case models.ActionRunCommand:
			executes++
		default:
			t.Errorf("tool %s resolved to %q", e.tool.id, action)
		}
		if target == "" {
			t.Errorf("tool %s (%s) resolved to an empty target", e.tool.id, action)
		}
	}
	// 1 read, 1 create (Crew's lossy `edit` label + command=create),
	// 1 str-replace edit, 6 shell executes.
	if reads != 1 || creates != 1 || edits != 1 || executes != 6 {
		t.Errorf("read=%d create=%d edit=%d execute=%d, want 1/1/1/6", reads, creates, edits, executes)
	}
}

// TestParseConversation_TurnStatsDuration pins the one measured number
// the Crew transcript carries: elapsed_ms on the assistant line that
// closed the turn. Credits are decoded and deliberately dropped.
func TestParseConversation_TurnStatsDuration(t *testing.T) {
	c := loadFixtureConversation(t)
	var withDuration int
	for _, e := range c.events {
		if e.kind == "assistant" && e.durationMs > 0 {
			withDuration++
		}
	}
	if withDuration != 1 {
		t.Errorf("assistant messages carrying a duration = %d, want exactly 1 (the turn's last)", withDuration)
	}
}

func TestParseConversation_RejectsNonMetadataHeader(t *testing.T) {
	c := parseConversation([]byte(`{"role":"user","content":"hi"}` + "\n"))
	if len(c.events) != 0 {
		t.Errorf("events = %d, want 0 when line 1 is not a metadata header", len(c.events))
	}
	if len(c.warnings) != 1 {
		t.Errorf("warnings = %v, want exactly one", c.warnings)
	}
}

func TestParseConversation_UnknownKindIsHonest(t *testing.T) {
	rec := toolRecord{id: "tooluse_x", kind: "teleport", input: "{}"}
	action, target, _ := resolveTool(rec)
	if action != models.ActionUnknown || target != "" {
		t.Errorf("resolveTool(unknown kind) = (%q, %q), want (unknown, \"\")", action, target)
	}
}

// --- ParseSessionFile: the ownership branches -------------------------

// TestParseSessionFile_TwinSuppresses is the DOUBLE-COUNT rule's own pin:
// a Crew chat whose session_map resolves a kiro-cli twin emits NOTHING.
func TestParseSessionFile_TwinSuppresses(t *testing.T) {
	root := testdataDir(t, filepath.Join("crew", "sessions"))
	a := NewWithOptions(nil, root)
	path := filepath.Join(root, fixtureSlot+".jsonl")

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 || len(res.SessionSurfaces) != 0 {
		t.Errorf("emitted %d events / %d tokens / %d surfaces, want 0/0/0 — kiro-cli owns this conversation",
			len(res.ToolEvents), len(res.TokenEvents), len(res.SessionSurfaces))
	}
	if res.NewOffset == 0 {
		t.Error("NewOffset not advanced to the file size")
	}
	var named bool
	for _, w := range res.Warnings {
		if strings.Contains(w, fixtureTwinSID) {
			named = true
		}
	}
	if !named {
		t.Errorf("warnings %v do not name the owning kiro-cli session", res.Warnings)
	}
}

// TestParseSessionFile_NoTwinEmits pins the other branch: a Crew chat the
// session_map does NOT resolve is the only record of its conversation, so
// the full transcript is emitted.
func TestParseSessionFile_NoTwinEmits(t *testing.T) {
	root := testdataDir(t, filepath.Join("crew-no-twin", "sessions"))
	a := NewWithOptions(nil, root)
	path := filepath.Join(root, fixtureSlot+".jsonl")

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 15 {
		t.Fatalf("ToolEvents = %d, want 15 (1 prompt + 5 assistant + 9 tools)", len(res.ToolEvents))
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("TokenEvents = %d, want 0 — the Crew transcript carries no usage data", len(res.TokenEvents))
	}

	byType := map[string]int{}
	ids := map[string]int{}
	for _, e := range res.ToolEvents {
		byType[e.ActionType]++
		ids[e.SourceEventID]++
		if e.Tool != models.ToolKiroCrew {
			t.Errorf("event tool = %q, want %q", e.Tool, models.ToolKiroCrew)
		}
		if e.SessionID != fixtureSlot {
			t.Errorf("event session = %q, want %q", e.SessionID, fixtureSlot)
		}
		if e.Model != "" {
			t.Errorf("event model = %q, want empty (Crew writes none)", e.Model)
		}
	}
	want := map[string]int{
		models.ActionUserPrompt:       1,
		models.ActionAssistantMessage: 5,
		models.ActionReadFile:         1,
		models.ActionWriteFile:        1,
		models.ActionEditFile:         1,
		models.ActionRunCommand:       6,
	}
	for k, n := range want {
		if byType[k] != n {
			t.Errorf("action %s = %d, want %d", k, byType[k], n)
		}
	}
	for id, n := range ids {
		if n != 1 {
			t.Errorf("SourceEventID %q emitted %d times, want 1", id, n)
		}
	}

	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("SessionSurfaces = %d, want 1", len(res.SessionSurfaces))
	}
	s := res.SessionSurfaces[0]
	if s.Surface != models.SurfaceDesktop || s.SurfaceHost != surfaceHost || s.SessionID != fixtureSlot {
		t.Errorf("surface = %+v, want desktop/%s on %s", s, surfaceHost, fixtureSlot)
	}
}

// TestParseSessionFile_Idempotent pins that a full re-read produces the
// identical event set — the property the file-size cursor relies on.
func TestParseSessionFile_Idempotent(t *testing.T) {
	root := testdataDir(t, filepath.Join("crew-no-twin", "sessions"))
	a := NewWithOptions(nil, root)
	path := filepath.Join(root, fixtureSlot+".jsonl")

	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.ParseSessionFile(context.Background(), path, first.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.ToolEvents) != len(second.ToolEvents) {
		t.Fatalf("re-parse emitted %d events, first pass %d", len(second.ToolEvents), len(first.ToolEvents))
	}
	for i := range first.ToolEvents {
		if first.ToolEvents[i].SourceEventID != second.ToolEvents[i].SourceEventID {
			t.Errorf("event %d id drifted: %q -> %q", i,
				first.ToolEvents[i].SourceEventID, second.ToolEvents[i].SourceEventID)
		}
	}
}

func TestName(t *testing.T) {
	if got := New().Name(); got != models.ToolKiroCrew {
		t.Errorf("Name() = %q, want %q", got, models.ToolKiroCrew)
	}
	if ToolName != models.ToolKiroCrew {
		t.Errorf("ToolName = %q, want %q", ToolName, models.ToolKiroCrew)
	}
}
