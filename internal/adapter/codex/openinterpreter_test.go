package codex

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// oiFixtureDir returns the directory holding the live-captured Open
// Interpreter rollout fixture (testdata/openinterpreter/sessions/
// 2026/07/17/), and oiFixturePath the file itself.
func oiFixtureDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata", "openinterpreter", "sessions", "2026", "07", "17")
}

func oiFixturePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(oiFixtureDir(t), "rollout-2026-07-17T14-59-49-019f6f69-23a0-7e32-bdba-9a9fabc946be.jsonl")
}

// TestOpenInterpreterName pins the retagged tool identity.
func TestOpenInterpreterName(t *testing.T) {
	t.Parallel()
	a := NewOpenInterpreter()
	if got := a.Name(); got != models.ToolOpenInterpreter {
		t.Errorf("Name() = %q, want %q", got, models.ToolOpenInterpreter)
	}
	if got := a.Name(); got == models.ToolCodex {
		t.Errorf("Name() = %q, must NOT collapse to the base codex identity", got)
	}
}

// isOIDesktopRoot reports whether p is one of the desktop app's
// embedded codex-home sessions roots (any of the three OS rungs).
func isOIDesktopRoot(p string) bool {
	tail := filepath.Join(interpreterDesktopAppDir, "codex-home", "sessions")
	return strings.HasSuffix(p, tail)
}

// TestOpenInterpreterWatchPathsDefaultRoots confirms platform-default
// discovery expands to ".openinterpreter/sessions" (the CLI store) AND
// the desktop app's embedded codex-home under every cross-mount-
// resolved $HOME — and never to ".codex/sessions".
func TestOpenInterpreterWatchPathsDefaultRoots(t *testing.T) {
	t.Parallel()
	a := NewOpenInterpreter()
	paths := a.WatchPaths()
	if len(paths) == 0 {
		t.Fatal("WatchPaths() returned no roots")
	}
	var cli, desktop int
	for _, p := range paths {
		switch {
		case strings.HasSuffix(p, filepath.Join(".openinterpreter", "sessions")):
			cli++
		case isOIDesktopRoot(p):
			desktop++
		default:
			t.Errorf("root %q is neither the CLI store nor the desktop codex-home", p)
		}
		if strings.HasSuffix(p, filepath.Join(".codex", "sessions")) {
			t.Errorf("root %q leaked the codex path shape", p)
		}
	}
	if cli == 0 {
		t.Error("no .openinterpreter/sessions CLI root emitted")
	}
	if desktop == 0 {
		t.Errorf("no desktop codex-home root emitted; got %v", paths)
	}
}

// TestOpenInterpreterDesktopRootLadder pins the per-OS Electron
// userData ladder against a synthetic HomeRoot for each OS — the two
// UNVERIFIED rungs (darwin/linux) included, so a future re-grounding
// that changes them is a loud test edit rather than a silent drift.
func TestOpenInterpreterDesktopRootLadder(t *testing.T) {
	t.Parallel()
	a := NewOpenInterpreter()
	tests := []struct {
		name string
		home crossmount.HomeRoot
		want string
	}{
		{
			name: "windows_crossmount", // GROUNDED shape
			home: crossmount.HomeRoot{Path: "/mnt/c/Users/u", OS: crossmount.OSWindows, Origin: "wsl-mnt:u"},
			want: filepath.Join("/mnt/c/Users/u", "AppData", "Roaming", "interpreter", "codex-home", "sessions"),
		},
		{
			name: "darwin_unverified",
			home: crossmount.HomeRoot{Path: "/Users/u", OS: crossmount.OSDarwin, Origin: "native"},
			want: filepath.Join("/Users/u", "Library", "Application Support", "interpreter", "codex-home", "sessions"),
		},
		{
			name: "linux_unverified",
			home: crossmount.HomeRoot{Path: "/home/u", OS: crossmount.OSLinux, Origin: "native"},
			want: filepath.Join("/home/u", ".config", "interpreter", "codex-home", "sessions"),
		},
		{
			name: "unknown_os_yields_nothing",
			home: crossmount.HomeRoot{Path: "/x", OS: "plan9", Origin: "native"},
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := a.desktopStoreRoots(tc.home)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("desktopStoreRoots = %v; want none", got)
				}
				return
			}
			if len(got) != 1 || got[0] != tc.want {
				t.Errorf("desktopStoreRoots = %v; want [%s]", got, tc.want)
			}
		})
	}
}

// TestCodexProperHasNoDesktopRoots is the §2.1(d) other branch for the
// desktop widening: codex proper declares no desktop app, so it grows
// no codex-home root.
func TestCodexProperHasNoDesktopRoots(t *testing.T) {
	t.Parallel()
	c := New()
	if got := c.desktopStoreRoots(crossmount.HomeRoot{Path: "/home/u", OS: crossmount.OSLinux}); len(got) != 0 {
		t.Fatalf("codex proper grew desktop roots: %v", got)
	}
	for _, p := range c.WatchPaths() {
		if isOIDesktopRoot(p) {
			t.Errorf("codex WatchPaths leaked a desktop codex-home root: %q", p)
		}
	}
}

// TestOpenInterpreterWatchPathsDeduped pins that a home reachable
// twice (the same directory listed under two spellings) contributes
// one root — WatchPaths runs adapter.DedupRootsByIdentity.
func TestOpenInterpreterWatchPathsDeduped(t *testing.T) {
	t.Parallel()
	paths := NewOpenInterpreter().WatchPaths()
	seen := map[string]struct{}{}
	for _, p := range paths {
		if _, dup := seen[p]; dup {
			t.Errorf("duplicate root %q in %v", p, paths)
		}
		seen[p] = struct{}{}
	}
}

// TestOpenInterpreterWatchPathsHonorsInterpreterHome mirrors
// TestWatchPathsHonorsCodexHome for the variant's own env var — with
// the documented carve-out that the env var relocates the CLI's own
// home ONLY. The desktop app's embedded codex-home is a different
// product's store at a fixed platform convention, so it survives the
// override rather than silently zeroing desktop capture.
func TestOpenInterpreterWatchPathsHonorsInterpreterHome(t *testing.T) {
	t.Setenv("INTERPRETER_HOME", "/custom/openinterpreter")
	a := NewOpenInterpreter()
	paths := a.WatchPaths()
	want := filepath.Join("/custom/openinterpreter", "sessions")
	if len(paths) == 0 || paths[0] != want {
		t.Fatalf("INTERPRETER_HOME not honored: %v", paths)
	}
	for _, p := range paths[1:] {
		if !isOIDesktopRoot(p) {
			t.Errorf("root %q survived the env override but is not a desktop codex-home root", p)
		}
	}
	// The per-home CLI roots ARE suppressed by the override.
	for _, p := range paths {
		if strings.HasSuffix(p, filepath.Join(".openinterpreter", "sessions")) && p != want {
			t.Errorf("env override did not suppress the per-home CLI root %q", p)
		}
	}
}

// TestCodexWatchPathsHonorsCodexHomeStaysSingle pins that the
// env-override carve-out above did NOT leak into codex proper: with no
// desktop app declared, $CODEX_HOME still collapses to exactly one
// root.
func TestCodexWatchPathsHonorsCodexHomeStaysSingle(t *testing.T) {
	t.Setenv("CODEX_HOME", "/custom/codex")
	paths := New().WatchPaths()
	want := filepath.Join("/custom/codex", "sessions")
	if len(paths) != 1 || paths[0] != want {
		t.Errorf("CODEX_HOME root set = %v; want exactly [%s]", paths, want)
	}
}

// TestOpenInterpreterCoexistsWithCodex is the checklist §2.1(d) guard:
// asserts BOTH branches — a fresh codex.New() instance is completely
// unaffected by the existence of the Open Interpreter variant (no
// shared mutable state, no accidental retag), and IsSessionFile /
// WatchPaths stay scoped to each instance's own roots.
func TestOpenInterpreterCoexistsWithCodex(t *testing.T) {
	t.Parallel()
	c := New()
	oi := NewOpenInterpreter()

	if got := c.Name(); got != models.ToolCodex {
		t.Errorf("codex.New().Name() = %q, want %q (must not be retagged)", got, models.ToolCodex)
	}
	if got := oi.Name(); got != models.ToolOpenInterpreter {
		t.Errorf("NewOpenInterpreter().Name() = %q, want %q", got, models.ToolOpenInterpreter)
	}

	for _, p := range c.WatchPaths() {
		if strings.HasSuffix(p, filepath.Join(".openinterpreter", "sessions")) {
			t.Errorf("codex WatchPaths leaked an .openinterpreter root: %q", p)
		}
	}
	for _, p := range oi.WatchPaths() {
		if strings.HasSuffix(p, filepath.Join(".codex", "sessions")) {
			t.Errorf("open-interpreter WatchPaths leaked a .codex root: %q", p)
		}
	}

	// A codex rollout file under the OI instance's own watch root is
	// still recognized (identical filename shape) — only the root
	// discriminates which instance owns a given file in the real
	// watcher dispatch, not the adapter's IsSessionFile predicate
	// shape itself.
	dir := t.TempDir()
	oiScoped := NewOpenInterpreterWithOptions(nil, dir)
	if !oiScoped.IsSessionFile(filepath.Join(dir, "rollout-2026-04-16-abc.jsonl")) {
		t.Error("rollout-*.jsonl under the OI instance's own watch root should match")
	}
}

// oiDesktopFixtureDir / oiDesktopFixturePath locate the anonymized
// live-captured Interpreter DESKTOP rollout (testdata/openinterpreter/
// desktop/codex-home/sessions/2026/09/03/), which mirrors the on-disk
// shape of %APPDATA%\interpreter\codex-home\sessions.
func oiDesktopFixtureDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata", "openinterpreter", "desktop",
		"codex-home", "sessions", "2026", "09", "03")
}

func oiDesktopFixturePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(oiDesktopFixtureDir(t),
		"rollout-2026-09-03T16-57-59-01a0aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee.jsonl")
}

// TestOpenInterpreterSurfaceVocabulary is the §2.1(d) BOTH-branches
// guard for the variant surface table: the Open Interpreter instance
// stamps the desktop app's originator desktop/"open-interpreter",
// while codex proper leaves the same token unmapped (no stamp when
// `source` cannot resolve it either).
func TestOpenInterpreterSurfaceVocabulary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		vocab      surfaceVocabulary
		source     string
		originator string
		wantKind   string
		wantHost   string
		wantOK     bool
	}{
		{
			name: "oi_desktop_grounded_pair", vocab: openInterpreterSurface,
			source: "vscode", originator: "codex_ui",
			wantKind: models.SurfaceDesktop, wantHost: models.ToolOpenInterpreter, wantOK: true,
		},
		{
			// The overlay is originator-keyed, so it holds even if a
			// future desktop build drops the inherited source leftover.
			name: "oi_desktop_no_source", vocab: openInterpreterSurface,
			source: "", originator: "codex_ui",
			wantKind: models.SurfaceDesktop, wantHost: models.ToolOpenInterpreter, wantOK: true,
		},
		{
			// GAP: the CLI rebuild's own originator is not grounded, so
			// the variant falls through to the shared codex vocabulary.
			name: "oi_cli_falls_through_to_codex_vocab", vocab: openInterpreterSurface,
			source: "cli", originator: "codex_cli_rs",
			wantKind: models.SurfaceCLI, wantHost: "codex-cli", wantOK: true,
		},
		{
			name: "codex_proper_leaves_codex_ui_unmapped", vocab: surfaceVocabulary{},
			source: "", originator: "codex_ui",
			wantKind: "", wantHost: "", wantOK: false,
		},
		{
			// Honesty note: on codex proper a KNOWN source still
			// resolves on its own, so the pair is stamped from `source`
			// — codex_ui contributes nothing either way.
			name: "codex_proper_codex_ui_with_known_source", vocab: surfaceVocabulary{},
			source: "vscode", originator: "codex_ui",
			wantKind: models.SurfaceIDE, wantHost: "vscode", wantOK: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			kind, host, ok := tc.vocab.resolve(tc.source, tc.originator)
			if ok != tc.wantOK || kind != tc.wantKind || host != tc.wantHost {
				t.Errorf("resolve(%q, %q) = (%q, %q, %v); want (%q, %q, %v)",
					tc.source, tc.originator, kind, host, ok, tc.wantKind, tc.wantHost, tc.wantOK)
			}
		})
	}
}

// TestOpenInterpreterIsSessionFileMatrix pins the predicate's root
// discrimination across BOTH OI roots and the codex-proper root: the
// desktop codex-home is claimed by the OI instance and never by codex
// proper, and vice versa for ~/.codex.
func TestOpenInterpreterIsSessionFileMatrix(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	oi := NewOpenInterpreter()
	cx := New()

	oiRoots := oi.WatchPaths()
	cxRoots := cx.WatchPaths()

	// Root disjointness: no OI root is a codex root or vice versa.
	for _, o := range oiRoots {
		for _, c := range cxRoots {
			if strings.EqualFold(filepath.Clean(o), filepath.Clean(c)) {
				t.Errorf("root overlap between open-interpreter and codex: %q", o)
			}
		}
	}

	rollout := "rollout-2026-09-03T16-57-59-01a0aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee.jsonl"
	for _, r := range oiRoots {
		p := filepath.Join(r, "2026", "09", "03", rollout)
		if !oi.IsSessionFile(p) {
			t.Errorf("open-interpreter IsSessionFile(%q) = false; want true", p)
		}
		if cx.IsSessionFile(p) {
			t.Errorf("codex claimed an open-interpreter rollout: %q", p)
		}
	}
	for _, r := range cxRoots {
		p := filepath.Join(r, "2026", "09", "03", rollout)
		if !cx.IsSessionFile(p) {
			t.Errorf("codex IsSessionFile(%q) = false; want true", p)
		}
		if oi.IsSessionFile(p) {
			t.Errorf("open-interpreter claimed a codex rollout: %q", p)
		}
	}

	// Non-rollout names under an owned root are still rejected.
	if len(oiRoots) > 0 {
		if oi.IsSessionFile(filepath.Join(oiRoots[0], "state_5.sqlite")) {
			t.Error("non-rollout file under an OI root must not match")
		}
		if oi.IsSessionFile(filepath.Join(oiRoots[0], "rollout-x.json")) {
			t.Error("rollout-*.json (wrong extension) must not match")
		}
	}
}

// TestOpenInterpreterParsesDesktopFixtureEndToEnd parses the
// anonymized DESKTOP rollout and asserts the whole capture contract
// for that surface: every row retagged open-interpreter, the model
// resolved from turn_context (the desktop session_meta carries NO
// model field — only model_provider), gross→net token math, and the
// desktop capture-surface stamp.
func TestOpenInterpreterParsesDesktopFixtureEndToEnd(t *testing.T) {
	t.Parallel()
	dir := oiDesktopFixtureDir(t)
	path := oiDesktopFixturePath(t)
	a := NewOpenInterpreterWithOptions(nil, dir)

	if !a.IsSessionFile(path) {
		t.Fatalf("IsSessionFile(%q) = false, want true", path)
	}

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	const wantSession = "01a0aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee"
	const wantModel = "nvidia/nemotron-3-super-120b-a12b:free"

	if len(res.ToolEvents) == 0 {
		t.Fatal("no ToolEvents parsed from the desktop fixture")
	}
	for i, e := range res.ToolEvents {
		if e.Tool != models.ToolOpenInterpreter {
			t.Errorf("ToolEvents[%d].Tool = %q, want %q", i, e.Tool, models.ToolOpenInterpreter)
		}
		if e.SessionID != wantSession {
			t.Errorf("ToolEvents[%d].SessionID = %q, want %q", i, e.SessionID, wantSession)
		}
		if e.ProjectRoot == "" {
			t.Errorf("ToolEvents[%d].ProjectRoot empty; want the session cwd", i)
		}
	}

	if len(res.TokenEvents) == 0 {
		t.Fatal("no TokenEvents parsed from the desktop fixture")
	}
	for i, e := range res.TokenEvents {
		if e.Tool != models.ToolOpenInterpreter {
			t.Errorf("TokenEvents[%d].Tool = %q, want %q", i, e.Tool, models.ToolOpenInterpreter)
		}
		if e.Model != wantModel {
			t.Errorf("TokenEvents[%d].Model = %q, want %q (resolved from turn_context, not session_meta)",
				i, e.Model, wantModel)
		}
		if e.Source != models.TokenSourceJSONL {
			t.Errorf("TokenEvents[%d].Source = %q, want %q (Tier 2)", i, e.Source, models.TokenSourceJSONL)
		}
		if e.InputTokens < 0 || e.OutputTokens < 0 {
			t.Errorf("TokenEvents[%d] negative net tokens: %+v", i, e)
		}
	}
	// First graded turn: last_token_usage input=32361 cached=0
	// output=245 reasoning=220 → net input 32361, net output 25.
	first := res.TokenEvents[0]
	if first.InputTokens != 32361 || first.CacheReadTokens != 0 {
		t.Errorf("TokenEvents[0] input/cached = %d/%d; want 32361/0", first.InputTokens, first.CacheReadTokens)
	}
	if first.OutputTokens != 245-220 || first.ReasoningTokens != 220 {
		t.Errorf("TokenEvents[0] output/reasoning = %d/%d; want %d/220",
			first.OutputTokens, first.ReasoningTokens, 245-220)
	}

	// Capture surface: desktop / open-interpreter, from the variant
	// overlay (the fixture's session_meta says source:"vscode").
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("SessionSurfaces = %+v; want exactly 1", res.SessionSurfaces)
	}
	got := res.SessionSurfaces[0]
	if got.SessionID != wantSession || got.Surface != models.SurfaceDesktop ||
		got.SurfaceHost != models.ToolOpenInterpreter {
		t.Errorf("surface = %+v; want {%s %s %s}", got, wantSession,
			models.SurfaceDesktop, models.ToolOpenInterpreter)
	}
}

// TestCodexProperOnTheDesktopFixtureStampsVSCode is the contrasting
// branch: the SAME bytes parsed by codex proper get the codex-proper
// vocabulary (source-derived ide/vscode) and the codex tool tag — the
// variant, not the file content, is what makes it a desktop
// open-interpreter session.
func TestCodexProperOnTheDesktopFixtureStampsVSCode(t *testing.T) {
	t.Parallel()
	dir := oiDesktopFixtureDir(t)
	res, err := NewWithOptions(nil, dir).ParseSessionFile(context.Background(), oiDesktopFixturePath(t), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("SessionSurfaces = %+v; want exactly 1", res.SessionSurfaces)
	}
	if got := res.SessionSurfaces[0]; got.Surface != models.SurfaceIDE || got.SurfaceHost != "vscode" {
		t.Errorf("codex-proper surface = %+v; want ide/vscode", got)
	}
	for i, e := range res.ToolEvents {
		if e.Tool != models.ToolCodex {
			t.Errorf("ToolEvents[%d].Tool = %q, want %q", i, e.Tool, models.ToolCodex)
		}
	}
}

// TestOpenInterpreterParsesRealFixtureEndToEnd parses the live-
// captured rollout fixture and asserts: every emitted ToolEvent/
// TokenEvent is retagged models.ToolOpenInterpreter, the gross→net
// token math nets the cached portion out of input exactly as codex's
// shared parser already does, the model string round-trips
// (gpt-5.6-sol), and cwd/project-root resolution succeeds (this
// fixture's cwd happens to be this very repo's path, so ProjectRoot
// must be non-empty — see resolveProjectRoot's git.Resolve-or-
// fallback-to-cwd contract).
func TestOpenInterpreterParsesRealFixtureEndToEnd(t *testing.T) {
	t.Parallel()
	dir := oiFixtureDir(t)
	path := oiFixturePath(t)
	a := NewOpenInterpreterWithOptions(nil, dir)

	if !a.IsSessionFile(path) {
		t.Fatalf("IsSessionFile(%q) = false, want true", path)
	}

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	if len(res.ToolEvents) == 0 {
		t.Fatal("no ToolEvents parsed from fixture")
	}
	if len(res.TokenEvents) != 2 {
		t.Fatalf("TokenEvents count = %d, want 2 (fixture has two token_count events)", len(res.TokenEvents))
	}

	for i, e := range res.ToolEvents {
		if e.Tool != models.ToolOpenInterpreter {
			t.Errorf("ToolEvents[%d].Tool = %q, want %q", i, e.Tool, models.ToolOpenInterpreter)
		}
		if e.SessionID != "019f6f69-23a0-7e32-bdba-9a9fabc946be" {
			t.Errorf("ToolEvents[%d].SessionID = %q, want the fixture's session id", i, e.SessionID)
		}
		if e.ProjectRoot == "" {
			t.Errorf("ToolEvents[%d].ProjectRoot empty; want cwd (or its resolved git root)", i)
		}
	}

	// Fixture token_count events (last_token_usage, the modern
	// v1.7.24+ per-inference-delta path — see parseModernTokenCount):
	//   turn 1: input=14278 cached=9984 output=39  reasoning=0
	//   turn 2: input=14551 cached=14080 output=176 reasoning=0
	// netInput = input - cached; netOutput = output - reasoning.
	wantTokens := []struct {
		net, out, cached, reasoning int64
	}{
		{net: 14278 - 9984, out: 39, cached: 9984, reasoning: 0},
		{net: 14551 - 14080, out: 176, cached: 14080, reasoning: 0},
	}
	for i, e := range res.TokenEvents {
		if e.Tool != models.ToolOpenInterpreter {
			t.Errorf("TokenEvents[%d].Tool = %q, want %q", i, e.Tool, models.ToolOpenInterpreter)
		}
		if e.Model != "gpt-5.6-sol" {
			t.Errorf("TokenEvents[%d].Model = %q, want %q", i, e.Model, "gpt-5.6-sol")
		}
		w := wantTokens[i]
		if e.InputTokens != w.net {
			t.Errorf("TokenEvents[%d].InputTokens = %d, want %d (gross-cached net)", i, e.InputTokens, w.net)
		}
		if e.OutputTokens != w.out {
			t.Errorf("TokenEvents[%d].OutputTokens = %d, want %d", i, e.OutputTokens, w.out)
		}
		if e.CacheReadTokens != w.cached {
			t.Errorf("TokenEvents[%d].CacheReadTokens = %d, want %d", i, e.CacheReadTokens, w.cached)
		}
		if e.ReasoningTokens != w.reasoning {
			t.Errorf("TokenEvents[%d].ReasoningTokens = %d, want %d", i, e.ReasoningTokens, w.reasoning)
		}
		if e.Source != models.TokenSourceJSONL {
			t.Errorf("TokenEvents[%d].Source = %q, want %q (Tier 2)", i, e.Source, models.TokenSourceJSONL)
		}
		if e.ProjectRoot == "" {
			t.Errorf("TokenEvents[%d].ProjectRoot empty", i)
		}
	}

	// SessionLineages carries no Tool field (nothing to retag) but
	// should still surface the fixture's thread_source:"user" marker
	// unmodified by the retag pass.
	if len(res.SessionLineages) != 1 {
		t.Fatalf("SessionLineages count = %d, want 1", len(res.SessionLineages))
	}
	if res.SessionLineages[0].ThreadSource != "user" {
		t.Errorf("SessionLineages[0].ThreadSource = %q, want %q", res.SessionLineages[0].ThreadSource, "user")
	}
}

// TestOpenInterpreterIncrementalParseRetagsResumedChunk pins that the
// retag seam also applies to incremental (fromOffset > 0) resumes, not
// just a fresh full parse — the resumed chunk goes through the same
// ParseSessionFile wrapper.
func TestOpenInterpreterIncrementalParseRetagsResumedChunk(t *testing.T) {
	t.Parallel()
	dir := oiFixtureDir(t)
	path := oiFixturePath(t)
	a := NewOpenInterpreterWithOptions(nil, dir)

	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if first.NewOffset == 0 {
		t.Fatal("first parse advanced NewOffset to 0; fixture is non-empty")
	}
	// Resume from partway through the file (after the first
	// token_count event) and confirm the resumed events are still
	// retagged.
	second, err := a.ParseSessionFile(context.Background(), path, first.NewOffset)
	if err != nil {
		t.Fatalf("resume parse: %v", err)
	}
	for i, e := range second.TokenEvents {
		if e.Tool != models.ToolOpenInterpreter {
			t.Errorf("resumed TokenEvents[%d].Tool = %q, want %q", i, e.Tool, models.ToolOpenInterpreter)
		}
	}
}

// TestOpenInterpreterReasoningNeverMintsAnAction pins that the B3 fix
// covers the RETAG too: `NewOpenInterpreter` shares this package's
// single response_item parser (the §2.1 boundary seam), so one emit-site
// change has to hold for both tool identities. Encrypted-only reasoning
// (the dominant live shape) produces nothing; readable summary text is
// threaded onto the turn's next tool row instead of minting one.
func TestOpenInterpreterReasoningNeverMintsAnAction(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-2026-07-18T10-00-00-oi-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-07-18T10:00:00.000Z","type":"session_meta","payload":{"id":"oi-thread","cwd":"/tmp","model":"gpt-5.6-sol"}}`,
		`{"timestamp":"2026-07-18T10:00:00.500Z","type":"turn_context","payload":{"turn_id":"turn-oi","model":"gpt-5.6-sol","cwd":"/tmp"}}`,
		`{"timestamp":"2026-07-18T10:00:01.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-oi"}}`,
		// Encrypted-only reasoning: the 100% live shape. Emits nothing.
		`{"timestamp":"2026-07-18T10:00:02.000Z","type":"response_item","payload":{"type":"reasoning","summary":[],"encrypted_content":"abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"}}`,
		// Readable summary: threaded, still no row of its own.
		`{"timestamp":"2026-07-18T10:00:03.000Z","type":"response_item","payload":{"type":"reasoning","summary":[{"type":"summary_text","text":"I should list the directory."}],"encrypted_content":"opaque..."}}`,
		`{"timestamp":"2026-07-18T10:00:04.000Z","type":"event_msg","payload":{"type":"exec_command_end","call_id":"call_OI","turn_id":"turn-oi","command":["bash","-lc","ls"],"cwd":"/tmp","aggregated_output":"ok","exit_code":0,"duration":{"secs":1,"nanos":0},"status":"completed"}}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewOpenInterpreterWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	var exec *models.ToolEvent
	for i := range res.ToolEvents {
		ev := &res.ToolEvents[i]
		if ev.Tool != models.ToolOpenInterpreter {
			t.Errorf("ToolEvents[%d].Tool = %q, want %q", i, ev.Tool, models.ToolOpenInterpreter)
		}
		if strings.Contains(strings.ToLower(ev.RawToolName), "reasoning") {
			t.Fatalf("reasoning-named action row emitted on the retag: raw=%q %+v", ev.RawToolName, *ev)
		}
		if strings.Contains(ev.Target, "encrypted reasoning") || ev.Target == "(reasoning)" {
			t.Fatalf("placeholder reasoning surfaced as an action target: %+v", *ev)
		}
		if strings.Contains(ev.PrecedingReasoning, "encrypted reasoning") {
			t.Fatalf("placeholder reasoning threaded into PrecedingReasoning: %+v", *ev)
		}
		if ev.RawToolName == "exec_command_end" {
			exec = ev
		}
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("tool events: %d want 1 (exec_command_end only): %+v", len(res.ToolEvents), res.ToolEvents)
	}
	if exec == nil {
		t.Fatal("missing exec_command_end row")
	}
	if !strings.Contains(exec.PrecedingReasoning, "list the directory") {
		t.Errorf("exec_command_end PrecedingReasoning = %q, want the threaded summary text", exec.PrecedingReasoning)
	}
}
