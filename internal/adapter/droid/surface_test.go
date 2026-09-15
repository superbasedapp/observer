package droid

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// Factory Desktop fixture coordinates. See testdata/factory/README.md.
// Ground-truth capture 2026-09-03: a51ce7d2 is the desktop-composed
// session forked from f2083b6a (the "please give me a summary…" prompt
// kit run through Factory Desktop, forked mid-conversation into a
// follow-up ask); 6c9d4a17 is an empty desktop "New Session" that never
// sent a message (model still "auto", no routed turn yet).
const (
	desktopDir     = "windows-desktop-C-Users-operator-workspace-antigravity"
	desktopEncoded = "-C-Users-operator-workspace-antigravity"
	desktopCWD     = `C:\Users\operator\workspace\antigravity`

	desktopChildID  = "a51ce7d2-3f68-4e91-9a2c-7bd410f3e88a"
	desktopParentID = "f2083b6a-1a4d-47c2-8e55-2c9761aa5b40"
	desktopEmptyID  = "6c9d4a17-5e2b-4f80-b731-0a8e3d5c9f14"
)

// --- capture-surface attribution -----------------------------------

// TestDesktopSurfaceStamped pins the one grounded discriminator: a
// message.userMessageSource=="desktop" marker on a real user-typed turn
// stamps the session Desktop/factory-desktop. The forked child fixture
// carries 9 such markers (one per real prompt after the fork).
func TestDesktopSurfaceStamped(t *testing.T) {
	res, _ := parseStaged(t, desktopDir, desktopEncoded, desktopChildID)
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("SessionSurfaces=%d want 1: %+v", len(res.SessionSurfaces), res.SessionSurfaces)
	}
	got := res.SessionSurfaces[0]
	if got.SessionID != desktopChildID || got.Surface != models.SurfaceDesktop || got.SurfaceHost != factoryDesktopHost {
		t.Errorf("surface=%+v want {%s %s %s}", got, desktopChildID, models.SurfaceDesktop, factoryDesktopHost)
	}
}

// TestDesktopSurfaceStampedOnSingleRealPrompt pins that even a session
// with just ONE real user-typed turn (not nine) gets stamped — the
// parent fixture carries exactly one userMessageSource="desktop" marker
// before its turn was cut short by a usage-limit outcome.
func TestDesktopSurfaceStampedOnSingleRealPrompt(t *testing.T) {
	res, _ := parseStaged(t, desktopDir, desktopEncoded, desktopParentID)
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].Surface != models.SurfaceDesktop {
		t.Errorf("SessionSurfaces=%+v want exactly one Desktop stamp", res.SessionSurfaces)
	}
}

// TestNoSurfaceStampWithoutTheMarker pins the honest-zero half of the
// discriminator decision (docs/droid-adapter.md "Factory Desktop"): a
// session_start record carries NO client/entrypoint/source field on
// either OS, and a CLI-composed prompt never carries
// userMessageSource at all (absent, not a "cli" value) — so the
// pre-existing CLI fixtures, which predate this ticket and were never
// touched, must still emit NO SessionSurfaces. Absence of the desktop
// marker is never treated as proof of "cli".
func TestNoSurfaceStampWithoutTheMarker(t *testing.T) {
	for _, fx := range []struct{ dir, enc, id string }{
		{linuxDir, linuxEncoded, minimalID},
		{linuxDir, linuxEncoded, richID},
		{windowsDir, windowsEncoded, windowsID},
	} {
		res, _ := parseStaged(t, fx.dir, fx.enc, fx.id)
		if len(res.SessionSurfaces) != 0 {
			t.Errorf("%s: SessionSurfaces=%+v want none (no grounded CLI marker exists to stamp)", fx.id, res.SessionSurfaces)
		}
	}
}

// TestEmptySessionNoSurfaceStamp: a session that never sent a message
// has no userMessageSource data point either way, so it must not be
// stamped.
func TestEmptySessionNoSurfaceStamp(t *testing.T) {
	res, _ := parseStaged(t, desktopDir, desktopEncoded, desktopEmptyID)
	if len(res.SessionSurfaces) != 0 {
		t.Errorf("SessionSurfaces=%+v want none for a session with no messages", res.SessionSurfaces)
	}
}

// TestDesktopSurfaceIdempotentAcrossResume: a resumed parse window that
// contains no NEW desktop-marker message must not re-stamp (harmless
// either way, but pin the actual behavior: the flag is per-window, not
// carried across resumes).
func TestDesktopSurfaceIdempotentAcrossResume(t *testing.T) {
	home, transcript := stage(t, desktopDir, desktopEncoded, desktopChildID)
	a := NewWithOptions(nil, homeSessionsRoot(home))
	ctx := context.Background()

	full, err := a.ParseSessionFile(ctx, transcript, 0)
	if err != nil {
		t.Fatalf("full parse: %v", err)
	}
	if len(full.SessionSurfaces) != 1 {
		t.Fatalf("full parse SessionSurfaces=%d want 1", len(full.SessionSurfaces))
	}
	// Re-parsing from the persisted cursor (EOF) sees no further
	// messages, so it must not emit a second (harmless, but pointless)
	// stamp.
	second, err := a.ParseSessionFile(ctx, transcript, full.NewOffset)
	if err != nil {
		t.Fatalf("resumed parse: %v", err)
	}
	if len(second.SessionSurfaces) != 0 {
		t.Errorf("resumed parse (no new content) SessionSurfaces=%+v want none", second.SessionSurfaces)
	}
}

// --- fork lineage -----------------------------------------------------

// TestForkLineageCaptured pins the fork-lineage emission: the desktop
// child's session_start carries `parent` (and `forkedAtMessageId`,
// which has no SessionLineage field to land on and is not captured).
// ThreadSource mirrors codex's existing "user" vocabulary (normal +
// user-fork) rather than inventing a "fork" token — see
// threadSourceUserFork's doc comment.
func TestForkLineageCaptured(t *testing.T) {
	res, _ := parseStaged(t, desktopDir, desktopEncoded, desktopChildID)
	if len(res.SessionLineages) != 1 {
		t.Fatalf("SessionLineages=%d want 1: %+v", len(res.SessionLineages), res.SessionLineages)
	}
	lin := res.SessionLineages[0]
	if lin.SessionID != desktopChildID || lin.ForkedFromID != desktopParentID || lin.ThreadSource != "user" {
		t.Errorf("lineage=%+v want {%s %s user}", lin, desktopChildID, desktopParentID)
	}
	if lin.ParentThreadID != "" {
		t.Errorf("ParentThreadID=%q want empty — droid has no distinct parent-thread field", lin.ParentThreadID)
	}
}

// TestNoForkLineageWithoutParent: a normal (non-forked) session must not
// emit a lineage row — pins the negative across both the new parent
// fixture (which is itself not a fork) and the pre-existing CLI fixture.
func TestNoForkLineageWithoutParent(t *testing.T) {
	for _, fx := range []struct{ dir, enc, id string }{
		{desktopDir, desktopEncoded, desktopParentID},
		{desktopDir, desktopEncoded, desktopEmptyID},
		{linuxDir, linuxEncoded, richID},
	} {
		res, _ := parseStaged(t, fx.dir, fx.enc, fx.id)
		if len(res.SessionLineages) != 0 {
			t.Errorf("%s: SessionLineages=%+v want none (not a fork)", fx.id, res.SessionLineages)
		}
	}
}

// TestForkLineageOnlyOnFirstParse: like the session_start marker itself,
// the lineage row is derived entirely from line 1, so it must only be
// emitted once — on the offset-0 parse — never re-emitted on a resumed
// window (which re-reads the header for session id / cwd but would
// otherwise redundantly re-append the identical lineage row every poll).
func TestForkLineageOnlyOnFirstParse(t *testing.T) {
	home, transcript := stage(t, desktopDir, desktopEncoded, desktopChildID)
	a := NewWithOptions(nil, homeSessionsRoot(home))
	ctx := context.Background()

	full, err := a.ParseSessionFile(ctx, transcript, 0)
	if err != nil {
		t.Fatalf("full parse: %v", err)
	}
	if len(full.SessionLineages) != 1 {
		t.Fatalf("full parse SessionLineages=%d want 1", len(full.SessionLineages))
	}
	second, err := a.ParseSessionFile(ctx, transcript, full.NewOffset)
	if err != nil {
		t.Fatalf("resumed parse: %v", err)
	}
	if len(second.SessionLineages) != 0 {
		t.Errorf("resumed parse SessionLineages=%+v want none (offset-0-only emission)", second.SessionLineages)
	}
}

// --- model resolution ladder -------------------------------------------

// TestResolvedModelLadder table-drives the 3-tier ladder directly
// against sidecar.resolvedModel().
func TestResolvedModelLadder(t *testing.T) {
	cases := []struct {
		name string
		sc   sidecar
		want string
	}{
		{
			name: "explicit non-auto model wins outright",
			sc:   sidecar{Model: "custom:superbased-0"},
			want: "custom:superbased-0",
		},
		{
			name: "auto with a routed effective model falls to tier 2",
			sc: func() sidecar {
				var s sidecar
				s.Model = "auto"
				s.EffectiveFactoryRouterModel.ModelID = "claude-opus-5"
				return s
			}(),
			want: "claude-opus-5",
		},
		{
			name: "auto with no routed turn falls to the literal sentinel",
			sc:   sidecar{Model: "auto"},
			want: "auto",
		},
		{
			name: "blank model with a routed effective model still falls to tier 2",
			sc: func() sidecar {
				var s sidecar
				s.EffectiveFactoryRouterModel.ModelID = "gpt-5.6"
				return s
			}(),
			want: "gpt-5.6",
		},
		{
			name: "blank model with nothing to resolve stays blank",
			sc:   sidecar{},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.sc.resolvedModel(); got != tc.want {
				t.Errorf("resolvedModel()=%q want %q", got, tc.want)
			}
		})
	}
}

// TestParentFixtureModelLadderEndToEnd exercises the ladder through a
// full parse: f2083b6a's sidecar has model:"auto" +
// effectiveFactoryRouterModel.modelId:"claude-opus-5" (a routed turn
// that hit a usage-limit outcome before any token usage accrued), so
// every emitted row's Model must resolve to "claude-opus-5", never the
// literal "auto".
func TestParentFixtureModelLadderEndToEnd(t *testing.T) {
	res, _ := parseStaged(t, desktopDir, desktopEncoded, desktopParentID)
	if len(res.ToolEvents) == 0 {
		t.Fatal("no ToolEvents parsed")
	}
	for _, ev := range res.ToolEvents {
		if ev.Model != "" && ev.Model != "claude-opus-5" {
			t.Errorf("event %q Model=%q want claude-opus-5 (resolved through the auto-router ladder)", ev.SourceEventID, ev.Model)
		}
	}
	// The sidecar's own tokenUsage is all-zero (the turn never completed
	// a call), so no token row — but if it existed it would need the
	// same resolution. Pinned directly by TestResolvedModelLadder.
	if len(res.TokenEvents) != 0 {
		t.Errorf("TokenEvents=%+v want none (all-zero sidecar tokenUsage)", res.TokenEvents)
	}
}

// TestEmptySessionModelStaysLiteralAuto: the empty "New Session" fixture
// has model:"auto" and no effectiveFactoryRouterModel at all (no turn
// was ever routed), so the session_start row's Model must be the
// literal "auto" sentinel rather than blank or a guess.
func TestEmptySessionModelStaysLiteralAuto(t *testing.T) {
	res, _ := parseStaged(t, desktopDir, desktopEncoded, desktopEmptyID)
	if len(res.ToolEvents) != 1 {
		t.Fatalf("ToolEvents=%d want 1 (session_start only)", len(res.ToolEvents))
	}
	if got := res.ToolEvents[0].Model; got != "auto" {
		t.Errorf("Model=%q want the literal auto sentinel", got)
	}
}

// TestDesktopFixtureProjectRoot pins that the desktop fixtures resolve
// their project root from the inline session_start cwd the same way the
// pre-existing CLI fixtures do — Factory Desktop writes the identical
// transcript shape, so nothing about project-root resolution changes.
func TestDesktopFixtureProjectRoot(t *testing.T) {
	res, _ := parseStaged(t, desktopDir, desktopEncoded, desktopChildID)
	want := crossmount.TranslateForeignPath(desktopCWD)
	for _, ev := range res.ToolEvents {
		if ev.ProjectRoot != want {
			t.Errorf("event %q ProjectRoot=%q want %q", ev.SourceEventID, ev.ProjectRoot, want)
		}
	}
}

// homeSessionsRoot mirrors the <home>/.factory/sessions layout `stage`
// writes fixtures into, for tests that need to build their own Adapter
// against a staged tree.
func homeSessionsRoot(home string) string {
	return filepath.Join(home, ".factory", "sessions")
}
