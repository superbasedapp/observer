package codex

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestResolveCodexSurface pins the (source, originator) → (kind, host)
// resolution table (surface.go). Rows mirror the 2026-09-02 80-rollout
// grounding sample (§0 of docs/plans/ide-surface-capture-remediation-
// plan-2026-09-02.md) plus the cli/codex_cli_rs pairing already present
// in this repo's own testdata fixtures, REVISED by the 2026-09-06
// controlled A/B (plan §13.1 of docs/plans/uncaptured-surfaces-login-
// schedule-2026-09-03.md) which found "Codex Desktop" and
// "codex_vscode" cleanly distinct — the standalone desktop app and the
// VS Code extension, respectively — so "Codex Desktop" now resolves to
// desktop/codex-desktop instead of ide/vscode.
func TestResolveCodexSurface(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		source     string
		originator string
		wantKind   string
		wantHost   string
		wantOK     bool
	}{
		{"cli+codex_cli_rs", "cli", "codex_cli_rs", models.SurfaceCLI, "codex-cli", true},
		{"cli+codex_cli", "cli", "codex_cli", models.SurfaceCLI, "codex-cli", true},
		{"cli+unseen_originator", "cli", "some_future_cli", models.SurfaceCLI, "codex-cli", true},
		{"exec+codex_exec", "exec", "codex_exec", models.SurfaceCLI, "codex-exec", true},
		{"exec+empty_originator", "exec", "", models.SurfaceCLI, "codex-exec", true},
		{"vscode+CodexDesktop", "vscode", "Codex Desktop", models.SurfaceDesktop, "codex-desktop", true},
		{"vscode+codex_vscode", "vscode", "codex_vscode", models.SurfaceIDE, "vscode", true},
		{"vscode+empty_originator", "vscode", "", models.SurfaceIDE, "vscode", true},
		{"unknown_source+known_originator_exec", "", "codex_exec", models.SurfaceCLI, "codex-exec", true},
		{"unknown_source+known_originator_desktop", "", "Codex Desktop", models.SurfaceDesktop, "codex-desktop", true},
		{"unknown_both", "", "", "", "", false},
		{"unknown_source_and_originator", "carrier-pigeon", "smoke-signal", "", "", false},

		// Originator precedence (2026-09-03 grounding). The JetBrains
		// plugin drives the same codex binary, which stamps the
		// INHERITED source:"vscode" regardless of the embedding IDE —
		// so the authoritative originator must override the source
		// pre-fill, or the session is stamped ide/vscode (right kind,
		// wrong host), which is exactly what the live DB shows.
		{"jetbrains_idea_over_vscode_source", "vscode", "JetBrains.IntelliJ IDEA", models.SurfaceIDE, "jetbrains-idea", true},
		{"jetbrains_idea_no_source", "", "JetBrains.IntelliJ IDEA", models.SurfaceIDE, "jetbrains-idea", true},
		{"jetbrains_goland_over_cli_source", "cli", "JetBrains.GoLand", models.SurfaceIDE, "jetbrains-goland", true},
		{"jetbrains_pycharm", "vscode", "JetBrains.PyCharm", models.SurfaceIDE, "jetbrains-pycharm", true},
		// An unknown JetBrains product still resolves — jetbrainshost
		// owns that fallback, not this table.
		{"jetbrains_unknown_product_generic", "vscode", "JetBrains.Aqua", models.SurfaceIDE, "jetbrains", true},
		// "JetBrains" WITHOUT the dot separator is not a client name.
		{"jetbrains_bare_word_is_not_a_client_name", "", "JetBrains", "", "", false},

		// The Open Interpreter DESKTOP originator stays UNMAPPED on
		// codex proper: it is unknown whether some OpenAI surface also
		// writes it, so codex emits no stamp from the originator. The
		// variant's own overlay (openinterpreter.go) is what resolves
		// it to desktop/open-interpreter — see
		// TestOpenInterpreterSurfaceVocabulary.
		{"open_interpreter_desktop_originator_unmapped_here", "", "codex_ui", "", "", false},
		// With a KNOWN source, codex proper still resolves from source
		// alone; codex_ui contributes nothing either way.
		{"open_interpreter_desktop_originator_source_only", "vscode", "codex_ui", models.SurfaceIDE, "vscode", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			kind, host, ok := resolveCodexSurface(tc.source, tc.originator)
			if ok != tc.wantOK || kind != tc.wantKind || host != tc.wantHost {
				t.Errorf("resolveCodexSurface(%q, %q) = (%q, %q, %v); want (%q, %q, %v)",
					tc.source, tc.originator, kind, host, ok, tc.wantKind, tc.wantHost, tc.wantOK)
			}
		})
	}
}

// sessionMetaLine builds a minimal session_meta rollout line carrying
// originator/source, for surface-attribution tests.
func sessionMetaLine(sessionID, originator, source string) string {
	return `{"timestamp":"2026-09-02T10:00:00.000Z","type":"session_meta","payload":{"id":"` + sessionID +
		`","session_id":"` + sessionID + `","cwd":"/w","model":"gpt-5.6","originator":"` + originator +
		`","source":"` + source + `"}}`
}

// TestParseSessionFile_SurfaceAttribution pins Part E: ParseSessionFile
// resolves the owning session_meta's originator/source into exactly one
// models.SessionSurface, for each vendor pairing observed live plus the
// unknown → no-stamp case.
func TestParseSessionFile_SurfaceAttribution(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		originator string
		source     string
		wantStamp  bool
		wantKind   string
		wantHost   string
	}{
		{"exec_majority_case", "codex_exec", "exec", true, models.SurfaceCLI, "codex-exec"},
		{"desktop_app", "Codex Desktop", "vscode", true, models.SurfaceDesktop, "codex-desktop"},
		{"codex_vscode_originator", "codex_vscode", "vscode", true, models.SurfaceIDE, "vscode"},
		{"cli_rs_binary", "codex_cli_rs", "cli", true, models.SurfaceCLI, "codex-cli"},
		{"jetbrains_idea_plugin", "JetBrains.IntelliJ IDEA", "vscode", true, models.SurfaceIDE, "jetbrains-idea"},
		{"unknown_vendor_token_emits_nothing", "some_new_client", "some_new_source", false, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "rollout-surface-"+tc.name+".jsonl")
			body := sessionMetaLine("sess-"+tc.name, tc.originator, tc.source) + "\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			res, err := NewWithOptions(nil, dir).ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			if !tc.wantStamp {
				if len(res.SessionSurfaces) != 0 {
					t.Fatalf("session surfaces = %+v; want none for an unknown vendor token", res.SessionSurfaces)
				}
				return
			}
			if len(res.SessionSurfaces) != 1 {
				t.Fatalf("session surfaces: got %d want 1", len(res.SessionSurfaces))
			}
			got := res.SessionSurfaces[0]
			wantSessionID := "sess-" + tc.name
			if got.SessionID != wantSessionID || got.Surface != tc.wantKind || got.SurfaceHost != tc.wantHost {
				t.Errorf("surface = %+v; want {%s %s %s}", got, wantSessionID, tc.wantKind, tc.wantHost)
			}
		})
	}
}

// TestParseSessionFile_SurfaceAttributionFixture parses the on-disk
// testdata/codex/rollout-surface-attribution.jsonl fixture (originator
// "codex_exec" / source "exec", the majority shape in the 2026-09-02
// grounding sample) end to end, exercising the real fixture-file path
// alongside the inline-body cases above.
func TestParseSessionFile_SurfaceAttributionFixture(t *testing.T) {
	t.Parallel()
	a := New()
	res, err := a.ParseSessionFile(context.Background(), fixture(t, "rollout-surface-attribution.jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("session surfaces: got %d want 1", len(res.SessionSurfaces))
	}
	got := res.SessionSurfaces[0]
	if got.SessionID != "surface-001" || got.Surface != models.SurfaceCLI || got.SurfaceHost != "codex-exec" {
		t.Errorf("surface = %+v; want {surface-001 %s codex-exec}", got, models.SurfaceCLI)
	}
}

// TestParseSessionFile_SurfaceJetBrainsFixture parses the on-disk
// testdata/codex/rollout-surface-jetbrains.jsonl fixture, which mirrors
// the live 2026-09-03 IntelliJ IDEA rollout's real session_meta shape
// (an `ordinal` envelope field, both `session_id` and `id`, and an
// OBJECT-valued `base_instructions` — shapes the older exec fixture
// lacks). It pins the originator-precedence fix end to end: the
// inherited `source:"vscode"` must not win over the JetBrains
// originator.
func TestParseSessionFile_SurfaceJetBrainsFixture(t *testing.T) {
	t.Parallel()
	res, err := New().ParseSessionFile(context.Background(), fixture(t, "rollout-surface-jetbrains.jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("session surfaces: got %d want 1", len(res.SessionSurfaces))
	}
	got := res.SessionSurfaces[0]
	if got.SessionID != "surface-jb-001" || got.Surface != models.SurfaceIDE || got.SurfaceHost != "jetbrains-idea" {
		t.Errorf("surface = %+v; want {surface-jb-001 %s jetbrains-idea}", got, models.SurfaceIDE)
	}
}

// TestParseSessionFile_SurfaceCodexDesktopFixture parses the on-disk
// testdata/codex/rollout-surface-codex-desktop.jsonl fixture, which
// mirrors the standalone Codex/ChatGPT desktop app's real session_meta
// shape from the 2026-09-06 controlled A/B (plan §13.1): originator
// "Codex Desktop", source "vscode" — the same inherited source the VS
// Code extension writes, distinguished only by the authoritative
// originator row. It pins the remap end to end: the inherited
// `source:"vscode"` must not win over the desktop originator.
func TestParseSessionFile_SurfaceCodexDesktopFixture(t *testing.T) {
	t.Parallel()
	res, err := New().ParseSessionFile(context.Background(), fixture(t, "rollout-surface-codex-desktop.jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("session surfaces: got %d want 1", len(res.SessionSurfaces))
	}
	got := res.SessionSurfaces[0]
	if got.SessionID != "surface-desktop-001" || got.Surface != models.SurfaceDesktop || got.SurfaceHost != "codex-desktop" {
		t.Errorf("surface = %+v; want {surface-desktop-001 %s codex-desktop}", got, models.SurfaceDesktop)
	}
}

// TestParseSessionFile_SurfaceNotRestampedOnResume mirrors the lineage-
// marker resume contract (TestParseForkedRolloutIncrementalRace): the
// owning session_meta is read only in the first (fromOffset==0) chunk,
// so surface attribution is emitted once — a resumed chunk that reads no
// session_meta itself must NOT re-emit it.
func TestParseSessionFile_SurfaceNotRestampedOnResume(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-surface-resume.jsonl")

	leading := sessionMetaLine("resume-sess", "codex_exec", "exec") + "\n"
	tail := `{"timestamp":"2026-09-02T10:00:01.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"t1"}}` + "\n"

	if err := os.WriteFile(path, []byte(leading), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if len(first.SessionSurfaces) != 1 {
		t.Fatalf("first chunk session surfaces = %d; want 1 (owner meta read this chunk)", len(first.SessionSurfaces))
	}

	full := leading + tail
	if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := a.ParseSessionFile(context.Background(), path, first.NewOffset)
	if err != nil {
		t.Fatalf("resumed parse: %v", err)
	}
	if len(second.SessionSurfaces) != 0 {
		t.Errorf("resumed chunk session surfaces = %d; want 0 (owner meta not read this chunk)", len(second.SessionSurfaces))
	}
}
