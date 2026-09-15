package copilotcli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// jetbrainsFixtureRoot is the anonymised JetBrains-hosted capture under
// testdata/copilotcli/jetbrains/ — see its README for provenance.
const (
	jetbrainsFixtureSession = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
	jetbrainsFixtureDir     = "../../../testdata/copilotcli/jetbrains"
)

// TestSurfaceForClientName pins the grounded client_name → surface table
// (surface.go), including every honesty case that must produce NO stamp.
func TestSurfaceForClientName(t *testing.T) {
	const sid = "sess-1"
	tests := []struct {
		name       string
		clientName string
		wantOK     bool
		want       models.SessionSurface
	}{
		{
			// Grounded 2026-09-03: IntelliJ IDEA 2026.2 AI Assistant
			// driving the GitHub Copilot ACP agent.
			name:       "jetbrains idea",
			clientName: "JetBrains.IntelliJ IDEA",
			wantOK:     true,
			want:       models.SessionSurface{SessionID: sid, Surface: models.SurfaceIDE, SurfaceHost: "jetbrains-idea"},
		},
		{
			// A JetBrains product jetbrainshost's table does not name
			// still resolves to the generic JetBrains host — the
			// vendor prefix itself IS grounded.
			name:       "jetbrains unknown product",
			clientName: "JetBrains.Aqua",
			wantOK:     true,
			want:       models.SessionSurface{SessionID: sid, Surface: models.SurfaceIDE, SurfaceHost: "jetbrains"},
		},
		{
			name:       "jetbrains pycharm",
			clientName: "JetBrains.PyCharm",
			wantOK:     true,
			want:       models.SessionSurface{SessionID: sid, Surface: models.SurfaceIDE, SurfaceHost: "jetbrains-pycharm"},
		},
		{
			// Grounded 2026-09-03: an ordinary terminal `copilot` run.
			name:       "interactive cli",
			clientName: "github/cli",
			wantOK:     true,
			want:       models.SessionSurface{SessionID: sid, Surface: models.SurfaceCLI, SurfaceHost: "copilot-cli"},
		},
		{
			name:       "interactive cli case insensitive",
			clientName: "GitHub/CLI",
			wantOK:     true,
			want:       models.SessionSurface{SessionID: sid, Surface: models.SurfaceCLI, SurfaceHost: "copilot-cli"},
		},
		// Honesty rules — no stamp rather than a guess.
		{name: "absent client_name", clientName: "", wantOK: false},
		{name: "whitespace only", clientName: "   ", wantOK: false},
		{name: "unknown host string", clientName: "Visual Studio Code", wantOK: false},
		{name: "unknown vendor", clientName: "acme/agent", wantOK: false},
		// A JetBrains-LOOKING string without the vendor's own dot
		// prefix is not the vendor's string.
		{name: "near-miss prefix", clientName: "JetBrains IntelliJ IDEA", wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := surfaceForClientName(sid, tc.clientName)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, tc.wantOK, got)
			}
			if !tc.wantOK {
				if got != (models.SessionSurface{}) {
					t.Errorf("expected zero surface, got %+v", got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("surface = %+v, want %+v", got, tc.want)
			}
			if got.Hosted {
				t.Error("adapter self-reports must never set Hosted")
			}
			if !models.KnownSurface(got.Surface) {
				t.Errorf("surface kind %q is out of vocabulary", got.Surface)
			}
		})
	}
}

// TestSurfaceForClientNameRequiresSessionID pins that a stamp is never
// emitted without a session to attach it to.
func TestSurfaceForClientNameRequiresSessionID(t *testing.T) {
	if _, ok := surfaceForClientName("", "JetBrains.IntelliJ IDEA"); ok {
		t.Error("expected no stamp without a session id")
	}
}

// TestJetBrainsFixtureParse parses the anonymised JetBrains-hosted
// capture end-to-end: the surface stamp lands, and the pre-existing
// extraction (project root from workspace.yaml, actions, tokens) is
// unchanged by the surface work.
func TestJetBrainsFixtureParse(t *testing.T) {
	root, err := filepath.Abs(jetbrainsFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture root must be named "session-state" for
	// isEventsFile's grandparent check; stage a copy under a temp dir
	// so the repo layout stays readable.
	ssRoot := filepath.Join(t.TempDir(), "session-state")
	sessDir := filepath.Join(ssRoot, jetbrainsFixtureSession)
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"events.jsonl", "workspace.yaml"} {
		b, rerr := os.ReadFile(filepath.Join(root, jetbrainsFixtureSession, name))
		if rerr != nil {
			t.Fatalf("read fixture %s: %v", name, rerr)
		}
		if werr := os.WriteFile(filepath.Join(sessDir, name), b, 0o644); werr != nil {
			t.Fatal(werr)
		}
	}

	evt := filepath.Join(sessDir, "events.jsonl")
	a := NewWithOptions(nil, ssRoot)
	if !a.IsSessionFile(evt) {
		t.Fatalf("IsSessionFile(%q) = false", evt)
	}
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("SessionSurfaces = %+v, want exactly one", res.SessionSurfaces)
	}
	want := models.SessionSurface{
		SessionID:   jetbrainsFixtureSession,
		Surface:     models.SurfaceIDE,
		SurfaceHost: "jetbrains-idea",
	}
	if res.SessionSurfaces[0] != want {
		t.Errorf("surface = %+v, want %+v", res.SessionSurfaces[0], want)
	}

	// Pre-existing extraction, unchanged. The fixture is the first 30
	// events of the live run (two full assistant turns): 2 assistant
	// messages carrying outputTokens, and every tool/permission row
	// they produced.
	if len(res.TokenEvents) != 2 {
		t.Errorf("TokenEvents = %d, want 2", len(res.TokenEvents))
	}
	for _, te := range res.TokenEvents {
		if te.SessionID != jetbrainsFixtureSession {
			t.Errorf("token SessionID = %q", te.SessionID)
		}
		if te.Model != "gpt-5.6-luna" {
			t.Errorf("token Model = %q, want gpt-5.6-luna", te.Model)
		}
		if te.OutputTokens <= 0 {
			t.Errorf("token OutputTokens = %d, want > 0", te.OutputTokens)
		}
	}
	if len(res.ToolEvents) == 0 {
		t.Fatal("expected tool events")
	}
	// workspace.yaml's git_root wins over the in-stream cwd; on a box
	// with no such repo git.Resolve falls through to the stated path.
	const wantRoot = `C:\Users\dev\projects\demo`
	for _, ev := range res.ToolEvents {
		if ev.SessionID != jetbrainsFixtureSession {
			t.Errorf("tool SessionID = %q", ev.SessionID)
		}
		if ev.ProjectRoot != wantRoot {
			t.Errorf("tool ProjectRoot = %q, want %q", ev.ProjectRoot, wantRoot)
			break
		}
	}
	// Two user.message events: the operator's prompt, plus the
	// harness's own deferred-tool reminder message (empty `content`,
	// non-empty `transformedContent`) — both are user-role turns in
	// Copilot CLI's stream and both already produced a user_prompt row
	// before this change.
	if got := countActions(res.ToolEvents, models.ActionUserPrompt); got != 2 {
		t.Errorf("user_prompt rows = %d, want 2", got)
	}
	if got := countActions(res.ToolEvents, models.ActionPermissionRequest); got != 3 {
		t.Errorf("permission_request rows = %d, want 3", got)
	}

	// Idempotence: a second parse from the same offset repeats the
	// stamp verbatim (SetSessionSurface is first-wins-unless-empty, so
	// a repeat is a no-op downstream).
	again, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if len(again.SessionSurfaces) != 1 || again.SessionSurfaces[0] != want {
		t.Errorf("re-parse surfaces = %+v", again.SessionSurfaces)
	}
}

// TestWorkspaceYAMLClientNameRead pins that the ONE workspace.yaml
// reader carries client_name alongside the project fields, and that a
// missing file yields the zero value rather than a partial guess.
func TestWorkspaceYAMLClientNameRead(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "workspace.yaml")
	body := "id: abc\n" +
		"cwd: " + filepath.ToSlash(dir) + "\n" +
		"branch: feature/x\n" +
		"client_name: JetBrains.GoLand\n" +
		"user_named: false\n"
	if err := os.WriteFile(yamlPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ws := resolveProjectFromWorkspaceYAML(yamlPath)
	if ws.ClientName != "JetBrains.GoLand" {
		t.Errorf("ClientName = %q", ws.ClientName)
	}
	if ws.Branch != "feature/x" {
		t.Errorf("Branch = %q", ws.Branch)
	}
	if ws.ProjectRoot == "" {
		t.Error("ProjectRoot should resolve from cwd")
	}

	if got := resolveProjectFromWorkspaceYAML(filepath.Join(dir, "missing.yaml")); got != (workspaceMeta{}) {
		t.Errorf("missing file = %+v, want zero", got)
	}

	// A workspace.yaml with a client_name but NO usable path still
	// carries the client_name — the surface stamp must not depend on
	// project-root resolution succeeding.
	clientOnly := filepath.Join(dir, "client-only.yaml")
	if err := os.WriteFile(clientOnly, []byte("client_name: github/cli\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ws = resolveProjectFromWorkspaceYAML(clientOnly)
	if ws.ClientName != "github/cli" || ws.ProjectRoot != "" {
		t.Errorf("client-only = %+v", ws)
	}
}

func countActions(evs []models.ToolEvent, action string) int {
	n := 0
	for _, e := range evs {
		if e.ActionType == action {
			n++
		}
	}
	return n
}
