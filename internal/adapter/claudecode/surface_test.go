package claudecode

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestResolveClaudeSurface pins the `entrypoint` → (kind, host)
// resolution table (surface.go). Vocabulary per the plan's §0 sample:
// cli, claude-vscode, claude-jetbrains (unverified spelling, still
// tabled), claude-desktop, and the sdk-* family.
func TestResolveClaudeSurface(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		entrypoint string
		wantKind   string
		wantHost   string
		wantOK     bool
	}{
		{"cli", "cli", models.SurfaceCLI, "claude", true},
		{"vscode", "claude-vscode", models.SurfaceIDE, "vscode", true},
		{"jetbrains", "claude-jetbrains", models.SurfaceIDE, "jetbrains", true},
		{"desktop", "claude-desktop", models.SurfaceDesktop, "claude-desktop", true},
		{"sdk-ts", "sdk-ts", models.SurfaceSDK, "ts", true},
		{"sdk-py", "sdk-py", models.SurfaceSDK, "py", true},
		{"bare-sdk", "sdk", models.SurfaceSDK, "sdk", true},
		{"sdk-trailing-dash-only", "sdk-", models.SurfaceSDK, "sdk", true},
		{"unknown", "some-future-client", "", "", false},
		{"empty", "", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			kind, host, ok := resolveClaudeSurface(tc.entrypoint)
			if ok != tc.wantOK || kind != tc.wantKind || host != tc.wantHost {
				t.Errorf("resolveClaudeSurface(%q) = (%q, %q, %v); want (%q, %q, %v)",
					tc.entrypoint, kind, host, ok, tc.wantKind, tc.wantHost, tc.wantOK)
			}
		})
	}
}

// userLine builds a minimal `type:"user"` JSONL line carrying an
// entrypoint, for surface-attribution tests.
func userLine(sessionID, uuid, entrypoint string) string {
	line := `{"type":"user","sessionId":"` + sessionID + `","cwd":"/tmp/w","uuid":"` + uuid +
		`","timestamp":"2026-09-02T10:00:00Z"`
	if entrypoint != "" {
		line += `,"entrypoint":"` + entrypoint + `"`
	}
	line += `,"message":{"role":"user","content":[{"type":"text","text":"hi"}]}}`
	return line
}

// TestParseSessionFile_SurfaceAttribution pins Part E: ParseSessionFile
// resolves the first entrypoint-bearing line into exactly one
// models.SessionSurface, for each vendor value plus the missing/unknown
// → no-stamp cases.
func TestParseSessionFile_SurfaceAttribution(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		entrypoint string
		wantStamp  bool
		wantKind   string
		wantHost   string
	}{
		{"cli", "cli", true, models.SurfaceCLI, "claude"},
		{"claude_desktop_majority_case", "claude-desktop", true, models.SurfaceDesktop, "claude-desktop"},
		{"vscode", "claude-vscode", true, models.SurfaceIDE, "vscode"},
		{"sdk_ts", "sdk-ts", true, models.SurfaceSDK, "ts"},
		{"missing_entrypoint_emits_nothing", "", false, "", ""},
		{"unknown_entrypoint_emits_nothing", "some-future-client", false, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "session-surface-"+tc.name+".jsonl")
			sessionID := "sess-" + tc.name
			body := userLine(sessionID, "msg-1", tc.entrypoint) + "\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			res, err := New().ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			if !tc.wantStamp {
				if len(res.SessionSurfaces) != 0 {
					t.Fatalf("session surfaces = %+v; want none", res.SessionSurfaces)
				}
				return
			}
			if len(res.SessionSurfaces) != 1 {
				t.Fatalf("session surfaces: got %d want 1", len(res.SessionSurfaces))
			}
			got := res.SessionSurfaces[0]
			if got.SessionID != sessionID || got.Surface != tc.wantKind || got.SurfaceHost != tc.wantHost {
				t.Errorf("surface = %+v; want {%s %s %s}", got, sessionID, tc.wantKind, tc.wantHost)
			}
		})
	}
}

// TestParseSessionFile_SurfaceStampedFromFirstLineOnly pins the
// "first line only" contract: a later line in the SAME parse pass
// carrying a different entrypoint must NOT override the value latched
// from the first entrypoint-bearing line.
func TestParseSessionFile_SurfaceStampedFromFirstLineOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "session-surface-first-line.jsonl")
	body := userLine("sess-first", "msg-1", "cli") + "\n" +
		userLine("sess-first", "msg-2", "claude-desktop") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("session surfaces: got %d want 1", len(res.SessionSurfaces))
	}
	got := res.SessionSurfaces[0]
	if got.Surface != models.SurfaceCLI || got.SurfaceHost != "claude" {
		t.Errorf("surface = %+v; want the FIRST line's cli/claude, not the second line's claude-desktop", got)
	}
}

// TestParseSessionFile_SurfaceAttributionFixture parses the real
// testdata/claudecode/simple-session.jsonl fixture (line 1 carries
// entrypoint="cli") end to end.
func TestParseSessionFile_SurfaceAttributionFixture(t *testing.T) {
	t.Parallel()
	res, err := New().ParseSessionFile(context.Background(), fixturePath(t, "simple-session.jsonl"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("session surfaces: got %d want 1", len(res.SessionSurfaces))
	}
	got := res.SessionSurfaces[0]
	if got.SessionID != "sess-001" || got.Surface != models.SurfaceCLI || got.SurfaceHost != "claude" {
		t.Errorf("surface = %+v; want {sess-001 %s claude}", got, models.SurfaceCLI)
	}
}
