package cline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestHostTokenFor pins the host_name → host-token table. The grounded
// live value is the DISPLAY name "Visual Studio Code" (operator's Cline
// 3.88.0 tasks, read 2026-09-02), NOT a slug — the audit's assumption
// that the field carries "vscode" was wrong, so both spellings are
// mapped and an unrecognised name refines nothing.
func TestHostTokenFor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"Visual Studio Code", "vscode", true},
		{"visual studio code", "vscode", true},
		{"vscode", "vscode", true},
		{"Code", "vscode", true},
		{"Visual Studio Code - Insiders", "vscode-insiders", true},
		{"VSCodium", "vscodium", true},
		{"Cursor", "cursor", true},
		{"Windsurf", "windsurf", true},
		{"Kiro", "kiro", true},
		{"Qoder", "qoder", true},
		{"Trae", "trae", true},
		{"JetBrains", "jetbrains", true},
		{"", "", false},
		{"Emacs From The Future", "", false},
	}
	for _, tc := range cases {
		got, ok := hostTokenFor(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("hostTokenFor(%q) = (%q,%v) want (%q,%v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestResolveSurfaceHost pins the two-signal ladder: the path's
// VS Code product first, task_metadata.json's host_name refining it,
// and — when NEITHER signal exists — the honest EMPTY token rather
// than a guessed "vscode" (the Surface KIND stays ide; only the host
// goes unstamped).
func TestResolveSurfaceHost(t *testing.T) {
	t.Parallel()
	cursorPath := filepath.Join("C:", "Users", "u", "AppData", "Roaming", "Cursor", "User",
		"globalStorage", "saoudrizwan.claude-dev", "tasks", "t1", "api_conversation_history.json")
	codePath := filepath.Join("home", "u", ".config", "Code", "User",
		"globalStorage", "saoudrizwan.claude-dev", "tasks", "t1", "api_conversation_history.json")
	relocated := filepath.Join("d:", "roo-store", "tasks", "t1", "api_conversation_history.json")

	cases := []struct {
		name     string
		path     string
		meta     taskMetadata
		haveMeta bool
		want     string
	}{
		{name: "path_only_code", path: codePath, want: "vscode"},
		{name: "path_only_cursor", path: cursorPath, want: "cursor"},
		{name: "no_signal_emits_no_host", path: relocated, want: ""},
		{
			name:     "metadata_refines_path",
			path:     codePath,
			meta:     taskMetadata{EnvironmentHistory: []taskEnvironmentRecord{{Ts: 1, HostName: "Windsurf"}}},
			haveMeta: true,
			want:     "windsurf",
		},
		{
			name:     "metadata_rescues_relocated_store",
			path:     relocated,
			meta:     taskMetadata{EnvironmentHistory: []taskEnvironmentRecord{{Ts: 1, HostName: "Cursor"}}},
			haveMeta: true,
			want:     "cursor",
		},
		{
			name:     "unrecognised_host_does_not_override_path",
			path:     cursorPath,
			meta:     taskMetadata{EnvironmentHistory: []taskEnvironmentRecord{{Ts: 1, HostName: "Nano"}}},
			haveMeta: true,
			want:     "cursor",
		},
		{
			name: "newest_environment_entry_wins",
			path: codePath,
			meta: taskMetadata{EnvironmentHistory: []taskEnvironmentRecord{
				{Ts: 1, HostName: "Cursor"},
				{Ts: 9, HostName: "Windsurf"},
			}},
			haveMeta: true,
			want:     "windsurf",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveSurfaceHost(tc.path, tc.meta, tc.haveMeta); got != tc.want {
				t.Errorf("resolveSurfaceHost = %q want %q", got, tc.want)
			}
		})
	}
}

// TestLatestModelID pins newest-ts-wins over model_usage[].
func TestLatestModelID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		meta taskMetadata
		want string
	}{
		{name: "empty", want: ""},
		{
			name: "single",
			meta: taskMetadata{ModelUsage: []taskModelUsage{{Ts: 1, ModelID: "a/b"}}},
			want: "a/b",
		},
		{
			name: "newest_wins",
			meta: taskMetadata{ModelUsage: []taskModelUsage{
				{Ts: 5, ModelID: "old/model"},
				{Ts: 50, ModelID: "new/model"},
			}},
			want: "new/model",
		},
		{
			name: "empty_ids_skipped",
			meta: taskMetadata{ModelUsage: []taskModelUsage{{Ts: 9, ModelID: ""}, {Ts: 1, ModelID: "only/one"}}},
			want: "only/one",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := latestModelID(tc.meta); got != tc.want {
				t.Errorf("latestModelID = %q want %q", got, tc.want)
			}
		})
	}
}

// TestParseStampsSurfaceAndModel is the end-to-end pin: a task dir
// carrying the anonymized live task_metadata.json stamps the IDE
// surface, the metadata host, and backfills the task model onto rows
// that carried none.
func TestParseStampsSurfaceAndModel(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "tasks", "1780707193341")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	copyTestdata(t, "api_conversation_history_xml.json", filepath.Join(dir, "api_conversation_history.json"))
	copyTestdata(t, "task_metadata.json", filepath.Join(dir, taskMetadataName))

	path := filepath.Join(dir, "api_conversation_history.json")
	res, err := New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("surfaces = %d want 1", len(res.SessionSurfaces))
	}
	s := res.SessionSurfaces[0]
	if s.SessionID != "1780707193341" {
		t.Errorf("surface session = %q", s.SessionID)
	}
	if s.Surface != models.SurfaceIDE {
		t.Errorf("surface = %q want %q", s.Surface, models.SurfaceIDE)
	}
	if s.SurfaceHost != "vscode" {
		t.Errorf("surface host = %q want vscode", s.SurfaceHost)
	}
	// Every emitted row inherits the newest model_usage entry — the
	// fixture's messages carry no per-message model at all.
	if len(res.ToolEvents) == 0 {
		t.Fatal("no tool events")
	}
	for _, e := range res.ToolEvents {
		if e.Model != "anthropic/claude-sonnet-4" {
			t.Errorf("%s model = %q want anthropic/claude-sonnet-4", e.RawToolName, e.Model)
		}
	}
}

// TestParseWithoutTaskMetadataStillStampsSurface pins the pre-metadata
// build: no sibling file ⇒ still an IDE stamp (this parser only ever
// reads an editor extension's storage), host from the path when the
// path names a product and otherwise UNSTAMPED (the fixture lives in a
// t.TempDir(), which names none) — never a fabricated "vscode".
func TestParseWithoutTaskMetadataStillStampsSurface(t *testing.T) {
	t.Parallel()
	path := copyFixture(t, "no-meta-task")
	res, err := New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("surfaces = %d want 1", len(res.SessionSurfaces))
	}
	if res.SessionSurfaces[0].Surface != models.SurfaceIDE {
		t.Errorf("surface = %q", res.SessionSurfaces[0].Surface)
	}
	if res.SessionSurfaces[0].SurfaceHost != "" {
		t.Errorf("host = %q want empty (no grounded host signal)", res.SessionSurfaces[0].SurfaceHost)
	}
	if defaultSurfaceHost != "" {
		t.Errorf("defaultSurfaceHost = %q — the no-signal fallback must stay the honest empty token", defaultSurfaceHost)
	}
}

// copyTestdata copies one testdata/cline/<name> file to dst.
func copyTestdata(t *testing.T, name, dst string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "cline", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
