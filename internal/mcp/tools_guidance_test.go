package mcp

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guidance"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedGuidance records one scan against a real directory so the content path
// has something to read. Returns the project root.
func seedGuidance(t *testing.T, database *sql.DB) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "CLAUDE.md"),
		[]byte("# House rules\nAWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLEKEY123456789\n"), 0o600); err != nil {
		t.Fatalf("write CLAUDE.md: %v", err)
	}
	skillDir := filepath.Join(root, ".claude", "skills", "deploy")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: deploy\n---\nship it\n"), 0o600); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}
	files := []guidance.File{
		{
			Tool: "claude-code", Kind: guidance.KindInstructions, Scope: guidance.ScopeProject,
			RelPath: "CLAUDE.md", AbsPath: filepath.Join(root, "CLAUDE.md"),
			Name: "CLAUDE.md", SizeBytes: 70, ModTime: time.Now().UTC().Add(-time.Minute),
			ContentHash: "h1",
		},
		{
			Tool: "claude-code", Kind: guidance.KindSkill, Scope: guidance.ScopeProject,
			RelPath: filepath.ToSlash(filepath.Join(".claude", "skills", "deploy", "SKILL.md")),
			AbsPath: filepath.Join(skillDir, "SKILL.md"),
			Name:    "deploy", Description: "ship it", SizeBytes: 30,
			ModTime: time.Now().UTC().Add(-time.Minute), ContentHash: "h2",
			Frontmatter: map[string]string{"name": "deploy"},
		},
		{
			Tool: "cursor", Kind: guidance.KindRule, Scope: guidance.ScopeProject,
			RelPath: filepath.ToSlash(filepath.Join(".cursor", "rules", "style.mdc")),
			AbsPath: filepath.Join(root, ".cursor", "rules", "style.mdc"),
			Name:    "style", SizeBytes: 12, ModTime: time.Now().UTC().Add(-time.Minute),
			ContentHash: "h3",
		},
	}
	if _, err := store.New(database).UpsertGuidanceScan(context.Background(), root, files, time.Now().UTC()); err != nil {
		t.Fatalf("UpsertGuidanceScan: %v", err)
	}
	return root
}

// TestGetProjectGuidance_Inventory covers the default (metadata-only) call.
func TestGetProjectGuidance_Inventory(t *testing.T) {
	s, database, _ := testServer(t)
	root := seedGuidance(t, database)

	out := callTool(t, s, "get_project_guidance", map[string]any{"project_root": root})
	if out["project_root"] != root {
		t.Errorf("project_root = %v, want %q", out["project_root"], root)
	}
	if int(out["count"].(float64)) != 3 {
		t.Fatalf("count = %v, want 3", out["count"])
	}
	files := out["files"].([]any)
	first := files[0].(map[string]any)
	// Sorted by tool then kind: claude-code/instructions precedes
	// claude-code/skill precedes cursor/rule.
	if first["tool"] != "claude-code" || first["kind"] != "instructions" {
		t.Errorf("first file = %v/%v, want claude-code/instructions", first["tool"], first["kind"])
	}
	// Metadata-only: no body unless asked.
	if _, ok := first["content"]; ok {
		t.Error("content returned without include_content")
	}
	if scrubbed, _ := out["content_scrubbed"].(bool); scrubbed {
		t.Error("content_scrubbed = true on a metadata-only call")
	}
}

// TestGetProjectGuidance_Filters is the table-driven pin over the tool/kind
// narrowing arguments.
func TestGetProjectGuidance_Filters(t *testing.T) {
	s, database, _ := testServer(t)
	root := seedGuidance(t, database)

	cases := []struct {
		name  string
		args  map[string]any
		count int
	}{
		{name: "no filter", args: map[string]any{"project_root": root}, count: 3},
		{name: "by tool", args: map[string]any{"project_root": root, "tool": "cursor"}, count: 1},
		{name: "by kind", args: map[string]any{"project_root": root, "kind": "skill"}, count: 1},
		{name: "tool and kind", args: map[string]any{"project_root": root, "tool": "claude-code", "kind": "instructions"}, count: 1},
		{name: "no match", args: map[string]any{"project_root": root, "tool": "no-such-tool"}, count: 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			out := callTool(t, s, "get_project_guidance", tc.args)
			if got := int(out["count"].(float64)); got != tc.count {
				t.Errorf("count = %d, want %d", got, tc.count)
			}
		})
	}
}

// TestGetProjectGuidance_Content covers include_content: the body comes back,
// it is scrubbed, and a row whose file is gone carries a reason instead of an
// empty string.
func TestGetProjectGuidance_Content(t *testing.T) {
	s, database, _ := testServer(t)
	root := seedGuidance(t, database)

	out := callTool(t, s, "get_project_guidance", map[string]any{
		"project_root":    root,
		"kind":            "instructions",
		"include_content": true,
	})
	if scrubbed, _ := out["content_scrubbed"].(bool); !scrubbed {
		t.Error("content_scrubbed = false — the tool has no raw mode")
	}
	files := out["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("files = %d, want 1", len(files))
	}
	body, _ := files[0].(map[string]any)["content"].(string)
	if !strings.Contains(body, "# House rules") {
		t.Errorf("body lost the prose: %q", body)
	}
	if strings.Contains(body, "AKIAIOSFODNN7EXAMPLEKEY123456789") {
		t.Errorf("the secret survived the scrub: %q", body)
	}
}

// TestGetProjectGuidance_UnknownRoot is the honesty pin: an unscanned root is
// never walked, it is explained.
func TestGetProjectGuidance_UnknownRoot(t *testing.T) {
	s, database, _ := testServer(t)
	seedGuidance(t, database)

	out := callTool(t, s, "get_project_guidance", map[string]any{
		"project_root": filepath.Join(t.TempDir(), "elsewhere"),
	})
	if int(out["count"].(float64)) != 0 {
		t.Errorf("count = %v, want 0", out["count"])
	}
	note, _ := out["note"].(string)
	if !strings.Contains(note, "no guidance inventory") {
		t.Errorf("note = %q, want an honest explanation naming the scanned roots", note)
	}
}

// TestGetProjectGuidance_NothingScanned covers the fresh-install answer: an
// empty array plus a note pointing at the scan command, never an error.
func TestGetProjectGuidance_NothingScanned(t *testing.T) {
	s, _, _ := testServer(t)
	out := callTool(t, s, "get_project_guidance", map[string]any{})
	if int(out["count"].(float64)) != 0 {
		t.Errorf("count = %v, want 0", out["count"])
	}
	if note, _ := out["note"].(string); !strings.Contains(note, "guidance scan") {
		t.Errorf("note = %q, want a pointer at `observer guidance scan`", note)
	}
}

// TestResolveGuidanceRoot is the table-driven unit over the root-resolution
// ladder, including the nearest-ancestor rule the cwd default relies on.
func TestResolveGuidanceRoot(t *testing.T) {
	known := []string{"/repo", "/repo/sub"}
	cases := []struct {
		name      string
		requested string
		wantRoot  string
		wantNote  string
	}{
		{name: "exact known", requested: "/repo", wantRoot: "/repo"},
		{name: "nested known", requested: "/repo/sub", wantRoot: "/repo/sub"},
		{name: "trailing slash cleaned", requested: "/repo/", wantRoot: "/repo"},
		{name: "unknown", requested: "/elsewhere", wantNote: "no guidance inventory"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			root, note := resolveGuidanceRoot(tc.requested, known)
			if root != tc.wantRoot {
				t.Errorf("root = %q, want %q", root, tc.wantRoot)
			}
			if tc.wantNote != "" && !strings.Contains(note, tc.wantNote) {
				t.Errorf("note = %q, want it to contain %q", note, tc.wantNote)
			}
			if tc.wantNote == "" && note != "" {
				t.Errorf("unexpected note %q", note)
			}
		})
	}

	t.Run("nothing scanned", func(t *testing.T) {
		root, note := resolveGuidanceRoot("/repo", nil)
		if root != "" {
			t.Errorf("root = %q, want empty", root)
		}
		if !strings.Contains(note, "guidance scan") {
			t.Errorf("note = %q", note)
		}
	})
}
