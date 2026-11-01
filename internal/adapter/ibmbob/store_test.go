package ibmbob

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

func TestDefaultRoots(t *testing.T) {
	orig := allHomesFunc
	defer func() { allHomesFunc = orig }()

	native := filepath.Join(t.TempDir(), "native")
	foreign := filepath.Join(t.TempDir(), "foreign")
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: native, OS: crossmount.OSLinux, Origin: "native"},
			{Path: foreign, OS: crossmount.OSWindows, Origin: "wsl-mnt:c"},
			{Path: native, OS: crossmount.OSLinux, Origin: "native"}, // duplicate
			{Path: "", OS: crossmount.OSLinux, Origin: "native"},     // empty
		}
	}
	got := defaultRoots()
	want := []string{
		filepath.Join(native, ".bob", "db"),
		filepath.Join(foreign, ".bob", "db"),
	}
	if len(got) != len(want) {
		t.Fatalf("defaultRoots = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("root %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestResolveDBPath(t *testing.T) {
	dir := filepath.Join("x", ".bob", "db")
	main := filepath.Join(dir, "bob.db")
	cases := []struct {
		in, want string
	}{
		{main, main},
		{filepath.Join(dir, "bob.db-wal"), main},
		{filepath.Join(dir, "bob.db-shm"), main},
	}
	for _, c := range cases {
		if got := resolveDBPath(c.in); got != c.want {
			t.Errorf("resolveDBPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsForeignMountPathAndMirror(t *testing.T) {
	orig := allHomesFunc
	defer func() { allHomesFunc = orig }()

	nativeHome := filepath.Join(t.TempDir(), "native")
	foreignHome := t.TempDir()
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: nativeHome, OS: crossmount.OSLinux, Origin: "native"},
			{Path: foreignHome, OS: crossmount.OSWindows, Origin: "wsl-mnt:c"},
		}
	}

	if p := filepath.Join(nativeHome, ".bob", "db", "bob.db"); isForeignMountPath(p) {
		t.Errorf("native path %q classified foreign", p)
	}
	srcDB := filepath.Join(foreignHome, ".bob", "db", "bob.db")
	if !isForeignMountPath(srcDB) {
		t.Fatalf("foreign path %q not classified foreign", srcDB)
	}

	// Staging itself (a filtered mirror, never a byte copy) is pinned by
	// TestForeignMirrorKeepsOnlyAllowListedTables (RB1 sweep finding A2).
}

func TestMapTool(t *testing.T) {
	cases := []struct {
		name, args, wantAction, wantTarget string
	}{
		{"execute_command", `{"command":"ls -la","cwd":"/p"}`, models.ActionRunCommand, "ls -la"},
		{"read_file", `{"path":"a.go"}`, models.ActionReadFile, "a.go"},
		{"office_read", `{"path":"r.docx","mode":"text"}`, models.ActionReadFile, "r.docx"},
		{"write_file", `{"path":"b.go","content":"x"}`, models.ActionWriteFile, "b.go"},
		{"apply_diff", `{"path":"c.go","diff":"@@"}`, models.ActionEditFile, "c.go"},
		{"insert_content", `{"path":"d.go","line":1,"content":"y"}`, models.ActionEditFile, "d.go"},
		{"search_and_replace", `{"path":"e.go","search":"a","replace":"b"}`, models.ActionEditFile, "e.go"},
		{"office_edit", `{"path":"s.xlsx","operation":"set"}`, models.ActionEditFile, "s.xlsx"},
		{"list_files", `{"path":"src","recursive":true}`, models.ActionSearchFiles, "src"},
		{"glob", `{"pattern":"**/*.go","path":"."}`, models.ActionSearchFiles, "**/*.go"},
		{"grep", `{"pattern":"TODO","path":"."}`, models.ActionSearchText, "TODO"},
		{"web_fetch", `{"url":"https://example.com","format":"markdown"}`, models.ActionWebFetch, "https://example.com"},
		{"web_search", `{"query":"go generics"}`, models.ActionWebSearch, "go generics"},
		{"search_ibm_docs", `{"query":"mq queues","library_name":"mq"}`, models.ActionWebSearch, "mq queues"},
		{"update_todo_list", `{"todos":"[ ] a"}`, models.ActionTodoUpdate, "update_todo_list"},
		{"spawn_subagent", `{"description":"look","name":"general"}`, models.ActionSpawnSubagent, "look"},
		{"use_skill", `{"skill_name":"pdf"}`, models.ActionSkillInvoke, "pdf"},
		{"switch_mode", `{"mode_id":"plan"}`, models.ActionHarnessCall, "plan"},
		{"list_ibm_doc_libraries", `{}`, models.ActionHarnessCall, "list_ibm_doc_libraries"},
		{"mcp__docs__lookup", `{"q":"x"}`, models.ActionMCPCall, "mcp__docs__lookup"},
		{"Execute_Command", `{"command":"pwd"}`, models.ActionRunCommand, "pwd"},
		{"brand_new_tool", `{"path":"z"}`, models.ActionUnknown, "z"},
		{"brand_new_tool", ``, models.ActionUnknown, "brand_new_tool"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotAction, gotTarget := mapTool(c.name, []byte(c.args))
			if gotAction != c.wantAction || gotTarget != c.wantTarget {
				t.Errorf("mapTool(%q) = (%q, %q), want (%q, %q)", c.name, gotAction, gotTarget, c.wantAction, c.wantTarget)
			}
		})
	}
}

func TestAuthoredBytes(t *testing.T) {
	cases := []struct {
		name, args string
		want       int64
	}{
		{"write_file", `{"path":"a","content":"hello"}`, 5},
		{"insert_content", `{"path":"a","line":3,"content":"abc"}`, 3},
		{"search_and_replace", `{"path":"a","search":"x","replace":"yy"}`, 2},
		{"apply_diff", `{"path":"a","diff":"@@ -1 +1 @@"}`, 0},
		{"execute_command", `{"command":"echo hi"}`, 0},
	}
	for _, c := range cases {
		if got := authoredBytes(c.name, []byte(c.args)); got != c.want {
			t.Errorf("authoredBytes(%q) = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestModelID(t *testing.T) {
	cases := []struct {
		raw, want string
	}{
		{`{"id":"premium-ide","contextWindow":270000}`, "premium-ide"},
		{`"premium-ide"`, "premium-ide"},
		{``, ""},
		{`42`, ""},
	}
	for _, c := range cases {
		if got := modelID(json.RawMessage(c.raw)); got != c.want {
			t.Errorf("modelID(%s) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestWorkspaceOf(t *testing.T) {
	cases := []struct {
		name      string
		env       taskEnv
		projectID string
		want      string
	}{
		{"env workspace wins", taskEnv{Workspace: "/home/user/p"}, "file:/elsewhere", "/home/user/p"},
		{"posix project_id", taskEnv{}, "file:/home/user/p", "/home/user/p"},
		{"windows project_id", taskEnv{}, `file:C:\Users\user\p`, `C:\Users\user\p`},
		{"uri project_id left for the normalizer", taskEnv{}, "file:///home/user/p", "file:///home/user/p"},
		{"empty", taskEnv{}, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := workspaceOf(c.env, c.projectID); got != c.want {
				t.Errorf("workspaceOf = %q, want %q", got, c.want)
			}
		})
	}
}

func TestContentText(t *testing.T) {
	cases := []struct {
		raw, want string
	}{
		{`"plain"`, "plain"},
		{`[{"type":"text","text":"a"},{"type":"image","image":"x"},{"type":"text","text":"b"}]`, "a\nb"},
		{`[]`, ""},
		{``, ""},
		{`{"weird":true}`, ""},
	}
	for _, c := range cases {
		if got := contentText(json.RawMessage(c.raw)); got != c.want {
			t.Errorf("contentText(%s) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestResolveProjectRootFallback(t *testing.T) {
	a := NewWithOptions(nil, []string{fixtureRoot})
	if root, remote, _ := a.resolveProjectRoot("  "); root != fallbackProjectRoot || remote != "" {
		t.Errorf("empty workspace = (%q, %q), want (%q, \"\")", root, remote, fallbackProjectRoot)
	}
	// An unreachable path is returned as-is (never CWD-prefixed).
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if root, _, _ := a.resolveProjectRoot(missing); filepath.ToSlash(root) != filepath.ToSlash(missing) {
		t.Errorf("missing workspace root = %q, want %q", root, missing)
	}
}
