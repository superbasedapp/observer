package main

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// samePath compares two paths the way this host's filesystem does.
func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// TestHookIngestIdentity: a hook event's working directory is filed under
// the root the watcher records for it: the main repository inside a linked
// worktree (F0-14), the top level inside a subdirectory. Outside a git tree,
// and for a root that is no path on this host, the event keeps its root.
func TestHookIngestIdentity(t *testing.T) {
	mainRoot, wtRoot := linkedWorktreeFixture(t)
	wtSub := filepath.Join(wtRoot, "web")
	mainSub := filepath.Join(mainRoot, "docs")
	for _, d := range []string{wtSub, mainSub} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	plain := t.TempDir()
	cases := []struct {
		name     string
		root     string
		ok       bool
		want     string
		worktree bool
	}{
		{"linked worktree checkout", wtRoot, true, mainRoot, true},
		{"subdirectory of a linked worktree", wtSub, true, mainRoot, true},
		{"subdirectory of the main repository", mainSub, true, mainRoot, false},
		{"the main repository itself", mainRoot, true, mainRoot, false},
		{"not a git tree", plain, false, "", false},
		{"per-tool placeholder", "[cursor]", false, "", false},
		{"empty", "", false, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := hookIngestIdentity(tc.root)
			if ok != tc.ok {
				t.Fatalf("hookIngestIdentity(%q) ok = %v, want %v (%+v)", tc.root, ok, tc.ok, id)
			}
			if !ok {
				if got := hookIngestRootOf(tc.root); got != tc.root {
					t.Errorf("hookIngestRootOf(%q) = %q, want it unchanged", tc.root, got)
				}
				return
			}
			if !samePath(id.Root, tc.want) || id.IsWorktree != tc.worktree {
				t.Errorf("hookIngestIdentity(%q) = root %q worktree %v, want %q %v", tc.root, id.Root, id.IsWorktree, tc.want, tc.worktree)
			}
			if got := hookIngestRootOf(tc.root); !samePath(got, tc.want) {
				t.Errorf("hookIngestRootOf(%q) = %q, want %q", tc.root, got, tc.want)
			}
		})
	}
}

// TestDaemonIngestRootResolver: the daemon's cached resolver gives the same
// answers as the hook rule, from many goroutines at once (the watcher and
// the OTLP receiver share the shape), and keeps giving them from its cache.
func TestDaemonIngestRootResolver(t *testing.T) {
	mainRoot, wtRoot := linkedWorktreeFixture(t)
	plain := t.TempDir()
	resolve := daemonIngestRootResolver()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				id, ok := resolve(wtRoot)
				if !ok || !samePath(id.Root, mainRoot) || !id.IsWorktree {
					t.Errorf("resolve(worktree) = %q worktree=%v ok=%v, want %q", id.Root, id.IsWorktree, ok, mainRoot)
					return
				}
				if _, ok := resolve(plain); ok {
					t.Error("resolve(plain folder) ok, want not a git tree")
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestClaudeCodeHookFilesWorktreeUnderMainProject drives the real Claude Code
// hook handler from inside a linked worktree's subdirectory: the session and
// its row land on the main repository's project, the one the watcher files
// the same session under, never a project of the worktree's own (live
// 2026-11-07: every hook moved a worktree session back to its own project).
func TestClaudeCodeHookFilesWorktreeUnderMainProject(t *testing.T) {
	mainRoot, wtRoot := linkedWorktreeFixture(t)
	cwd := filepath.Join(wtRoot, "web")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := cloudSessionFixture(t)
	t.Setenv("CLAUDE_CODE_REMOTE", "")
	cwdJSON, err := json.Marshal(cwd)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"session_id":"sess-wt","transcript_path":"/tmp/t.jsonl","cwd":` + string(cwdJSON) + `,"hook_event_name":"Stop","last_assistant_message":"Done."}`
	ctx := context.Background()
	var reply bytes.Buffer
	old := hookStdout
	hookStdout = &reply
	t.Cleanup(func() { hookStdout = old })
	handleClaudeCodeActionEvent(ctx, strings.NewReader(body), "claude-code:stop", cfg, buildClaudeStopEvent)

	database, err := db.Open(ctx, db.Options{Path: filepath.Join(filepath.Dir(cfg), "observer.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var sessionRoot string
	var worktree bool
	if err := database.QueryRowContext(ctx,
		`SELECT p.root_path, s.is_worktree FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = 'sess-wt'`).Scan(&sessionRoot, &worktree); err != nil {
		t.Fatalf("session row not created by the hook: %v", err)
	}
	if !samePath(sessionRoot, mainRoot) {
		t.Errorf("session filed under %q, want the main repository %q", sessionRoot, mainRoot)
	}
	if !worktree {
		t.Error("sessions.is_worktree = false, want true for a linked worktree's session")
	}
	var others int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions a JOIN projects p ON p.id = a.project_id WHERE a.session_id = 'sess-wt' AND p.root_path <> ?`, sessionRoot).Scan(&others); err != nil {
		t.Fatal(err)
	}
	if others != 0 {
		t.Errorf("%d hook rows filed under another project", others)
	}
}

// TestHookIngestSitesResolveRoots pins the seam: in the hook files no store
// that ingests is built by store.New, so every hook row goes through
// hookIngestStore's root resolver (directly, or via hookCaptureStore). A
// direct store.New(...).Ingest(...), a store.New(...) handed to an
// internal/hook receiver (which ingests through it), and a variable built by
// store.New whose Ingest is called all fail.
func TestHookIngestSitesResolveRoots(t *testing.T) {
	files, err := filepath.Glob("hook*.go")
	if err != nil {
		t.Fatal(err)
	}
	isStoreNew := func(e ast.Expr) bool {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		pkg, ok := sel.X.(*ast.Ident)
		return ok && pkg.Name == "store" && sel.Sel.Name == "New"
	}
	fset := token.NewFileSet()
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			fromStoreNew := map[string]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.AssignStmt:
					for i, rhs := range n.Rhs {
						if i < len(n.Lhs) && isStoreNew(rhs) {
							if id, ok := n.Lhs[i].(*ast.Ident); ok {
								fromStoreNew[id.Name] = true
							}
						}
					}
				case *ast.CallExpr:
					if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
						if sel.Sel.Name == "Ingest" {
							if isStoreNew(sel.X) {
								t.Errorf("%s: store.New(...).Ingest in %s: build the store with hookIngestStore", fset.Position(n.Pos()), fn.Name.Name)
							}
							if id, ok := sel.X.(*ast.Ident); ok && fromStoreNew[id.Name] {
								t.Errorf("%s: %s.Ingest on a store.New store in %s: build it with hookIngestStore", fset.Position(n.Pos()), id.Name, fn.Name.Name)
							}
						}
						if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "hook" {
							for _, arg := range n.Args {
								if isStoreNew(arg) {
									t.Errorf("%s: store.New(...) handed to hook.%s in %s: pass hookIngestStore", fset.Position(arg.Pos()), sel.Sel.Name, fn.Name.Name)
								}
							}
						}
					}
				}
				return true
			})
		}
	}
	if checked == 0 {
		t.Fatal("no hook files found to check")
	}
}
