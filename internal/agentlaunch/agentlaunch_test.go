package agentlaunch

import (
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// TestWorkspaceSourcesMatchWorkspacePackage pins the closed source
// vocabulary to internal/workspace, the owner of the sources.
func TestWorkspaceSourcesMatchWorkspacePackage(t *testing.T) {
	for got, want := range map[string]workspace.Source{
		WorkspaceLive:        workspace.SourceLive,
		WorkspaceCloneLocal:  workspace.SourceCloneLocal,
		WorkspaceCloneRemote: workspace.SourceCloneRemote,
		WorkspaceWorktree:    workspace.SourceWorktree,
	} {
		if got != string(want) {
			t.Errorf("agentlaunch %q != workspace %q", got, want)
		}
	}
}

func base() Request {
	return Request{Tool: "claude", Project: "/home/dev/repo"}
}

// TestNormalizeRows walks the validation table: one case per row, plus the
// accepted shapes.
func TestNormalizeRows(t *testing.T) {
	cases := []struct {
		name    string
		mut     func(*Request)
		code    string
		field   string
		check   func(t *testing.T, n Normalized)
		wantErr string
	}{
		{name: "V1 missing tool", mut: func(r *Request) { r.Tool = " " }, code: CodeInvalid, field: "tool"},
		{name: "V2 unknown tool", mut: func(r *Request) { r.Tool = "no-such-tool" }, code: CodeNotLaunchable, field: "tool"},
		{name: "V3 relative project", mut: func(r *Request) { r.Project = "repo" }, code: CodeInvalid, field: "project"},
		{name: "V3 empty project", mut: func(r *Request) { r.Project = "" }, code: CodeInvalid, field: "project"},
		{name: "V3 control char", mut: func(r *Request) { r.Project = "/home/dev/re\npo" }, code: CodeInvalid, field: "project"},
		{name: "V4 bad backend spelling", mut: func(r *Request) { r.Sandbox = "Bwrap;rm" }, code: CodeInvalid, field: "sandbox"},
		{name: "V4 leading dash", mut: func(r *Request) { r.Sandbox = "-x" }, code: CodeInvalid, field: "sandbox"},
		{name: "V5 unknown workspace", mut: func(r *Request) { r.Workspace = "copy" }, code: CodeInvalid, field: "workspace"},
		{name: "V6 clone without sandbox", mut: func(r *Request) { r.Workspace = WorkspaceCloneLocal }, code: CodeInvalid, field: "workspace"},
		{name: "V7 clone-remote without remote", mut: func(r *Request) { r.Sandbox, r.Workspace = "auto", WorkspaceCloneRemote }, code: CodeInvalid, field: "remote"},
		{name: "V7 remote without clone-remote", mut: func(r *Request) { r.Sandbox, r.Workspace, r.Remote = "auto", WorkspaceCloneLocal, "https://x/y.git" }, code: CodeInvalid, field: "remote"},
		{name: "V7 remote option injection", mut: func(r *Request) {
			r.Sandbox, r.Workspace, r.Remote = "auto", WorkspaceCloneRemote, "--upload-pack=evil"
		}, code: CodeInvalid, field: "remote"},
		{name: "V8 branch on live", mut: func(r *Request) { r.Branch = "main" }, code: CodeInvalid, field: "branch"},
		{name: "V8 branch with space", mut: func(r *Request) { r.Sandbox, r.Workspace, r.Branch = "auto", WorkspaceWorktree, "a b" }, code: CodeInvalid, field: "branch"},
		{name: "V7 ext transport", mut: func(r *Request) {
			r.Sandbox, r.Workspace, r.Remote = "auto", WorkspaceCloneRemote, "ext::sh -c touch% /tmp/x"
		}, code: CodeInvalid, field: "remote"},
		{name: "V7 file remote", mut: func(r *Request) {
			r.Sandbox, r.Workspace, r.Remote = "auto", WorkspaceCloneRemote, "file:///etc"
		}, code: CodeInvalid, field: "remote"},
		{name: "V7 scp form accepted", mut: func(r *Request) {
			r.Sandbox, r.Workspace, r.Remote = "auto", WorkspaceCloneRemote, "git@github.com:org/repo.git"
		}, check: func(t *testing.T, n Normalized) {
			if n.Remote != "git@github.com:org/repo.git" {
				t.Fatalf("got %+v", n)
			}
		}},
		{name: "V8 branch with a slash", mut: func(r *Request) { r.Sandbox, r.Workspace, r.Branch = "auto", WorkspaceCloneLocal, "feature/x" }, code: CodeInvalid, field: "branch"},
		{name: "V8 worktree label with a slash", mut: func(r *Request) { r.Sandbox, r.Workspace, r.Branch = "auto", WorkspaceWorktree, "feature/x" }, code: CodeInvalid, field: "branch"},
		{name: "V8 branch with dots", mut: func(r *Request) { r.Sandbox, r.Workspace, r.Branch = "auto", WorkspaceCloneLocal, "a..b" }, code: CodeInvalid, field: "branch"},
		{name: "V8 branch ending in .lock", mut: func(r *Request) { r.Sandbox, r.Workspace, r.Branch = "auto", WorkspaceWorktree, "work.lock" }, code: CodeInvalid, field: "branch"},
		{name: "V8 plain branch accepted", mut: func(r *Request) { r.Sandbox, r.Workspace, r.Branch = "auto", WorkspaceWorktree, "fix-123" }, check: func(t *testing.T, n Normalized) {
			if n.Branch != "fix-123" {
				t.Fatalf("got %+v", n)
			}
		}},
		{name: "V9 model option", mut: func(r *Request) { r.Model = "-m" }, code: CodeInvalid, field: "model"},
		{name: "V9 model too long", mut: func(r *Request) { r.Model = strings.Repeat("a", maxFieldLen+1) }, code: CodeInvalid, field: "model"},
		{name: "verb resolves to tool", mut: func(*Request) {}, check: func(t *testing.T, n Normalized) {
			if n.Tool != "claude-code" || n.Subcommand != "claude" || n.Sandboxed || n.Workspace != WorkspaceLive {
				t.Fatalf("got %+v", n)
			}
		}},
		{name: "tool id accepted", mut: func(r *Request) { r.Tool = "claude-code"; r.Project = "/home/dev/repo/" }, check: func(t *testing.T, n Normalized) {
			if n.Tool != "claude-code" || n.Project != "/home/dev/repo" {
				t.Fatalf("got %+v", n)
			}
		}},
		{name: "none is unsandboxed", mut: func(r *Request) { r.Sandbox = SandboxNone }, check: func(t *testing.T, n Normalized) {
			if n.Sandboxed || n.Auto || n.Backend != "" {
				t.Fatalf("got %+v", n)
			}
		}},
		{name: "auto", mut: func(r *Request) { r.Sandbox = SandboxAuto }, check: func(t *testing.T, n Normalized) {
			if !n.Sandboxed || !n.Auto || n.Backend != "" {
				t.Fatalf("got %+v", n)
			}
		}},
		{name: "explicit clone-remote with branch", mut: func(r *Request) {
			r.Sandbox, r.Workspace, r.Remote, r.Branch, r.Model = "oci-runc", WorkspaceCloneRemote, "https://example.com/r.git", "feature-x", "opus"
		}, check: func(t *testing.T, n Normalized) {
			if !n.Sandboxed || n.Auto || n.Backend != "oci-runc" || n.Remote == "" || n.Branch != "feature-x" || n.Model != "opus" {
				t.Fatalf("got %+v", n)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			tc.mut(&r)
			n, err := Normalize(r)
			if tc.code != "" {
				var e *Error
				if err == nil {
					t.Fatalf("want refusal %s, got %+v", tc.code, n)
				}
				if CodeOf(err) != tc.code {
					t.Fatalf("code = %q, want %q (%v)", CodeOf(err), tc.code, err)
				}
				if !errors.As(err, &e) {
					t.Fatalf("not an *Error: %v", err)
				}
				if e.Field != tc.field {
					t.Fatalf("field = %q, want %q", e.Field, tc.field)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
			tc.check(t, n)
		})
	}
}

// TestNormalizeRowIDsUnique keeps the table's row ids unique.
func TestNormalizeRowIDsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range validationRows {
		if seen[r.id] {
			t.Fatalf("duplicate row %s", r.id)
		}
		seen[r.id] = true
	}
	for _, r := range choiceRows {
		if seen[r.id] {
			t.Fatalf("duplicate row %s", r.id)
		}
		seen[r.id] = true
	}
}

// TestResolveToolRefusesUnlaunchable checks an unknown name and an empty
// name are refused by the registry predicate.
func TestResolveToolRefusesUnlaunchable(t *testing.T) {
	for _, name := range []string{"", "definitely-not-a-tool"} {
		if _, _, ok := ResolveTool(name); ok {
			t.Errorf("%q resolved", name)
		}
	}
}

func TestCodeOfNil(t *testing.T) {
	if CodeOf(nil) != "" {
		t.Fatal("nil error has a code")
	}
}
