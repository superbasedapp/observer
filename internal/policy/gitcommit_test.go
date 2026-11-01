package policy

import (
	"reflect"
	"testing"
)

// TestClassifyCommitShellTable is one case per shell-table row and per
// JSP-6 corpus line the sink must add (security plan section 4.7 item 4).
func TestClassifyCommitShellTable(t *testing.T) {
	cases := []struct {
		name    string
		cmd     string
		dialect Dialect
		want    []string
	}{
		{"plain commit", "git commit -m wip", "", []string{"commit"}},
		{"commit-tree", "git commit-tree HEAD^{tree} -p HEAD -m wip", "", []string{"commit_tree"}},
		{"update-ref", "git update-ref refs/heads/main 0123456789abcdef0123456789abcdef01234567", "", []string{"update_ref"}},
		{"plumbing pair", "c=$(git commit-tree HEAD^{tree} -p HEAD -m x) && git update-ref refs/heads/main $c", "", []string{"update_ref", "commit_tree"}},
		{"merge", "git merge feature", "", []string{"merge"}},
		{"merge abort", "git merge --abort", "", nil},
		{"cherry-pick", "git cherry-pick abc123", "", []string{"cherry_pick"}},
		{"cherry-pick quit", "git cherry-pick --quit", "", nil},
		{"am", "git am < p.patch", "", []string{"am"}},
		{"rebase", "git rebase main", "", []string{"rebase"}},
		{"rebase exec", `git rebase --exec "make" main`, "", []string{"rebase"}},
		{"revert", "git revert HEAD", "", []string{"revert"}},
		{"stash", "git stash", "", []string{"stash"}},
		{"stash push", "git stash push -m x", "", []string{"stash"}},
		{"stash list", "git stash list", "", nil},
		{"push", "git push origin main", "", []string{"push"}},
		{"push dry run", "git push --dry-run origin main", "", nil},
		// RB1 sweep H1: a later negation cancels a skip option, and an
		// abbreviated value option takes the next word (git 2.43 writes
		// for every one of these).
		{"commit dry run negated", "git commit -am x --dry-run --no-dry-run", "", []string{"commit"}},
		{"commit dry run negated abbreviated", "git commit -am x --dry-run --no-dry", "", []string{"commit"}},
		{"commit dry run after negation", "git commit -am x --no-dry-run --dry-run", "", nil},
		{"commit abbreviated message", "git commit -a --mes --dry-run", "", []string{"commit"}},
		{"push dry run negated", "git push --dry-run --no-dry-run origin main", "", []string{"push"}},
		{"merge abort negated", "git merge --abort --no-abort topic", "", []string{"merge"}},
		{"merge quit negated", "git merge --quit --no-quit topic", "", []string{"merge"}},
		{"merge abbreviated message", "git merge --mes --abort topic", "", []string{"merge"}},
		{"pull dry run negated", "git pull --dry-run --no-dry-run origin main", "", []string{"merge"}},
		{"gh pr merge", "gh pr merge 1 --merge", "", []string{"gh_pr_merge"}},
		{"gh api put contents", "gh api -X PUT repos/o/r/contents/a.txt -f message=x -f content=eA==", "", []string{"gh_api_write"}},
		{"gh api implied post", "gh api repos/o/r/git/refs -f ref=refs/heads/x -f sha=abc", "", []string{"gh_api_write"}},
		{"gh api get", "gh api repos/o/r/contents/a.txt", "", nil},
		{"gh pr list", "gh pr list", "", nil},
		{"git -C", "git -C sub commit -m wip", "", []string{"commit"}},
		{"git-dir", "git --git-dir=/r/.git commit -m wip", "", []string{"commit"}},
		{"nested bash", `bash -c "git commit -m wip"`, "", []string{"commit"}},
		{"nested sh cd", "sh -c 'cd sub && git commit -n -m wip'", "", []string{"commit"}},
		{"inline alias", `git config alias.ci "commit --no-verify" && git ci -m wip`, "", []string{"commit"}},
		{"-c alias", "git -c alias.ci=commit ci -m wip", "", []string{"commit"}},
		{"status is not a commit", "git status", "", nil},
		{"log is not a commit", "git log --oneline", "", nil},
		{"interpreter residual", `python3 -c "import subprocess; subprocess.run(['git','commit','--no-verify','-m','x'])"`, "", []string{"residual"}},
		{"node residual", `node -e "require('child_process').execSync('git push')"`, "", []string{"residual"}},
		{"interpreter without git", `python3 -c "print(1)"`, "", nil},
		{"package script residual", "npm run release", "", []string{"residual"}},
		{"package script test", "npm run test", "", nil},
		{"powershell joined", "$env:HUSKY='0'; git commit -m wip", DialectPowerShell, []string{"commit"}},
		// SEC-C2 milestone 1f: history writers the first lane missed.
		{"pull merges", "git pull origin main", "", []string{"merge"}},
		{"pull rebase", "git pull --rebase origin main", "", []string{"rebase"}},
		{"pull -r", "git pull -r", "", []string{"rebase"}},
		{"pull rebase false", "git pull --rebase=false", "", []string{"merge"}},
		{"fast-import", "git fast-import < stream.fi", "", []string{"update_ref"}},
		{"filter-branch", "git filter-branch --tree-filter 'rm -f k' HEAD", "", []string{"rebase"}},
		{"filter-repo", "git filter-repo --path secrets.txt --invert-paths", "", []string{"rebase"}},
		{"filter-repo analyze", "git filter-repo --analyze", "", nil},
		{"replace", "git replace 0123456 89abcde", "", []string{"update_ref"}},
		{"replace graft", "git replace --graft HEAD~1", "", []string{"update_ref"}},
		{"replace list", "git replace -l", "", nil},
		{"replace bare", "git replace", "", nil},
		{"gh api graphql commit", `gh api graphql -f query='mutation { createCommitOnBranch(input: $i) { commit { oid } } }'`, "", []string{"gh_api_write"}},
		{"gh api graphql merge", `gh api graphql -f query='mutation { mergePullRequest(input: {pullRequestId: "x"}) { clientMutationId } }'`, "", []string{"gh_api_write"}},
		{"gh api graphql file query", "gh api graphql -F query=@q.graphql", "", []string{"gh_api_write"}},
		{"gh api graphql read", `gh api graphql -f query='query { viewer { login } }'`, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := &Event{Kind: KindShellExec, Target: tc.cmd, Dialect: tc.dialect}
			var got []string
			for _, w := range ClassifyGitWrites(ev) {
				got = append(got, kindOf(w))
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ClassifyGitWrites(%q) = %v, want %v", tc.cmd, got, tc.want)
			}
		})
	}
}

// TestClassifyCommitForm reads the commit form the quick scan covers.
func TestClassifyCommitForm(t *testing.T) {
	cases := []struct {
		cmd  string
		want GitWrite
	}{
		{"git commit -am wip", GitWrite{Form: GitWriteCommit, All: true}},
		{"git commit --all -m wip", GitWrite{Form: GitWriteCommit, All: true}},
		{"git commit -m -a", GitWrite{Form: GitWriteCommit}},
		{"git commit --amend --no-edit", GitWrite{Form: GitWriteCommit, Amend: true}},
		{"git commit -m wip -- a.go b.go", GitWrite{Form: GitWriteCommit, Pathspecs: []string{"a.go", "b.go"}}},
		{"git commit -m wip a.go", GitWrite{Form: GitWriteCommit, Pathspecs: []string{"a.go"}}},
		{"git -C sub commit -m x", GitWrite{Form: GitWriteCommit, Dir: "sub"}},
		{"git --git-dir /r/.git commit -m x", GitWrite{Form: GitWriteCommit, Dir: "/r/.git"}},
		{"git rebase -x 'go test' main", GitWrite{Form: GitWriteRebase, Exec: true}},
		{"git rebase --exec=make main", GitWrite{Form: GitWriteRebase, Exec: true}},
		{"git stash", GitWrite{Form: GitWriteStash, FlagOnly: true}},
		{"git push", GitWrite{Push: true}},
		{"git push origin main", GitWrite{Push: true, PushOperands: []string{"origin", "main"}}},
		{"git push -u origin +feat:main", GitWrite{Push: true, PushOperands: []string{"origin", "+feat:main"}}},
		{"git push --all origin", GitWrite{Push: true, PushOperands: []string{"origin"}, PushOpaque: true}},
		{"git push --tags", GitWrite{Push: true, PushOpaque: true}},
		{"git push -d origin old", GitWrite{Push: true, PushOperands: []string{"origin", "old"}, PushOpaque: true}},
		{"git push --repo=https://example.invalid/r.git", GitWrite{Push: true, PushOpaque: true}},
	}
	for _, tc := range cases {
		got := ClassifyGitWrites(&Event{Kind: KindShellExec, Target: tc.cmd})
		if len(got) != 1 {
			t.Fatalf("%q: %d intents, want 1", tc.cmd, len(got))
		}
		g := got[0]
		if !reflect.DeepEqual(g, tc.want) {
			t.Errorf("%q = %+v, want %+v", tc.cmd, g, tc.want)
		}
	}
}

// TestClassifyCommitRewordings: a denied commit retried in other words
// reaches the same parsed intent (JSP-6 live half, Kilo).
func TestClassifyCommitRewordings(t *testing.T) {
	forms := []string{
		`git commit -m "add feature"`,
		`git commit --message="add the feature, take two"`,
		`git -c user.name=bot commit -qm retry`,
		`cd . && git commit -m x`,
		`GIT_AUTHOR_NAME=x git commit -m y`,
	}
	for _, f := range forms {
		got := ClassifyGitWrites(&Event{Kind: KindShellExec, Target: f})
		if len(got) != 1 || got[0].Form != GitWriteCommit || !GitWriteGates(got[0]) {
			t.Errorf("%q = %+v, want one gating plain commit", f, got)
		}
	}
}

// TestClassifyCommitClineArgv: a pre-split argv (Cline's argv objects
// arrive as Args) classifies the same as the line.
func TestClassifyCommitClineArgv(t *testing.T) {
	got := ClassifyGitWrites(&Event{Kind: KindShellExec, Args: []string{"git", "commit", "-m", "x"}})
	if len(got) != 1 || got[0].Form != GitWriteCommit {
		t.Fatalf("argv = %+v", got)
	}
}

// TestClassifyCommitAliasTable reads the daemon's alias table.
func TestClassifyCommitAliasTable(t *testing.T) {
	cmds := ParseCommand("git save -m x", DialectPosix)
	got := ClassifyCommitCommands(cmds, map[string]string{"save": "commit -a"})
	if len(got) != 1 || got[0].Write.Form != GitWriteCommit || !got[0].Write.All {
		t.Fatalf("alias table = %+v", got)
	}
	got = ClassifyCommitCommands(ParseCommand("git sh", DialectPosix), map[string]string{"sh": "!git push origin HEAD"})
	if len(got) != 1 || !GitWriteIsPush(got[0].Write) {
		t.Fatalf("shell alias = %+v", got)
	}
}

// TestClassifyCommitMCPTable is one case per MCP-table row plus misses.
func TestClassifyCommitMCPTable(t *testing.T) {
	cases := map[string]bool{
		"git_commit":                       true,
		"mcp__github__push_files":          true,
		"github.create_or_update_file":     true,
		"github/merge_pull_request":        true,
		"mcp__github__delete_file":         true,
		"mcp__git__git_merge":              true,
		"mcp__git__git_cherry_pick":        true,
		"mcp__git__git_rebase":             true,
		"mcp__git__git_revert":             true,
		"mcp__forge__create_commit":        true,
		"mcp__github__get_file_contents":   false,
		"mcp__git__git_status":             false,
		"mcp__github__create_pull_request": false,
	}
	for name, want := range cases {
		got := ClassifyGitWrites(&Event{Kind: KindMCPCall, Target: name})
		if (len(got) == 1 && got[0].Form == GitWriteMCP) != want {
			t.Errorf("%q = %+v, want match=%v", name, got, want)
		}
	}
}

// TestClassifyCommitReadsOnlyCommand: the classifier reads Target/Args
// only; a non-shell event whose raw payload restates a commit (Gemini's
// update_topic summary) is never classified.
func TestClassifyCommitReadsOnlyCommand(t *testing.T) {
	ev := &Event{
		Kind:   KindToolCall,
		Target: "update_topic",
		Raw:    []byte(`{"summary":"next I will run git commit -m wip"}`),
	}
	if got := ClassifyGitWrites(ev); len(got) != 0 {
		t.Fatalf("tool_call = %+v, want none", got)
	}
	ev = &Event{Kind: KindShellExec, Target: "ls", Raw: []byte(`git commit -m x`)}
	if got := ClassifyGitWrites(ev); len(got) != 0 {
		t.Fatalf("raw read: %+v", got)
	}
}

// kindOf labels a classified write for the table: its form, or "push", or
// "residual" (an opaque flag-only command).
func kindOf(w GitWrite) string {
	switch {
	case w.Form != "":
		return string(w.Form)
	case GitWriteIsPush(w):
		return "push"
	case w.FlagOnly:
		return "residual"
	}
	return "?"
}

// TestClassifyGitWritesCtxReadsTheAliasTable: the sink's entry reads the
// daemon's per-directory alias table through Config.GitAliases (lane
// SEC-A's table and shell alias cases).
func TestClassifyGitWritesCtxReadsTheAliasTable(t *testing.T) {
	cfg := &Config{Home: "/home/u", GitAliases: func(dir string) (map[string]string, bool) {
		if dir != "/repo" {
			return nil, false
		}
		return map[string]string{"ci": "commit -a", "ship": "!git commit -m x && git push"}, true
	}}
	ctx := func(target string) *MatchContext {
		return &MatchContext{Event: &Event{Kind: KindShellExec, Target: target, Cwd: "/repo", ProjectRoot: "/repo"}, Cfg: cfg}
	}
	if got := GatedGitWrites(ctx("git ci -m x")); !reflect.DeepEqual(got, []GitWrite{{Form: GitWriteCommit, All: true}}) {
		t.Errorf("table alias = %+v", got)
	}
	if got := GatedGitWrites(ctx("git ship")); !reflect.DeepEqual(got, []GitWrite{{Form: GitWriteCommit}}) {
		t.Errorf("shell alias = %+v", got)
	}
	var push bool
	for _, c := range ClassifyGitWritesCtx(ctx("git ship")) {
		push = push || GitWriteIsPush(c.Write)
	}
	if !push {
		t.Error("the shell alias's push is classified as a push")
	}
	if got := GatedGitWrites(ctx("git push origin main")); len(got) != 0 {
		t.Errorf("a push is not a commit: %+v", got)
	}
	if got := GatedGitWrites(ctx("git stash")); len(got) != 0 {
		t.Errorf("a flag-only form is not gated: %+v", got)
	}
	noTable := &MatchContext{Event: &Event{Kind: KindShellExec, Target: "git ci -m x", Cwd: "/elsewhere"}, Cfg: cfg}
	if got := GatedGitWrites(noTable); len(got) != 0 {
		t.Errorf("an alias with no table for the directory = %+v", got)
	}
	mcp := &MatchContext{Event: &Event{Kind: KindMCPCall, Target: "mcp__github__push_files"}, Cfg: cfg}
	if got := GatedGitWrites(mcp); !reflect.DeepEqual(got, []GitWrite{{Form: GitWriteMCP}}) {
		t.Errorf("mcp = %+v", got)
	}
}
