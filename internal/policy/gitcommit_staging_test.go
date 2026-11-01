package policy

import (
	"reflect"
	"testing"
)

// TestPlannedCommitStaging pins one row per command shape (lane SEC-F2B,
// decision log P-078 ruling 2): what the trailer binds an agent commit to.
func TestPlannedCommitStaging(t *testing.T) {
	whole := StagedScope{WholeTree: true}
	tracked := StagedScope{WholeTree: true, TrackedOnly: true}
	cases := []struct {
		name   string
		line   string
		want   CommitStaging
		reason string
	}{
		{"add then commit", "git add X && git commit -m m", CommitStaging{Commit: true, Readable: true, Scopes: []StagedScope{{Path: "X"}}}, ""},
		{"add -A; commit", "git add -A; git commit", CommitStaging{Commit: true, Readable: true, Scopes: []StagedScope{whole}}, ""},
		{"add dot", "git add . && git commit -m m", CommitStaging{Commit: true, Readable: true, Scopes: []StagedScope{{Path: "."}}}, ""},
		{"commit -a", "git commit -a -m m", CommitStaging{Commit: true, Readable: true, Scopes: []StagedScope{tracked}}, ""},
		{"commit -am", "git commit -am m", CommitStaging{Commit: true, Readable: true, Scopes: []StagedScope{tracked}}, ""},
		{"commit --all", "git commit --all -m m", CommitStaging{Commit: true, Readable: true, Scopes: []StagedScope{tracked}}, ""},
		{"pathspec commit", "git commit -m m -- a.go b/c.go", CommitStaging{Commit: true, Readable: true, Scopes: []StagedScope{{Path: "a.go"}, {Path: "b/c.go"}}}, ""},
		{"plain commit", "git commit -m m", CommitStaging{Commit: true, Readable: true}, ""},
		{"add -u", "git add -u && git commit -m m", CommitStaging{Commit: true, Readable: true, Scopes: []StagedScope{tracked}}, ""},
		{"rm then commit", "git rm -r old && git commit -m m", CommitStaging{Commit: true, Readable: true, Scopes: []StagedScope{{Path: "old"}}}, ""},
		{"variable", "git add $F && git commit -m m", CommitStaging{Commit: true}, StagingPathspec},
		{"subshell", "git add $(ls) && git commit -m m", CommitStaging{Commit: true}, StagingPathspec},
		{"glob", "git add '*.go' && git commit -m m", CommitStaging{Commit: true}, StagingPathspec},
		{"patch add", "git add -p && git commit -m m", CommitStaging{Commit: true}, StagingOption},
		{"unknown alias", "git a X && git commit -m m", CommitStaging{Commit: true}, StagingAlias},
		{"cd first", "cd sub && git add x && git commit -m m", CommitStaging{Commit: true}, StagingDirChange},
		{"other index", "GIT_INDEX_FILE=/tmp/i git commit -m m", CommitStaging{Commit: true}, StagingIndexEnv},
		{"other repo add", "git -C ../o add x && git commit -m m", CommitStaging{Commit: true}, StagingOtherRepo},
		{"from file", "git commit --pathspec-from-file=list -m m", CommitStaging{Commit: true}, StagingOption},
		{"add after commit ignored", "git commit -m m && git add $F", CommitStaging{Commit: true, Readable: true}, ""},
		{"no commit", "git add X", CommitStaging{}, ""},
		{"dry run", "git commit --dry-run", CommitStaging{}, ""},
		{"inline alias", "git -c alias.st=add st X && git commit -m m", CommitStaging{Commit: true, Readable: true, Scopes: []StagedScope{{Path: "X"}}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := &Event{Kind: KindShellExec, Target: tc.line, Dialect: DialectPosix}
			got := PlannedCommitStaging(&MatchContext{Event: ev})
			want := tc.want
			want.Reason = tc.reason
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%q:\n got %+v\nwant %+v", tc.line, got, want)
			}
		})
	}
}

// TestPlannedCommitStagingAliasTable reads a project alias table.
func TestPlannedCommitStagingAliasTable(t *testing.T) {
	ev := &Event{Kind: KindShellExec, Target: "git aa X && git ci -m m", Dialect: DialectPosix, Cwd: "/r"}
	cfg := &Config{GitAliases: func(string) (map[string]string, bool) {
		return map[string]string{"aa": "add", "ci": "commit"}, true
	}}
	got := PlannedCommitStaging(&MatchContext{Event: ev, Cfg: cfg})
	want := CommitStaging{Commit: true, Readable: true, Scopes: []StagedScope{{Path: "X"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if PlannedCommitStaging(&MatchContext{Event: &Event{Kind: KindMCPCall, Target: "git_commit"}}).Commit {
		t.Fatal("an MCP event has no shell staging")
	}
}

// TestPlannedCommitStagingMessageSubstitution keeps the common agent
// spelling of a commit message readable.
func TestPlannedCommitStagingMessageSubstitution(t *testing.T) {
	line := "git add a.go && git commit -m \"$(cat <<'EOF'\nfix: x\nEOF\n)\""
	got := PlannedCommitStaging(&MatchContext{Event: &Event{Kind: KindShellExec, Target: line, Dialect: DialectPosix}})
	want := CommitStaging{Commit: true, Readable: true, Scopes: []StagedScope{{Path: "a.go"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	argv := PlannedCommitStaging(&MatchContext{Event: &Event{Kind: KindShellExec, Args: []string{"bash", "-lc", "git add x && git commit -m m"}, Dialect: DialectPosix}})
	if !argv.Readable || len(argv.Scopes) != 1 || argv.Scopes[0].Path != "x" {
		t.Fatalf("argv form: %+v", argv)
	}
}
