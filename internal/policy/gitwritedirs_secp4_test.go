package policy

import (
	"strings"
	"testing"
)

// TestGitWriteLocationsFunctionLineIsUnplaced (lane SEC-P4 decision 1,
// SECP-18): a line that defines a function reads every gating write on it
// unplaced, under POSIX and PowerShell spellings; a POSIX header glued to
// its body (`f(){ git commit`) no longer hides the commit. The near-miss
// rows (a quoted header, a commit message naming a function, an array)
// stay placed.
func TestGitWriteLocationsFunctionLineIsUnplaced(t *testing.T) {
	rows := []struct {
		name    string
		line    string
		dialect Dialect
		unknown bool
	}{
		{"posix glued", "f(){ git commit -m x; }; cd /o; f", DialectPosix, true},
		{"posix spaced", "f() { git commit -m x; }; cd /o; f", DialectPosix, true},
		{"posix name space parens", "f () { git commit; }; cd /o; f", DialectPosix, true},
		{"posix blank parens", "f ( ) { git commit; }; f", DialectPosix, true},
		{"posix function keyword", "function f { git commit -m x; }; cd /o && f", DialectPosix, true},
		{"posix function keyword parens", "function f() { git commit -m x; }; cd /o && f", DialectPosix, true},
		{"posix newline body", "f()\n{\ngit commit\n}\ncd /o\nf", DialectPosix, true},
		{"posix subshell body", "f(){ (cd /o && git commit); }; f", DialectPosix, true},
		{"nested shell", "bash -c 'f(){ git commit; }; f'", DialectPosix, true},
		{"powershell function", "function f { git commit -m x }; Set-Location C:\\o; f", DialectPowerShell, true},
		{"powershell filter", "filter g { git commit -m x }; g", DialectPowerShell, true},
		{"plain commit", "git commit -m x", DialectPosix, false},
		{"message names a function", "git commit -m 'add function parse'", DialectPosix, false},
		{"quoted header", "echo 'f() {'; git commit -m x", DialectPosix, false},
		{"array assignment", "a=(); git commit -m x", DialectPosix, false},
		{"command substitution", "x=$( ); git commit -m x", DialectPosix, false},
		// Audit SEC-P4 F1: a heredoc body or a quoted message naming a call
		// is data, never a function header.
		{"heredoc message names a call", "git commit -F - <<EOF\nfix parse() bug\nEOF", DialectPosix, false},
		{"heredoc file body then commit", "cat > a.py <<EOF && git commit -am x\ndef main():\n    pass\nmain()\nEOF", DialectPosix, false},
		{"heredoc file body, commit next line", "cat > a.py <<EOF\nmain()\nEOF\ngit commit -am x", DialectPosix, false},
		{"quoted heredoc delimiter", "git commit -F - <<'EOF'\ncall f() now\nEOF", DialectPosix, false},
		{"double-quoted message names a call", "git commit -m \"call f() now\"", DialectPosix, false},
		{"function after a heredoc", "cat > a.py <<EOF\nmain()\nEOF\nf() { git commit; }; f", DialectPosix, true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			ev := &Event{Kind: KindShellExec, Target: r.line, Dialect: r.dialect, Cwd: "/r"}
			locs := GitWriteLocations(&MatchContext{Event: ev, Cfg: &Config{}})
			if len(locs) == 0 {
				t.Fatalf("no gating write found on %q", r.line)
			}
			for _, l := range locs {
				if l.Unknown != r.unknown {
					t.Fatalf("%q: location %+v, want unknown=%v", r.line, l, r.unknown)
				}
			}
		})
	}
}

// TestGitWriteLocationsMCPPlacementColumn (lane SEC-P4 decision 2): the
// reference git server's rows place by their repo_path argument; absent,
// unreadable, over-cap or network arguments read unknown; the GitHub rows
// keep the event's own directory.
func TestGitWriteLocationsMCPPlacementColumn(t *testing.T) {
	big := `{"repo_path":"/o","message":"` + strings.Repeat("a", MaxMCPToolInput) + `"}`
	rows := []struct {
		name, tool, raw string
		dirs            []string
		unknown         bool
	}{
		{"absolute repo_path", "mcp__git__git_commit", `{"repo_path":"/o","message":"m"}`, []string{"/o"}, false},
		{"relative repo_path", "mcp__git__git_commit", `{"repo_path":"sub","message":"m"}`, []string{"/r/sub"}, false},
		{"string-wrapped input", "git.git_commit", `"{\"repo_path\":\"/o\"}"`, []string{"/o"}, false},
		{"merge row", "mcp__git__git_merge", `{"repo_path":"/o"}`, []string{"/o"}, false},
		{"absent repo_path", "mcp__git__git_commit", `{"message":"m"}`, nil, true},
		{"no input", "mcp__git__git_commit", ``, nil, true},
		{"unreadable input", "mcp__git__git_commit", `{"repo_path":`, nil, true},
		{"repo_path not a string", "mcp__git__git_commit", `{"repo_path":["/o"]}`, nil, true},
		{"two repo_path keys", "mcp__git__git_commit", `{"repo_path":"/r","repo_path":"/o"}`, nil, true},
		{"over the cap", "mcp__git__git_commit", big, nil, true},
		{"unc path", "mcp__git__git_commit", `{"repo_path":"\\\\host\\share\\repo"}`, nil, true},
		{"network root", "mcp__git__git_commit", `{"repo_path":"/net/host/repo"}`, nil, true},
		{"expansion", "mcp__git__git_commit", `{"repo_path":"$HOME/repo"}`, nil, true},
		{"github merge keeps the event's directory", "mcp__github__merge_pull_request", `{"owner":"o","repo":"r"}`, []string{"/r"}, false},
		{"github delete keeps the event's directory", "mcp__github__delete_file", ``, []string{"/r"}, false},
		{"github push keeps the event's directory", "mcp__github__push_files", `{"files":[]}`, []string{"/r"}, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			ev := &Event{Kind: KindMCPCall, Target: r.tool, Cwd: "/r", Raw: []byte(r.raw)}
			locs := GitWriteLocations(&MatchContext{Event: ev, Cfg: &Config{}})
			if len(locs) != 1 {
				t.Fatalf("locations %+v, want one", locs)
			}
			if locs[0].Unknown != r.unknown || !sameStrings(locs[0].Dirs, r.dirs) {
				t.Fatalf("location %+v, want dirs %v unknown %v", locs[0], r.dirs, r.unknown)
			}
		})
	}
}

// TestMCPCommitContents (lane SEC-P4 decision 2): the content rows hand
// their content arguments to the detector; any other tool does not apply.
func TestMCPCommitContents(t *testing.T) {
	rows := []struct {
		name, tool, raw   string
		texts             []string
		applies, readable bool
	}{
		{"push_files", "mcp__github__push_files", `{"files":[{"path":"a","content":"x"},{"path":"b","content":"y"}]}`, []string{"x", "y"}, true, true},
		{"create_or_update_file", "mcp__github__create_or_update_file", `{"path":"a","content":"z"}`, []string{"z"}, true, true},
		{"create_commit", "create_commit", `{"files":[{"content":"q"}]}`, []string{"q"}, true, true},
		{"no content", "mcp__github__push_files", `{"files":[]}`, nil, true, true},
		{"unreadable", "mcp__github__push_files", `{"files":`, nil, true, false},
		{"absent", "mcp__github__push_files", ``, nil, true, false},
		{"content not a string", "mcp__github__create_or_update_file", `{"content":{"b64":"x"}}`, nil, true, false},
		{"files not a list", "mcp__github__push_files", `{"files":"x"}`, nil, true, false},
		{"git_commit does not apply", "mcp__git__git_commit", `{"content":"x"}`, nil, false, false},
		{"merge does not apply", "mcp__github__merge_pull_request", `{"content":"x"}`, nil, false, false},
		{"read tool does not apply", "mcp__github__get_file_contents", `{"content":"x"}`, nil, false, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			texts, applies, ok := MCPCommitContents(&Event{Kind: KindMCPCall, Target: r.tool, Raw: []byte(r.raw)})
			if applies != r.applies || (applies && ok != r.readable) || (ok && !sameStrings(texts, r.texts)) {
				t.Fatalf("got %v %v %v, want %v %v %v", texts, applies, ok, r.texts, r.applies, r.readable)
			}
		})
	}
}

// TestClassifyCommitCommandsReadsGluedFunctionBody: a POSIX function
// header glued to the body's first command is classified (it matched
// nothing before), and a PowerShell definition is not read twice.
func TestClassifyCommitCommandsReadsGluedFunctionBody(t *testing.T) {
	for _, line := range []string{"f(){ git commit -m x; }; f", "function f { git push; }; f", "function f() { git commit; }"} {
		if got := ClassifyGitWrites(&Event{Kind: KindShellExec, Target: line}); len(got) != 1 {
			t.Fatalf("%q: writes %+v, want one", line, got)
		}
	}
	if got := ClassifyGitWrites(&Event{Kind: KindShellExec, Target: "function f { git commit -m x }; f", Dialect: DialectPowerShell}); len(got) != 1 {
		t.Fatalf("powershell definition: writes %+v, want one", got)
	}
}
