package cloudevidence

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

func TestCommandClass(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want string
	}{
		{"go test", "go test -race ./internal/...", "test"},
		{"go build", "go build ./cmd/observer", "build"},
		{"go vet is just go", "go vet ./...", "go"},
		{"npm run build", "npm run build", "build"},
		{"npm test", "npm test", "test"},
		{"pytest", "pytest -q tests/", "test"},
		{"vitest", "vitest run", "test"},
		{"make test", "make test", "test"},
		{"make build", "make build", "build"},
		{"cargo test", "cargo test --all", "test"},
		{"git", "git status --porcelain", "git"},
		{"grep", "grep -rn foo internal/", "search"},
		{"absolute path program", "/usr/bin/git log -1", "git"},
		{"env assignment prefix", "SP=/tmp/secret/path go test ./...", "test"},
		{"env assignment then unknown", "LOG=/tmp/x.log ./scripts/roll.sh", "shell"},
		{"wrapper skipped", "sudo make test", "test"},
		{"unknown program", "scripts/restart-daemon.sh --compression on", "shell"},
		{"empty", "", "shell"},
		{"whitespace", "   ", "shell"},
		{"sqlite", "sqlite3 ~/.observer/observer.db '.schema'", "db"},
		{"az", "az containerapp update -n api", "cloud"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CommandClass(tc.cmd); got != tc.want {
				t.Errorf("CommandClass(%q) = %q, want %q", tc.cmd, got, tc.want)
			}
		})
	}
}

// TestCommandClassNeverLeaksCommandText is the privacy assertion: whatever a
// command contains, the emitted label is drawn from the closed table. A label
// that is a substring of the command's own arguments would be a leak.
func TestCommandClassNeverLeaksCommandText(t *testing.T) {
	allowed := map[string]bool{"test": true, "build": true, "shell": true}
	for _, r := range commandRules {
		allowed[r.label] = true
	}
	secrets := []string{
		"TOKEN=sk-live-abcdef ./deploy.sh /srv/customer-acme/prod",
		"curl -H 'Authorization: Bearer hunter2' https://internal.example.com/x",
		"C:\\Users\\alice\\secret\\run.bat --client=Acme",
		"../../etc/passwd",
		strings.Repeat("x", 5000),
	}
	for _, cmd := range secrets {
		got := CommandClass(cmd)
		if !allowed[got] {
			t.Fatalf("CommandClass(%q) = %q, which is not a closed-vocabulary label", cmd, got)
		}
		if len(got) > cloudcontract.MaxShortLabelBytes {
			t.Fatalf("label %q exceeds MaxShortLabelBytes", got)
		}
		if strings.ContainsAny(got, "/\\ ") || strings.Contains(got, "..") {
			t.Fatalf("label %q carries a path character", got)
		}
	}
}

func TestMCPCategory(t *testing.T) {
	cases := []struct{ in, want string }{
		{"mcp__claude-in-chrome__navigate", "browser"},
		{"mcp__chrome__click", "browser"},
		{"mcp__observer__get_session_summary", "observer"},
		{"mcp__github__create_pr", "github"},
		{"mcp__playwright__screenshot", "playwright"},
		{"mcp__cloudflare-bindings__d1_query", "cloudflare"},
		{"mcp__postgres__query", "db"},
		{"mcp__sqlite__read_query", "db"},
		{"mcp__linear__issue", "tracker"},
		{"mcp__slack__post", "chat"},
		{"mcp__filesystem__read", "filesystem"},
		{"mcp__OBSERVER__x", "observer"},
		// Everything unknown collapses to the fixed bucket — the server id is
		// user-configurable and is never echoed.
		{"mcp__server", "mcp"},
		{"mcp__payroll.csv__query", "mcp"},
		{"mcp__acme-holdings-payroll__query", "mcp"},
		{"mcp__../../etc/passwd__read", "mcp"},
		{"Read", "mcp"},
		{"", "mcp"},
		{"mcp__" + strings.Repeat("a", 64) + "__x", "mcp"},
		{"mcp__has/slash__x", "mcp"},
	}
	for _, tc := range cases {
		if got := MCPCategory(tc.in); got != tc.want {
			t.Errorf("MCPCategory(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestMCPCategoryNeverEchoesServerID is the F3 privacy pin: the MCP server
// segment is USER-CONFIGURABLE (a filename, a client codename, a confidential
// project name), so it may never appear in the envelope. Every output must be a
// member of the closed label set.
func TestMCPCategoryNeverEchoesServerID(t *testing.T) {
	allowed := map[string]bool{"mcp": true}
	for _, label := range mcpServerLabels {
		allowed[label] = true
	}
	for _, r := range mcpServerPrefixLabels {
		allowed[r.label] = true
	}
	hostile := []string{
		"mcp__payroll.csv__query",
		"mcp__project-thunderclap__plan",
		"mcp__acme-holdings__accounts",
		"mcp__..__escape",
		"mcp__../../etc/passwd__read",
		"mcp__c:__drive",
		"mcp__" + strings.Repeat("z", 200) + "__x",
	}
	for _, in := range hostile {
		got := MCPCategory(in)
		if !allowed[got] {
			t.Fatalf("MCPCategory(%q) = %q, which is not a closed-vocabulary label", in, got)
		}
	}
}

// TestStructuralEnvelopeNeverCarriesAnMCPServerID walks the SERIALIZED bytes:
// a filename-shaped and a confidential-looking server name must not appear
// anywhere, in any field.
func TestStructuralEnvelopeNeverCarriesAnMCPServerID(t *testing.T) {
	in := baseInput()
	for i, raw := range []string{
		"mcp__payroll.csv__query_rows",
		"mcp__acme-holdings-2027-merger__read",
		"mcp__../../etc/passwd__read",
	} {
		cat, pathOK := ActionCategory(RawAction{Kind: "mcp_call", RawToolName: raw})
		if pathOK {
			t.Fatalf("an mcp_call handed its target on as a path")
		}
		in.Actions = append(in.Actions, ActionInput{
			Ref: "am" + refIndex(i), Kind: "mcp", Category: cat, Status: "ok",
		})
	}
	env, err := BuildEnvelope(in, cloudcontract.PlanePersonal, structuralOpts())
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	b, _, err := Serialize(env)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	for _, forbidden := range []string{"payroll", ".csv", "acme-holdings", "merger", "passwd", ".."} {
		if strings.Contains(string(b), forbidden) {
			t.Errorf("MCP server id fragment %q reached the envelope bytes", forbidden)
		}
	}
}

// TestTestAndBuildCommandsUseTheSubcommandPosition is the F8 pin: a DIRECTORY
// named test (or build) is an argument, never a subcommand, so it may not turn a
// build into a test run — that is how a session got credited with a passing test
// suite it never ran.
func TestTestAndBuildCommandsUseTheSubcommandPosition(t *testing.T) {
	cases := []struct {
		cmd       string
		wantTest  bool
		wantBuild bool
		wantClass string
	}{
		{"go build ./test", false, true, "build"},
		{"go build ./test/...", false, true, "build"},
		{"go vet ./test", false, false, "go"},
		{"cargo build --manifest-path test/Cargo.toml", false, true, "build"},
		{"npm run build -- --dir test", false, true, "build"},
		{"ls test", false, false, "fs"},
		{"rm -rf build", false, false, "fs"},
		{"cp -r test build", false, false, "fs"},
		{"git commit -m 'add test'", false, false, "git"},
		{"go test ./...", true, false, "test"},
		{"npm run test", true, false, "test"},
		{"npm test", true, false, "test"},
		{"make test", true, false, "test"},
		{"make build", false, true, "build"},
		{"sudo make test", true, false, "test"},
		{"tsc --build", false, true, "build"},
		{"pytest -q tests/", true, false, "test"},
		{"go install ./cmd/observer", false, true, "build"},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			if got := IsTestCommand(tc.cmd); got != tc.wantTest {
				t.Errorf("IsTestCommand(%q) = %v, want %v", tc.cmd, got, tc.wantTest)
			}
			if got := IsBuildCommand(tc.cmd); got != tc.wantBuild {
				t.Errorf("IsBuildCommand(%q) = %v, want %v", tc.cmd, got, tc.wantBuild)
			}
			if got := CommandClass(tc.cmd); got != tc.wantClass {
				t.Errorf("CommandClass(%q) = %q, want %q", tc.cmd, got, tc.wantClass)
			}
		})
	}
}

// TestCompoundCommandsClassifyByTheWorkSegment is the N1 pin. A shell line is
// routinely a COMPOUND: `cd <dir> && <runner>`, `<runner> 2>&1 | tail`,
// `sh -c '…'`. The old parser took the whole line's first token as the program,
// so roughly two thirds of the corpus's real test invocations were classified
// "fs" (a `cd`) and counted as neither a test nor a build.
//
// The F8 guarantee is unchanged and is re-asserted here: an ARGUMENT still never
// matches. `go build ./test` is a build, `cd test && ls` is fs, and
// `echo test | grep x` is text.
func TestCompoundCommandsClassifyByTheWorkSegment(t *testing.T) {
	cases := []struct {
		name      string
		cmd       string
		wantClass string
		wantTest  bool
		wantBuild bool
	}{
		{"cd then npm test", "cd web && npm test", "test", true, false},
		{"semicolon then go test through a pipe", "cd /tmp/x; go test ./... 2>&1 | tail", "test", true, false},
		{"bash -c wrapping a compound", "bash -c 'cd api && make test'", "test", true, false},
		{"sh -c double quoted", `sh -c "cd api && go test ./..."`, "test", true, false},
		{"bash -lc cluster flag", "bash -lc 'make check'", "test", true, false},
		{"build then run with a --test flag", "make build && ./bin/app --test", "build", false, true},
		{"grep for the word test is not a test", "git status | grep test", "git", false, false},
		{"echo test piped is text", "echo test | grep x", "text", false, false},
		{"cd into a dir named test", "cd test && ls", "fs", false, false},
		{"or-else fallback runner", "go test ./... || echo failed", "test", true, false},
		{"pushd then cargo test", "pushd crates/core && cargo test --all", "test", true, false},
		{"export then pytest", "export CI=1 && pytest -q", "test", true, false},
		{"source then vitest", "source .venv/bin/activate && vitest run", "test", true, false},
		{"build and test on one line", "make build && go test ./...", "build", true, true},
		{"quoted operator is not a separator", "git commit -m 'fix && test the thing'", "git", false, false},
		{"only navigation falls back to the first segment", "cd /tmp/x && cd /tmp/y", "fs", false, false},
		{"pipeline of two known programs", "cat log.txt | grep -c FAIL", "fs", false, false},
		{"npm build after a cd", "cd web && npm run build", "build", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CommandClass(tc.cmd); got != tc.wantClass {
				t.Errorf("CommandClass(%q) = %q, want %q", tc.cmd, got, tc.wantClass)
			}
			if got := IsTestCommand(tc.cmd); got != tc.wantTest {
				t.Errorf("IsTestCommand(%q) = %v, want %v", tc.cmd, got, tc.wantTest)
			}
			if got := IsBuildCommand(tc.cmd); got != tc.wantBuild {
				t.Errorf("IsBuildCommand(%q) = %v, want %v", tc.cmd, got, tc.wantBuild)
			}
		})
	}
}

// TestWrappersWithArgumentsAreSkipped is the N2 pin: skipping a wrapper's NAME
// but not its options (or the values those options take) left the option value
// standing in program position, so `sudo -u ci make test` parsed `ci` as the
// program and reported a test run as "shell".
func TestWrappersWithArgumentsAreSkipped(t *testing.T) {
	cases := []struct {
		cmd       string
		wantClass string
		wantTest  bool
		wantBuild bool
	}{
		{"timeout 60 go test ./...", "test", true, false},
		{"timeout --kill-after 5s 30s go test ./...", "test", true, false},
		{"timeout 1.5h make check", "test", true, false},
		{"sudo -u ci make test", "test", true, false},
		{"sudo --user=ci make test", "test", true, false},
		{"env -i make test", "test", true, false},
		{"env -u GOFLAGS go test ./...", "test", true, false},
		{"nice -n 5 cargo build", "build", false, true},
		{"nice 5 cargo build", "build", false, true},
		{"stdbuf -o0 go test ./...", "test", true, false},
		{"/usr/bin/time -f %e make build", "build", false, true},
		{"sudo -u ci env FOO=1 timeout 30 npm test", "test", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			if got := CommandClass(tc.cmd); got != tc.wantClass {
				t.Errorf("CommandClass(%q) = %q, want %q", tc.cmd, got, tc.wantClass)
			}
			if got := IsTestCommand(tc.cmd); got != tc.wantTest {
				t.Errorf("IsTestCommand(%q) = %v, want %v", tc.cmd, got, tc.wantTest)
			}
			if got := IsBuildCommand(tc.cmd); got != tc.wantBuild {
				t.Errorf("IsBuildCommand(%q) = %v, want %v", tc.cmd, got, tc.wantBuild)
			}
		})
	}
}

// TestCompoundCommandClassNeverLeaksCommandText re-runs the privacy assertion
// over compound and interpreter-wrapped lines: however a line is segmented, the
// label is still drawn from the closed table.
func TestCompoundCommandClassNeverLeaksCommandText(t *testing.T) {
	allowed := map[string]bool{"test": true, "build": true, "shell": true}
	for _, r := range commandRules {
		allowed[r.label] = true
	}
	hostile := []string{
		"cd /srv/customer-acme && TOKEN=sk-live-abcdef ./deploy.sh",
		"bash -c 'curl -H \"Authorization: Bearer hunter2\" https://x/y | jq .'",
		"sh -c 'sh -c \"sh -c \\\"echo deep\\\"\"'",
		"cd ../../etc && cat passwd",
		strings.Repeat("cd a && ", 500) + "go test ./...",
		strings.Repeat("x", 9000) + " && " + strings.Repeat("y", 9000),
		"; ; ; |||| &&&&",
		"'unterminated quote && go test",
	}
	for _, cmd := range hostile {
		got := CommandClass(cmd)
		if !allowed[got] {
			t.Fatalf("CommandClass(%q…) = %q, which is not a closed-vocabulary label", cmd[:minInt(40, len(cmd))], got)
		}
		if strings.ContainsAny(got, "/\\ ") || strings.Contains(got, "..") {
			t.Fatalf("label %q carries a path character", got)
		}
	}
}

// TestDeriveOutcomesCountsCompoundCommands is the surface the N1 defect was
// visible on: a session that only ever ran `cd … && go test …` reported zero
// test runs and no build at all.
//
// It ALSO now pins the A3 attribution, which changed two of these rows'
// meanings. The old expectations were not merely different numbers — they were
// wrong ones:
//
//   - `cd /repo; go test … | tail -30` recorded a FAILURE, and the old rule
//     counted it as a failed test run. The failure is `tail`'s exit status; the
//     suite's is not in the evidence at all. It is TestsUnknown.
//   - `make build && go test ./...` recorded a FAILURE, and the old rule marked
//     the BUILD failed. The build must have SUCCEEDED for the test to have run;
//     the failure is the test's. The build is passed, the test run is failed.
func TestDeriveOutcomesCountsCompoundCommands(t *testing.T) {
	got := DeriveOutcomes([]RawAction{
		{Kind: "run_command", Target: "cd web && npm test", Success: true},
		{Kind: "run_command", Target: "cd /repo; go test ./... 2>&1 | tail -30", Success: false},
		{Kind: "run_command", Target: "bash -c 'cd api && make test'", Success: true},
		{Kind: "run_command", Target: "cd web && npm run build", Success: true},
		{Kind: "run_command", Target: "cd test && ls", Success: true},
		{Kind: "run_command", Target: "make build && go test ./...", Success: false},
	})
	// 3 knowable runs: two passed (`npm test`, `make test`), one failed (the
	// test half of the `&&` line). The piped one is unknowable.
	if got.TestsRun != 3 || got.TestsPassed != 2 {
		t.Errorf("tests = %d/%d, want 2/3", got.TestsPassed, got.TestsRun)
	}
	if got.TestsUnknown != 1 {
		t.Errorf("tests_unknown = %d, want 1 (the suite piped into tail)", got.TestsUnknown)
	}
	// The LAST build whose outcome was knowable is the `make build` that had to
	// succeed for the test after it to run.
	if got.Build != "passed" {
		t.Errorf("build = %q, want passed — the recorded failure was the TEST's", got.Build)
	}
	if got.BuildsUnknown != 0 {
		t.Errorf("builds_unknown = %d, want 0", got.BuildsUnknown)
	}
}

// TestOutcomeAttributionIsPerSegment is the A3 pin, stated as the table of
// shapes whose exit status does NOT belong to the work in them. Every row here
// was previously credited to a test or a build that the recording cannot speak
// for.
func TestOutcomeAttributionIsPerSegment(t *testing.T) {
	cases := []struct {
		name          string
		cmd           string
		success       bool
		wantTests     int
		wantPassed    int
		wantUnknownT  int
		wantBuild     string
		wantUnknownB  int
		whyItMattered string
	}{
		{
			name: "or-true swallows the suite's status", cmd: "go test ./... || true", success: true,
			wantUnknownT:  1,
			whyItMattered: "`|| true` exits 0 whether the suite passed or failed — the classic CI-quieting idiom, counted as a pass",
		},
		{
			name: "or-else after a failure", cmd: "go test ./... || echo failed", success: false,
			wantUnknownT:  1,
			whyItMattered: "the 0/non-zero could be either side of the ||",
		},
		{
			name: "short-circuit means the suite never ran", cmd: "true || go test ./...", success: true,
			wantUnknownT:  1,
			whyItMattered: "credited a passing test run to a suite that was never executed",
		},
		{
			name: "pipeline status belongs to the last stage", cmd: "go test ./... 2>&1 | tail -30", success: true,
			wantUnknownT:  1,
			whyItMattered: "`tail` almost always exits 0, so every piped suite read as passing",
		},
		{
			name: "the last stage IS attributable", cmd: "cat log | go test ./...", success: false,
			wantTests:     1,
			whyItMattered: "the honest half: the pipeline's status really is its last stage's",
		},
		{
			name: "and-chain credits the earlier link", cmd: "make build && go test ./...", success: false,
			wantTests: 1, wantBuild: "passed",
			whyItMattered: "marked the BUILD failed when the build had to succeed for the test to run at all",
		},
		{
			name: "and-chain success reaches every link", cmd: "make build && go test ./...", success: true,
			wantTests: 1, wantPassed: 1, wantBuild: "passed",
			whyItMattered: "a wholly-successful chain is knowable end to end",
		},
		{
			name: "an earlier list's status is discarded", cmd: "go test ./...; echo done", success: true,
			wantUnknownT:  1,
			whyItMattered: "`;` discards the earlier status; the recorded 0 is echo's",
		},
		{
			name: "the last list is attributable", cmd: "echo start; go test ./...", success: false,
			wantTests:     1,
			whyItMattered: "the last list of a `;` line does own the status",
		},
		{
			name: "an || anywhere in the list poisons it", cmd: "make build || true && go test ./...", success: true,
			wantUnknownT: 1, wantUnknownB: 1,
			whyItMattered: "neither segment's outcome survives the short-circuit",
		},
		{
			name: "a dangling && credits nothing", cmd: "go test ./... &&", success: false,
			wantTests:     1,
			whyItMattered: "the trailing operator must not make the suite an 'earlier link' and credit it a success",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveOutcomes([]RawAction{{Kind: "run_command", Target: tc.cmd, Success: tc.success}})
			if got.TestsRun != tc.wantTests || got.TestsPassed != tc.wantPassed || got.TestsUnknown != tc.wantUnknownT {
				t.Errorf("%q (success=%v): tests run/passed/unknown = %d/%d/%d, want %d/%d/%d\nwhy: %s",
					tc.cmd, tc.success, got.TestsRun, got.TestsPassed, got.TestsUnknown,
					tc.wantTests, tc.wantPassed, tc.wantUnknownT, tc.whyItMattered)
			}
			if got.Build != tc.wantBuild || got.BuildsUnknown != tc.wantUnknownB {
				t.Errorf("%q (success=%v): build = %q / unknown %d, want %q / %d\nwhy: %s",
					tc.cmd, tc.success, got.Build, got.BuildsUnknown, tc.wantBuild, tc.wantUnknownB,
					tc.whyItMattered)
			}
		})
	}
}

// TestShellParsingIgnoresCommentsAndHeredocBodies is the A4 pin: text that is
// NOT a command must not be parsed as one.
func TestShellParsingIgnoresCommentsAndHeredocBodies(t *testing.T) {
	cases := []struct {
		name      string
		cmd       string
		wantClass string
		wantTest  bool
		wantBuild bool
	}{
		{
			name: "comment after a command", cmd: "echo hello # ignored ; go test ./...",
			wantClass: "text",
		},
		{
			name: "a # inside a word is not a comment", cmd: "git log --format=%h#%s",
			wantClass: "git",
		},
		{
			name: "a quoted # is not a comment", cmd: "git commit -m 'fix #42 ; go test'",
			wantClass: "git",
		},
		{
			name: "a comment does not eat the next line", cmd: "echo hi # note\ngo test ./...",
			wantClass: "text", wantTest: true,
		},
		{
			name:      "heredoc body is data",
			cmd:       "cat <<'EOF' > run.sh\ngo test ./...\nEOF\n",
			wantClass: "fs",
		},
		{
			name:      "heredoc body then a real command",
			cmd:       "cat <<EOF > run.sh\ngo build ./...\nEOF\ngo test ./...",
			wantClass: "fs", wantTest: true,
		},
		{
			name:      "tab-indented heredoc terminator",
			cmd:       "cat <<-EOF > x\n\tgo test ./...\n\tEOF\n",
			wantClass: "fs",
		},
		{
			name:      "here-string is not a heredoc",
			cmd:       "grep -q FAIL <<< \"$out\"",
			wantClass: "search",
		},
		{
			name:      "unterminated heredoc abstains",
			cmd:       "cat <<EOF > run.sh\ngo test ./...\n",
			wantClass: "shell",
		},
		{
			name: "env -S carries the whole command", cmd: "env -S 'go test ./...'",
			wantClass: "test", wantTest: true,
		},
		{
			name: "env --split-string too", cmd: "env --split-string='go test ./...'",
			wantClass: "test", wantTest: true,
		},
		{
			name: "env -S with an assignment inside", cmd: "env -S 'GOFLAGS=-count=1 go build ./cmd/observer'",
			wantClass: "build", wantBuild: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CommandClass(tc.cmd); got != tc.wantClass {
				t.Errorf("CommandClass(%q) = %q, want %q", tc.cmd, got, tc.wantClass)
			}
			if got := IsTestCommand(tc.cmd); got != tc.wantTest {
				t.Errorf("IsTestCommand(%q) = %v, want %v", tc.cmd, got, tc.wantTest)
			}
			if got := IsBuildCommand(tc.cmd); got != tc.wantBuild {
				t.Errorf("IsBuildCommand(%q) = %v, want %v", tc.cmd, got, tc.wantBuild)
			}
		})
	}
}

// TestCommentedOutTestIsNotAnOutcome is the A4 defect at the surface it was
// visible on: a commented-out invocation used to become a counted test run.
func TestCommentedOutTestIsNotAnOutcome(t *testing.T) {
	got := DeriveOutcomes([]RawAction{
		{Kind: "run_command", Target: "echo hello # ignored ; go test ./...", Success: true},
		{Kind: "run_command", Target: "cat <<'EOF' > ci.sh\ngo test ./...\nEOF\n", Success: true},
	})
	if got.TestsRun != 0 || got.TestsPassed != 0 || got.TestsUnknown != 0 {
		t.Errorf("tests run/passed/unknown = %d/%d/%d, want 0/0/0 — no suite ran; one line was a comment and one wrote a file",
			got.TestsRun, got.TestsPassed, got.TestsUnknown)
	}
}

// TestMCPMappingOutputsAreContractVocabulary is the A10 pin, in the direction
// that catches drift. The old membership test derived its allowed set from
// mcpServerLabels itself, so relabelling sentry from "observability" to
// "monitoring" satisfied it — and shipped a label the hosted prompt (which
// renders cloudcontract.MCPFamilyLabels) never explains.
func TestMCPMappingOutputsAreContractVocabulary(t *testing.T) {
	vocab := map[string]bool{}
	for _, l := range cloudcontract.MCPFamilyLabels() {
		vocab[l] = true
	}
	for server, label := range mcpServerLabels {
		if !vocab[label] {
			t.Errorf("mcpServerLabels[%q] = %q, which is not in cloudcontract.MCPFamilyLabels() %v",
				server, label, cloudcontract.MCPFamilyLabels())
		}
	}
	for _, r := range mcpServerPrefixLabels {
		if !vocab[r.label] {
			t.Errorf("mcpServerPrefixLabels[%q] = %q, which is not in the contract vocabulary", r.prefix, r.label)
		}
	}
	if !vocab[mcpFallbackLabel] {
		t.Errorf("the MCP fallback %q is not in the contract vocabulary", mcpFallbackLabel)
	}
	// And the map must actually cover the vocabulary's non-fallback members, so
	// a label added to the contract without a mapping is caught too.
	emitted := map[string]bool{mcpFallbackLabel: true}
	for _, label := range mcpServerLabels {
		emitted[label] = true
	}
	for _, r := range mcpServerPrefixLabels {
		emitted[r.label] = true
	}
	for _, l := range cloudcontract.MCPFamilyLabels() {
		if !emitted[l] {
			t.Errorf("contract family %q is in the vocabulary but no server maps to it — "+
				"either map one or drop it from the contract", l)
		}
	}
}

// TestOutcomesNotInflatedByDirectoryNamedTest is the same defect at the surface
// that made it visible: a build-only session must not report a passing suite.
func TestOutcomesNotInflatedByDirectoryNamedTest(t *testing.T) {
	got := DeriveOutcomes([]RawAction{
		{Kind: "run_command", Target: "go build ./test", Success: true},
		{Kind: "run_command", Target: "go build ./test/helpers", Success: true},
	})
	if got.TestsRun != 0 || got.TestsPassed != 0 {
		t.Errorf("tests = %d/%d, want 0/0 — no test suite ran", got.TestsPassed, got.TestsRun)
	}
	if got.Build != "passed" {
		t.Errorf("build = %q, want passed", got.Build)
	}
}

func TestActionCategoryStrategies(t *testing.T) {
	cases := []struct {
		name     string
		action   RawAction
		wantCat  string
		wantPath bool
	}{
		{
			"read keeps path for extension derivation",
			RawAction{Kind: "read_file", Target: "internal/store/store.go"},
			"", true,
		},
		{
			"command classified, path withheld",
			RawAction{Kind: "run_command", Target: "git log -1"},
			"git", false,
		},
		{
			"mcp server label, path withheld",
			RawAction{Kind: "mcp_call", RawToolName: "mcp__observer__x"},
			"observer", false,
		},
		{
			"assistant message buckets to other",
			RawAction{Kind: "assistant_message", Target: "some prose"},
			"other", false,
		},
		// N6: a harness call is the AI client's OWN machinery, not an MCP
		// server call, so it gets its own fixed label instead of being reported
		// as the "mcp" bucket — a label that would simply be false.
		{
			"harness call gets its own fixed label",
			RawAction{Kind: "harness_call", RawToolName: "TodoWrite"},
			"harness", false,
		},
		{
			"harness call with an mcp-shaped tool name is still harness",
			RawAction{Kind: "harness_call", RawToolName: "mcp__payroll.csv__x"},
			"harness", false,
		},
		{
			"unknown kind buckets to other",
			RawAction{Kind: "brand_new_kind", Target: "anything"},
			"other", false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cat, pathOK := ActionCategory(tc.action)
			if cat != tc.wantCat || pathOK != tc.wantPath {
				t.Errorf("ActionCategory = (%q,%v), want (%q,%v)", cat, pathOK, tc.wantCat, tc.wantPath)
			}
		})
	}
}

func TestDeriveMilestones(t *testing.T) {
	actions := []RawAction{
		{Kind: "user_prompt", ElapsedSeconds: 0, Success: true},
		{Kind: "read_file", ElapsedSeconds: 5, Success: true},
		{Kind: "run_command", Target: "git status", ElapsedSeconds: 10, Success: true},
		{Kind: "edit_file", ElapsedSeconds: 30, Success: true},
		{Kind: "run_command", Target: "make build", ElapsedSeconds: 40, Success: false},
		{Kind: "run_command", Target: "go test ./...", ElapsedSeconds: 60, Success: true},
		{Kind: "task_complete", ElapsedSeconds: 90, Success: true},
		{Kind: "session_end", ElapsedSeconds: 100, Success: true},
	}
	got := DeriveMilestones(actions)
	want := []struct {
		kind    string
		elapsed int
	}{
		{"first_edit", 30},
		{"first_command", 10},
		{"first_test", 60},
		{"first_error", 40},
		{"first_task_complete", 90},
		{"session_end", 100},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d milestones, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Kind != w.kind || got[i].ElapsedSeconds != w.elapsed {
			t.Errorf("milestone %d = %+v, want %s@%d", i, got[i], w.kind, w.elapsed)
		}
		if got[i].Ref == "" {
			t.Errorf("milestone %d has an empty ref", i)
		}
	}
}

func TestDeriveMilestonesEmptyAndAbsent(t *testing.T) {
	if got := DeriveMilestones(nil); len(got) != 0 {
		t.Errorf("nil actions produced %d milestones", len(got))
	}
	got := DeriveMilestones([]RawAction{{Kind: "read_file", Success: true, ElapsedSeconds: 3}})
	if len(got) != 0 {
		t.Errorf("a read-only session should produce no milestones, got %+v", got)
	}
}

func TestDeriveOutcomes(t *testing.T) {
	actions := []RawAction{
		{Kind: "run_command", Target: "go test ./a", Success: true},
		{Kind: "run_command", Target: "go test ./b", Success: false},
		{Kind: "run_command", Target: "go test ./c", Success: true},
		{Kind: "run_command", Target: "go build ./cmd/x", Success: false},
		{Kind: "run_command", Target: "make build", Success: true},
		{Kind: "run_command", Target: "git status", Success: true},
		{Kind: "edit_file", Target: "x.go", Success: true},
	}
	got := DeriveOutcomes(actions)
	if got.TestsRun != 3 || got.TestsPassed != 2 {
		t.Errorf("tests = %d/%d, want 2/3", got.TestsPassed, got.TestsRun)
	}
	if got.Build != "passed" {
		t.Errorf("build = %q, want passed (the LAST build command succeeded)", got.Build)
	}
	if got.TestsPassed > got.TestsRun {
		t.Fatal("contract violation: tests_passed exceeds tests_run")
	}
}

func TestDeriveOutcomesNoBuildStaysEmpty(t *testing.T) {
	got := DeriveOutcomes([]RawAction{{Kind: "run_command", Target: "git log", Success: true}})
	if got.Build != "" {
		t.Errorf("build = %q, want empty — no build command was observed", got.Build)
	}
}

func TestBuildActivityMix(t *testing.T) {
	got := buildActivityMix([]ActivityMixInput{
		{Kind: "run_command", Count: 339},
		{Kind: "edit_file", Count: 80},
		{Kind: "read_file", Count: 0},
		{Kind: "has space", Count: 4},
		{Kind: "../escape", Count: 1},
	})
	want := map[string]int{"run_command": 339, "edit_file": 80, "unclassified": 5}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %d entries", got, len(want))
	}
	prev := ""
	for _, e := range got {
		if want[e.Key] != e.Count {
			t.Errorf("entry %+v not expected (want %v)", e, want)
		}
		if e.Key <= prev {
			t.Fatalf("mix is not strictly key-ascending: %q after %q", e.Key, prev)
		}
		prev = e.Key
	}
}

// TestBuildActivityMixBoundedAndValid feeds far more distinct kinds than the
// contract's entry bound and asserts the result is bounded, count-preserving and
// schema-valid. Since the N7 allow-list landed, the bound cannot actually be
// REACHED through this path — there are fewer known action kinds than
// MaxStructuralMixEntries and everything else merges into one "unclassified"
// bucket — which is a stronger property than the bound, not a weaker one; the
// truncation in buildActivityMix stays as the defence that makes it structural.
func TestBuildActivityMixBoundedAndValid(t *testing.T) {
	in := make([]ActivityMixInput, cloudcontract.MaxStructuralMixEntries+40)
	total := 0
	for i := range in {
		in[i] = ActivityMixInput{Kind: "kind-" + refIndex(i), Count: i + 1}
		total += i + 1
	}
	in = append(in, ActivityMixInput{Kind: "run_command", Count: 7})
	total += 7

	got := buildActivityMix(in)
	if len(got) > cloudcontract.MaxStructuralMixEntries {
		t.Fatalf("got %d entries, exceeds the %d bound", len(got), cloudcontract.MaxStructuralMixEntries)
	}
	sum := 0
	for _, e := range got {
		sum += e.Count
		if e.Key != "run_command" && e.Key != unclassifiedMixKey {
			t.Errorf("unknown kind %q survived as its own key", e.Key)
		}
	}
	if sum != total {
		t.Errorf("counts sum to %d, want %d — folding an unknown kind must not lose its count", sum, total)
	}
	// A VALID envelope, with only the mix swapped: the previous version of this
	// test built a bare Envelope{ActivityMix: …}, which fails on schema_version
	// long before validateMix ever runs — so it asserted nothing (F9).
	env := validEnvelopeForMixTest(t)
	env.ActivityMix = got
	if err := env.Validate(); err != nil {
		t.Fatalf("bounded mix failed validation: %v", err)
	}
}

// validEnvelopeForMixTest returns a fully valid envelope whose only interesting
// variable is ActivityMix, so a Validate() failure can only be the mix.
func validEnvelopeForMixTest(t *testing.T) cloudcontract.Envelope {
	t.Helper()
	env, err := BuildEnvelope(baseInput(), cloudcontract.PlanePersonal, structuralOpts())
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	if err := env.Validate(); err != nil {
		t.Fatalf("precondition: the base envelope must be valid: %v", err)
	}
	return *env
}

// TestActivityMixValidationRejectsBadMixes reaches validateMix for real: each
// case starts from a VALID envelope and swaps in one broken mix.
func TestActivityMixValidationRejectsBadMixes(t *testing.T) {
	tooMany := make([]cloudcontract.StructuralMixEntry, cloudcontract.MaxStructuralMixEntries+1)
	for i := range tooMany {
		tooMany[i] = cloudcontract.StructuralMixEntry{Key: "k" + refIndex(i+100), Count: 1}
	}
	cases := []struct {
		name string
		mix  []cloudcontract.StructuralMixEntry
		want string
	}{
		{"invalid key", []cloudcontract.StructuralMixEntry{{Key: "internal/store/store.go", Count: 3}}, "activity_mix"},
		{"path escape key", []cloudcontract.StructuralMixEntry{{Key: "../etc", Count: 3}}, "activity_mix"},
		{"empty key", []cloudcontract.StructuralMixEntry{{Key: "", Count: 3}}, "activity_mix"},
		{"duplicate keys", []cloudcontract.StructuralMixEntry{{Key: "edit", Count: 1}, {Key: "edit", Count: 2}}, "activity_mix"},
		{"unsorted", []cloudcontract.StructuralMixEntry{{Key: "run", Count: 2}, {Key: "edit", Count: 1}}, "activity_mix"},
		{"zero count", []cloudcontract.StructuralMixEntry{{Key: "edit", Count: 0}}, "activity_mix"},
		{"negative count", []cloudcontract.StructuralMixEntry{{Key: "edit", Count: -4}}, "activity_mix"},
		{"too many entries", tooMany, "activity_mix"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := validEnvelopeForMixTest(t)
			env.ActivityMix = tc.mix
			err := env.Validate()
			if err == nil {
				t.Fatalf("Validate accepted an invalid activity_mix %+v", tc.mix)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %q — the failure may be unrelated to the mix", err, tc.want)
			}
		})
	}
	// Positive control: the same envelope with a well-formed mix validates.
	env := validEnvelopeForMixTest(t)
	env.ActivityMix = []cloudcontract.StructuralMixEntry{{Key: "edit", Count: 1}, {Key: "run", Count: 2}}
	if err := env.Validate(); err != nil {
		t.Fatalf("a well-formed mix was rejected: %v", err)
	}
}

// TestActivityMixFoldsUnknownActionKinds is the N7 pin: a mix key is a member of
// a table WE wrote, not merely a well-SHAPED string. action_type is closed by
// convention today, but an adapter bug or a hand-written row could put anything
// there, and a hostile value like "payroll.csv" normalizes to a perfectly valid
// slug. The count must survive; the string must not.
func TestActivityMixFoldsUnknownActionKinds(t *testing.T) {
	got := buildActivityMix([]ActivityMixInput{
		{Kind: "run_command", Count: 12},
		{Kind: "payroll.csv", Count: 3},
		{Kind: "acme-holdings-2027-merger", Count: 2},
		{Kind: "brand_new_kind", Count: 1},
	})
	want := map[string]int{"run_command": 12, unclassifiedMixKey: 6}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %v", got, want)
	}
	for _, e := range got {
		if want[e.Key] != e.Count {
			t.Errorf("entry %+v not expected (want %v)", e, want)
		}
	}
	// End to end: the hostile kind must not appear in the serialized bytes.
	in := baseInput()
	in.ActivityMix = []ActivityMixInput{{Kind: "payroll.csv", Count: 3}, {Kind: "run_command", Count: 1}}
	env, err := BuildEnvelope(in, cloudcontract.PlanePersonal, structuralOpts())
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	b, _, err := Serialize(env)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	for _, forbidden := range []string{"payroll", ".csv"} {
		if strings.Contains(string(b), forbidden) {
			t.Errorf("hostile action_type fragment %q reached the envelope bytes", forbidden)
		}
	}
}

// TestKnownActionKindsMirrorsModels keeps the allow-list honest against the
// package that owns the kinds. internal/cloudevidence may not IMPORT
// internal/models (imports_test.go pins the closed set), so the mirror is
// checked by parsing the source of record: every Action* string constant there
// must be a member here, or a newly added kind would silently start folding into
// "unclassified".
func TestKnownActionKindsMirrorsModels(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, filepath.Join("..", "models"), func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse internal/models: %v", err)
	}
	found := 0
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.CONST {
					continue
				}
				for _, spec := range gen.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
						continue
					}
					name := vs.Names[0].Name
					if !strings.HasPrefix(name, "Action") {
						continue
					}
					lit, ok := vs.Values[0].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					value, err := strconv.Unquote(lit.Value)
					if err != nil {
						continue
					}
					found++
					if !knownActionKinds[value] {
						t.Errorf("models.%s = %q is not in knownActionKinds — a new action kind would fold into %q", name, value, unclassifiedMixKey)
					}
				}
			}
		}
	}
	if found < 40 {
		t.Fatalf("only found %d models.Action* constants — the mirror check is not actually reading them", found)
	}
}

func TestBuildActivityMixEmpty(t *testing.T) {
	if got := buildActivityMix(nil); got != nil {
		t.Errorf("nil input produced %+v, want nil (the field is omitempty)", got)
	}
	if got := buildActivityMix([]ActivityMixInput{{Kind: "x", Count: 0}}); got != nil {
		t.Errorf("all-zero counts produced %+v, want nil", got)
	}
}
