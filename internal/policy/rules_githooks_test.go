package policy

import (
	"strings"
	"testing"
	"time"
)

// coreRuleCase is one R-112 / R-113 / R-114 / R-165 row case. wantRule ""
// means none of watched may win the verdict.
type coreRuleCase struct {
	name       string
	kind       EventKind
	actionType string
	target     string
	dialect    Dialect
	// alt is the boundary's second reading (Event.AltDialect).
	alt   Dialect
	edits []ProposedEdit
	// current is the file's content before the write ("" means unknown).
	current     string
	wantRule    string
	wantEnforce Decision
}

// testGitAliases is the alias table the daemon would publish for the
// test project (Config.GitAliases).
var testGitAliases = map[string]string{
	"ci":   "commit -n",
	"save": "commit -m wip",
	"yolo": "!HUSKY=0 git commit",
	"pf":   "!f() { git push --no-verify \"$@\"; }; f",
	"lazy": "ci -m x",
}

// runCoreRuleCases evaluates every case in observe and enforce mode:
// observe always flags (every row's observe decision), enforce takes the
// case's decision.
func runCoreRuleCases(t *testing.T, cases []coreRuleCase, watched ...string) {
	t.Helper()
	isWatched := func(id string) bool {
		for _, w := range watched {
			if w == id {
				return true
			}
		}
		return false
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const home, root = "/home/u", "/home/u/proj"
			ev := Event{
				Kind: tc.kind, ActionType: tc.actionType, Target: tc.target, Dialect: tc.dialect, AltDialect: tc.alt,
				Cwd: root, ProjectRoot: root, SessionID: "s1", Edits: tc.edits,
				Now: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC),
			}
			read := func(p string) ([]byte, bool) {
				if tc.current == "" || !strings.HasSuffix(p, strings.TrimPrefix(tc.target, "./")) {
					return nil, false
				}
				return []byte(tc.current), true
			}
			aliases := func(dir string) (map[string]string, bool) {
				if !strings.HasPrefix(dir, root) {
					return nil, false
				}
				return testGitAliases, true
			}
			for _, mode := range []Mode{ModeObserve, ModeEnforce} {
				e, err := New(Config{Mode: mode, Home: home, ReadFile: read, GitAliases: aliases})
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				v := e.Evaluate(ev)
				if tc.wantRule == "" {
					if isWatched(v.RuleID) {
						t.Fatalf("%s: want no %v hit, got %s/%s (%q)", mode, watched, v.RuleID, v.Decision, v.Reason)
					}
					continue
				}
				want := tc.wantEnforce
				if mode == ModeObserve {
					want = DecisionFlag
				}
				if v.RuleID != tc.wantRule || v.Decision != want {
					t.Fatalf("%s: got %s/%s, want %s/%s (%q)", mode, v.RuleID, v.Decision, tc.wantRule, want, v.Reason)
				}
			}
		})
	}
}

func sh(name, line string, rule string, d Decision) coreRuleCase {
	return coreRuleCase{name: name, kind: KindShellExec, target: line, wantRule: rule, wantEnforce: d}
}

func TestGitHookBypassRuleR112(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		// Options that skip hooks (gitHookSkipOptions rows).
		sh("commit --no-verify", `git commit --no-verify -m "fix"`, "R-112", DecisionDeny),
		sh("commit -n", `git commit -n -m fix`, "R-112", DecisionDeny),
		sh("commit -n in a cluster", `git commit -anm fix`, "R-112", DecisionDeny),
		sh("commit abbreviated --no-veri", `git commit --no-veri -m fix`, "R-112", DecisionDeny),
		sh("am -n", `git am -n fix.patch`, "R-112", DecisionDeny),
		sh("merge --no-verify", `git merge --no-verify feature`, "R-112", DecisionDeny),
		sh("pull --no-verify", `git pull --no-verify origin main`, "R-112", DecisionDeny),
		sh("push --no-verify", `git push --no-verify origin feature`, "R-112", DecisionDeny),
		sh("rebase --no-verify", `git rebase --no-verify main`, "R-112", DecisionDeny),
		sh("inside bash -c", `bash -c "git commit --no-verify -m x"`, "R-112", DecisionDeny),
		sh("after cd", `cd sub && git commit -n -m x`, "R-112", DecisionDeny),
		{name: "powershell dialect", kind: KindShellExec, target: `git commit --no-verify -m x`, dialect: DialectPowerShell, wantRule: "R-112", wantEnforce: DecisionDeny},
		// Values read as values, never as options.
		sh("message that is -n", `git commit -m -n`, "", 0),
		sh("message containing -n after -am", `git commit -am "-n fix"`, "", 0),
		sh("untracked-files=no cluster", `git commit -uno -m fix`, "", 0),
		sh("--message value --no-verify", `git commit --message --no-verify`, "", 0),
		sh("pathspec after --", `git commit -m fix -- -n`, "", 0),
		sh("push -n is a dry run", `git push -n origin main`, "", 0),
		sh("merge -n is --no-stat", `git merge -n feature`, "", 0),
		sh("plain commit", `git commit -m "fix"`, "", 0),
		sh("merge --no-verify-signatures", `git merge --no-verify-signatures feature`, "", 0),
		// core.hooksPath for one command.
		sh("-c core.hooksPath", `git -c core.hooksPath=/dev/null commit -m x`, "R-112", DecisionDeny),
		sh("-c core.hookspath lower case, empty", `git -c core.hookspath= commit -m x`, "R-112", DecisionDeny),
		sh("--config-env core.hooksPath", `git --config-env=core.hooksPath=HOOKS commit -m x`, "R-112", DecisionDeny),
		sh("-c other key", `git -c user.name=bot commit -m x`, "", 0),
		// Configuration injected through the environment.
		sh("GIT_CONFIG_PARAMETERS", `GIT_CONFIG_PARAMETERS="'core.hooksPath'='/dev/null'" git commit -m x`, "R-112", DecisionDeny),
		sh("GIT_CONFIG_PARAMETERS old form", `GIT_CONFIG_PARAMETERS="'core.hooksPath=/dev/null'" git commit -m x`, "R-112", DecisionDeny),
		sh("GIT_CONFIG_PARAMETERS unreadable", `GIT_CONFIG_PARAMETERS="$CFG" git commit -m x`, "R-112", DecisionDeny),
		sh("GIT_CONFIG_PARAMETERS harmless", `GIT_CONFIG_PARAMETERS="'user.name'='bot'" git commit -m x`, "", 0),
		sh("GIT_CONFIG_COUNT", `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git commit -m x`, "R-112", DecisionDeny),
		sh("GIT_CONFIG_COUNT through env", `env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/x git push`, "R-112", DecisionDeny),
		sh("GIT_CONFIG_COUNT exported earlier", `export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/x; git commit -m x`, "R-112", DecisionDeny),
		// Aliases: defined on the command line, defined for good, or from
		// the daemon's table.
		sh("-c alias then used", `git -c alias.ci='commit --no-verify' ci -m x`, "R-112", DecisionDeny),
		sh("git config alias definition", `git config alias.ci "commit --no-verify"`, "R-112", DecisionDeny),
		sh("global shell alias definition", `git config --global alias.p '!git push --no-verify'`, "R-112", DecisionDeny),
		sh("git config set alias (new syntax)", `git config set alias.c "commit -n"`, "R-112", DecisionDeny),
		sh("harmless alias definition", `git config alias.st status`, "", 0),
		sh("table alias to commit -n", `git ci -m fix`, "R-112", DecisionDeny),
		sh("table shell alias to push --no-verify", `git pf origin main`, "R-112", DecisionDeny),
		sh("table alias chained through another alias", `git lazy`, "R-112", DecisionDeny),
		sh("table alias that is harmless", `git save`, "", 0),
		sh("alias not in the table", `git unknown-thing`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-112")
}

func TestGitHookBypassRuleR113(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		// Git command row: one case per hookSkipVars row.
		sh("HUSKY=0", `HUSKY=0 git commit -m x`, "R-113", DecisionDeny),
		sh("HUSKY_SKIP_HOOKS=1", `HUSKY_SKIP_HOOKS=1 git commit -m x`, "R-113", DecisionDeny),
		sh("SKIP=", `SKIP=flake8,mypy git commit -m x`, "R-113", DecisionDeny),
		sh("PRE_COMMIT_ALLOW_NO_CONFIG", `PRE_COMMIT_ALLOW_NO_CONFIG=1 git commit -m x`, "R-113", DecisionDeny),
		sh("LEFTHOOK=0 through env", `env LEFTHOOK=0 git commit -m x`, "R-113", DecisionDeny),
		sh("LEFTHOOK_EXCLUDE", `LEFTHOOK_EXCLUDE=lint git push`, "R-113", DecisionDeny),
		sh("OVERCOMMIT_DISABLE", `OVERCOMMIT_DISABLE=1 git commit -m x`, "R-113", DecisionDeny),
		sh("SKIP_SIMPLE_GIT_HOOKS", `SKIP_SIMPLE_GIT_HOOKS=1 git commit -m x`, "R-113", DecisionDeny),
		sh("value the guard cannot read", `HUSKY=$H git commit -m x`, "R-113", DecisionDeny),
		sh("export earlier in the line", `export HUSKY=0 && git commit -m x`, "R-113", DecisionDeny),
		{name: "powershell $env: earlier in the line", kind: KindShellExec, target: `$env:HUSKY=0; git commit -m x`, dialect: DialectPowerShell, wantRule: "R-113", wantEnforce: DecisionDeny},
		{name: "cmd set earlier in the line", kind: KindShellExec, target: `set HUSKY=0 && git commit -m x`, dialect: DialectCmd, wantRule: "R-113", wantEnforce: DecisionDeny},
		sh("through a table shell alias", `git yolo -m x`, "R-113", DecisionDeny),
		sh("HUSKY=1 turns hooks on", `HUSKY=1 git commit -m x`, "", 0),
		sh("empty SKIP", `SKIP= git commit -m x`, "", 0),
		sh("not a git command", `HUSKY=0 npm ci`, "", 0),
		sh("unrelated variable", `CI=1 git commit -m x`, "", 0),
		// Export row: the switch set for later commands.
		sh("export alone", `export HUSKY=0`, "R-113", DecisionAsk),
		sh("declare -x alone", `declare -x SKIP=all`, "R-113", DecisionAsk),
		sh("setx alone", `setx HUSKY 0`, "R-113", DecisionAsk),
		{name: "powershell $env: alone", kind: KindShellExec, target: `$env:LEFTHOOK = "0"`, dialect: DialectPowerShell, wantRule: "R-113", wantEnforce: DecisionAsk},
		sh("export of an unrelated variable", `export NODE_ENV=production`, "", 0),
		{name: "posix set is not an export", kind: KindShellExec, target: `set HUSKY=0`, wantRule: "", wantEnforce: 0},
	}
	runCoreRuleCases(t, cases, "R-113")
}

func TestGitHookBypassRuleR114(t *testing.T) {
	t.Parallel()
	fa := func(name, action, target string, edits []ProposedEdit, current, rule string, d Decision) coreRuleCase {
		return coreRuleCase{name: name, kind: KindFileAccess, actionType: action, target: target, edits: edits, current: current, wantRule: rule, wantEnforce: d}
	}
	cases := []coreRuleCase{
		// git config row.
		sh("set core.hooksPath", `git config core.hooksPath .githooks`, "R-114", DecisionDeny),
		sh("set global core.hooksPath", `git config --global core.hooksPath /tmp/h`, "R-114", DecisionDeny),
		sh("set core.hooksPath (new syntax)", `git config set core.hooksPath /tmp/h`, "R-114", DecisionDeny),
		sh("unset core.hooksPath", `git config --unset core.hooksPath`, "R-114", DecisionDeny),
		sh("remove the core section", `git config --remove-section core`, "R-114", DecisionDeny),
		sh("set core.fsmonitor to a program", `git config core.fsmonitor ./watch.sh`, "R-114", DecisionDeny),
		sh("-c core.fsmonitor for one command", `git -c core.fsmonitor=./watch.sh status`, "R-114", DecisionDeny),
		sh("edit in an editor", `git config --edit`, "R-114", DecisionDeny),
		sh("core.fsmonitor false", `git config core.fsmonitor false`, "", 0),
		sh("read core.hooksPath", `git config --get core.hooksPath`, "", 0),
		sh("read core.hooksPath (one positional)", `git config core.hooksPath`, "", 0),
		sh("set user.email", `git config user.email bot@example.com`, "", 0),
		// git internals, file tools.
		fa("write .git/config", "write_file", ".git/config", whole("[core]\n"), "", "R-114", DecisionDeny),
		fa("edit .git/info/attributes", "edit_file", ".git/info/attributes", nil, "", "R-114", DecisionDeny),
		fa("write a ref", "write_file", ".git/refs/heads/main", whole("0000\n"), "", "R-114", DecisionDeny),
		fa("write an object", "write_file", ".git/objects/ab/cdef", nil, "", "R-114", DecisionDeny),
		fa("write the global git config", "write_file", "~/.gitconfig", whole("[core]\n"), "", "R-114", DecisionDeny),
		fa("read .git/config", "read_file", ".git/config", nil, "", "", 0),
		// git internals, shell.
		sh("append to .git/config", `echo "[core] hooksPath = /x" >> .git/config`, "R-114", DecisionDeny),
		sh("sed -i .git/info/attributes", `sed -i 's/a/b/' .git/info/attributes`, "R-114", DecisionDeny),
		sh("tee into a ref", `echo 0000 | tee .git/refs/heads/main`, "R-114", DecisionDeny),
		sh("delete of objects is R-102's", `rm -rf ./.git/objects`, "", 0),
		sh("cat .git/config", `cat .git/config`, "", 0),
		// Hook manager config.
		fa("write .pre-commit-config.yaml", "write_file", ".pre-commit-config.yaml", whole("repos: []\n"), "", "R-114", DecisionAsk),
		fa("edit a husky hook", "edit_file", ".husky/pre-commit", nil, "", "R-114", DecisionAsk),
		fa("write lefthook.yml", "write_file", "lefthook.yml", whole("pre-commit:\n"), "", "R-114", DecisionAsk),
		sh("echo into a husky hook", `echo "exit 0" > .husky/pre-commit`, "R-114", DecisionAsk),
		fa("read .pre-commit-config.yaml", "read_file", ".pre-commit-config.yaml", nil, "", "", 0),
		// .gitattributes drivers.
		fa("gitattributes custom filter", "write_file", ".gitattributes", whole("* filter=evil\n"), "", "R-114", DecisionAsk),
		fa("gitattributes edit adding a custom diff driver", "edit_file", ".gitattributes",
			[]ProposedEdit{replace("*.png binary\n", "*.png binary\n*.json diff=jsontool\n")}, "*.png binary\n", "R-114", DecisionAsk),
		fa("gitattributes LFS line", "write_file", ".gitattributes", whole("*.psd filter=lfs diff=lfs merge=lfs -text\n"), "", "", 0),
		fa("gitattributes built-in diff pattern", "write_file", ".gitattributes", whole("*.go diff=golang\n"), "", "", 0),
		fa("gitattributes keeping an existing driver", "edit_file", ".gitattributes",
			[]ProposedEdit{replace("* filter=x\n", "* filter=x\n*.go diff=golang\n")}, "* filter=x\n", "", 0),
		sh("echo a custom driver into .gitattributes", `echo '* filter=evil' >> .gitattributes`, "R-114", DecisionAsk),
		sh("echo an LFS line into .gitattributes", `echo '*.bin filter=lfs' >> .gitattributes`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-114")
}

// TestGitHookRulesAreNotIntegrity pins that R-112 to R-114 follow Guard's
// ordinary overrides: they protect the repository's hooks, which the
// developer may switch off for a project, not Guard's own.
func TestGitHookRulesAreNotIntegrity(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"R-112", "R-113", "R-114"} {
		if IsIntegrityRuleID(id) {
			t.Errorf("%s is in the integrity set", id)
		}
	}
	e, err := New(Config{Mode: ModeEnforce, Home: "/home/u", Disabled: []string{"R-112"}})
	if err != nil {
		t.Fatal(err)
	}
	v := e.Evaluate(Event{Kind: KindShellExec, Target: "git commit --no-verify -m x", Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj"})
	if v.RuleID == "R-112" {
		t.Fatalf("disabled R-112 still fired: %+v", v)
	}
}

// TestParseGitConfigParameters pins the GIT_CONFIG_PARAMETERS reader one
// shape per row.
func TestParseGitConfigParameters(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		ok      bool
		keys    []string
		lastVal string
	}{
		{`'core.hooksPath'='/dev/null'`, true, []string{"core.hookspath"}, "/dev/null"},
		{`'core.hooksPath=/dev/null'`, true, []string{"core.hookspath"}, "/dev/null"},
		{`'a.b'='1' 'alias.x'='commit -n'`, true, []string{"a.b", "alias.x"}, "commit -n"},
		{`'user.name'='O'\''Brien'`, true, []string{"user.name"}, "O'Brien"},
		{`core.hooksPath=/dev/null`, false, nil, ""},
		{`'unterminated`, false, nil, ""},
	}
	for _, tc := range cases {
		got, ok := parseGitConfigParameters(tc.in)
		if ok != tc.ok {
			t.Errorf("%q: ok=%v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if len(got) != len(tc.keys) {
			t.Errorf("%q: %d entries, want %d", tc.in, len(got), len(tc.keys))
			continue
		}
		for i, k := range tc.keys {
			if got[i].key != k {
				t.Errorf("%q: key %d = %q, want %q", tc.in, i, got[i].key, k)
			}
		}
		if got[len(got)-1].value != tc.lastVal {
			t.Errorf("%q: value %q, want %q", tc.in, got[len(got)-1].value, tc.lastVal)
		}
	}
}

// TestUnitEnv pins Command.Env: prefix assignments and env-wrapper
// operands, never the command's own arguments.
func TestUnitEnv(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line string
		want []string
	}{
		{`HUSKY=0 git commit`, []string{"HUSKY=0"}},
		{`A=1 B=2 git commit X=3`, []string{"A=1", "B=2"}},
		{`env -u X SKIP=all git commit`, []string{"SKIP=all"}},
		{`if FOO=1 git status; then :; fi`, []string{"FOO=1"}},
		{`git commit`, nil},
	}
	for _, tc := range cases {
		cmds := ParseCommand(tc.line, DialectPosix)
		if len(cmds) == 0 {
			t.Fatalf("%q: no units", tc.line)
		}
		got := cmds[0].Env
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%q: Env %q, want %q", tc.line, got, tc.want)
		}
	}
}
