package policy

import (
	"testing"
	"time"
)

// g4Context builds the engine's match context for one event, as Evaluate
// does.
func g4Context(t *testing.T, ev Event) *MatchContext {
	t.Helper()
	const home, root = "/home/u", "/home/u/proj"
	ev.Cwd, ev.ProjectRoot, ev.SessionID = root, root, "s1"
	ev.Now = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	e, err := New(Config{Mode: ModeEnforce, Home: home})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e.buildContext(&ev)
}

// TestPushTargetForRedirects (lane sec-gate4 audit findings 3 and 5): a
// command line that may change where a push goes makes its target unknown;
// a plain push goes to the signed default push remote, unknown without one.
func TestPushTargetForRedirects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, line string
		dialect    Dialect
		def        string
		want       string // "" = unknown
	}{
		{"named remote", `git push origin main`, "", "origin", "origin"},
		{"plain push goes to the default", `git push`, "", "origin", "origin"},
		{"plain push -u goes to the default", `git push -u`, "", "origin", "origin"},
		{"plain push without a default", `git push`, "", "", ""},
		{"a default that is not a remote name", `git push`, "", "../x", ""},
		{"-c pushurl", `git -c remote.origin.pushurl=https://x.invalid/r.git push origin main`, "", "origin", ""},
		{"-c pushurl, other case", `git -c Remote.origin.PushURL=/tmp/x push origin main`, "", "origin", ""},
		{"-c pushInsteadOf", `git -c url./tmp/x.pushInsteadOf=https://example.invalid/ push origin main`, "", "origin", ""},
		{"-c branch pushRemote on a plain push", `git -c branch.main.pushRemote=backup push`, "", "origin", ""},
		{"-c remote.pushDefault on a plain push", `git -c remote.pushDefault=backup push`, "", "origin", ""},
		{"-c include.path", `git -c include.path=/tmp/evil push origin main`, "", "origin", ""},
		{"--config-env url", `git --config-env=remote.origin.url=U push origin main`, "", "origin", ""},
		{"--config-env separate", `git --config-env remote.origin.url=U push origin main`, "", "origin", ""},
		{"-c of another key", `git -c user.name=x push origin main`, "", "origin", "origin"},
		{"GIT_CONFIG_COUNT prefix", `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=remote.origin.pushurl GIT_CONFIG_VALUE_0=/tmp/x git push origin main`, "", "origin", ""},
		{"GIT_CONFIG_PARAMETERS through env", `env GIT_CONFIG_PARAMETERS="'remote.origin.pushurl'='/tmp/x'" git push origin main`, "", "origin", ""},
		{"GIT_CONFIG_GLOBAL prefix", `GIT_CONFIG_GLOBAL=/tmp/g git push origin main`, "", "origin", ""},
		{"GIT_CONFIG_SYSTEM on a plain push", `GIT_CONFIG_SYSTEM=/tmp/s git push`, "", "origin", ""},
		{"GIT_DIR prefix", `GIT_DIR=/tmp/r.git git push origin main`, "", "origin", ""},
		{"export GIT_DIR", `export GIT_DIR=/tmp/r.git; git push origin main`, "", "origin", ""},
		{"PowerShell $env:GIT_CONFIG_GLOBAL", `$env:GIT_CONFIG_GLOBAL = 'C:\g'; git push origin main`, DialectPowerShell, "origin", ""},
		{"PowerShell $env:GIT_DIR", `$env:GIT_DIR='C:\r'; git push`, DialectPowerShell, "origin", ""},
		{"remote set-url earlier on the line", `git remote set-url origin /tmp/x && git push origin main`, "", "origin", ""},
		{"branch switch earlier on the line", `git checkout other && git push`, "", "origin", ""},
		{"a read earlier on the line", `git status && git push origin main`, "", "origin", "origin"},
		{"through an alias", `git config alias.p push && git -c remote.origin.pushurl=/tmp/x p origin main`, "", "origin", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var push *GitWrite
			for _, c := range ClassifyCommitCommands(ParseCommand(tc.line, tc.dialect), nil) {
				if GitWriteIsPush(c.Write) {
					w := c.Write
					push = &w
				}
			}
			if push == nil {
				t.Fatalf("%q: no push classified", tc.line)
			}
			got := PushTargetFor(*push, tc.def)
			if (tc.want != "") != got.Known || got.Remote != tc.want {
				t.Fatalf("%q: target %+v, want %q", tc.line, got, tc.want)
			}
		})
	}
}

// TestRemoteStateWriteOf (lane sec-gate4 audit finding 3): the writes that
// would make the per-remote credit read a remote as having a commit it
// never received, each spelling, and the reads that stay unmatched.
func TestRemoteStateWriteOf(t *testing.T) {
	t.Parallel()
	shell := func(line string) Event { return Event{Kind: KindShellExec, ActionType: "run_command", Target: line} }
	file := func(action, path string) Event { return Event{Kind: KindFileAccess, ActionType: action, Target: path} }
	cases := []struct {
		name string
		ev   Event
		want bool
	}{
		{"update-ref a tracking ref", shell(`git update-ref refs/remotes/backup/x HEAD`), true},
		{"update-ref with a message, other case", shell(`git update-ref -m sync refs/Remotes/backup/x HEAD`), true},
		{"update-ref --stdin", shell(`git update-ref --stdin`), true},
		{"update-ref a branch", shell(`git update-ref refs/heads/x HEAD`), false},
		{"symbolic-ref a tracking ref", shell(`git symbolic-ref refs/remotes/backup/HEAD refs/heads/main`), true},
		{"fetch from the repository itself", shell(`git fetch . HEAD:refs/remotes/backup/x`), true},
		{"fetch from a relative path", shell(`git fetch ../clone main`), true},
		{"fetch from an absolute path", shell(`git fetch /tmp/clone`), true},
		{"fetch from a file URL", shell(`git fetch file:///tmp/clone`), true},
		{"fetch from a Windows path", shell(`git fetch C:\work\clone`), true},
		{"fetch refspec into the tracking refs", shell(`git fetch origin +main:refs/remotes/backup/main`), true},
		{"fetch --refmap into the tracking refs", shell(`git fetch origin --refmap=+refs/heads/*:refs/remotes/backup/*`), true},
		{"fetch with a url override", shell(`git -c remote.origin.url=. fetch origin`), true},
		{"fetch through an alias", shell(`git config alias.f fetch && git f . HEAD:refs/remotes/backup/x`), true},
		{"plain fetch", shell(`git fetch origin`), false},
		{"fetch --all --prune", shell(`git fetch --all --prune`), false},
		{"remote set-url", shell(`git remote set-url origin /tmp/x`), true},
		{"remote set-url --push", shell(`git remote set-url --push backup /tmp/x`), true},
		{"remote add", shell(`git remote add backup .`), true},
		{"remote rename", shell(`git remote rename backup origin`), true},
		{"remote remove", shell(`git remote remove backup`), true},
		{"remote -v", shell(`git remote -v`), false},
		{"config a remote URL", shell(`git config remote.backup.url /tmp/x`), true},
		{"config --unset a push URL", shell(`git config --unset remote.backup.pushurl`), true},
		{"config --remove-section", shell(`git config --remove-section remote.backup`), true},
		{"config pushInsteadOf", shell(`git config url./tmp/x.pushInsteadOf https://example.invalid/`), true},
		{"config branch pushRemote", shell(`git config branch.main.pushRemote origin`), true},
		{"config --edit", shell(`git config -e`), true},
		{"config --get is a read", shell(`git config --get remote.origin.url`), false},
		{"config get verb is a read", shell(`git config get remote.origin.url`), false},
		{"config of another key", shell(`git config user.name x`), false},
		{"branch --set-upstream-to", shell(`git branch --set-upstream-to=backup/main`), true},
		{"branch -u", shell(`git branch -u backup/main`), true},
		{"branch -vv is a read", shell(`git branch -vv`), false},
		{"redirect into a tracking ref", shell(`echo 0123 > .git/refs/remotes/backup/main`), true},
		{"cp onto the packed refs", shell(`cp /tmp/p .git/packed-refs`), true},
		{"tee the git config", shell(`printf '[remote "b"]' | tee -a .git/config`), true},
		{"python writes the packed refs", shell(`python3 -c "open('.git/packed-refs','a').write('x')"`), true},
		{"PowerShell Set-Content on the git config", Event{Kind: KindShellExec, ActionType: "run_command", Dialect: DialectPowerShell, Target: `Set-Content -Path .git\config -Value x`}, true},
		{"cat the git config is a read", shell(`cat .git/config`), false},
		{"Write tool on a tracking ref", file("write_file", "/home/u/proj/.git/refs/remotes/backup/main"), true},
		{"Edit tool on the git config", file("edit_file", ".git/config"), true},
		{"Write tool on the packed refs", file("write_file", "/home/u/proj/.git/packed-refs"), true},
		{"Read tool on the git config", file("read_file", "/home/u/proj/.git/config"), false},
		{"Write tool on another file", file("write_file", "/home/u/proj/config"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, d := RemoteStateWriteOf(g4Context(t, tc.ev))
			if got != tc.want {
				t.Fatalf("%q: %v (%q), want %v", tc.ev.Target, got, d, tc.want)
			}
		})
	}
}
