package policy

import (
	"testing"
	"time"
)

// runBoundaryFACases runs file-access / config-change boundaryCases against
// fresh observe- and enforce-mode engines, the same body TestBoundaryRules_
// FileAccess uses inline (home defaults to /home/u, root to /home/u/proj).
func runBoundaryFACases(t *testing.T, cases []boundaryCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			home := tc.home
			if home == "" {
				home = "/home/u"
			}
			root, cwd := tc.root, tc.cwd
			if root == "" {
				root = "/home/u/proj"
			}
			if cwd == "" {
				cwd = root
			}
			if root == "-" {
				root, cwd = "", ""
			}
			ev := Event{
				Kind: tc.kind, ActionType: tc.actionType, Target: tc.target,
				Cwd: cwd, ProjectRoot: root, SessionID: "s1",
				Now: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
			}
			enforce, err := New(Config{Mode: ModeEnforce, Home: home, KnownProjectRoots: tc.known})
			if err != nil {
				t.Fatalf("New enforce: %v", err)
			}
			v := enforce.Evaluate(ev)
			if tc.wantRule == "" {
				if v.RuleID != "" {
					t.Fatalf("%q: want no hit, got %+v", tc.target, v)
				}
				return
			}
			if v.RuleID != tc.wantRule || v.Decision != tc.wantEnforce {
				t.Errorf("%q = %s/%s, want %s/%s (reason %q)", tc.target, v.RuleID, v.Decision, tc.wantRule, tc.wantEnforce, v.Reason)
			}
		})
	}
}

// TestSA1ClassifyWriteGuardConfig pins SA-1: the writers classifyWrite
// missed now resolve to writes, so a write to Observer's own config /
// guard files is R-160 (and a sensitive-path write is R-152). Each is run
// in ModeEnforce under the default unix fixture (home /home/u, project
// /home/u/proj) via runRuleCases.
func TestSA1ClassifyWriteGuardConfig(t *testing.T) {
	t.Parallel()
	cases := []destructiveCase{
		// In-place editors naming the guard config.
		{name: "perl -pi observer config", cmd: `perl -pi -e 's/enforce/off/' ~/.observer/config.toml`, wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "perl -i.bak observer config", cmd: `perl -i.bak -pe 's/a/b/' ~/.observer/guard-policy.toml`, wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "ruby -i observer config", cmd: `ruby -i -e 'gsub(/a/,"b")' ~/.observer/config.toml`, wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "gawk -i inplace observer config", cmd: `gawk -i inplace '{print}' ~/.observer/config.toml`, wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "ex -sc observer config", cmd: `ex -sc 'wq' ~/.observer/config.toml`, wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "vim -c observer config", cmd: `vim -c 'wq' ~/.observer/config.toml`, wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "vi -c observer config", cmd: `vi -c 'wq' ~/.observer/config.toml`, wantRule: "R-160", wantEnforce: DecisionDeny},
		// Byte / link / archive / buffer writers.
		{name: "dd of observer config", cmd: `dd of=~/.observer/config.toml`, wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "ln -sf observer config", cmd: `ln -sf /tmp/evil ~/.observer/config.toml`, wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "cp -t guard-recipes", cmd: `cp -t ~/.observer/guard-recipes/ x.toml`, wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "cp --target-directory guard-recipes", cmd: `cp --target-directory=~/.observer/guard-recipes/ x.toml`, wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "tar -C observer extract", cmd: `tar -C ~/.observer -xf x.tar`, wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "tar --directory observer extract", cmd: `tar --directory ~/.observer -xf x.tar`, wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "unzip -d observer", cmd: `unzip -d ~/.observer x.zip`, wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "sponge observer config", cmd: `sponge ~/.observer/config.toml`, wantRule: "R-160", wantEnforce: DecisionDeny},
		// The same writers generalise to the sensitive-path set (R-152).
		{name: "dd of ssh authorized_keys", cmd: `dd of=~/.ssh/authorized_keys`, wantRule: "R-152", wantEnforce: DecisionDeny},
		{name: "ln -sf ssh key", cmd: `ln -sf /tmp/evil ~/.ssh/id_rsa`, wantRule: "R-152", wantEnforce: DecisionDeny},
		{name: "perl -pi bashrc profile", cmd: `perl -pi -e 's/a/b/' ~/.bashrc`, wantRule: "R-154", wantEnforce: DecisionDeny},

		// --- False positives that must STAY allowed ---
		{name: "FP perl -pi project file", cmd: `perl -pi -e 's/a/b/' src/main.go`},
		{name: "FP ruby -i project file", cmd: `ruby -i -e 'x' src/app.rb`},
		{name: "FP gawk inplace project file", cmd: `gawk -i inplace '{print}' build/out.txt`},
		{name: "FP vim -c project file", cmd: `vim -c 'set ft=go' src/main.go`},
		{name: "FP vim read-only no command", cmd: `vim ~/.observer/config.toml`}, // opens, not a batch edit
		{name: "FP tar -C project extract", cmd: `tar -C build -xf x.tar`},
		{name: "FP tar -C observer but CREATE not extract", cmd: `tar -C ~/.observer -cf /tmp/scratch/out.tar .`}, // reads the dir
		{name: "FP cp -t project dir", cmd: `cp -t build x.toml`},
		{name: "FP dd of project file", cmd: `dd of=out.bin if=/dev/zero`},
		{name: "FP sponge project file", cmd: `sponge out.txt`},
		{name: "FP unzip -d project", cmd: `unzip -d build x.zip`},
	}
	runRuleCases(t, cases, KindShellExec, "run_command")
}

// TestSA1InlineGuardConfig pins the SA-1 R-160 inline row: a guard-owned
// path named inside interpreter program text is R-160.
func TestSA1InlineGuardConfig(t *testing.T) {
	t.Parallel()
	cases := []destructiveCase{
		{name: "python open append observer config", cmd: `python3 -c "open('/home/u/.observer/config.toml','a').write('x')"`, wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "node appendFileSync observer config", cmd: `node -e "require('fs').appendFileSync('/home/u/.observer/config.toml','x')"`, wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "python heredoc observer config", cmd: "python3 - <<'PY'\nopen('/home/u/.observer/config.toml','a').write('x')\nPY", wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "node writeFileSync claude settings", cmd: `node -e "require('fs').writeFileSync('/home/u/.claude/settings.json','{}')"`, wantRule: "R-160", wantEnforce: DecisionDeny},
		// FP: an inline program naming a project file is not guard config.
		{name: "FP python open project file", cmd: `python3 -c "open('/home/u/proj/main.py','a').write('x')"`},
	}
	runRuleCases(t, cases, KindShellExec, "run_command")
}

// uncWSL builds a `\\<host>\<distro>\<linux path>` UNC string at runtime so
// the leading double backslash is unambiguous in source.
func uncWSL(host, rest string) string {
	bs := string([]byte{'\\'})
	return bs + bs + host + bs + rest
}

// TestSA3WSLUNCGuardConfig pins SA-3: Observer's protected home reached
// across the WSL boundary — via a `\\wsl.localhost` / `\\wsl$` UNC path
// (Windows tool, WSL daemon) or a `/mnt/c` drvfs mount (WSL tool, Windows
// daemon) — is still R-160, both as a Write-tool file access and as a shell
// write. Near-misses (a non-guard project file) stay clear.
func TestSA3WSLUNCGuardConfig(t *testing.T) {
	t.Parallel()
	// File-access (Write tool) cases, WSL daemon home /home/u.
	fa := []boundaryCase{
		{
			name: "wsl.localhost UNC observer config write", kind: KindFileAccess, actionType: "write_file",
			target: uncWSL("wsl.localhost", `Ubuntu\home\u\.observer\config.toml`), home: "/home/u",
			wantRule: "R-160", wantEnforce: DecisionDeny,
		},
		{
			name: "wsl$ UNC observer config write", kind: KindFileAccess, actionType: "write_file",
			target: uncWSL("wsl$", `Ubuntu\home\u\.observer\guard-recipes\x.toml`), home: "/home/u",
			wantRule: "R-160", wantEnforce: DecisionDeny,
		},
		{
			name: "wsl UNC ssh key sensitive write", kind: KindFileAccess, actionType: "write_file",
			target: uncWSL("wsl.localhost", `Ubuntu\home\u\.ssh\authorized_keys`), home: "/home/u",
			wantRule: "R-152", wantEnforce: DecisionDeny,
		},
		{
			name: "near-miss: wsl UNC project file", kind: KindFileAccess, actionType: "write_file",
			target: uncWSL("wsl.localhost", `Ubuntu\home\u\proj\main.go`), home: "/home/u", root: "/home/u/proj",
		},
	}
	runBoundaryFACases(t, fa)

	// drvfs mount, Windows daemon home C:\Users\u.
	drvfs := []boundaryCase{
		{
			name: "mnt-c observer config write (windows daemon)", kind: KindFileAccess, actionType: "write_file",
			target: "/mnt/c/Users/u/.observer/config.toml", home: `C:\Users\u`, root: `C:\Users\u\proj`,
			wantRule: "R-160", wantEnforce: DecisionDeny,
		},
	}
	runBoundaryFACases(t, drvfs)

	// Shell write across the WSL UNC boundary (PowerShell Set-Content).
	sh := []destructiveCase{
		{
			name: "PS Set-Content wsl UNC observer config", dialect: DialectPowerShell,
			cmd:  `Set-Content -Path ` + uncWSL("wsl.localhost", `Ubuntu\home\u\.observer\config.toml`) + ` -Value x`,
			home: "/home/u", root: `C:\proj`, cwd: `C:\proj`,
			wantRule: "R-160", wantEnforce: DecisionDeny,
		},
	}
	runRuleCases(t, sh, KindShellExec, "run_command")
}
