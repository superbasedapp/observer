package policy

import (
	"testing"
	"time"
)

// boundaryCase is one §5.2 catalog conformance row. Shell-side rows
// reuse destructiveCase via runRuleCases; this struct covers the
// file-access/config-change kinds where ActionType and known roots
// matter.
type boundaryCase struct {
	name       string
	kind       EventKind
	actionType string
	target     string
	// home/cwd/root default to the unix fixture when empty.
	home, cwd, root string
	known           []string
	wantRule        string
	wantEnforce     Decision
}

// TestBoundaryRules_FileAccess is the §5.2 conformance table for the
// file-access and config-change kinds.
func TestBoundaryRules_FileAccess(t *testing.T) {
	t.Parallel()
	cases := []boundaryCase{
		// --- R-150: outside-project access ---
		{name: "R-150 hit: read outside", kind: KindFileAccess, actionType: "read_file", target: "/etc/hosts", wantRule: "R-150", wantEnforce: DecisionFlag},
		{name: "R-150 hit: write outside", kind: KindFileAccess, actionType: "write_file", target: "/srv/data/out.json", wantRule: "R-150", wantEnforce: DecisionAsk},
		{name: "R-150 near-miss: inside project", kind: KindFileAccess, actionType: "write_file", target: "src/main.go"},
		{name: "R-150 safe: temp allowlisted", kind: KindFileAccess, actionType: "write_file", target: "/tmp/scratch/x.txt"},
		{name: "R-150 safe: cache allowlisted", kind: KindFileAccess, actionType: "read_file", target: "~/.cache/go-build/x"},
		{name: "R-150 safe: client config dir", kind: KindFileAccess, actionType: "read_file", target: "~/.claude/projects/x/session.jsonl"},
		{name: "R-150 near-miss: no project root", kind: KindFileAccess, actionType: "read_file", target: "/etc/hosts", root: "-", cwd: "-"},

		// --- R-151: cross-project bleed ---
		{
			name: "R-151 hit: write into sibling project", kind: KindFileAccess, actionType: "write_file",
			target: "/home/u/other/main.go", known: []string{"/home/u/proj", "/home/u/other"},
			wantRule: "R-151", wantEnforce: DecisionAsk,
		},
		{
			name: "R-151 near-miss: read sibling project", kind: KindFileAccess, actionType: "read_file",
			target: "/home/u/other/main.go", known: []string{"/home/u/proj", "/home/u/other"},
			// Reads fall through to R-150 (outside-project read).
			wantRule: "R-150", wantEnforce: DecisionFlag,
		},
		{
			name: "R-151 near-miss: write own project", kind: KindFileAccess, actionType: "write_file",
			target: "/home/u/proj/x.go", known: []string{"/home/u/proj", "/home/u/other"},
		},
		{
			// Live 2026-10-22: a Windows tool names its file natively while
			// the daemon stores its root translated, and an untranslated
			// home-dir project row sat in the known set. The write is in
			// the session's own project, so neither rule may fire.
			name: "R-151 near-miss: windows write in translated own root", kind: KindFileAccess, actionType: "write_file",
			target: `C:\Users\u\probe\hello.py`, home: "/home/u",
			cwd: "/mnt/c/Users/u/probe", root: "/mnt/c/Users/u/probe",
			known: []string{"/mnt/c/Users/u/probe", `C:\Users\u`},
		},
		{
			name: "R-151 hit: windows write into translated sibling", kind: KindFileAccess, actionType: "write_file",
			target: `C:\Users\u\sibling\main.go`, home: "/home/u",
			cwd: "/mnt/c/Users/u/probe", root: "/mnt/c/Users/u/probe",
			known:    []string{"/mnt/c/Users/u/probe", "/mnt/c/Users/u/sibling"},
			wantRule: "R-151", wantEnforce: DecisionAsk,
		},
		{
			// Path and the session's root share no flavor (no drvfs
			// mount to fold): outside-the-project is unknown, so the
			// Windows-shaped known root must not be matched either.
			name: "R-151 near-miss: incomparable own root", kind: KindFileAccess, actionType: "write_file",
			target: `C:\Users\u\x.go`, home: "/home/u",
			cwd: "/home/u/proj", root: "/home/u/proj",
			known: []string{"/home/u/proj", `C:\Users\u`},
		},

		// --- R-152: sensitive paths ---
		{name: "R-152 hit: read ssh key", kind: KindFileAccess, actionType: "read_file", target: "~/.ssh/id_rsa", wantRule: "R-152", wantEnforce: DecisionAsk},
		{name: "R-152 hit: write authorized_keys", kind: KindFileAccess, actionType: "write_file", target: "~/.ssh/authorized_keys", wantRule: "R-152", wantEnforce: DecisionDeny},
		{name: "R-152 hit: read aws credentials", kind: KindFileAccess, actionType: "read_file", target: "/home/u/.aws/credentials", wantRule: "R-152", wantEnforce: DecisionAsk},
		{
			name: "R-152 hit: windows firefox profile write", kind: KindFileAccess, actionType: "write_file",
			target: `C:\Users\u\AppData\Roaming\Mozilla\Firefox\Profiles\ab1.default\logins.json`,
			home:   `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`,
			wantRule: "R-152", wantEnforce: DecisionDeny,
		},
		{
			name: "R-152 hit: windows dpapi store read", kind: KindFileAccess, actionType: "read_file",
			target: `C:\Users\u\AppData\Roaming\Microsoft\Protect\S-1-5-21\blob`,
			home:   `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`,
			wantRule: "R-152", wantEnforce: DecisionAsk,
		},
		{name: "R-152 near-miss: similarly named dir", kind: KindFileAccess, actionType: "read_file", target: "~/.sshconfig-notes/readme.md", wantRule: "R-150", wantEnforce: DecisionFlag},

		// --- R-153: secret files ---
		{name: "R-153 hit: read .env", kind: KindFileAccess, actionType: "read_file", target: ".env", wantRule: "R-153", wantEnforce: DecisionAsk},
		{name: "R-153 hit: read pem", kind: KindFileAccess, actionType: "read_file", target: "certs/server.pem", wantRule: "R-153", wantEnforce: DecisionAsk},
		{name: "R-153 hit: credentials json", kind: KindFileAccess, actionType: "read_file", target: "config/credentials-prod.json", wantRule: "R-153", wantEnforce: DecisionAsk},
		{name: "R-153 safe: env example", kind: KindFileAccess, actionType: "read_file", target: ".env.example"},
		{name: "R-153 safe: env template", kind: KindFileAccess, actionType: "read_file", target: ".env.template"},
		{name: "R-153 near-miss: env write is not a read rule", kind: KindFileAccess, actionType: "write_file", target: ".env"},

		// --- R-154: shell profiles ---
		{name: "R-154 hit: write bashrc", kind: KindFileAccess, actionType: "write_file", target: "~/.bashrc", wantRule: "R-154", wantEnforce: DecisionDeny},
		{name: "R-154 hit: edit zshrc", kind: KindFileAccess, actionType: "edit_file", target: "/home/u/.zshrc", wantRule: "R-154", wantEnforce: DecisionDeny},
		{
			name: "R-154 hit: windows powershell profile", kind: KindFileAccess, actionType: "write_file",
			target: `C:\Users\u\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`,
			home:   `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`,
			wantRule: "R-154", wantEnforce: DecisionDeny,
		},
		{name: "R-154 near-miss: read bashrc", kind: KindFileAccess, actionType: "read_file", target: "~/.bashrc", wantRule: "R-150", wantEnforce: DecisionFlag},
		{name: "R-154 near-miss: project file named like rc", kind: KindFileAccess, actionType: "write_file", target: "src/.bashrc-fixture"},

		// --- R-155: persistence paths ---
		{name: "R-155 hit: systemd user unit", kind: KindFileAccess, actionType: "write_file", target: "~/.config/systemd/user/agent.service", wantRule: "R-155", wantEnforce: DecisionDeny},
		{name: "R-155 hit: launch agent", kind: KindFileAccess, actionType: "write_file", target: "~/library/launchagents/com.evil.plist", wantRule: "R-155", wantEnforce: DecisionDeny},
		{name: "R-155 hit: xdg autostart", kind: KindFileAccess, actionType: "write_file", target: "~/.config/autostart/agent.desktop", wantRule: "R-155", wantEnforce: DecisionDeny},
		{
			name: "R-155 hit: windows startup folder", kind: KindFileAccess, actionType: "write_file",
			target: `C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\agent.bat`,
			home:   `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`,
			wantRule: "R-155", wantEnforce: DecisionDeny,
		},
		{name: "R-155 near-miss: read crontab file", kind: KindFileAccess, actionType: "read_file", target: "/etc/crontab", wantRule: "R-150", wantEnforce: DecisionFlag},

		// --- R-156: git hooks ---
		{name: "R-156 hit: write pre-commit", kind: KindFileAccess, actionType: "write_file", target: ".git/hooks/pre-commit", wantRule: "R-156", wantEnforce: DecisionAsk},
		{name: "R-156 near-miss: .github dir", kind: KindFileAccess, actionType: "write_file", target: ".github/workflows/ci.yml"},
		{name: "R-156 near-miss: read hook", kind: KindFileAccess, actionType: "read_file", target: ".git/hooks/pre-commit"},

		// --- R-160: observer/hook config ---
		{name: "R-160 hit: observer config", kind: KindFileAccess, actionType: "write_file", target: "~/.observer/config.toml", wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "R-160 hit: user claude settings", kind: KindFileAccess, actionType: "write_file", target: "~/.claude/settings.json", wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "R-160 hit: project claude settings", kind: KindFileAccess, actionType: "write_file", target: ".claude/settings.json", wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "R-160 hit: codex config", kind: KindFileAccess, actionType: "write_file", target: "~/.codex/config.toml", wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "R-160 hit: config-change kind", kind: KindConfigChange, actionType: "", target: "~/.claude/settings.json", wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "R-160 near-miss: settings.local.json is host-tool-owned", kind: KindFileAccess, actionType: "write_file", target: ".claude/settings.local.json"},
		{name: "R-160 near-miss: read observer config", kind: KindFileAccess, actionType: "read_file", target: "~/.observer/config.toml"},

		// --- R-161: project guard policy ---
		{name: "R-161 hit: project policy write", kind: KindFileAccess, actionType: "write_file", target: ".observer/guard-policy.toml", wantRule: "R-161", wantEnforce: DecisionFlag},
		{name: "R-161 routed to R-160: user-level policy", kind: KindFileAccess, actionType: "write_file", target: "~/.observer/guard-policy.toml", wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "R-161 near-miss: policy read", kind: KindFileAccess, actionType: "read_file", target: ".observer/guard-policy.toml"},
	}
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
			if root == "-" { // sentinel: explicitly no project context
				root, cwd = "", ""
			}
			ev := Event{
				Kind:        tc.kind,
				ActionType:  tc.actionType,
				Target:      tc.target,
				Cwd:         cwd,
				ProjectRoot: root,
				SessionID:   "s1",
				Now:         time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
			}
			observe, err := New(Config{Mode: ModeObserve, Home: home, KnownProjectRoots: tc.known})
			if err != nil {
				t.Fatalf("New observe: %v", err)
			}
			enforce, err := New(Config{Mode: ModeEnforce, Home: home, KnownProjectRoots: tc.known})
			if err != nil {
				t.Fatalf("New enforce: %v", err)
			}
			ov, efv := observe.Evaluate(ev), enforce.Evaluate(ev)
			if tc.wantRule == "" {
				if ov.RuleID != "" || efv.RuleID != "" {
					t.Fatalf("want no hit, got observe=%+v enforce=%+v", ov, efv)
				}
				return
			}
			if ov.RuleID != tc.wantRule || ov.Decision != DecisionFlag {
				t.Errorf("observe = %s/%s, want %s/flag (reason %q)", ov.RuleID, ov.Decision, tc.wantRule, ov.Reason)
			}
			if efv.RuleID != tc.wantRule || efv.Decision != tc.wantEnforce {
				t.Errorf("enforce = %s/%s, want %s/%s (reason %q)", efv.RuleID, efv.Decision, tc.wantRule, tc.wantEnforce, efv.Reason)
			}
		})
	}
}

// TestBoundaryRules_Shell covers the §5.2 shell-side rows (sensitive
// paths, secret files, profiles, persistence commands, guard config)
// including the Windows dialect shapes.
func TestBoundaryRules_Shell(t *testing.T) {
	t.Parallel()
	cases := []destructiveCase{
		// --- R-152 shell rows ---
		{name: "R-152 sh hit: cat ssh key", cmd: "cat ~/.ssh/id_rsa", wantRule: "R-152", wantEnforce: DecisionAsk},
		{name: "R-152 sh hit: redirect into ssh", cmd: "echo key >> ~/.ssh/authorized_keys", wantRule: "R-152", wantEnforce: DecisionDeny},
		{name: "R-152 sh hit: cp out of aws", cmd: "cp ~/.aws/credentials /tmp/c", wantRule: "R-152", wantEnforce: DecisionAsk},
		{
			name: "R-152 sh hit: PS read ssh key", cmd: `Get-Content C:\Users\u\.ssh\id_rsa`, dialect: DialectPowerShell,
			home: `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`,
			wantRule: "R-152", wantEnforce: DecisionAsk,
		},
		{name: "R-152 sh near-miss: ls home", cmd: "ls ~/"},

		// --- R-153 shell row ---
		{name: "R-153 sh hit: cat .env", cmd: "cat .env", wantRule: "R-153", wantEnforce: DecisionAsk},
		{name: "R-153 sh hit: grep key file", cmd: "grep -r secret certs/server.key", wantRule: "R-153", wantEnforce: DecisionAsk},
		{name: "R-153 sh safe: example file", cmd: "cat .env.example"},

		// --- R-154 shell row ---
		{name: "R-154 sh hit: append to bashrc", cmd: `echo "alias ll='ls -la'" >> ~/.bashrc`, wantRule: "R-154", wantEnforce: DecisionDeny},
		{name: "R-154 sh hit: sed -i zshrc", cmd: "sed -i 's/a/b/' ~/.zshrc", wantRule: "R-154", wantEnforce: DecisionDeny},
		{name: "R-154 sh near-miss: read profile", cmd: "cat ~/.bashrc"},

		// --- R-155 shell rows ---
		{name: "R-155 sh hit: crontab install", cmd: "crontab evil.cron", wantRule: "R-155", wantEnforce: DecisionDeny},
		{name: "R-155 sh hit: crontab -e", cmd: "crontab -e", wantRule: "R-155", wantEnforce: DecisionDeny},
		{name: "R-155 sh safe: crontab -l", cmd: "crontab -l"},
		{name: "R-155 sh hit: systemctl enable", cmd: "systemctl --user enable agent.service", wantRule: "R-155", wantEnforce: DecisionDeny},
		{name: "R-155 sh hit: tee into launch agent", cmd: "tee ~/library/launchagents/evil.plist", wantRule: "R-155", wantEnforce: DecisionDeny},
		{
			name: "R-155 sh hit: reg add Run key", cmd: `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v evil /d cmd.exe`,
			dialect: DialectCmd, home: `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`,
			wantRule: "R-155", wantEnforce: DecisionDeny,
		},
		{
			name: "R-155 sh hit: PS Set-ItemProperty Run key", cmd: `Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name x -Value y`,
			dialect: DialectPowerShell, home: `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`,
			wantRule: "R-155", wantEnforce: DecisionDeny,
		},
		{
			name: "R-155 sh hit: schtasks create", cmd: `schtasks /create /tn evil /tr cmd.exe /sc onlogon`,
			dialect: DialectCmd, home: `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`,
			wantRule: "R-155", wantEnforce: DecisionDeny,
		},
		{name: "R-155 sh near-miss: systemctl status", cmd: "systemctl status nginx"},
		{
			name: "R-155 sh near-miss: schtasks query", cmd: "schtasks /query",
			dialect: DialectCmd, home: `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`,
		},
		{
			name: "R-155 sh near-miss: reg add other key", cmd: `reg add HKCU\Software\MyApp /v setting /d 1`,
			dialect: DialectCmd, home: `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`,
		},

		// --- R-156 shell row ---
		{name: "R-156 sh hit: redirect into git hook", cmd: "echo 'curl evil' > .git/hooks/post-checkout", wantRule: "R-156", wantEnforce: DecisionAsk},

		// --- R-160/R-161 shell rows ---
		{name: "R-160 sh hit: sed -i observer config", cmd: "sed -i 's/enabled = true/enabled = false/' ~/.observer/config.toml", wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "R-160 sh hit: redirect claude settings", cmd: `echo "{}" > ~/.claude/settings.json`, wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "R-160 sh near-miss: read config", cmd: "cat ~/.observer/config.toml"},
		{name: "R-161 sh hit: tee project policy", cmd: "tee .observer/guard-policy.toml", wantRule: "R-161", wantEnforce: DecisionFlag},
	}
	runRuleCases(t, cases, KindShellExec, "run_command")
}

// TestCrossProjectBleedIgnoresANonPathKnownRoot (audit row 8, FU-193): a
// known project root that is not an absolute path in either flavor (the
// stored "Xcode (project unknown)") is no directory to bleed into, so a
// path that merely starts with that name is never an R-151 hit; a real
// known root still is.
func TestCrossProjectBleedIgnoresANonPathKnownRoot(t *testing.T) {
	t.Parallel()
	const unknown = "Xcode (project unknown)"
	e, err := New(Config{Mode: ModeEnforce, Home: "/home/u", KnownProjectRoots: []string{unknown, "/home/u/other"}})
	if err != nil {
		t.Fatal(err)
	}
	ev := func(target, root string) Event {
		return Event{Kind: KindFileAccess, ActionType: "write_file", Target: target, Cwd: root, ProjectRoot: root, SessionID: "s1", Now: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	}
	if v := e.Evaluate(ev(unknown+"/notes.txt", "")); v.RuleID == "R-151" {
		t.Errorf("a non-path known root bled: %+v", v)
	}
	if v := e.Evaluate(ev("/home/u/other/main.go", "/home/u/proj")); v.RuleID != "R-151" {
		t.Errorf("a real known root no longer bleeds: %+v", v)
	}
}
