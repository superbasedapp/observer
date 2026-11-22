package policy

import (
	"testing"
	"time"
)

// destructiveCase is one §5.1 catalog conformance row: every rule ID
// gets at least one hit, one safe-pattern pass and one near-miss (the
// dcg corpus style, spec §18).
type destructiveCase struct {
	name    string
	cmd     string
	dialect Dialect
	// home/cwd/root default to the unix test fixture when empty.
	home, cwd, root string
	wantRule        string   // "" = no hit
	wantEnforce     Decision // checked when wantRule != ""
}

// runRuleCases executes catalog conformance cases against fresh
// observe- and enforce-mode engines. All G1 rules observe-flag, so
// the observe expectation is derived: Flag when a rule is expected,
// Allow otherwise.
func runRuleCases(t *testing.T, cases []destructiveCase, kind EventKind, actionType string) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			home := tc.home
			if home == "" {
				home = "/home/u"
			}
			root := tc.root
			if root == "" {
				root = "/home/u/proj"
			}
			cwd := tc.cwd
			if cwd == "" {
				cwd = root
			}
			ev := Event{
				Kind:        kind,
				ActionType:  actionType,
				Target:      tc.cmd,
				Dialect:     tc.dialect,
				Cwd:         cwd,
				ProjectRoot: root,
				SessionID:   "s1",
				Now:         time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
			}
			observe, err := New(Config{Mode: ModeObserve, Home: home})
			if err != nil {
				t.Fatalf("New observe: %v", err)
			}
			enforce, err := New(Config{Mode: ModeEnforce, Home: home})
			if err != nil {
				t.Fatalf("New enforce: %v", err)
			}
			ov, ev2 := observe.Evaluate(ev), enforce.Evaluate(ev)
			if tc.wantRule == "" {
				if ov.RuleID != "" || ev2.RuleID != "" {
					t.Fatalf("want no hit, got observe=%+v enforce=%+v", ov, ev2)
				}
				return
			}
			if ov.RuleID != tc.wantRule || ov.Decision != DecisionFlag {
				t.Errorf("observe = %s/%s, want %s/flag (reason %q)", ov.RuleID, ov.Decision, tc.wantRule, ov.Reason)
			}
			if ev2.RuleID != tc.wantRule || ev2.Decision != tc.wantEnforce {
				t.Errorf("enforce = %s/%s, want %s/%s (reason %q)", ev2.RuleID, ev2.Decision, tc.wantRule, tc.wantEnforce, ev2.Reason)
			}
		})
	}
}

// TestDestructiveRules is the §5.1 conformance table.
func TestDestructiveRules(t *testing.T) {
	t.Parallel()
	cases := []destructiveCase{
		// --- R-101: catastrophic recursive delete ---
		{name: "R-101 hit: rm -rf root", cmd: "rm -rf /", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: rm -fr home", cmd: "rm -fr ~", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: home trailing slash", cmd: "rm -rf ~/", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: $HOME literal", cmd: `rm -rf $HOME`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: outside project", cmd: "rm -rf /etc/nginx", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: relative escape", cmd: "rm -rf ../other", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: root-depth wildcard", cmd: "rm -rf /*", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: sudo wrapped", cmd: "sudo rm -rf /var/www", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: bash -c nested", cmd: `bash -c "rm -rf /"`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: substitution smuggled", cmd: "echo $(rm -rf /etc/x)", wantRule: "R-101", wantEnforce: DecisionDeny},
		{
			name: "R-101 hit: cmd dialect drive root", cmd: `rd /s /q C:\`, dialect: DialectCmd,
			home: `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`,
			wantRule: "R-101", wantEnforce: DecisionDeny,
		},
		{
			name: "R-101 hit: powershell home", cmd: `Remove-Item -Recurse -Force C:\Users\u`, dialect: DialectPowerShell,
			home: `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`,
			wantRule: "R-101", wantEnforce: DecisionDeny,
		},
		{
			name: "R-101 hit: cmd del root wildcard", cmd: `del /s /q C:\*`, dialect: DialectCmd,
			home: `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`,
			wantRule: "R-101", wantEnforce: DecisionDeny,
		},
		// A home directory under an allowlisted location (/tmp/** by
		// default: CI runners, sandboxes, throwaway test homes) must not
		// turn the home / root-depth arms into an exempt temp-dir delete;
		// only the outside-the-project arm is allow_paths-exemptible.
		{name: "R-101 hit: home under tmp", cmd: "rm -rf ~", home: "/tmp/h", root: "/tmp/h/proj", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: $HOME under tmp", cmd: `rm -rf $HOME`, home: "/tmp/h", root: "/tmp/h/proj", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: home wildcard under tmp", cmd: "rm -rf ~/*", home: "/tmp/h", root: "/tmp/h/proj", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: home plus tmp path", cmd: "rm -rf /tmp/build ~", home: "/tmp/h", root: "/tmp/h/proj", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 safe: tmp sibling with home under tmp", cmd: "rm -rf /tmp/build", home: "/tmp/h", root: "/tmp/h/proj"},
		{name: "R-101 safe: tmp allowlisted", cmd: "rm -rf /tmp/build"},
		{name: "R-101 safe: cache allowlisted", cmd: "rm -rf ~/.cache/observer"},
		{name: "R-101 near-miss: inside project", cmd: "rm -rf ./build"},
		// Sol A2-04 (as narrowed): shell expansion the lexer cannot perform.
		// A braced or quoted home variable is the home directory. Any other
		// unexpanded expansion is judged as if it were EMPTY: catastrophic
		// only where that lands on a root, the home directory or a root-depth
		// wildcard; `$VAR/<named subpath>` goes through the normal rules. A
		// single-quoted or escaped `$` is a literal, not an expansion.
		{name: "R-101 hit: quoted braced HOME", cmd: `rm -rf "${HOME}"`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: braced HOME slash", cmd: `rm -rf ${HOME}/`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: braced HOME wildcard", cmd: `rm -rf "${HOME}"/*`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: bare variable", cmd: `rm -rf $TARGET`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: quoted bare variable", cmd: `rm -rf "$TARGET"`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: braced bare variable", cmd: `rm -rf "${TARGET}"`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: variable slash", cmd: `rm -rf "$DIR/"`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: variable wildcard", cmd: `rm -rf "$DIR"/*`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: variable dot", cmd: `rm -rf $DIR/.`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: variable dotdot", cmd: `rm -rf ${DIR}/..`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: root then variable", cmd: `rm -rf /$DIR`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: home then variable", cmd: `rm -rf $HOME/$SUB`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: two bare variables", cmd: `rm -rf "$A$B"`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: command substitution operand", cmd: "rm -rf ./$(echo ..)/..", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 hit: backtick operand", cmd: "rm -rf `pwd`/..", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 near-miss: variable with a named subpath", cmd: `rm -rf "$BUILD_DIR/out"`},
		{name: "R-101 near-miss: braced variable with a named subpath and glob", cmd: `rm -rf "${BUILD_DIR}"/out/*`},
		{name: "R-101 near-miss: variable as the last project segment", cmd: `rm -rf ./build/${SUB}`},
		{name: "R-101 near-miss: single-quoted dollar is a literal", cmd: `rm -rf '$TARGET'`},
		{name: "R-101 near-miss: escaped dollar is a literal", cmd: `rm -rf \$TARGET`},
		{name: "R-101 near-miss: escaped dollar inside double quotes", cmd: `rm -rf "\$TARGET/"`},
		{
			name: "R-101 hit: powershell env home", cmd: `Remove-Item -Recurse -Force $env:USERPROFILE`, dialect: DialectPowerShell,
			home: `C:\Users\u`, root: `C:\Users\u\proj`,
			wantRule: "R-101", wantEnforce: DecisionDeny,
		},
		{
			name: "R-101 hit: powershell bare scoped variable", cmd: `Remove-Item -Recurse -Force $env:TARGET`, dialect: DialectPowerShell,
			home: `C:\Users\u`, root: `C:\Users\u\proj`,
			wantRule: "R-101", wantEnforce: DecisionDeny,
		},
		{
			name: "R-101 near-miss: powershell single-quoted dollar", cmd: `Remove-Item -Recurse -Force '$env:TARGET'`, dialect: DialectPowerShell,
			home: `C:\Users\u`, root: `C:\Users\u\proj`,
		},
		{
			name: "R-101 near-miss: powershell variable with a named subpath", cmd: `Remove-Item -Recurse -Force $env:BUILD\out`, dialect: DialectPowerShell,
			home: `C:\Users\u`, root: `C:\Users\u\proj`,
		},
		{
			name: "R-101 hit: cmd bare variable", cmd: `rd /s /q %APPDATA%`, dialect: DialectCmd,
			home: `C:\Users\u`, root: `C:\Users\u\proj`,
			wantRule: "R-101", wantEnforce: DecisionDeny,
		},
		{
			name: "R-101 near-miss: cmd variable with a named subpath", cmd: `rd /s /q %APPDATA%\x`, dialect: DialectCmd,
			home: `C:\Users\u`, root: `C:\Users\u\proj`,
		},
		{name: "R-101 near-miss: percent is literal outside cmd", cmd: "rm -rf ./build/%X%"},
		// The literal offsets follow the argv through stripped assignments
		// and wrappers.
		{name: "R-101 near-miss: literal dollar after a wrapper", cmd: `FOO=1 sudo rm -rf '$TARGET'`},
		{name: "R-101 hit: bare variable after a wrapper", cmd: `FOO=1 sudo rm -rf "$TARGET"`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "R-101 near-miss: variable on a non-recursive rm", cmd: `rm -f "$TARGET"`},
		{name: "R-101 near-miss: literal dollar-free percent", cmd: "rm -rf ./build/100%"},
		{name: "R-101 near-miss: not recursive", cmd: "rm /etc/nginx/nginx.conf"},

		// --- R-102: VCS / project-root delete ---
		{name: "R-102 hit: .git", cmd: "rm -rf .git", wantRule: "R-102", wantEnforce: DecisionAsk},
		{name: "R-102 hit: nested .git path", cmd: "rm -rf ./.git/objects", wantRule: "R-102", wantEnforce: DecisionAsk},
		{name: "R-102 hit: project root itself", cmd: "rm -rf /home/u/proj", wantRule: "R-102", wantEnforce: DecisionAsk},
		{name: "R-102 near-miss: src subdir", cmd: "rm -rf src"},

		// --- R-103: mass-deletion chains ---
		{name: "R-103 hit: find -delete", cmd: "find . -delete", wantRule: "R-103", wantEnforce: DecisionAsk},
		{name: "R-103 hit: find -name -delete", cmd: `find . -name "*.log" -delete`, wantRule: "R-103", wantEnforce: DecisionAsk},
		{name: "R-103 hit: find -exec rm", cmd: `find . -exec rm {} ;`, wantRule: "R-103", wantEnforce: DecisionAsk},
		{name: "R-103 hit: xargs rm", cmd: "git ls-files | xargs rm -f", wantRule: "R-103", wantEnforce: DecisionAsk},
		{name: "R-103 safe: find under tmp", cmd: "find /tmp/scratch -delete"},
		{name: "R-103 near-miss: find only lists", cmd: `find . -name "*.go"`},

		// --- R-104: git discard ---
		{name: "R-104 hit: reset --hard", cmd: "git reset --hard HEAD~1", wantRule: "R-104", wantEnforce: DecisionAsk},
		{name: "R-104 hit: checkout --", cmd: "git checkout -- .", wantRule: "R-104", wantEnforce: DecisionAsk},
		{name: "R-104 hit: clean -fd", cmd: "git clean -fd", wantRule: "R-104", wantEnforce: DecisionAsk},
		{name: "R-104 safe: clean dry run", cmd: "git clean -n"},
		{name: "R-104 safe: clean -fdn dry", cmd: "git clean -fdn"},
		{name: "R-104 near-miss: checkout branch", cmd: "git checkout main"},
		{name: "R-104 near-miss: soft reset", cmd: "git reset --soft HEAD~1"},

		// --- R-110: force push ---
		{name: "R-110 hit: --force main", cmd: "git push --force origin main", wantRule: "R-110", wantEnforce: DecisionDeny},
		{name: "R-110 hit: -f master", cmd: "git push -f origin master", wantRule: "R-110", wantEnforce: DecisionDeny},
		{name: "R-110 hit: release glob", cmd: "git push --force origin release/1.0", wantRule: "R-110", wantEnforce: DecisionDeny},
		{name: "R-110 hit: refspec dst", cmd: "git push -f origin HEAD:main", wantRule: "R-110", wantEnforce: DecisionDeny},
		{name: "R-110 hit: no refspec conservative", cmd: "git push --force", wantRule: "R-110", wantEnforce: DecisionDeny},
		{name: "R-110 safe: force-with-lease", cmd: "git push --force-with-lease origin main"},
		{name: "R-110 near-miss: feature branch", cmd: "git push -f origin feature-x"},
		{name: "R-110 near-miss: plain push", cmd: "git push origin main"},

		// --- R-111: protected ref deletion ---
		{name: "R-111 hit: branch -D main", cmd: "git branch -D main", wantRule: "R-111", wantEnforce: DecisionAsk},
		{name: "R-111 hit: push :ref", cmd: "git push origin :main", wantRule: "R-111", wantEnforce: DecisionAsk},
		{name: "R-111 hit: push --delete", cmd: "git push --delete origin master", wantRule: "R-111", wantEnforce: DecisionAsk},
		{name: "R-111 near-miss: feature branch", cmd: "git branch -D feature-x"},
		{name: "R-111 near-miss: lowercase -d merged-only", cmd: "git branch -d main"},

		// --- R-120: destructive SQL ---
		{name: "R-120 hit: psql DROP", cmd: `psql -c "DROP TABLE users"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "R-120 hit: mysql DELETE no WHERE", cmd: `mysql -e "DELETE FROM accounts"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "R-120 hit: sqlite3 positional", cmd: `sqlite3 app.db "DROP TABLE users"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "R-120 hit: heredoc TRUNCATE", cmd: "psql <<SQL\nTRUNCATE TABLE logs;\nSQL", wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "R-120 near-miss: DELETE with WHERE", cmd: `mysql -e "DELETE FROM accounts WHERE id = 5"`},
		{name: "R-120 near-miss: SELECT", cmd: `psql -c "SELECT * FROM users"`},

		// --- R-130: cloud destroy ---
		{name: "R-130 hit: terraform destroy", cmd: "terraform destroy", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "R-130 hit: apply -auto-approve", cmd: "terraform apply -auto-approve", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "R-130 hit: aws s3 rm recursive", cmd: "aws s3 rm s3://bucket --recursive", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "R-130 hit: terminate instances", cmd: "aws ec2 terminate-instances --instance-ids i-123", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "R-130 hit: gcloud delete", cmd: "gcloud compute instances delete vm-1", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "R-130 hit: kubectl --all", cmd: "kubectl delete pods --all", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "R-130 hit: kubectl namespace", cmd: "kubectl delete namespace prod", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "R-130 hit: helm uninstall", cmd: "helm uninstall my-release", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "R-130 near-miss: plain apply", cmd: "terraform apply"},
		{name: "R-130 near-miss: terraform plan", cmd: "terraform plan"},
		{name: "R-130 near-miss: single pod", cmd: "kubectl delete pod my-pod"},
		{name: "R-130 near-miss: aws s3 ls", cmd: "aws s3 ls s3://bucket"},

		// --- R-140: registry publish/yank ---
		{name: "R-140 hit: npm publish", cmd: "npm publish", wantRule: "R-140", wantEnforce: DecisionAsk},
		{name: "R-140 hit: npm unpublish", cmd: "npm unpublish my-pkg", wantRule: "R-140", wantEnforce: DecisionAsk},
		{name: "R-140 hit: cargo publish", cmd: "cargo publish", wantRule: "R-140", wantEnforce: DecisionAsk},
		{name: "R-140 hit: twine upload", cmd: "twine upload dist/*", wantRule: "R-140", wantEnforce: DecisionAsk},
		{name: "R-140 hit: gem push", cmd: "gem push pkg-1.0.gem", wantRule: "R-140", wantEnforce: DecisionAsk},
		{name: "R-140 near-miss: npm install", cmd: "npm install"},
		{name: "R-140 near-miss: cargo build", cmd: "cargo build --release"},

		// --- R-141: bulk permission change ---
		{name: "R-141 hit: chmod -R 777", cmd: "chmod -R 777 /var/www", wantRule: "R-141", wantEnforce: DecisionAsk},
		{name: "R-141 hit: chmod -R 0777 inside", cmd: "chmod -R 0777 .", wantRule: "R-141", wantEnforce: DecisionAsk},
		{name: "R-141 hit: chown -R outside", cmd: "chown -R bob /etc/app", wantRule: "R-141", wantEnforce: DecisionAsk},
		{name: "R-141 near-miss: chmod -R 755", cmd: "chmod -R 755 ."},
		{name: "R-141 near-miss: no recursion", cmd: "chmod 777 build/script.sh"},
		{name: "R-141 near-miss: chown inside project", cmd: "chown -R bob ./src"},

		// --- R-142: disk/device ops ---
		{name: "R-142 hit: mkfs", cmd: "mkfs.ext4 /dev/sda1", wantRule: "R-142", wantEnforce: DecisionDeny},
		{name: "R-142 hit: dd to device", cmd: "dd if=/dev/zero of=/dev/sda bs=1M", wantRule: "R-142", wantEnforce: DecisionDeny},
		{name: "R-142 hit: diskpart", cmd: "diskpart /s wipe.txt", dialect: DialectCmd, home: `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`, wantRule: "R-142", wantEnforce: DecisionDeny},
		{name: "R-142 hit: cmd format", cmd: "format d:", dialect: DialectCmd, home: `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`, wantRule: "R-142", wantEnforce: DecisionDeny},
		{name: "R-142 hit: Format-Volume", cmd: "Format-Volume -DriveLetter D", dialect: DialectPowerShell, home: `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`, wantRule: "R-142", wantEnforce: DecisionDeny},
		{name: "R-142 near-miss: dd to file", cmd: "dd if=/dev/zero of=./disk.img bs=1M"},
		{name: "R-142 near-miss: posix format script", cmd: "format --check ./src"},
	}
	runRuleCases(t, cases, KindShellExec, "run_command")
}

// TestR101BehindExecPrefixWrappers is NEW-02 (NEW-F-01, 2026-11-22): the
// critical recursive-delete row must hold behind every exec-prefix command
// that runs its argv (or a shell line) as a command. Before the wrapper
// rows each of these allowed in ModeEnforce, because the unit's Base was
// the wrapper and deleteShape matches only delete commands.
func TestR101BehindExecPrefixWrappers(t *testing.T) {
	t.Parallel()
	var cases []destructiveCase
	for _, cmd := range []string{
		"ionice -c3 rm -rf ~",
		"taskset 0x3 rm -rf ~",
		"taskset -c 0,1 rm -rf ~",
		"chrt -f 99 rm -rf ~",
		"chrt -o rm -rf ~",
		"flock /tmp/l rm -rf ~",
		"flock /tmp/l -c 'rm -rf ~'",
		"pkexec rm -rf ~",
		"pkexec --user root rm -rf ~",
		"runuser -u root -- rm -rf ~",
		"runuser -l root -c 'rm -rf ~'",
		"chroot / rm -rf ~",
		"unshare -r rm -rf ~",
		"nsenter -t 1 -m rm -rf ~",
		"strace -o /dev/null rm -rf ~",
		"ltrace -o /dev/null rm -rf ~",
		"fakeroot rm -rf ~",
		"watch -n 1 rm -rf ~",
		"watch 'rm -rf ~'",
		"caffeinate -t 10 rm -rf ~",
		"su -c 'rm -rf ~'",
		"su root -c 'rm -rf ~'",
		"script -q -c 'rm -rf ~' /dev/null",
		"sudo -u root -r role rm -rf ~",
		"sudo -t type rm -rf ~",
		"sudo -U bob rm -rf ~",
		"sudo -nu root rm -rf ~",
		"xargs -i rm -rf ~",
	} {
		cases = append(cases, destructiveCase{name: "R-101 hit: " + cmd, cmd: cmd, wantRule: "R-101", wantEnforce: DecisionDeny})
	}
	// Near-misses: the same wrappers around a delete inside the project.
	cases = append(cases,
		destructiveCase{name: "R-101 near-miss: ionice inside project", cmd: "ionice -c3 rm -rf ./build"},
		destructiveCase{name: "R-101 near-miss: flock -c inside project", cmd: "flock /tmp/l -c 'rm -rf ./build'"},
	)
	runRuleCases(t, cases, KindShellExec, "run_command")
}

// TestR101ThroughSymlink pins Sol A2-04's second bypass: a delete whose
// operand is lexically inside the project but whose existing prefix is a
// symlink to the home directory (or out of the project) is judged by
// where it resolves, through the injected resolver.
func TestR101ThroughSymlink(t *testing.T) {
	links := map[string]string{
		"/home/u/proj/out": "/home/u",
		"/home/u/proj/etc": "/etc",
		"/home/u/proj/lib": "/home/u/proj/vendor/lib",
	}
	resolve := func(p string) string {
		for from, to := range links {
			if p == from {
				return to
			}
			if len(p) > len(from) && p[:len(from)+1] == from+"/" {
				return to + p[len(from):]
			}
		}
		return ""
	}
	for _, tc := range []struct {
		name, cmd string
		want      string
	}{
		{"home contents through a symlink", "rm -rf ./out/*", "R-101"},
		{"home itself through a symlink", "rm -rf out", "R-101"},
		{"outside the project through a symlink", "rm -rf ./etc/nginx", "R-101"},
		{"symlink that stays inside the project", "rm -rf ./lib/x", ""},
		{"plain inside path", "rm -rf ./build", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u", ResolveLinks: resolve})
			if err != nil {
				t.Fatal(err)
			}
			v := eng.Evaluate(Event{
				Kind: KindShellExec, Target: tc.cmd, Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj",
				SessionID: "s1", Now: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
			})
			if v.RuleID != tc.want {
				t.Fatalf("rule = %q (%s), want %q", v.RuleID, v.Reason, tc.want)
			}
			if tc.want != "" && v.Decision != DecisionDeny {
				t.Errorf("decision = %s, want deny", v.Decision)
			}
		})
	}
	// Without a resolver the engine stays lexical (the pure default).
	eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u"})
	if err != nil {
		t.Fatal(err)
	}
	if v := eng.Evaluate(Event{Kind: KindShellExec, Target: "rm -rf ./out/*", Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj", Now: time.Now()}); v.RuleID == "R-101" {
		t.Error("a lexical engine resolved a symlink it was never told about")
	}
}
