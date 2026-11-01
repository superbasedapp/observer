package guardtest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

func base() policy.Event {
	return Base("/repo/sub", "/repo", time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC))
}

func TestEventShapes(t *testing.T) {
	cases := []struct {
		name       string
		ev         policy.Event
		kind       policy.EventKind
		actionType string
		target     string
		session    string
	}{
		{"a command", Command(base(), "rm -rf ./build"), policy.KindShellExec, "run_command", "rm -rf ./build", "guard-test"},
		{"a file write", FileWrite(base(), "~/.ssh/config"), policy.KindFileAccess, "write_file", "~/.ssh/config", "guard-test"},
		{"a raw event keeps its session", Raw(base(), "shell_exec", "git push -f", "", "s-1"), policy.KindShellExec, "", "git push -f", "s-1"},
		{"a raw event without a session", Raw(base(), "file_access", "/etc/passwd", "read_file", ""), policy.KindFileAccess, "read_file", "/etc/passwd", "guard-test"},
	}
	for _, tc := range cases {
		ev := tc.ev
		if ev.Kind != tc.kind || ev.ActionType != tc.actionType || ev.Target != tc.target || ev.SessionID != tc.session {
			t.Errorf("%s: event = %+v", tc.name, ev)
		}
		if ev.Tool != "guard-test" || ev.Cwd != "/repo/sub" || ev.ProjectRoot != "/repo" {
			t.Errorf("%s: base fields lost: %+v", tc.name, ev)
		}
	}
}

// TestRunAnswersBothModes: one dry run reports the verdict under the current
// mode AND under enforce, the question `observer guard test` exists for.
func TestRunAnswersBothModes(t *testing.T) {
	cfg := config.Default().Guard
	cfg.Mode = "observe"
	home := t.TempDir()
	res, err := Run(cfg, home, nil, Command(base(), "git push --force origin main"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict.RuleID != "R-110" || res.EnforceVerdict.Decision != policy.DecisionDeny {
		t.Fatalf("verdicts = %+v / %+v", res.Verdict, res.EnforceVerdict)
	}
	if !res.ModeChangesVerdict() {
		t.Fatalf("observe -> enforce should change the verdict: %s vs %s", res.Verdict.Decision, res.EnforceVerdict.Decision)
	}
	if res.Mode != "observe" {
		t.Fatalf("mode = %q", res.Mode)
	}

	quiet, err := Run(cfg, home, nil, Command(base(), "ls -la"))
	if err != nil {
		t.Fatal(err)
	}
	if quiet.Verdict.RuleID != "" || quiet.ModeChangesVerdict() {
		t.Fatalf("a harmless command matched: %+v", quiet.Verdict)
	}
}

// TestReportJSONKeys pins the --json shape the CLI always printed (the keys,
// alphabetical as the CLI's map encoding emitted them) so the dashboard and
// the CLI answer with the same document.
func TestReportJSONKeys(t *testing.T) {
	cfg := config.Default().Guard
	res, err := Run(cfg, t.TempDir(), nil, Command(base(), "git push --force origin main"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(res.Report())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`"advice"`, `"decision"`, `"enforce_decision"`, `"kind"`, `"project_root"`, `"reason"`, `"rule_id"`, `"severity"`, `"source"`, `"target"`}
	last := -1
	for _, k := range want {
		i := strings.Index(string(raw), k)
		if i < 0 || i < last {
			t.Fatalf("key %s missing or out of order in %s", k, raw)
		}
		last = i
	}
}

// TestCommandDialectOnWindows is WINNODE item 2 at the dry run: on a Windows
// working directory an unstated shell is also read as PowerShell (the reading
// a hook gives a generic shell tool there), so the reason keeps the path's
// backslashes; --shell names one reading; a POSIX directory keeps one reading.
func TestCommandDialectOnWindows(t *testing.T) {
	win := Base(`C:\Users\developer\proj`, `C:\Users\developer\proj`, time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC))
	cases := []struct {
		name          string
		ev            policy.Event
		dialect, alt  policy.Dialect
		reasonContain string
	}{
		{"unstated on windows reads powershell too", Command(win, `Remove-Item -Recurse -Force C:\Users\developer`), "", policy.DialectPowerShell, `C:\Users\developer is the home directory`},
		{"--shell powershell", CommandIn(win, `Remove-Item -Recurse -Force C:\Users\developer`, policy.DialectPowerShell), policy.DialectPowerShell, "", `C:\Users\developer is the home directory`},
		{"--shell cmd", CommandIn(win, `rd /s /q C:\Users\x`, policy.DialectCmd), policy.DialectCmd, "", `C:\Users\x resolves outside the project root`},
		{"posix directory keeps one reading", Command(base(), "rm -rf ./build"), "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.ev.Dialect != tc.dialect || tc.ev.AltDialect != tc.alt {
				t.Fatalf("dialect = %q alt = %q, want %q / %q", tc.ev.Dialect, tc.ev.AltDialect, tc.dialect, tc.alt)
			}
			if tc.reasonContain == "" {
				return
			}
			res, err := Run(config.Default().Guard, `C:\Users\developer`, nil, tc.ev)
			if err != nil {
				t.Fatal(err)
			}
			if res.EnforceVerdict.RuleID != "R-101" || !strings.Contains(res.EnforceVerdict.Reason, tc.reasonContain) {
				t.Fatalf("enforce verdict = %s %s (%s), want R-101 naming %q", res.EnforceVerdict.Decision, res.EnforceVerdict.RuleID, res.EnforceVerdict.Reason, tc.reasonContain)
			}
		})
	}
	for name, want := range map[string]policy.Dialect{"": "", "posix": policy.DialectPosix, "powershell": policy.DialectPowerShell, "cmd": policy.DialectCmd} {
		if got, ok := ShellDialect(name); !ok || got != want {
			t.Errorf("ShellDialect(%q) = %q, %v", name, got, ok)
		}
	}
	if _, ok := ShellDialect("fish"); ok {
		t.Error("ShellDialect(fish) accepted")
	}
}
