package policy

import (
	"strings"
	"testing"
	"time"
)

// TestWindowsShellPathsKeepTheirBackslashes is the WINNODE item 2 table: a
// PowerShell or cmd command line is lexed under its own dialect (stated by
// the boundary, or the PowerShell second reading a generic shell gets on a
// Windows directory), so its paths keep their backslashes in the path
// matching AND in the reason. Each row pins the verdict, the rule id and the
// path as typed in the reason. The package is OS-agnostic, so these rows run
// on every host.
func TestWindowsShellPathsKeepTheirBackslashes(t *testing.T) {
	t.Parallel()
	eng, err := New(Config{Mode: ModeEnforce, Home: `C:\Users\developer`})
	if err != nil {
		t.Fatal(err)
	}
	const proj = `C:\Users\developer\proj`
	const share = `\\fileserver\share\proj`
	cases := []struct {
		name       string
		dialect    Dialect
		alt        Dialect
		root       string
		cmd        string
		wantRule   string
		wantDec    Decision
		wantReason string // a substring that must appear verbatim
	}{
		{
			"powershell home delete", DialectPowerShell, "", proj,
			`Remove-Item -Recurse -Force C:\Users\developer`, "R-101", DecisionDeny,
			`target C:\Users\developer is the home directory`,
		},
		{
			"generic shell on windows reads powershell for the reason", "", DialectPowerShell, proj,
			`Remove-Item -Recurse -Force C:\Users\developer`, "R-101", DecisionDeny,
			`target C:\Users\developer is the home directory`,
		},
		{
			"powershell other profile delete", DialectPowerShell, "", proj,
			`Remove-Item -Recurse -Force C:\Users\alex`, "R-101", DecisionDeny,
			`target C:\Users\alex resolves outside the project root`,
		},
		{
			"cmd del /s /q wildcard", DialectCmd, "", proj,
			`del /s /q C:\Users\x\*`, "R-101", DecisionDeny,
			`target C:\Users\x\* resolves outside the project root`,
		},
		{
			"cmd rd /s /q", DialectCmd, "", proj,
			`rd /s /q C:\Users\x`, "R-101", DecisionDeny,
			`target C:\Users\x resolves outside the project root`,
		},
		{
			"powershell ssh key read", DialectPowerShell, "", proj,
			`Get-Content C:\Users\x\.ssh\id_rsa`, "R-152", DecisionAsk,
			`(C:\Users\x\.ssh\id_rsa)`,
		},
		{
			"generic shell on windows ssh key read", "", DialectPowerShell, proj,
			`Get-Content C:\Users\x\.ssh\id_rsa`, "R-152", DecisionAsk,
			`(C:\Users\x\.ssh\id_rsa)`,
		},
		{
			"cmd type ssh key", DialectCmd, "", proj,
			`type C:\Users\x\.ssh\id_rsa`, "R-152", DecisionAsk,
			`(C:\Users\x\.ssh\id_rsa)`,
		},
		{
			"powershell secret file read", DialectPowerShell, "", proj,
			`Get-Content C:\Users\developer\notes\.env`, "R-153", DecisionAsk,
			`secret file C:\Users\developer\notes\.env`,
		},
		{
			"powershell quoted path with spaces", DialectPowerShell, "", proj,
			`Remove-Item -Recurse -Force "C:\Program Files\App Data"`, "R-101", DecisionDeny,
			`target C:\Program Files\App Data resolves outside the project root`,
		},
		{
			"cmd quoted path with spaces", DialectCmd, "", proj,
			`rd /s /q "C:\Program Files\App Data"`, "R-101", DecisionDeny,
			`target C:\Program Files\App Data resolves outside the project root`,
		},
		{
			"powershell quoted secret with spaces", DialectPowerShell, "", proj,
			`Get-Content "C:\Users\x\My Keys\.ssh\id_ed25519"`, "R-153", DecisionAsk,
			`secret file C:\Users\x\My Keys\.ssh\id_ed25519`,
		},
		{
			"powershell unc delete outside the project", DialectPowerShell, "", proj,
			`Remove-Item -Recurse -Force \\fileserver\share\team`, "R-101", DecisionDeny,
			`target \\fileserver\share\team resolves outside the project root`,
		},
		{
			"cmd unc delete outside the project", DialectCmd, "", proj,
			`rd /s /q \\fileserver\share\team`, "R-101", DecisionDeny,
			`target \\fileserver\share\team resolves outside the project root`,
		},
		{
			"unc share root is a filesystem root", DialectPowerShell, "", proj,
			`Remove-Item -Recurse -Force \\fileserver\share`, "R-101", DecisionDeny,
			`target \\fileserver\share is a filesystem root`,
		},
		{
			"unc share wildcard is root depth", DialectPowerShell, "", proj,
			`Remove-Item -Recurse -Force \\fileserver\share\*`, "R-101", DecisionDeny,
			`target \\fileserver\share\* is a root-depth wildcard`,
		},
		{
			"unc key read", DialectPowerShell, "", proj,
			`Get-Content \\fileserver\share\.ssh\id_rsa`, "R-153", DecisionAsk,
			`secret file \\fileserver\share\.ssh\id_rsa`,
		},
		{
			"unc delete inside a unc project", DialectPowerShell, "", share,
			`Remove-Item -Recurse -Force \\fileserver\share\proj\build`, "", DecisionAllow, "",
		},
		{
			"unc in another case stays outside (no verdict loosens)", DialectPowerShell, "", share,
			`Remove-Item -Recurse -Force \\FILESERVER\Share\proj\build`, "R-101", DecisionDeny,
			`target \\FILESERVER\Share\proj\build resolves outside the project root`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := eng.Evaluate(Event{
				Kind: KindShellExec, ActionType: "run_command", Target: tc.cmd,
				Dialect: tc.dialect, AltDialect: tc.alt, Cwd: tc.root, ProjectRoot: tc.root,
				SessionID: "s1", Now: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC),
			})
			if v.RuleID != tc.wantRule || v.Decision != tc.wantDec {
				t.Fatalf("verdict = %s %s (%s), want %s %s", v.Decision, v.RuleID, v.Reason, tc.wantDec, tc.wantRule)
			}
			if !strings.Contains(v.Reason, tc.wantReason) {
				t.Fatalf("reason %q does not keep the path as typed (%q)", v.Reason, tc.wantReason)
			}
		})
	}
}

// TestUNCFileAccessIsOutsideADriveProject pins the boundary row for a file
// event: a write to a share from a drive-rooted project is outside it
// (R-150), where the folded POSIX look-alike used to compare with nothing.
func TestUNCFileAccessIsOutsideADriveProject(t *testing.T) {
	t.Parallel()
	eng, err := New(Config{Mode: ModeEnforce, Home: `C:\Users\developer`})
	if err != nil {
		t.Fatal(err)
	}
	const proj = `C:\Users\developer\proj`
	v := eng.Evaluate(Event{
		Kind: KindFileAccess, ActionType: "write_file", Target: `\\fileserver\share\x.txt`,
		Cwd: proj, ProjectRoot: proj, SessionID: "s1", Now: time.Now(),
	})
	if v.RuleID != "R-150" || v.Decision != DecisionAsk || !strings.Contains(v.Reason, `path \\fileserver\share\x.txt is outside`) {
		t.Fatalf("verdict = %s %s (%s), want ask R-150 naming the share path", v.Decision, v.RuleID, v.Reason)
	}
	// A POSIX project still sees a share outside it, as before the change.
	v = eng.Evaluate(Event{
		Kind: KindFileAccess, ActionType: "write_file", Target: `\\fileserver\share\x.txt`,
		Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj", SessionID: "s1", Now: time.Now(),
	})
	if v.RuleID != "R-150" {
		t.Fatalf("posix project: verdict = %s %s (%s), want R-150", v.Decision, v.RuleID, v.Reason)
	}
}

// TestUnstatedShellAltDialect pins the second-reading rule shared by the
// hook boundary and `observer guard test`.
func TestUnstatedShellAltDialect(t *testing.T) {
	t.Parallel()
	cases := []struct {
		kind    EventKind
		dialect Dialect
		cwd     string
		want    Dialect
	}{
		{KindShellExec, "", `C:\Users\dev\proj`, DialectPowerShell},
		{KindShellExec, "", "c:/Users/dev", DialectPowerShell},
		{KindShellExec, "", `\\fileserver\share\proj`, DialectPowerShell},
		{KindShellExec, "", "/home/dev/proj", ""},
		{KindShellExec, "", "", ""},
		{KindShellExec, DialectPosix, `C:\Users\dev`, ""},
		{KindShellExec, DialectCmd, `C:\Users\dev`, ""},
		{KindFileAccess, "", `C:\Users\dev`, ""},
	}
	for _, tc := range cases {
		if got := UnstatedShellAltDialect(tc.kind, tc.dialect, tc.cwd); got != tc.want {
			t.Errorf("UnstatedShellAltDialect(%s, %q, %q) = %q, want %q", tc.kind, tc.dialect, tc.cwd, got, tc.want)
		}
	}
}
