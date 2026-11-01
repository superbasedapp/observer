package diag

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/cursorusage"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/remedy"
)

// assertSpelled pins the one-owner rule (T-421 item 3): a check that carries
// a structured remediation spells that remediation's command in its own text,
// so the CLI line and the dashboard button can never name different fixes.
func assertSpelled(t *testing.T, c Check, want ...remedy.Action) {
	t.Helper()
	text := c.Message + "\n" + strings.Join(c.Details, "\n")
	got := map[remedy.Action]bool{}
	for _, r := range c.Remediations {
		got[r.Action] = true
		if !remedy.Known(r.Action) {
			t.Errorf("%s: unknown remediation %q", c.Name, r.Action)
		}
		if !remedy.Mentions(text, r) {
			t.Errorf("%s: remediation %+v (%q) is not spelled in the check's text:\n%s", c.Name, r, remedy.Command(r), text)
		}
	}
	for _, a := range want {
		if !got[a] {
			t.Errorf("%s: remediations %+v, want %s", c.Name, c.Remediations, a)
		}
	}
}

func TestHookChecksRemediations(t *testing.T) {
	home := t.TempDir()
	assertSpelled(t, checkHookChecksums(home), remedy.Init)
	c := checkMCPRegistrations(home, "/opt/observer", "/opt/observer", nil, false)
	assertSpelled(t, c, remedy.Init)
	if c.Remediations[0].Tool != "" {
		t.Errorf("mcp remediation = %+v", c.Remediations)
	}
}

func TestWindowsRouteRemediations(t *testing.T) {
	// A routed-nowhere Windows .claude: wire the Windows side.
	home := writeWindowsClaudeDirOnly(t)
	homes := []crossmount.HomeRoot{{Path: home, OS: crossmount.OSWindows}}
	c, ok := windowsProxyRoutesCheck(context.Background(), config.Config{}, true, homes,
		func(string) bool { return true }, func(context.Context, string) (int, error) { return 200, nil })
	if !ok {
		t.Fatal("no check")
	}
	assertSpelled(t, c, remedy.InitWindowsRoute)
	if c.Remediations[0].Tool != "claude-code-windows" {
		t.Errorf("target = %q", c.Remediations[0].Tool)
	}

	// Two unowned Windows homes carrying .cursor: choose the home.
	a, b := t.TempDir(), t.TempDir()
	for _, h := range []string{a, b} {
		if err := os.MkdirAll(filepath.Join(h, ".cursor"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	c, ok = windowsProxyRoutesCheck(context.Background(), config.Config{}, true,
		[]crossmount.HomeRoot{{Path: a, OS: crossmount.OSWindows}, {Path: b, OS: crossmount.OSWindows}},
		func(string) bool { return false }, func(context.Context, string) (int, error) { return 0, os.ErrNotExist })
	if !ok {
		t.Fatal("no check")
	}
	assertSpelled(t, c, remedy.InitWindowsHome)
	if !strings.Contains(strings.Join(c.Details, "\n"), "observer init --windows-cursor-home <path>") {
		t.Errorf("details lost the CLI flag:\n%s", strings.Join(c.Details, "\n"))
	}
}

func TestIntegritySkipRemediation(t *testing.T) {
	for _, d := range integrityDecisions {
		if d.skip == nil {
			continue
		}
		c := d.skip(integrityInput{scope: "cursor", maxGB: 1, sizeBytes: 5 << 30})
		assertSpelled(t, c, remedy.DoctorDBIntegrity)
	}
}

// TestCursorUsageRemediationsAreSpelled: every cursorusage row's structured
// fixes appear in its remedy text.
func TestCursorUsageRemediationsAreSpelled(t *testing.T) {
	for _, r := range []cursorusage.Reason{
		cursorusage.ReasonFinishHooksMissing, cursorusage.ReasonNoFinishHook, cursorusage.ReasonNoEvidence,
	} {
		fixes := cursorusage.Remediations(r)
		if len(fixes) == 0 {
			t.Errorf("%s: no structured fix", r)
		}
		for _, f := range fixes {
			if !remedy.Mentions(cursorusage.Remedy(r), f) {
				t.Errorf("%s: fix %+v not spelled in %q", r, f, cursorusage.Remedy(r))
			}
		}
	}
	if fixes := cursorusage.Remediations(cursorusage.ReasonFinishHooksSilent); len(fixes) != 0 {
		t.Errorf("re-registering changes nothing for %s, yet it offers %+v", cursorusage.ReasonFinishHooksSilent, fixes)
	}
}
