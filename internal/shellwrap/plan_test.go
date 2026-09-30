package shellwrap

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

func hostWith(goos string, existing ...string) Host {
	set := map[string]bool{}
	for _, p := range existing {
		set[p] = true
	}
	home := "/home/u"
	if goos == "windows" {
		home = `C:\Users\u`
	}
	return Host{GOOS: goos, Home: home, Exists: func(p string) bool { return set[p] }}
}

func TestRCTargetsTable(t *testing.T) {
	cases := []struct {
		name  string
		host  Host
		shell Shell
		want  []string
	}{
		{"linux bash", hostWith("linux"), ShellBash, []string{"/home/u/.bashrc"}},
		{"linux zsh", hostWith("linux"), ShellZsh, []string{"/home/u/.zshrc"}},
		{"zsh honours ZDOTDIR", func() Host { h := hostWith("linux"); h.ZDotDir = "/z"; return h }(), ShellZsh, []string{"/z/.zshrc"}},
		{"fish conf.d drop-in", hostWith("linux"), ShellFish, []string{"/home/u/.config/fish/conf.d/" + FishFileName}},
		{"fish honours XDG_CONFIG_HOME", func() Host { h := hostWith("linux"); h.XDGConfigHome = "/x"; return h }(), ShellFish, []string{"/x/fish/conf.d/" + FishFileName}},
		{"darwin bash, nothing exists: create .bash_profile", hostWith("darwin"), ShellBash, []string{"/home/u/.bash_profile"}},
		// Creating ~/.bash_profile would silently stop bash reading ~/.profile.
		{"darwin bash uses the existing .profile", hostWith("darwin", "/home/u/.profile"), ShellBash, []string{"/home/u/.profile"}},
		{"darwin bash also an existing .bashrc", hostWith("darwin", "/home/u/.bash_profile", "/home/u/.bashrc"), ShellBash, []string{"/home/u/.bash_profile", "/home/u/.bashrc"}},
		{
			"windows powershell, none exist: Windows PowerShell's", hostWith("windows"), ShellPowerShell,
			[]string{`C:\Users\u\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`},
		},
		{
			"windows powershell prefers pwsh when installed", hostWith("windows", `C:\Users\u\Documents\PowerShell`), ShellPowerShell,
			[]string{`C:\Users\u\Documents\PowerShell\Microsoft.PowerShell_profile.ps1`},
		},
		{
			"windows powershell: every existing profile", hostWith("windows",
				`C:\Users\u\Documents\PowerShell\Microsoft.PowerShell_profile.ps1`,
				`C:\Users\u\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`), ShellPowerShell,
			[]string{`C:\Users\u\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`, `C:\Users\u\Documents\PowerShell\Microsoft.PowerShell_profile.ps1`},
		},
		{"bash is not managed on windows", hostWith("windows"), ShellBash, nil},
		{"powershell is not managed on linux", hostWith("linux"), ShellPowerShell, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RCTargets(tc.shell, tc.host)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestDetectShellsTable(t *testing.T) {
	cases := []struct {
		name string
		host Host
		want []Shell
	}{
		{"nothing", hostWith("linux"), nil},
		{"login shell only", func() Host { h := hostWith("linux"); h.LoginShell = "/usr/bin/zsh"; return h }(), []Shell{ShellZsh}},
		{"rc files", hostWith("linux", "/home/u/.bashrc", "/home/u/.config/fish"), []Shell{ShellBash, ShellFish}},
		{"windows without a profile detects nothing", hostWith("windows"), nil},
		{"windows with a profile", hostWith("windows", `C:\Users\u\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`), []Shell{ShellPowerShell}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectShells(tc.host)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

// TestRCBodyPutsShimDirFirstIdempotently sources the rendered POSIX block
// twice and checks the resulting PATH.
func TestRCBodyPutsShimDirFirstIdempotently(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	shim := filepath.Join(dir, "it's shims")
	body, err := RCBody(ShellBash, shim)
	if err != nil {
		t.Fatal(err)
	}
	rc := filepath.Join(dir, "rc")
	if err := os.WriteFile(rc, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "-c", ". '"+rc+"'; . '"+rc+"'; printf %s \"$PATH\"").Output() //nolint:gosec // test
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(out), ":")
	if parts[0] != shim {
		t.Fatalf("PATH[0]=%q", parts[0])
	}
	n := 0
	for _, p := range parts {
		if p == shim {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("shim dir appears %d times in %q", n, out)
	}
}

func TestRCBodyQuoting(t *testing.T) {
	for _, sh := range []Shell{ShellBash, ShellZsh, ShellFish, ShellPowerShell} {
		if _, err := RCBody(sh, "/a\nb"); err == nil {
			t.Fatalf("%s: a newline path must be refused", sh)
		}
	}
	fish, _ := RCBody(ShellFish, `/it's\dir`)
	if !strings.Contains(fish, `'/it\'s\\dir'`) {
		t.Fatalf("fish quoting: %s", fish)
	}
	ps, _ := RCBody(ShellPowerShell, `C:\it's`)
	if !strings.Contains(ps, `'C:\it''s'`) {
		t.Fatalf("powershell quoting: %s", ps)
	}
}

func TestHonestyTable(t *testing.T) {
	cases := []struct {
		w    integration.WrappedCommand
		want Honesty
	}{
		{integration.WrappedCommand{Routes: false, TrafficProven: false}, HonestyLaunchOnly},
		{integration.WrappedCommand{Routes: false, TrafficProven: true}, HonestyLaunchOnly},
		{integration.WrappedCommand{Routes: true, TrafficProven: false}, HonestyProofOwed},
		{integration.WrappedCommand{Routes: true, TrafficProven: true}, HonestyRouted},
	}
	for _, tc := range cases {
		if got, text := HonestyFor(tc.w); got != tc.want || text == "" {
			t.Errorf("%+v: got %s %q want %s", tc.w, got, text, tc.want)
		}
	}
}

// TestCandidatesComeFromTheSeam pins that every candidate is exactly what
// integration.WrappedCommandFor says - the package owns no tool list.
func TestCandidatesComeFromTheSeam(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		cands := Candidates(goos)
		if len(cands) == 0 {
			t.Fatalf("%s: no candidates", goos)
		}
		for _, c := range cands {
			w, ok := integration.WrappedCommandFor(c.ID)
			if !ok {
				t.Fatalf("%s: %s not a WrappedCommandFor hit", goos, c.ID)
			}
			if c.Kind != w.Kind || c.Routes != w.Routes || c.TrafficProven != w.TrafficProven ||
				c.Wrapped != "observer "+strings.Join(w.Args, " ") {
				t.Fatalf("%s: %s diverges from the seam: %+v vs %+v", goos, c.ID, c, w)
			}
			if h, _ := HonestyFor(w); h != c.Honesty {
				t.Fatalf("%s: %s honesty %s vs %s", goos, c.ID, c.Honesty, h)
			}
			for _, cmd := range c.Commands {
				if !ValidCommandName(cmd) || (goos == "windows" && strings.HasSuffix(strings.ToLower(cmd), ".exe")) {
					t.Fatalf("%s: %s bad command %q", goos, c.ID, cmd)
				}
			}
		}
	}
}

// TestProbeOnlyGUIRowsAreNeverShimmed: a ProbeOnly row's spelling collides
// with an unrelated PATH binary (Claude Desktop's claude.exe vs the CLI), so
// shimming it would shadow the wrong program.
func TestProbeOnlyGUIRowsAreNeverShimmed(t *testing.T) {
	for _, g := range integration.GUILaunchables() {
		if !g.Spec.ProbeOnly {
			continue
		}
		for _, goos := range []string{"linux", "darwin", "windows"} {
			if _, ok := CandidateFor(g.Spec.ID, goos); ok {
				t.Fatalf("ProbeOnly row %s is wrappable on %s", g.Spec.ID, goos)
			}
		}
	}
}

func firstRouted(t *testing.T, goos string) Candidate {
	t.Helper()
	for _, c := range Candidates(goos) {
		if c.Kind == integration.LaunchKindTerminal && c.Honesty == HonestyRouted {
			return c
		}
	}
	t.Fatal("no routed CLI candidate")
	return Candidate{}
}

func TestBuildPlanExplicitSelection(t *testing.T) {
	c := firstRouted(t, "linux")
	h := hostWith("linux", "/home/u/.bashrc")
	p, err := BuildPlan(PlanInput{
		Host: h, ShimDir: "/home/u/.observer/shims", ObserverPath: "/usr/bin/observer",
		Selection: Selection{Tools: []string{c.ID, "no-such-tool"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Tools) != 1 || p.Tools[0].ID != c.ID || len(p.Shims) != len(c.Commands) {
		t.Fatalf("plan tools/shims: %+v", p)
	}
	if p.Shims[0].Path != "/home/u/.observer/shims/"+p.Shims[0].FileName {
		t.Fatalf("shim path %q", p.Shims[0].Path)
	}
	if len(p.RC) != 1 || p.RC[0].Path != "/home/u/.bashrc" || p.RC[0].Shell != ShellBash {
		t.Fatalf("rc: %+v", p.RC)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "no-such-tool") {
		t.Fatalf("warnings: %v", p.Warnings)
	}
}

func TestBuildPlanAllTakesInstalledCLIRowsOnly(t *testing.T) {
	c := firstRouted(t, "linux")
	installed := func(id string) bool { return id == c.ID || id == "vscode" }
	p, err := BuildPlan(PlanInput{
		Host: hostWith("linux"), ShimDir: "/s", ObserverPath: "/o",
		Selection: Selection{Tools: []string{AllTools}, Shells: []Shell{ShellZsh}}, Installed: installed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Tools) != 1 || p.Tools[0].ID != c.ID {
		t.Fatalf("all must expand to installed CLI rows only (never an IDE row): %+v", p.Tools)
	}
	if len(p.RC) != 1 || p.RC[0].Path != "/home/u/.zshrc" {
		t.Fatalf("rc: %+v", p.RC)
	}
}

func TestBuildPlanEmptyWritesNoBlock(t *testing.T) {
	p, err := BuildPlan(PlanInput{Host: hostWith("linux", "/home/u/.bashrc"), ShimDir: "/s", ObserverPath: "/o"})
	if err != nil || !p.Empty() || len(p.RC) != 0 {
		t.Fatalf("empty plan: %+v err %v", p, err)
	}
}

func TestBuildPlanWindowsShimsAreCmdFiles(t *testing.T) {
	c := firstRouted(t, "windows")
	p, err := BuildPlan(PlanInput{
		Host: hostWith("windows"), ShimDir: `C:\Users\u\.observer\shims`, ObserverPath: `C:\o\observer.exe`,
		Selection: Selection{Tools: []string{c.ID}, Shells: []Shell{ShellPowerShell}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range p.Shims {
		if !strings.HasSuffix(s.FileName, ".cmd") || !strings.HasPrefix(s.Content, "@echo off\r\n") ||
			s.Path != `C:\Users\u\.observer\shims\`+s.FileName {
			t.Fatalf("windows shim %+v", s)
		}
	}
	if _, err := BuildPlan(PlanInput{
		Host: hostWith("windows"), ShimDir: "/s", ObserverPath: "/o",
		Selection: Selection{Tools: []string{c.ID}, Shells: []Shell{ShellBash}},
	}); err == nil {
		t.Fatal("bash must be refused on windows")
	}
}

func TestBuildPlanWarnsWhenNoShellDetected(t *testing.T) {
	c := firstRouted(t, "linux")
	p, err := BuildPlan(PlanInput{Host: hostWith("linux"), ShimDir: "/s", ObserverPath: "/o", Selection: Selection{Tools: []string{c.ID}}})
	if err != nil || len(p.RC) != 0 || len(p.Warnings) == 0 {
		t.Fatalf("plan %+v err %v", p, err)
	}
}

func TestComputeStatus(t *testing.T) {
	c := firstRouted(t, "linux")
	h := hostWith("linux", "/home/u/.bashrc")
	plan, err := BuildPlan(PlanInput{Host: h, ShimDir: "/s", ObserverPath: "/o", Selection: Selection{Tools: []string{c.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	inSync := OnDisk{ShimDir: "/s"}
	for _, s := range plan.Shims {
		inSync.Shims = append(inSync.Shims, OnDiskShim{FileName: s.FileName, Path: s.Path, ToolID: s.ToolID, Command: s.Command, Content: s.Content})
	}
	inSync.RC = []OnDiskRC{{Path: "/home/u/.bashrc", Shell: ShellBash, Exists: true, HasBlock: true, Body: plan.RC[0].Body}}

	st := ComputeStatus(StatusInput{Host: h, Enabled: true, Plan: plan, Selected: []string{c.ID}, Disk: inSync})
	if !st.InSync || !st.Active {
		t.Fatalf("expected in sync: %+v", st)
	}

	stale := inSync
	stale.Shims = append([]OnDiskShim(nil), inSync.Shims...)
	stale.Shims[0].Content += "# edited\n"
	st = ComputeStatus(StatusInput{Host: h, Enabled: true, Plan: plan, Selected: []string{c.ID}, Disk: stale})
	if st.InSync {
		t.Fatal("an edited shim must be out of sync")
	}
	for _, ts := range st.Tools {
		if ts.ID == c.ID && len(ts.Stale) == 0 {
			t.Fatal("stale shim not reported")
		}
	}

	orphan := inSync
	orphan.Shims = append(append([]OnDiskShim(nil), inSync.Shims...), OnDiskShim{FileName: "gone", ToolID: "removed-tool", Command: "gone"})
	st = ComputeStatus(StatusInput{Host: h, Enabled: true, Plan: plan, Selected: []string{c.ID}, Disk: orphan})
	if st.InSync || len(st.Orphans) != 1 {
		t.Fatalf("orphan: %+v", st.Orphans)
	}

	st = ComputeStatus(StatusInput{Host: h, Enabled: false, Plan: Plan{ShimDir: "/s"}, Disk: OnDisk{ShimDir: "/s"}})
	if !st.InSync || st.Active {
		t.Fatalf("clean disabled state: %+v", st)
	}
}
