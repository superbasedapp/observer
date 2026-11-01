package invariant

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/isolation"
	"github.com/marmutapp/superbased-observer/internal/planlimits"
	"github.com/marmutapp/superbased-observer/internal/seccustom"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depdriver"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvscanner"
	"github.com/marmutapp/superbased-observer/internal/service"
	"github.com/marmutapp/superbased-observer/internal/sshprofile"
	"github.com/marmutapp/superbased-observer/internal/tailnet"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// process_declaration_test.go is the Surface.Processes declaration test
// (joint roadmap F0-2; sandbox plan section 11.3; security plan section
// 4.4): a component may start only the programs its catalog row declares
// in Surface.Processes. internal/components declares the field and, before
// this test, nothing checked it.
//
// It checks three kinds of exec site:
//
//  1. The shared runner's own seam (internal/extrun): every plan the fake
//     executor records carries its owning component, so a consumer's test
//     that drives its code path through extruntest gets the check for free
//     by adding a row to runnerConsumers.
//  2. The pure argv builders of existing exec sites that are not on the
//     runner yet (ssh, systemctl and journalctl, the Tailscale setup, the
//     Plans & limits vendor CLIs): their first program, and the program a
//     sudo wrapper runs, must be declared by the package's owner.
//  3. A static scan of every package under internal/: every exec.Command,
//     exec.CommandContext and exec.LookPath call with a LITERAL program
//     name is checked against the owning component's declaration, or, for a
//     core package no component lists, against coreExecAllowance. A call
//     whose program is not a literal, and an exec function used as a value
//     (a package-level `var x = exec.Command` seam), cannot be checked this
//     way; those sites are listed in dynamicExecSites with how they are
//     covered, so a new one fails until someone records it. cmd/ is not
//     scanned.
//
// extrun.DeclaresProcess is the matching rule (a declared phrase names a
// program when one of its words equals the program's file name).

// declaredBy returns the Surface.Processes of a component id.
func declaredBy(t *testing.T, id string) []string {
	t.Helper()
	c, ok := components.Get(id)
	if !ok {
		t.Fatalf("component %q is not in the catalog", id)
	}
	return c.Surface.Processes
}

// ownerOfPackage returns the component that owns a package path relative
// to the module root, or "core" when none does (an unowned package is core).
// A package two components list is not expected; the first wins.
func ownerOfPackage(pkg string) string {
	for _, c := range components.All() {
		for _, p := range c.Packages {
			if p == pkg {
				return c.ID
			}
		}
	}
	return "core"
}

// checkDeclared fails t when component does not declare the program.
func checkDeclared(t *testing.T, component, program, where string) {
	t.Helper()
	if !extrun.DeclaresProcess(declaredBy(t, component), program) {
		t.Errorf("%s: component %q starts %q but its Surface.Processes %q does not declare it (add it to the catalog row in internal/components)",
			where, component, extrun.ProcessName(program), declaredBy(t, component))
	}
}

// gaps collects undeclared programs found at exec sites that are not on the
// runner yet, so they can be compared with processDeclarationBaseline.
type gaps map[string]bool

// check records a gap when component does not declare program.
func (g gaps) check(t *testing.T, component, program, site string) {
	t.Helper()
	if !extrun.DeclaresProcess(declaredBy(t, component), program) {
		g[component+" starts "+extrun.ProcessName(program)+" at "+site] = true
	}
}

// compare fails t for every gap not in the baseline, and for every baseline
// entry of this kind that no longer occurs (the gap was fixed: delete it).
func (g gaps) compare(t *testing.T, baseline map[string]string) {
	t.Helper()
	keys := make([]string, 0, len(g))
	for k := range g {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, ok := baseline[k]; !ok {
			t.Errorf("undeclared program: %s. Declare it in the component's Surface.Processes (internal/components) and run make components-build", k)
		}
	}
	for k := range baseline {
		if !g[k] {
			t.Errorf("processDeclarationBaseline entry %q no longer occurs; delete it", k)
		}
	}
}

// runnerConsumers are the code paths that start programs through the shared
// runner. Each row drives its path with a fake executor; the recorded plans
// are checked. Empty today apart from the self-test rows below: the first
// consumer of each plan adds its row here (roadmap F0-2, stage 1 onward).
var runnerConsumers = []struct {
	name string
	run  func(r *extrun.Runner)
}{
	{"projects runs git through the runner", func(r *extrun.Runner) {
		r.Run(context.Background(), extrun.Request{Component: "projects", Program: extrun.Program{Path: "/usr/bin/git"}, Args: []string{"log"}})
	}},
	{"terminals.ssh runs ssh through the runner", func(r *extrun.Runner) {
		r.Run(context.Background(), extrun.Request{Component: "terminals.ssh", Program: extrun.Program{Path: "/usr/bin/ssh"}, Args: []string{"-V"}})
	}},
	// The dependency scanners (security Phase D2): the linked driver
	// starts the observer binary itself as its scan child; the subprocess
	// driver starts osv-scanner (a version probe, then the scan).
	{"security.scan.scalibr starts the scan child through the runner", func(r *extrun.Runner) {
		_, _ = depdriver.NewScalibr(depdriver.Env{Runner: r, Executable: "/usr/bin/observer", Compiled: true, GOOS: "linux", GOARCH: "amd64"}).
			Scan(context.Background(), secscan.Target{ProjectRoot: "/home/u/src/p"})
	}},
	{"security.scan.osv starts osv-scanner through the runner", func(r *extrun.Runner) {
		epochs := map[string]string{}
		for _, e := range depscan.Ecosystems() {
			epochs[e] = "e"
		}
		r.Resolve = func(integration.BinaryResolveSpec) toolresolve.Resolution {
			return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: "/usr/bin/osv-scanner"}
		}
		env := osvscanner.Env{
			Runner: r, DBDir: "/home/u/.observer/security/osv", Epochs: epochs, CanaryDir: "/home/u/.observer/security/osv-canary",
			HomeDir: "/home/u/.observer/security/osv-scanner-home", GOOS: "linux", GOARCH: "amd64",
		}
		_, _ = osvscanner.New(env).Scan(context.Background(), secscan.Target{ProjectRoot: "/home/u/src/p"})
	}},
	// The code-rules driver (security Phase G lane G1): a version probe
	// and a scan of opengrep, with git as its companion executable.
	{"security.scan.opengrep starts opengrep through the runner", func(r *extrun.Runner) {
		r.Resolve = func(s integration.BinaryResolveSpec) toolresolve.Resolution {
			for _, n := range s.Names.Unix {
				if n == "opengrep" || n == "git" {
					return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: "/usr/bin/" + n}
				}
			}
			return toolresolve.Resolution{}
		}
		pack, err := secrulepack.Floor()
		if err != nil {
			return
		}
		env := opengrep.Env{
			Runner: r, Pack: pack, PackDir: "/home/u/.cache/sbo/opengrep/pack", CacheDir: "/home/u/.cache/sbo/opengrep/engine",
			OutDir: "/home/u/.cache/sbo/opengrep/runs/r", GOOS: "linux", GOARCH: "amd64",
			ListTree: func(string) secengine.TreeListing { return secengine.TreeListing{Missing: true} },
			ReadFile: func(string, int64) ([]byte, error) { return nil, os.ErrNotExist },
		}
		_, _ = opengrep.New(env).Scan(context.Background(), secscan.Target{ProjectRoot: "/home/u/src/p"})
	}},
	// The isolation engine (roadmap F0-11): a one-shot run is started as
	// bwrap with the program inside it, so the executor sees bwrap.
	{"isolation runs a program inside bwrap through the runner", func(r *extrun.Runner) {
		p, err := isolation.Factory(isolation.Host{Bwrap: "/usr/bin/bwrap", Home: "/home/u", ObserverDir: "/home/u/.observer"})(
			extrun.OneShotDirs{Project: "/home/u/src/p", Output: "/tmp/run/out", Cache: "/tmp/run/cache"})
		if err != nil {
			return
		}
		r.Isolation = p
		r.Run(context.Background(), extrun.Request{Component: "isolation", Program: extrun.Program{Path: "/usr/bin/git"}, Args: []string{"--version"}, RequireIsolation: true})
	}},
	// Custom scanners (security plan section 8.6, Phase D3): each built-in
	// template's run request, as internal/seccustom builds it, starts the
	// template's engine and asks its companion's version.
	{"security.scan.custom runs its template engines through the runner", func(r *extrun.Runner) {
		for _, tpl := range seccustom.Templates() {
			var comps []string
			for range tpl.Companions {
				comps = append(comps, customCompanions[tpl.ID])
			}
			m := seccustom.FromTemplate(tpl, "/opt/"+tpl.ID+"/bin/"+tpl.ID, comps)
			m.ExecutableSHA256 = "sha256-of:" + m.Executable
			for i := range m.Companions {
				m.Companions[i].SHA256 = "sha256-of:" + m.Companions[i].Path
			}
			spec, err := seccustom.BuildRun("linux", seccustom.Record{ID: tpl.ID, Manifest: m}, seccustom.RunDirs{Project: "/home/u/src/p", Output: "/home/u/.cache/run/out", Cache: "/home/u/.cache/run/cache"}, nil)
			if err != nil {
				continue
			}
			r.Run(context.Background(), spec.Request)
		}
	}},
}

// customCompanions are the companion paths the custom scanner row uses.
var customCompanions = map[string]string{"gosec": "/usr/local/go/bin/go", "bandit": "/usr/bin/python3", "semgrep": "/usr/bin/python3"}

// runnerFiles is the fake file table the consumers run against.
var runnerFiles = extruntest.Files{
	"/usr/bin/git":  {},
	"/usr/bin/ssh":  {},
	"/usr/bin/curl": {},
	// The custom scanner templates' engines and companions.
	"/opt/gosec/bin/gosec":     {},
	"/opt/bandit/bin/bandit":   {},
	"/opt/semgrep/bin/semgrep": {},
	"/usr/local/go/bin/go":     {},
	"/usr/bin/python3":         {},
	"/usr/bin/observer":        {},
	"/usr/bin/osv-scanner":     {},
	"/usr/bin/opengrep":        {},
}

// posixHostOnly names the runnerConsumers rows whose path cannot start
// anything on a Windows host, with the reason. The row's POSIX fixture
// paths are not absolute there, so the product correctly refuses before
// the executor (isolation.New rejects a bwrap path filepath.IsAbs denies).
var posixHostOnly = map[string]string{
	"isolation runs a program inside bwrap through the runner": "bwrap isolation is Linux-only; on Windows /usr/bin/bwrap is not an absolute path and isolation.New refuses it",
}

func TestProcessDeclarationRunnerSeam(t *testing.T) {
	t.Parallel()
	for _, rc := range runnerConsumers {
		if why, ok := posixHostOnly[rc.name]; ok && runtime.GOOS == "windows" {
			t.Logf("%s: skipped on Windows: %s", rc.name, why)
			continue
		}
		ex := &extruntest.Executor{}
		rc.run(extruntest.NewRunner("linux", runnerFiles, ex, nil))
		calls := ex.Calls()
		if len(calls) == 0 {
			t.Errorf("%s: the path started nothing through the fake executor", rc.name)
		}
		for _, p := range calls {
			checkDeclared(t, p.Component, p.Path, rc.name)
		}
	}
}

// TestProcessDeclarationCatchesUndeclared proves the check bites: a run of
// a program the component does not declare is caught by the same rule.
func TestProcessDeclarationCatchesUndeclared(t *testing.T) {
	t.Parallel()
	ex := &extruntest.Executor{}
	r := extruntest.NewRunner("linux", runnerFiles, ex, nil)
	r.Run(context.Background(), extrun.Request{Component: "projects", Program: extrun.Program{Path: "/usr/bin/curl"}})
	calls := ex.Calls()
	if len(calls) != 1 || calls[0].Component != "projects" {
		t.Fatalf("the runner did not hand the owning component to the executor: %+v", calls)
	}
	if extrun.DeclaresProcess(declaredBy(t, "projects"), calls[0].Path) {
		t.Fatal("projects declares curl; pick a program it does not declare for this self-test")
	}
}

// sudoNext is the set of wrapper programs whose next argument is itself a
// program the component starts.
var sudoNext = map[string]bool{"sudo": true}

// TestProcessDeclarationArgvBuilders checks the argv builders of exec sites
// that are not on the runner yet.
func TestProcessDeclarationArgvBuilders(t *testing.T) {
	t.Parallel()
	profile := sshprofile.Profile{Name: "dev", Host: "devbox"}
	var opts sshprofile.Options
	sshArgv := func(f func() ([]string, error)) []string {
		argv, err := f()
		if err != nil {
			t.Fatalf("ssh argv builder: %v", err)
		}
		return argv
	}
	rows := []struct {
		pkg  string
		site string
		argv []string
	}{
		{"internal/sshprofile", "sshprofile.Argv", sshArgv(func() ([]string, error) { return sshprofile.Argv(profile, opts) })},
		{"internal/sshprofile", "sshprofile.ForwardArgv", sshArgv(func() ([]string, error) { return sshprofile.ForwardArgv(profile, opts, 18081) })},
		{"internal/sshprofile", "sshprofile.TestArgv", sshArgv(func() ([]string, error) { return sshprofile.TestArgv(profile, opts) })},
		{"internal/sshprofile", "sshprofile.ResolveArgv", sshArgv(func() ([]string, error) { return sshprofile.ResolveArgv(profile) })},
		{"internal/service", "service.Systemctl", append([]string{service.Systemctl(service.ScopeUser, "status").Name}, service.Systemctl(service.ScopeUser, "status").Args...)},
		{"internal/service", "service.Journalctl", append([]string{service.Journalctl(service.ScopeUser, false, 10).Name}, service.Journalctl(service.ScopeUser, false, 10).Args...)},
		{"internal/tailnet", "tailnet.OperatorGrantArgv", tailnet.OperatorGrantArgv("dev")},
		{"internal/tailnet", "tailnet.LoginArgv(root)", tailnet.LoginArgv(true)},
		{"internal/tailnet", "tailnet.LoginArgv(user)", tailnet.LoginArgv(false)},
		{"internal/tailnet", "tailnet.InstallArgv", tailnet.InstallArgv()},
	}
	// The Plans & limits vendor CLIs: the driver table's fixed argv vectors
	// (a Converse process, or a planned exec request).
	ids := make([]string, 0, len(planlimits.Drivers))
	for id := range planlimits.Drivers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		d := planlimits.Drivers[id]
		if len(d.Argv) > 0 {
			rows = append(rows, struct {
				pkg, site string
				argv      []string
			}{"internal/planlimits", "planlimits driver " + id, d.Argv})
		}
		if d.Plan == nil {
			continue
		}
		reqs, err := d.Plan(planlimits.PlanInput{Params: map[string]string{}, Secrets: map[string]string{}})
		if err != nil {
			continue // a driver that needs a key plans no exec without one
		}
		for _, rq := range reqs {
			if rq.Kind == planlimits.ReqExec && len(rq.Argv) > 0 {
				rows = append(rows, struct {
					pkg, site string
					argv      []string
				}{"internal/planlimits", "planlimits driver " + id, rq.Argv})
			}
		}
	}
	found := gaps{}
	for _, row := range rows {
		if len(row.argv) == 0 {
			t.Errorf("%s: empty argv", row.site)
			continue
		}
		owner := ownerOfPackage(row.pkg)
		found.check(t, owner, row.argv[0], row.site)
		if sudoNext[row.argv[0]] && len(row.argv) > 1 {
			found.check(t, owner, row.argv[1], row.site+" (run by sudo)")
		}
	}
	found.compare(t, argvBuilderBaseline)
}

// argvBuilderBaseline records the undeclared programs the argv builders
// start today (lane s0-runner, 2026-10-20). It is a ratchet, like
// componentsFenceBaseline: a new gap fails, and an entry whose gap was
// fixed (the program declared in the catalog) fails until it is deleted.
// Each gap belongs to the owning component's catalog row. Empty since lane
// LEFT-SHARED (PT-04) declared the nine programs in their owning rows.
var argvBuilderBaseline = map[string]string{}

// dynamicSite is how one dynamic exec site is grounded (lane LEFT2-SEC
// item R-025, PT-04: every entry is checked, none is "not checked"). Exactly
// one of the four grounding fields is set, and TestDynamicExecSitesGrounded
// checks it.
type dynamicSite struct {
	// programs are the programs the site may start (or resolve), each
	// checked against the owning component's Surface.Processes
	// (extrun.DeclaresProcess) or, in a core package, coreExecAllowance.
	programs []string
	// class is a program family no closed list of names covers (the AI
	// agent CLI under test, the MCP server a user configured): the phrase
	// must appear in the owner's Surface.Processes.
	class string
	// checkedBy names the test that checks the site's argv,
	// "<repo-relative test file>:<TestName>".
	checkedBy string
	// lookupOnly: the site only resolves a path (exec.LookPath) for its
	// caller and starts nothing; the test checks it calls no Command.
	lookupOnly bool
	// serverSide: a core package that is never linked into the node (the
	// org server's harness and the gateway's P0 stub); a reason, checked
	// against the package path.
	serverSide bool
	how        string
}

// dynamicExecSites are the exec calls under internal/ whose program is not a
// literal, and the exec functions used as values (seams), keyed
// "package/file.go:function" ("<pkg>" for a package-level declaration). The
// static scan cannot read their program, so it requires each to be recorded
// here with its grounding; a new one fails until it is, and an entry that
// matches no use fails too.
var dynamicExecSites = map[string]dynamicSite{
	"internal/adapter/antigravity/process.go:discoveryOutput":                {programs: []string{"powershell", "ps", "lsof"}, how: "the discovery command chosen by OS"},
	"internal/arena/driver.go:spawnDrive":                                    {class: "AI agent CLIs", how: "the benchmark runs the agent CLI under test"},
	"internal/browserhost/remove.go:DeleteKey":                               {programs: []string{"reg"}, how: "reg.exe for the browser host keys"},
	"internal/browserhost/windowsreg.go:GetDefault":                          {programs: []string{"reg"}, how: "reg.exe for the browser host keys"},
	"internal/browserhost/windowsreg.go:SetDefault":                          {programs: []string{"reg"}, how: "reg.exe for the browser host keys"},
	"internal/guard/notify/notify.go:runWithTimeout":                         {programs: []string{"notify-send", "osascript", "powershell"}, how: "the desktop notifier, one per OS"},
	"internal/intelligence/dashboard/backfill_run.go:realExecBackfill":       {programs: []string{"observer"}, how: "the observer binary itself"},
	"internal/intelligence/dashboard/guard_hookcoverage.go:runSelfDoctor":    {programs: []string{"observer"}, how: "the observer binary itself"},
	"internal/intelligence/dashboard/guard_prompt.go:handleGuardPromptProbe": {programs: []string{"observer"}, how: "the observer binary itself"},
	"internal/launch/launch.go:Detect":                                       {programs: []string{"x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal", "xterm"}, how: "the Linux terminal emulators it looks for, in order"},
	"internal/launch/launch.go:Spawn":                                        {programs: []string{"wt", "cmd", "osascript", "x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal", "xterm"}, how: "the terminal emulator Detect chose"},
	"internal/mcprelay/wrapper.go:ServeStdioWrapper":                         {class: "the configured MCP server", how: "the wrapped MCP server the user configured"},
	"internal/processbridge/setup/env.go:runSchtasksQuery":                   {programs: []string{"schtasks"}, how: "the read-only schtasks.exe query"},
	"internal/processobs/bridge/backend.go:runCapturer":                      {programs: []string{"observer"}, how: "the Windows observer.exe the WSL bridge runs"},
	"internal/shellwrapsvc/target.go:interopShellFolder":                     {programs: []string{"reg"}, how: "reg.exe at the interop mount or on PATH"},
	"internal/termsession/spawn_unix.go:Spawn":                               {class: "vendor AI tool CLIs", how: "the AI tool CLI a terminal launches"},
	"internal/sshforward/spawn.go:Spawn":                                     {programs: []string{"ssh"}, how: "argv from sshprofile, also checked by TestProcessDeclarationArgvBuilders"},
	"internal/sshforward/spawn.go:NewOSTestRunner":                           {programs: []string{"ssh"}, how: "argv from sshprofile.TestArgv, also checked by TestProcessDeclarationArgvBuilders"},
	"internal/sshforward/spawn.go:resolveDestination":                        {programs: []string{"ssh"}, how: "argv from sshprofile.ResolveArgv, also checked by TestProcessDeclarationArgvBuilders"},
	"internal/tailnet/status.go:RunServe":                                    {programs: []string{"tailscale"}, how: "the path exec.LookPath(\"tailscale\") returned"},
	"internal/tailnet/status.go:Detect":                                      {programs: []string{"tailscale"}, how: "the path exec.LookPath(\"tailscale\") returned"},
	"internal/tailnet/status.go:ServeStatus":                                 {programs: []string{"tailscale"}, how: "the path exec.LookPath(\"tailscale\") returned"},
	"internal/processbridge/setup/env.go:ProductionEnv":                      {programs: []string{"schtasks"}, how: "exec.LookPath as the schtasks.exe resolver seam"},
	"internal/termsession/spawn_resolve.go:<pkg>":                            {class: "vendor AI tool CLIs", how: "the lookProgram seam (exec.LookPath) resolving the AI tool CLI Spawn starts"},
	"internal/thirdparty/actionlint/process.go:run":                          {checkedBy: "internal/secscan/actionlint/actionlint_test.go:TestNoProcessStarted", how: "never reached: the driver leaves the shellcheck and pyflakes names empty, so actionlint creates neither rule"},
	// Core packages (no component lists them).
	"internal/deliverynet/client.go:getGH":                               {programs: []string{"gh"}, how: "the gh CLI, resolved by its literal name through the deliverynet resolver"},
	"internal/deliverynet/client.go:lookPath":                            {programs: []string{"gh", "git"}, how: "the PATH-directory probe behind the deliverynet resolver"},
	"internal/deliverynet/mirror.go:configSSHCommand":                    {programs: []string{"git"}, how: "git, as the deliverynet resolver found it"},
	"internal/deliverynet/mirror.go:runGit":                              {programs: []string{"git"}, how: "git, as the deliverynet resolver found it"},
	"internal/diag/pspolicy_read.go:readExecutionPolicyList":             {programs: []string{"pwsh", "powershell"}, how: "a PowerShell from the host's own candidate list (integration.WindowsHookRunner, data) with a fixed read-only Get-ExecutionPolicy -List"},
	"internal/diag/crossos_windowsenv.go:probeWindowsEnv":                {programs: []string{"powershell"}, how: "powershell.exe on the WSL interop PATH, running crossmount's read of the Windows persistent environment, built only from validated variable names (doctor's crossos.windows_env row, surface-gap FU-70)"},
	"internal/diag/windowshookrunner.go:checkWindowsHookRunners":         {lookupOnly: true, how: "exec.LookPath as the probe's lookPath seam: resolves a PowerShell candidate on PATH and runs nothing"},
	"internal/platform/crossmount/wsldistros_windows.go:runWSLList":      {programs: []string{"wsl"}, how: "the System32 wsl.exe (%SystemRoot%, never a PATH lookup) with the fixed read-only argv --list --running --quiet, the running WSL distros a Windows host reads homes from (surface-gap FU-189)"},
	"internal/diag/windowsroute.go:probeWindowsCurl":                     {programs: []string{"curl"}, how: "the Windows curl.exe at a constant /mnt/c path (doctor's Windows route probe)"},
	"internal/extrun/host/exec.go:start":                                 {checkedBy: "tests/invariant/process_declaration_test.go:TestProcessDeclarationRunnerSeam", how: "the shared runner's executor: the checked plan's program, or this binary in its trampoline mode"},
	"internal/extrun/host/supervise_linux.go:supervise":                  {checkedBy: "tests/invariant/process_declaration_test.go:TestProcessDeclarationRunnerSeam", how: "the shared runner's supervisor: this binary in its exec-mode trampoline, which then execs the checked plan"},
	"internal/hookbridgesvc/run.go:Run":                                  {programs: []string{"wsl"}, how: "the System32 wsl.exe (hookbridge.WSLExe, never a PATH lookup) with a closed-spelling argv from hookbridge.Entry.Argv, run by `observer hook-bridge` (surface-gap AW-37)"},
	"internal/hook/agyhost.go:cachedAgyVersion":                          {programs: []string{"agy"}, how: "the agy binary that is the hook's own ancestor, run with --version"},
	"internal/hook/ibmbob_policy.go:ibmBobBinaryMissing":                 {lookupOnly: true, how: "resolves the observer binary an IBM Bob EnforcedHooks command names (doctor and stand-down); nothing is started"},
	"internal/hook/ibmbob_policy_unix.go:plistToJSON":                    {programs: []string{"plutil"}, how: "/usr/bin/plutil by a constant path (the IBM Bob managed policy plists and, by key name, the user com.ibm.bob domain on macOS)"},
	"internal/hook/windowsshell_path_other.go:readPersistentWindowsPATH": {programs: []string{"powershell"}, how: "powershell.exe on the WSL interop PATH, with a constant script (the VT Code sh check)"},
	"internal/machineid/machineid.go:<pkg>":                              {programs: []string{"ioreg", "reg"}, how: "the runTool seam: ioreg (darwin) and reg (windows) for the machine id"},
	"internal/managedconfig/source_darwin.go:plistToJSON":                {programs: []string{"plutil"}, how: "/usr/bin/plutil by a constant path (managed settings plist on macOS)"},
	"internal/mcpregister/ownership.go:<pkg>":                            {lookupOnly: true, how: "exec.LookPath as the lookPath seam: resolves the bare command an Observer MCP entry names (FU-24 ownership: stale-observer and same-install) and runs nothing"},
	"internal/mcpgw/agwadapter/p0stub/gateway.go:StartGateway":           {serverSide: true, how: "the pinned agentgateway binary the P0 stub harness runs (server side, not linked into the node)"},
	"internal/mcpgw/agwadapter/p0stub/gateway.go:RunOnce":                {serverSide: true, how: "the pinned agentgateway binary the P0 stub harness runs (server side, not linked into the node)"},
	"internal/orgserver/harness/external.go:runChild":                    {serverSide: true, how: "the configured external child of the org-server harness (server side)"},
	"internal/planlimitsnet/net.go:lookPath":                             {checkedBy: "tests/invariant/process_declaration_test.go:TestProcessDeclarationArgvBuilders", how: "the PATH-directory probe for a Plans & limits driver's argv[0]"},
	"internal/planlimitsnet/net.go:doExec":                               {checkedBy: "tests/invariant/process_declaration_test.go:TestProcessDeclarationArgvBuilders", how: "argv from the planlimits driver table"},
	"internal/planlimitsnet/net.go:Converse":                             {checkedBy: "tests/invariant/process_declaration_test.go:TestProcessDeclarationArgvBuilders", how: "argv from the planlimits driver table"},
	"internal/shimguard/shimguard.go:LookPath":                           {lookupOnly: true, how: "resolves the vendor binary a caller names past the command-wrapping shims; the caller starts it"},
	"internal/toolresolve/host/host.go:<pkg>":                            {programs: []string{"npm", "bash", "zsh", "sh", "ksh", "dash", "fish"}, how: "npm (prefix -g) and the operator's login shell from the closed loginShellTable, through the runNpmPrefix and runLoginShell seams"},
}

// TestDynamicExecSitesGrounded (lane LEFT2-SEC item R-025, PT-04): every
// dynamic exec site is grounded by exactly one rule, and the rule holds:
// its programs are declared by the owning component (or listed for the
// core package in coreExecAllowance), its class phrase is in the owner's
// Surface.Processes, the test it names exists, a lookup-only site starts
// nothing, and a server-side site is in a server-only package.
func TestDynamicExecSitesGrounded(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	for where, site := range dynamicExecSites {
		kinds := 0
		for _, set := range []bool{len(site.programs) > 0, site.class != "", site.checkedBy != "", site.lookupOnly, site.serverSide} {
			if set {
				kinds++
			}
		}
		if kinds != 1 || site.how == "" {
			t.Errorf("%s: want exactly one grounding and a reason, got %+v", where, site)
			continue
		}
		file, _, _ := strings.Cut(where, ":")
		pkg := file[:strings.LastIndex(file, "/")]
		owner := ownerOfPackage(pkg)
		switch {
		case len(site.programs) > 0:
			for _, prog := range site.programs {
				if owner == "core" {
					if _, ok := coreAllows(pkg, prog); !ok {
						t.Errorf("%s: core package %s may start %q, which coreExecAllowance does not list", where, pkg, prog)
					}
					continue
				}
				if !extrun.DeclaresProcess(declaredBy(t, owner), prog) {
					t.Errorf("%s: %q is not declared by component %q (Surface.Processes %q)", where, prog, owner, declaredBy(t, owner))
				}
			}
		case site.class != "":
			if owner == "core" {
				t.Errorf("%s: a class needs an owning component's declaration; core has none", where)
				continue
			}
			found := false
			for _, d := range declaredBy(t, owner) {
				if strings.Contains(d, site.class) {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: component %q does not declare the class %q", where, owner, site.class)
			}
		case site.checkedBy != "":
			path, name, _ := strings.Cut(site.checkedBy, ":")
			b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
			if err != nil || !strings.Contains(string(b), "func "+name+"(t *testing.T)") {
				t.Errorf("%s: checkedBy %s names no test (%v)", where, site.checkedBy, err)
			}
		case site.lookupOnly:
			if starts := execCommandsAt(t, root, where); starts {
				t.Errorf("%s: recorded as lookup-only, yet it calls exec.Command or exec.CommandContext", where)
			}
		case site.serverSide:
			if !strings.HasPrefix(pkg, "internal/orgserver/") && !strings.HasPrefix(pkg, "internal/mcpgw/") {
				t.Errorf("%s: recorded as server side, yet %s is not a server-only package", where, pkg)
			}
		}
	}
}

// execCommandsAt reports whether the declaration a dynamicExecSites key
// names calls exec.Command or exec.CommandContext.
func execCommandsAt(t *testing.T, root, where string) bool {
	t.Helper()
	file, fn, _ := strings.Cut(where, ":")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(file)), nil, 0)
	if err != nil {
		t.Fatalf("%s: %v", where, err)
	}
	execName := importName(f, "os/exec")
	starts := false
	for _, d := range f.Decls {
		name := "<pkg>"
		if fd, ok := d.(*ast.FuncDecl); ok {
			name = fd.Name.Name
		}
		if name != fn {
			continue
		}
		ast.Inspect(d, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == execName && (sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext") {
				starts = true
			}
			return true
		})
	}
	return starts
}

// execCallee names the exec functions the static scan reads and which
// argument holds the program.
var execCallee = map[string]int{
	"Command":        0,
	"CommandContext": 1,
	"LookPath":       0,
}

// TestProcessDeclarationStaticExecSites scans every package under internal/
// for exec calls. A component's packages are checked against its
// Surface.Processes (gaps go to staticExecBaseline); a package no component
// lists is core, and its literal programs must be listed, with a reason, in
// coreExecAllowance. A package-level seam (`var execCommand = exec.Command`)
// or any other non-call use of an exec function is a dynamic site like a
// non-literal program: it must be recorded in dynamicExecSites. cmd/ is not
// scanned (recorded in the SHR-1 ledger row).
func TestProcessDeclarationStaticExecSites(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	seenDynamic := map[string]bool{}
	coreUsed := map[string]bool{}
	found := gaps{}
	for _, pkg := range internalPackages(t, root) {
		owner := ownerOfPackage(pkg)
		forEachExecSite(t, root, pkg, func(where, pos, prog string) {
			switch {
			case prog == "":
				seenDynamic[where] = true
				if _, ok := dynamicExecSites[where]; !ok {
					t.Errorf("%s (%s): exec call with a non-literal program, or an exec function used as a value (a seam), in component %q; record it in dynamicExecSites with how its program is checked",
						where, pos, owner)
				}
			case owner == "core":
				key, ok := coreAllows(pkg, prog)
				if !ok {
					t.Errorf("%s (%s): core package %s starts %q, which coreExecAllowance does not list for it; add it with a reason, or move the package into the component that owns it",
						where, pos, pkg, extrun.ProcessName(prog))
					return
				}
				coreUsed[key] = true
			default:
				found.check(t, owner, prog, where)
			}
		})
	}
	public := inPublicTree(root)
	for where, site := range dynamicExecSites {
		// A server-side site lives in a server-only package, which the
		// public tree does not carry (scripts/release.sh PRIVATE_ONLY_PATHS:
		// internal/orgserver, internal/mcpgw), so the scan there cannot see
		// it. The private tree, which always has it, still requires the match.
		if site.serverSide && public {
			continue
		}
		if !seenDynamic[where] {
			t.Errorf("dynamicExecSites entry %q matches no exec call any more; delete it", where)
		}
		// A core package's dynamic site is grounded by its allowance rows
		// (TestDynamicExecSitesGrounded), which counts as their use.
		file, _, _ := strings.Cut(where, ":")
		pkg := file[:strings.LastIndex(file, "/")]
		for _, prog := range site.programs {
			if key, ok := coreAllows(pkg, prog); ok {
				coreUsed[key] = true
			}
		}
	}
	for _, row := range coreExecAllowance {
		for _, b := range row.binaries {
			if !coreUsed[row.pkg+" "+b] {
				t.Errorf("coreExecAllowance %s %q matches no exec call any more; delete it", row.pkg, b)
			}
		}
	}
	found.compare(t, staticExecBaseline)
}

// coreAllows reports whether coreExecAllowance lists prog for pkg, and the
// row key it matched.
func coreAllows(pkg, prog string) (string, bool) {
	for _, row := range coreExecAllowance {
		if row.pkg != pkg {
			continue
		}
		for _, b := range row.binaries {
			if extrun.DeclaresProcess([]string{b}, prog) {
				return row.pkg + " " + b, true
			}
		}
	}
	return "", false
}

// internalPackages lists every directory under internal/ that holds a
// non-test Go file, module-relative with forward slashes. testdata trees
// are skipped.
func internalPackages(t *testing.T, root string) []string {
	t.Helper()
	set := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "testdata" || n == "node_modules" || strings.HasPrefix(n, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if n := d.Name(); strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
			rel, err := filepath.Rel(root, filepath.Dir(p))
			if err != nil {
				return err
			}
			set[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// forEachExecSite parses pkg's non-test files and calls visit for every use
// of an exec function: prog is the literal program, or "" for a non-literal
// program or a use as a value. where is "pkg/file.go:function", with
// "<pkg>" for a package-level declaration.
func forEachExecSite(t *testing.T, root, pkg string, visit func(where, pos, prog string)) {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(pkg))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s/%s: %v", pkg, name, err)
		}
		execName := importName(f, "os/exec")
		if execName == "" {
			continue
		}
		isExec := func(sel *ast.SelectorExpr) (int, bool) {
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != execName {
				return 0, false
			}
			argIdx, known := execCallee[sel.Sel.Name]
			return argIdx, known
		}
		for _, d := range f.Decls {
			fnName := "<pkg>"
			if fd, ok := d.(*ast.FuncDecl); ok {
				fnName = fd.Name.Name
			}
			where := pkg + "/" + name + ":" + fnName
			called := map[*ast.SelectorExpr]bool{}
			ast.Inspect(d, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					sel, ok := x.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					argIdx, ok := isExec(sel)
					if !ok {
						return true
					}
					called[sel] = true
					prog := ""
					if len(x.Args) > argIdx {
						if lit, ok := x.Args[argIdx].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							if p, err := strconv.Unquote(lit.Value); err == nil {
								prog = p
							}
						}
					}
					visit(where, fset.Position(x.Pos()).String(), prog)
				case *ast.SelectorExpr:
					if _, ok := isExec(x); ok && !called[x] {
						visit(where, fset.Position(x.Pos()).String(), "")
					}
				}
				return true
			})
		}
	}
}

// staticExecBaseline records the undeclared literal programs the static
// scan finds today (lane s0-runner, 2026-10-20), as a ratchet like
// argvBuilderBaseline.
var staticExecBaseline = map[string]string{}

// coreExecAllowance lists, for each core package (one no component lists in
// its Packages), the literal programs it may start and why. Core has no
// Surface.Processes of its own for these, so this table is their
// declaration; a new literal program in a core package fails until it is
// listed here, and a listed program no call starts any more fails until it
// is deleted.
var coreExecAllowance = []struct {
	pkg      string
	binaries []string
	reason   string
}{
	{"internal/deliverynet", []string{"gh", "git"}, "the delivery lane's gh CLI and git, through its resolver (dynamic sites, lane LEFT2-SEC R-025)"},
	{"internal/diag", []string{"pwsh", "powershell"}, "doctor's Windows hook-runner rows read the PowerShell execution policy with a fixed read-only Get-ExecutionPolicy -List (surface-gap W-8, dynamic site)"},
	{"internal/diag", []string{"curl"}, "doctor's Windows route probe runs the Windows curl.exe at a constant /mnt/c path (dynamic site, lane LEFT2-SEC R-025)"},
	{"internal/diag", []string{"git"}, "`observer doctor` commit-capture probe looks for git on PATH (LookPath only)"},
	{"internal/diag", []string{"npx"}, "the Teams doctor probes look for npx for the native-console helpers (LookPath only)"},
	{"internal/diag", []string{"observer"}, "doctor's observer.path row looks for an observer on PATH older than the running one (LookPath only)"},
	{"internal/git", []string{"git"}, "repository root, worktree, merge-base and identity reads"},
	{"internal/gitview", []string{"git"}, "read-only git views (gitview.RunReadOnly, the one git exec envelope)"},
	{"internal/hookbridgesvc", []string{"wsl"}, "`observer hook-bridge` starts the System32 wsl.exe to run the WSL daemon's hook for an enforcing managed node's tool gate (surface-gap AW-37, dynamic site)"},
	{"internal/hook", []string{"powershell"}, "the VT Code Windows sh check reads the persistent Windows PATH over WSL interop (registration warning and doctor row)"},
	{"internal/hook", []string{"agy", "plutil"}, "the agy ancestor's --version and the IBM Bob policy plist reads on macOS (managed, and the user domain by key name, FU-105; dynamic sites, lane LEFT2-SEC R-025)"},
	{"internal/machineid", []string{"ioreg", "reg"}, "the machine id on darwin and windows (dynamic site, lane LEFT2-SEC R-025)"},
	{"internal/managedconfig", []string{"plutil"}, "the managed settings plist read on macOS (dynamic site, lane LEFT2-SEC R-025)"},
	{"internal/toolresolve/host", []string{"npm", "bash", "zsh", "sh", "ksh", "dash", "fish"}, "npm prefix -g and the operator's login shell from the closed loginShellTable (dynamic site, lane LEFT2-SEC R-025)"},
	{"internal/platform/crossmount", []string{"cmd", "wsl"}, "reads %USERNAME% over WSL interop to find the Windows home; on a Windows host lists the running WSL distros with wsl.exe --list --running --quiet (surface-gap FU-189, dynamic site)"},
}

// importName returns the local name a file imports path under, or "".
func importName(f *ast.File, path string) string {
	for _, imp := range f.Imports {
		if p, err := strconv.Unquote(imp.Path.Value); err != nil || p != path {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		return filepath.Base(path)
	}
	return ""
}
