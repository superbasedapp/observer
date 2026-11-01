//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_windows_live_fix_test.go pins the fixes of the Windows 11 Pro live
// run of 2026-10-22 (mxc-process, MXC 1.0.1, build 26300.9711).

// windowsShellEnv is what a process started from cmd or PowerShell inherits:
// Windows' hidden "=" entries come first in its environment block.
var windowsShellEnv = []string{
	`=C:=C:\Users\winagent\work`, "=ExitCode=00000001", `=::=::\`,
	`PATH=C:\iso\bin;C:\Windows\System32`, `SystemRoot=C:\Windows`, `USERPROFILE=C:\iso`,
}

// TestMXCBoxEnvSkipsHiddenWindowsEntries (item 1): the run's policy is built
// from a shell's environment instead of being refused with "an environment
// entry is not KEY=VALUE", and no reader on the launch path passes a hidden
// entry on.
func TestMXCBoxEnvSkipsHiddenWindowsEntries(t *testing.T) {
	tok, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("h", 32)))
	env := mxcBoxEnv(windowsShellEnv, `C:\t\observer-sbx-r7`, `C:\t\observer-sbx-r7\tmp`, vocab.TierInternet, 4321, tok, nil)
	for _, kv := range env {
		if strings.HasPrefix(kv, "=") {
			t.Errorf("the box's environment keeps the hidden entry %q", kv)
		}
	}
	if !slices.Contains(env, `PATH=C:\iso\bin;C:\Windows\System32`) || !slices.Contains(env, `USERPROFILE=C:\iso`) {
		t.Fatalf("the box's environment lost the host's own variables: %v", env)
	}
	inner, err := mxcInnerLaunch([]string{`C:\p6live\observer.exe`, "claude"})
	if err != nil {
		t.Fatal(err)
	}
	plan := mxcPlanFile{RunID: "r7", Workspace: `C:\iso\work`, ReadWrite: []string{`C:\iso\work`}, Tier: "internet"}
	if _, err := mxcRunDocument(plan, `C:\t\observer-sbx-r7`, `C:\t\observer-sbx-r7\tmp`, inner, env, 4321, false); err != nil {
		t.Fatalf("the run's policy refused a shell's environment: %v", err)
	}
	for _, kv := range mxcExecEnv(windowsShellEnv) {
		if strings.HasPrefix(kv, "=") {
			t.Errorf("wxc-exec's environment keeps the hidden entry %q", kv)
		}
	}
	if got := mxcSystemRootOf(windowsShellEnv); got != `C:\Windows` {
		t.Fatalf("SystemRoot %q", got)
	}
}

// TestPathUnderWindowsRules (item 3): the containment check compares Windows
// paths with the Windows separator and case rule, so the placeholder
// `<cwd>\.git` lies inside the run's only writable root <cwd>; Linux keeps
// its rules.
func TestPathUnderWindowsRules(t *testing.T) {
	const iso = `C:\Users\winagent\AppData\Local\Temp\sbo-p6-iso-1`
	for _, c := range []struct {
		p, root string
		sep     byte
		fold    bool
		want    bool
	}{
		{iso + `\work\.git`, iso + `\work`, '\\', true, true},
		{iso + `\work`, iso + `\work`, '\\', true, true},
		{strings.ToLower(iso) + `\WORK\.git`, iso + `\work`, '\\', true, true},
		{iso + `\work2\.git`, iso + `\work`, '\\', true, false},
		{iso, iso + `\work`, '\\', true, false},
		{`D:\x\work\.git`, `C:\x\work`, '\\', true, false},
		{`C:\x`, `C:\`, '\\', true, true},
		{`D:\x`, `C:\`, '\\', true, false},
		{"/home/a/w/.git", "/home/a/w", '/', false, true},
		{"/home/a/w2", "/home/a/w", '/', false, false},
		{"/home/A/w/.git", "/home/a/w", '/', false, false},
		{"/anything/below", "/", '/', false, true},
		{"/", "/", '/', false, true},
	} {
		if got := pathUnder(c.p, c.root, c.sep, c.fold); got != c.want {
			t.Errorf("pathUnder(%q, %q, %q, %v) = %v, want %v", c.p, c.root, c.sep, c.fold, got, c.want)
		}
	}
	ws := t.TempDir()
	created, err := mxcCreatePlaceholders(mxcPlanFile{ReadWrite: []string{ws}, PlaceholderDirs: []string{filepath.Join(ws, ".git")}})
	if err != nil {
		t.Fatalf("a placeholder inside the only writable root was refused: %v", err)
	}
	mxcRemovePlaceholders(created)
}

// TestBoxLaunchGateRefusalIsVisible (item 2): an in-box launch check that
// cannot reach the relay is refused with a message the terminal shows,
// naming why box detection declined, never a bare exit 1.
func TestBoxLaunchGateRefusalIsVisible(t *testing.T) {
	t.Setenv(sandboxEnvMarker, "1")
	oldRec, oldNote := boxRecordPath, boxDetectNote
	boxRecordPath = filepath.Join(t.TempDir(), "missing", sandboxrelayd.BoxRecordName)
	boxDetectNote = "this process holds no AppContainer token"
	t.Cleanup(func() { boxRecordPath, boxDetectNote = oldRec, oldNote })
	err, boxed := boxLaunchGate("claude-code", budgetLaunchEvidence{})
	if !boxed || err == nil {
		t.Fatalf("boxed %v err %v", boxed, err)
	}
	var visible launcherMessageError
	if !errors.As(err, &visible) {
		t.Fatalf("a plain error, which a launcher's silenced Cobra hides: %v", err)
	}
	root := &cobra.Command{Use: "observer", SilenceErrors: true}
	claude := &cobra.Command{Use: "claude", SilenceErrors: true}
	root.AddCommand(claude)
	var out bytes.Buffer
	if !renderSuppressedLauncherError(&out, root, claude, err) {
		t.Fatal("the refusal was not rendered")
	}
	if !strings.Contains(out.String(), boxGateRefusals[boxGateNotRecognised]) || !strings.Contains(out.String(), "no AppContainer token") {
		t.Fatalf("the terminal shows %q", out.String())
	}
}

// TestBoxInnerFailureIsNeverSilent (item 2): inside a box that names an
// inner log, a failure Cobra hid is printed as one line and logged, a
// tool's own exit code is logged only, the run's token never reaches either,
// and outside a box nothing changes.
func TestBoxInnerFailureIsNeverSilent(t *testing.T) {
	logp := filepath.Join(t.TempDir(), mxcInnerLogName)
	t.Setenv(sandboxInnerLogEnv, logp)
	const secret = "tok-0123456789abcdef"
	boxSecretsMu.Lock()
	oldSecrets := boxSecrets
	boxSecretsMu.Unlock()
	t.Cleanup(func() { boxSecretsMu.Lock(); boxSecrets = oldSecrets; boxSecretsMu.Unlock() })
	registerBoxSecret(secret)

	root := &cobra.Command{Use: "observer"}
	claude := &cobra.Command{Use: "claude", SilenceErrors: true}
	root.AddCommand(claude)
	var out bytes.Buffer
	reportBoxInnerFailure(&out, claude, false, fmt.Errorf("exec claude: exec: \"C:\\\\iso\\\\bin\\\\claude.cmd\": file does not exist\nvia http://127.0.0.1:5/t/%s", secret))
	if n := strings.Count(out.String(), "\n"); n != 1 || !strings.HasPrefix(out.String(), "observer claude: exec claude") {
		t.Fatalf("printed %q", out.String())
	}
	out.Reset()
	reportBoxInnerFailure(&out, claude, false, exitErr(7))
	reportBoxInnerFailure(&out, claude, true, newVisibleLauncherError(errors.New("internal"), "a shown launcher message"))
	if out.Len() != 0 {
		t.Fatalf("printed %q for a tool's own exit or a message already shown", out.String())
	}
	b, err := os.ReadFile(logp)
	if err != nil {
		t.Fatal(err)
	}
	log := string(b)
	for _, want := range []string{"observer claude: exec claude", "observer claude: exited with code 7", "a shown launcher message", "[REDACTED]"} {
		if !strings.Contains(log, want) {
			t.Errorf("the inner log lacks %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, secret) || strings.Count(log, "\n") != 3 {
		t.Fatalf("the inner log:\n%s", log)
	}
	t.Setenv(sandboxInnerLogEnv, "")
	reportBoxInnerFailure(&out, claude, false, errors.New("outside a box"))
	if b2, _ := os.ReadFile(logp); out.Len() != 0 || string(b2) != log {
		t.Fatal("outside a box the failure was reported")
	}
}

// TestMXCReportInnerLog (item 2): the helper prints what the box logged when
// it exits non-zero, only the tail, without control characters, never
// through a link, and says so when nothing was logged.
func TestMXCReportInnerLog(t *testing.T) {
	dir := t.TempDir()
	p := mxcInnerLogPath(dir)
	var w bytes.Buffer
	mxcReportInnerLog(&w, p, 1)
	if !strings.Contains(w.String(), "exited with code 1 and no Observer process in it logged anything") {
		t.Fatalf("no log: %q", w.String())
	}
	body := "t pid 1: box detection: not recognised: this process holds no AppContainer token\nt pid 1: observer claude: refused\x1b[31m\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reset()
	mxcReportInnerLog(&w, p, 1)
	if !strings.Contains(w.String(), "no AppContainer token") || !strings.Contains(w.String(), "observer claude: refused") || strings.Contains(w.String(), "\x1b") {
		t.Fatalf("log: %q", w.String())
	}
	big := strings.Repeat("filler line\n", 2000) + "LAST LINE\n"
	if err := os.WriteFile(p, []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reset()
	mxcReportInnerLog(&w, p, 2)
	if !strings.Contains(w.String(), "LAST LINE") || w.Len() > mxcInnerLogTail+1024 {
		t.Fatalf("tail: %d bytes", w.Len())
	}
	if runtime.GOOS != "windows" {
		secret := filepath.Join(t.TempDir(), "host-secret")
		if err := os.WriteFile(secret, []byte("HOST-SECRET\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := mxcInnerLogPath(t.TempDir())
		if err := testSymlink(t, secret, link); err != nil {
			t.Fatal(err)
		}
		w.Reset()
		mxcReportInnerLog(&w, link, 1)
		if strings.Contains(w.String(), "HOST-SECRET") || !strings.Contains(w.String(), "not read") {
			t.Fatalf("a link was followed: %q", w.String())
		}
	}
	// The box's environment names the log, replacing an inherited value.
	tok, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("q", 32)))
	env := mxcBoxEnv([]string{sandboxInnerLogEnv + `=C:\forged`}, `C:\b`, dir, vocab.TierProxyOnly, 4242, tok, nil)
	if !slices.Contains(env, sandboxInnerLogEnv+"="+p) || slices.Contains(env, sandboxInnerLogEnv+`=C:\forged`) {
		t.Fatalf("box env %v", env)
	}
}

// TestMXCBoxDetectionSaysWhy (item 2): every decline of box detection has a
// reason, which the inner log and a refused launch check carry.
func TestMXCBoxDetectionSaysWhy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), mxcBoxDirPrefix+"run-7")
	own := mxcBoxFacts{
		AppContainer: true, TokenSID: "S-1-15-2-observer-run-7", BoxDir: dir, RecordRunID: "run-7",
		Identity: hostIdentity("run-7", "S-1-15-2-observer-run-7"), NameSID: fakeProfileSID,
		DriverSelected: func() bool { return true },
	}
	if id, why := mxcBoxRunIDWhy(own); id != "run-7" || why != "" {
		t.Fatalf("our own box: %q %q", id, why)
	}
	for name, c := range map[string]struct {
		mut  func(*mxcBoxFacts)
		want string
	}{
		"no AppContainer token":     {func(f *mxcBoxFacts) { f.AppContainer = false }, "no AppContainer token"},
		"no SID":                    {func(f *mxcBoxFacts) { f.TokenSID = "" }, "SID cannot be read"},
		"a relative box directory":  {func(f *mxcBoxFacts) { f.BoxDir = "observer-sbx-run-7" }, "not an absolute path"},
		"a directory naming no run": {func(f *mxcBoxFacts) { f.RecordRunID, f.BoxDir = "", t.TempDir() }, "names no run"},
		"a bad run id":              {func(f *mxcBoxFacts) { f.RecordRunID = "../x" }, "not valid"},
		"no identity answer":        {func(f *mxcBoxFacts) { f.Identity, f.IdentityErr = nil, errors.New("no") }, "could not be asked"},
		"another container":         {func(f *mxcBoxFacts) { f.TokenSID = "S-1-15-2-1-2-3" }, "is not the SID"},
		"the driver not selected":   {func(f *mxcBoxFacts) { f.DriverSelected = func() bool { return false } }, mxcComponent},
	} {
		f := own
		c.mut(&f)
		id, why := mxcBoxRunIDWhy(f)
		if id != "" || !strings.Contains(why, c.want) {
			t.Errorf("%s: id %q why %q", name, id, why)
		}
	}
}

// TestSandboxCLIForwardsTheUsersArguments (item 2): a sandboxed CLI launch
// hands the box every one of the user's arguments, in order, through the
// host helper's argv and the box process's command line.
func TestSandboxCLIForwardsTheUsersArguments(t *testing.T) {
	exe := `C:\p6live\observer.exe`
	req, ok, err := parseSandboxCLI([]string{exe, "claude", "--claude-path", `C:\iso\work\claude.exe`, "--observer-sandbox", "mxc-process", "--no-attach", "--", "--print", "hi there"})
	if !ok || err != nil {
		t.Fatalf("parse %v %v", ok, err)
	}
	obs := t.TempDir()
	argv := sandboxCLIInnerArgv(mxcWrapArgv(exe, filepath.Join(obs, "plan.json"), "r1", obs), exe, req.Verb, req.Rest)
	h, err := parseMXCHostArgs(argv)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{exe, "claude", "--claude-path", `C:\iso\work\claude.exe`, "--no-attach", "--", "--print", "hi there"}
	if !slices.Equal(h.inner, want) {
		t.Fatalf("the helper's inner launch %q, want %q", h.inner, want)
	}
	inner, err := mxcInnerLaunch(h.inner)
	if err != nil {
		t.Fatal(err)
	}
	if line := sandboxmxc.CommandLine(inner); !strings.Contains(line, `claude --claude-path C:\iso\work\claude.exe --no-attach -- --print "hi there"`) {
		t.Fatalf("the box process's command line %q", line)
	}
}

// TestLaunchersDocumentObserverSandbox (item 5): a launcher's --help names
// --observer-sandbox, which runs before Cobra and is no registered flag.
func TestLaunchersDocumentObserverSandbox(t *testing.T) {
	cmd := newClaudeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "--observer-sandbox <profile>") || !strings.Contains(out.String(), sandboxbackend.BackendMXCProcess) {
		t.Fatalf("observer claude --help:\n%s", out.String())
	}
}

// TestSandboxOverallWindowsLiveShape (item 4): the operator's status shape
// (mxc-process listed and available, beta, bwrap's own probe saying it needs
// Linux) never prints bwrap's "requires a Linux daemon" as the overall line.
func TestSandboxOverallWindowsLiveShape(t *testing.T) {
	mxc, bwrap := sandboxbackend.BackendMXCProcess, sandboxbackend.BackendBwrap
	r := &sandboxRuntime{
		cfg:     config.TerminalSandboxConfig{Enabled: true, Backends: []string{mxc}},
		drivers: map[string]sandboxDriver{mxc: nil},
	}
	legacy := sandbox.Availability{Verdict: sandbox.VerdictUnsupportedPlatform, Backend: bwrap, Reason: `bubblewrap sandboxing requires a Linux daemon (incl. WSL2); this daemon runs "windows"`}
	rows := []dashapi.SandboxBackendAvail{
		{ID: bwrap, Verdict: "disabled_by_config", Reason: "not in the enabled backends list"},
		{ID: mxc, Available: true, Beta: true},
	}
	av := sandboxPlatformOverall(r.preferDriverInLegacy(legacy, rows), rows, sandboxbackend.HostWindows)
	if av.Verdict == sandbox.VerdictUnsupportedPlatform || strings.Contains(av.Reason, "Linux daemon") || av.Backend != mxc {
		t.Fatalf("status overall %+v", av)
	}
	r.forceBackend = mxc
	if av := sandboxPlatformOverall(r.preferDriverInLegacy(legacy, rows), rows, sandboxbackend.HostWindows); !av.Available || av.Backend != mxc {
		t.Fatalf("named on the command line: %+v", av)
	}
}
