//go:build windows && !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/sandboxmxcdll"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// terminal_sandbox_mxc_windows.go is the MXC driver's Windows I/O (lane
// SBX-P6): the two helper verbs, the only code that reaches
// internal/sandboxmxcdll's loader (TestMXCLibraryOnlyInTheHelper), and the
// box-side wiring a process inside one of this driver's containers picks
// up at start.

func init() { boxDetect = mxcDetectBox }

// mxcDetectBox recognises, once per process, that this process runs inside
// one of this driver's ProcessContainers (audit finding F1): an
// AppContainer token alone is not enough, since any vendor's AppContainer
// carries one. The token's container must be the one the run's host helper
// read from the token of the box process under its own wxc-exec, which it
// answers on the run's port (MXC 1.0.1 names the AppContainer itself, so
// the profile observer-<run id> this check once derived is not it: Windows
// 11 Pro rerun 2026-10-22), for the run the box directory names
// (mxcBoxRunID), and the mxc driver must be selected in the config this
// process reads.
// Anything else leaves every box variable as it was before the driver
// existed, so an observer hook or CLI started in another vendor's
// AppContainer runs as it always did.
func mxcDetectBox() {
	sid, inside := sandboxmxcdll.AppContainerSID()
	dir := os.Getenv(mxcBoxDirEnv)
	if !inside && dir == "" {
		return
	}
	f := mxcBoxFacts{
		AppContainer: inside, TokenSID: sid, BoxDir: dir,
		NameSID: sandboxmxcdll.AppContainerProfileSID, DriverSelected: mxcDriverSelectedInBox,
	}
	if inside && filepath.IsAbs(dir) {
		if rec, present, err := sandboxrelayd.ReadBoxRecord(filepath.Join(dir, sandboxrelayd.BoxRecordName)); present && err == nil {
			f.RecordRunID = rec.RunID
		}
		f.Identity, f.IdentityErr = mxcAskBoxIdentity(dir)
	}
	id, why := mxcBoxRunIDWhy(f)
	if id == "" {
		// A process the run's environment points at a box, yet that does
		// not recognise it, says why: a refused launch check names it and
		// the run's inner log, which the helper prints when the box exits
		// non-zero, records it (Windows 11 Pro live run 2026-10-22, where
		// this decline was invisible). It runs nothing: main exits 125
		// before any command (WINFIX4 audit finding 4), since such a
		// process never entered the UI-limited job. Another vendor's
		// AppContainer, which no box directory names, stays silent.
		if dir != "" {
			boxDetectNote = why
			boxStartRefusal = mxcUnrecognisedRefusal(why)
			appendBoxInnerLog("box detection: not recognised: " + why + "; nothing more runs in the box")
		}
		return
	}
	appendBoxInnerLog("box detection: recognised run " + id)
	// The job UI limits (RERUN2 D2): this process runs before the tool, so
	// it puts itself, and with it everything the box starts later, in a
	// nested job carrying every limit, and reports the class it read back
	// to the run's host helper, which ends a run whose box never does. The
	// helper cannot set them on its own job (MXC refuses to create a box
	// under one). Fail closed.
	class, entered, uerr := sandboxmxcdll.EnterUIRestrictedJob(sandboxmxc.JobUIRestrictions)
	refusal, line := mxcBoxUIOutcome(class, entered, uerr, func(c uint32) error { return mxcReportUIClass(dir, c) })
	appendBoxInnerLog(line)
	if refusal != "" {
		boxStartRefusal = refusal
		return
	}
	// The tool's temp and LocalAppData folders exist before it starts
	// (D1): Windows names folders under the run's LOCALAPPDATA that nobody
	// created.
	set, mkdir := mxcBoxTempEnv(os.Getenv, dir)
	for _, d := range mkdir {
		if err := os.MkdirAll(d, 0o700); err != nil {
			appendBoxInnerLog("box detection: cannot create " + d + ": " + err.Error())
		}
	}
	for _, kv := range set {
		_ = os.Setenv(kv[0], kv[1])
	}
	// Inside this driver's box: a missing or refused launch record blocks
	// gate events (sandbox plan section 5.2, Opus M8) and the hook reaches
	// the relay through the run's loopback port.
	boxInsideByToken = true
	boxSocketDir = dir
	boxRecordPath = filepath.Join(dir, sandboxrelayd.BoxRecordName)
	relaySpoolDir = filepath.Join(os.TempDir(), ".observer-relay-spool")
	boxRoundTrip = func(ctx context.Context, rec sandboxrelayd.BoxRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
		return mxcBoxRoundTrip(ctx, dir, rec, req)
	}
	boxOOBStream = func() (io.WriteCloser, string, bool) {
		lb, err := readMXCLoopback(dir)
		if err != nil {
			return nil, "", false
		}
		// The box hook's dial reads the Windows first-hook floor (SBX-P6
		// audit info 9), the one owner of that number.
		ctx, cancel := context.WithTimeout(context.Background(), integration.WindowsFirstHookFloor)
		defer cancel()
		c, err := dialMXCUpgrade(ctx, lb, "oob", sandboxmxc.UpgradeOOB)
		if err != nil {
			return nil, "", false
		}
		return c, lb.Token, true
	}
	// The inner launcher's proxy flag arrives in its environment, never on
	// a command line (finding F2): it is inserted into this process's own
	// argv in memory and the variable is dropped, so the tool and its hooks
	// never inherit it.
	boxArgvRewrite = func(args []string) []string {
		url := os.Getenv(mxcProxyURLEnv)
		_ = os.Unsetenv(mxcProxyURLEnv)
		// Neither the inner log nor a failure line ever carries the token.
		registerBoxSecret(url)
		if i := strings.LastIndex(url, "/t/"); i >= 0 {
			registerBoxSecret(url[i+len("/t/"):])
		}
		return mxcBoxArgv(args, url)
	}
}

// mxcBundleDir is where this binary's MXC files are installed.
func mxcBundleDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return filepath.Join(filepath.Dir(exe), sandboxmxc.BundleDir), nil
}

// mxcProbeDocs are the request probe's and the create-and-close check's
// documents: the run's policy shape with a command that exits at once
// (the request probe also allows host loopback for a port, so MXC answers
// for the network shape a run uses).
func mxcProbeDocs() ([]byte, []byte, error) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	cmdExe := filepath.Join(root, "System32", "cmd.exe")
	lad := mxcProbeLocalAppData()
	check, err := sandboxmxc.ProbeDocument(cmdExe, root, lad)
	if err != nil {
		return nil, nil, err
	}
	probe, err := sandboxmxc.BuildDocument(sandboxmxc.RunPlan{RunID: "probe", Argv: []string{cmdExe, "/d", "/c", "exit 0"}, Cwd: root, ProxyPort: 9, SystemRoot: root, LocalAppData: lad})
	if err != nil {
		return nil, nil, err
	}
	pb, err := probe.Encode()
	if err != nil {
		return nil, nil, err
	}
	cb, err := check.Encode()
	return pb, cb, err
}

// mxcProbeLocalAppData is the LOCALAPPDATA the probes' one-shot commands
// get: a path in the probe's own box directory name, never the host user's
// LocalAppData. Windows needs only its presence (MXC 1.0.1).
func mxcProbeLocalAppData() string {
	return mxcLocalAppDataDir(filepath.Join(os.TempDir(), mxcBoxDirPrefix+"probe"))
}

// mxcGather gathers the ladder's facts within timeout. A gather that does
// not finish (native code that hangs) is reported as probe_failed; the
// process exits afterwards, which unloads what it loaded.
func mxcGather(active, keepOpen bool, stage sandboxmxcdll.Stage, timeout time.Duration) (sandboxmxc.HostFacts, *sandboxmxcdll.Verified, error) {
	if r := mxcSignedSet(); !r.OK {
		// The signed manifest refused the set: nothing is opened or loaded,
		// on the passive probe too, so availability matches launches
		// (SBX-P3D audit finding 6).
		return sandboxmxc.HostFacts{}, nil, errors.New(r.Verdict.Error())
	}
	dir, err := mxcBundleDir()
	if err != nil {
		return sandboxmxc.HostFacts{}, nil, err
	}
	pb, cb, err := mxcProbeDocs()
	if err != nil {
		return sandboxmxc.HostFacts{}, nil, err
	}
	type out struct {
		f sandboxmxc.HostFacts
		v *sandboxmxcdll.Verified
	}
	ch := make(chan out, 1)
	go func() {
		env := sandboxmxcdll.HostEnv(dir, active, pb, cb)
		env.Stage = stage
		f, v := sandboxmxcdll.Gather(env, keepOpen)
		ch <- out{f, v}
	}()
	select {
	case o := <-ch:
		return o.f, o.v, nil
	case <-time.After(timeout):
		return sandboxmxc.HostFacts{}, nil, fmt.Errorf("the MXC probe did not finish within %s", timeout)
	}
}

// runMXCProbe is `observer sandbox-mxc-probe --active [--stage S]`: the
// probe ladder in a short-lived process, answered as JSON on stdout. The
// daemon passes no stage (every row, the create-and-close check included,
// and the answer is the ladder's result alone). The live checks of
// scripts/sandbox/p6-live-check.ps1 pass a stage and get the facts too:
// version (load and read mxc_version, nothing else), request (MXC's request
// probe, nothing created), create (every row) or echo (every row, then one
// ProcessContainer run of `cmd /c echo` whose output is reported). A stage
// is judged only through its own last row (mxcStageLastRow, finding L3).
func runMXCProbe(args []string) int {
	active, stage, report := false, sandboxmxcdll.StageCreate, ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--active":
			active = true
		case mxcFlagObserverDir:
			if i+1 >= len(args) || !filepath.IsAbs(args[i+1]) {
				return mxcRefuse("%s needs an absolute path", mxcFlagObserverDir)
			}
			i++
			mxcHelperObserverDir = args[i]
		case "--stage":
			if i+1 >= len(args) {
				return mxcRefuse("--stage needs version, request, create or echo")
			}
			i++
			report = args[i]
			switch report {
			case "version":
				stage = sandboxmxcdll.StageVersion
			case "request":
				stage = sandboxmxcdll.StageRequest
			case "create", "echo":
			default:
				return mxcRefuse("--stage needs version, request, create or echo")
			}
		}
	}
	// The probe reads the daemon's content store: the daemon passes its
	// observer dir, and a hand-run probe must name it (lane LEFT-SBX).
	if why := mxcProbeDirRefusal(mxcHelperObserverDir, mxcObserverDir()); why != "" {
		return mxcRefuse("%s", why)
	}
	facts, verified, err := mxcGather(active, report == "echo", stage, mxcDefaultProbeTimeout)
	res := mxcProbeAnswer(sandboxmxc.ProbeThrough(facts, mxcManifest(), mxcStageLastRow(report)), err, mxcSignedSet())
	enc := json.NewEncoder(os.Stdout)
	if report == "" {
		if err := enc.Encode(res); err != nil {
			return 1
		}
		return 0
	}
	out := mxcProbeReport{Stage: report, Result: res, Facts: facts}
	if report == "echo" && verified != nil && verified.Library != nil {
		out.Echo = mxcEcho(verified.Library)
	}
	verified.Release()
	if err := enc.Encode(out); err != nil {
		return 1
	}
	return 0
}

// mxcProbeReport is a staged probe's answer (the live checks' receipt).
type mxcProbeReport struct {
	Stage  string                 `json:"stage"`
	Result sandboxmxc.ProbeResult `json:"result"`
	Facts  sandboxmxc.HostFacts   `json:"facts"`
	Echo   string                 `json:"echo,omitempty"`
}

// mxcEcho runs one ProcessContainer `cmd /c echo` through the C ABI and
// reports what it printed or why it failed.
func mxcEcho(lib sandboxmxcdll.Library) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	doc, err := sandboxmxc.BuildDocument(sandboxmxc.RunPlan{RunID: "echo", Argv: []string{filepath.Join(root, "System32", "cmd.exe"), "/d", "/c", "echo", "observer-mxc-echo-ok"}, Cwd: root, SystemRoot: root, LocalAppData: mxcProbeLocalAppData()})
	if err != nil {
		return "error: " + err.Error()
	}
	b, err := doc.Encode()
	if err != nil {
		return "error: " + err.Error()
	}
	r, err := lib.RunOneShot(b)
	switch {
	case err != nil:
		return "error: " + err.Error()
	case r.Error != nil:
		return "error: " + r.Error.Error()
	}
	return fmt.Sprintf("exit %d: %s", r.ExitCode, r.Stdout)
}

// mxcManifest is the pinned set for this architecture (an empty manifest
// refuses every file as missing): the compiled pins, which stay the floor
// whether or not a signed sandbox.native_files manifest is installed
// (mxcSignedSet; lane SBX-P3D).
func mxcManifest() sandboxmxc.Manifest {
	return mxcSignedSet().Manifest
}

// mxcSignedSet resolves the compiled pins against the installed signed
// manifest (sandbox_content_native.go): none installed is the compiled pins
// byte for byte; a revoked, expired past its floor, unverifiable or
// out-of-floor one refuses before anything is loaded (mxcGather). A
// variable so a test can stand in a result.
var mxcSignedSet = func() sandboxmxc.SignedResult {
	if dir := mxcStoreDir(); dir != "" {
		return mxcEffectiveSet(dir, runtime.GOARCH)
	}
	m, ok := sandboxmxc.ManifestFor(runtime.GOARCH)
	return sandboxmxc.ResolveSigned(sandboxmxc.SignedInput{Compiled: m, HasCompiled: ok, Arch: runtime.GOARCH})
}

// mxcHelperObserverDir is the observer directory the daemon passed this
// helper (--observer-dir on both helper verbs): the content store of the
// daemon's real config (SBX-P3D audit finding 5).
var mxcHelperObserverDir string

// mxcStoreDir is the directory whose content store the helper reads: the
// one the daemon passed. The probe refuses without it (mxcProbeDirRefusal,
// lane LEFT-SBX); only the host verb, which always gets it, reaches the
// fallback, which reads this process's own config.
func mxcStoreDir() string {
	if mxcHelperObserverDir != "" {
		return mxcHelperObserverDir
	}
	return mxcObserverDir()
}

// mxcObserverDir is the observer directory of this process's config: the
// --config the process was given, else the default one. The daemon's
// helpers never use it (they get --observer-dir).
func mxcObserverDir() string {
	path, err := config.ResolveGlobalPath(daemonConfigPath())
	if err != nil {
		return ""
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil || cfg.Observer.DBPath == "" {
		return ""
	}
	return filepath.Dir(cfg.Observer.DBPath)
}

// mxcDesktopEndCode is the exit code of a run ended because its desktop
// could not be narrowed (mxcDesktopNotNarrowed) or its box never reported
// its UI limits (mxcAwaitUIClass).
const mxcDesktopEndCode = 125

// mxcRefuse prints a refusal on the terminal and returns the helper's
// refusal status.
func mxcRefuse(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "observer sandbox (mxc-process): "+format+"\n", a...)
	return 125
}

// runMXCHost is the per-run host helper, the PTY child inside the
// terminal's ConPTY.
func runMXCHost(args []string) int {
	h, err := parseMXCHostArgs(args)
	if err != nil {
		return mxcRefuse("%v", err)
	}
	mxcHelperObserverDir = h.observerDir
	plan, err := readMXCPlan(h.plan)
	if err != nil || plan.RunID != h.runID {
		return mxcRefuse("the run's plan cannot be read: %v", err)
	}
	defer func() { _ = removeMXCPlan(h.observerDir, plan.RunID) }()
	rec, err := sandboxrelayd.ReadRun(h.observerDir, h.runID)
	if err != nil {
		return mxcRefuse("the run's record cannot be read: %v", err)
	}
	unhold, herr := sandboxrelayd.HoldRun(h.observerDir, h.runID)
	if herr != nil {
		unhold = func() {}
	}
	defer func() {
		_ = sandboxrelayd.RemoveRun(h.observerDir, h.runID)
		unhold()
	}()
	// Protected paths missing at launch get a placeholder before the box
	// exists (finding F3, the bwrap host helper's rule): the box can then
	// neither create .git/config nor .git/hooks for the next host git.
	created, err := mxcCreatePlaceholders(plan)
	defer mxcRemovePlaceholders(created)
	if err != nil {
		return mxcRefuse("%v", err)
	}
	// A .git the host lacked is not made (B5); one the run made is named
	// when the helper ends.
	defer func() { _, _ = io.WriteString(os.Stderr, mxcAbsentGitNotice(mxcAbsentGitCreated(plan))) }()

	timeout := mxcDefaultProbeTimeout
	if plan.ProbeTimeoutSeconds > 0 {
		timeout = time.Duration(plan.ProbeTimeoutSeconds) * time.Second
	}
	facts, verified, err := mxcGather(true, true, sandboxmxcdll.StageCreate, timeout)
	if err != nil {
		return mxcRefuse("%v", err)
	}
	res := sandboxmxc.Probe(facts, mxcManifest())
	if !res.Verdict.OK() || verified == nil {
		verified.Release()
		return mxcRefuse("%s", res.Verdict.Error())
	}
	defer verified.Release()

	run, err := newMXCHostRun(plan, rec)
	if err != nil {
		return mxcRefuse("%v", err)
	}
	defer run.close()
	run.enumerate = res.EnumeratePaths
	run.console = mxcConsoleRouteFor(mxcConsoleFactsHere())
	execPath, cfg, err := run.document(h, verified)
	defer cfg.remove()
	if err != nil {
		return mxcRefuse("%v", err)
	}
	return run.serveAndRun(h, execPath, cfg)
}

// mxcHostRun is one run's host side: its port, token and box directory.
type mxcHostRun struct {
	plan           mxcPlanFile
	rec            sandboxrelayd.RunRecord
	ln             net.Listener
	port           int
	token          string
	tier           vocab.Tier
	boxDir, tmpDir string
	// log is the helper's side of the run's inner log (host lines).
	log *mxcHostLog
	// enumerate: this host's BaseContainer serves enumerate-only paths, so
	// the document lists the grants' parents (Windows 11 Pro run 4).
	enumerate bool
	// console is how the box's console reaches the user (RERUN2 D1).
	console mxcConsoleRoute
}

// newMXCHostRun mints the token, opens the loopback port and writes the
// box directory: the launch record and the loopback record (read-only in
// the box) and the run's private temp directory.
func newMXCHostRun(plan mxcPlanFile, rec sandboxrelayd.RunRecord) (*mxcHostRun, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("mint the run token: %w", err)
	}
	token, _ := sandboxmxc.EncodeToken(raw[:])
	// No host line, like no box line, ever carries the token.
	registerBoxSecret(token)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen on loopback: %w", err)
	}
	r := &mxcHostRun{plan: plan, rec: rec, ln: ln, port: ln.Addr().(*net.TCPAddr).Port, token: token, tier: vocab.Tier(plan.Tier)}
	r.boxDir = filepath.Join(os.TempDir(), mxcBoxDirPrefix+plan.RunID)
	r.tmpDir = filepath.Join(r.boxDir, "tmp")
	if err := os.Mkdir(r.boxDir, 0o700); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("create the run's box directory: %w", err)
	}
	fail := func(what string, err error) (*mxcHostRun, error) {
		r.close()
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	// Every folder and file of the run's box is the token user's, also when
	// this helper is elevated (ownSandboxRecord, B2).
	if err := ownSandboxRecord(r.boxDir); err != nil {
		return fail("own the run's box directory", err)
	}
	// The owner file the daemon's sweep recognises the folder by (RERUN2
	// D4), written before anything else goes in.
	if err := writeMXCBoxOwner(r.boxDir, plan.RunID, mxcHelperObserverDir); err != nil {
		return fail("write the box folder's owner file", err)
	}
	if err := os.Mkdir(r.tmpDir, 0o700); err != nil {
		return fail("create the run's temp directory", err)
	}
	if err := ownSandboxRecord(r.tmpDir); err != nil {
		return fail("own the run's temp directory", err)
	}
	if r.log, err = openMXCHostLog(r.tmpDir); err != nil {
		return fail("create the run's inner log", err)
	}
	if err := os.Mkdir(mxcLocalAppDataDir(r.boxDir), 0o700); err != nil {
		return fail("create the run's LOCALAPPDATA directory", err)
	}
	if err := ownSandboxRecord(mxcLocalAppDataDir(r.boxDir)); err != nil {
		return fail("own the run's LOCALAPPDATA directory", err)
	}
	if ch := plan.ConfigHome; ch != nil {
		// The tool's run-local config folder (D3), seeded with the plan's
		// non-secret state only.
		dir := mxcConfigHomeDir(r.boxDir)
		if err := os.Mkdir(dir, 0o700); err != nil {
			return fail("create the run's config folder", err)
		}
		if err := ownSandboxRecord(dir); err != nil {
			return fail("own the run's config folder", err)
		}
		f, err := createOwnerOnly(filepath.Join(dir, ch.File))
		if err != nil {
			return fail("create the run's config state file", err)
		}
		_, werr := f.Write(ch.Seed)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return fail("write the run's config state file", werr)
		}
	}
	if err := sandboxrelayd.WriteBoxRecord(r.boxDir, rec); err != nil {
		return fail("write the launch record", err)
	}
	if err := writeMXCLoopback(r.boxDir, mxcLoopback{V: 1, Port: r.port, Token: token}); err != nil {
		return fail("write the loopback record", err)
	}
	return r, nil
}

// close releases the port and removes the box directory.
func (r *mxcHostRun) close() {
	_ = r.ln.Close()
	r.log.close()
	_ = os.RemoveAll(r.boxDir)
}

// document composes the run's config document, has MXC's own probe
// validate it through the C ABI (the exact policy must choose the PSEC tier
// without changing host ACLs, and a plan that hides a path needs a
// BaseContainer that can deny paths, finding F4), then unloads the library
// (the held files stay held until the helper exits) and writes the
// document to its owner-only config file for wxc-exec (finding F2).
func (r *mxcHostRun) document(h mxcHostArgs, verified *sandboxmxcdll.Verified) (string, *mxcConfigFile, error) {
	inner, err := mxcInnerLaunch(h.inner)
	if err != nil {
		return "", nil, err
	}
	env := mxcWithConfigHome(mxcBoxEnv(os.Environ(), r.boxDir, r.tmpDir, r.tier, r.port, r.token, r.plan.TempDirEnv), r.plan.ConfigHome, r.boxDir)
	env = append(env, mxcConsoleEnv+"="+string(r.console))
	doc, err := mxcRunDocument(r.plan, r.boxDir, r.tmpDir, inner, env, r.port, r.enumerate)
	if err != nil {
		return "", nil, fmt.Errorf("the run's policy: %w", err)
	}
	b, err := doc.Encode()
	if err != nil {
		return "", nil, err
	}
	out, err := verified.Library.ProbeRequest(b)
	if err != nil {
		return "", nil, fmt.Errorf("MXC refused the run's policy: %w", err)
	}
	po, err := sandboxmxc.ParseProbeOutput(out)
	if err != nil {
		return "", nil, fmt.Errorf("MXC's answer for the run's policy: %w", err)
	}
	if v := sandboxmxc.CheckRunPolicy(doc, po); !v.OK() {
		return "", nil, v
	}
	_ = verified.Library.Close()
	verified.Library = nil
	cfg, err := writeMXCConfig(h.observerDir, r.plan.RunID, b)
	if err != nil {
		return "", nil, err
	}
	return verified.Path(sandboxmxc.FileExec), cfg, nil
}

// serveAndRun opens the OOB uplink, serves the run's port (relay hop to
// the daemon over its named pipe, model proxy, gateway, box OOB) and runs
// wxc-exec as a console client of the terminal's ConPTY. The config file
// is removed as soon as wxc-exec has read it: at the box's first
// connection to the run's port, after mxcConfigGrace, or when wxc-exec
// exits, whichever comes first.
func (r *mxcHostRun) serveAndRun(h mxcHostArgs, execPath string, cfg *mxcConfigFile) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var up *mxcOOBUplink
	if hello, ok := mxcHelloFromEnv(os.Getenv); ok {
		if ep, err := mxcOOBEndpoint(h.observerDir, h.runID); err == nil {
			// Bounded by the Windows first-hook floor, as the box hook's
			// dial is (SBX-P6 audit info 9).
			if c, err := localipc.DefaultTransport().Dial(ctx, ep, integration.WindowsFirstHookFloor); err == nil {
				up = newMXCOOBUplink(c, hello, time.Now().UnixNano())
			}
		}
	}
	gw, err := mxcGatewayFor(r.plan, r.tier)
	if err != nil {
		return mxcRefuse("%v", err)
	}
	// The helper's stderr is the tool's screen: refusals go to the run's
	// inner log, and the user sees one plain line per host (P-111) only
	// until the tool starts. While the tool owns the screen nothing is
	// printed there (Windows 11 Pro run 4, N2: the line drew over Claude
	// Code's trust dialog); the count goes to the run's status over the OOB
	// uplink, and one summary line follows the tool's exit.
	notices := sandboxnet.NewTerminalNotices(os.Stderr)
	notices.OnHeld(up.egressRefused)
	if gw != nil {
		gw.Logger = sandboxnet.RefusalLoggerTo(r.log.line, notices)
	}
	fw := mxcHelperForwarder(ctx, r.rec, h.observerDir, relayHookProbe(r.rec), 0)
	srv := &mxcPort{
		Token: r.token, Tier: r.tier, Gateway: gw,
		ProxyAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(r.plan.ProxyPort)),
		Relay:     fw.ServeConn,
		OOB:       func(_ context.Context, c net.Conn) { mxcForwardBoxOOB(c, r.token, up) },
		// Every refusal and every stream the port closes unserved goes to
		// the run's inner log as a host line (Windows 11 Pro run 3).
		Log: r.log.line,
	}
	// The box's container identity: MXC 1.0.1 names the AppContainer itself
	// and returns neither its name nor its SID, so the helper reads the SID
	// from the token of the box process under the wxc-exec it starts below
	// and answers it on the run's port, where box detection compares its
	// own token against it (Windows 11 Pro rerun 2026-10-22).
	ident := newMXCIdentityLatch()
	srv.Identity = func(ctx context.Context) sandboxmxc.BoxIdentity { return mxcIdentityAnswer(ctx, r.plan.RunID, ident) }
	// The box's report of its UI limits (WINFIX4 audit finding 4): the
	// first one counts.
	uiClass := newMXCUIClassLatch()
	srv.UIClass = uiClass.set
	ln := mxcOnFirstAccept(r.ln, cfg.remove)
	go func() { _ = srv.Serve(ctx, ln) }()

	// Ctrl-C and Ctrl-Break are the agent's: the helper ignores them so the
	// ConPTY's console event reaches wxc-exec and the container.
	signal.Ignore(os.Interrupt)
	// The box gets a desktop of its own (D1, sandboxmxc/ui.go): the run's
	// document keeps Win32k on so user32 initialises, and wxc-exec, started
	// on this desktop, starts the box on it, never on the interactive
	// desktop. A desktop that cannot be made refuses the run.
	// The name carries a random nonce (WINFIX2 audit finding 2).
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		up.end(126, time.Now().UnixNano())
		return mxcRefuse("the run's desktop name cannot be drawn (%v)", err)
	}
	// On the logon session's alternate window station, never WinSta0 (RERUN2
	// D2): from WinSta0 a box could open WinSta0\Default, move a thread
	// there, see the foreground window and copy the screen.
	desk, err := sandboxmxcdll.CreateRunStation(sandboxmxc.DesktopName(r.plan.RunID, nonce))
	if err != nil {
		up.end(126, time.Now().UnixNano())
		return mxcRefuse("the run's own desktop on a window station other than the user's cannot be created (%v); the box is never started on the interactive window station", err)
	}
	defer desk.Close()
	// If this run created the alternate station's box entry (it had none of
	// its own), remove exactly that entry at run end when no other Observer
	// run is live on this node (WINFIX4 audit finding 3); a station the
	// browsers' sandboxes already opened to AppContainers is left untouched.
	defer desk.ReleaseStationEntry(func() bool { return mxcOtherRunLive(h.observerDir, r.plan.RunID) })
	r.log.line("box desktop: " + desk.Path + " (this run only, random name, on the logon session's alternate window station, never WinSta0; narrowed to the box's SID once it is read, else the run is ended; the pre-narrow window is the identity watch's first poll, " + mxcIdentityPoll.String() + ")")
	// The box writes to the handles wxc-exec inherits (RERUN2 D1): on the
	// daemon's or the launcher's pseudo console they reach the terminal.
	r.log.line("box console: " + string(r.console))
	spec := sandboxmxcdll.StartSpec{
		Exe: execPath, Args: mxcExecArgs(cfg.path), Dir: r.plan.Workspace, Env: mxcExecEnv(os.Environ()), Desktop: desk.Path,
	}
	spec.Stdin, spec.Stdout, spec.Stderr = mxcStartHandles()
	started, err := sandboxmxcdll.Start(spec)
	if err != nil {
		up.end(126, time.Now().UnixNano())
		return mxcRefuse("start wxc-exec: %v", err)
	}
	notices.ToolStarted()
	grace := time.AfterFunc(mxcConfigGrace, cfg.remove)
	watchCtx, stopWatch := context.WithCancel(ctx)
	go mxcWatchBoxIdentity(watchCtx, ident, mxcBoxSIDScanner(started.PID, mxcSameImage(h.inner[0])), mxcIdentityPoll, mxcIdentityLimit)
	// Once the box's SID is read, the desktop admits that SID only; a SID
	// not read in time or a narrowing that fails ends the run (fail closed,
	// WINFIX2 audit finding 2).
	var ended atomic.Pointer[string]
	go func() {
		state, reason := mxcNarrowDesktop(watchCtx, ident.wait, desk.Narrow)
		switch {
		case reason != "":
			ended.CompareAndSwap(nil, &reason)
			r.log.line("box desktop: " + reason)
			_ = started.Kill(mxcDesktopEndCode)
		case state == mxcDesktopNarrowed:
			r.log.line("box desktop: narrowed to the box's SID")
		}
	}()
	// The UI limits are never assumed: the helper's job carries none (MXC
	// cannot start a box under a job with UI limits), so a box whose first
	// Observer process does not report the class it read back is ended.
	go func() {
		line, reason := mxcAwaitUIClass(watchCtx, uiClass.wait, mxcUIClassLimit)
		switch {
		case reason != "":
			ended.CompareAndSwap(nil, &reason)
			r.log.line("box UI limits: " + reason)
			_ = started.Kill(mxcDesktopEndCode)
		case line != "":
			r.log.line(line)
		}
	}()
	code, err := started.Wait()
	stopWatch()
	if err != nil {
		code = 126
	}
	if n := notices.Held(); n > 0 {
		r.log.line(fmt.Sprintf("egress: %d connection(s) were refused while the tool ran; kept off its screen, one summary line after it exited", n))
	}
	notices.Finish()
	if reason := ended.Load(); reason != nil {
		code = mxcDesktopEndCode
		fmt.Fprintf(os.Stderr, "\r\nobserver sandbox (mxc-process): %s\r\n", *reason)
	}
	grace.Stop()
	cfg.remove()
	up.end(code, time.Now().UnixNano())
	if code != 0 {
		// Never a silent non-zero exit (Windows 11 Pro live run
		// 2026-10-22): what the box's observer processes logged, or one
		// line saying they logged nothing.
		mxcReportInnerLog(os.Stderr, mxcInnerLogPath(r.tmpDir), code)
	}
	return code
}

// mxcBoxSIDScanner is one look at the processes under the run's wxc-exec
// (rootPID, whose handle the helper holds while it runs) for the box's
// container SID. The root's creation time is fixed at the first look, so a
// later look at a reused PID (wxc-exec gone) is refused, never walked.
func mxcBoxSIDScanner(rootPID uint32, isImage func(string) bool) func() (string, error) {
	var created int64
	return func() (string, error) {
		root, procs, err := sandboxmxcdll.ProcessTree(rootPID)
		if err != nil {
			return "", err
		}
		if created == 0 {
			created = root.Created
		} else if root.Created != created {
			return "", fmt.Errorf("wxc-exec (pid %d) is no longer running", rootPID)
		}
		return sandboxmxc.BoxSID(root, procs, isImage)
	}
}

// createOwnerOnly creates path fresh, readable by this user only (the 0600
// equivalent the run's config file needs, finding F2). The protected-DACL
// create moved to fsatomic.CreateOwnerOnly, the one owner (R-160).
func createOwnerOnly(path string) (*os.File, error) { return fsatomic.CreateOwnerOnly(path) }

// mxcConfigGrace bounds how long the run's config file stays on disk after
// wxc-exec started, when the box has not yet reached the run's port.
const mxcConfigGrace = 30 * time.Second

// mxcIdentityPoll and mxcIdentityLimit pace the host's search for the box
// process after wxc-exec started.
const (
	mxcIdentityPoll  = 25 * time.Millisecond
	mxcIdentityLimit = 30 * time.Second
)

// mxcOtherRunLive reports whether an Observer MXC run other than self is
// still live on this node (its helper holds its liveness lock), so the
// shared station's box entry is kept while another run needs it (WINFIX4
// audit finding 3).
func mxcOtherRunLive(observerDir, self string) bool {
	for _, id := range sandboxrelayd.LiveRunIDs(observerDir) {
		if id != self {
			return true
		}
	}
	return false
}

// mxcDriverSelectedInBox reports whether the user's config selects the mxc
// driver (the box reads the daemon's config file read-only; governance,
// which needs the node database the box cannot reach, is not applied).
func mxcDriverSelectedInBox() bool {
	cfg, err := config.Load(config.LoadOptions{GovernanceSidecar: config.NoGovernanceSidecar})
	if err != nil {
		return false
	}
	return sandboxDriverSelected(componentstate.Resolve(cfg.Components, nil), mxcComponent)
}

// mxcUIClassLimit bounds how long the host helper waits, after wxc-exec
// started, for the box's UI class report before it ends the run (WINFIX4
// audit finding 4). Read only here, so it lives in the Windows file.
const mxcUIClassLimit = 60 * time.Second
