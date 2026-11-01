//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termoob"
)

// terminal_sandbox_mxc_run.go is the OS-neutral half of the MXC host
// helper (lane SBX-P6): the box environment, the run's config document,
// the proxy flag lookup and the OOB uplink. The Windows file does the I/O
// around it; everything here is tested on any host.

// mxcMaxCommandLine bounds the box process's command line below
// CreateProcess's 32767-character limit (the config document itself
// travels as a file, finding F2).
const mxcMaxCommandLine = 32000

// mxcProxyURLEnv carries the run's token-scoped proxy base URL to the
// inner launcher in the box's environment, never on its command line
// (finding F2): the launcher inserts its own proxy flag in memory
// (mxcBoxArgv) and drops the variable.
const mxcProxyURLEnv = "OBSERVER_SANDBOX_PROXY_URL"

// mxcBoxDirPrefix names a run's box directory (mxcBoxDirPrefix + run id,
// under the helper's temp directory).
const mxcBoxDirPrefix = "observer-sbx-"

// mxcProxyFlags are the launcher flags that set the proxy base URL, in the
// order the helper looks for them on the inner launcher verb.
var mxcProxyFlags = []string{"proxy", "proxy-url"}

// mxcProxyFlagFor returns the inner launcher verb's proxy flag, read from
// the command tree (a capability of the verb, never its name), or "".
func mxcProxyFlagFor(verb string) string {
	root := newRootCmd()
	cmd, _, err := root.Find([]string{verb})
	if err != nil || cmd == nil || cmd == root {
		return ""
	}
	for _, name := range mxcProxyFlags {
		if cmd.Flags().Lookup(name) != nil {
			return name
		}
	}
	return ""
}

// mxcWithProxyFlag inserts `--<flag> <url>` after the launcher verb. An
// argv that already names a proxy is refused: the box's base URL is the
// helper's to set.
func mxcWithProxyFlag(argv []string, flag, baseURL string) ([]string, error) {
	if len(argv) < 2 {
		return nil, errors.New("the inner launch has no launcher verb")
	}
	if flag == "" {
		return nil, fmt.Errorf("the %s launcher has no proxy flag, and the Windows sandbox reaches the model proxy only through its token-scoped base URL", argv[1])
	}
	for _, a := range argv[2:] {
		if a == "--" {
			break
		}
		for _, f := range mxcProxyFlags {
			if a == "--"+f || strings.HasPrefix(a, "--"+f+"=") {
				return nil, errors.New("the inner launch already names a proxy")
			}
		}
	}
	out := make([]string, 0, len(argv)+2)
	out = append(out, argv[0], argv[1], "--"+flag, baseURL)
	return append(out, argv[2:]...), nil
}

// mxcDroppedEnv are host variables the box never inherits: the host's own
// proxy settings and temp directories (replaced with the run's), MXC's own
// configuration knobs, and the OBSERVER_PROXY_PORT override (the box has
// no route to the daemon's port).
var mxcDroppedEnv = map[string]bool{
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "ALL_PROXY": true, "NO_PROXY": true,
	"TEMP": true, "TMP": true, "OBSERVER_PROXY_PORT": true,
}

// mxcBoxEnv is the inner launch's environment: the helper's own through the
// box allow-list (sandboxBoxEnv, WINFIX2 R-167: before, the helper's whole
// environment minus a short deny-list crossed) minus the daemon's internal
// variables, the dropped ones and Windows' hidden "=" entries, plus the
// run's markers, its box directory, its private temp directory, its inner
// log and the tier's network variables. Last, every name in tempEnv (the
// tool's own temp-dir variables, sandboxenv.TempDirEnv) is set to the
// private temp directory, replacing any value the user passed (D-UC1).
func mxcBoxEnv(base []string, boxDir, tmpDir string, tier vocab.Tier, port int, token string, tempEnv []string) []string {
	base = sandboxBoxEnv("windows", base)
	out := make([]string, 0, len(base)+12)
	daemonChild := false
	for _, kv := range base {
		// Windows' hidden "=C:" and "=ExitCode" entries mean nothing in a
		// box and are not KEY=VALUE (Windows 11 Pro live run 2026-10-22:
		// the policy builder refused every launch from cmd or PowerShell).
		if sandboxmxc.HiddenEnvEntry(kv) {
			continue
		}
		k, _, _ := strings.Cut(kv, "=")
		ku := strings.ToUpper(k)
		if ku == strings.ToUpper(envDaemonChild) {
			daemonChild = true
		}
		if isInternalChildEnv(kv) || mxcDroppedEnv[ku] || strings.HasPrefix(ku, "MXC_") || ku == mxcBoxDirEnv || ku == mxcProxyURLEnv || ku == sandboxInnerLogEnv || ku == sandbox.EnvEgress {
			continue
		}
		out = append(out, kv)
	}
	if daemonChild {
		out = append(out, envDaemonChild+"=1")
	}
	out = append(out,
		sandboxEnvMarker+"=1",
		sandbox.EnvEgress+"="+string(tier),
		mxcBoxDirEnv+"="+boxDir,
		"OBSERVER_OOB_BOX=1",
		"TEMP="+tmpDir, "TMP="+tmpDir,
		sandboxInnerLogEnv+"="+mxcInnerLogPath(tmpDir),
		mxcProxyURLEnv+"="+sandboxmxc.BaseURL(port, token),
	)
	return sandboxenv.WithTempDir(append(out, mxcInnerEnv(tier, port, token)...), tempEnv, tmpDir)
}

// mxcInnerLaunch checks the inner launch the helper hands the box: its
// launcher verb has a proxy flag and the argv names no proxy of its own.
// The argv is returned unchanged: the token-scoped base URL reaches the
// launcher through mxcProxyURLEnv, never through the box process's
// command line (finding F2).
func mxcInnerLaunch(argv []string) ([]string, error) {
	if len(argv) < 2 {
		return nil, errors.New("the inner launch has no launcher verb")
	}
	if _, err := mxcWithProxyFlag(argv, mxcProxyFlagFor(argv[1]), "check"); err != nil {
		return nil, err
	}
	return append([]string(nil), argv...), nil
}

// mxcBoxArgv is the inner launcher's own argv inside the box with its proxy
// flag inserted (in memory only; the OS command line is untouched). An
// empty url, a verb without a proxy flag or an argv that already names a
// proxy leave args as they are.
func mxcBoxArgv(args []string, url string) []string {
	if url == "" || len(args) < 2 {
		return args
	}
	out, err := mxcWithProxyFlag(args, mxcProxyFlagFor(args[1]), url)
	if err != nil {
		return args
	}
	return out
}

// mxcExecEnv is wxc-exec's own environment: what Windows itself needs and
// nothing of the user's (no keys, no proxy, no MXC knobs).
func mxcExecEnv(base []string) []string {
	keep := map[string]bool{
		"SYSTEMROOT": true, "SYSTEMDRIVE": true, "WINDIR": true, "COMSPEC": true, "PATHEXT": true,
		"USERPROFILE": true, "LOCALAPPDATA": true, "APPDATA": true, "USERNAME": true, "USERDOMAIN": true,
		"PROGRAMDATA": true, "PROGRAMFILES": true, "NUMBER_OF_PROCESSORS": true, "PROCESSOR_ARCHITECTURE": true,
		"TEMP": true, "TMP": true, "OS": true,
	}
	var out []string
	sysRoot := `C:\Windows`
	for _, kv := range base {
		if sandboxmxc.HiddenEnvEntry(kv) {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		if keep[strings.ToUpper(k)] {
			out = append(out, kv)
		}
		if strings.EqualFold(k, "SystemRoot") && v != "" {
			sysRoot = v
		}
	}
	return append(out, "PATH="+filepath.Join(sysRoot, "System32"))
}

// mxcRunDocument is the run's config document from the plan, the box
// directory and the inner launch, refused when the box process's command
// line would pass CreateProcess's limit. enumerate (the host's
// BaseContainer serves enumerate-only paths) lists the grants' parent
// directories enumerate-only, which a runtime that resolves a granted path
// component by component needs (Windows 11 Pro run 4: cmd.exe could not run
// the read-only claude.cmd).
func mxcRunDocument(plan mxcPlanFile, boxDir, tmpDir string, inner, env []string, port int, enumerate bool) (sandboxmxc.Document, error) {
	lad := mxcLocalAppDataDir(boxDir)
	rw := append(append([]string(nil), plan.ReadWrite...), tmpDir, lad)
	if plan.ConfigHome != nil {
		rw = append(rw, mxcConfigHomeDir(boxDir))
	}
	ro := append(append([]string(nil), plan.ReadOnly...), boxDir)
	doc, err := sandboxmxc.BuildDocument(sandboxmxc.RunPlan{
		RunID: plan.RunID, Argv: inner, Cwd: plan.Workspace, Env: env,
		ReadWrite: rw, ReadOnly: ro, Denied: plan.Denied, ProxyPort: port,
		EnumerateAncestors: enumerate, NeedsWin32k: plan.NeedsWin32k,
		// Windows needs both present (MXC 1.0.1, policy_validation): the
		// host's own SYSTEMROOT, and LOCALAPPDATA in the run's box
		// directory, never the host user's.
		SystemRoot: mxcSystemRootOf(env), LocalAppData: lad,
	})
	if err != nil {
		return sandboxmxc.Document{}, err
	}
	if n := len(doc.Process.CommandLine); n > mxcMaxCommandLine {
		return sandboxmxc.Document{}, fmt.Errorf("the inner launch's command line is %d characters, above CreateProcess's limit", n)
	}
	return doc, nil
}

// mxcLocalAppDataDir is the run's private LOCALAPPDATA: a directory inside
// its box directory, writable by the box (newMXCHostRun creates it).
func mxcLocalAppDataDir(boxDir string) string {
	return strings.TrimRight(boxDir, `\/`) + `\localappdata`
}

// mxcBoxTempEnv is what a recognised box process changes in its own
// environment before it starts the tool (Windows 11 Pro rerun 2026-10-25,
// D1). Windows points TEMP, TMP and LOCALAPPDATA of an AppContainer process
// at <LOCALAPPDATA>\Packages\<profile>\AC[\Temp] under the LOCALAPPDATA the
// run's document names (the run's private box directory), and nothing
// creates those folders, so a tool that writes a temp file failed ("The
// system cannot find the path specified"). TEMP and TMP are pointed at the
// run's own temp directory (the inner log's directory, which the helper made
// and the box may write), and LOCALAPPDATA is created when it lies inside
// the run's box directory (which the box may write). Paths outside the run
// are never created. set lists the variables to set, mkdir the directories
// to create.
func mxcBoxTempEnv(getenv func(string) string, boxDir string) (set [][2]string, mkdir []string) {
	if log := getenv(sandboxInnerLogEnv); sandboxmxc.LocalWindowsPath(log) {
		if i := strings.LastIndexAny(log, `\/`); i > 2 {
			tmp := log[:i]
			set = append(set, [2]string{"TEMP", tmp}, [2]string{"TMP", tmp})
		}
	}
	lad := getenv(sandboxmxc.EnvLocalAppData)
	if sandboxmxc.LocalWindowsPath(lad) && sandboxmxc.LocalWindowsPath(boxDir) {
		root := strings.ToLower(strings.ReplaceAll(mxcLocalAppDataDir(boxDir), "/", `\`)) + `\`
		if strings.HasPrefix(strings.ToLower(strings.ReplaceAll(lad, "/", `\`))+`\`, root) {
			mkdir = append(mkdir, lad)
		}
	}
	return set, mkdir
}

// mxcInnerLogName is the run's inner log in its private temp directory:
// every observer process in the box appends one line per failure and box
// detection's outcome to it (sandboxInnerLogEnv, box_inner_log.go), and the
// helper prints its tail when the box exits non-zero, so an inner failure
// is never silent (Windows 11 Pro live run 2026-10-22).
const mxcInnerLogName = "observer-inner.log"

// mxcInnerLogTail bounds the bytes the helper reads from the end of the
// inner log, and mxcInnerLogLines the lines it prints. Only whole lines are
// printed: a partial first line of the read is dropped, never cut mid-value
// (Windows 11 Pro rerun 2026-10-22, where a SID was cut with "...").
const (
	mxcInnerLogTail  = 16 << 10
	mxcInnerLogLines = 40
)

// mxcInnerLogPath is the run's inner log.
func mxcInnerLogPath(tmpDir string) string { return filepath.Join(tmpDir, mxcInnerLogName) }

// mxcReadInnerLog reads the last max bytes of the box's inner log, and
// whether the read starts past the log's first byte (so its first line may
// be partial). The box can write the run's temp directory, so the log is
// read only when it is a regular file and the very file that was opened: a
// link there must never make the helper read, and print, a host file the
// box cannot read itself.
func mxcReadInnerLog(path string, max int64) ([]byte, bool, error) {
	lfi, err := os.Lstat(path)
	if err != nil {
		return nil, false, err
	}
	if !lfi.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path) //nolint:gosec // G304: the run's own inner log, checked to be the regular file just stat'ed
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if !fi.Mode().IsRegular() || !os.SameFile(lfi, fi) {
		return nil, false, fmt.Errorf("%s changed while it was opened", path)
	}
	off := fi.Size() - max
	if off < 0 {
		off = 0
	}
	buf := make([]byte, fi.Size()-off)
	n, err := f.ReadAt(buf, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	return buf[:n], off > 0, nil
}

// mxcWholeLines are the last maxLines whole lines of b, and how many
// earlier lines were left out: when cut (b starts mid-log) the first line
// is partial and dropped, so no printed line is ever cut.
func mxcWholeLines(b []byte, cut bool, maxLines int) ([]string, int) {
	s := strings.TrimRight(string(b), "\r\n")
	if cut {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			return nil, 1
		}
		s = s[i+1:]
	}
	if strings.TrimSpace(s) == "" {
		return nil, 0
	}
	lines := strings.Split(s, "\n")
	omitted := 0
	if len(lines) > maxLines {
		omitted = len(lines) - maxLines
		lines = lines[omitted:]
	}
	if cut {
		omitted++
	}
	return lines, omitted
}

// mxcReportInnerLog prints, after the box exited non-zero, what its
// observer processes logged (the tail, control characters removed), or one
// line saying they logged nothing, which, when the tool did not start
// either, points at the box's environment.
func mxcReportInnerLog(w io.Writer, path string, exit int) {
	code := boxExitCodeText(exit)
	b, cut, err := mxcReadInnerLog(path, mxcInnerLogTail)
	switch {
	case errors.Is(err, fs.ErrNotExist) || (err == nil && len(bytes.TrimSpace(b)) == 0):
		fmt.Fprintf(w, "observer sandbox (mxc-process): the box exited with code %s and no Observer process in it logged anything (%s); if the tool did not start, the box may not have received the run's environment\n", code, path)
		return
	case err != nil:
		fmt.Fprintf(w, "observer sandbox (mxc-process): the box exited with code %s; its Observer log was not read: %v\n", code, err)
		return
	}
	fmt.Fprintf(w, "observer sandbox (mxc-process): the box exited with code %s; what Observer logged inside it (%s):\n", code, path)
	lines, omitted := mxcWholeLines(b, cut, mxcInnerLogLines)
	if omitted > 0 {
		fmt.Fprintf(w, "  (%d earlier line(s) not shown)\n", omitted)
	}
	for _, line := range lines {
		line = strings.Map(func(r rune) rune {
			switch {
			case r == '\t':
				return ' '
			case r < 0x20 || r == 0x7f:
				return -1
			}
			return r
		}, line)
		fmt.Fprintf(w, "  %s\n", line)
	}
}

// mxcSystemRootOf is the SystemRoot an environment names (Windows keys are
// case-insensitive), or C:\Windows when it names none.
func mxcSystemRootOf(env []string) string {
	for _, kv := range env {
		if sandboxmxc.HiddenEnvEntry(kv) {
			continue
		}
		if k, v, ok := strings.Cut(kv, "="); ok && strings.EqualFold(k, sandboxmxc.EnvSystemRoot) && v != "" {
			return v
		}
	}
	return `C:\Windows`
}

// mxcExecArgs is wxc-exec's argument list: the path of the run's config
// file and nothing else (finding F2). The document, which carries the
// box's environment (provider keys from the user's environment and the
// run's token among them), never travels on a command line, where any
// same-user process, process-creation auditing and Observer's own process
// reader would see it.
func mxcExecArgs(configPath string) []string {
	return []string{"--config", configPath}
}

// mxcConfigPath is a run's config file, under the driver's node-local
// directory (never granted to any box).
func mxcConfigPath(observerDir, runID string) string {
	return filepath.Join(mxcStateDir(observerDir), "run", runID+".json")
}

// mxcConfigFile is a run's config document on disk for wxc-exec. remove is
// safe to call many times and on a nil file.
type mxcConfigFile struct {
	path string
	once sync.Once
}

// remove deletes the file (once).
func (c *mxcConfigFile) remove() {
	if c == nil {
		return
	}
	c.once.Do(func() { _ = os.Remove(c.path) }) //nolint:gosec // G703: c.path is the run's own config file, written by writeMXCConfig under the driver's node-local dir
}

// writeMXCConfig writes the document to a fresh owner-only file
// (createOwnerOnly: a protected DACL granting this user and SYSTEM on
// Windows, 0600 elsewhere).
func writeMXCConfig(observerDir, runID string, b []byte) (*mxcConfigFile, error) {
	p := mxcConfigPath(observerDir, runID)
	if err := mkdirSandboxOwned(filepath.Dir(p)); err != nil {
		return nil, fmt.Errorf("the run's config directory: %w", err)
	}
	f, err := createOwnerOnly(p)
	if err != nil {
		return nil, fmt.Errorf("the run's config file: %w", err)
	}
	_, werr := f.Write(b)
	if err := errors.Join(werr, f.Close(), ownSandboxRecord(p)); err != nil {
		_ = os.Remove(p)
		return nil, fmt.Errorf("write the run's config file: %w", err)
	}
	return &mxcConfigFile{path: p}, nil
}

// mxcOnFirstAccept calls f once, at the first connection ln accepts.
func mxcOnFirstAccept(ln net.Listener, f func()) net.Listener {
	return &firstAcceptListener{Listener: ln, f: f}
}

type firstAcceptListener struct {
	net.Listener
	once sync.Once
	f    func()
}

func (l *firstAcceptListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.once.Do(l.f)
	}
	return c, err
}

// mxcStageLastRow is the probe ladder row a live-check stage ends at
// (finding L3): the version stage is judged through the version row, the
// request stage through the request probe, every other stage in full.
func mxcStageLastRow(stage string) string {
	switch stage {
	case "version":
		return "version"
	case "request":
		return "request_probe"
	}
	return ""
}

// mxcBoxFacts are what a process reads to decide whether it runs inside
// one of this driver's boxes (audit finding F1).
type mxcBoxFacts struct {
	// AppContainer: the process holds an AppContainer token; TokenSID is
	// its container's SID.
	AppContainer bool
	TokenSID     string
	// BoxDir is the box directory the environment names; RecordRunID the
	// run id of the launch record found there ("" when absent or refused).
	BoxDir      string
	RecordRunID string
	// Identity is the host helper's answer on the run's port: the SID it
	// read from the token of the box process under its own wxc-exec (nil
	// when it could not be asked; IdentityErr says why). MXC 1.0.1 names
	// the AppContainer itself, so no name this process knows derives it
	// (sandboxmxc/identity.go).
	Identity    *sandboxmxc.BoxIdentity
	IdentityErr error
	// NameSID derives an AppContainer profile's SID from its name. It only
	// enriches a mismatch's reason (would a profile named after the run's
	// containerId have matched?) and never recognises a box.
	NameSID func(name string) (string, error)
	// DriverSelected reports whether the mxc driver is selected in the
	// config this process reads.
	DriverSelected func() bool
}

// mxcBoxRunID is the run id of this driver's box the process runs in, or
// "": the token must be an AppContainer token whose SID is the SID the
// run's host helper read from that run's box process (mxcIdentityMismatch),
// the run id named by the launch record (or, when the record is missing or
// refused, by the box directory's own name, so a faulted record still
// blocks gate events), and the driver selected. Any other AppContainer is
// not an Observer box.
func mxcBoxRunID(f mxcBoxFacts) string {
	id, _ := mxcBoxRunIDWhy(f)
	return id
}

// mxcBoxRunIDWhy is mxcBoxRunID with the reason it declines ("" when it
// recognises the box), which box detection records (Windows 11 Pro live
// run 2026-10-22: an unrecognised box failed every launch check silently).
func mxcBoxRunIDWhy(f mxcBoxFacts) (string, string) {
	switch {
	case !f.AppContainer:
		return "", "this process holds no AppContainer token"
	case f.TokenSID == "":
		return "", "this process's AppContainer SID cannot be read"
	case !filepath.IsAbs(f.BoxDir):
		return "", fmt.Sprintf("the box directory %s=%q is not an absolute path", mxcBoxDirEnv, f.BoxDir)
	}
	id := f.RecordRunID
	if id == "" {
		base := filepath.Base(f.BoxDir)
		if !strings.HasPrefix(base, mxcBoxDirPrefix) {
			return "", "the box directory names no run and holds no readable launch record"
		}
		id = strings.TrimPrefix(base, mxcBoxDirPrefix)
	}
	if !sandboxrelay.ValidRunID(id) {
		return "", "the run id the box names is not valid"
	}
	if why := mxcIdentityMismatch(id, f); why != "" {
		return "", why
	}
	if f.DriverSelected == nil || !f.DriverSelected() {
		return "", "the Windows sandbox driver (" + mxcComponent + ") is not selected in the config this process reads"
	}
	return id, ""
}

// mxcIdentityMismatch is box detection's binding: "" when this process's
// token SID is the SID the host helper read from run id's box process, else
// why not. The answer is the host's own reading (sandboxmxc.BoxSID over the
// processes under the wxc-exec it started), so a process outside the box
// can learn it but never match it: its token's AppContainer SID is not
// that one, and a token's SID cannot be chosen. A mismatch names the
// containerId the document asked for and both SIDs (plus, when it can be
// derived, the SID a profile of that name would have).
func mxcIdentityMismatch(id string, f mxcBoxFacts) string {
	container := sandboxmxc.ContainerName(id)
	in := f.Identity
	switch {
	case in == nil:
		why := "no answer"
		if f.IdentityErr != nil {
			why = f.IdentityErr.Error()
		}
		return fmt.Sprintf("the run's host helper could not be asked which container run %s's box runs in: %s", id, why)
	case in.V != sandboxmxc.BoxIdentityVersion:
		return fmt.Sprintf("the host helper's identity answer has version %d, not %d", in.V, sandboxmxc.BoxIdentityVersion)
	case in.RunID != id:
		return fmt.Sprintf("the host helper answers for run %q, not for run %s the box names", in.RunID, id)
	case in.SID == "":
		why := in.Error
		if why == "" {
			why = "it named no SID"
		}
		return fmt.Sprintf("the host helper could not read the container of run %s's box (containerId %s): %s", id, container, why)
	case !strings.EqualFold(in.SID, f.TokenSID):
		return fmt.Sprintf("this process's AppContainer SID %s is not the SID %s the host helper read from run %s's box process (containerId %s%s)", f.TokenSID, in.SID, id, container, mxcNameSIDNote(container, f.NameSID))
	}
	return ""
}

// mxcNameSIDNote says which SID an AppContainer profile named container
// would have ("" when it cannot be derived).
func mxcNameSIDNote(container string, derive func(string) (string, error)) string {
	if derive == nil {
		return ""
	}
	sid, err := derive(container)
	if err != nil || sid == "" {
		return ""
	}
	return fmt.Sprintf("; a profile named %s would have SID %s", container, sid)
}

// mxcIdentityLatch holds the box's container SID once the host helper read
// it (or why it could not): set once, waited on by the run's port.
type mxcIdentityLatch struct {
	once sync.Once
	done chan struct{}
	sid  string
	err  error

	mu   sync.Mutex
	last error // the latest not-yet look, for a wait that times out
}

// note records the latest look that found no box yet.
func (l *mxcIdentityLatch) note(err error) {
	l.mu.Lock()
	l.last = err
	l.mu.Unlock()
}

// newMXCIdentityLatch is an unset latch.
func newMXCIdentityLatch() *mxcIdentityLatch { return &mxcIdentityLatch{done: make(chan struct{})} }

// set latches the outcome; later calls change nothing.
func (l *mxcIdentityLatch) set(sid string, err error) {
	l.once.Do(func() {
		l.sid, l.err = sid, err
		close(l.done)
	})
}

// wait is the latched outcome, or ctx's error when it is not set in time.
func (l *mxcIdentityLatch) wait(ctx context.Context) (string, error) {
	select {
	case <-l.done:
		return l.sid, l.err
	case <-ctx.Done():
		l.mu.Lock()
		last := l.last
		l.mu.Unlock()
		if last != nil {
			return "", fmt.Errorf("the box's container is not known yet: %w (last look: %w)", ctx.Err(), last)
		}
		return "", fmt.Errorf("the box's container is not known yet: %w", ctx.Err())
	}
}

// mxcUnrecognisedRefusal is why a process the run's environment points at a
// box, but that does not recognise the box, runs nothing: it exits 125
// before any command, the tool included, starts (WINFIX4 audit finding 4;
// before, only the launcher's launch gate stopped the tool, with exit 1, and
// nothing put the process in the UI-limited job).
func mxcUnrecognisedRefusal(why string) string {
	return "this process did not recognise the sandbox it runs in (" + why + "); the box's UI limits are not in force, so nothing is started"
}

// mxcBoxUIOutcome is box detection's UI step, after the process entered the
// UI-limited job (sandboxmxcdll.EnterUIRestrictedJob: the class it read back
// on its own job, whether it put itself there, the error): the refusal the
// process exits 125 with ("" when it goes on) and its inner log line. It
// fails closed: an error, a class missing a limit, or a first process whose
// report to the run's host helper fails starts nothing. Only the process
// that entered the job reports (a later Observer process of the box, a
// hook, finds the job in place).
func mxcBoxUIOutcome(class uint32, entered bool, enterErr error, report func(uint32) error) (refusal, line string) {
	want := sandboxmxc.JobUIRestrictions
	switch {
	case enterErr != nil:
		return "the box's UI limits could not be set (" + enterErr.Error() + "); the tool is not started",
			"box UI limits: not set: " + enterErr.Error() + "; nothing more runs in the box"
	case class&want != want:
		why := fmt.Sprintf("the job reads class 0x%X, not 0x%X", class, want)
		return "the box's UI limits are not all in force (" + why + "); the tool is not started",
			"box UI limits: " + why + "; nothing more runs in the box"
	}
	text := fmt.Sprintf("this box process's job carries class 0x%X (%s), read back", class, sandboxmxc.JobUIClassText(class))
	if !entered {
		return "", "box UI limits: " + text + " (the job was already in place)"
	}
	if err := report(class); err != nil {
		return "the box's UI limits could not be reported to the run's host helper (" + err.Error() + "); the tool is not started",
			"box UI limits: " + text + ", but the report to the host helper failed: " + err.Error() + "; nothing more runs in the box"
	}
	return "", "box UI limits: " + text + " and reported to the host helper"
}

// mxcUIClassLatch holds the first UI class the box reported.
type mxcUIClassLatch struct {
	once  sync.Once
	done  chan struct{}
	class uint32
}

// newMXCUIClassLatch is an unset latch.
func newMXCUIClassLatch() *mxcUIClassLatch { return &mxcUIClassLatch{done: make(chan struct{})} }

// set latches the first report; later reports (anything the tool sends with
// the token it can read) change nothing.
func (l *mxcUIClassLatch) set(class uint32) {
	l.once.Do(func() {
		l.class = class
		close(l.done)
	})
}

// wait is the first report, or false when ctx ends first.
func (l *mxcUIClassLatch) wait(ctx context.Context) (uint32, bool) {
	select {
	case <-l.done:
		return l.class, true
	case <-ctx.Done():
		return 0, false
	}
}

// mxcAwaitUIClass is the helper's side of the UI limits (WINFIX4 audit
// finding 4), and it FAILS CLOSED: the helper cannot set the limits itself
// (MXC refuses to create a box under a job carrying them), so it holds the
// run to the box's own report. A box that never reports within limit, or
// reports a class missing a limit, is ended (reason non-empty). runCtx ends
// when the run ends by itself; then nothing is reported. line is the inner
// log line for a report that holds.
func mxcAwaitUIClass(runCtx context.Context, wait func(context.Context) (uint32, bool), limit time.Duration) (line, reason string) {
	ctx, cancel := context.WithTimeout(runCtx, limit)
	defer cancel()
	class, ok := wait(ctx)
	if runCtx.Err() != nil {
		return "", ""
	}
	want := sandboxmxc.JobUIRestrictions
	switch {
	case !ok:
		return "", fmt.Sprintf("ui_limits_not_reported: the box's first Observer process did not report its job's UI limits within %s, so they are not known to be in force; the run is ended", limit)
	case class&want != want:
		return "", fmt.Sprintf("ui_limits_not_reported: the box reported UI limit class 0x%X, not 0x%X; the run is ended", class, want)
	}
	return fmt.Sprintf("box UI limits: the box's first Observer process read class 0x%X (%s) back on its own job before the tool started", class, sandboxmxc.JobUIClassText(class)), ""
}

// The run desktop's narrowing states (WINFIX2 audit finding 2), recorded in
// the run's inner log; a run that is not narrowed is ended, and its terminal
// says why.
const (
	// mxcDesktopNarrowed: the desktop admits the user and the box's SID only.
	mxcDesktopNarrowed = "narrowed"
	// mxcDesktopNotNarrowed is the named reason a run is ended for.
	mxcDesktopNotNarrowed = "desktop_not_narrowed"
	// mxcDesktopRunEnded: the run ended before its box's SID was read, so
	// there was nothing left to narrow.
	mxcDesktopRunEnded = "run_ended"
)

// mxcNarrowDesktop narrows the run's desktop to the box's SID once wait reads
// it, and FAILS CLOSED: until then the desktop admits ALL APPLICATION
// PACKAGES, so a SID that is not read (in time, or at all) or a narrowing
// that fails ends the run (reason non-empty) rather than leaving the desktop
// open for its whole life (WINFIX2 audit finding 2). ctx is the run's watch:
// once it ends the run has ended by itself and nothing is reported.
func mxcNarrowDesktop(ctx context.Context, wait func(context.Context) (string, error), narrow func(string) error) (state, reason string) {
	sid, err := wait(ctx)
	if ctx.Err() != nil {
		return mxcDesktopRunEnded, ""
	}
	if err == nil && sid == "" {
		err = errors.New("no SID")
	}
	if err != nil {
		return mxcDesktopNotNarrowed, fmt.Sprintf("%s: the box's container SID was not read (%v), so the run's desktop could not be closed to other AppContainer processes; the run is ended", mxcDesktopNotNarrowed, err)
	}
	if err := narrow(sid); err != nil {
		return mxcDesktopNotNarrowed, fmt.Sprintf("%s: narrowing the run's desktop to the box's SID failed (%v); the run is ended", mxcDesktopNotNarrowed, err)
	}
	return mxcDesktopNarrowed, ""
}

// mxcWatchBoxIdentity calls scan until it names the box's SID or fails with
// anything but sandboxmxc.ErrBoxNotStarted, ctx ends or limit passes, and
// latches that outcome once (the first sighting is final, so a process
// that appears later cannot change it).
func mxcWatchBoxIdentity(ctx context.Context, l *mxcIdentityLatch, scan func() (string, error), every, limit time.Duration) {
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		sid, err := scan()
		if err == nil || !errors.Is(err, sandboxmxc.ErrBoxNotStarted) {
			l.set(sid, err)
			return
		}
		l.note(err)
		select {
		case <-ctx.Done():
			l.set("", errors.New("the run ended before its box process was found"))
			return
		case <-deadline.C:
			l.set("", fmt.Errorf("%w (searched for %s)", err, limit))
			return
		case <-tick.C:
		}
	}
}

// mxcIdentityAnswer is the run's port answer to the box's identity request.
func mxcIdentityAnswer(ctx context.Context, runID string, l *mxcIdentityLatch) sandboxmxc.BoxIdentity {
	ans := sandboxmxc.BoxIdentity{V: sandboxmxc.BoxIdentityVersion, RunID: runID, ContainerID: sandboxmxc.ContainerName(runID)}
	sid, err := l.wait(ctx)
	if err != nil {
		ans.Error = err.Error()
		return ans
	}
	ans.SID = sid
	return ans
}

// mxcSameImage reports whether a process image path names want, the inner
// launch's executable: the same file when both can be stat'ed, else the
// same cleaned path compared case-insensitively (Windows paths are).
func mxcSameImage(want string) func(string) bool {
	wfi, werr := os.Stat(want)
	return func(p string) bool {
		if werr == nil {
			if fi, err := os.Stat(p); err == nil { //nolint:gosec // G703: a metadata read of a process image path the OS reported
				return os.SameFile(wfi, fi)
			}
		}
		return strings.EqualFold(filepath.Clean(p), filepath.Clean(want))
	}
}

// mxcPlaceholder is a protected path the helper created because it was
// missing at launch (finding F3).
type mxcPlaceholder struct {
	path    string
	dir     bool
	fi      fs.FileInfo
	content []byte
}

// mxcCreatePlaceholders creates the plan's placeholders before the box
// exists, the bwrap host helper's rule (sandbox_helpers_linux.go): an
// empty directory or a file with sandbox.PlaceholderContent, so the box
// finds the path present and read-only (or denied) and cannot create it
// for the next host process. Each path must lie inside one of the plan's
// writable roots. A path that appeared meanwhile is kept as it is (it is
// in the policy either way). It returns what it created, even on error.
func mxcCreatePlaceholders(plan mxcPlanFile) ([]mxcPlaceholder, error) {
	var out []mxcPlaceholder
	inside := func(p string) error {
		if !filepath.IsAbs(p) || !withinAny(p, plan.ReadWrite) {
			return fmt.Errorf("protected placeholder %s is outside the run's writable roots", p)
		}
		return nil
	}
	record := func(p string, dir bool, content []byte) error {
		fi, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("stat protected placeholder %s: %w", p, err)
		}
		out = append(out, mxcPlaceholder{path: p, dir: dir, fi: fi, content: content})
		return nil
	}
	for _, p := range plan.PlaceholderDirs {
		if err := inside(p); err != nil {
			return out, err
		}
		if err := os.Mkdir(p, 0o700); err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue
			}
			return out, fmt.Errorf("create protected placeholder dir %s (the box must not be able to create it): %w", p, err)
		}
		if err := ownSandboxRecord(p); err != nil {
			_ = os.Remove(p)
			return out, fmt.Errorf("own protected placeholder dir %s: %w", p, err)
		}
		if err := record(p, true, nil); err != nil {
			return out, err
		}
	}
	for _, p := range plan.PlaceholderFiles {
		if err := inside(p); err != nil {
			return out, err
		}
		content := sandbox.PlaceholderContent(p)
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a protected path the daemon planned inside the run's writable roots
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue
			}
			return out, fmt.Errorf("create protected placeholder %s (the box must not be able to create it): %w", p, err)
		}
		_, werr := f.Write(content)
		cerr := f.Close()
		if err := record(p, false, content); err != nil {
			return out, err
		}
		if err := errors.Join(werr, cerr, ownSandboxRecord(p)); err != nil {
			return out, fmt.Errorf("write protected placeholder %s: %w", p, err)
		}
	}
	return out, nil
}

// mxcRemovePlaceholders removes, in reverse order, each created placeholder
// that is still the one the helper made and still holds what it was
// created with (an empty directory, a file with the same bytes); anything
// the host changed meanwhile is left in place.
func mxcRemovePlaceholders(created []mxcPlaceholder) {
	for i := len(created) - 1; i >= 0; i-- {
		c := created[i]
		fi, err := os.Lstat(c.path)
		if err != nil || !os.SameFile(fi, c.fi) {
			continue
		}
		if c.dir {
			_ = os.Remove(c.path) // fails, and keeps the dir, unless it is empty
			continue
		}
		if fi.Size() != int64(len(c.content)) {
			continue
		}
		if b, err := os.ReadFile(c.path); err == nil && bytes.Equal(b, c.content) { //nolint:gosec // G304: the placeholder this helper created
			_ = os.Remove(c.path)
		}
	}
}

// mxcOOBUplink is the helper's trusted OOB channel to the daemon: the
// helper is the run's launcher on the host, so it authenticates the
// channel with the daemon's own Hello (the OBSERVER_OOB_* variables the
// daemon gave it), and forwards box claims only lowered.
type mxcOOBUplink struct {
	mu  sync.Mutex
	w   io.WriteCloser
	enc *termoob.Encoder
}

// newMXCOOBUplink authenticates the channel; nil when w is nil or the
// Hello cannot be written.
func newMXCOOBUplink(w io.WriteCloser, hello termoob.Hello, startedAt int64) *mxcOOBUplink {
	if w == nil {
		return nil
	}
	enc := termoob.NewEncoder(w)
	if err := enc.WriteHello(hello); err != nil {
		_ = w.Close()
		return nil
	}
	_ = enc.WriteLifecycle(termoob.Lifecycle{Phase: termoob.PhaseLauncherStarted, At: startedAt})
	return &mxcOOBUplink{w: w, enc: enc}
}

// session forwards a box-announced session id as discovered (a claim from
// inside the box may only lower confidence, sandbox plan section 5.6).
func (u *mxcOOBUplink) session(id string) {
	if u == nil || id == "" {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	_ = u.enc.WriteSession(termoob.Session{SessionID: id, Source: termoob.SessionSourceDiscovered})
}

// egressRefused reports how many connections the run's gateway refused
// while the tool owned the terminal (Windows 11 Pro run 4, N2): the daemon
// shows the count in the run's status, since the notices stay off the
// tool's screen. nil-safe.
func (u *mxcOOBUplink) egressRefused(total int) {
	if u == nil || total <= 0 {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	_ = u.enc.WriteLifecycle(termoob.Lifecycle{Phase: termoob.PhaseSandboxEgressRefused, Count: &total, At: time.Now().UnixNano()})
}

// end emits tool_exec_end and closes the channel.
func (u *mxcOOBUplink) end(exitCode int, at int64) {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	_ = u.enc.WriteLifecycle(termoob.Lifecycle{Phase: termoob.PhaseToolExecEnd, ExitCode: &exitCode, At: at})
	_ = u.w.Close()
}

// mxcForwardBoxOOB reads one box OOB stream (authenticated with the run's
// port token) and forwards each session announce through the uplink,
// lowered. Lifecycle frames from the box are dropped: the helper reports
// the run's own start and end.
func mxcForwardBoxOOB(box io.Reader, token string, up *mxcOOBUplink) {
	dec := termoob.NewDecoder(box, token)
	for {
		f, err := dec.Read()
		if err != nil {
			return
		}
		if f.Type == termoob.TypeSession && f.Session != nil {
			up.session(f.Session.SessionID)
		}
	}
}

// mxcHelloFromEnv is the helper's Hello from the variables the daemon set.
func mxcHelloFromEnv(getenv func(string) string) (termoob.Hello, bool) {
	h := termoob.Hello{
		AuthToken: getenv(envOOBAuth), CorrelationToken: getenv(envOOBCorr),
		Tool: getenv(envOOBTool), PID: os.Getpid(),
	}
	return h, h.AuthToken != ""
}

// mxcGatewayFor is the run's egress gateway (nil below the internet tier).
func mxcGatewayFor(plan mxcPlanFile, tier vocab.Tier) (*sandboxnet.Gateway, error) {
	if !sandboxmxc.Grants(tier, sandboxmxc.StreamGateway) {
		return nil, nil
	}
	allow, err := sandboxnet.ParseAllowCIDRs(plan.AllowCIDRs)
	if err != nil {
		return nil, err
	}
	// The agent-run host allow-list (lane LEFT-SBX), one rule for every row.
	hosts, err := sandboxAgentEgressRules(plan.ObserverDir, plan.RunID)
	if err != nil {
		return nil, err
	}
	g := &sandboxnet.Gateway{Allow: allow, Hosts: hosts}
	if plan.ProviderBlock {
		g.Providers = sandboxnet.NewProviderBlock(plan.ProviderHosts)
	}
	return g, nil
}

// mxcHostLog is the host helper's side of the run's inner log (Windows 11
// Pro run 3, 2026-10-22: the helper closed the box's relay stream and nothing
// said why). The helper creates the log before the box exists and writes its
// own lines, prefixed "host:", through the handle it holds, so a host line
// always lands in the file the helper created, never in one the box put at
// that path afterwards (the run's temp directory is the box's to write). The
// box's own observer processes append to the same file (appendBoxInnerLog),
// and the helper prints its tail when the box exits non-zero.
type mxcHostLog struct {
	mu sync.Mutex
	f  *os.File
}

// openMXCHostLog creates the run's inner log in tmpDir, fresh.
func openMXCHostLog(tmpDir string) (*mxcHostLog, error) {
	f, err := os.OpenFile(mxcInnerLogPath(tmpDir), os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600) //nolint:gosec // G304: the run's own fresh temp directory
	if err != nil {
		return nil, err
	}
	if err := ownSandboxRecord(mxcInnerLogPath(tmpDir)); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &mxcHostLog{f: f}, nil
}

// line appends one host line (the run's secrets removed, bounded like a box
// line); a log past boxInnerLogMax gets nothing. nil-safe.
func (l *mxcHostLog) line(s string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return
	}
	if fi, err := l.f.Stat(); err != nil || fi.Size() > boxInnerLogMax {
		return
	}
	_, _ = fmt.Fprintf(l.f, "%s host: %s\n", time.Now().UTC().Format(time.RFC3339), boxOneLine(s))
}

// close closes the log (nil-safe, once).
func (l *mxcHostLog) close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		_ = l.f.Close()
		l.f = nil
	}
}
