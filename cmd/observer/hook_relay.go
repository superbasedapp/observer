//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// hook_relay.go is the hook side of the capture relay (sandbox plan v2
// section 5.2, lane sbx-p2): the two ends a hook invocation can be.
//
//   - Inside a box (boxHookRelay): the host-written launch record in the
//     per-run socket dir says relay = required, so the hook never opens a
//     database. It sends the invocation over the relay and answers with
//     what the host answered. When the relay cannot be reached, a gate event
//     BLOCKS (whatever the guard mode: the guard could not be asked) and a
//     capture-only event is spooled inside the box and replayed by the next
//     invocation that reaches the relay. A box that carries the sandbox
//     marker but no valid launch record is a fault, handled the same way;
//     without the marker an invalid record is ignored (it can only be one
//     another user planted in a shared /tmp on the host).
//   - On the host as the daemon's relay child (relayChildHookContext): the
//     hook context is filled through hookctx's Daemon entry from the channel
//     record the daemon handed it on fd 3.

// boxSocketDir is the per-run socket dir inside a box (a variable so a test
// can stand a relay up elsewhere).
var boxSocketDir = sandbox.GuestSocketDir

// boxRecordPath is where the launch record sits inside a box.
var boxRecordPath = filepath.Join(boxSocketDir, sandboxrelayd.BoxRecordName)

// boxInsideByToken is set by a driver's box detection (box_detect.go) when
// the process carries an unforgeable fact of that driver's own box (the MXC
// row: an AppContainer token whose container is the run's own profile,
// lane SBX-P6, audit finding F1): such a process is inside a box whether
// or not the sandbox marker survived in its environment, so a missing
// record blocks gate events instead of letting the hook run as a host
// hook. Another vendor's AppContainer never sets it.
var boxInsideByToken bool

// boxRoundTrip carries one request to the run's relay. The default dials
// the per-run socket dir's relay socket; a driver whose box reaches the
// relay another way (the MXC row's token-scoped loopback port) replaces it
// from init.
var boxRoundTrip = func(ctx context.Context, rec sandboxrelayd.BoxRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
	return boxRedial(ctx, hookctx.Process().Getenv(hostedRelayRedialEnv) == "1", func(ctx context.Context) (sandboxrelay.HookResponse, error) {
		return sandboxrelayd.BoxRoundTrip(ctx, boxSocketDir, rec, req, sandboxrelay.ClientConnLimits)
	})
}

// hostedRelayRedialEnv is set in a hosted box's agent environment. That
// box's relay is a process on a vendor exec stream, which the home side
// re-opens after a drop; a hook that finds no relay to connect to then
// waits for the new one within its own budget instead of failing closed at
// once, and still fails closed when the budget ends (live run 2026-10-23,
// finding F7). The variable only lengthens a wait: it never lets an
// unchecked action through.
const hostedRelayRedialEnv = "OBSERVER_SANDBOX_RELAY_REDIAL"

// boxRedialEvery is the wait between two connects to a relay being
// re-opened.
var boxRedialEvery = 250 * time.Millisecond

// boxRedial runs try, and with redial runs it again after each failure to
// connect to the relay, or a relay stream closed during its handshake
// (in both nothing was sent, so a retry never repeats a request), until ctx
// ends. Any other failure is returned at once. The closed handshake is the
// hosted relay being re-opened under the hook (a box connection accepted by
// a relay process that is ending, or one whose session could not open a
// stream home): before lane SBX-UPD it refused a first internet-tier launch
// on Modal at once (finding H1, P-103).
func boxRedial(ctx context.Context, redial bool, try func(context.Context) (sandboxrelay.HookResponse, error)) (sandboxrelay.HookResponse, error) {
	for {
		resp, err := try(ctx)
		var hop *sandboxrelay.HopError
		if !redial || err == nil || !errors.As(err, &hop) ||
			(hop.Hop != sandboxrelay.HopBoxConnect && !errors.Is(err, sandboxrelayd.ErrNothingSent)) {
			return resp, err
		}
		select {
		case <-ctx.Done():
			return resp, err
		case <-time.After(boxRedialEvery):
		}
	}
}

// boxGetwd is the working directory a relayed request names (a seam: a
// test speaks for a box whose working directory is another host's path).
var boxGetwd = boxWorkingDir

// boxWorkingDir is the box's own working directory, which the relayed
// request DECLARES as a frame field the host validates (never a host fact;
// internal/hook's inventory class relay_box_client). internal/hookctx has
// no working-directory accessor for that reason, so the read stays here,
// in a named, classified function.
func boxWorkingDir() (string, error) { return os.Getwd() }

// boxMarked reports whether this process must treat itself as inside a box
// (the sandbox marker, or a driver's own process fact).
func boxMarked() bool {
	ensureBoxDetected()
	return boxInsideByToken || os.Getenv(sandboxEnvMarker) == "1"
}

// relaySpoolDir is the box-local spool for capture-only events (inside the
// box's private /tmp, so it lives exactly as long as the run).
var relaySpoolDir = "/tmp/.observer-relay-spool"

// Spool bounds.
const (
	relaySpoolMaxFiles = 64
	relaySpoolMaxBytes = 16 << 20
	relayReplayPerCall = 16
)

// relayUnreachableReason is the block reason of a gate event the relay
// could not carry.
const relayUnreachableReason = "Observer's sandbox relay could not be reached, so this action cannot be checked and is blocked. " +
	"Check that the Observer daemon is running; the sandbox keeps blocking checked actions until it is."

// boxHookRelay handles a hook invocation inside a box. ok=false means the
// hook is not inside any Observer sandbox and runs as before.
func boxHookRelay(args []string, stdin io.Reader, stdout, stderr io.Writer) (int, bool) {
	ensureBoxDetected()
	rec, present, err := sandboxrelayd.ReadBoxRecord(boxRecordPath)
	if !present || err != nil {
		// No valid record. Without the sandbox marker this is a host hook:
		// a record another user planted in a shared /tmp is ignored, never
		// a reason to block this user's hooks. With the marker it is a box
		// whose record is missing or refused: a fault.
		if !boxMarked() {
			return 0, false
		}
		if err == nil {
			err = errors.New("the sandbox marker is set but the box has no launch record")
		}
	}
	pos := hookPositionalArgs(args)
	if len(pos) == 0 {
		return 0, false
	}
	tool, event := pos[0], ""
	if len(pos) > 1 {
		event = canonicalHookEvent(tool, pos[1])
	}
	limit := int64(defaultHookBodyLimit)
	if len(pos) > 1 && strings.Contains(strings.ToLower(pos[1]), "prompt") {
		limit = promptSubmitBodyLimit
	}
	body, _ := readHookBodyDetectTruncation(stdin, limit)
	req := sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: pos, Env: declaredHookEnv(os.Getenv), Stdin: body}
	if cwd, werr := boxGetwd(); werr == nil {
		req.Cwd = filepath.Clean(cwd)
	}
	if err == nil {
		start := time.Now()
		budget := relayHookBudget(tool, event)
		gated := provisionalHookFailurePlan(tool, event, "").Gated
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		resp, rerr := boxRoundTrip(ctx, rec, req)
		cancel()
		if rerr == nil {
			if resp.Refused != "" {
				return relayRefused(tool, event, gated, resp.Refused, stdout, stderr), true
			}
			_, _ = stdout.Write(resp.Stdout)
			_, _ = stderr.Write(resp.Stderr)
			// The spool is replayed only after the live answer, and never by
			// a gate event: a gate answer is never late for a capture-only
			// backlog (P-026). A capture-only invocation replays within what
			// is left of its own budget.
			if !gated {
				replaySpool(rec, start.Add(budget))
			}
			return resp.Exit, true
		}
		err = rerr
	}
	return relayFailure(tool, event, req, err, stdout, stderr), true
}

// relayRefusedReason is the block reason of a gate event the host refused.
const relayRefusedReason = "Observer's sandbox relay refused this action because it does not belong to this sandbox's run, so it is blocked."

// relayRefused answers an invocation the host refused with a reason: a gate
// event blocks; a capture-only event is dropped (never spooled, the host
// would refuse it again).
func relayRefused(tool, event string, gated bool, why sandboxrelay.Refusal, stdout, stderr io.Writer) int {
	ans := relayRefusalAnswer(tool, event, gated, why)
	_, _ = stdout.Write(ans.Stdout)
	_, _ = stderr.Write(ans.Stderr)
	return ans.Exit
}

// relayRefusalAnswer is what a box answers its tool with for a refused
// invocation. The daemon renders the same answer for a box that sent a
// version 1 request (its decoder cannot read a refusal), so an older box
// blocks or drops exactly as a current one does.
func relayRefusalAnswer(tool, event string, gated bool, why sandboxrelay.Refusal) sandboxrelay.HookResponse {
	var out sandboxrelay.HookResponse
	if gated {
		plan := provisionalHookFailurePlan(tool, event, "")
		if reply, ok := hook.BuildFailClosedReply(plan.Dialect, relayRefusedReason); ok {
			out.Stdout = reply.Stdout
			if reply.StderrReason {
				out.Stderr = []byte(hook.StderrBlockReason(relayRefusedReason) + "\n")
			} else {
				out.Stderr = fmt.Appendf(nil, "observer-hook: %s:%s blocked: the sandbox relay refused it (%s)\n", tool, event, why)
			}
			out.Exit = reply.ExitCode
			return out
		}
	}
	out.Stderr = fmt.Appendf(nil, "observer-hook: %s:%s not captured: the sandbox relay refused it (%s)\n", tool, event, why)
	return out
}

// relayFailure answers an invocation the relay could not carry: a gate
// event blocks, a capture-only event is spooled.
func relayFailure(tool, event string, req sandboxrelay.HookRequest, cause error, stdout, stderr io.Writer) int {
	plan := provisionalHookFailurePlan(tool, event, "")
	if plan.Gated {
		if reply, ok := hook.BuildFailClosedReply(plan.Dialect, relayUnreachableReason); ok {
			_, _ = stdout.Write(reply.Stdout)
			if reply.StderrReason {
				hook.WriteStderrBlockReason(stderr, relayUnreachableReason)
			} else if why, ok := relayHopReason(cause); ok {
				fmt.Fprintf(stderr, "observer-hook: %s:%s blocked: the sandbox relay could not carry it: %s\n", tool, event, why)
			} else {
				fmt.Fprintf(stderr, "observer-hook: %s:%s blocked: the sandbox relay is unreachable (%v)\n", tool, event, cause)
			}
			return reply.ExitCode
		}
	}
	if err := spoolRequest(req); err != nil {
		fmt.Fprintf(stderr, "observer-hook: %s:%s not captured: the sandbox relay is unreachable and the spool refused it (%v)\n", tool, event, err)
	}
	return 0
}

// relayHookBudget bounds one relayed invocation below the host's own hook
// timeout (a gate) or the hook runtime default.
func relayHookBudget(tool, event string) time.Duration {
	budget := resolveHookMaxRuntime(0, os.Getenv("OBSERVER_HOOK_MAX_RUNTIME"))
	return hookGateBudget(budget, provisionalHookFailurePlan(tool, event, ""))
}

// hookPositionalArgs drops the hook's own flags (the host decides its
// config and runtime) and keeps the tool and event.
func hookPositionalArgs(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--config" || a == "--max-runtime":
			i++
		case strings.HasPrefix(a, "-"):
		default:
			out = append(out, a)
		}
	}
	return out
}

// declaredHookEnv collects the declarable variables that are set.
func declaredHookEnv(getenv func(string) string) map[string]string {
	out := map[string]string{}
	for name := range relayDeclaredEnv {
		if v := getenv(name); v != "" {
			out[name] = v
		}
	}
	return out
}

// spoolRequest stores a capture-only request in the box-local spool.
func spoolRequest(req sandboxrelay.HookRequest) error {
	req.Replay = true
	msg, err := sandboxrelay.EncodeHookRequest(req)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(relaySpoolDir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(relaySpoolDir)
	if err != nil {
		return err
	}
	var total int64
	for _, e := range entries {
		if fi, err := e.Info(); err == nil {
			total += fi.Size()
		}
	}
	if len(entries) >= relaySpoolMaxFiles || total+int64(len(msg)) > relaySpoolMaxBytes {
		return errors.New("the spool is full")
	}
	name := filepath.Join(relaySpoolDir, strconv.FormatInt(time.Now().UnixNano(), 10)+".req")
	return os.WriteFile(name, msg, 0o600)
}

// relayReplayMin is the least time left in the budget worth one replay.
const relayReplayMin = 50 * time.Millisecond

// replaySpool sends up to relayReplayPerCall spooled requests, oldest
// first, before deadline, deleting each one the host answered (a refused
// one too: the host would refuse it again).
func replaySpool(rec sandboxrelayd.BoxRecord, deadline time.Time) {
	entries, err := os.ReadDir(relaySpoolDir)
	if err != nil {
		return
	}
	for i, e := range entries {
		if i >= relayReplayPerCall || time.Until(deadline) < relayReplayMin {
			return
		}
		p := filepath.Join(relaySpoolDir, e.Name())
		msg, err := os.ReadFile(p) //nolint:gosec // G304: the box's own spool dir
		if err != nil {
			continue
		}
		req, err := sandboxrelay.DecodeHookRequest(msg, relayRules)
		if err != nil {
			_ = os.Remove(p)
			continue
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		_, err = boxRoundTrip(ctx, rec, req)
		cancel()
		if err != nil {
			return
		}
		_ = os.Remove(p)
	}
}

// relayChildHookContext fills the invocation's context on the daemon path
// when this process is a relay child (the daemon set relayEnvFD and handed
// the channel record on that descriptor). ok=false means a plain hook.
func relayChildHookContext(ctx context.Context, req hookctx.Request, configPath string) (*hookctx.Context, bool) {
	fd := os.Getenv(relayEnvFD)
	if fd == "" {
		return nil, false
	}
	rec, err := readRelayChildRecord(fd)
	if err != nil {
		// A relay child with no readable channel reads nothing at all: the
		// daemon path with an empty channel refuses every path and has no
		// environment, which is the safe answer.
		rec = relayChildRecord{}
	}
	ch := hookctx.Channel{
		RunID:        rec.RunID,
		Env:          rec.Env,
		Files:        sandboxrelayd.ConfinedFiles(rec.Roots),
		Delivery:     rec.Delivery,
		CopyHostPath: rec.CopyHostPath,
		ProjectRoot:  rec.ProjectRoot,
		CheckoutRoot: rec.CheckoutRoot,
		Contains:     sandboxrelayd.ConfinedContains(rec.Roots),
	}
	return hookctx.Daemon(ctx, req, ch, securityDaemonProviders(configPath)), true
}

// readRelayChildRecord reads the channel record from descriptor fd.
func readRelayChildRecord(fd string) (relayChildRecord, error) {
	f, err := relayChannelFile(fd)
	if err != nil {
		return relayChildRecord{}, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return relayChildRecord{}, err
	}
	var rec relayChildRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return relayChildRecord{}, err
	}
	return rec, nil
}

// relayLaunchGateRefusal is the refusal of an in-box launch whose gates
// could not be asked, when the failure names no relay hop (boxGateHops
// names the hop otherwise; only the hop where the helper could not connect
// to the daemon asks to check the daemon).
const relayLaunchGateRefusal = "the sandbox's launch checks could not reach Observer's capture relay, so the launch is refused"

// boxGateHops is the refusal of an in-box launch check whose request failed
// on a named relay hop (Windows 11 Pro run 3, 2026-10-22, where the host
// helper's EOF read as a stopped daemon while the daemon was answering): each
// row names the hop and its address (%s). Only the row where the helper's
// upstream to the daemon failed to connect asks to check the daemon.
var boxGateHops = map[sandboxrelay.Hop]string{
	sandboxrelay.HopBoxConnect:    "the box to helper hop failed: the box could not connect to the run's host helper at %s",
	sandboxrelay.HopBoxStream:     "the box to helper hop failed: the run's host helper at %s refused the relay stream",
	sandboxrelay.HopBoxClosed:     "the box to helper hop failed: the run's host helper at %s closed the relay stream without answering",
	sandboxrelay.HopHelperRequest: "the run's host helper at %s refused the request",
	sandboxrelay.HopDaemonConnect: "the helper to daemon relay hop failed: the run's host helper could not connect to Observer's capture relay at %s; check that the Observer daemon is running",
	sandboxrelay.HopDaemonLink:    "the helper to daemon relay hop failed: Observer's capture relay at %s refused the run's host helper (it does not know this run)",
	sandboxrelay.HopDaemonAnswer:  "the helper to daemon relay hop failed: Observer's capture relay at %s ended the request without an answer (the daemon's log names why, with this run's id)",
}

// boxClosedLogNotes say where the helper's reason for a closed relay
// stream is kept, by the log the box's row keeps (lane SBX-UPD, finding H1:
// the old text sent every row to "the run's inner log", which only the MXC
// row keeps; a hosted row keeps a relay log at home instead). The row is
// read from the box's environment (a capability of the run, never a
// backend name).
var boxClosedLogNotes = map[string]string{
	"inner_log":  "its reason is on a host: line of the run's inner log",
	"hosted_log": "its reason is in the run's relay log on the machine that launched it, ~/.observer/sandbox-hosted/<run>/relay.log; `observer sandbox hosted status` lists it",
	"":           "the run's host helper logs its reason with this run's id",
}

// boxClosedLogNote picks the note for this box: an inner log named in the
// environment (the MXC row), a hosted box's relay (its redial marker), or
// neither.
func boxClosedLogNote(getenv func(string) string) string {
	kind := ""
	switch {
	case getenv(sandboxInnerLogEnv) != "":
		kind = "inner_log"
	case getenv(hostedRelayRedialEnv) == "1":
		kind = "hosted_log"
	}
	return boxClosedLogNotes[kind]
}

// relayHopReason renders the relay hop err names through boxGateHops, its
// detail in parentheses; ok=false when err names no hop.
func relayHopReason(err error) (string, bool) {
	var hop *sandboxrelay.HopError
	if !errors.As(err, &hop) {
		return "", false
	}
	row, ok := boxGateHops[hop.Hop]
	if !ok {
		return "", false
	}
	addr := hop.Addr
	if addr == "" {
		addr = "an unnamed address"
	}
	msg := fmt.Sprintf(row, addr)
	if hop.Hop == sandboxrelay.HopBoxClosed {
		msg += " (" + boxClosedLogNote(hookctx.Process().Getenv) + ")"
	}
	if hop.Detail != "" {
		msg += " (" + hop.Detail + ")"
	}
	return msg, true
}

// boxGateUnreachableRefusal is the refusal of a launch check the relay did
// not carry: the hop that failed when err names one, else the relay in
// general.
func boxGateUnreachableRefusal(err error) error {
	if msg, ok := relayHopReason(err); ok {
		return boxLaunchGateError(errors.New("the sandbox's launch checks did not complete, so the launch is refused: " + msg))
	}
	return boxGateRefusal(boxGateUnreachable, err.Error())
}

// boxGateCause is why an in-box launch check refused the launch.
type boxGateCause int

// The causes, one refusal each (boxGateRefusals).
const (
	// boxGateNotRecognised: box detection declined, so the launch record
	// this process would speak for is not its own.
	boxGateNotRecognised boxGateCause = iota
	// boxGateNoRecord: the process is inside a box, but the launch record
	// is missing or refused.
	boxGateNoRecord
	// boxGateUnreachable: the relay could not be reached.
	boxGateUnreachable
	// boxGateRelayRefused: the relay answered, refusing the request.
	boxGateRelayRefused
)

// boxGateRefusals is the refusal of each cause, leading with the cause that
// actually happened (Windows 11 Pro rerun 2026-10-22: a failed box
// detection read as an unreachable daemon while the daemon was answering).
var boxGateRefusals = map[boxGateCause]string{
	boxGateNotRecognised: "the sandbox's launch checks refused the launch because this process did not recognise the sandbox it runs in",
	boxGateNoRecord:      "the sandbox's launch checks refused the launch because the sandbox's launch record is missing or refused",
	boxGateUnreachable:   relayLaunchGateRefusal,
	boxGateRelayRefused:  "the sandbox's launch checks refused the launch because Observer's capture relay refused the request",
}

// boxGateRefusal is cause's refusal with its detail, as a visible launcher
// error.
func boxGateRefusal(cause boxGateCause, detail string) error {
	msg := boxGateRefusals[cause]
	if detail != "" {
		msg += " (" + detail + ")"
	}
	return boxLaunchGateError(errors.New(msg))
}

// boxLaunchGate runs the inner launcher's launch-gate walk host-side when
// this launcher runs inside a box (the walk reads the node database, which
// the box does not have). ok=false means the launcher is not inside any
// Observer sandbox and walks the table itself.
func boxLaunchGate(tool string, evidence budgetLaunchEvidence) (error, bool) { //nolint:revive // the (error, ok) pair mirrors boxHookRelay
	ensureBoxDetected()
	rec, present, err := sandboxrelayd.ReadBoxRecord(boxRecordPath)
	if !present || err != nil {
		if !boxMarked() {
			return nil, false
		}
		// Visible, leading with what happened: the launchers silence Cobra,
		// so the plain error this was ended the inner launch with exit 1 and
		// nothing on the terminal (Windows 11 Pro live run 2026-10-22).
		if boxDetectNote != "" {
			return boxGateRefusal(boxGateNotRecognised, boxDetectNote), true
		}
		detail := ""
		if err != nil {
			detail = err.Error()
		}
		return boxGateRefusal(boxGateNoRecord, detail), true
	}
	evidence.Executable = launchEvidenceExecutable(evidence.Executable)
	body, err := json.Marshal(evidence)
	if err != nil {
		return boxLaunchGateError(fmt.Errorf("launch gate evidence: %w", err)), true
	}
	req := sandboxrelay.HookRequest{Kind: sandboxrelay.KindLaunchGate, Args: []string{tool}, Env: declaredHookEnv(os.Getenv), Stdin: body}
	if cwd, werr := boxGetwd(); werr == nil {
		req.Cwd = filepath.Clean(cwd)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := boxRoundTrip(ctx, rec, req)
	if err != nil {
		return boxGateUnreachableRefusal(err), true
	}
	if resp.Refused != "" {
		return boxGateRefusal(boxGateRelayRefused, string(resp.Refused)), true
	}
	if resp.Exit == 0 {
		return nil, true
	}
	msg := strings.TrimSpace(string(resp.Stderr))
	if msg == "" {
		msg = "the launch was refused by Observer's launch checks"
	}
	return boxLaunchGateError(errors.New(msg)), true
}

// boxLaunchGateError is an in-box launch check's refusal as a visible
// launcher error (launcher_errors.go). Each message is Observer's own (the
// relay refusal, or the host-side walk's own stderr), so the terminal shows
// it instead of a bare exit 1.
func boxLaunchGateError(err error) error {
	return newVisibleLauncherError(err, err.Error())
}

// inRelayBox reports whether this process runs inside a box whose capture
// goes through the relay (a valid launch record is present). Such a process
// has no node database: loadConfigAndDB refuses, and the launch seed is not
// recorded (the daemon links the run through the trusted out-of-band
// channel instead).
func inRelayBox() bool {
	ensureBoxDetected()
	_, present, err := sandboxrelayd.ReadBoxRecord(boxRecordPath)
	return boxInsideByToken || (present && err == nil)
}

// errNoDatabaseInBox is loadConfigAndDB's refusal inside a relayed box.
var errNoDatabaseInBox = errors.New("the Observer database is not available inside a sandbox (its capture goes through the relay); run this outside the sandbox")

// launchEvidenceExecutable is the executable the launch evidence names when
// it crosses the capture relay (boxLaunchGate): the resolved binary as an
// absolute path. Every launcher takes its binary-path flag (--claude-path and
// the like) verbatim, so a relative path (./agent.sh, the shape a sandboxed
// run names a tool inside its workspace with) reached the evidence relative,
// and the daemon's relay gate refuses any executable that is not an absolute
// clean path (boxLaunchEvidence), so the sandboxed CLI launch never started
// its tool (the microVM row's second live run). A bare name is resolved over
// PATH the way the exec will resolve it; one PATH does not resolve stays as
// given and the gate refuses it.
func launchEvidenceExecutable(bin string) string {
	if bin == "" || filepath.IsAbs(bin) {
		return bin
	}
	p := bin
	if !strings.ContainsRune(bin, '/') && !strings.ContainsRune(bin, filepath.Separator) {
		lp, err := exec.LookPath(bin)
		if err != nil {
			return bin
		}
		p = lp
	}
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return bin
}
