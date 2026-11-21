package attachsock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/localipc"
)

// control.go adds the one-shot CONTROL operations to the attach channel
// (decision P-228, docs/plans/discovery-cli-2026-11-03.md section 4.1, phase
// 1b): a detached launch and the run inventory verbs behind `observer launch`
// and `observer terminals`. They are additive. A control connection sends one
// control frame whose op is launch, list, show, stop or wait, reads one reply
// (a result frame or an error frame) and closes; no PTY stream rides it and
// no TTY is needed on either side, so these work on every transport the
// daemon serves (the owner-only unix socket and the Windows named pipe).
//
// Compatibility: protocol version stays ProtocolVersion. An older daemon reads
// the first frame as a spawn and answers a protocol error naming the op it
// expected, which ControlCall maps to ErrDaemonTooOld; an older client never
// sends these ops. The daemon side of the ops is the OPTIONAL Controller
// capability of the Host: a Host without it answers CodeUnsupported.

// Control op names (client → server) and the reply op (server → client).
const (
	opLaunch = "launch"
	opList   = "list"
	opShow   = "show"
	opStop   = "stop"
	opWait   = "wait"
	// opConfirm and opReject answer a launch the daemon holds for a human
	// (lane cli-2 fixes-1): the run reference is the hold's id.
	opConfirm = "confirm"
	opReject  = "reject"
	opResult  = "result"
)

// Control error codes, in addition to the spawn codes.
const (
	// CodeUnsupported: the daemon serves the attach channel but has no
	// control capability (the launch surface is not wired).
	CodeUnsupported = "unsupported"
	// CodeNotFound: no run matches the reference.
	CodeNotFound = "not_found"
	// CodeAmbiguousRun: a run-id prefix matches more than one run.
	CodeAmbiguousRun = "ambiguous_run"
	// CodeNotStoppable: the run is not a terminal this daemon owns.
	CodeNotStoppable = "not_stoppable"
	// CodeBusy: the daemon already serves maxConcurrentWaits waits.
	CodeBusy = "busy"
	// CodeControlFailed: the operation failed for another reason.
	CodeControlFailed = "control_failed"
)

// Wait conditions.
const (
	// WaitSession returns once the run has a correlated session id (or has
	// ended without one).
	WaitSession = "session"
	// WaitExit returns once the run is no longer running.
	WaitExit = "exit"
)

// Run states reported in RunInfo.State.
const (
	// StateRunning: the tool's process is live.
	StateRunning = "running"
	// StateExited: the process exited; the daemon still holds its terminal.
	StateExited = "exited"
	// StateEnded: the run's end is recorded.
	StateEnded = "ended"
	// StateAbandoned: no end was recorded, but the run is far too old to be
	// live (a daemon-death orphan), read-time verdict only.
	StateAbandoned = "abandoned"
	// StatePending: an agent asked for the launch and the daemon holds it
	// for a human's confirm (lane cli-2 fixes-1); nothing runs yet.
	StatePending = "pending_confirm"
)

// maxWait bounds a wait whatever the client asks for.
const maxWait = 24 * time.Hour

// maxConcurrentWaits bounds the waits a daemon serves at once; a wait past
// it is refused with CodeBusy. A var so tests lower it.
var maxConcurrentWaits = 32

// waitPoll is the first interval a wait re-reads the run at; each read
// that does not end the wait doubles it, up to waitPollMax, so a wait of
// hours costs a read every few seconds, not four a second. Vars so tests
// tighten them.
var (
	waitPoll    = 250 * time.Millisecond
	waitPollMax = 5 * time.Second
)

// nextWaitPoll is the backoff step: double, capped at waitPollMax.
func nextWaitPoll(d time.Duration) time.Duration {
	if d *= 2; d > waitPollMax {
		return waitPollMax
	}
	return d
}

// LaunchSpec is a detached launch request, plain strings (the vocabulary of
// internal/agentlaunch.Request, mapped by the cmd layer).
type LaunchSpec struct {
	Tool      string `json:"tool"`
	Project   string `json:"project"`
	Sandbox   string `json:"sandbox,omitempty"`
	Workspace string `json:"workspace,omitempty"`
	Remote    string `json:"remote,omitempty"`
	Branch    string `json:"branch,omitempty"`
	Model     string `json:"model,omitempty"`
	// AgentEnv and AgentEnvSession are the client's agent-session hint
	// (lane cli-2): the client found an agent session's environment marker
	// (procmodel.SessionTokenEnvKeys) in its own environment, and the
	// session id it named. A hint can only make the launch an agent's, never
	// a human's; the daemon judges the caller's ancestry itself. Additive.
	AgentEnv        bool   `json:"agent_env,omitempty"`
	AgentEnvSession string `json:"agent_env_session,omitempty"`
}

// RunInfo is one terminal run as the control ops report it. It is also the
// `--json` shape of `observer launch` and `observer terminals`. Metadata
// only: no path, no command text, no output.
type RunInfo struct {
	RunID      string `json:"run_id"`
	Handle     string `json:"handle,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	Tool       string `json:"tool"`
	Subcommand string `json:"subcommand,omitempty"`
	Kind       string `json:"kind,omitempty"`
	State      string `json:"state"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	EndReason  string `json:"end_reason,omitempty"`
	Sandboxed  bool   `json:"sandboxed"`
	Backend    string `json:"backend,omitempty"`
	Isolation  string `json:"isolation,omitempty"`
	Capture    string `json:"capture,omitempty"`
	LaunchedAt string `json:"launched_at,omitempty"`
	EndedAt    string `json:"ended_at,omitempty"`
	// Initiator is who started the run (lane cli-2, migration 220):
	// human_dashboard, human_cli or agent; "" when not recorded.
	Initiator string `json:"initiator,omitempty"`
	// ParentSessionID is the agent session an agent-started run was traced
	// to; "" otherwise or when not known.
	ParentSessionID string `json:"parent_session_id,omitempty"`
	// PendingID, PendingWhat and ExpiresAt describe a launch held for a
	// human (State StatePending): confirm it with `observer terminals
	// confirm <PendingID>` before ExpiresAt.
	PendingID   string `json:"pending_id,omitempty"`
	PendingWhat string `json:"pending_what,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	// PendingDetails are every field the held launch is bound to (lane
	// cli-2 fixes-2): what a confirm starts, shown whole.
	PendingDetails []PendingDetail `json:"pending_details,omitempty"`
}

// PendingDetail is one bound field of a held launch.
type PendingDetail struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Warn  bool   `json:"warn,omitempty"`
}

// Live reports whether the run's process is still running.
func (r RunInfo) Live() bool { return r.State == StateRunning }

// Controller is the OPTIONAL Host capability behind the control ops. The cmd
// adapter implements it over the terminal service; attachsock never sees
// that service.
type Controller interface {
	// LaunchDetached validates and starts a run without attaching to it.
	// A refusal is a *ControlError whose Code the client reports.
	LaunchDetached(ctx context.Context, spec LaunchSpec) (RunInfo, error)
	// Runs lists runs, live first then recent history, newest first.
	Runs(ctx context.Context) ([]RunInfo, error)
	// Run resolves a run id or handle; ErrRunNotFound when none matches.
	Run(ctx context.Context, ref string) (RunInfo, error)
	// StopRun ends a live run; ErrRunNotFound when none matches.
	StopRun(ctx context.Context, ref string) (RunInfo, error)
}

// PendingController is the OPTIONAL Controller capability behind the
// confirm and reject ops (lane cli-2 fixes-1). A Controller without it
// answers CodeUnsupported.
type PendingController interface {
	// ConfirmLaunch starts the held launch id for the caller in ctx
	// (CallerPID), once; a caller attributed to an agent is refused.
	ConfirmLaunch(ctx context.Context, id string) (RunInfo, error)
	// RejectLaunch drops the held launch id without starting it.
	RejectLaunch(ctx context.Context, id string) (RunInfo, error)
}

// ErrRunNotFound is what a Controller returns for an unknown reference.
var ErrRunNotFound = errors.New("attachsock: no such run")

// ErrDaemonTooOld is returned by ControlCall when the daemon predates the
// control ops (it answered the request as a malformed spawn).
var ErrDaemonTooOld = errors.New("attachsock: the running observer daemon predates detached launch control; restart it with this observer build")

// ControlError is a refusal relayed over the channel: Code is a closed code
// (one of this package's codes, or the launch refusal code the Controller
// set), Message the human line.
type ControlError struct {
	Code    string
	Message string
}

// Error implements error.
func (e *ControlError) Error() string { return e.Message }

// controlMsg is a client → server control request.
type controlMsg struct {
	Op        string      `json:"op"`
	V         int         `json:"v"`
	Launch    *LaunchSpec `json:"launch,omitempty"`
	Run       string      `json:"run,omitempty"`
	For       string      `json:"for,omitempty"`
	TimeoutMS int64       `json:"timeout_ms,omitempty"`
	// AgentEnv and AgentEnvSession are the client's agent-session hint on
	// any op (lane cli-2 fixes-2: a confirm reports it as a launch does).
	AgentEnv        bool   `json:"agent_env,omitempty"`
	AgentEnvSession string `json:"agent_env_session,omitempty"`
}

// resultMsg is the server → client reply.
type resultMsg struct {
	Op       string    `json:"op"`
	Run      *RunInfo  `json:"run,omitempty"`
	Runs     []RunInfo `json:"runs,omitempty"`
	TimedOut bool      `json:"timed_out,omitempty"`
}

// controlOps is the closed set of control op names.
var controlOps = map[string]bool{opLaunch: true, opList: true, opShow: true, opStop: true, opWait: true, opConfirm: true, opReject: true}

// isControlOp reports whether op is a control op.
func isControlOp(op string) bool { return controlOps[op] }

// serveControl answers one control request and returns; the caller closes
// the connection. Every reply is one frame.
func (s *server) serveControl(ctx context.Context, fc *frameConn, nc net.Conn, payload []byte) {
	var m controlMsg
	if err := unmarshalControl(payload, &m); err != nil {
		_ = fc.sendError(CodeProtocol, err.Error())
		return
	}
	if m.V != ProtocolVersion {
		_ = fc.sendError(CodeProtocol, fmt.Sprintf("unsupported protocol version %d (want %d)", m.V, ProtocolVersion))
		return
	}
	ctx = WithCallerHint(ctx, CallerHint{AgentEnv: m.AgentEnv, Session: m.AgentEnvSession})
	ctl, ok := s.host.(Controller)
	if !ok {
		_ = fc.sendError(CodeUnsupported, "this observer daemon does not offer detached launch control ([terminal.attach] is on, the launch surface is not wired)")
		return
	}
	var (
		res resultMsg
		err error
	)
	switch m.Op {
	case opLaunch:
		if m.Launch == nil {
			_ = fc.sendError(CodeProtocol, "launch needs a launch spec")
			return
		}
		var ri RunInfo
		ri, err = ctl.LaunchDetached(ctx, *m.Launch)
		res.Run = &ri
	case opList:
		res.Runs, err = ctl.Runs(ctx)
	case opShow:
		var ri RunInfo
		ri, err = ctl.Run(ctx, m.Run)
		res.Run = &ri
	case opStop:
		var ri RunInfo
		ri, err = ctl.StopRun(ctx, m.Run)
		res.Run = &ri
	case opConfirm, opReject:
		pc, ok := ctl.(PendingController)
		if !ok {
			_ = fc.sendError(CodeUnsupported, "this observer daemon does not hold launches for a human's confirm")
			return
		}
		var ri RunInfo
		if m.Op == opConfirm {
			ri, err = pc.ConfirmLaunch(ctx, m.Run)
		} else {
			ri, err = pc.RejectLaunch(ctx, m.Run)
		}
		res.Run = &ri
	case opWait:
		// Each wait holds a connection and a polling goroutine for up to
		// maxWait, so the number in progress is bounded (audit L1).
		if s.activeWaits.Add(1) > int64(maxConcurrentWaits) {
			s.activeWaits.Add(-1)
			_ = fc.sendError(CodeBusy, fmt.Sprintf("%d waits are already in progress on this daemon; retry when one ends", maxConcurrentWaits))
			return
		}
		res, err = s.waitRun(ctx, fc, nc, ctl, m)
		s.activeWaits.Add(-1)
	}
	if err != nil {
		_ = fc.sendError(controlErrorCode(err), err.Error())
		return
	}
	res.Op = opResult
	_ = fc.sendControl(res)
}

// controlErrorCode maps a Controller error onto the wire code.
func controlErrorCode(err error) string {
	var ce *ControlError
	switch {
	case errors.As(err, &ce) && ce.Code != "":
		return ce.Code
	case errors.Is(err, ErrRunNotFound):
		return CodeNotFound
	default:
		return CodeControlFailed
	}
}

// waitRun re-reads the run, backing off from waitPoll to waitPollMax, until
// the condition holds, the
// timeout passes (a result with TimedOut), the client goes away or the
// daemon shuts down.
func (s *server) waitRun(ctx context.Context, fc *frameConn, nc net.Conn, ctl Controller, m controlMsg) (resultMsg, error) {
	cond := m.For
	if cond == "" {
		cond = WaitExit
	}
	if cond != WaitExit && cond != WaitSession {
		return resultMsg{}, &ControlError{Code: CodeProtocol, Message: fmt.Sprintf("unknown wait condition %q (session or exit)", m.For)}
	}
	timeout := time.Duration(m.TimeoutMS) * time.Millisecond
	if timeout <= 0 || timeout > maxWait {
		timeout = maxWait
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// A client that hangs up ends the wait: the only thing it may still
	// send is nothing, so any read result (EOF included) cancels.
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		_, _ = io.Copy(io.Discard, nc)
		cancel()
	}()
	defer func() {
		// Unblock the reader goroutine before returning.
		_ = nc.SetReadDeadline(time.Now())
		<-gone
		_ = nc.SetReadDeadline(time.Time{})
	}()
	poll := waitPoll
	timer := time.NewTimer(poll)
	defer timer.Stop()
	for {
		ri, err := ctl.Run(ctx, m.Run)
		if err != nil {
			return resultMsg{}, err
		}
		if waitDone(cond, ri) {
			return resultMsg{Run: &ri}, nil
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return resultMsg{Run: &ri, TimedOut: true}, nil
			}
			return resultMsg{}, ctx.Err()
		case <-timer.C:
			poll = nextWaitPoll(poll)
			timer.Reset(poll)
		}
	}
}

// waitDone is the wait condition table: a session wait also ends when the
// run is over (no session can correlate any more).
func waitDone(cond string, ri RunInfo) bool {
	switch cond {
	case WaitSession:
		return ri.SessionID != "" || !ri.Live()
	default:
		return !ri.Live()
	}
}

// ControlRequest is one client control call.
type ControlRequest struct {
	// Op is "launch", "list", "show", "stop", "wait", "confirm" or
	// "reject".
	Op string
	// Launch is the spec for "launch".
	Launch *LaunchSpec
	// Run is the run id or handle for "show", "stop" and "wait", and the
	// held launch's id for "confirm" and "reject".
	Run string
	// For is the wait condition (WaitSession or WaitExit).
	For string
	// Timeout bounds a wait (0 = the daemon's ceiling).
	Timeout time.Duration
	// AgentEnv and AgentEnvSession are the client's agent-session hint
	// (procmodel.SessionTokenEnvKeys found in its own environment); a
	// confirm sends it like a launch, and the Controller reads it from
	// CallerHint (lane cli-2 fixes-2).
	AgentEnv        bool
	AgentEnvSession string
}

// ControlResult is the reply to a control call.
type ControlResult struct {
	Run      *RunInfo
	Runs     []RunInfo
	TimedOut bool
}

// controlReplyGrace is how long past a wait's own timeout the client waits
// for the reply; every other op gets controlReplyTimeout.
const (
	controlReplyGrace   = 10 * time.Second
	controlReplyTimeout = 60 * time.Second
)

// ControlCall dials the attach endpoint, sends one control request and
// returns the reply. A refusal is a *ControlError; an unreachable daemon
// wraps ErrDaemonUnreachable; an old daemon is ErrDaemonTooOld.
func ControlCall(ctx context.Context, endpoint string, req ControlRequest) (ControlResult, error) {
	if !isControlOp(req.Op) {
		return ControlResult{}, fmt.Errorf("attachsock.ControlCall: unknown op %q", req.Op)
	}
	conn, err := Dial(endpoint)
	if err != nil {
		return ControlResult{}, err
	}
	defer func() { _ = conn.Close() }()
	// ATT-1's client precondition: on Windows the pipe name is predictable,
	// so confirm the pipe is served by this user (or SYSTEM) before a
	// request, which may carry a --remote URL with a credential, is sent.
	// A no-op on unix, where the 0700 directory already guarantees it.
	if err := verifyControlServer(conn); err != nil {
		return ControlResult{}, err
	}
	return controlOn(ctx, conn, req)
}

// ControlOn sends one control request over a connection the caller already
// holds (one it inherited from the process that dialed it, say) and
// returns the reply; ControlCall dials the endpoint itself. The server
// still judges the process that connected (lane cli-2 fixes-3, audit M1).
func ControlOn(ctx context.Context, conn net.Conn, req ControlRequest) (ControlResult, error) {
	if !isControlOp(req.Op) {
		return ControlResult{}, fmt.Errorf("attachsock.ControlOn: unknown op %q", req.Op)
	}
	if err := verifyControlServer(conn); err != nil {
		return ControlResult{}, err
	}
	return controlOn(ctx, conn, req)
}

// verifyControlServer is localipc.VerifyServer (a var so tests can refuse).
var verifyControlServer = localipc.VerifyServer

// ErrServerUnverified is localipc.ErrServerUnverified.
var ErrServerUnverified = localipc.ErrServerUnverified

// controlOn runs one control exchange over an established connection.
func controlOn(ctx context.Context, conn net.Conn, req ControlRequest) (ControlResult, error) {
	fc := newFrameConn(conn)
	budget := controlReplyTimeout
	if req.Op == opWait {
		w := req.Timeout
		if w <= 0 || w > maxWait {
			w = maxWait
		}
		budget = w + controlReplyGrace
	}
	deadline := time.Now().Add(budget)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()

	msg := controlMsg{
		Op: req.Op, V: ProtocolVersion, Launch: req.Launch, Run: req.Run, For: req.For,
		AgentEnv: req.AgentEnv, AgentEnvSession: req.AgentEnvSession,
	}
	if req.Timeout > 0 {
		msg.TimeoutMS = req.Timeout.Milliseconds()
	}
	if err := fc.sendControl(msg); err != nil {
		return ControlResult{}, fmt.Errorf("attachsock.ControlCall: send: %w", err)
	}
	for {
		t, payload, err := fc.readFrame()
		if err != nil {
			if ctx.Err() != nil {
				return ControlResult{}, ctx.Err()
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return ControlResult{}, ErrConnLost
			}
			return ControlResult{}, fmt.Errorf("attachsock.ControlCall: read: %w", err)
		}
		if t != frameControl {
			continue // forward compat: skip unknown frame types
		}
		op, err := peekOp(payload)
		if err != nil {
			return ControlResult{}, err
		}
		switch op {
		case opResult:
			var rm resultMsg
			if err := unmarshalControl(payload, &rm); err != nil {
				return ControlResult{}, err
			}
			if req.Op == opList && rm.Runs == nil {
				rm.Runs = []RunInfo{} // an empty list is a list, never null
			}
			return ControlResult{Run: rm.Run, Runs: rm.Runs, TimedOut: rm.TimedOut}, nil
		case opError:
			var em errorMsg
			if err := unmarshalControl(payload, &em); err != nil {
				return ControlResult{}, err
			}
			if em.Code == CodeProtocol && strings.Contains(em.Message, `expected op "`+opSpawn+`"`) {
				return ControlResult{}, ErrDaemonTooOld
			}
			return ControlResult{}, &ControlError{Code: em.Code, Message: em.Message}
		default:
			continue // a notice this client does not know
		}
	}
}
