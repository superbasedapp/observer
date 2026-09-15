package dashboard

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/processbridge/setup"
)

// etwRegisterLabel is the SetupSpec label for the elevation broker's PTY.
//
// It is distinct from every other setup label ("tailscale-install",
// "install:<tool>", …) because the launch manager's setup single-flight is
// keyed by label: a distinct label means a duplicate POST to THIS route is
// refused with 409 while an unrelated setup PTY (a Tailscale login, say) is
// still free to run. Sharing a label with another feature would make the two
// mutually exclusive for no reason; reusing a label across two routes would
// silently let one POST-spam the other's single-flight.
const etwRegisterLabel = "process-etw-register"

// etwRegisterResponse is the POST /api/process/etw/register success shape.
//
// It carries no state vocabulary of its own: the card re-reads
// GET /api/process/etw/status once the PTY exits, so this response only has to
// say what was STARTED, never what the outcome was. Claiming a registration
// here would be a claim about a UAC prompt the operator has not seen yet.
type etwRegisterResponse struct {
	// Handle is the PTY the frontend opens /ws/launch/<handle> against. The
	// session is SpecSetup — local-writer-only — so this handle is useless to
	// a remote device even if it somehow learned it.
	Handle string `json:"handle"`
	// TaskName is the Scheduled Task being registered, so the operator can
	// verify with their own `schtasks /Query` against the same literal.
	TaskName string `json:"task_name"`
	// Command is the equivalent copy-paste line for an elevated shell — the
	// SAME bytes the spawned child hands to schtasks.exe (both come from
	// setup.TaskArgs). Returned so the card can show what it just ran, and so
	// a failed run leaves the manual path visible.
	Command string `json:"command"`
	// Notes are the planner's caveats (which account must own the task, how to
	// check a \\wsl.localhost token file is reachable), carried through
	// unchanged.
	Notes []string `json:"notes,omitempty"`
	// UACRequired is always true and is stated rather than implied: the whole
	// point of this route is that a consent dialog appears on the machine and
	// nothing happens until a human approves it. A card that renders a spinner
	// without saying so would be lying about what it is waiting for.
	UACRequired bool `json:"uac_required"`
	// AlreadyRunning reports that this POST did NOT start anything: an
	// elevated registration PTY of this kind was already live, and the launch
	// manager handed back that PTY's handle (its labelled setup ops are
	// idempotent by design — see handleProcessETWRegister). Every other field
	// then describes THAT run, not the plan this request computed.
	AlreadyRunning bool `json:"already_running,omitempty"`
	// PlanState echoes the planner state the spawn was authorised from
	// ("manual" or "unknown"). "unknown" keeps its hedge: the read-only probe
	// could not tell us the task was absent, so schtasks may still refuse
	// (without /F it will not overwrite), and the card must not promise
	// otherwise.
	PlanState string `json:"plan_state"`
}

// handleProcessETWRegister serves POST /api/process/etw/register — the
// ELEVATION BROKER half of the dashboard-driven ETW capturer setup (plan §E3).
//
// It spawns, in a local-only PTY, a fixed PowerShell program that runs
// `Start-Process schtasks.exe -Verb RunAs`: Windows shows a UAC consent
// dialog, and the Scheduled Task is created under the elevated token the
// operator approves. This is the direct analogue of
// handleRemoteTailscaleOperatorGrant's `sudo tailscale set --operator` — a
// privilege step Observer cannot take for the user, only put in front of them.
//
// SECURITY PROPERTIES, none of them optional:
//
//   - CAPABILITY LOCAL + CONFIRM TOKEN. Owner-loopback only, refused on any
//     remote listener (registered `L` in registerRoutes), plus the §10
//     double-submit confirm token — exactly like every other machine-reaching
//     POST.
//   - THE REQUEST CONTRIBUTES NOTHING TO ARGV. The body is never decoded;
//     there is not even a request struct for it. Every byte of the argv comes
//     from setup.ElevatedRegisterArgv over the planner's own resolved inputs,
//     which in turn come from config.toml and the read-only schtasks probe.
//     The injection surface is zero by construction, which is the property
//     that made the Tailscale seam safe.
//   - SpecSetup IS LOCAL-WRITER-ONLY BY SESSION KIND, so a paired remote
//     device can neither drive this PTY, read it, nor terminate it. That
//     matters more here than anywhere else: a UAC prompt is a local physical
//     act, and brokering one from a phone would be handing a remote principal
//     a consent dialog they cannot see and the local user did not ask for.
//     What that does NOT hide is the OPERATION'S EXISTENCE AND TIMING. The
//     lease-audit sink writes a `setup:process-etw-register` row for this
//     PTY's lease transitions (cmd/observer/launch_dashboard.go's
//     newLeaseAuditSink deliberately substitutes that label for the handle),
//     and GET /api/remote/audit is capability View. So a paired remote viewer
//     can see THAT an elevated registration was brokered and when; the handle,
//     the PTY's contents and any control over it stay local. Confidentiality
//     of the operation's CONTENT is what the session kind buys — not secrecy
//     that it happened, which is a property an audit log exists to deny.
//   - SINGLE-FLIGHT per label. A duplicate POST while a spawn is still in
//     flight is refused 409. A duplicate POST once the PTY is LIVE is not: the
//     launch manager's labelled setup ops are idempotent by design (shared with
//     the Tailscale and tool-install flows) and hand back the running handle,
//     so the operator's second click re-attaches to the UAC prompt they already
//     have instead of orphaning it. That path is reported as such — see
//     etwRegisterResponse.AlreadyRunning.
//   - PRECONDITIONS ARE RE-CHECKED AT THE SPAWN BOUNDARY, not only in the
//     advisory pass — see below for exactly what that does and does not buy.
//
// It refuses, with a reason naming what the operator must do, when process
// capture or the ETW feed is off, when this is not a Windows host, when the
// task already exists, and when the plan is blocked (the blocked reason names
// the exact missing dependency AND the path it tried).
//
// NOTE ON THE COMMAND POLICY ENGINE: this spawn deliberately needs NO
// carve-out, and none was added. The agent-command policy engine judges tool
// calls made BY an observed agent; it is not in this path. Two independent
// confirmations, neither of them a code reading:
//
//   - Empirically, a SpecSetup spawned with engine-DENIED argv runs anyway.
//   - Structurally, `go list -deps ./internal/termsession` contains neither
//     internal/policy nor internal/guard, and launchManagerAdapter.CreateSetup
//     calls termsession.Create directly — bypassing termsvc, which is where the
//     AI-launch policy lives.
//
// This matters because the argv here is a `powershell -Command Start-Process
// -Verb RunAs` WRAPPER, and wrapper shapes are exactly what the two prior
// R-155 allow-list bypasses used. Widening an allow-list to admit this shape
// would have been a real regression for no gain. If a future change ever routes
// setup spawns through the engine, the fix is to narrow THAT path, not to
// broaden the allow-list.
func (s *Server) handleProcessETWRegister(w http.ResponseWriter, r *http.Request) {
	// Confirm token FIRST (it also enforces POST + application/json), so a
	// cross-origin or token-less caller never reaches any probe, let alone a
	// spawn. The body is deliberately not read at all.
	if !requireConfirmToken(w, r) {
		return
	}
	if s.opts.LaunchManager == nil {
		// Q16: the elevation-prompt PTY here is exactly as ConPTY-capable as
		// the New Terminal launch path since 2026-07-04 — reuse
		// errTerminalUnavailable (audit DI-16) instead of the stale
		// "run under WSL/Linux" claim.
		writeErrStatus(w, errors.New("the elevation prompt cannot be brokered from here: "+errTerminalUnavailable+
			" — run the elevated schtasks command shown on the card yourself"), http.StatusServiceUnavailable)
		return
	}
	if s.opts.ConfigPath == "" {
		writeErrStatus(w, errors.New("this dashboard was started without a config path, so the ETW setup command "+
			"cannot be composed (it needs the listen address and token path from config.toml)"), http.StatusConflict)
		return
	}

	// Pass 1 — advisory. Same planner, same read-only probe the status
	// endpoint runs, so the refusal the operator sees matches the card.
	plan, code, err := s.planETWRegistration(r.Context())
	if err != nil {
		writeErrStatus(w, err, code)
		return
	}

	// Pass 2 — the spawn boundary. Re-resolve and re-plan immediately before
	// CreateSetup and spawn from THIS plan, the way handleTerminalInstall does
	// for `tailscale`: the task may have been registered out-of-band between
	// the two passes (a concurrent CLI run, a second dashboard tab), and the
	// whole point of the no-/F command is that we never clobber a task that
	// already exists.
	//
	// WHAT THIS ACTUALLY GUARANTEES, precisely: the argv handed to CreateSetup
	// is composed from inputs read on THIS request, after the advisory answer
	// the operator saw — so a stale card cannot spawn a stale command, and a
	// task that appeared in between is seen. It is NOT a guarantee about the
	// state at EXECUTION time. The UAC prompt is answered by a human, possibly
	// minutes later, and in that window the config, the observer.exe on disk,
	// the token file and the task itself can all change. The command is safe
	// there for a different reason: it carries no /F, so a task that appears
	// after the plan is refused rather than overwritten, and schtasks' non-zero
	// exit is reported to the operator verbatim.
	plan, code, err = s.planETWRegistration(r.Context())
	if err != nil {
		writeErrStatus(w, err, code)
		return
	}

	// Fail-closed floor. A plan that authorises a spawn always carries the
	// schtasks tail, but an empty one would elevate a bare `schtasks.exe` —
	// harmless in effect (it prints usage) yet it would put a UAC prompt in
	// front of the operator for nothing, and a consent dialog raised for no
	// reason is exactly how a consent dialog stops being read.
	if strings.TrimSpace(plan.SchtasksArgs) == "" {
		writeErrStatus(w, errors.New("the setup planner authorised a registration but produced no command, "+
			"so nothing was run — this is a bug; please report it"), http.StatusInternalServerError)
		return
	}

	handle, err := s.opts.LaunchManager.CreateSetup(SetupSpec{
		// Built entirely server-side from the planner's resolved inputs. No
		// request field reaches this slice — see the doc comment.
		Argv:  setup.ElevatedRegisterArgv(plan.SchtasksArgs),
		Label: etwRegisterLabel,
	})
	if err != nil {
		writeSetupSpawnErr(w, err)
		return
	}
	state, _ := etwStateOf(plan.Outcome)
	resp := etwRegisterResponse{
		Handle:      handle,
		TaskName:    setup.TaskName,
		Command:     plan.Command,
		Notes:       plan.Notes,
		UACRequired: true,
		PlanState:   state,
	}
	// REUSE, NOT SPAWN. A labelled setup op whose PTY is still live comes back
	// as that PTY's handle with a nil error — deliberate idempotence, shared
	// with the Tailscale and tool-install flows, and NOT this route's to
	// change. What IS this route's job is not to lie about it: the plan just
	// computed can differ from the one the live PTY is running (the operator
	// edits config between two clicks), and reporting the new command beside
	// the old process would tell them a command is running that is not.
	//
	// So the ORIGINAL response is returned verbatim, flagged AlreadyRunning.
	// Handles are unique per session, so handle equality is a sound reuse
	// signal; a genuinely fresh spawn always replaces the record.
	if prev, reused := s.rememberETWRegistration(handle, resp); reused {
		if s.opts.Logger != nil {
			s.opts.Logger.Info("dashboard: elevated ETW task registration already running — reattaching",
				slog.String("task", setup.TaskName), slog.String("command", prev.Command))
		}
		prev.AlreadyRunning = true
		writeJSON(w, prev)
		return
	}
	if s.opts.Logger != nil {
		s.opts.Logger.Info("dashboard: elevated ETW task registration spawned",
			slog.String("task", setup.TaskName), slog.String("command", plan.Command))
	}
	writeJSON(w, resp)
}

// etwRegisterRecord is what the last elevated-registration PTY was started
// with. One entry is all that can exist: the route's single-flight label admits
// one live registration PTY at a time.
type etwRegisterRecord struct {
	handle string
	resp   etwRegisterResponse
}

// rememberETWRegistration records a fresh spawn, or reports that this handle is
// a REUSED live PTY and returns what that PTY was actually started with.
//
// reused=false for a handle we have not seen, which is also the honest answer
// after a daemon restart (the record is in-memory, the PTY is not): a fresh
// spawn is exactly what the manager just did in that case.
func (s *Server) rememberETWRegistration(handle string, resp etwRegisterResponse) (etwRegisterResponse, bool) {
	s.etwRegisterMu.Lock()
	defer s.etwRegisterMu.Unlock()
	if handle != "" && s.etwRegisterOps.handle == handle {
		return s.etwRegisterOps.resp, true
	}
	s.etwRegisterOps = etwRegisterRecord{handle: handle, resp: resp}
	return resp, false
}

// planETWRegistration re-runs the whole detection ladder — load config, resolve
// inputs, probe, plan — and returns the plan ONLY when it authorises a
// registration spawn. Otherwise it returns the honest refusal and its status.
//
// It is a function rather than inline code precisely so the advisory pass and
// the spawn-boundary pass are the SAME check: a re-check that drifted from the
// check it re-runs would be worse than no re-check at all.
//
// Every refusal names the thing the operator must change. None of them is a
// generic "not ready".
func (s *Server) planETWRegistration(ctx context.Context) (setup.Plan, int, error) {
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		return setup.Plan{}, http.StatusInternalServerError,
			errors.New("config.toml at " + s.opts.ConfigPath + " could not be read, so the ETW setup command " +
				"cannot be composed: " + err.Error())
	}
	in := setup.ResolveInputs(ctx, cfg.Observer.Process, filepath.Dir(cfg.Observer.DBPath), s.etwSetupEnv())
	plan := setup.PlanTask(in)

	switch plan.Outcome {
	case setup.OutcomeManual, setup.OutcomeUnknown:
		return plan, http.StatusOK, nil
	case setup.OutcomeSkip:
		return setup.Plan{}, http.StatusBadRequest, etwSkipRefusal(in, s.opts.ConfigPath)
	case setup.OutcomePresent:
		return setup.Plan{}, http.StatusConflict,
			errors.New("the Scheduled Task \"" + setup.TaskName + "\" is already registered — it was left " +
				"untouched. To change it, delete it first (elevated): schtasks.exe /Delete /TN \"" +
				setup.TaskName + "\" /F")
	case setup.OutcomeBlocked:
		// plan.Reason is the §W4.6 #6 wording: it names the exact missing
		// dependency AND, when a path WAS configured, the path it tried. Pass
		// it through verbatim rather than summarising it away.
		return setup.Plan{}, http.StatusBadRequest,
			errors.New("the elevated Scheduled Task cannot be set up yet — " + plan.Reason +
				". Nothing was registered.")
	default:
		// An outcome this build does not map. Refuse; do not round it to the
		// nearest-looking one and spawn a privileged process on the guess.
		return setup.Plan{}, http.StatusInternalServerError,
			errors.New("the setup planner returned an outcome this build does not recognise, so no elevated " +
				"command was run")
	}
}

// etwSkipRefusal spells out WHICH skip this is. The planner collapses two
// unrelated situations into OutcomeSkip — the feature is off, or this host has
// no Task Scheduler at all — and they need opposite advice, so a single "not
// applicable" would send half of callers to the wrong fix. Mirrors PlanTask's
// own gate order, so a host that is neither Windows nor enabled reports the
// actionable reason.
//
// "Off" is TWO switches, and the message names the ones that are actually off.
// [observer.process.etw] opens the accept listener, but the master
// [observer.process] switch gates the subsystem that constructs it — with the
// master off, runProcessObserver returns early, so a task registered here would
// install and then reconnect forever against a listener that never starts.
// Naming only the ETW key in that state would send the operator to set a key
// that changes nothing.
func etwSkipRefusal(in setup.Inputs, configPath string) error {
	if !in.Enabled {
		keys := "[observer.process].enabled and [observer.process.etw].enabled"
		switch {
		case in.ProcessEnabled && !in.ETWEnabled:
			keys = "[observer.process.etw].enabled"
		case !in.ProcessEnabled && in.ETWEnabled:
			keys = "[observer.process].enabled (the master switch — the whole process-capture subsystem, " +
				"including the listener the task dials into, is skipped without it)"
		}
		return errors.New("the elevated ETW capturer feed is turned off — set " + keys + " = true in " +
			configPath + " (the card's toggle writes both), restart the daemon, then register the task")
	}
	return errors.New("this host has no schtasks.exe, so there is no Windows Task Scheduler to register a task " +
		"with — the elevated ETW capturer is a Windows-only feed and everything else keeps working without it")
}
