package dashapi

import (
	"errors"
	"io"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termcore"
)

// LaunchManager is the dashboard's seam onto internal/termsession (the
// embedded web-terminal PTY registry). It is DEFINED here, not imported, so
// the dashboard package carries no dependency on termsession's concrete
// types - the same injected-seam discipline as BuildHandoff/DemoSeeder. cmd
// wires a thin adapter that injects the observer BinPath and translates
// types. Dispatch is on capability shape (the LaunchSpec set), never tool
// name.
type LaunchManager interface {
	// Create spawns a PTY-backed launcher and returns its opaque handle.
	Create(spec LaunchSpec) (handle string, err error)
	// CreateFresh spawns a FRESH agent (no --continue-from) after the
	// application service validates the operator's fresh-launch opt-in
	// ([terminal.launch]: allow_fresh_agent + allowed_tools +
	// allowed_project_roots). It returns the opaque handle. F1.
	CreateFresh(spec FreshLaunchSpec) (handle string, err error)
	// CreateResume spawns a NATIVE resume of a CLOSED session (session-attach
	// design Phase 3): a fresh dashboard-owned PTY running the tool's own resume
	// mechanism (claude `--resume <id>`, codex `resume <id>`) so the real prior
	// transcript reopens - NOT a distilled fork. The application service enforces
	// the SAME fresh-launch opt-in as CreateFresh (a dashboard-initiated Execute
	// respects the allow-lists, unlike the owner-only CLI attach socket). It
	// returns the opaque handle AND the durable run id so the response carries
	// both. P3.
	CreateResume(spec ResumeLaunchSpec) (handle string, runID string, err error)
	// CreateGUI spawns a DETACHED IDE / desktop application - no PTY, no
	// handle, no terminal tab. The application service enforces the SAME
	// [terminal.launch] opt-in as CreateFresh, keyed by the GUI id, plus its
	// own "is this an ADVERTISED GUI row" gate. It returns a receipt (run id,
	// pid, and the honest wrap verdict) rather than a terminal token, because
	// there is nothing for the browser to attach to. T2.
	CreateGUI(spec GUILaunchSpec) (GUILaunchResult, error)
	// GUIRuns lists this daemon's GUI launches, newest first, including exited
	// ones (bounded in-memory history). A detached app never appears in
	// Snapshot - it owns no PTY - so this is the only live view of it.
	GUIRuns() []GUIRunInfo
	// CreateSetup spawns a fixed, server-derived local operator SETUP command
	// (SetupSpec.Argv - e.g. the one-time Tailscale operator grant) in a PTY,
	// bypassing the AI-launch policy / terminal_run identity / OOB channel. The
	// resulting session is LOCAL-WRITER-ONLY (a remote principal can never
	// acquire its writer lease). It returns the opaque handle. The caller MUST
	// build Argv from a server-side helper, never from request input.
	CreateSetup(spec SetupSpec) (handle string, err error)
	// Subscribe registers a read-only viewer (§4.α.1 output fan-out). Every
	// attach - local or remote - starts as a viewer; input requires a separate
	// writer lease. The caller MUST Unsubscribe. This is the OWNER-LOCAL path.
	Subscribe(handle string) (LaunchSubscription, error)
	// SubscribeRemote is the REMOTE-principal viewer path. It refuses a SpecSetup
	// (privileged, local-only) session - whose output can echo a typed sudo
	// password / login URL - mirroring AcquireWriterRemote's write-side pin at
	// the READ seam; every other session subscribes normally. Used by the
	// remote-exposed /ws/launch bridge so a paired remote device can never read a
	// setup PTY.
	SubscribeRemote(handle string) (LaunchSubscription, error)
	// IsSetupSession reports whether a handle is a SpecSetup (privileged,
	// local-only) session. The dashboard redacts these from remotely-visible
	// snapshots and refuses their remote termination. Unknown handle ⇒ false.
	IsSetupSession(handle string) bool
	// IsRemoteSensitiveSession reports whether a handle is a remote-VIEW
	// sensitive run: an external `observer <tool> --attach` session (KindAttach)
	// OR a native resume of a real closed transcript (KindResume) - both bind a
	// daemon-owned PTY to a REAL external transcript whose TUI can echo
	// secrets/customer data. Whether the dashboard exposes such a handle to a
	// remote-exposed caller (its snapshot row via visibleSnapshot and its
	// websocket subscription via handleLaunchWS) is governed by the
	// [remote].allow_terminal_view toggle, which now DEFAULTS TRUE (§3.2) - set
	// it false to restore the deny-read posture. Branches on run KIND (the shared
	// termrun.IsRemoteSensitiveKind table), never a tool name. Unknown handle ⇒
	// false.
	IsRemoteSensitiveSession(handle string) bool
	// Unsubscribe releases a viewer's subscription (child survives for
	// reconnect).
	Unsubscribe(sub LaunchSubscription)
	// AcquireWriterLocal grants the owner-local exclusive writer lease - the
	// loopback path (CapabilityLocal provenance), never refused, always takes
	// over an incumbent remote writer (§4.α.2a/§4.α.3).
	AcquireWriterLocal(handle string) (LaunchWriter, error)
	// AcquireWriterRemote grants a remote writer lease after the cmd adapter
	// runs the single §4.δ authorization conjunction over the request-derived
	// inputs and mints the unforgeable grant. The dashboard passes plain
	// strings; the grant type never crosses this seam.
	AcquireWriterRemote(req RemoteWriterRequest) (LaunchWriter, error)
	// Close reaps the session's process tree and removes it.
	Close(handle string)
	// Snapshot lists live sessions (Phase 3 running-session list).
	Snapshot() []LaunchInfo
	// SessionForRun resolves a durable run id to the observer session id that
	// correlation has linked the run's PTY to, if any. It is the run→"driving
	// session" lookup handleAttachSessions uses to key a handoff row by its
	// FORKED session (the session the PTY is actually driving) rather than the
	// SOURCE session the spec stamped at spawn. Returns ("", false) when no link
	// exists yet (~10-30 s post-spawn) or the run is unknown - the caller
	// fails open to an empty session id, never crashing the list. Delegates to
	// termsvc.SessionForRun; the dashboard never imports termsvc.
	SessionForRun(runID string) (sessionID string, ok bool)
	// RevokeAllRemoteWriters revokes every live session's REMOTE-held writer
	// lease (leaving any owner-LOCAL loopback writer untouched) through the ONE
	// termsession revocation funnel - the manager-level global kill the admin
	// transitions (remote disable / rotate / allow_terminal→false) drive so a
	// live remote writer is actually terminated, not merely blocked for future
	// acquires. Returns the count revoked. The cmd adapter delegates to
	// termsession.Manager.RevokeAllRemoteWriters; the dashboard never imports it.
	RevokeAllRemoteWriters(reason string) int
	// RevokeRemoteWriterByHolder revokes the REMOTE writer lease whose holder key
	// equals the passed key - the FULL device-session hash (deviceSessionKey /
	// SessionInfo.ID / grant.HolderKey()), NOT the 8-char display fingerprint -
	// if any, through the same funnel. It is the single-device kill a device-
	// session revoke drives; the caller resolves the device to its full session
	// hash first, so the match hits exactly one lease with no 8-char-prefix
	// over-revoke. The owner-LOCAL writer is never matched. Returns whether a
	// lease was revoked.
	RevokeRemoteWriterByHolder(holderKey, reason string) bool
}

// LaunchSubscription is one read-only viewer of a terminal session. It streams
// PTY output (replay then live tail); its input never reaches the PTY.
// *termsession.Subscription satisfies it structurally.
type LaunchSubscription interface {
	io.Reader
	Done() <-chan struct{}
	Exited() (bool, int)
	// Lost is the bytes this viewer missed to the drop-oldest ring (a gap).
	Lost() int64
}

// LaunchWriter is the exclusive right to drive a session's PTY. Its Write /
// Resize reach the PTY only while the lease is live; a revoked/taken-over lease
// returns an error (the server-side input-frame drop, §4.β).
// *termsession.WriterLease satisfies it structurally.
type LaunchWriter interface {
	io.Writer
	Resize(rows, cols uint16) error
	// Revoked is closed when the lease is revoked/taken-over/expired so the WS
	// bridge can tell the (remote) writer it lost control.
	Revoked() <-chan struct{}
	// Release voluntarily yields the lease (local yield / disconnect).
	Release()
	// Holder is the lease holder identity ("local" or a device fingerprint).
	Holder() string
	// RevokeIsTakeover reports (meaningfully only AFTER Revoked() has closed)
	// whether the lease ended because another granted writer superseded it. On the
	// remote bridge a takeover only DEMOTES the client to a viewer (the device
	// session is still valid); any other termination - an admin/device revoke,
	// an expiry, or teardown - CLOSES the socket. *termsession.WriterLease
	// satisfies it structurally.
	RevokeIsTakeover() bool
}

// RemoteWriterRequest carries the request-derived inputs for a remote writer
// acquire. The cmd adapter runs termlease.Authorize over these (device session +
// allow_terminal + launch policy + single-use capability + bound confirm) and
// mints the unforgeable grant; the dashboard never sees the grant type.
type RemoteWriterRequest struct {
	Handle          string
	DeviceSessionID string
	CapabilityToken string
	Confirm         string
	// RemoteExposed marks that the request arrived on a remotely-exposed
	// execute-classified route (listener provenance, §4.4).
	RemoteExposed bool
}

// LaunchSpec is the dashboard's server-derived launch request. It carries no
// BinPath - the cmd adapter injects os.Executable() so a client can never
// influence which binary runs.
type LaunchSpec struct {
	Subcommand  string
	SessionID   string
	Carry       string
	FromMessage int
	Rows        uint16
	Cols        uint16
}

// FreshLaunchSpec is the dashboard's server-derived FRESH-launch request (F1).
// Tool is the client-chosen tool NAME (validated against the operator's
// allow-list by the application service); Subcommand is resolved server-side
// from the capability registry; ProjectRoot is the only client-influenced path
// and is canonicalized + allow-list-checked before spawn. No BinPath, no argv.
type FreshLaunchSpec struct {
	Tool        string
	Subcommand  string
	ProjectRoot string
	Rows        uint16
	Cols        uint16
	// Shell requests a fresh PLAIN SHELL instead of an AI tool. When true,
	// Tool/Subcommand are ignored by the application service - see
	// handleTerminalLaunch's shellPseudoTool branch, gated by
	// [terminal.launch].allow_shell instead of allowed_tools.
	Shell bool
	// Model is an optional client-chosen model identifier for the New
	// Terminal model picker (B5). It is validated server-side by
	// handleTerminalLaunch (re-derived membership against
	// modelSuggestionsFor's own output - never trusted verbatim from the
	// client) before being threaded down; an invalid or unknown value is
	// silently dropped so the launch proceeds with the tool's own
	// default, never a 400 and never a blocked launch. The composition
	// into argv/env happens in termsvc.LaunchFresh via
	// integration.ModelLaunch, so the daemon's own capability registry -
	// not this handler - decides whether a model is an arg or an env var.
	Model string
	// Sandbox requests a B9 filesystem-isolated launch (bwrap). By the time
	// this reaches CreateFresh, handleTerminalLaunch has already run the
	// fail-CLOSED sandbox validation (nil seam / unavailable verdict /
	// unknown workspace source / missing project root / unmapped tool all
	// refuse the launch BEFORE this spec is built) - so a true value here
	// is a request the server has already confirmed it CAN honour. Ignored
	// by the application service when Shell is set (sandboxing a bare
	// shell is not v1 scope).
	Sandbox bool
	// WorkspaceSource selects how the sandboxed workspace is prepared:
	// "live" (default; no copy - the workspace IS ProjectRoot),
	// "clone-local", "clone-remote", or "worktree" (off by default).
	// handleTerminalLaunch defaults an empty client value to "live" and
	// validates it by MEMBERSHIP against the server's own probed Sources
	// list before it ever reaches here. Ignored when Sandbox is false.
	WorkspaceSource string
	// WorkspaceRemote is the remote URL for a "clone-remote"
	// WorkspaceSource. Ignored otherwise.
	WorkspaceRemote string
	// WorkspaceBranch is an optional branch to check out after clone/
	// worktree. Ignored for "live".
	WorkspaceBranch string
	// Backend is the isolation row the New Terminal picker chose for this
	// launch, already re-validated by handleTerminalLaunch against the
	// daemon's probed rows; "" lets selection pick (it never takes a beta
	// row, ruling P-062). Ignored when Sandbox is false.
	Backend string
	// SignInSeed and SignInAsk carry the New Terminal dialog's answer to
	// copying the tool's sign-in into the box, and that it can ask (lane
	// BOXSIGNIN; termsvc.FreshRequest). Ignored when Sandbox is false.
	SignInSeed *bool
	SignInAsk  bool
}

// SSHLaunchSpec is the dashboard's server-derived SSH remote-system request.
// Profile is the ONLY client-influenced field, and it is a NAME the application
// service must find in the operator's own config - see LaunchManager.CreateSSH.
type SSHLaunchSpec struct {
	Profile string
	Rows    uint16
	Cols    uint16
}

// SSHProfileInfo is one picker row. It carries what the UI needs to let an
// operator recognise a system and nothing more: KeyHint is the key file's
// BASENAME (so the dashboard never discloses the operator's filesystem layout)
// and there is no field for key material, because none exists anywhere in this
// feature.
type SSHProfileInfo struct {
	Name    string `json:"name"`
	Label   string `json:"label"`
	Target  string `json:"target"`
	Jump    string `json:"jump,omitempty"`
	HasKey  bool   `json:"has_key"`
	KeyHint string `json:"key_hint,omitempty"`
}

// ResumeLaunchSpec is the dashboard's server-derived NATIVE-resume request
// (P3). Tool is the client-chosen tool NAME (validated against the fresh-launch
// allow-list by the application service); Subcommand is resolved server-side
// from the capability registry; SessionID is the closed session being resumed;
// ExtraArgs is the resume tail composed server-side via integration.ResumeArgs
// (uniformly `--resume <id>`); ProjectRoot is canonicalized + allow-list-checked
// before spawn. No BinPath, no raw argv.
type ResumeLaunchSpec struct {
	Tool        string
	Subcommand  string
	SessionID   string
	ProjectRoot string
	ExtraArgs   []string
	Rows        uint16
	Cols        uint16
}

// SetupSpec is a server-derived local operator setup command run in a PTY (the
// dashboard-tailnet-guided-setup plan §B). Argv is the complete argv built by
// the handler from a fixed helper (tailnet.OperatorGrantArgv) - NEVER request
// input; Label is a short human tag for logs. The spawned session is
// local-writer-only, launches no agent, and mints no terminal_run.
type SetupSpec struct {
	Argv  []string
	Label string
	Rows  uint16
	Cols  uint16
}

// LaunchInfo is a running-session snapshot row (Phase 3 list).
type LaunchInfo struct {
	ID         string `json:"token"`
	Subcommand string `json:"subcommand"`
	SessionID  string `json:"session_id"`
	// Kind is the terminal_run kind this PTY handle belongs to ("attach" /
	// "handoff" / "fresh" / "resume"), resolved from the run identity
	// (session-attach design Phase 2). Empty when the session predates
	// run-identity wiring. It drives the dashboard's "Jump in" gating: ANY valid
	// kind on a live, non-setup handle is joinable, because every such row is a
	// real daemon-owned PTY with exact liveness. A kindless (empty) row is not a
	// joinable run.
	Kind string `json:"kind,omitempty"`
	// Tool is the target tool NAME (e.g. "claude-code") the run launched, as
	// distinct from Subcommand (the observer launcher verb). Empty when unknown.
	Tool string `json:"tool,omitempty"`
	// RunID is the durable terminal_run identity this PTY handle belongs to
	// (F1); empty when the session predates the run-identity wiring.
	RunID string `json:"run_id,omitempty"`
	// HasProjectRoot reports whether this run has a resolvable project root
	// (Arc A). It lets the dashboard enable/disable the per-terminal Files/Git
	// panel buttons straight from the /api/launch/sessions rehydrate with no
	// extra round-trip. The raw path is DELIBERATELY not carried here (this
	// struct flows to remote viewers); the path itself is served only by the
	// gated project-panel endpoint.
	HasProjectRoot bool      `json:"has_project_root"`
	CreatedAt      time.Time `json:"created_at"`
	// Attached is retained for wire compatibility: true when at least one viewer
	// is subscribed. Viewers is the exact read-only subscriber count and
	// WriterHolder identifies the controlling writer ("local" or a remote device
	// fingerprint, empty when none) - the §4.α controller display.
	Attached     bool   `json:"attached"`
	Viewers      int    `json:"viewers"`
	WriterHolder string `json:"writer_holder,omitempty"`
	// Setup marks a SpecSetup (privileged, local-only) session. It is redacted
	// from snapshots served to REMOTE callers (visibleSnapshot), so a remote
	// device never even learns the handle exists.
	Setup    bool `json:"setup,omitempty"`
	Exited   bool `json:"exited"`
	ExitCode int  `json:"exit_code"`
	// PTY geometry (Feature 2): InitialRows/InitialCols are the spawn size (or
	// the first resize when the launch Spec was 0×0); Rows/Cols are the current
	// live size. Zero means not yet known. Surfaced so REST + the terminal UI can
	// report / restore the session's real dimensions.
	InitialRows uint16 `json:"initial_rows,omitempty"`
	InitialCols uint16 `json:"initial_cols,omitempty"`
	Rows        uint16 `json:"rows,omitempty"`
	Cols        uint16 `json:"cols,omitempty"`
	// Sandboxed reports whether this run was launched through the B9
	// Sandboxer seam (bwrap-isolated). In-memory only - see B9 plan §10
	// ledger G19 (no durable "was this run sandboxed?" column exists).
	// Drives the dashboard's "sandboxed" pill on the Terminals list/header.
	Sandboxed bool `json:"sandboxed,omitempty"`
	// Isolation is the sandboxed run's G19 evidence for the run pill
	// (sandbox plan v2 section 9): closed enums only, no path, so it is
	// safe on the snapshot remote viewers see. Nil for an unsandboxed run.
	Isolation *LaunchIsolation `json:"isolation,omitempty"`
}

// LaunchIsolation is the run pill's view of a sandboxed run: the class
// built, the backend, the network tier, the computed capture level and the
// rule that decided it ("C6" with "full" renders as "full
// (gateway-guarded)"), and this host's verification of the backend.
type LaunchIsolation struct {
	Class        string `json:"class"`
	Backend      string `json:"backend,omitempty"`
	EgressTier   string `json:"egress_tier,omitempty"`
	CaptureLevel string `json:"capture_level,omitempty"`
	CaptureRule  string `json:"capture_rule,omitempty"`
	Verification string `json:"verification,omitempty"`
	// CaptureDegraded says the run's capture was lowered after launch
	// (sandbox plan v2 section 5.2), and CaptureCauses why: the closed
	// cause vocabulary of internal/sandboxrelayd (hooks_drifted means the
	// box's hook configuration no longer matches the launch's, so capture
	// is no longer complete).
	CaptureDegraded bool     `json:"capture_degraded,omitempty"`
	CaptureCauses   []string `json:"capture_causes,omitempty"`
}

// ErrLaunchTooMany signals the concurrent-session cap was hit (429).
var ErrLaunchTooMany = errors.New("too many concurrent terminal sessions")

// ErrLaunchUnsupported signals the platform can't host a PTY (501) -
// a native-Windows daemon (run under WSL instead).
var ErrLaunchUnsupported = errors.New("embedded terminal is not supported on this platform")

// ErrLaunchExecuteUnavailable signals the remote writer-lease path is not
// wired (the §4.γ/§4.δ authorizer is nil) - a fail-closed 503-shaped state.
var ErrLaunchExecuteUnavailable = errors.New("remote terminal writer is not configured")

// ErrLaunchFreshDisabled signals [terminal.launch].allow_fresh_agent is
// off (403). Fresh-agent launch is a conscious opt-in, never migrated on.
var ErrLaunchFreshDisabled = errors.New("fresh-agent launch is disabled (set [terminal.launch].allow_fresh_agent)")

// ErrLaunchToolNotAllowed signals the tool is not in the operator's
// [terminal.launch].allowed_tools allow-list (403).
var ErrLaunchToolNotAllowed = errors.New("tool is not in the fresh-launch allow-list")

// ErrLaunchProjectRootDenied signals the requested project_root failed the
// allow-list / canonicalization check (400).
var ErrLaunchProjectRootDenied = errors.New("project root not permitted")

// ErrLaunchShellDisabled signals [terminal.launch].allow_shell is off
// (403). Plain-shell launch is a SEPARATE conscious opt-in from
// allow_fresh_agent, never migrated on.
var ErrLaunchShellDisabled = errors.New("plain-shell launch is disabled (set [terminal.launch].allow_shell)")

// ErrLaunchSetupInFlight signals a setup session of the same kind
// (operator-grant / login / install) is already starting - the setup
// single-flight refusal (409). Prevents a POST-spam from spawning many
// privileged PTYs.
var ErrLaunchSetupInFlight = errors.New("a setup session of this kind is already starting")

// ErrLaunchSSHDisabled signals [terminal.ssh].enabled is off (403). An SSH
// shell runs arbitrary commands on ANOTHER machine, so it is a conscious
// opt-in separate from allow_shell (which grants only a local shell).
var ErrLaunchSSHDisabled = errors.New("SSH remote-system launch is disabled (set [terminal.ssh].enabled)")

// ErrLaunchSSHProfileUnknown signals the requested profile name is not in
// the operator's [[terminal.ssh.profiles]] list (400). This is the gate
// that makes a client-supplied NAME safe: a destination the operator never
// wrote down can never be reached.
var ErrLaunchSSHProfileUnknown = errors.New("no such SSH profile")

// ErrLaunchSSHProfileInvalid signals the named profile failed re-validation
// at launch - a malformed field, or a key_path that no longer resolves to a
// regular file (400).
var ErrLaunchSSHProfileInvalid = errors.New("SSH profile is not valid")

// ErrLaunchSandboxRequired signals the organization's org_disallow choice
// for a proxied tool with no sandbox available (D-178 / D-221): the guard
// enforces, the tool's only containment lever is the sandbox, none can be
// built here, and the org does not accept an unsandboxed launch (403). The
// wrapped error carries the developer-facing reason.
var ErrLaunchSandboxRequired = errors.New("launch refused by your organization's sandbox policy")

// ControlDenialReason is the stable wire taxonomy for a refused remote writer
// acquire. Exactly TWO values are permanent verdicts on the presented
// credential - ControlDenialAuth (it was judged and rejected) and
// ControlDenialAuthRevoked (no standing secret exists on the server at all).
// Callers must not clear a standing secret for any other reason.
type ControlDenialReason string

const (
	// ControlDenialAuth means the capability/confirm or standing secret failed
	// its credential check - the credential WAS judged and rejected. It is the
	// ONLY reason a device may treat as proof that a saved standing secret is
	// dead (and therefore the only one it may clear the secret for).
	ControlDenialAuth ControlDenialReason = "auth"
	// ControlDenialAuthTransient means the credential leg refused WITHOUT ever
	// judging the presented credential - standing access is currently switched
	// off, the attempt was rate-limited, or the acquire raced an admin
	// transition (the standing generation moved between verify and install).
	// The refusal is exactly as hard as ControlDenialAuth; the difference is
	// purely diagnostic, and the device MUST keep its saved standing secret.
	// Added 2026-07-25: these cases used to report "auth", which made a
	// momentary rate-limit or a disabled-then-re-enabled toggle wipe a valid
	// secret and force the operator to mint a new one. Clients that predate this
	// value fall through their default branch to the neutral "temporarily
	// unavailable, secret not cleared" handling, which is the correct behaviour.
	ControlDenialAuthTransient ControlDenialReason = "auth_transient"
	// ControlDenialAuthRevoked means the standing terminal-control secret has
	// been REVOKED on this server and not re-provisioned: the revoke path
	// deletes the hash at rest, so there is nothing left for any device's saved
	// secret to match, now or later (a fresh mint issues a DIFFERENT secret).
	// Like ControlDenialAuth it is a PERMANENT verdict on the presented
	// credential and the device should clear it - unlike ControlDenialAuth the
	// secret was never compared, because there was nothing to compare it
	// against.
	//
	// Added 2026-07-25 (operator decision A2). It splits the one genuinely
	// terminal case out of ControlDenialAuthTransient, which had swept up
	// "revoked forever" with "switched off for a minute" and left devices
	// retrying a dead secret indefinitely. The server emits it ONLY when it can
	// prove no secret exists at rest; a merely-disabled gate stays transient.
	// Clients that predate this value fall through to their default branch and
	// keep the secret, which is the safe direction.
	ControlDenialAuthRevoked ControlDenialReason = "auth_revoked"
	// ControlDenialHeldLocally means a local/native writer holds control and the
	// authenticated-remote takeover policy is disabled.
	ControlDenialHeldLocally ControlDenialReason = "held_locally"
	// ControlDenialHeldByRemote means another remote writer holds control and the
	// authenticated-remote takeover policy is disabled.
	ControlDenialHeldByRemote ControlDenialReason = "held_by_remote"
	// ControlDenialTerminalDisabled means [remote].allow_terminal is off.
	ControlDenialTerminalDisabled ControlDenialReason = "terminal_disabled"
	// ControlDenialSessionInvalid means the paired device session is no longer valid.
	ControlDenialSessionInvalid ControlDenialReason = "session_invalid"
	// ControlDenialPolicyDenied means listener/launch/session policy refused the target.
	ControlDenialPolicyDenied ControlDenialReason = "policy_denied"
	// ControlDenialNotFound means the terminal session no longer exists.
	ControlDenialNotFound ControlDenialReason = "not_found"
	// ControlDenialUnavailable means the writer path or a raced lifecycle state
	// was unavailable without proving any credential defect.
	ControlDenialUnavailable ControlDenialReason = "unavailable"
)

// ControlDeniedError carries a typed acquire refusal across the cmd adapter
// boundary without importing internal/termsession into dashboard. Cause remains
// unwrap-able for backend tests and diagnostics. CapabilityConsumed is true
// only when a valid single-use capability was burned before a later lease-policy
// refusal, allowing the audit/UI to request a fresh approval honestly.
type ControlDeniedError struct {
	Reason             ControlDenialReason
	CapabilityConsumed bool
	Cause              error
}

// Error implements error without exposing secret-adjacent details.
func (e *ControlDeniedError) Error() string {
	if e == nil {
		return "terminal control denied"
	}
	return "terminal control denied: " + string(e.Reason)
}

// Unwrap preserves the adapter's underlying sentinel for internal callers.
func (e *ControlDeniedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// NewControlDeniedError constructs a typed dashboard-boundary denial.
func NewControlDeniedError(reason ControlDenialReason, capabilityConsumed bool, cause error) error {
	return &ControlDeniedError{Reason: reason, CapabilityConsumed: capabilityConsumed, Cause: cause}
}

// SpawnAuditKind maps a spawned run KIND to its metadata-only remote_audit
// event kind (session-attach design §3.5). Table-driven per CLAUDE.md #5 - a new
// spawnable kind is one row, never a nested branch - and the SINGLE vocabulary
// both spawn sites use (the dashboard resume handler + the cmd-side attach host)
// instead of bespoke inline strings. Empty for a kind with no spawn-audit event.
func SpawnAuditKind(k termcore.Kind) string {
	switch k {
	case termcore.KindAttach:
		return "terminal_attach"
	case termcore.KindResume:
		return "terminal_resume"
	default:
		return ""
	}
}

// RecentModelsWindow and RecentModelsLimit bound the store history query
// behind the Options.RecentModels seam (B5): 180 days / 12 rows keeps the
// "recent" list to genuinely-recent, genuinely-distinct choices without an
// unbounded scan of token_usage. Exported so the cmd-side seam constructor
// (recentModelsSeam) uses the same values the picker's semantics document -
// one authority, not a duplicated literal.
const (
	RecentModelsWindow = 180 * 24 * time.Hour
	RecentModelsLimit  = 12
)

// ToolPreflight is the wire shape of GET /api/terminal/launch/preflight - the
// pre-launch binary-resolution verdict for a launchable tool
// (tool-binary-resolution arc). It tells the New-Terminal dialog, BEFORE a
// launch, whether the daemon can resolve the tool's binary and - when it cannot
// - the grounded install command to fix it. The install ARGV is NEVER carried
// here: InstallCommand is the human Display string only; the server owns argv
// (registry constants) at the install endpoint. Produced by the nil-able
// Options.ToolPreflight seam, so the dashboard package carries no dependency on
// internal/toolresolve (CLAUDE.md #2).
type ToolPreflight struct {
	Tool string `json:"tool"`
	// Kind is the launch SHAPE this verdict describes: "gui" for an IDE /
	// desktop-app row, omitted for the terminal (PTY) rows this endpoint has
	// always served. It exists so the dialog can render the right affordances
	// (no model picker, no sandbox, a project-root control only when the app
	// takes one) from the preflight alone, without a second lookup - and so a
	// client that predates GUI rows sees an unchanged payload.
	Kind           string   `json:"kind,omitempty"`
	Verdict        string   `json:"verdict"`
	Bin            string   `json:"bin,omitempty"`
	Notes          []string `json:"notes,omitempty"`
	InstallCommand string   `json:"install_command,omitempty"`
	CanInstall     bool     `json:"can_install"`
	// InstallNote is the honest-zero companion to InstallCommand (audit
	// DI-03): the grounded REASON there is no guided install for this tool on
	// this OS, so the dialog's not-installed branch never dead-ends with a
	// bare "X is not installed." and no next step. It is filled by the seam
	// ONLY when no install plan exists - never alongside a usable
	// InstallCommand - and is omitted from the wire when empty.
	InstallNote string `json:"install_note,omitempty"`

	// The fields below are the STRUCTURED facts behind Notes, so a UI phrases
	// its own copy from data instead of rendering the resolver's engineering
	// sentences. Notes stays on the wire unchanged (observer adapters /
	// doctor); every field here is additive and omitted when it does not
	// apply, so an older client sees the payload it always did.

	// RoutingReachesApp reports whether a launch of this GUI row would deliver
	// the observer proxy route to the app - the same guilaunch.Compose verdict
	// the launch itself records as wrap_applied, dry-run here. nil (omitted)
	// when it is not knowable: a terminal row, or a row nothing can launch.
	RoutingReachesApp *bool `json:"routing_reaches_app,omitempty"`
	// RoutingReason is the closed guilaunch.WrapReason cause when
	// RoutingReachesApp is false (e.g. "interop_env_not_propagated").
	RoutingReason string `json:"routing_reason,omitempty"`
	// ConfigOverride is "used" when [launch.tools.<tool>].path supplies the
	// binary, or "missing" when that key is set but nothing is there.
	ConfigOverride string `json:"config_override,omitempty"`
	// MissingInterpreter names the `#!/usr/bin/env <name>` interpreter the
	// resolved script needs and that nothing on the merged PATH provides - the
	// launch would fail at startup.
	MissingInterpreter string `json:"missing_interpreter,omitempty"`
	// InstallNeedsProgram names the program the install command runs when it
	// is on neither the daemon's PATH nor the login shell's.
	InstallNeedsProgram string `json:"install_needs_program,omitempty"`
	// InstallMissingPrereqs lists the host programs the install command's
	// vendor script is grounded to need (integration.InstallHint.Requires)
	// that are not installed here ("a|b" = either one). Non-empty forces
	// CanInstall false: the install would fail inside the vendor script.
	InstallMissingPrereqs []string `json:"install_missing_prereqs,omitempty"`
	// InstallPrereqRemedy is the plain-language fix for
	// InstallMissingPrereqs: the programs, and the package-manager command
	// for this host family. Observer never runs it (it would need sudo).
	InstallPrereqRemedy string `json:"install_prereq_remedy,omitempty"`
	// InstallUnverified is true when the launch target (a Windows packaged
	// app) was asserted from the registry but not probed on this machine.
	InstallUnverified bool `json:"install_unverified,omitempty"`
	// UserInstallHint is the registry's optional plain-language companion to
	// InstallNote (integration.BinaryResolveSpec.UserInstallHint), sent only
	// when there is no guided install - the one install-gap sentence meant
	// for end users.
	UserInstallHint string `json:"user_install_hint,omitempty"`
	// DashboardInstall is the tool's latest guided-install record from THIS
	// dashboard (node-local tool_installs), with whether - and how - it can be
	// uninstalled from here. Omitted when the dashboard never installed the
	// tool (or no record seam is wired): absence means "not installed from
	// here", which is exactly when no Uninstall may be offered.
	DashboardInstall *ToolInstallRecord `json:"dashboard_install,omitempty"`
	// LaunchRuntime is the tool's grounded minimum host runtime checked against
	// the interpreter the resolved shim would run on (e.g. Gemini CLI needs
	// Node.js 20; this machine's node is 18.19.1). Omitted when nothing
	// applies (no grounded requirement, a native binary, not installed). A
	// too_old status means the launch would crash at startup: the launcher
	// refuses it with Remedy, and the dialog disables Start.
	LaunchRuntime *PreflightRuntime `json:"launch_runtime,omitempty"`
	// InstallRuntime is the same requirement checked for the guided-install
	// plan, when its channel runs the tool on the host runtime (npm). A
	// too_old status forces CanInstall false and POST /api/terminal/install
	// refuses with Remedy before anything is installed.
	InstallRuntime *PreflightRuntime `json:"install_runtime,omitempty"`
	// BudgetLaunch is set when the org's managed hard budget will refuse this
	// launch before the tool starts, on a cause that does not depend on the
	// route a launch would carry (T-685): the node's Guard is not enforcing,
	// the tool has no Observer proxy route, or its route can never be
	// proven, and no process cutoff covers it. The dialog shows Reason and
	// Remedy so the refusal is not a dead end. Omitted when the launch is not
	// predictably refused (the launcher still decides).
	BudgetLaunch *PreflightBudgetLaunch `json:"budget_launch,omitempty"`
	// RouteSetup is the next step for a tool whose proxy route lives in its
	// OWN config file when that file is not on this machine yet (T-685): the
	// launch starts unproxied until the developer sets up a provider. Omitted
	// when there is nothing to set up.
	RouteSetup string `json:"route_setup,omitempty"`
}

// PreflightBudgetLaunch is the picker's dry run of the managed-budget launch
// boundary: why the launch would be refused, and what to do about it. Both
// are plain sentences, content-free.
type PreflightBudgetLaunch struct {
	Reason string `json:"reason"`
	Remedy string `json:"remedy"`
}

// PreflightRuntime is the wire form of one minimum-runtime check
// (internal/toolinstall.RuntimeCheck), filled by the cmd-side seam so this
// package imports no resolver.
type PreflightRuntime struct {
	// Runtime is the runtime key ("node").
	Runtime string `json:"runtime"`
	// Display is its product name ("Node.js").
	Display string `json:"display"`
	// Product is the tool's product name ("Gemini CLI").
	Product string `json:"product,omitempty"`
	// Min is the floor as shown to people ("20").
	Min string `json:"min"`
	// Have is the checked interpreter's version; empty when unread.
	Have string `json:"have,omitempty"`
	// Path is the interpreter that was checked.
	Path string `json:"path,omitempty"`
	// Status is ok | too_old | outside_range | unknown | missing. Only
	// too_old blocks; outside_range (above the floor, outside the declared
	// range) is reported only.
	Status string `json:"status"`
	// Remedy is the whole fix for too_old as plain text, one part per line
	// (what is needed and what this machine has, then the command on its own
	// line, then a note). A UI renders the structured parts below instead.
	Remedy string `json:"remedy,omitempty"`
	// Summary is the short too_old sentence ("Gemini CLI needs Node.js 20 or
	// newer. This machine has 18.19.1."), without the path or the fix; for
	// outside_range it is the non-blocking advisory sentence.
	Summary string `json:"summary,omitempty"`
	// FixCommand is the grounded command that installs a newer runtime on
	// this host family; empty when the only grounded advice is FixNote.
	FixCommand string `json:"fix_command,omitempty"`
	// FixNote is the one-line context for FixCommand, or the whole advice
	// when FixCommand is empty.
	FixNote string `json:"fix_note,omitempty"`
	// FloorFrom is where Min came from: "installed" (the installed
	// package's own engines.node) or "registry" (the grounded floor).
	FloorFrom string `json:"floor_from,omitempty"`
	// Range is the vendor's whole declared engines range, set for an
	// outside_range status (T-396), so a UI can name it; Summary carries the
	// sentence ("X declares Node.js >=20 <23. This machine has 24.1.0, ...").
	Range string `json:"range,omitempty"`
}

// Preflight ConfigOverride values.
const (
	PreflightOverrideUsed    = "used"
	PreflightOverrideMissing = "missing"
)
