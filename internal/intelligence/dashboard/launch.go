package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/handoff"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/remoteauth"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// Embedded web-terminal launch surface (docs/session-handoff.md launch
// section). Two endpoints, both inheriting the dashboard's loopback +
// browserGuard trust boundary:
//
//   - POST /api/session/<id>/launch mints an opaque session handle after
//     validating the target tool against the launchable capability set. The
//     argv is built SERVER-SIDE by internal/termsession from the validated
//     Spec; the client never supplies argv or paths. This POST is
//     Origin-checked by browserGuard (CSRF), so a malicious page can't mint
//     a handle.
//   - GET /ws/launch/<handle> upgrades to a websocket bridging the PTY to
//     the browser. coder/websocket's Accept rejects cross-origin upgrades by
//     default (Origin host must equal the request Host), which — together
//     with the opaque handle minted only by the Origin-checked POST — is the
//     CSWSH defense. No browserGuard relaxation is made for the GET.
//
// The whole surface is gated by Options.LaunchManager != nil; cmd wires the
// manager only when [handoff].allow_dashboard_launch is true, so a nil seam
// (503) is the honest "disabled" state.

// LaunchManager is the dashboard's seam onto internal/termsession (the
// embedded web-terminal PTY registry). It is DEFINED here, not imported, so
// the dashboard package carries no dependency on termsession's concrete
// types — the same injected-seam discipline as BuildHandoff/DemoSeeder. cmd
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
	// transcript reopens — NOT a distilled fork. The application service enforces
	// the SAME fresh-launch opt-in as CreateFresh (a dashboard-initiated Execute
	// respects the allow-lists, unlike the owner-only CLI attach socket). It
	// returns the opaque handle AND the durable run id so the response carries
	// both. P3.
	CreateResume(spec ResumeLaunchSpec) (handle string, runID string, err error)
	// CreateGUI spawns a DETACHED IDE / desktop application — no PTY, no
	// handle, no terminal tab. The application service enforces the SAME
	// [terminal.launch] opt-in as CreateFresh, keyed by the GUI id, plus its
	// own "is this an ADVERTISED GUI row" gate. It returns a receipt (run id,
	// pid, and the honest wrap verdict) rather than a terminal token, because
	// there is nothing for the browser to attach to. T2.
	CreateGUI(spec GUILaunchSpec) (GUILaunchResult, error)
	// GUIRuns lists this daemon's GUI launches, newest first, including exited
	// ones (bounded in-memory history). A detached app never appears in
	// Snapshot — it owns no PTY — so this is the only live view of it.
	GUIRuns() []GUIRunInfo
	// CreateSetup spawns a fixed, server-derived local operator SETUP command
	// (SetupSpec.Argv — e.g. the one-time Tailscale operator grant) in a PTY,
	// bypassing the AI-launch policy / terminal_run identity / OOB channel. The
	// resulting session is LOCAL-WRITER-ONLY (a remote principal can never
	// acquire its writer lease). It returns the opaque handle. The caller MUST
	// build Argv from a server-side helper, never from request input.
	CreateSetup(spec SetupSpec) (handle string, err error)
	// Subscribe registers a read-only viewer (§4.α.1 output fan-out). Every
	// attach — local or remote — starts as a viewer; input requires a separate
	// writer lease. The caller MUST Unsubscribe. This is the OWNER-LOCAL path.
	Subscribe(handle string) (LaunchSubscription, error)
	// SubscribeRemote is the REMOTE-principal viewer path. It refuses a SpecSetup
	// (privileged, local-only) session — whose output can echo a typed sudo
	// password / login URL — mirroring AcquireWriterRemote's write-side pin at
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
	// OR a native resume of a real closed transcript (KindResume) — both bind a
	// daemon-owned PTY to a REAL external transcript whose TUI can echo
	// secrets/customer data. Whether the dashboard exposes such a handle to a
	// remote-exposed caller (its snapshot row via visibleSnapshot and its
	// websocket subscription via handleLaunchWS) is governed by the
	// [remote].allow_terminal_view toggle, which now DEFAULTS TRUE (§3.2) — set
	// it false to restore the deny-read posture. Branches on run KIND (the shared
	// termrun.IsRemoteSensitiveKind table), never a tool name. Unknown handle ⇒
	// false.
	IsRemoteSensitiveSession(handle string) bool
	// Unsubscribe releases a viewer's subscription (child survives for
	// reconnect).
	Unsubscribe(sub LaunchSubscription)
	// AcquireWriterLocal grants the owner-local exclusive writer lease — the
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
	// exists yet (~10–30 s post-spawn) or the run is unknown — the caller
	// fails open to an empty session id, never crashing the list. Delegates to
	// termsvc.SessionForRun; the dashboard never imports termsvc.
	SessionForRun(runID string) (sessionID string, ok bool)
	// RevokeAllRemoteWriters revokes every live session's REMOTE-held writer
	// lease (leaving any owner-LOCAL loopback writer untouched) through the ONE
	// termsession revocation funnel — the manager-level global kill the admin
	// transitions (remote disable / rotate / allow_terminal→false) drive so a
	// live remote writer is actually terminated, not merely blocked for future
	// acquires. Returns the count revoked. The cmd adapter delegates to
	// termsession.Manager.RevokeAllRemoteWriters; the dashboard never imports it.
	RevokeAllRemoteWriters(reason string) int
	// RevokeRemoteWriterByHolder revokes the REMOTE writer lease whose holder key
	// equals the passed key — the FULL device-session hash (deviceSessionKey /
	// SessionInfo.ID / grant.HolderKey()), NOT the 8-char display fingerprint —
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
	// session is still valid); any other termination — an admin/device revoke,
	// an expiry, or teardown — CLOSES the socket. *termsession.WriterLease
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
// BinPath — the cmd adapter injects os.Executable() so a client can never
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
	// Tool/Subcommand are ignored by the application service — see
	// handleTerminalLaunch's shellPseudoTool branch, gated by
	// [terminal.launch].allow_shell instead of allowed_tools.
	Shell bool
	// Model is an optional client-chosen model identifier for the New
	// Terminal model picker (B5). It is validated server-side by
	// handleTerminalLaunch (re-derived membership against
	// modelSuggestionsFor's own output — never trusted verbatim from the
	// client) before being threaded down; an invalid or unknown value is
	// silently dropped so the launch proceeds with the tool's own
	// default, never a 400 and never a blocked launch. The composition
	// into argv/env happens in termsvc.LaunchFresh via
	// integration.ModelLaunch, so the daemon's own capability registry —
	// not this handler — decides whether a model is an arg or an env var.
	Model string
	// Sandbox requests a B9 filesystem-isolated launch (bwrap). By the time
	// this reaches CreateFresh, handleTerminalLaunch has already run the
	// fail-CLOSED sandbox validation (nil seam / unavailable verdict /
	// unknown workspace source / missing project root / unmapped tool all
	// refuse the launch BEFORE this spec is built) — so a true value here
	// is a request the server has already confirmed it CAN honour. Ignored
	// by the application service when Shell is set (sandboxing a bare
	// shell is not v1 scope).
	Sandbox bool
	// WorkspaceSource selects how the sandboxed workspace is prepared:
	// "live" (default; no copy — the workspace IS ProjectRoot),
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
}

// SSHLaunchSpec is the dashboard's server-derived SSH remote-system request.
// Profile is the ONLY client-influenced field, and it is a NAME the application
// service must find in the operator's own config — see LaunchManager.CreateSSH.
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
// the handler from a fixed helper (tailnet.OperatorGrantArgv) — NEVER request
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
	// fingerprint, empty when none) — the §4.α controller display.
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
	// Sandboxer seam (bwrap-isolated). In-memory only — see B9 plan §10
	// ledger G19 (no durable "was this run sandboxed?" column exists).
	// Drives the dashboard's "sandboxed" pill on the Terminals list/header.
	Sandboxed bool `json:"sandboxed,omitempty"`
}

// Errors the cmd adapter maps termsession errors onto so the handler can
// pick an honest HTTP status without importing termsession.
var (
	// ErrLaunchTooMany signals the concurrent-session cap was hit (429).
	ErrLaunchTooMany = errors.New("too many concurrent terminal sessions")
	// ErrLaunchUnsupported signals the platform can't host a PTY (501) —
	// a native-Windows daemon (run under WSL instead).
	ErrLaunchUnsupported = errors.New("embedded terminal is not supported on this platform")
	// ErrLaunchAlreadyAttached signals a second client tried to attach. Retained
	// for callers that still map it; the output fan-out (§4.α) no longer rejects
	// a second viewer.
	ErrLaunchAlreadyAttached = errors.New("session already has an attached client")
	// ErrLaunchExecuteUnavailable signals the remote writer-lease path is not
	// wired (the §4.γ/§4.δ authorizer is nil) — a fail-closed 503-shaped state.
	ErrLaunchExecuteUnavailable = errors.New("remote terminal writer is not configured")
	// ErrLaunchFreshDisabled signals [terminal.launch].allow_fresh_agent is
	// off (403). Fresh-agent launch is a conscious opt-in, never migrated on.
	ErrLaunchFreshDisabled = errors.New("fresh-agent launch is disabled (set [terminal.launch].allow_fresh_agent)")
	// ErrLaunchToolNotAllowed signals the tool is not in the operator's
	// [terminal.launch].allowed_tools allow-list (403).
	ErrLaunchToolNotAllowed = errors.New("tool is not in the fresh-launch allow-list")
	// ErrLaunchProjectRootDenied signals the requested project_root failed the
	// allow-list / canonicalization check (400).
	ErrLaunchProjectRootDenied = errors.New("project root not permitted")
	// ErrLaunchShellDisabled signals [terminal.launch].allow_shell is off
	// (403). Plain-shell launch is a SEPARATE conscious opt-in from
	// allow_fresh_agent, never migrated on.
	ErrLaunchShellDisabled = errors.New("plain-shell launch is disabled (set [terminal.launch].allow_shell)")
	// ErrLaunchSetupInFlight signals a setup session of the same kind
	// (operator-grant / login / install) is already starting — the setup
	// single-flight refusal (409). Prevents a POST-spam from spawning many
	// privileged PTYs.
	ErrLaunchSetupInFlight = errors.New("a setup session of this kind is already starting")
	// ErrLaunchSandboxUnavailable signals a sandbox=true fresh-launch
	// request arrived with Options.SandboxProber nil — the B9 sandbox
	// feature is entirely absent from this daemon build/config (501). This
	// is the A5 build-order invariant: a nil seam is fail-CLOSED, exactly
	// like ErrLaunchUnsupported for the base PTY seam, never a silent
	// fall-through to an unsandboxed launch.
	ErrLaunchSandboxUnavailable = errors.New("sandboxed launch requested but the sandbox seam is not configured on this daemon")
	// ErrLaunchSSHDisabled signals [terminal.ssh].enabled is off (403). An SSH
	// shell runs arbitrary commands on ANOTHER machine, so it is a conscious
	// opt-in separate from allow_shell (which grants only a local shell).
	ErrLaunchSSHDisabled = errors.New("SSH remote-system launch is disabled (set [terminal.ssh].enabled)")
	// ErrLaunchSSHProfileUnknown signals the requested profile name is not in
	// the operator's [[terminal.ssh.profiles]] list (400). This is the gate
	// that makes a client-supplied NAME safe: a destination the operator never
	// wrote down can never be reached.
	ErrLaunchSSHProfileUnknown = errors.New("no such SSH profile")
	// ErrLaunchSSHProfileInvalid signals the named profile failed re-validation
	// at launch — a malformed field, or a key_path that no longer resolves to a
	// regular file (400).
	ErrLaunchSSHProfileInvalid = errors.New("SSH profile is not valid")
)

// ControlDenialReason is the stable wire taxonomy for a refused remote writer
// acquire. Exactly TWO values are permanent verdicts on the presented
// credential — ControlDenialAuth (it was judged and rejected) and
// ControlDenialAuthRevoked (no standing secret exists on the server at all).
// Callers must not clear a standing secret for any other reason.
type ControlDenialReason string

const (
	// ControlDenialAuth means the capability/confirm or standing secret failed
	// its credential check — the credential WAS judged and rejected. It is the
	// ONLY reason a device may treat as proof that a saved standing secret is
	// dead (and therefore the only one it may clear the secret for).
	ControlDenialAuth ControlDenialReason = "auth"
	// ControlDenialAuthTransient means the credential leg refused WITHOUT ever
	// judging the presented credential — standing access is currently switched
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
	// credential and the device should clear it — unlike ControlDenialAuth the
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

// visibleSnapshot returns the live launch-session list filtered for the request
// principal: on the owner-trusted loopback listener (not remote-exposed) it is
// the full snapshot; for a REMOTE-exposed caller every SpecSetup handle is
// redacted, and every remote-sensitive (attach OR resume) handle is redacted
// UNLESS the [remote].allow_terminal_view READ opt-in is on (defence in depth
// over the SubscribeRemote / WS-gate refusals). Branches on the boundary-resolved
// local-vs-remote signal (remoteExposedFromContext) + the run KIND carried on the
// row (the shared termrun.IsRemoteSensitiveKind table), never on tool/route name.
//
// The remote-VIEW gate `[remote].allow_terminal_view` now DEFAULTS TRUE (§3.2),
// so a paired remote device SEES attach/resume rows by default and may subscribe
// read-only past the WS gate. This is acceptable because remote access is already
// multi-lever gated (armed rail + authenticated paired device over the tailnet)
// and the remote WRITE/drive path is UNCHANGED — driving still requires
// allow_terminal plus the full writer-acquire conjunction. The toggle still
// exists: allow_terminal_view = false restores the deny-read posture, redacting
// these rows uniformly across every remotely-visible snapshot
// (/api/attach/sessions, /api/terminal/sessions, /api/launch/sessions all route
// through here). SpecSetup handles are ALWAYS redacted — no view opt-in relaxes
// them.
func (s *Server) visibleSnapshot(ctx context.Context) []LaunchInfo {
	all := s.opts.LaunchManager.Snapshot()
	if !remoteExposedFromContext(ctx) {
		return all
	}
	// The remote-VIEW opt-in ([remote].allow_terminal_view, default TRUE) lets a
	// remote caller SEE attach/resume rows; when explicitly turned OFF they are
	// redacted. Setup handles are ALWAYS redacted (local-only; no view opt-in
	// relaxes them).
	viewSensitive := s.allowTerminalView()
	out := make([]LaunchInfo, 0, len(all))
	for _, info := range all {
		if info.Setup {
			continue // redact privileged setup handles from remote callers
		}
		if !viewSensitive && termrun.IsRemoteSensitiveKind(termrun.Kind(info.Kind)) {
			continue // allow_terminal_view is OFF — hide this attach/resume PTY (§3.2; default is now ON)
		}
		out = append(out, info)
	}
	return out
}

// allowTerminalView reports whether the LIVE [remote].allow_terminal_view READ
// opt-in is enabled (session-attach design §3.2). It is the independent
// remote-VIEW gate for attach/resume rows — strictly weaker than allow_terminal
// (write) — and now DEFAULTS TRUE in config, so a remote-exposed node exposes
// these rows read-only unless the operator sets allow_terminal_view = false.
// Read via a type assertion off the injected RemoteController (additive,
// CLAUDE.md #6): a nil / non-implementing controller (loopback-only, no remote
// exposure) yields false, so the redaction still holds on any non-remote path
// and every existing test path is unchanged. Mirrors how the live allow_terminal
// gate is read.
func (s *Server) allowTerminalView() bool {
	v, ok := s.opts.Remote.(allowTerminalViewer)
	return ok && v.AllowTerminalView()
}

// SpawnAuditKind maps a spawned run KIND to its metadata-only remote_audit
// event kind (session-attach design §3.5). Table-driven per CLAUDE.md #5 — a new
// spawnable kind is one row, never a nested branch — and the SINGLE vocabulary
// both spawn sites use (the dashboard resume handler + the cmd-side attach host)
// instead of bespoke inline strings. Empty for a kind with no spawn-audit event.
func SpawnAuditKind(k termrun.Kind) string {
	switch k {
	case termrun.KindAttach:
		return "terminal_attach"
	case termrun.KindResume:
		return "terminal_resume"
	default:
		return ""
	}
}

// sensitiveViewer is one registered remote-exposed read-only viewer of a
// remote-sensitive (attach/resume) session admitted under allow_terminal_view.
// It carries the bridge-scoped cancel AND the viewer's FULL device-session key
// (its sha256 hash, NOT the 32-bit display fingerprint) so a per-device
// revocation can target exactly that device's open views without a prefix
// collision reaching another device's viewer (F2).
type sensitiveViewer struct {
	deviceKey string
	cancel    context.CancelFunc
}

// registerSensitiveViewer records the bridge-scoped cancel of a LIVE
// remote-exposed read-only viewer of a remote-sensitive (attach/resume) session,
// admitted under allow_terminal_view. deviceKey is the viewer's FULL
// device-session key (deviceSessionKey — the sha256 hash of its device-session,
// never the 32-bit display fingerprint), so a per-device revoke can close
// exactly this viewer with no prefix-collision hole (F2). It returns a deregister
// func the caller MUST defer so a normally-disconnecting viewer leaves no entry
// behind. On an allow_terminal_view→false flip, closeRemoteSensitiveViewers
// cancels every registered entry, tearing the open view down at once (§3.2
// read-side revoke).
func (s *Server) registerSensitiveViewer(deviceKey string, cancel context.CancelFunc) func() {
	s.sensitiveViewerMu.Lock()
	if s.sensitiveViewers == nil {
		s.sensitiveViewers = make(map[uint64]sensitiveViewer)
	}
	id := s.sensitiveViewerSeq
	s.sensitiveViewerSeq++
	s.sensitiveViewers[id] = sensitiveViewer{deviceKey: deviceKey, cancel: cancel}
	s.sensitiveViewerMu.Unlock()
	return func() {
		s.sensitiveViewerMu.Lock()
		delete(s.sensitiveViewers, id)
		s.sensitiveViewerMu.Unlock()
	}
}

// closeRemoteSensitiveViewers cancels every LIVE remote-exposed read-only viewer
// of a remote-sensitive session admitted under allow_terminal_view — the READ
// analogue of revokeRemoteWriters. Called when the owner flips
// allow_terminal_view→false so an already-open remote view of a secret-bearing
// attach/resume TUI is torn down NOW, not merely blocked for future subscribes.
// The owner-local (loopback) viewers are never registered here, so they are
// untouched. Snapshots the cancels under the lock, then cancels outside it (each
// cancel unblocks a bridge goroutine that will deregister itself).
func (s *Server) closeRemoteSensitiveViewers() int {
	s.sensitiveViewerMu.Lock()
	cancels := make([]context.CancelFunc, 0, len(s.sensitiveViewers))
	for _, v := range s.sensitiveViewers {
		cancels = append(cancels, v.cancel)
	}
	s.sensitiveViewerMu.Unlock()
	for _, c := range cancels {
		c()
	}
	return len(cancels)
}

// closeRemoteSensitiveViewersForDevice cancels every LIVE remote-exposed
// read-only sensitive viewer belonging to ONE device session key (F2) — the
// per-device analogue of closeRemoteSensitiveViewers. Called when a single
// device session is revoked (admin per-device revoke or self-logout) so a
// revoked device stops receiving attach/resume PTY output at once, WITHOUT
// disturbing other devices' still-authorized views. The key is the FULL device-
// session hash (deviceSessionKey / SessionInfo.ID), never the display prefix, so
// a fingerprint collision can never disconnect the wrong device's viewer. An
// empty key (the owner-local path, never registered here) matches nothing.
// Snapshots the matching cancels under the lock, then cancels outside it (each
// cancel unblocks a bridge goroutine that will deregister itself). Returns the
// count closed.
func (s *Server) closeRemoteSensitiveViewersForDevice(deviceKey string) int {
	if deviceKey == "" {
		return 0
	}
	s.sensitiveViewerMu.Lock()
	cancels := make([]context.CancelFunc, 0)
	for _, v := range s.sensitiveViewers {
		if v.deviceKey == deviceKey {
			cancels = append(cancels, v.cancel)
		}
	}
	s.sensitiveViewerMu.Unlock()
	for _, c := range cancels {
		c()
	}
	return len(cancels)
}

// sessionLifetimeFloor bounds how eagerly a bound sensitive viewer re-checks a
// device session it could not yet prove expired. Revoke/rotate arrive INSTANTLY
// on the revocation channel; only the timer-less TTL/idle expiry needs a wake.
// The floor clamps ONLY a non-positive (already-at/past-deadline) re-arm so it
// can't spin — a KNOWN positive deadline is honoured un-floored, so expiry
// cancels the viewer at the deadline instead of up to a floor's-width later.
const sessionLifetimeFloor = 250 * time.Millisecond

// deviceSessionLive reports whether the raw device-session cookie is STILL a
// live session — the F1a post-register re-validation. An absent controller
// (loopback) or an empty cookie is treated as live (not disproven): the remote
// authz chain that admits a real remote request always carries a valid session,
// so the only race this closes involves a cookie that authenticated and was then
// revoked/expired between the gate check and registration. Read-only (via
// SessionLifetime — no idle refresh).
func (s *Server) deviceSessionLive(raw string) bool {
	if raw == "" {
		return true
	}
	lt, ok := s.opts.Remote.(deviceSessionLifetimer)
	if !ok {
		return true
	}
	_, _, live := lt.SessionLifetime(raw)
	return live
}

// bindViewerLifetime cancels a live remote-sensitive viewer the moment its
// device session ends — revoked, rotated, or TTL/idle-expired (F1b) — closing
// the gap the allow_terminal_view drain alone leaves (a session can end without
// the operator ever flipping the view opt-in). A nil / non-lifetimer controller
// (loopback) or empty cookie is a no-op. The watch goroutine exits when the
// viewer disconnects (done closed) so it never leaks.
func (s *Server) bindViewerLifetime(raw string, done <-chan struct{}, cancel context.CancelFunc) {
	if raw == "" {
		return
	}
	lt, ok := s.opts.Remote.(deviceSessionLifetimer)
	if !ok {
		return
	}
	go watchSessionLifetime(raw, lt, done, cancel, sessionLifetimeFloor)
}

// watchSessionLifetime is the testable core of bindViewerLifetime. It selects on
// the session's revocation channel (instant revoke/rotate), a timer to the next
// TTL/idle deadline (re-armed on each wake so an idle refresh that extended the
// session is honoured), and done (viewer disconnect). On session-end it calls
// cancel; on a clean disconnect it returns WITHOUT cancelling. floor clamps ONLY
// a non-positive re-arm so a near-deadline poll can't spin — a known positive
// deadline is left un-floored so expiry cancels at the deadline, not later.
func watchSessionLifetime(raw string, lt deviceSessionLifetimer, done <-chan struct{}, cancel context.CancelFunc, floor time.Duration) {
	for {
		revoked, until, live := lt.SessionLifetime(raw)
		if !live {
			cancel()
			return
		}
		if until <= 0 {
			// Only a non-positive (deadline already reached) wake gets the
			// floor, to keep the re-arm from spinning; a KNOWN positive deadline
			// passes through un-floored so TTL/idle expiry cancels the viewer
			// promptly rather than up to floor later.
			until = floor
		}
		timer := time.NewTimer(until)
		select {
		case <-done:
			timer.Stop()
			return
		case <-revoked:
			timer.Stop()
			cancel()
			return
		case <-timer.C:
			// Deadline reached — loop re-reads liveness. If the session was
			// idle-refreshed by other activity it is still live with a fresh
			// deadline; otherwise SessionLifetime now reports live=false → cancel.
		}
	}
}

// viewerSessionTouchInterval is how often an ATTACHED terminal websocket
// refreshes its device session's idle clock. It is a package var (not a const)
// solely so a test can shorten it; production callers never write it.
//
// 60s is far below any supported session_idle_minutes, and the store throttles
// the DURABLE write to once per Idle/4, so the SQLite cost is negligible.
var viewerSessionTouchInterval = 60 * time.Second

// deviceSessionToucher is the ADDITIVE optional write seam that lets an attached
// terminal websocket count as device-session activity. It is deliberately
// SEPARATE from deviceSessionLifetimer — that interface's SessionLifetime is
// contractually read-only and several callers depend on it never extending a
// session, so this is a distinct, explicitly-named method rather than a change
// to that contract. Type-asserted off the RemoteController, so nil/fake/loopback
// controllers stay valid (CLAUDE.md #6). Satisfied by *remoteController.
type deviceSessionToucher interface {
	// TouchDeviceSession refreshes a LIVE device session's idle clock and
	// reports whether it was live. It can only extend an already-live session —
	// never resurrect a revoked/expired one, and never past the absolute TTL.
	TouchDeviceSession(raw string) bool
}

// keepDeviceSessionAliveWhileAttached starts the heartbeat that stops a device
// session idling out from under a user who is actively watching a terminal
// (2026-07-25, mobile terminal-continuity arc). Before this, an open terminal
// viewer generated no HTTP requests at all, so nothing refreshed the idle clock:
// a phone left on a live terminal expired mid-watch, the socket was cancelled
// through bindViewerLifetime, and the user was told to re-pair.
//
// No-op for an empty cookie or a controller without the touch seam (the local
// loopback dashboard has no device session at all). The goroutine exits when the
// socket's done channel closes, so it never leaks.
func (s *Server) keepDeviceSessionAliveWhileAttached(raw string, done <-chan struct{}) {
	if raw == "" {
		return
	}
	tr, ok := s.opts.Remote.(deviceSessionToucher)
	if !ok {
		return
	}
	go viewerSessionHeartbeat(raw, tr, done, viewerSessionTouchInterval)
}

// viewerSessionHeartbeat is the testable core of
// keepDeviceSessionAliveWhileAttached: it touches the device session every
// interval while the viewer stays attached, and returns as soon as the viewer
// disconnects OR the session stops being live (a revoked/expired session is
// never resurrected — the bound viewer's own lifetime watcher owns the teardown,
// so this simply stops touching).
func viewerSessionHeartbeat(raw string, tr deviceSessionToucher, done <-chan struct{}, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			if !tr.TouchDeviceSession(raw) {
				return // session already dead — nothing to keep alive
			}
		}
	}
}

// sessionHasLiveSensitiveRun reports whether a live (non-exited) terminal run of
// a remote-sensitive kind (attach OR resume) is already bound to sessionID. It
// reads the SAME Snapshot + run-kind data the remote gates use: a resume run
// carries the resumed session as its Snapshot SessionID; a live attach run
// carries its OOB-correlated session id. Used by handleSessionResume to refuse a
// duplicate native resume (F5) that would otherwise spawn a second tool process
// writing the same transcript concurrently. A nil manager / empty id ⇒ false.
func (s *Server) sessionHasLiveSensitiveRun(sessionID string) bool {
	if s.opts.LaunchManager == nil || sessionID == "" {
		return false
	}
	for _, info := range s.opts.LaunchManager.Snapshot() {
		if info.Exited || info.SessionID != sessionID {
			continue
		}
		if termrun.IsRemoteSensitiveKind(termrun.Kind(info.Kind)) {
			return true
		}
	}
	return false
}

// launchSubcommand resolves a target tool name to its observer launcher
// verb, or ("", false) when the tool is not launchable in the embedded
// terminal. Branches on the Launch capability shape + the harness
// lifecycle (integration.TerminalLaunchable), never the tool name: a
// deprecated or dead row is never offered for launch.
func launchSubcommand(tool string) (string, bool) {
	cap, ok := integration.For(tool)
	if !ok || !integration.TerminalLaunchable(cap) {
		return "", false
	}
	return cap.Handoff.Launch.Subcommand, true
}

// sessionResumeInfo is the additive `resume` block on the session-detail
// payload (session-attach design Phase 3). It tells the frontend, by CAPABILITY
// SHAPE (never a tool-name branch), how a CLOSED session on this tool can be
// reopened:
//   - Kind "native":  the tool has a grounded ResumeNative contract — the
//     dashboard offers a Resume button that POSTs /resume and docks a terminal
//     running the tool's own resume mechanism (the real transcript).
//   - Kind "handoff": no native resume, but the tool is launchable in the
//     embedded terminal — the frontend points the operator at the existing
//     Continue-in… (handoff-fork) card rather than duplicating that UI.
//   - Kind "none":    neither — an honest-disabled affordance naming the gap.
//
// Subcommand carries the native launcher verb for kind "native" (empty
// otherwise) so the honest-disabled/hint copy can name the exact command.
type sessionResumeInfo struct {
	Kind       string `json:"kind"`
	Subcommand string `json:"subcommand"`
}

// resumeInfoForTool derives the session-detail `resume` block from the
// integration capability registry, dispatching on capability SHAPE (CLAUDE.md
// #3): a grounded ResumeNative spec → "native"; else a launchable
// handoff/continue-from capability → "handoff"; else "none". An unknown tool
// (no registry row) is "none" — the honest floor.
func resumeInfoForTool(tool string) sessionResumeInfo {
	cap, ok := integration.For(tool)
	if !ok {
		return sessionResumeInfo{Kind: "none"}
	}
	if cap.Resume.Kind == integration.ResumeNative {
		return sessionResumeInfo{Kind: "native", Subcommand: cap.Resume.Subcommand}
	}
	if integration.TerminalLaunchable(cap) {
		return sessionResumeInfo{Kind: "handoff"}
	}
	return sessionResumeInfo{Kind: "none"}
}

// resumeInfoForSession excludes transcript partitions whose display ID is not
// a vendor-resumable conversation. Their parent link and handoff stay usable.
func resumeInfoForSession(tool, sessionID string) sessionResumeInfo {
	info := resumeInfoForTool(tool)
	if info.Kind == "native" && strings.Contains(sessionID, ":agent:") {
		return sessionResumeInfo{Kind: "handoff"}
	}
	return info
}

// launchableTools returns every tool NAME launchable in the embedded terminal,
// sorted, resolved from the capability registry (dispatch on capability shape,
// never tool name) through integration.TerminalLaunchable — so a row whose
// product the vendor deprecated or killed is absent from the picker while its
// existing sessions keep being captured. The fresh-launch dialog uses it to
// populate its picker honestly; the operator's [terminal.launch].allowed_tools
// allow-list still governs which of these actually launch (enforced
// server-side).
func launchableTools() []string {
	var out []string
	for _, c := range integration.Capabilities() {
		if integration.TerminalLaunchable(c) {
			out = append(out, c.Tool)
		}
	}
	sort.Strings(out)
	return out
}

// RecentModelsWindow and RecentModelsLimit bound the store history query
// behind the Options.RecentModels seam (B5): 180 days / 12 rows keeps the
// "recent" list to genuinely-recent, genuinely-distinct choices without an
// unbounded scan of token_usage. Exported so the cmd-side seam constructor
// (recentModelsSeam) uses the same values the picker's semantics document —
// one authority, not a duplicated literal.
const (
	RecentModelsWindow = 180 * 24 * time.Hour
	RecentModelsLimit  = 12
)

// modelSuggestion is one entry in the New Terminal model picker's
// suggestion list (B5). Source is "history" for a model this tool has
// actually been launched with recently, or "known" for a model the
// capability registry documents as a grounded example but that hasn't been
// observed locally yet. Count/LastUsed are populated only for "history"
// entries (omitempty — a "known" entry never fabricates usage stats).
type modelSuggestion struct {
	Model    string `json:"model"`
	Count    int    `json:"count,omitempty"`
	LastUsed string `json:"last_used,omitempty"`
	Source   string `json:"source"`
}

// modelSuggestionsFor composes the New Terminal model picker's suggestion
// list for tool (B5): recent usage history (via the nil-able
// Options.RecentModels seam) followed by the capability registry's
// grounded Known examples, deduplicated against history. It is the SINGLE
// composition point shared by handleTerminalLaunchModels (the picker's own
// endpoint) and handleTerminalLaunch (server-side membership validation of
// a client-supplied model) — dispatch is on capability SHAPE
// (ModelSpec.Kind), never tool name (CLAUDE.md #3).
//
// supported is false — with an empty, non-nil suggestion slice — when the
// tool has no registry row, no launch capability, or a zero ModelSpec
// (ModelKind ModelNone); the picker stays hidden for that row, the honest
// floor. It is also false when the RecentModels seam itself is nil (an
// older daemon build without the store wiring) so the endpoint and the
// launch-time validator degrade identically to a preflight-less daemon.
func modelSuggestionsFor(ctx context.Context, recentModels func(context.Context, string) ([]store.RecentToolModel, error), tool string) (supported bool, suggestions []modelSuggestion) {
	suggestions = []modelSuggestion{}
	if recentModels == nil {
		return false, suggestions
	}
	cap, ok := integration.For(tool)
	if !ok || !integration.TerminalLaunchable(cap) || cap.Model.Kind == integration.ModelNone {
		return false, suggestions
	}

	seen := make(map[string]bool)
	if history, err := recentModels(ctx, tool); err == nil {
		for _, h := range history {
			suggestions = append(suggestions, modelSuggestion{
				Model: h.Model, Count: h.Count, LastUsed: h.LastUsed, Source: "history",
			})
			seen[h.Model] = true
		}
	}
	// A history load error is fail-soft here (not fail-closed): the Known
	// list below still gives the picker something honest to show, and the
	// endpoint's overall response is still `supported: true`.
	for _, m := range cap.Model.Known {
		if !seen[m] {
			suggestions = append(suggestions, modelSuggestion{Model: m, Source: "known"})
			seen[m] = true
		}
	}
	return true, suggestions
}

// modelIsMember reports whether model appears among suggestions — the
// server-side membership check handleTerminalLaunch applies to a
// client-supplied model before trusting it (B5).
func modelIsMember(suggestions []modelSuggestion, model string) bool {
	for _, s := range suggestions {
		if s.Model == model {
			return true
		}
	}
	return false
}

type launchRequest struct {
	To          string `json:"to"`
	Carry       string `json:"carry"`
	ForkMessage int    `json:"fork_message"`
}

type launchResponse struct {
	Token      string `json:"token"`
	Subcommand string `json:"subcommand"`
	SessionID  string `json:"session_id"`
	// HasProjectRoot lets the dock enable the Files/Git project panels
	// immediately on a fresh launch instead of waiting for a later
	// /api/launch/sessions rehydrate (finding 8). Resolved from the same
	// token→root seam the project panel Snapshot uses.
	HasProjectRoot bool `json:"has_project_root"`
}

// hasProjectRoot reports whether a freshly-minted terminal token resolves to a
// BROWSABLE directory — via the same ProjectRootResolver seam the project panel
// uses, so the button the dock enables and the endpoint that serves it can
// never disagree. A nil resolver (panel unwired), an unknown token, or a run
// with no local directory at all (SSH) yield false; a default-cwd launch yields
// TRUE on its own working directory (operator ruling 2026-08-28), so the
// Files/Git buttons are enabled by default rather than gated on the launch
// allow-list.
func (s *Server) hasProjectRoot(token string) bool {
	if s.opts.ProjectRootResolver == nil {
		return false
	}
	root, known := s.opts.ProjectRootResolver(token)
	return known && root.Path != ""
}

// handleSessionLaunch serves POST /api/session/<id>/launch. It validates the
// target against the launchable capability set, builds a server-derived
// LaunchSpec, and returns the opaque session handle. The websocket bridge is
// a separate GET route the client opens with the returned handle.
func (s *Server) handleSessionLaunch(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.LaunchManager == nil {
		http.Error(w, "launch unavailable — this dashboard runs without the embedded-terminal launcher (set [handoff].allow_dashboard_launch and run via `observer start`)", http.StatusServiceUnavailable)
		return
	}
	if strings.TrimSpace(sessionID) == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	var body launchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	// W5.1 org-governed feature gate: node.features.terminals — this path
	// spawns an embedded terminal with no sandbox lane, so it presents
	// requestedSandbox=false (an org sandbox_required policy therefore
	// denies it). Fail-open on nil gate / no accepted policy.
	if s.opts.TerminalFeatureGate != nil {
		if allowed, reason := s.opts.TerminalFeatureGate(false); !allowed {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}
	sub, ok := launchSubcommand(body.To)
	if !ok {
		http.Error(w, "tool "+body.To+" is not launchable in the embedded terminal", http.StatusBadRequest)
		return
	}
	// "" defers to the launcher's configured default; otherwise defer to
	// handoff.ValidCarry (the single owner of the carry vocabulary) so a new
	// mode never needs a second allow-list here.
	if body.Carry != "" && !handoff.ValidCarry(handoff.CarryMode(body.Carry)) {
		http.Error(w, "invalid carry mode", http.StatusBadRequest)
		return
	}
	if body.ForkMessage < 0 {
		http.Error(w, "fork_message must be >= 0", http.StatusBadRequest)
		return
	}

	handle, err := s.opts.LaunchManager.Create(LaunchSpec{
		Subcommand:  sub,
		SessionID:   sessionID,
		Carry:       body.Carry,
		FromMessage: body.ForkMessage,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrLaunchTooMany):
			http.Error(w, err.Error(), http.StatusTooManyRequests)
		case errors.Is(err, ErrLaunchUnsupported):
			http.Error(w, err.Error(), http.StatusNotImplemented)
		default:
			http.Error(w, "launch failed: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, launchResponse{
		Token: handle, Subcommand: sub, SessionID: sessionID,
		HasProjectRoot: s.hasProjectRoot(handle),
	})
}

// resumeResponse is the reply from POST /api/session/<id>/resume. It carries
// the opaque terminal handle (`token` — the field the frontend dock.launch path
// reads, identical to handleSessionLaunch's launchResponse) plus the durable
// run id and the resolved launcher subcommand. session_id echoes the resumed
// session so the dock header can name it without re-deriving.
type resumeResponse struct {
	Token      string `json:"token"`
	RunID      string `json:"run_id"`
	Subcommand string `json:"subcommand"`
	SessionID  string `json:"session_id"`
	// HasProjectRoot: see launchResponse (finding 8).
	HasProjectRoot bool `json:"has_project_root"`
}

// resumeGate is a reference-counted per-session mutex used to single-flight the
// resume check+spawn (R2-3). refs is guarded by Server.resumeMu; mu serializes
// the critical section for one session id.
type resumeGate struct {
	mu   sync.Mutex
	refs int
}

// acquireResumeLock returns a function that releases the per-session resume
// gate. It blocks until this caller holds the gate for sessionID, so the
// liveness check + spawn between acquire and release run single-flight against
// any concurrent resume of the same session (R2-3). The gate is reference-
// counted: the last releaser deletes it from the map so idle sessions leave no
// entry behind. Different session ids never contend (independent gates).
func (s *Server) acquireResumeLock(sessionID string) func() {
	s.resumeMu.Lock()
	if s.resumeGates == nil {
		s.resumeGates = make(map[string]*resumeGate)
	}
	g := s.resumeGates[sessionID]
	if g == nil {
		g = &resumeGate{}
		s.resumeGates[sessionID] = g
	}
	g.refs++
	s.resumeMu.Unlock()

	g.mu.Lock()
	return func() {
		g.mu.Unlock()
		s.resumeMu.Lock()
		g.refs--
		if g.refs == 0 {
			delete(s.resumeGates, sessionID)
		}
		s.resumeMu.Unlock()
	}
}

// handleSessionResume serves POST /api/session/<id>/resume — the P3 NATIVE
// resume. It loads the closed session's tool + project_root, REQUIRES a grounded
// ResumeNative contract for that tool (else 409, naming the handoff-fork
// fallback honestly), composes the resume argv tail through the single pure seam
// integration.ResumeArgs (dispatch on capability SHAPE, never tool name —
// CLAUDE.md #3), and spawns a fresh dashboard-owned terminal via CreateResume
// under the application service's fresh-launch policy. The response mirrors
// handleSessionLaunch's wire shape (a `token`) so the frontend dock path is
// identical, plus run_id.
func (s *Server) handleSessionResume(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.LaunchManager == nil {
		http.Error(w, "resume unavailable — this dashboard runs without the embedded-terminal launcher (set [handoff].allow_dashboard_launch and run via `observer start`)", http.StatusServiceUnavailable)
		return
	}
	if strings.TrimSpace(sessionID) == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	// W5.1 org-governed feature gate: node.features.terminals — this path
	// spawns an embedded terminal with no sandbox lane, so it presents
	// requestedSandbox=false (an org sandbox_required policy therefore
	// denies it). Fail-open on nil gate / no accepted policy.
	if s.opts.TerminalFeatureGate != nil {
		if allowed, reason := s.opts.TerminalFeatureGate(false); !allowed {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}

	// Load the session's tool + project_root (the only server-side inputs a
	// resume needs; argv is composed from the registry, never the client).
	var tool, projectRoot string
	err := s.db().QueryRowContext(
		r.Context(),
		`SELECT s.tool, COALESCE(p.root_path, '')
		 FROM sessions s LEFT JOIN projects p ON p.id = s.project_id
		 WHERE s.id = ?`, sessionID,
	).Scan(&tool, &projectRoot)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		writeErr(w, err)
		return
	}

	// Require a grounded native-resume contract. A tool without one (ResumeNone
	// / ResumeFork) has no real transcript to reopen from the dashboard — 409
	// with an honest message naming the handoff-fork fallback the Continue-in…
	// card provides. Dispatch on capability SHAPE, never a tool-name switch.
	cap, ok := integration.For(tool)
	if !ok || cap.Resume.Kind != integration.ResumeNative || resumeInfoForSession(tool, sessionID).Kind != "native" {
		http.Error(w, "native resume not grounded for "+tool+"; use Continue in… to fork instead", http.StatusConflict)
		return
	}

	// Single-flight the duplicate-resume check + spawn per session id (R2-3):
	// hold the per-session gate across BOTH sessionHasLiveSensitiveRun and
	// CreateResume so two concurrent POSTs can't both pass the check and both
	// spawn. The second POST blocks here, then observes the first's now-live run
	// and 409s. Released at handler return (covers every branch below).
	releaseResume := s.acquireResumeLock(sessionID)
	defer releaseResume()

	// Refuse a DUPLICATE native resume (F5): if the session already has a live
	// (non-exited) terminal run of a remote-sensitive kind — a resume bound to
	// this session, or a live attach the operator can Jump into — spawning a
	// second one would run TWO tool processes writing the SAME transcript
	// concurrently. 409 with an honest message; the client flips the Resume
	// button to a disabled "already running" state on this status.
	if s.sessionHasLiveSensitiveRun(sessionID) {
		http.Error(w, "session already has a live terminal run — jump in or wait for it to end", http.StatusConflict)
		return
	}

	extraArgs, err := integration.ResumeArgs(cap.Resume, sessionID)
	if err != nil {
		// A grounded ResumeNative whose argv still can't be composed (empty/
		// unsafe id, unknown mechanism) is a 400 — the id came from the URL.
		http.Error(w, "cannot compose resume command: "+err.Error(), http.StatusBadRequest)
		return
	}

	handle, runID, err := s.opts.LaunchManager.CreateResume(ResumeLaunchSpec{
		Tool:        tool,
		Subcommand:  cap.Resume.Subcommand,
		SessionID:   sessionID,
		ProjectRoot: projectRoot,
		ExtraArgs:   extraArgs,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrLaunchFreshDisabled):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, ErrLaunchToolNotAllowed):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, ErrLaunchProjectRootDenied):
			// F6: the project root is loaded server-side from the stored session,
			// so an allow-list rejection is an AUTHORIZATION-policy refusal (403),
			// not malformed client input (400). Mirrors fresh-disabled /
			// tool-denied, which correctly return 403.
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, ErrLaunchTooMany):
			http.Error(w, err.Error(), http.StatusTooManyRequests)
		case errors.Is(err, ErrLaunchUnsupported):
			http.Error(w, err.Error(), http.StatusNotImplemented)
		default:
			http.Error(w, "resume failed: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}
	// Spawn-time audit (F4, session-attach design §3.5): emit exactly one
	// metadata-only terminal_resume row at the spawn success point, BEFORE
	// returning the resume token. Without this a caller that POSTs /resume but
	// never opens the websocket produces a real process with NO remote_audit row
	// (the writer-lease audit only fires once a client attaches). Metadata only —
	// run id, handle, tool — never argv/env/content.
	s.auditSpawn(SpawnAuditKind(termrun.KindResume), tool, handle, runID, r)
	writeJSON(w, resumeResponse{
		Token: handle, RunID: runID, Subcommand: cap.Resume.Subcommand, SessionID: sessionID,
		HasProjectRoot: s.hasProjectRoot(handle),
	})
}

// terminalLaunchRequest is the POST /api/terminal/launch body (F1). The only
// client inputs are the tool NAME (allow-listed server-side), an optional
// project_root (canonicalized + allow-list-checked server-side), and an
// optional model (B5, New Terminal model picker) — re-validated by
// MEMBERSHIP against modelSuggestionsFor's own output server-side (never
// trusted verbatim); an invalid/unknown value is silently dropped rather
// than rejected, see handleTerminalLaunch. No argv, no session id (fresh
// launch), no BinPath.
type terminalLaunchRequest struct {
	// Kind selects the launch SHAPE (integration.LaunchKind): "" or "terminal"
	// is the PTY launch this endpoint has always served — that path is
	// byte-identical when the field is absent — and "gui" dispatches to the
	// detached IDE / desktop-app launch. The dashboard branches on this SHAPE,
	// never on the tool name (CLAUDE.md #3). Any other value is a 400.
	Kind        string `json:"kind"`
	Tool        string `json:"tool"`
	ProjectRoot string `json:"project_root"`
	Model       string `json:"model"`
	// Sandbox requests a B9 filesystem-isolated launch (bwrap). Unlike
	// Model (a preference, fail-open on any problem), a true Sandbox is a
	// SAFETY property handleTerminalLaunch validates fail-CLOSED — see the
	// "validation inversion vs B5" comment on that handler.
	Sandbox bool `json:"sandbox"`
	// WorkspaceSource / WorkspaceRemote / WorkspaceBranch select and
	// parameterize the B9 workspace-preparation mechanism for a sandboxed
	// launch (plan §4/§5). All three are re-validated server-side —
	// WorkspaceSource by membership against the daemon's own probed
	// Sources list, never trusted verbatim from the client. Ignored when
	// Sandbox is false.
	WorkspaceSource string `json:"workspace_source"`
	WorkspaceRemote string `json:"workspace_remote"`
	WorkspaceBranch string `json:"workspace_branch"`
}

// terminalLaunchResponse mirrors launchResponse plus the tool label so the
// client can render the terminal header without re-deriving it.
type terminalLaunchResponse struct {
	Token      string `json:"token"`
	Tool       string `json:"tool"`
	Subcommand string `json:"subcommand"`
	// HasProjectRoot: see launchResponse (finding 8).
	HasProjectRoot bool `json:"has_project_root"`
}

// handleTerminalLaunch serves POST /api/terminal/launch — the F1 fresh-agent
// launch. It is classified EXECUTE in the route-capability registry (§9): a
// fresh launch starts a new process, the privilege-expansion feature of this
// plan. The tool is resolved to its launcher subcommand server-side from the
// capability registry; the application service enforces the operator's
// [terminal.launch] opt-in (allow_fresh_agent + allowed_tools +
// allowed_project_roots) and canonicalizes project_root before spawn.
func (s *Server) handleTerminalLaunch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.LaunchManager == nil {
		http.Error(w, "launch unavailable — this dashboard runs without the embedded-terminal launcher (run via `observer start`)", http.StatusServiceUnavailable)
		return
	}
	var body terminalLaunchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	// W5.1 org-governed feature gate: node.features.terminals. Checked
	// before any launch work begins. Fail-open (nil TerminalFeatureGate,
	// or no accepted policy) — see dashboard.Options.TerminalFeatureGate.
	if s.opts.TerminalFeatureGate != nil {
		if allowed, reason := s.opts.TerminalFeatureGate(body.Sandbox); !allowed {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}
	// Launch-SHAPE dispatch (T2). An absent or "terminal" kind falls through to
	// the PTY path below unchanged — every gate above it already ran, and
	// nothing after this switch reads body.Kind — so a client that predates the
	// field gets byte-identical behaviour. Only "gui" branches away.
	switch integration.LaunchKind(strings.TrimSpace(body.Kind)) {
	case "", integration.LaunchKindTerminal:
		// fall through to the PTY launch
	case integration.LaunchKindGUI:
		s.handleGUILaunch(w, body)
		return
	default:
		writeErrStatus(w, errors.New("unknown launch kind "+body.Kind), http.StatusBadRequest)
		return
	}
	// The reserved pseudo-tool "shell" (termsvc.ShellTool) requests a fresh
	// PLAIN SHELL — never a member of the launchable capability set, so it
	// skips launchSubcommand entirely and is gated by [terminal.launch].
	// allow_shell instead of allowed_tools (see FreshLaunchSpec.Shell).
	isShell := body.Tool == termsvc.ShellTool
	var sub string
	if !isShell {
		var ok bool
		sub, ok = launchSubcommand(body.Tool)
		if !ok {
			http.Error(w, "tool "+body.Tool+" is not launchable in the embedded terminal", http.StatusBadRequest)
			return
		}
	}
	// Model (B5): re-derive the SAME suggestion list the picker itself
	// showed and require membership before trusting a client-supplied
	// value. A model that isn't in that list — including every case where
	// the tool has no model capability at all — is silently DROPPED so the
	// launch proceeds with the tool's own default; this is deliberate
	// fail-open (never a 400, never a blocked launch) per the New Terminal
	// model picker's semantics.
	model := strings.TrimSpace(body.Model)
	if model != "" && !isShell {
		if _, suggestions := modelSuggestionsFor(r.Context(), s.opts.RecentModels, body.Tool); !modelIsMember(suggestions, model) {
			model = ""
		}
	} else {
		model = ""
	}
	// Sandbox (B9, plan §5): a client-supplied workspace_source is
	// re-derived server-side by MEMBERSHIP against the daemon's own probed
	// Sources list — the SAME re-derivation discipline the model check
	// above applies — but where an unusable Model is silently DROPPED
	// (fail-open: a model is a preference, the launch still succeeds
	// without it), an unsatisfiable sandbox request FAILS THE LAUNCH
	// outright (fail-closed: the caller asked for isolation, and silently
	// handing back an unsandboxed process instead would be a safety
	// regression, not a graceful degrade). Both rules get this comment
	// because the two endpoints look identical at a glance and the
	// difference is deliberate, not an oversight. See plan §7 "no
	// unsandboxed fallback path exists in the code" (mutation proof #1).
	workspaceSource := strings.TrimSpace(body.WorkspaceSource)
	if workspaceSource == "" {
		workspaceSource = "live"
	}
	if body.Sandbox && !s.sandboxRequestOK(w, r, body, workspaceSource) {
		return
	}
	handle, err := s.opts.LaunchManager.CreateFresh(FreshLaunchSpec{
		Tool:            body.Tool,
		Subcommand:      sub,
		ProjectRoot:     body.ProjectRoot,
		Shell:           isShell,
		Model:           model,
		Sandbox:         body.Sandbox,
		WorkspaceSource: workspaceSource,
		WorkspaceRemote: body.WorkspaceRemote,
		WorkspaceBranch: body.WorkspaceBranch,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrLaunchFreshDisabled):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, ErrLaunchToolNotAllowed):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, ErrLaunchShellDisabled):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, ErrLaunchProjectRootDenied):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, ErrLaunchTooMany):
			http.Error(w, err.Error(), http.StatusTooManyRequests)
		case errors.Is(err, ErrLaunchUnsupported):
			http.Error(w, err.Error(), http.StatusNotImplemented)
		case errors.Is(err, termsvc.ErrSandboxUnavailable):
			// U4's own fail-closed refusal (e.g. the Sandboxer seam was
			// removed/raced between this handler's probe check and the
			// actual spawn) — 501, same class as ErrLaunchSandboxUnavailable
			// above.
			http.Error(w, err.Error(), http.StatusNotImplemented)
		case errors.Is(err, termsvc.ErrWorkspacePrepFailed):
			// git/clone workspace preparation failed server-side — 500 per
			// plan §7 (the default branch below already maps to 500; this
			// case exists so the mapping is explicit and documented).
			http.Error(w, "workspace preparation failed: "+err.Error(), http.StatusInternalServerError)
		default:
			http.Error(w, "launch failed: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, terminalLaunchResponse{
		Token: handle, Tool: body.Tool, Subcommand: sub,
		HasProjectRoot: s.hasProjectRoot(handle),
	})
	// Kick the watcher so a tool whose sessions directory did not exist
	// at daemon start (just-installed Muse/Prime/…) is hot-added and
	// scanned. Fire-and-forget; never blocks the launch response.
	s.kickWatchRootsRefresh()
}

// sandboxRequestOK runs handleTerminalLaunch's FAIL-CLOSED sandbox validation
// and reports whether the launch may proceed. It writes the refusal itself
// (and returns false) on every miss, so the caller's whole sandbox branch is
// one line. Extracted verbatim from handleTerminalLaunch — the checks, their
// order, their status codes and their messages are unchanged; the extraction
// exists to keep that handler under the gocyclo bound as the launch-kind
// dispatch grows.
//
// Every arm refuses rather than degrading: the caller asked for isolation, and
// silently handing back an unsandboxed process would be a safety regression,
// not a graceful degrade (plan §7, "no unsandboxed fallback path exists in the
// code").
func (s *Server) sandboxRequestOK(w http.ResponseWriter, r *http.Request, body terminalLaunchRequest, workspaceSource string) bool {
	if s.opts.SandboxProber == nil {
		// A5: nil seam = feature absent = fail closed, exactly like the
		// LaunchManager==nil 503 but scoped to the sandbox sub-feature (501 —
		// capability absent on this daemon build/config, distinct from
		// LaunchManager's total absence).
		http.Error(w, ErrLaunchSandboxUnavailable.Error(), http.StatusNotImplemented)
		return false
	}
	av := s.opts.SandboxProber.ProbeSandbox(r.Context())
	if !av.Available {
		http.Error(w, "sandbox unavailable ("+av.Verdict+"): "+av.Reason, statusForSandboxVerdict(av.Verdict))
		return false
	}
	src, ok := sandboxSourceByID(av.Sources, workspaceSource)
	switch {
	case !ok:
		http.Error(w, "unknown workspace source "+workspaceSource, http.StatusBadRequest)
		return false
	case !src.Available:
		http.Error(w, "workspace source "+workspaceSource+" is not available: "+src.Reason, http.StatusBadRequest)
		return false
	}
	if workspaceSource == "live" && strings.TrimSpace(body.ProjectRoot) == "" {
		http.Error(w, "a sandboxed terminal needs a project directory", http.StatusBadRequest)
		return false
	}
	toolAvail, ok := av.Tools[body.Tool]
	switch {
	case !ok:
		http.Error(w, "tool "+body.Tool+" cannot be sandboxed: no grounded sandbox row for this tool", http.StatusBadRequest)
		return false
	case !toolAvail.Available:
		http.Error(w, "tool "+body.Tool+" cannot be sandboxed: "+toolAvail.Reason, http.StatusBadRequest)
		return false
	}
	return true
}

// kickWatchRootsRefresh invokes Options.RefreshWatchRoots when wired.
// Fail-open: a nil seam is a no-op (standalone dashboard without watcher).
func (s *Server) kickWatchRootsRefresh() {
	if s.opts.RefreshWatchRoots == nil {
		return
	}
	s.opts.RefreshWatchRoots()
}

// sandboxVerdictStatus maps a closed B9 sandbox verdict (plan §7) to the
// HTTP status handleTerminalLaunch's fail-closed check refuses the launch
// with. Table-driven per CLAUDE.md #5 (a growing if/else-if ladder is
// refactored before it lands): verdicts describing the daemon's own
// environment — a missing/too-old backend, an unsupported OS, or a denied
// user-namespace sysctl — are 501 (feature absent server-side, nothing the
// caller can fix); "disabled_by_config" is 403 (the operator switched it
// off, an authorization refusal, not a capability gap). An unrecognised
// verdict is NOT in this table — statusForSandboxVerdict below defaults it
// to 501, the fail-closed floor, so a new verdict added to the probe by a
// future change is never silently treated as available.
var sandboxVerdictStatus = map[string]int{
	"unsupported_platform": http.StatusNotImplemented,
	"backend_missing":      http.StatusNotImplemented,
	"backend_too_old":      http.StatusNotImplemented,
	"userns_denied":        http.StatusNotImplemented,
	"tool_unmapped":        http.StatusNotImplemented,
	"disabled_by_config":   http.StatusForbidden,
}

// statusForSandboxVerdict resolves sandboxVerdictStatus with a fail-closed
// default (501) for any verdict the table doesn't name.
func statusForSandboxVerdict(verdict string) int {
	if status, ok := sandboxVerdictStatus[verdict]; ok {
		return status
	}
	return http.StatusNotImplemented
}

// sandboxSourceByID finds the SandboxSourceAvail entry matching id in a
// probe's Sources list — the server-side membership check
// handleTerminalLaunch applies to a client-supplied workspace_source
// before trusting it, mirroring modelIsMember's role for the model picker.
// ok is false when no entry matches id at all (an unrecognised source
// name, distinct from a recognised-but-unavailable one).
func sandboxSourceByID(sources []SandboxSourceAvail, id string) (src SandboxSourceAvail, ok bool) {
	for _, s := range sources {
		if s.ID == id {
			return s, true
		}
	}
	return SandboxSourceAvail{}, false
}

// errTerminalUnavailable is the ONE honest sentence every 503 on the terminal
// routes uses when Options.LaunchManager is nil (audit DI-16). A nil manager
// means buildTerminalStack returned nothing, which has exactly two causes:
// [handoff].allow_dashboard_launch = false, or no PTY backend on this OS.
// The pre-ConPTY copy ("run the daemon under WSL/Linux") is WRONG since
// 2026-07-04 — a native-Windows daemon runs these terminals.
const errTerminalUnavailable = "the in-dashboard terminal is disabled on this daemon " +
	"([handoff].allow_dashboard_launch = false) or unsupported on this OS " +
	"(Windows before 10 version 1809 has no ConPTY)"

// LaunchableTool annotates ONE entry of the New-Terminal picker with the two
// independent allow-lists that decide what actually happens after the operator
// hits Start (audit DI-06 / DI-07). It is a SIBLING of the plain
// launchable_tools string list, never a replacement — existing clients keep
// reading launchable_tools.
//
// Allowed and Watched are deliberately separate because the gates are
// separate: a tool may be launchable-and-allowed yet produce no captured data,
// or be watched yet refused at launch. "installed" is deliberately ABSENT —
// answering it would run the binary resolver once per launchable tool on every
// poll of this VIEW route; the per-tool /api/terminal/launch/preflight answers
// it on demand.
type LaunchableTool struct {
	Tool string `json:"tool"`
	// Allowed mirrors [terminal.launch].allowed_tools membership — the LAUNCH
	// gate termsvc enforces at spawn time (default empty = deny-all).
	Allowed bool `json:"allowed"`
	// Watched mirrors [observer.watch].enabled_adapters membership — the
	// CAPTURE gate. Computed through diag.AdapterWatched, the one owner of the
	// list's nil-vs-empty rule (nil = every adapter watched; non-nil empty =
	// none), so this flag and /api/terminal/policy's unwatched_allowed_tools
	// can never disagree.
	Watched bool `json:"watched"`
}

// launchableToolInfo annotates the launchable capability set with the two
// independent allow-lists (DI-06). It is pure over the passed config — the
// zero config is the honest floor (nothing allowed, everything watched),
// matching what the launch + watch paths themselves do with a zero config.
func launchableToolInfo(cfg config.Config) []LaunchableTool {
	allowed := make(map[string]bool, len(cfg.Terminal.Launch.AllowedTools))
	for _, t := range cfg.Terminal.Launch.AllowedTools {
		allowed[strings.TrimSpace(t)] = true
	}
	tools := launchableTools()
	out := make([]LaunchableTool, 0, len(tools))
	for _, t := range tools {
		out = append(out, LaunchableTool{
			Tool:    t,
			Allowed: allowed[t],
			Watched: diag.AdapterWatched(cfg, t),
		})
	}
	return out
}

// handleTerminalSessions serves GET /api/terminal/sessions — the live
// terminal-session list (metadata only, no content). Classified VIEW (§9).
// It generalizes /api/launch/sessions under the terminal route namespace.
//
// It is also the picker's annotation SOURCE (DI-06): a paired remote device
// gets 403 on the Local /api/terminal/policy route, so the per-tool allowed /
// watched flags must ride this VIEW route to be readable from a remote tab.
func (s *Server) handleTerminalSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.LaunchManager == nil {
		// Two causes, both honest (DI-16): the operator turned the launch
		// surface off, or this OS cannot build a PTY. JSON so the SPA can read
		// the reason instead of rendering "no launchable tools" (DI-05).
		writeErrStatus(w, errors.New(errTerminalUnavailable), http.StatusServiceUnavailable)
		return
	}
	// Surface the operator's canonicalized [terminal.launch].allowed_project_roots
	// so the "New terminal" dialog can honestly mark which known-project roots a
	// fresh launch will actually accept (empty = only the launcher's own default
	// cwd is permitted). The SPA reuses these canonical strings verbatim — it never
	// re-canonicalizes a path — so its permitted/not-permitted marking matches the
	// server's spawn-time ValidateProjectRoot check.
	var allowedRoots []string
	// shellEnabled reflects [terminal.launch].allow_shell — the "New terminal"
	// dialog uses it to decide whether to offer the plain-shell picker option
	// honestly (rather than always showing it and failing at launch time).
	var shellEnabled bool
	// cfg stays the zero value when the config cannot be loaded — the same
	// deny-all / watch-all floor every other read of an unloadable config uses.
	var cfg config.Config
	if loaded, err := loadConfigForDashboard(s.opts.ConfigPath); err == nil {
		cfg = loaded
		allowedRoots = resolveAllowedProjectRoots(cfg.Terminal.Launch.AllowedProjectRoots)
		shellEnabled = cfg.Terminal.Enabled && cfg.Terminal.Launch.AllowShell
	}
	writeJSON(w, map[string]any{
		"sessions":              s.visibleSnapshot(r.Context()),
		"launchable_tools":      launchableTools(),
		"launchable_tool_info":  launchableToolInfo(cfg),
		"allowed_project_roots": allowedRoots,
		"shell_enabled":         shellEnabled,
		// The GUI launch surface (T2), strictly ADDITIVE: the picker's
		// "IDE / desktop app" group and the live detached-app list. A GUI run
		// owns no PTY, so it can never appear in "sessions" — the two lists
		// describe disjoint things and neither shadows the other.
		"gui_launchables": guiLaunchableInfo(cfg),
		"gui_runs":        s.guiRuns(),
	})
}

// ToolPreflight is the wire shape of GET /api/terminal/launch/preflight — the
// pre-launch binary-resolution verdict for a launchable tool
// (tool-binary-resolution arc). It tells the New-Terminal dialog, BEFORE a
// launch, whether the daemon can resolve the tool's binary and — when it cannot
// — the grounded install command to fix it. The install ARGV is NEVER carried
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
	// takes one) from the preflight alone, without a second lookup — and so a
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
	// ONLY when no install plan exists — never alongside a usable
	// InstallCommand — and is omitted from the wire when empty.
	InstallNote string `json:"install_note,omitempty"`
}

// handleTerminalPreflight serves GET /api/terminal/launch/preflight?tool=<name>
// — the pre-launch binary-resolution verdict (VIEW; tool-binary-resolution
// arc). It resolves how the daemon would find the tool's binary and returns an
// honest verdict plus, when unresolved, the grounded install command, so the
// dialog can warn before a launch that would fail. The verdict is produced by
// the server-side Options.ToolPreflight seam (registry + resolver); a nil seam
// is the honest disabled state (501). An unknown / non-launchable tool is 400
// (the seam reports ok=false), mirroring handleTerminalLaunch's tool
// validation.
func (s *Server) handleTerminalPreflight(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.ToolPreflight == nil {
		writeErrStatus(w, errors.New("preflight unavailable — this dashboard runs without the tool-resolution seam (run via `observer start`)"), http.StatusNotImplemented)
		return
	}
	tool := strings.TrimSpace(r.URL.Query().Get("tool"))
	if tool == "" {
		writeErrStatus(w, errors.New("missing tool query parameter"), http.StatusBadRequest)
		return
	}
	// DI-18: the reserved plain-shell pseudo-tool LAUNCHES fine (handleTerminalLaunch
	// special-cases termsvc.ShellTool and skips binary resolution entirely) but has
	// no binary to preflight. Keep the 400 — there is genuinely no verdict to give —
	// but say WHY, instead of the misleading "not launchable" the generic arm below
	// produces. termsvc.ShellTool is the single owner of the sentinel's spelling
	// (handleTerminalLaunch reads the same constant); the SPA mirrors it as
	// SHELL_TOOL in NewTerminalDialog.tsx.
	if tool == termsvc.ShellTool {
		writeErrStatus(w, errors.New("the plain shell has no binary to preflight"), http.StatusBadRequest)
		return
	}
	pf, ok := s.opts.ToolPreflight(tool)
	if !ok {
		writeErrStatus(w, errors.New("tool "+tool+" is not launchable in the embedded terminal"), http.StatusBadRequest)
		return
	}
	writeJSON(w, pf)
}

// terminalLaunchModelsResponse is the wire shape of
// GET /api/terminal/launch/models — the New Terminal model picker's
// suggestion list (B5). Supported is false (with an empty Models slice)
// when the tool has no grounded model-selection mechanism (ModelSpec.Kind
// ModelNone) or the tool is unknown/not launchable; the frontend treats
// supported=false identically to a fetch error — no picker.
type terminalLaunchModelsResponse struct {
	Tool      string            `json:"tool"`
	Supported bool              `json:"supported"`
	Models    []modelSuggestion `json:"models"`
}

// handleTerminalLaunchModels serves GET /api/terminal/launch/models?tool=<name>
// — the New Terminal model picker's suggestion list (B5, VIEW). It composes
// recent usage history (via the nil-able Options.RecentModels seam) with the
// capability registry's grounded Known examples through the single shared
// modelSuggestionsFor function — the SAME composition handleTerminalLaunch
// uses to validate a client-supplied model. A nil RecentModels seam or an
// unknown/non-model-capable tool both resolve to supported=false rather than
// an error status, matching the frontend's fail-soft "any problem = no
// picker" contract (unlike preflight, which distinguishes 501/400).
func (s *Server) handleTerminalLaunchModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tool := strings.TrimSpace(r.URL.Query().Get("tool"))
	if tool == "" {
		http.Error(w, "missing tool query parameter", http.StatusBadRequest)
		return
	}
	supported, suggestions := modelSuggestionsFor(r.Context(), s.opts.RecentModels, tool)
	writeJSON(w, terminalLaunchModelsResponse{
		Tool: tool, Supported: supported, Models: suggestions,
	})
}

// terminalInstallRequest is the POST /api/terminal/install body. The only client
// input is the tool NAME — used SOLELY as a registry map key to look up the
// server-side install argv; the request never contributes argv (the injection
// surface is zero by construction, tool-binary-resolution arc §Security).
type terminalInstallRequest struct {
	Tool string `json:"tool"`
}

// handleTerminalInstall serves POST /api/terminal/install — the guided
// "Install in terminal" affordance (tool-binary-resolution arc). It spawns the
// tool's GROUNDED, compile-time-constant install command (from the capability
// registry, keyed by the request's tool name) in a visible local-only PTY, so
// the operator sees and can Ctrl-C it. Classified LOCAL + confirm-token-gated,
// EXACTLY like the Tailscale setup handlers — a machine-reaching mutation a
// remote principal must never drive. Gates, in order: confirm token FIRST; then
// LaunchManager nil → 503; the [terminal.launch].allow_install kill-switch off
// (or its seam nil) → 403; no grounded install command for the tool → 400. The
// argv is a registry constant supplied by the Options.ToolInstallHint seam,
// never request input, and the spawned session is SpecSetup → local-writer-only.
//
// DELIBERATELY NOT gated by [terminal.launch].allowed_tools or
// allow_fresh_agent (audit DI-21, decision confirmed 2026-09-02): installing is
// not launching. The argv is a compile-time constant, the route is Local +
// confirm-token gated, and the operator who flipped allow_install on has
// already consented to running vendor installers from here. Gating install on
// the LAUNCH allow-list would force an operator to widen the launch policy just
// to obtain a binary. The picker's per-tool `allowed` flag (LaunchableTool,
// DI-06) closes the real UX gap instead. Pinned by
// TestTerminalInstallIsNotGatedByAllowedTools.
//
// Every non-200 emits application/json {"error": …} via writeErrStatus (DI-05)
// so the SPA can map status → copy instead of surfacing a raw body.
func (s *Server) handleTerminalInstall(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	if s.opts.LaunchManager == nil {
		writeErrStatus(w, errors.New(errTerminalUnavailable), http.StatusServiceUnavailable)
		return
	}
	if s.opts.AllowToolInstall == nil || !s.opts.AllowToolInstall() {
		writeErrStatus(w, errors.New("guided install is disabled — set [terminal.launch].allow_install = true to enable the Install-in-terminal affordance"), http.StatusForbidden)
		return
	}
	var body terminalInstallRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErrStatus(w, fmt.Errorf("invalid JSON body: %w", err), http.StatusBadRequest)
		return
	}
	tool := strings.TrimSpace(body.Tool)
	if tool == "" {
		writeErrStatus(w, errors.New("missing tool"), http.StatusBadRequest)
		return
	}
	if s.opts.ToolInstallHint == nil {
		writeErrStatus(w, errors.New("no grounded install command for "+tool), http.StatusBadRequest)
		return
	}
	argv, display, ok := s.opts.ToolInstallHint(tool)
	if !ok {
		writeErrStatus(w, errors.New("no grounded install command for "+tool), http.StatusBadRequest)
		return
	}
	handle, err := s.opts.LaunchManager.CreateSetup(SetupSpec{
		Argv:  argv,
		Label: "install:" + tool,
	})
	if err != nil {
		writeSetupSpawnErr(w, err)
		return
	}
	s.opts.Logger.Info("dashboard: guided tool install spawned", slog.String("tool", tool), slog.String("command", display))
	writeJSON(w, map[string]any{
		"handle":  handle,
		"tool":    tool,
		"command": display,
	})
	// Best-effort: the install script may create the tool's home/sessions
	// tree before first launch. Even when it does not, the retry schedule
	// behind RefreshWatchRoots is harmless. Primary kick remains post-launch.
	s.kickWatchRootsRefresh()
}

// handleAttachSessions serves GET /api/attach/sessions — the live
// LIVE-JOINABLE session list (session-attach design Phase 2, dashboard "Jump
// in"). It returns the visibleSnapshot(ctx) rows that are LIVE daemon-owned PTY
// runs of ANY valid terminal_run kind (fresh / handoff / attach / resume) and
// are not setup: every dashboard-launched terminal PLUS every
// `observer <tool> --attach` session. Each such row is a daemon-owned PTY a
// dashboard tab (local or remote) can join as an extra seat over the existing
// /ws/launch/<handle> bridge. Classified VIEW (§9): metadata only, no content.
//
// The filter is a capability test, not a source-identity test (CLAUDE.md #3):
// any run with a VALID kind on a live, non-setup handle is joinable, because it
// is a real daemon-owned PTY with exact liveness. A kindless row predates the
// run-identity wiring and is not treated as a joinable run. A BARE external
// session (no daemon PTY at all) is excluded honestly — its stdio belongs to
// the user's own shell and is never re-parentable, and it has no launch-snapshot
// row in the first place, so it never appears here. `observer <tool> --attach`
// remains the way to make a session running in the operator's OWN terminal
// daemon-owned and therefore joinable.
//
// A fresh run carries session_id only once correlation links it (SessionForRun;
// the generic sweep links within ~10–30s). Until then the row appears with an
// empty session_id and the frontend keeps its "Jump in" button disabled.
//
// session_id on THIS endpoint always means "the session this PTY is driving".
// For a handoff row that is the FORKED session — NOT the SOURCE session the
// spec stamped at spawn (which Snapshot preserves for /api/terminal/sessions
// source labeling). So a handoff row's SessionID is overridden here with the
// run's correlated session id (empty until correlation links it), keeping the
// row LISTED but matched to the fork's session detail, never the source's. This
// override is endpoint-scoped: Snapshot/visibleSnapshot are unchanged.
//
// The explicit info.Setup skip is defense in depth: visibleSnapshot already
// redacts setup rows for REMOTE callers, but a LOCAL caller's snapshot still
// carries them; a privileged local-only setup PTY must never be offered here
// (SubscribeRemote refuses SpecSetup, but a local subscribe would not).
//
// Each row is the LaunchInfo JSON verbatim (no bespoke struct) — the frontend
// "Jump in" affordance builds against that shape directly.
//
// Remote callers keep visibleSnapshot semantics: attach/resume rows are the
// remote-VIEW-sensitive class and are redacted when
// [remote].allow_terminal_view = false, while fresh/handoff dashboard terminals
// are the non-sensitive floor a remote caller always sees. That gate is built
// now (see visibleSnapshot / allowTerminalView), not deferred.
func (s *Server) handleAttachSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.LaunchManager == nil {
		http.Error(w, "launch unavailable", http.StatusServiceUnavailable)
		return
	}
	all := s.visibleSnapshot(r.Context())
	out := make([]LaunchInfo, 0, len(all))
	for _, info := range all {
		if info.Exited || info.Setup {
			continue // dead handle / privileged local-only setup PTY
		}
		if !termrun.Kind(info.Kind).Valid() {
			continue // kindless row predates run-identity wiring — not a joinable run
		}
		// On THIS endpoint session_id ALWAYS means "the session this PTY is
		// driving". For a handoff that is the FORKED session, not the SOURCE
		// session the spec stamps at spawn (which Snapshot preserves for the
		// source-labeling /api/terminal/sessions consumers). Override the local
		// copy with the run's CORRELATED session id — known only once correlation
		// links it (~10–30 s) — or "" pre-link, so the row is still LISTED but
		// matches no session-detail page until the fork is known. Endpoint-scoped:
		// Snapshot/visibleSnapshot semantics are untouched.
		if termrun.Kind(info.Kind) == termrun.KindHandoff {
			info.SessionID = ""
			if info.RunID != "" {
				if sid, ok := s.opts.LaunchManager.SessionForRun(info.RunID); ok {
					info.SessionID = sid
				}
			}
		}
		out = append(out, info)
	}
	writeJSON(w, map[string]any{"sessions": out})
}

// resolveAllowedProjectRoots canonicalizes the configured
// [terminal.launch].allowed_project_roots through the SAME internal/termsvc
// validator the spawn path re-runs (real filesystem identity, symlinks
// resolved, UNC/relative rejected). A stale or now-invalid entry is skipped
// rather than failing the whole list, so the read surface degrades gracefully.
// The returned slice holds the exact canonical strings the server matches a
// requested project_root against — the SPA marks known roots permitted/not by
// comparing against these, never by re-canonicalizing client-side. Returns a
// non-nil empty slice when nothing is allow-listed (deny-all: only the default
// cwd is permitted) so the JSON field is always a real array.
func resolveAllowedProjectRoots(roots []string) []string {
	out := make([]string, 0, len(roots))
	for _, raw := range roots {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		canonical, err := termsvc.ValidateProjectRoot(entry, []string{entry})
		if err != nil {
			continue
		}
		out = append(out, canonical)
	}
	return out
}

// handleLaunchAdmin serves the running-session admin routes under
// /api/launch/: GET /api/launch/sessions lists live terminal sessions
// (metadata only — no content), and DELETE /api/launch/<handle> reaps one.
// Gated by the LaunchManager seam; DELETE is Origin-checked by browserGuard.
func (s *Server) handleLaunchAdmin(w http.ResponseWriter, r *http.Request) {
	if s.opts.LaunchManager == nil {
		http.Error(w, "launch unavailable", http.StatusServiceUnavailable)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/launch/")
	if rest == "sessions" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, map[string]any{"sessions": s.visibleSnapshot(r.Context())})
		return
	}
	// DELETE /api/launch/<handle> — reap one session.
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if rest == "" || strings.Contains(rest, "/") {
		http.NotFound(w, r)
		return
	}
	// A privileged SpecSetup PTY (sudo login / install / operator-grant) is
	// LOCAL-ONLY for its whole lifecycle: a remote-exposed principal may not
	// terminate it either. Return 404 so the remote caller cannot even confirm
	// the handle exists (same confidentiality posture as the snapshot redaction
	// + SubscribeRemote refusal). The owner-local loopback listener is never
	// remote-exposed, so the local owner's Cancel still reaps it.
	if remoteExposedFromContext(r.Context()) && s.opts.LaunchManager.IsSetupSession(rest) {
		http.NotFound(w, r)
		return
	}
	s.opts.LaunchManager.Close(rest)
	w.WriteHeader(http.StatusNoContent)
}

// wsControl is the text-frame control protocol between the browser and the
// PTY bridge. Terminal I/O rides BINARY frames (keystrokes in, output out);
// TEXT frames are JSON control messages. The client sends {"t":"resize",…};
// the server emits {"t":"exit","code":…} when the process ends.
type wsControl struct {
	T    string `json:"t"`
	Rows uint16 `json:"rows,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
	Code int    `json:"code,omitempty"`
	// Gen identifies the session-monotonic writer-lease generation on
	// control_granted and control_revoked. The browser uses it to ignore a stale
	// revoke that arrives after a newer grant during rapid takeover ping-pong.
	Gen uint64 `json:"gen,omitempty"`
	// InitialRows/InitialCols ride the on-open {"t":"pty_size",…} geometry frame
	// (Feature 2) alongside Rows/Cols (the current size), so the web terminal can
	// restore the PTY's real dimensions. Omitted on every other control frame.
	InitialRows uint16 `json:"initial_rows,omitempty"`
	InitialCols uint16 `json:"initial_cols,omitempty"`
	// Cap + Confirm ride the remote writer-acquire control frame
	// ({"t":"acquire-writer","cap":…,"confirm":…}) — the single-use terminal-
	// control capability + its bound confirm (§4.γ). They are accepted ONLY in
	// this TEXT frame body over the already-Origin-checked, cookie-authenticated
	// websocket, never a URL/subprotocol/query (§8.1 #5).
	Cap     string `json:"cap,omitempty"`
	Confirm string `json:"confirm,omitempty"`
	// By identifies the requester that superseded this writer (local|remote).
	By string `json:"by,omitempty"`
	// Expiry marks a control_revoked whose cause was the writer lease AGEING
	// OUT (idle lifetime or hard cap) rather than a takeover or a
	// trust-withdrawing revoke. It is the wire half of the demote-instead-of-
	// close rule (shouldCloseOnRevoke): the socket stays up, and the client
	// needs to know WHICH kind of revocation it just saw, because the two call
	// for opposite reactions.
	//
	// An expiry says nothing about the device's trust, so a client holding a
	// standing secret may silently re-present it and carry on — that is the
	// "the client can then silently re-acquire" behaviour this arc promised.
	// A revoke by a local/remote takeover, or any trust-withdrawing revoke,
	// must NOT be auto-answered: the owner just took control back, and a device
	// that immediately re-acquired would be fighting them. Without this flag
	// both arrive as {"t":"control_revoked","by":""} and are indistinguishable.
	// Added 2026-07-25 (review B3).
	Expiry bool `json:"expiry,omitempty"`
	// Reason carries the typed denial taxonomy on control_denied.
	Reason ControlDenialReason `json:"reason,omitempty"`
	// PolicyStop rides the {"t":"exit",…} frame ONLY, when this run's PTY
	// child was stopped by an org-managed node's own node-intervention loop
	// (policystop.go). Omitted when there is nothing to show — a bare exit
	// still renders exactly as before this arc.
	PolicyStop *PolicyStop `json:"policy_stop,omitempty"`
}

// ptyGeometry is the PTY dimension snapshot the on-open (and control-transition)
// pty_size frame carries (Feature 2): the current and initial dimensions.
type ptyGeometry struct {
	rows, cols, initialRows, initialCols uint16
}

// known reports whether this snapshot carries real dimensions. The launch
// manager seeds a session's geometry from the launch Spec and adopts the first
// successful resize when that Spec was 0×0, so an all-zero pair is its documented
// "size not yet known" — never a legitimate window size (a 0-row or 0-col winsize
// does not exist). Both axes must be known: a half-known pair describes no
// terminal the client could fit to.
func (g ptyGeometry) known() bool { return g.rows != 0 && g.cols != 0 }

// ptySizeForHandle returns the PTY geometry the pty_size frame reports for handle
// (Feature 2). It reads the ONE live snapshot the launch manager owns — never a
// second geometry source — so the value tracks the manager's resize funnel. All
// zero (including an unknown handle) means "size not yet known".
func (s *Server) ptySizeForHandle(handle string) ptyGeometry {
	if s.opts.LaunchManager == nil {
		return ptyGeometry{}
	}
	for _, info := range s.opts.LaunchManager.Snapshot() {
		if info.ID == handle {
			return ptyGeometry{rows: info.Rows, cols: info.Cols, initialRows: info.InitialRows, initialCols: info.InitialCols}
		}
	}
	return ptyGeometry{}
}

// writePTYSize sends the on-open (and, cheaply, control-transition) geometry
// frame (Feature 2), the pinned wire contract {"t":"pty_size","rows","cols",
// "initial_rows","initial_cols"}. Best-effort like the other control writes.
func writePTYSize(ctx context.Context, c *websocket.Conn, g ptyGeometry) {
	_ = wsjson.Write(ctx, c, wsControl{
		T: "pty_size", Rows: g.rows, Cols: g.cols,
		InitialRows: g.initialRows, InitialCols: g.initialCols,
	})
}

// ptySizeAnnounceInterval / ptySizeAnnounceWindow bound the on-open wait for a
// PTY geometry that is not known yet (Q1 probe, P4). The interval is short
// because the gap it covers is short — the launch manager converges within a
// spawn, and a client's own first resize lands in milliseconds — and the window
// is small enough that a session which simply never acquires a size (a launch
// that requested none and a client that never resizes) costs one idle goroutine
// for a couple of seconds and then nothing, rather than a permanent poller.
const (
	ptySizeAnnounceInterval = 25 * time.Millisecond
	ptySizeAnnounceWindow   = 2 * time.Second
)

// startPTYSizeAnnounce performs the bridge's on-open geometry announce and
// returns the send closure the bridge reuses on control transitions.
//
// An UNKNOWN geometry is never announced: the launch manager reports all-zero
// until the size is known (a launch that requested no dimensions, with no resize
// yet), and {"t":"pty_size"} with every field stripped by omitempty tells the
// client nothing it can restore — which is the frame's whole promise, and
// exactly what the Q1 probe captured as the FIRST text frame of every session
// (P4). So the returned closure reports whether it actually wrote, and an
// on-open announce with nothing to say instead leaves a bounded waiter that
// sends the first REAL geometry, off the bridge's own goroutine.
//
// nil geo (older call sites / tests) disables the frame entirely.
func startPTYSizeAnnounce(ctx context.Context, c *websocket.Conn, geo func() ptyGeometry) func() bool {
	send := func() bool {
		if geo == nil {
			return false
		}
		g := geo()
		if !g.known() {
			return false
		}
		writePTYSize(ctx, c, g)
		return true
	}
	if !send() {
		go awaitPTYSize(ctx, send, ptySizeAnnounceInterval, ptySizeAnnounceWindow)
	}
	return send
}

// awaitPTYSize retries send until it reports a frame actually went out, the
// window elapses, or ctx is done — whichever comes first. send is the bridge's
// geometry announce, which writes nothing while the size is unknown; this is the
// only thing that turns "nothing to announce yet" into "announced once, with real
// dimensions". It never sends more than one frame: the first successful send
// ends the loop.
//
// Durations are parameters rather than the constants above so the behaviour is
// testable without a real 2-second wait.
func awaitPTYSize(ctx context.Context, send func() bool, interval, window time.Duration) {
	deadline := time.NewTimer(window)
	defer deadline.Stop()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-tick.C:
			if send() {
				return
			}
		}
	}
}

// applyResizeFrame forwards ONE client {"t":"resize"} frame to a live writer
// lease and, on a reattaching client's no-op resize, spends the bridge's
// one-shot repaint nudge. It returns the new "already nudged" state.
//
// Why the nudge exists: a reconnecting client (mobile page reload) replays the
// session's output ring and then sends a resize carrying the SAME dimensions the
// PTY already has. Linux tty_do_resize() skips SIGWINCH when the winsize is
// unchanged (measured: 3 TIOCSWINSZ calls produced only 2 SIGWINCHs), so that
// resize is a silent no-op — and a full-screen TUI (Claude Code lives in the
// ?1049h alternate buffer) NEVER repaints, leaving whatever corrupted or partial
// screen was on the wire at reconnect time stuck there indefinitely. Bouncing
// the PTY through (rows-1, cols) and straight back forces exactly ONE guaranteed
// SIGWINCH, so the child redraws its whole screen. Do NOT "simplify" this into a
// single resize: an identical winsize raises no signal at all.
//
// The geometry snapshot is deliberately taken BEFORE the client's own resize is
// applied — afterwards the manager's snapshot has already converged on the
// requested size and every resize would misread as a no-op.
//
// Best-effort like the other control writes: a failed resize never breaks the
// connection. The nudge rides the writer lease (a read-only viewer's resize
// frame is dropped before this call, and WriterLease.Resize would return
// ErrNotWriter anyway) and fires at most once per bridge, so the momentary
// one-row flicker that every viewer of this PTY sees stays bounded.
func applyResizeFrame(writer LaunchWriter, geo func() ptyGeometry, rows, cols uint16, alreadyNudged bool) bool {
	var before ptyGeometry
	if geo != nil {
		before = geo()
	}
	_ = writer.Resize(rows, cols)
	mid, ok := repaintNudgeRows(before, rows, cols, alreadyNudged)
	if !ok {
		return alreadyNudged
	}
	_ = writer.Resize(mid, cols)
	_ = writer.Resize(rows, cols)
	return true
}

// repaintNudgeRows decides whether a writer's resize frame needs the forced-
// SIGWINCH reattach repaint nudge (see bridgeTerminalWS's resize branch for the
// kernel behaviour that makes it necessary) and, when it does, returns the
// intermediate row count to bounce the PTY through before restoring rows.
//
// before is the PTY geometry snapshot taken BEFORE the client's own resize was
// applied — after it, the snapshot has already converged on the requested size
// and every resize would misread as a no-op. rows/cols are the client's request.
//
// A nudge is issued only when all three hold: this bridge has not nudged yet
// (alreadyNudged is false), the geometry is KNOWN (an all-zero snapshot means
// "size not yet known" and there is nothing to bounce around), and the requested
// size is IDENTICAL to the live one — a resize that actually changes the winsize
// already raises SIGWINCH on its own, so nudging it would be redundant churn.
//
// The intermediate row count shrinks by one rather than growing, so the PTY is
// never briefly taller than the client's real viewport; a 1-row terminal bounces
// upward instead because 0 rows is not a legal winsize.
func repaintNudgeRows(before ptyGeometry, rows, cols uint16, alreadyNudged bool) (uint16, bool) {
	if alreadyNudged || before.rows == 0 || before.cols == 0 {
		return 0, false
	}
	if rows != before.rows || cols != before.cols {
		return 0, false
	}
	switch {
	case rows > 1:
		return rows - 1, true
	case rows == 1:
		return rows + 1, true
	default:
		return 0, false
	}
}

// handleLaunchWS serves GET /ws/launch/<handle> — the owner-local terminal
// bridge on the direct loopback listener. It upgrades to a websocket (Accept
// rejects cross-origin by default), SUBSCRIBES a read-only output viewer, and
// acquires the owner-local writer lease (§4.α: this loopback path is
// CapabilityLocal provenance, so it takes the writer without a grant and can
// never be refused — a second local tab takes over). On disconnect the viewer
// unsubscribes and the writer lease is released; the child process keeps running
// (an always-on pump drains its PTY into a replay ring), so a tab-close/refresh
// survives and a reconnecting client replays recent output then tails live.
func (s *Server) handleLaunchWS(w http.ResponseWriter, r *http.Request) {
	if s.opts.LaunchManager == nil {
		http.NotFound(w, r)
		return
	}
	handle := strings.TrimPrefix(r.URL.Path, "/ws/launch/")
	if handle == "" || strings.Contains(handle, "/") {
		http.NotFound(w, r)
		return
	}

	// Accept FIRST so a cross-origin upgrade is rejected before any session
	// state is touched. On rejection Accept has already written the response.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
	if err != nil {
		return
	}
	c.SetReadLimit(1 << 20) // allow large pastes; terminal input is otherwise tiny
	defer func() { _ = c.CloseNow() }()

	// Listener provenance (§4.4), resolved at the boundary — NOT from any client
	// field. A remote-exposed request subscribes through SubscribeRemote, which
	// REFUSES a SpecSetup (privileged, local-only) session: its output can echo a
	// typed sudo password / login URL, so a paired remote principal must not even
	// READ it. The owner-trusted loopback path uses Subscribe (setup PTYs are
	// driven and watched locally, so the in-dashboard xterm embed still works).
	remoteExposed := remoteExposedFromContext(r.Context())
	// Deny-by-default remote content access to a remote-sensitive session
	// (§3.2): a paired remote device may not READ the PTY of a session the
	// operator launched with `observer <tool> --attach` (KindAttach) OR a native
	// resume of a real closed transcript (KindResume) — its TUI can echo
	// secrets/customer data — UNLESS the owner has turned on the Phase-4 remote-
	// VIEW opt-in [remote].allow_terminal_view. When off, close with the SAME
	// "session not found" policy close SubscribeRemote uses for a refused setup
	// session, so a remote caller cannot distinguish "refused" from "absent".
	// When ON, the remote caller may VIEW (read-only subscribe) — but WRITER
	// acquisition stays governed by the EXISTING remote-write path below
	// (allow_terminal + the §4.δ execute conjunction); the view opt-in is
	// strictly weaker and never touches that. Gated on run KIND at the dashboard
	// boundary — never a termsession branch.
	if remoteExposed && s.opts.LaunchManager.IsRemoteSensitiveSession(handle) {
		if !s.allowTerminalView() {
			_ = c.Close(websocket.StatusPolicyViolation, "session not found")
			return
		}
		// View opted in: admit the read-only subscribe, but register this viewer
		// under a bridge-scoped cancelable context so an allow_terminal_view→false
		// flip tears it down immediately (§3.2 read-side revoke). Rebind the
		// request onto the cancelable context so the bridge below observes the
		// cancel. Keyed by the device fingerprint so a per-device revoke (F2) can
		// target exactly this viewer.
		vctx, vcancel := context.WithCancel(r.Context())
		defer vcancel()
		device := sessionCookie(r)
		// Key the viewer registry by the FULL device-session hash (F2b), never
		// the 32-bit display fingerprint, so a per-device revoke targets exactly
		// this device and a fingerprint collision can never disconnect it.
		unregister := s.registerSensitiveViewer(deviceSessionKey(device), vcancel)
		// F1: RE-CHECK the live gate AFTER registering. A concurrent
		// allow_terminal_view→false flips the gate and THEN drains the registry;
		// a subscribe that passed the first check but registered after that drain
		// would otherwise stream forever. Because the disable path orders
		// gate-flip → drain, and we order register → re-read, the two interleave
		// safely: either the drain observes our registration (and cancels it), or
		// the flip is visible to this re-read (and we refuse). Never both survive.
		if !s.allowTerminalView() {
			unregister()
			_ = c.Close(websocket.StatusPolicyViolation, "session not found")
			return
		}
		// F1a: RE-VALIDATE the DEVICE SESSION itself after registering — not just
		// the view gate. The SAME drain-then-register race closes for a session
		// REVOKE/expiry: an admin/self revoke drains the registry AFTER marking
		// the session dead, so a viewer that registered past that drain is caught
		// here by a post-register liveness re-read (revoked/expired ⇒ refuse). The
		// revoke orders mark-dead → drain and we order register → re-read, so the
		// two interleave safely (mirrors the gate re-check above).
		if !s.deviceSessionLive(device) {
			unregister()
			_ = c.Close(websocket.StatusPolicyViolation, "session not found")
			return
		}
		defer unregister()
		// F1b: BIND this viewer to the device session's lifetime — cancel it the
		// moment the session ends (revoke / rotate / TTL / idle expiry), so a
		// device that ends WITHOUT the operator flipping allow_terminal_view still
		// stops receiving attach/resume output at once. Exits on viewer disconnect.
		s.bindViewerLifetime(device, vctx.Done(), vcancel)
		r = r.WithContext(vctx)
	}
	var sub LaunchSubscription
	if remoteExposed {
		sub, err = s.opts.LaunchManager.SubscribeRemote(handle)
	} else {
		sub, err = s.opts.LaunchManager.Subscribe(handle)
	}
	if err != nil {
		// A setup-session refusal and a genuine not-found are both closed the
		// same way so a remote caller cannot distinguish "refused" from "absent".
		_ = c.Close(websocket.StatusPolicyViolation, "session not found")
		return
	}
	defer s.opts.LaunchManager.Unsubscribe(sub)

	// A remote-exposed request may never take the owner-local writer implicitly
	// (that would hand a remote principal an ungated PTY). It starts read-only and
	// must acquire through the §4.δ conjunction (AcquireWriterRemote) via a
	// writer-acquire control frame; only after that credential gate may live
	// policy permit a takeover. The owner-trusted loopback path keeps the
	// CapabilityLocal writer (never refused).
	if remoteExposed {
		device := sessionCookie(r)
		deviceFP := deviceFingerprint(device)
		peer := hostnameOnly(r.RemoteAddr)
		// An attached terminal socket IS device activity: keep its device
		// session's idle clock fresh for as long as this socket lives, so a user
		// watching a terminal does not have the session expire underneath them
		// (2026-07-25). Extends only — it can never resurrect a revoked/expired
		// session, and the absolute TTL is untouched.
		s.keepDeviceSessionAliveWhileAttached(device, r.Context().Done())
		// Writer-acquire lifecycle audit (plan §8.1), metadata only. The single-
		// use capability + confirm are NEVER recorded — only the request, the
		// coarse outcome, and the device/handle correlation. termlease.Authorize
		// is atomic (claim+confirm+consume in one call), so the claim and confirm
		// legs are not separately observable without leaking secret-adjacent
		// detail; they are collapsed into request + a single coarse denial on any
		// failed leg (never which leg) + consume on success.
		acquire := func(capTok, confirm string) (LaunchWriter, error) {
			s.auditTerminalControl("terminal_control_request", deviceFP, handle, peer, "request", "acquire_writer")
			standingCredential := remoteauth.IsStandingSecret(capTok)
			wl, err := s.opts.LaunchManager.AcquireWriterRemote(RemoteWriterRequest{
				Handle:          handle,
				DeviceSessionID: device,
				CapabilityToken: capTok,
				Confirm:         confirm,
				RemoteExposed:   true, // provenance, resolved at the boundary
			})
			if err != nil || wl == nil {
				reason := ControlDenialUnavailable
				var denial *ControlDeniedError
				if errors.As(err, &denial) {
					if denial.Reason != "" {
						reason = denial.Reason
					}
					if denial.CapabilityConsumed {
						s.auditTerminalControl("terminal_control_capability_consume", deviceFP, handle, peer, "allow", "consumed_before_"+string(reason))
					}
				}
				// The reason is coarse and stable; it never reveals which credential
				// sub-leg failed. A consumed capability is audited separately above.
				s.auditTerminalControl("terminal_control_denied", deviceFP, handle, peer, "deny", string(reason))
				return wl, err
			}
			if !standingCredential {
				s.auditTerminalControl("terminal_control_capability_consume", deviceFP, handle, peer, "allow", "")
			}
			return wl, err
		}
		// Denied-frame coalescer: a viewer with no writer lease flooding forged
		// input/control frames (§4.β drop) must not amplify the audit log — its
		// drops are batched into bounded rows carrying a coalesced count.
		denied := s.newDeniedFrameCoalescer(deviceFP, handle, peer)
		// closeOnHardRevoke=true: on the REMOTE bridge an admin/device revoke of
		// the writer lease closes the socket (the device is no longer trusted); a
		// lease takeover only demotes. The owner-local bridge below passes false
		// so its revoke behaviour stays byte-identical (always demote).
		s.bridgeTerminalWS(r.Context(), c, sub, nil, acquire, denied, true, handle, func() ptyGeometry { return s.ptySizeForHandle(handle) })
		return
	}

	// Owner-local writer lease (loopback path). If the session vanished between
	// Subscribe and here we degrade to a read-only viewer rather than failing.
	writer, werr := s.opts.LaunchManager.AcquireWriterLocal(handle)
	if werr == nil {
		defer writer.Release()
	}

	// Local mid-stream re-acquire: after a native-terminal reclaim revokes this
	// seat's lease, the client asks for control back with the same
	// {"t":"acquire-writer"} frame the remote path uses. The loopback seat is
	// owner-trusted (it took the CapabilityLocal writer unconditionally above),
	// so re-acquiring is the same privilege — no conjunction, cap/confirm
	// ignored.
	localAcquire := func(_, _ string) (LaunchWriter, error) {
		return s.opts.LaunchManager.AcquireWriterLocal(handle)
	}

	// The owner-local loopback path has no forged-viewer amplification surface
	// (it holds the writer), so no denied-frame coalescer is wired.
	// closeOnHardRevoke=false: the local loopback path always DEMOTES on a
	// revoke (byte-identical to prior behaviour) — the socket-closing branch is
	// remote-only.
	s.bridgeTerminalWS(r.Context(), c, sub, writer, localAcquire, nil, false, handle, func() ptyGeometry { return s.ptySizeForHandle(handle) })
}

// terminalPingInterval / terminalPingTimeout drive the WS liveness probe. Every
// interval the bridge pings the peer and waits up to the timeout for the pong
// (coder/websocket auto-replies to the client's pings and reads the pong on the
// main read loop). This detects a dead / half-open TCP peer — NOT an idle one:
// a terminal viewer legitimately sends nothing for long stretches while
// watching, so we never impose a read-idle deadline (that would evict a
// legitimately-idle watcher). Applies to BOTH the local and remote bridge —
// liveness is a transport property, not a security branch.
// terminalPingIntervalNs / terminalPingTimeoutNs hold the ping cadence in
// nanoseconds. They are atomics (not plain consts) solely so a test can lower
// the cadence race-free while a bridge goroutine reads it concurrently; the
// production defaults (set in init) are unchanged.
// terminalPingFailuresAllowed is how many CONSECUTIVE ping failures the bridge
// tolerates before declaring the peer dead (default 5 ⇒ ~3.3 minutes at the
// 30s/10s defaults). A mobile browser FREEZES a backgrounded tab: the user
// leaving to copy a pairing code from their mail app stops the tab answering
// pings, and the previous one-strike rule tore the bridge down inside ~40s. The
// check is not removed — a genuinely dead peer is still reaped, just after the
// grace window.
var (
	terminalPingIntervalNs    atomic.Int64
	terminalPingTimeoutNs     atomic.Int64
	terminalPingFailureBudget atomic.Int64
)

func init() {
	terminalPingIntervalNs.Store(int64(30 * time.Second))
	terminalPingTimeoutNs.Store(int64(10 * time.Second))
	terminalPingFailureBudget.Store(5)
}

// SetTerminalPingPolicy live-applies the terminal websocket liveness bounds:
// the ping interval, the per-pong timeout, and how many CONSECUTIVE failures are
// tolerated before the bridge tears down. Non-positive values leave the
// corresponding default in place, so a config that omits a key (or seeds 0) is a
// no-op for that key.
//
// It is a package-level setter rather than an Options field because the bounds
// are read by long-lived per-bridge goroutines, so they must be readable
// race-free from any Server instance; the same atomics are the existing test
// seam. Called once at daemon assembly from the [terminal] config block.
func SetTerminalPingPolicy(interval, timeout time.Duration, failuresAllowed int) {
	if interval > 0 {
		terminalPingIntervalNs.Store(int64(interval))
	}
	if timeout > 0 {
		terminalPingTimeoutNs.Store(int64(timeout))
	}
	if failuresAllowed > 0 {
		terminalPingFailureBudget.Store(int64(failuresAllowed))
	}
}

// bridgeTerminalWS bridges a terminal Subscription (output) and an optional
// WriterLease (input) to a websocket. A nil writer is a read-only viewer: its
// keystroke + resize frames are DROPPED (never forwarded) — the client-side
// half of the §4.β server-side drop (the manager refuses a write without a live
// lease regardless). When the writer's lease is revoked mid-session (local
// takeover / allow_terminal→false / device revoke), a control frame tells the
// client it lost control and input stops flowing.
//
// acquire, when non-nil (the remote-exposed path), lets the client request the
// writer role mid-session via an {"t":"acquire-writer",…} control frame; it runs
// the §4.δ conjunction (AcquireWriterRemote). Until it succeeds — and if it never
// does — the client is a pure viewer whose frames never reach the PTY. A writer
// acquired here is Release()d when the bridge exits.
//
// closeOnHardRevoke distinguishes the two revoke outcomes (§4.α): when true (the
// REMOTE bridge), a writer-lease revocation that is NOT a lease takeover — an
// admin disable/rotate/device-revoke/allow_terminal→false, i.e. the device is no
// longer trusted — CLOSES the socket; a lease takeover only demotes the client to
// a read-only viewer. When false (the owner-local bridge) every revoke merely
// demotes, keeping that path byte-identical. A normal PTY-exit teardown never
// reaches this branch: the exit notifier cancels the bridge context first, so
// watchRevoke returns via ctx.Done rather than the revoked channel.
func (s *Server) bridgeTerminalWS(parent context.Context, c *websocket.Conn, sub LaunchSubscription, writer LaunchWriter, acquire func(capTok, confirm string) (LaunchWriter, error), denied *deniedFrameCoalescer, closeOnHardRevoke bool, handle string, geo func() ptyGeometry) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// PTY geometry announce (Feature 2): send the pinned {"t":"pty_size",…} frame
	// right after bridge start so the web terminal can restore the PTY's real
	// dimensions, and re-send it on a control transition (cheap; the client
	// re-fits when control changes hands). geo re-reads the manager's live size
	// each call, so a control-transition re-send is never stale. nil geo (older
	// call sites / tests) disables the frame.
	//
	// An UNKNOWN geometry is never announced — see startPTYSizeAnnounce, which
	// performs the on-open announce and returns the closure reused below.
	sendPTYSize := startPTYSizeAnnounce(ctx, c, geo)
	// Flush the coalesced tail of dropped-frame drops on teardown so a viewer
	// that floods then disconnects still yields a bounded final count (nil-safe:
	// the owner-local path wires no coalescer).
	defer denied.flush()

	// A writer acquired remotely inside this bridge is owned here — release it on
	// exit (the owner-local loopback writer is released by handleLaunchWS's defer).
	var acquired LaunchWriter
	defer func() {
		if acquired != nil {
			acquired.Release()
		}
	}()

	// ctrlSeqMu serializes control_granted / control_revoked writes so the
	// client can never observe them out of order. Without it, watchRevoke (a
	// goroutine) and the read loop's grant branches write concurrently: a lease
	// revoked between the loop's staleness check and its wsjson.Write could land
	// control_revoked FIRST and control_granted SECOND, leaving the client
	// believing it is writable while every write is fenced. The grant branches
	// re-check the lease's Revoked signal UNDER this mutex: if a revoke has
	// already fired, the grant is withheld (the watcher sent — or is about to
	// send — the revoked frame); if the revoke fires after, the watcher blocks
	// on the mutex until the grant is on the wire, so the client converges on
	// revoked. Order is then always grant-before-revoke per lease.
	var ctrlSeqMu sync.Mutex

	// sendGrantChecked writes control_granted for wl unless wl is already
	// revoked (then it writes nothing — the revoke watcher owns the notice).
	// Returns whether the grant was sent. Also re-affirms geometry on a sent
	// grant (Feature 2).
	sendGrantChecked := func(wl LaunchWriter) bool {
		ctrlSeqMu.Lock()
		defer ctrlSeqMu.Unlock()
		select {
		case <-wl.Revoked():
			return false
		default:
		}
		_ = wsjson.Write(ctx, c, wsControl{T: "control_granted", Gen: launchWriterGen(wl)})
		sendPTYSize()
		return true
	}

	// watchRevoke tells the client it lost control when a writer's lease is
	// revoked (lease takeover / allow_terminal→false / device revoke). Started
	// once per writer (the initial loopback writer, and again after a remote
	// acquire installs a new one).
	watchRevoke := func(wl LaunchWriter) {
		go func() {
			select {
			case <-wl.Revoked():
				// Always tell the client it lost control. On the remote bridge, a
				// revocation that is NOT a lease takeover means the device is no
				// longer trusted (admin disable/rotate/device-revoke/allow_terminal
				// →false) — cancel the bridge so the deferred CloseNow tears the
				// socket down. A lease takeover (device still valid) only demotes.
				ctrlSeqMu.Lock()
				by := ""
				if rb, ok := wl.(interface{ RevokedBy() string }); ok && wl.RevokeIsTakeover() {
					by = rb.RevokedBy()
				}
				_ = wsjson.Write(ctx, c, wsControl{
					T: "control_revoked", By: by, Gen: launchWriterGen(wl),
					// Tell the client WHY it lost control: an age-out (which it
					// may silently answer with a stored standing secret) or a
					// takeover / trust-withdrawing revoke (which it must not).
					Expiry: launchWriterRevokeIsExpiry(wl),
				})
				// Re-affirm geometry on the control handoff (Feature 2, cheap):
				// after a native-terminal reclaim the client should re-fit to the
				// PTY's current dims.
				sendPTYSize()
				ctrlSeqMu.Unlock()
				if shouldCloseOnRevoke(wl, closeOnHardRevoke) {
					cancel()
				}
			case <-ctx.Done():
			}
		}()
	}

	// PTY output → client (binary frames). Runs until the PTY closes or a ws
	// write fails, then signals readerDone. It does NOT cancel on PTY EOF —
	// that ownership belongs to the exit notifier below, so the exit control
	// frame is emitted AFTER all output has flushed.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		buf := make([]byte, 32*1024)
		for {
			n, rerr := sub.Read(buf)
			if n > 0 {
				if wErr := c.Write(ctx, websocket.MessageBinary, buf[:n]); wErr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	// When the process exits AND its output is fully flushed, emit the exit
	// control frame and unblock the read loop.
	go func() {
		select {
		case <-sub.Done():
		case <-ctx.Done():
			return
		}
		<-readerDone // let the reader flush the final bytes first
		_, code := sub.Exited()
		frame := wsControl{T: "exit", Code: code}
		// Resolve the policy-stop explanation ONCE, off a short bounded
		// timeout independent of ctx (which this same goroutine cancels right
		// below) — a slow/unavailable lookup must never delay the exit frame
		// beyond a bounded budget. A nil PolicyStop seam or a not-found lookup
		// both leave frame.PolicyStop nil, so a bare exit renders unchanged.
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		if stop, ok := s.resolvePolicyStop(stopCtx, handle); ok {
			frame.PolicyStop = &stop
		}
		stopCancel()
		_ = wsjson.Write(ctx, c, frame)
		cancel()
	}()

	// Liveness probe: ping the peer periodically and cancel the bridge if a ping
	// fails (dead / half-open connection). This is NOT a read-idle timeout — a
	// viewer that sends nothing for a long time while watching stays connected;
	// only an unresponsive TRANSPORT tears down. Runs identically on the local and
	// remote bridge.
	go pingLoop(ctx, c, cancel)

	// Writer-lease revocation → tell the client it lost control (§4.α.3). Input
	// writes error out on their own once the lease is gone; this surfaces it.
	if writer != nil {
		watchRevoke(writer)
	}

	// Client → PTY (main loop). Binary = keystrokes; text = control frames.
	// Without a live writer lease every input/control frame is DROPPED at this
	// boundary (§4.β): a viewer's forged frames never reach Write/Resize. The
	// ONLY frame that can establish a writer is the acquire-writer control frame,
	// and only through the §4.δ conjunction (acquire) — never a client "oob" or
	// any other forged frame type.
	//
	// repaintNudged records whether this bridge has already spent its one-shot
	// reattach repaint nudge (see the resize branch). Read/written only by this
	// single read-loop goroutine, so it needs no synchronisation.
	repaintNudged := false
	for {
		typ, data, rerr := c.Read(ctx)
		if rerr != nil {
			break
		}
		if typ == websocket.MessageText {
			var ctrl wsControl
			if err := json.Unmarshal(data, &ctrl); err != nil {
				if writer == nil {
					denied.note() // malformed control frame from a lease-less viewer
				}
				continue
			}
			switch {
			case ctrl.T == "acquire-writer" && acquire != nil:
				var newlyAcquired LaunchWriter
				writer, newlyAcquired = bridgeAcquireWriter(ctx, c, ctrl, writer, acquire, sendGrantChecked)
				if newlyAcquired != nil {
					acquired = newlyAcquired
					watchRevoke(newlyAcquired)
				}
			case ctrl.T == "resize" && writer != nil:
				repaintNudged = applyResizeFrame(writer, geo, ctrl.Rows, ctrl.Cols, repaintNudged)
			default:
				if writer == nil {
					denied.note() // forged/dropped control frame with no live lease (§4.β)
				}
			}
			continue
		}
		if writer == nil {
			denied.note() // viewer keystroke dropped server-side (§4.β)
			continue
		}
		if _, wErr := writer.Write(data); wErr != nil {
			// Lease lost (revoked/taken over/expired) or PTY gone: stop driving
			// and degrade to a viewer, still watching output until the socket or
			// the exit notifier closes the bridge. A remote client may re-acquire.
			writer = nil
			continue
		}
	}
	cancel()
}

// launchWriterGen reads the concrete lease generation through an additive
// optional interface. LaunchWriter deliberately stays narrow so existing
// dashboard fakes and alternate adapters remain source-compatible; a writer
// without generation support preserves the pre-generation wire shape via
// wsControl's omitempty tag.
func launchWriterGen(wl LaunchWriter) uint64 {
	if withGen, ok := wl.(interface{ Gen() uint64 }); ok {
		return withGen.Gen()
	}
	return 0
}

// shouldCloseOnRevoke is the single decision table for "does this writer-lease
// revocation tear the websocket down?". Three ordered rules:
//
//	closeOnHardRevoke == false (the owner-local loopback bridge) → never close
//	the revocation was a TAKEOVER (device still trusted)         → never close
//	the revocation was an EXPIRY (credential aged out)           → never close
//	otherwise (admin disable / rotate / device revoke /
//	allow_terminal→false — the device lost trust)                → CLOSE
//
// The expiry row is the 2026-07-25 addition. A lease that merely aged out says
// nothing about the device's trust, and closing the socket for it is what forced
// a remote user to re-establish the terminal — and re-issue credentials — every
// 30 minutes. All three "never close" outcomes still DEMOTE the client to a
// read-only viewer, and the lease is gone either way: input stays fenced until a
// fresh §4.δ conjunction succeeds.
//
// The expiry row alone is only half the behaviour: keeping the socket open means
// the client's on-open standing auto-present never re-fires, so the revocation
// frame also carries wsControl.Expiry and the client answers THAT with a fresh
// standing acquire (review B3). Takeovers and trust-withdrawing revokes are
// deliberately left un-answerable — the owner just took control.
func shouldCloseOnRevoke(wl LaunchWriter, closeOnHardRevoke bool) bool {
	if !closeOnHardRevoke {
		return false
	}
	if wl.RevokeIsTakeover() {
		return false
	}
	return !launchWriterRevokeIsExpiry(wl)
}

// launchWriterRevokeIsExpiry reports whether a revoked lease aged out (idle
// lifetime / hard cap) rather than being revoked for loss of trust. Read through
// an ADDITIVE optional interface so the narrow LaunchWriter seam and every
// existing dashboard fake stay source-compatible; a writer without the method
// reports false, which preserves the pre-2026-07-25 close-on-any-non-takeover
// behaviour for those callers.
//
// The remote bridge uses it to DEMOTE rather than CLOSE on an expiry: a lease
// that merely aged out says nothing about the device's trust, and closing the
// socket for it is what forced a remote user to re-establish the terminal (and,
// with it, re-issue credentials). Trust-withdrawing revokes — admin disable,
// rotate, device revoke, allow_terminal→false — are unaffected and still close.
func launchWriterRevokeIsExpiry(wl LaunchWriter) bool {
	if withExpiry, ok := wl.(interface{ RevokeIsExpiry() bool }); ok {
		return withExpiry.RevokeIsExpiry()
	}
	return false
}

// bridgeAcquireWriter handles one {"t":"acquire-writer"} control frame for
// bridgeTerminalWS's read loop. The loop's writer can be a STALE demoted lease:
// a revoke (native-terminal reclaim / any lease takeover) fires watchRevoke, but
// the loop variable is only cleared when a write fails — and a demoted client
// stops writing. So a still-live writer is re-affirmed (idempotent,
// revoke-checked under the control-order mutex), a stale one is cleared and
// re-acquired, and a denied acquire yields control_denied. Returns the writer
// the loop should hold afterward, plus the newly acquired lease when one was
// taken (nil otherwise) — the caller owns its release-on-exit and revoke
// watcher. A fresh lease that is already revoked at grant time is returned as
// acquired-but-not-held (nil loop writer): the grant is withheld and the
// caller's watcher surfaces the revoked notice on its own.
func bridgeAcquireWriter(ctx context.Context, c *websocket.Conn, ctrl wsControl,
	writer LaunchWriter,
	acquire func(capTok, confirm string) (LaunchWriter, error),
	sendGrantChecked func(LaunchWriter) bool,
) (loopWriter, newlyAcquired LaunchWriter) {
	if writer != nil {
		if sendGrantChecked(writer) {
			return writer, nil
		}
		// Revoked (either before the check or racing it): treat as stale and
		// fall through to a fresh acquire.
	}
	wl, aerr := acquire(ctrl.Cap, ctrl.Confirm)
	if aerr != nil || wl == nil {
		reason := ControlDenialUnavailable
		var denial *ControlDeniedError
		if errors.As(aerr, &denial) && denial.Reason != "" {
			reason = denial.Reason
		}
		_ = wsjson.Write(ctx, c, wsControl{T: "control_denied", Reason: reason})
		return nil, nil
	}
	// Grant-before-watch: sendGrantChecked withholds the grant if this fresh
	// lease is somehow already revoked.
	if !sendGrantChecked(wl) {
		return nil, wl
	}
	return wl, wl
}

// pingLoop probes the websocket peer every terminalPingInterval and cancels the
// bridge (via cancel) once terminalPingFailureBudget CONSECUTIVE pings fail or
// time out — detecting a dead/half-open connection without evicting a
// legitimately-idle-but-alive viewer. It relies on the bridge's concurrent main
// read loop to read the pong (coder/websocket's Ping requires a concurrent
// Reader). Returns when the bridge context is done.
//
// The consecutive-failure budget (added 2026-07-25, mobile terminal-continuity
// arc) is the FROZEN-TAB tolerance: a backgrounded mobile tab is suspended by
// the OS and answers nothing, so a single missed pong is not evidence of a dead
// peer. One success anywhere in the window resets the budget, so a peer that is
// genuinely gone still exhausts it and is reaped — the check is weakened in
// LATENCY (~40s → ~3.3 min at the defaults), never removed. Deliberately kept
// as a plain counter rather than a wall-clock grace so the existing atomics test
// seam still drives it deterministically.
func pingLoop(ctx context.Context, c *websocket.Conn, cancel context.CancelFunc) {
	t := time.NewTicker(time.Duration(terminalPingIntervalNs.Load()))
	defer t.Stop()
	budget := terminalPingFailureBudget.Load()
	if budget < 1 {
		budget = 1
	}
	var consecutiveFailures int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, pcancel := context.WithTimeout(ctx, time.Duration(terminalPingTimeoutNs.Load()))
			err := c.Ping(pctx)
			pcancel()
			if err == nil {
				consecutiveFailures = 0
				continue
			}
			// The bridge context itself ending is a teardown, not a dead peer —
			// return without a redundant cancel.
			if ctx.Err() != nil {
				return
			}
			consecutiveFailures++
			if consecutiveFailures >= budget {
				cancel() // dead peer: tear the socket down
				return
			}
		}
	}
}

// auditTerminalControl emits one metadata-only execute-tier control event
// through the injected RemoteAudit sink (never a secret). device is the short
// device fingerprint (hash[:8]); handle is the opaque terminal handle carried in
// the route column so every terminal event correlates on it. Nil sink (the
// default) is a no-op. detail is a coarse, non-sensitive descriptor.
func (s *Server) auditTerminalControl(kind, device, handle, peer, decision, detail string) {
	if s.opts.RemoteAudit == nil {
		return
	}
	s.opts.RemoteAudit(RemoteAuditRecord{
		Kind:       kind,
		SessionID:  device,
		Principal:  "execute",
		RemoteAddr: peer,
		Route:      handle,
		Decision:   decision,
		Detail:     detail,
	})
}

// deniedFrameBatch bounds how many coalesced drops accumulate before a
// terminal_denied_frame row is emitted mid-flood (in addition to the first-drop
// row and the teardown flush), so a long-lived flooding viewer still surfaces
// periodically while the row count stays ~count/batch — never one row per frame.
const deniedFrameBatch = 128

// deniedFrameCoalescer bounds terminal_denied_frame audit rows so a viewer with
// no writer lease flooding forged input/control frames (§4.β) cannot amplify the
// audit log (plan §8.1 #): it emits the FIRST drop immediately (count 1),
// batches subsequent drops into one row every deniedFrameBatch, and flushes the
// remainder once at bridge teardown. The coalesced count rides the row detail;
// the counts across all rows sum to the exact number of dropped frames. It is
// touched only from the single WS read-loop goroutine (note) and that
// goroutine's deferred teardown (flush), so no lock is needed; all methods are
// nil-safe (the owner-local path wires no coalescer).
type deniedFrameCoalescer struct {
	emit    func(count int)
	pending int
	rows    int
}

// newDeniedFrameCoalescer builds a coalescer whose rows carry the (device,
// handle, peer) correlation. Nil audit sink still returns a live coalescer (its
// emit is a no-op) so the drop-counting path is uniform.
func (s *Server) newDeniedFrameCoalescer(device, handle, peer string) *deniedFrameCoalescer {
	return &deniedFrameCoalescer{emit: func(count int) {
		if s.opts.RemoteAudit == nil {
			return
		}
		s.opts.RemoteAudit(RemoteAuditRecord{
			Kind:       "terminal_denied_frame",
			SessionID:  device,
			Principal:  "view",
			RemoteAddr: peer,
			Route:      handle,
			Decision:   "deny",
			Detail:     "dropped=" + strconv.Itoa(count),
		})
	}}
}

// note records one dropped frame, emitting a bounded audit row on the first drop
// and once per deniedFrameBatch thereafter.
func (d *deniedFrameCoalescer) note() {
	if d == nil {
		return
	}
	d.pending++
	if d.rows == 0 || d.pending >= deniedFrameBatch {
		n := d.pending
		d.pending = 0
		d.rows++
		d.emit(n)
	}
}

// flush emits the coalesced remainder (if any) — called once at bridge teardown.
func (d *deniedFrameCoalescer) flush() {
	if d == nil || d.pending == 0 {
		return
	}
	n := d.pending
	d.pending = 0
	d.rows++
	d.emit(n)
}
