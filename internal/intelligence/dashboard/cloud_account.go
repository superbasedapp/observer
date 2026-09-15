package dashboard

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloud_account.go is the NODE dashboard's Cloud ACCOUNT surface — the
// "sign-in button somewhere prominent" (operator directive 2026-09-03): sign-in
// state on GET /api/cloud/status, the Sign in / Sign out actions behind
// POST /api/cloud/login, GET /api/cloud/login/state and POST /api/cloud/logout,
// and the "Sync now" action behind POST /api/cloud/sync + GET
// /api/cloud/sync/state (operator directive: every `observer cloud` CLI verb
// needs a dashboard equivalent) — the dashboard equivalent of
// `observer cloud sync`.
//
// # Zero-egress by construction
//
// This package links NOTHING from the cloud lane — not cloudclient / cloudpop /
// cloudcred (pinned by tests/invariant/cloud_egress_test.go) and not even the
// consent-gated internal/cloudgateway seam. Both halves are INJECTED from
// cmd/observer as plain funcs through CloudAccountSeams (the same
// `cmd/observer/*_wire.go` discipline as Governance / BuildHandoff):
//
//   - CloudSignInProbe answers "is a sign-in stored on this device?" exactly the
//     way `observer cloud status` does — a LOCAL keychain read, no network.
//   - CloudCommandRunner runs ONE `observer cloud <verb>` as a SUBPROCESS of the
//     running binary, precisely the way cmd/observer/cloudautosync.go spawns
//     `cloud sync`. The child is the exact consent-gated CLI a human types;
//     the daemon itself makes no network call and holds no credential handle.
//
// The login subprocess prints the AuthKit authorize URL before it blocks on the
// loopback callback; the state machine below captures that URL from the
// child's output so the page can offer "Open sign-in page" as a link when the
// automatic browser open does not reach the operator (headless / remote
// desktop / the WSL hop failing). One login at a time: a second POST while one
// is running returns the current state rather than spawning a second listener
// on the fixed 127.0.0.1:9797 port.
//
// Sync follows the SAME one-at-a-time shape (its own in-memory run, guarded by
// the same mutex): POST /api/cloud/sync spawns `observer cloud sync` unless one
// is already running (a second POST then returns the current state, 200, not a
// second spawn) or a sign-in is currently running (409 — the two would race on
// the credential store / outbox). It refuses 409 up front when no sign-in is
// stored — sync cannot succeed without one. GET /api/cloud/sync/state reports
// the run plus the store-derived LastResultAt (the same fact
// CloudStatusResponse.LastResultAt reports) so the card needs no second fetch.
//
// Nil seams (Options.CloudAccount == nil — `observer dashboard` embedders and
// tests that never set it) leave the status payload without a `sign_in` block
// and make the action routes answer 503 with honest copy.

// CloudSignInState is what the probe reports: LOCAL credential presence, read
// the same way `observer cloud status` reads it (no network call).
type CloudSignInState struct {
	// APITokenPresent: a device-bound API token is stored (may be expired —
	// the token carries no expiry and status never calls out to find out).
	APITokenPresent bool
	// WorkOSSignInPresent: persisted WorkOS refresh material is stored — the
	// self-heal an expired token is re-exchanged through.
	WorkOSSignInPresent bool
	// CredentialBackend names the credential store ("keychain",
	// "file", …), as `observer cloud status` prints it.
	CredentialBackend string
	// ClientIDConfigured: a WorkOS client id resolves (WORKOS_CLIENT_ID env,
	// else [cloud].workos_client_id) — without one there is nothing a Sign-in
	// could open a browser to, so the page shows the honest inline error.
	ClientIDConfigured bool
}

// CloudSignInProbe reports the local sign-in state. Injected by cmd/observer.
type CloudSignInProbe func() (CloudSignInState, error)

// CloudCommandRunner runs `observer cloud <verb> <args...>` as a subprocess,
// streaming the child's combined output to out, and returns when the child
// exits (or ctx ends). verb is the first token after `cloud` ("sync", "login",
// "logout", "preview", "consent", "delete-account"); args follow the verb
// verbatim (e.g. ["grant", "--purpose", "structural_activity_insights",
// "--yes"]) — the injected implementation appends `--config <path>` LAST when
// one is set, the same way a human would type flags after the subcommand.
// Injected by cmd/observer; tests inject a fake.
type CloudCommandRunner func(ctx context.Context, verb string, args []string, out io.Writer) error

// CloudGrantable is one purpose's standing-grantability, as GET
// /api/cloud/consent/grants surfaces it: whether a standing grant may be
// minted for it right now, and — honest-disabled-copy discipline — the reason
// when it may not.
type CloudGrantable struct {
	Purpose string `json:"purpose"`
	OK      bool   `json:"ok"`
	Reason  string `json:"reason,omitempty"`
}

// CloudGrantableProbe reports every FEATURE-lane purpose's standing-grant
// eligibility, mirroring cmd/observer/cloudconsent.go's
// cloudPrintGrantableHelp (a bootstrap-lane purpose is skipped — there is
// nothing to grant for it). Injected from cmd/observer so this package never
// imports the consent-gated internal/cloudgateway seam directly (this file's
// header discipline: "not even the consent-gated internal/cloudgateway
// seam").
type CloudGrantableProbe func() []CloudGrantable

// CloudAccountSeams bundles the three injected funcs with the ONE owner of the
// in-memory login/sync state (the current/last run of each). Construct with
// NewCloudAccountSeams; the zero value is not usable.
type CloudAccountSeams struct {
	probe     CloudSignInProbe
	run       CloudCommandRunner
	grantable CloudGrantableProbe
	// loginTimeout bounds one login subprocess. The CLI itself gives up after
	// 5 minutes; the daemon-side bound is a little longer so the child's own
	// honest "timed out" message wins over a kill.
	loginTimeout time.Duration
	// syncTimeout bounds one sync subprocess.
	syncTimeout time.Duration

	mu    sync.Mutex
	login *cloudLoginRun
	sync  *cloudSyncRun
}

// NewCloudAccountSeams builds the seams. probe may be nil (sign-in state then
// reads "unknown" and login completion is judged by the child's exit status
// alone); run must be non-nil for the action routes to work; grantable may be
// nil (GET /api/cloud/consent/grants then reports an empty grantable list
// rather than failing).
func NewCloudAccountSeams(probe CloudSignInProbe, run CloudCommandRunner, grantable CloudGrantableProbe) *CloudAccountSeams {
	return &CloudAccountSeams{probe: probe, run: run, grantable: grantable, loginTimeout: cloudLoginTimeout, syncTimeout: cloudSyncTimeout}
}

// cloudLoginTimeout is the daemon-side bound on one login subprocess: the
// CLI's own 5-minute callback wait plus grace for the exchanges after it.
const cloudLoginTimeout = 5*time.Minute + 30*time.Second

// cloudLogoutTimeout bounds the synchronous logout subprocess (one best-effort
// revocation call, then a local clear).
const cloudLogoutTimeout = 60 * time.Second

// cloudSyncTimeout is the daemon-side bound on one sync subprocess (outbox
// drain + result pull). Generous — a large outbox or a slow link should not be
// killed mid-drain — but finite so a hung child cannot pin the "one at a time"
// slot forever.
const cloudSyncTimeout = 10 * time.Minute

// cloudSyncTailMax bounds the sync run's captured combined output to roughly
// the last 2KB, the same "keep the tail, not the whole log" discipline as the
// login run's tail.
const cloudSyncTailMax = 2048

// cloudLoginRun is one login attempt's state. Fields are guarded by
// CloudAccountSeams.mu.
type cloudLoginRun struct {
	running    bool
	authURL    string
	finished   bool
	ok         bool
	message    string
	startedAt  time.Time
	finishedAt time.Time
	// tail keeps a bounded copy of the child's output for the failure message.
	tail bytes.Buffer
}

// cloudSyncRun is one `observer cloud sync` attempt's state. Fields are
// guarded by CloudAccountSeams.mu, same as cloudLoginRun.
type cloudSyncRun struct {
	sessionID  string
	running    bool
	finished   bool
	ok         bool
	exitError  string
	startedAt  time.Time
	finishedAt time.Time
	// tail keeps a bounded (cloudSyncTailMax) copy of the child's combined
	// stdout+stderr, surfaced verbatim (not just the last line — sync's output
	// is the operator-facing progress report `observer cloud sync` prints).
	tail bytes.Buffer
}

// CloudSignInView is the `sign_in` block on GET /api/cloud/status. It reports
// LOCAL credential presence only — never whether the token is valid server-side.
type CloudSignInView struct {
	// Known is false when the probe is not wired or failed (Error set); the
	// presence fields are then meaningless and the UI says "unknown".
	Known bool   `json:"known"`
	Error string `json:"error,omitempty"`
	// SignedIn is the derived headline: a WorkOS sign-in OR an API token is
	// stored on this device.
	SignedIn            bool   `json:"signed_in"`
	APITokenPresent     bool   `json:"api_token_present"`
	WorkOSSignInPresent bool   `json:"workos_sign_in_present"`
	CredentialBackend   string `json:"credential_backend,omitempty"`
	ClientIDConfigured  bool   `json:"client_id_configured"`
	// LoginRunning mirrors /api/cloud/login/state so the status poll alone can
	// drive the "Signing in…" pill.
	LoginRunning bool `json:"login_running"`
	// ActionsAvailable is true when the Sign in / Sign out routes are wired
	// (a runner is injected). False on an embedder that only reads state.
	ActionsAvailable bool `json:"actions_available"`
}

// CloudLoginState is the payload for GET /api/cloud/login/state and the
// response to POST /api/cloud/login.
type CloudLoginState struct {
	Running bool `json:"running"`
	// AuthURL is the AuthKit authorize URL captured from the login
	// subprocess's output, once it has printed it; "" until then.
	AuthURL    string `json:"auth_url,omitempty"`
	Finished   bool   `json:"finished"`
	OK         bool   `json:"ok"`
	Message    string `json:"message,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
}

// CloudSyncState is the payload for GET /api/cloud/sync/state and the response
// to POST /api/cloud/sync — the one-at-a-time `observer cloud sync` subprocess
// (the dashboard equivalent of the CLI verb).
type CloudSyncState struct {
	SessionID  string `json:"session_id,omitempty"`
	Running    bool   `json:"running"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
	// OK is nil until the run finishes (never run yet, or still running);
	// true/false once it has — the JSON "bool|null" the page's poll expects.
	OK *bool `json:"ok,omitempty"`
	// ExitError is the runner's error text (subprocess non-zero exit, or the
	// daemon-side timeout), set only when Finished && !*OK.
	ExitError string `json:"exit_error,omitempty"`
	// Tail is the last ~2KB of the child's combined stdout+stderr — the
	// operator-facing progress `observer cloud sync` prints (outbox drain +
	// result pull lines).
	Tail string `json:"tail,omitempty"`
	// LastResultAt is store-derived (internal/store.CloudResultsSummary) — the
	// newest synced enrichment result's received_at, the SAME fact
	// CloudStatusResponse.LastResultAt reports — so the sync card needs no
	// second fetch to show "last synced result at".
	LastResultAt string `json:"last_result_at,omitempty"`
}

// signInView renders the probe as the status block. nil-receiver safe.
func (c *CloudAccountSeams) signInView() *CloudSignInView {
	if c == nil {
		return nil
	}
	v := &CloudSignInView{ActionsAvailable: c.run != nil, LoginRunning: c.state().Running}
	if c.probe == nil {
		v.Error = "sign-in probe not wired"
		return v
	}
	st, err := c.probe()
	if err != nil {
		v.Error = err.Error()
		return v
	}
	v.Known = true
	v.APITokenPresent = st.APITokenPresent
	v.WorkOSSignInPresent = st.WorkOSSignInPresent
	v.SignedIn = st.APITokenPresent || st.WorkOSSignInPresent
	v.CredentialBackend = st.CredentialBackend
	v.ClientIDConfigured = st.ClientIDConfigured
	return v
}

// state snapshots the current/last login run. nil-receiver safe.
func (c *CloudAccountSeams) state() CloudLoginState {
	if c == nil {
		return CloudLoginState{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stateLocked()
}

func (c *CloudAccountSeams) stateLocked() CloudLoginState {
	r := c.login
	if r == nil {
		return CloudLoginState{}
	}
	return CloudLoginState{
		Running:    r.running,
		AuthURL:    r.authURL,
		Finished:   r.finished,
		OK:         r.ok,
		Message:    r.message,
		StartedAt:  cloudRFC3339(r.startedAt),
		FinishedAt: cloudRFC3339(r.finishedAt),
	}
}

// syncState snapshots the current/last sync run, plus the store-derived
// LastResultAt (the same fact CloudStatusResponse.LastResultAt reports).
// nil-receiver safe (unwired dashboards / embedders); st may be nil too.
func (c *CloudAccountSeams) syncState(ctx context.Context, st *store.Store) CloudSyncState {
	if c == nil {
		return CloudSyncState{}
	}
	c.mu.Lock()
	out := c.syncStateLocked()
	c.mu.Unlock()
	if st != nil {
		if _, last, err := st.CloudResultsSummary(ctx); err == nil {
			out.LastResultAt = last
		}
	}
	return out
}

func (c *CloudAccountSeams) syncStateLocked() CloudSyncState {
	r := c.sync
	if r == nil {
		return CloudSyncState{}
	}
	st := CloudSyncState{
		SessionID:  r.sessionID,
		Running:    r.running,
		StartedAt:  cloudRFC3339(r.startedAt),
		FinishedAt: cloudRFC3339(r.finishedAt),
		ExitError:  r.exitError,
		Tail:       strings.TrimSpace(r.tail.String()),
	}
	if r.finished {
		ok := r.ok
		st.OK = &ok
	}
	return st
}

// loginRunning reports whether a login is currently in flight — sync refuses
// to start while one is (the two would race on the credential store/outbox).
func (c *CloudAccountSeams) loginRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.login != nil && c.login.running
}

// syncRunning reports whether a sync is currently in flight — the consent
// action routes in cloud_consent.go (session consent, grant, revoke,
// delete-account) refuse to start while one is: the same outbox/credential
// race loginRunning guards login and sync against.
func (c *CloudAccountSeams) syncRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sync != nil && c.sync.running
}

// errCloudSyncRunning is returned by startSync when a sync is in flight; the
// caller answers with the current state rather than a second spawn.
var errCloudSyncRunning = errors.New("a sync is already running")

var errCloudSyncScopeConflict = errors.New("another sync is running; wait for it to finish, then retry this session")

// startSync spawns one sync subprocess unless one is running. Mirrors
// startLogin: returns the state immediately (running=true) so the caller can
// answer the POST; the goroutine finalizes the run when the child exits.
func (c *CloudAccountSeams) startSync(now time.Time, sessionID string) (CloudSyncState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sync != nil && c.sync.running {
		if c.sync.sessionID != sessionID {
			return CloudSyncState{}, errCloudSyncScopeConflict
		}
		return c.syncStateLocked(), errCloudSyncRunning
	}
	run := &cloudSyncRun{running: true, startedAt: now, sessionID: sessionID}
	c.sync = run
	ctx, cancel := context.WithTimeout(context.Background(), c.syncTimeout)
	go func() {
		defer cancel()
		var args []string
		if sessionID != "" {
			args = []string{"--session", sessionID}
		}
		err := c.run(ctx, "sync", args, &cloudSyncOutput{seams: c, run: run})
		c.finishSync(run, err)
	}()
	return c.syncStateLocked(), nil
}

// finishSync records the child's outcome. Unlike login, success is judged by
// the exit status alone — `observer cloud sync` has no local credential
// side-effect to re-probe, only outbox/result state already surfaced by
// CloudStatusResponse.
func (c *CloudAccountSeams) finishSync(run *cloudSyncRun, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	run.running = false
	run.finished = true
	run.ok = err == nil
	if err != nil {
		run.exitError = err.Error()
	}
	run.finishedAt = time.Now().UTC()
}

// cloudSyncOutput is the io.Writer handed to the sync subprocess: a bounded
// (cloudSyncTailMax) copy of its combined output, guarded by the seams mutex
// so a concurrent GET /api/cloud/sync/state (which may read mid-run) never
// races the write.
type cloudSyncOutput struct {
	seams *CloudAccountSeams
	run   *cloudSyncRun
}

func (o *cloudSyncOutput) Write(p []byte) (int, error) {
	o.seams.mu.Lock()
	o.run.tail.Write(p)
	if o.run.tail.Len() > cloudSyncTailMax {
		b := o.run.tail.Bytes()
		o.run.tail.Reset()
		o.run.tail.Write(b[len(b)-cloudSyncTailMax:])
	}
	o.seams.mu.Unlock()
	return len(p), nil
}

// errCloudLoginRunning is returned by startLogin when a login is in flight;
// the caller answers with the current state rather than a second spawn.
var errCloudLoginRunning = errors.New("a sign-in is already running")

// startLogin spawns one login subprocess unless one is running. It returns
// the state immediately after the spawn (running=true) so the caller can
// answer the POST; the goroutine finalizes the run when the child exits.
func (c *CloudAccountSeams) startLogin(now time.Time) (CloudLoginState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.login != nil && c.login.running {
		return c.stateLocked(), errCloudLoginRunning
	}
	run := &cloudLoginRun{running: true, startedAt: now}
	c.login = run
	ctx, cancel := context.WithTimeout(context.Background(), c.loginTimeout)
	go func() {
		defer cancel()
		err := c.run(ctx, "login", nil, &cloudLoginOutput{seams: c, run: run})
		c.finishLogin(run, err)
	}()
	return c.stateLocked(), nil
}

// finishLogin records the child's outcome. Success is judged by the PROBE when
// one is wired — the child printing "how to configure" and exiting 0 is not a
// sign-in — else by the exit status alone.
func (c *CloudAccountSeams) finishLogin(run *cloudLoginRun, err error) {
	ok := err == nil
	var msg string
	switch {
	case err != nil:
		msg = "sign-in failed: " + err.Error()
		if t := strings.TrimSpace(run.tailString()); t != "" {
			msg += " — " + t
		}
	case c.probe != nil:
		st, perr := c.probe()
		switch {
		case perr != nil:
			ok = false
			msg = "sign-in finished but the credential check failed: " + perr.Error()
		case st.APITokenPresent || st.WorkOSSignInPresent:
			msg = "Signed in — device-bound API token stored."
		default:
			ok = false
			msg = "sign-in did not complete (no credential was stored)"
			if t := strings.TrimSpace(run.tailString()); t != "" {
				msg += ": " + t
			}
		}
	default:
		msg = "Signed in."
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	run.running = false
	run.finished = true
	run.ok = ok
	run.message = msg
	run.finishedAt = time.Now().UTC()
}

// tailString returns the bounded output tail (last line-ish, capped) for a
// failure message. Caller holds no lock: tail is written only by the child's
// output writer, which has returned by the time the run is finalized.
func (r *cloudLoginRun) tailString() string {
	const max = 512
	b := r.tail.Bytes()
	if len(b) > max {
		b = b[len(b)-max:]
	}
	// The last non-empty line is the most useful (the CLI's error line).
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return ""
}

// cloudLoginOutput is the io.Writer handed to the login subprocess. It keeps a
// bounded tail for error copy and captures the FIRST absolute http(s) URL the
// child prints on a line of its own — `observer cloud login` prints the
// AuthKit authorize URL exactly that way ("If it does not open, visit this
// URL:" followed by the URL on an indented line).
type cloudLoginOutput struct {
	seams   *CloudAccountSeams
	run     *cloudLoginRun
	partial []byte
}

func (o *cloudLoginOutput) Write(p []byte) (int, error) {
	// Bounded tail (keep the last 4KB) for failure copy.
	o.run.tail.Write(p)
	if o.run.tail.Len() > 4096 {
		b := o.run.tail.Bytes()
		o.run.tail.Reset()
		o.run.tail.Write(b[len(b)-4096:])
	}
	// URL capture: line-buffered so a URL split across two writes still
	// matches. Stop scanning once captured.
	if o.seams.hasAuthURL(o.run) {
		return len(p), nil
	}
	o.partial = append(o.partial, p...)
	for {
		nl := bytes.IndexByte(o.partial, '\n')
		if nl < 0 {
			break
		}
		line := strings.TrimSpace(string(o.partial[:nl]))
		o.partial = o.partial[nl+1:]
		if cloudLooksLikeAuthURL(line) {
			o.seams.setAuthURL(o.run, line)
			o.partial = nil
			break
		}
	}
	return len(p), nil
}

// cloudLooksLikeAuthURL is the line test: a whole-line absolute http(s) URL
// (no spaces), which is how the CLI prints the authorize URL.
func cloudLooksLikeAuthURL(line string) bool {
	if line == "" || strings.ContainsAny(line, " \t") {
		return false
	}
	return strings.HasPrefix(line, "https://") || strings.HasPrefix(line, "http://")
}

func (c *CloudAccountSeams) hasAuthURL(run *cloudLoginRun) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return run.authURL != ""
}

func (c *CloudAccountSeams) setAuthURL(run *cloudLoginRun, u string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if run.authURL == "" {
		run.authURL = u
	}
}

// logout runs `observer cloud logout` synchronously (bounded), refusing while
// a login is in flight (the two would race on the credential store).
func (c *CloudAccountSeams) logout(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.login != nil && c.login.running {
		c.mu.Unlock()
		return "", errCloudLoginRunning
	}
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, cloudLogoutTimeout)
	defer cancel()
	var out bytes.Buffer
	err := c.run(ctx, "logout", nil, &out)
	msg := strings.TrimSpace(out.String())
	if len(msg) > 1024 {
		msg = "…" + msg[len(msg)-1024:]
	}
	return msg, err
}

// --- routes ------------------------------------------------------------------

// registerCloudAccountRoutes registers the five action routes. All are Local
// (owner-loopback-only, never remotely reachable): sign-in opens a browser and
// stores a credential on THIS machine, sign-out clears one, sync drains the
// outbox and pulls results — all machine-reaching mutations by definition —
// and the login state carries the PKCE authorize URL, which a remote viewer
// has no business seeing. reg is dashboard.go's local registration closure,
// passed in so this file adds one line there.
func (s *Server) registerCloudAccountRoutes(reg func(pattern string, cap Capability, section Section, h http.HandlerFunc)) {
	reg("/api/cloud/login", CapabilityLocal, SectionSettings, s.handleCloudLogin)
	reg("/api/cloud/login/state", CapabilityLocal, SectionSettings, s.handleCloudLoginState)
	reg("/api/cloud/logout", CapabilityLocal, SectionSettings, s.handleCloudLogout)
	reg("/api/cloud/sync", CapabilityLocal, SectionSettings, s.handleCloudSync)
	reg("/api/cloud/sync/state", CapabilityLocal, SectionSettings, s.handleCloudSyncState)
	// cloud_consent.go: the preview / per-session-consent / standing-grant
	// management / delete-account surface (operator directive: every
	// `observer cloud` verb needs a dashboard equivalent, and the session card
	// gets buttons instead of copy-paste CLI blocks).
	reg("/api/cloud/preview", CapabilityLocal, SectionSettings, s.handleCloudPreview)
	reg("/api/cloud/consent", CapabilityLocal, SectionSettings, s.handleCloudConsent)
	reg("/api/cloud/consent/grants", CapabilityLocal, SectionSettings, s.handleCloudConsentGrants)
	reg("/api/cloud/consent/grant", CapabilityLocal, SectionSettings, s.handleCloudConsentGrant)
	reg("/api/cloud/consent/revoke", CapabilityLocal, SectionSettings, s.handleCloudConsentRevoke)
	reg("/api/cloud/delete-account", CapabilityLocal, SectionSettings, s.handleCloudDeleteAccount)
	// cloud_policy.go: the standing Turn on / Turn off actions (thin wrappers
	// over `observer cloud enable`/`disable`) and the content-free "What we
	// sent" ledger read (value-upgrade plan §W2).
	reg("/api/cloud/enable", CapabilityLocal, SectionSettings, s.handleCloudEnable)
	reg("/api/cloud/disable", CapabilityLocal, SectionSettings, s.handleCloudDisable)
	reg("/api/cloud/ledger", CapabilityView, SectionSettings, s.handleCloudLedger)
	// cloud_events.go: the Sessions-page toast/banner poll (value-upgrade
	// plan §W3) — a pure store read, same class as /api/cloud/status.
	reg("/api/cloud/events", CapabilityView, SectionSettings, s.handleCloudEvents)
	// cloud_digests.go: the weekly project digests `observer cloud sync`
	// has pulled back (value-upgrade plan §W5) — a pure store read, same
	// class as /api/cloud/status.
	reg("/api/cloud/digests", CapabilityView, SectionSettings, s.handleCloudDigests)
}

// cloudAccountUnavailable is the 503 copy when no runner is wired.
const cloudAccountUnavailable = "cloud account actions are not available on this dashboard (no `observer cloud` runner is wired — run `observer start`, or use `observer cloud login` / `observer cloud logout` / `observer cloud sync` in a terminal)"

// cloudAccountSeams returns the seams when the action routes can work.
func (s *Server) cloudAccountSeams(w http.ResponseWriter) (*CloudAccountSeams, bool) {
	c := s.opts.CloudAccount
	if c == nil || c.run == nil {
		http.Error(w, cloudAccountUnavailable, http.StatusServiceUnavailable)
		return nil, false
	}
	return c, true
}

// cloudOrgEnrolledMessage is the 409 body when a personal sign-in is refused
// because this node is org-enrolled — enterprise-first: an enrolled node's
// sessions are stamped authority='org' and are excluded from personal cloud
// enrichment (internal/store/dataauthority.go, internal/cloudevidence), so a
// personal sign-in here would complete but enrich nothing.
const cloudOrgEnrolledMessage = "org-enrolled: personal cloud sign-in is managed by your organization and is unavailable on this node"

// orgEnrolled reports whether this node is currently enrolled in an org,
// reading the SAME local seam handleEnrolmentStatus uses (Options.OrgClient) —
// a local credential/state read, no network call. A nil OrgClient (solo-local
// install) or a status error is treated as "not enrolled" so a transient probe
// failure never blocks a legitimate personal sign-in.
func (s *Server) orgEnrolled(ctx context.Context) (enrolled bool, orgName string) {
	if s.opts.OrgClient == nil {
		return false, ""
	}
	st, err := s.opts.OrgClient.Status(ctx)
	if err != nil || !st.Enrolled {
		return false, ""
	}
	return true, st.OrgName
}

// handleCloudLogin serves POST /api/cloud/login: spawns `observer cloud login`
// (one at a time) and returns the login state. A missing client id is refused
// up front with the honest "set [cloud].workos_client_id or WORKOS_CLIENT_ID"
// line — the CLI would only print how to configure and exit 0, which the page
// could not tell from a sign-in. A second POST while one runs returns the
// current state (200) rather than a second spawn. An org-enrolled node refuses
// with 409 BEFORE any subprocess is spawned — enterprise-first (see
// cloudOrgEnrolledMessage).
func (s *Server) handleCloudLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if enrolled, _ := s.orgEnrolled(r.Context()); enrolled {
		writeJSONStatus(w, http.StatusConflict, map[string]string{
			"error":   "org_enrolled",
			"message": cloudOrgEnrolledMessage,
		})
		return
	}
	c, ok := s.cloudAccountSeams(w)
	if !ok {
		return
	}
	if c.probe != nil {
		st, err := c.probe()
		if err != nil {
			writeErr(w, err)
			return
		}
		if !st.ClientIDConfigured {
			http.Error(w, "no WorkOS client id is configured — set [cloud].workos_client_id in config.toml or the WORKOS_CLIENT_ID environment variable, then try again", http.StatusConflict)
			return
		}
	}
	st, err := c.startLogin(s.now())
	if err != nil && !errors.Is(err, errCloudLoginRunning) {
		writeErr(w, err)
		return
	}
	writeJSON(w, st)
}

// handleCloudLoginState serves GET /api/cloud/login/state.
func (s *Server) handleCloudLoginState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.cloudAccountSeams(w); !ok {
		return
	}
	writeJSON(w, s.opts.CloudAccount.state())
}

// CloudLogoutResponse is the payload for POST /api/cloud/logout.
type CloudLogoutResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

// handleCloudLogout serves POST /api/cloud/logout: runs `observer cloud logout`
// synchronously (best-effort server revocation, then local clear — the CLI's
// own semantics) and reports its output.
func (s *Server) handleCloudLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.cloudAccountSeams(w)
	if !ok {
		return
	}
	msg, err := c.logout(r.Context())
	if errors.Is(err, errCloudLoginRunning) {
		http.Error(w, "a sign-in is running — wait for it to finish (or time out) before signing out", http.StatusConflict)
		return
	}
	resp := CloudLogoutResponse{OK: err == nil, Message: msg}
	if err != nil {
		resp.Message = strings.TrimSpace("sign-out failed: " + err.Error() + " " + msg)
	}
	writeJSON(w, resp)
}

// cloudNotSignedInMessage is the 409 body when sync is refused because no
// sign-in is stored — sync cannot succeed without one.
const cloudNotSignedInMessage = "not signed in — sign in first (Sign in above, or `observer cloud login`) before syncing"

// handleCloudSync serves POST /api/cloud/sync: spawns `observer cloud sync`
// (one at a time — the dashboard equivalent of the CLI verb, operator
// directive that every `observer cloud` verb needs a dashboard equivalent).
// Refused up front, before any subprocess: a sign-in is currently running
// (409 — the two would race on the credential store/outbox), or no sign-in is
// stored at all (409 — sync cannot succeed without one). A second POST while a
// sync is already running returns the current state (200) rather than a
// second spawn, mirroring handleCloudLogin.
func (s *Server) handleCloudSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	sessionID, err := decodeCloudSyncSession(w, r)
	if err != nil {
		http.Error(w, "invalid sync request: "+err.Error(), http.StatusBadRequest)
		return
	}
	c, ok := s.cloudAccountSeams(w)
	if !ok {
		return
	}
	if c.loginRunning() {
		http.Error(w, "a sign-in is running — wait for it to finish (or time out) before syncing", http.StatusConflict)
		return
	}
	if c.probe != nil {
		st, err := c.probe()
		if err != nil {
			writeErr(w, err)
			return
		}
		if !st.APITokenPresent && !st.WorkOSSignInPresent {
			http.Error(w, cloudNotSignedInMessage, http.StatusConflict)
			return
		}
	}
	st, err := c.startSync(s.now(), sessionID)
	if errors.Is(err, errCloudSyncScopeConflict) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil && !errors.Is(err, errCloudSyncRunning) {
		writeErr(w, err)
		return
	}
	writeJSON(w, st)
}

// handleCloudSyncState serves GET /api/cloud/sync/state.
func (s *Server) handleCloudSyncState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.cloudAccountSeams(w)
	if !ok {
		return
	}
	writeJSON(w, c.syncState(r.Context(), store.New(s.db())))
}
