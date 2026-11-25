package dashapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// CloudSignInState is what the probe reports: LOCAL credential presence, read
// the same way `observer cloud status` reads it (no network call).
type CloudSignInState struct {
	// APITokenPresent: a device-bound API token is stored (may be expired -
	// the token carries no expiry and status never calls out to find out).
	APITokenPresent bool
	// WorkOSSignInPresent: persisted WorkOS refresh material is stored - the
	// self-heal an expired token is re-exchanged through.
	WorkOSSignInPresent bool
	// CredentialBackend names the credential store ("keychain",
	// "file", …), as `observer cloud status` prints it.
	CredentialBackend string
	// ClientIDConfigured: a WorkOS client id resolves (WORKOS_CLIENT_ID env,
	// else [cloud].workos_client_id) - without one there is nothing a Sign-in
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
// "--yes"]) - the injected implementation appends `--config <path>` LAST when
// one is set, the same way a human would type flags after the subcommand.
// Injected by cmd/observer; tests inject a fake.
type CloudCommandRunner func(ctx context.Context, verb string, args []string, out io.Writer) error

// CloudGrantable is one purpose's standing-grantability, as GET
// /api/cloud/consent/grants surfaces it: whether a standing grant may be
// minted for it right now, and - honest-disabled-copy discipline - the reason
// when it may not.
type CloudGrantable struct {
	Purpose string `json:"purpose"`
	OK      bool   `json:"ok"`
	Reason  string `json:"reason,omitempty"`
}

// CloudGrantableProbe reports every FEATURE-lane purpose's standing-grant
// eligibility, mirroring cmd/observer/cloudconsent.go's
// cloudPrintGrantableHelp (a bootstrap-lane purpose is skipped - there is
// nothing to grant for it). Injected from cmd/observer so this package never
// imports the consent-gated internal/cloudgateway seam directly (this file's
// header discipline: "not even the consent-gated internal/cloudgateway
// seam").
type CloudGrantableProbe func() []CloudGrantable

// CloudAccountSeams bundles the three injected funcs with the ONE owner of the
// in-memory login/sync state (the current/last run of each). Construct with
// NewCloudAccountSeams; the zero value is not usable.
type CloudAccountSeams struct {
	Probe     CloudSignInProbe
	Run       CloudCommandRunner
	Grantable CloudGrantableProbe
	// loginTimeout bounds one login subprocess. The CLI itself gives up after
	// 5 minutes; the daemon-side bound is a little longer so the child's own
	// honest "timed out" message wins over a kill.
	LoginTimeout time.Duration
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
	return &CloudAccountSeams{Probe: probe, Run: run, Grantable: grantable, LoginTimeout: cloudLoginTimeout, syncTimeout: cloudSyncTimeout}
}

// cloudLoginTimeout is the daemon-side bound on one login subprocess: the
// CLI's own 5-minute callback wait plus grace for the exchanges after it.
const cloudLoginTimeout = 5*time.Minute + 30*time.Second

// cloudLogoutTimeout bounds the synchronous logout subprocess (one best-effort
// revocation call, then a local clear).
const cloudLogoutTimeout = 60 * time.Second

// cloudSyncTimeout is the daemon-side bound on one sync subprocess (outbox
// drain + result pull). Generous - a large outbox or a slow link should not be
// killed mid-drain - but finite so a hung child cannot pin the "one at a time"
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
	// stdout+stderr, surfaced verbatim (not just the last line - sync's output
	// is the operator-facing progress report `observer cloud sync` prints).
	tail bytes.Buffer
}

// CloudSignInView is the `sign_in` block on GET /api/cloud/status. It reports
// LOCAL credential presence only - never whether the token is valid server-side.
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
// to POST /api/cloud/sync - the one-at-a-time `observer cloud sync` subprocess
// (the dashboard equivalent of the CLI verb).
type CloudSyncState struct {
	SessionID  string `json:"session_id,omitempty"`
	Running    bool   `json:"running"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
	// OK is nil until the run finishes (never run yet, or still running);
	// true/false once it has - the JSON "bool|null" the page's poll expects.
	OK *bool `json:"ok,omitempty"`
	// ExitError is the runner's error text (subprocess non-zero exit, or the
	// daemon-side timeout), set only when Finished && !*OK.
	ExitError string `json:"exit_error,omitempty"`
	// Tail is the last ~2KB of the child's combined stdout+stderr - the
	// operator-facing progress `observer cloud sync` prints (outbox drain +
	// result pull lines).
	Tail string `json:"tail,omitempty"`
	// LastResultAt is store-derived (internal/store.CloudResultsSummary) - the
	// newest synced enrichment result's received_at, the SAME fact
	// CloudStatusResponse.LastResultAt reports - so the sync card needs no
	// second fetch to show "last synced result at".
	LastResultAt string `json:"last_result_at,omitempty"`
}

// SignInView renders the probe as the status block. nil-receiver safe.
func (c *CloudAccountSeams) SignInView() *CloudSignInView {
	if c == nil {
		return nil
	}
	v := &CloudSignInView{ActionsAvailable: c.Run != nil, LoginRunning: c.State().Running}
	if c.Probe == nil {
		v.Error = "sign-in probe not wired"
		return v
	}
	st, err := c.Probe()
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

// State snapshots the current/last login run. nil-receiver safe.
func (c *CloudAccountSeams) State() CloudLoginState {
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
		StartedAt:  CloudRFC3339(r.startedAt),
		FinishedAt: CloudRFC3339(r.finishedAt),
	}
}

// SyncState snapshots the current/last sync run, plus the store-derived
// LastResultAt (the same fact CloudStatusResponse.LastResultAt reports).
// nil-receiver safe (unwired dashboards / embedders); st may be nil too.
func (c *CloudAccountSeams) SyncState(ctx context.Context, st *store.Store) CloudSyncState {
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
		StartedAt:  CloudRFC3339(r.startedAt),
		FinishedAt: CloudRFC3339(r.finishedAt),
		ExitError:  r.exitError,
		Tail:       strings.TrimSpace(r.tail.String()),
	}
	if r.finished {
		ok := r.ok
		st.OK = &ok
	}
	return st
}

// LoginRunning reports whether a login is currently in flight - sync refuses
// to start while one is (the two would race on the credential store/outbox).
func (c *CloudAccountSeams) LoginRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.login != nil && c.login.running
}

// SyncRunning reports whether a sync is currently in flight - the consent
// action routes in cloud_consent.go (session consent, grant, revoke,
// delete-account) refuse to start while one is: the same outbox/credential
// race LoginRunning guards login and sync against.
func (c *CloudAccountSeams) SyncRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sync != nil && c.sync.running
}

// errCloudSyncRunning is returned by StartSync when a sync is in flight; the
// caller answers with the current state rather than a second spawn.
var ErrCloudSyncRunning = errors.New("a sync is already running")

var ErrCloudSyncScopeConflict = errors.New("another sync is running; wait for it to finish, then retry this session")

// StartSync spawns one sync subprocess unless one is running. Mirrors
// StartLogin: returns the state immediately (running=true) so the caller can
// answer the POST; the goroutine finalizes the run when the child exits.
func (c *CloudAccountSeams) StartSync(now time.Time, sessionID string) (CloudSyncState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sync != nil && c.sync.running {
		if c.sync.sessionID != sessionID {
			return CloudSyncState{}, ErrCloudSyncScopeConflict
		}
		return c.syncStateLocked(), ErrCloudSyncRunning
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
		err := c.Run(ctx, "sync", args, &cloudSyncOutput{seams: c, run: run})
		c.finishSync(run, err)
	}()
	return c.syncStateLocked(), nil
}

// finishSync records the child's outcome. Unlike login, success is judged by
// the exit status alone - `observer cloud sync` has no local credential
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

// errCloudLoginRunning is returned by StartLogin when a login is in flight;
// the caller answers with the current state rather than a second spawn.
var ErrCloudLoginRunning = errors.New("a sign-in is already running")

// StartLogin spawns one login subprocess unless one is running. It returns
// the state immediately after the spawn (running=true) so the caller can
// answer the POST; the goroutine finalizes the run when the child exits.
func (c *CloudAccountSeams) StartLogin(now time.Time) (CloudLoginState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.login != nil && c.login.running {
		return c.stateLocked(), ErrCloudLoginRunning
	}
	run := &cloudLoginRun{running: true, startedAt: now}
	c.login = run
	ctx, cancel := context.WithTimeout(context.Background(), c.LoginTimeout)
	go func() {
		defer cancel()
		err := c.Run(ctx, "login", nil, &cloudLoginOutput{seams: c, run: run})
		c.finishLogin(run, err)
	}()
	return c.stateLocked(), nil
}

// finishLogin records the child's outcome. Success is judged by the PROBE when
// one is wired - the child printing "how to configure" and exiting 0 is not a
// sign-in - else by the exit status alone.
func (c *CloudAccountSeams) finishLogin(run *cloudLoginRun, err error) {
	ok := err == nil
	var msg string
	switch {
	case err != nil:
		msg = "sign-in failed: " + err.Error()
		if t := strings.TrimSpace(run.tailString()); t != "" {
			msg += " - " + t
		}
	case c.Probe != nil:
		st, perr := c.Probe()
		switch {
		case perr != nil:
			ok = false
			msg = "sign-in finished but the credential check failed: " + perr.Error()
		case st.APITokenPresent || st.WorkOSSignInPresent:
			msg = "Signed in - device-bound API token stored."
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
// child prints on a line of its own - `observer cloud login` prints the
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
		if CloudLooksLikeAuthURL(line) {
			o.seams.setAuthURL(o.run, line)
			o.partial = nil
			break
		}
	}
	return len(p), nil
}

// CloudLooksLikeAuthURL is the line test: a whole-line absolute http(s) URL
// (no spaces), which is how the CLI prints the authorize URL.
func CloudLooksLikeAuthURL(line string) bool {
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

// Logout runs `observer cloud logout` synchronously (bounded), refusing while
// a login is in flight (the two would race on the credential store).
func (c *CloudAccountSeams) Logout(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.login != nil && c.login.running {
		c.mu.Unlock()
		return "", ErrCloudLoginRunning
	}
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, cloudLogoutTimeout)
	defer cancel()
	var out bytes.Buffer
	err := c.Run(ctx, "logout", nil, &out)
	msg := strings.TrimSpace(out.String())
	if len(msg) > 1024 {
		msg = "…" + msg[len(msg)-1024:]
	}
	return msg, err
}
