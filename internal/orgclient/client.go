package orgclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient/gen"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Backoff bounds for the push loop on retryable failures (spec §2.4.2):
// exponential 250ms→10min with ±25% jitter, reset to the floor after a
// success.
const (
	initialBackoff = 250 * time.Millisecond
	// maxBackoff caps the retry cadence for a generic retryable failure
	// (a dead/unreachable org server, a 5xx, etc). Raised 2026-09-07 from
	// 30s to 10 minutes: at 30s, a dev box enrolled against a now-dead
	// localhost:8443 logged 316 "org push failed, backing off" / "org
	// announcement fetch failed" / "org routing policy fetch failed" WARN
	// lines in the first hour after every restart — a 30s ceiling means
	// the loop never settles below one attempt every 30s no matter how
	// long the server has been down. Paired with failureDeduper (below),
	// which independently silences the REPEATED identical WARNs down to
	// one-time-then-DEBUG; the two fixes are complementary, not
	// redundant — this cap slows how OFTEN the loop even tries, the
	// deduper controls how much each try logs.
	maxBackoff     = 10 * time.Minute
	backoffFactor  = 2
	jitterFraction = 0.25
	// authFailMaxBackoff caps the retry cadence for a REJECTED credential
	// (ErrAuthFailed). Auth failures are retryable, not terminal (see runLoop):
	// the loop re-reads its bearer + signing key every cycle, so a re-enrol or
	// key rotation recovers on the next cycle without a restart. The climb
	// starts at initialBackoff (a prompt re-enrol recovers within the first,
	// fast retries) and settles here so a genuinely-revoked node does not spam
	// the server — a slower (1.5x) steady state than maxBackoff, preserving
	// the "rejected credential settles slower than a generic failure"
	// ordering without needing to keep scaling further. Raised in lockstep
	// with maxBackoff (2026-09-07, 5min → 15min) to preserve that ordering
	// now that maxBackoff itself grew to 10min.
	authFailMaxBackoff = 15 * time.Minute
	// oversizedBatchBackoff is a circuit breaker for a deterministic local
	// payload that cannot satisfy the configured protocol limit. Rebuilding it
	// aggressively only burns CPU/RAM; a long park still lets a daemon recover
	// after retention/config changes without terminating the host process.
	oversizedBatchBackoff = time.Hour
)

// ErrNotEnrolled is returned by push operations when the agent is not enrolled
// (no org_enrolment row, or the bearer/signing key is missing). It is never a
// retryable error — the caller waits for an enrol rather than backing off.
var ErrNotEnrolled = errors.New("orgclient: not enrolled")

// ErrAuthFailed is returned when the server rejects the credential or the
// per-push signature (401/403). It is RETRYABLE, not terminal: the push/poll
// loop re-reads its credentials every cycle, so a re-enrol or key rotation
// recovers on the next cycle without a process restart. runLoop backs off on a
// dedicated capped track (authFailMaxBackoff) so a genuinely-revoked node
// settles to a slow cadence instead of spamming the server.
var ErrAuthFailed = errors.New("orgclient: authentication failed")

// ErrMemberNotActive is returned by Enroll when the server holds a GOOD,
// UNBURNED enrolment token but the account behind it is not active yet (the
// combined "add a developer" flow can mint a token against a member who
// still has to redeem their dashboard sign-in invite and set a password).
// Unlike ErrAuthFailed this is never a reason to mint a new token: the same
// compound token is still good and will exchange successfully once the
// account is active, so the caller should say "try again after signing in",
// never "ask your admin for a new one".
var ErrMemberNotActive = errors.New("orgclient: organisation account not active yet")

// ErrBatchTooLarge reports that the complete serialized push envelope exceeds
// either the node's configured maximum or the org server's accepted body size.
// It is not a transient network failure and therefore uses a circuit-breaker
// cadence in runLoop rather than exponential retry.
var ErrBatchTooLarge = errors.New("orgclient: push batch too large")

// ErrAgentTooOld reports that the org server refused this push because the
// node runs below its [server].min_agent_version and the org set
// min_agent_version_action = "refuse" (enterprise update management W5, §6
// O5). The server ingested NOTHING.
//
// It is RETRYABLE in the same sense ErrAuthFailed is — the condition clears
// the moment the node is updated, with no process restart — so the loop keeps
// its normal backoff rather than parking. What it must not do is look like a
// transient network error: the operator-facing message names both versions,
// and RecordPush stores it as a FAILED push so the node dashboard's banner can
// say exactly what is wrong and what to install.
var ErrAgentTooOld = errors.New("orgclient: agent below the org's minimum version")

// Client runs the agent side of the Teams enrolment + push protocol: it
// enrols (binding a fresh Ed25519 keypair), reads content-free rollup rows
// above the local push cursor, signs and ships them to the org server, and
// advances the cursor on acceptance. Nothing here runs unless the agent is
// both configured ([org_client] enabled) and enrolled; see package doc.
type Client struct {
	// bg owns the node-side break-glass lease state (breakglass.go).
	bg           breakGlassState
	cfg          config.OrgClientConfig
	store        *store.Store
	bearers      BearerStore
	httpClient   *http.Client
	logger       *slog.Logger
	agentVersion string

	// P0-6 effective-policy-state fetch-outcome sinks (nil-defaulted seam,
	// R6-1). When non-nil, PolicyPollLoop/PushLoop forward the TOTAL typed
	// fetch outcome (§2.5b/§2.5c) here on every decisive cycle so the reporter
	// can resolve stale_lkg and delivered_unaccepted, which onResult/success
	// never surface. A nil sink is EXACTLY today's behaviour, so the existing
	// call sites compile and run unchanged. Set via SetGuardOutcomeSink /
	// SetRoutingOutcomeSink.
	guardOutcomeSink   func(GuardFetchOutcome)
	routingOutcomeSink func(RoutingFetchOutcome)

	// integrityCollector is the Arc 4 P6b managed-integrity probe seam (plan
	// §9): a nil-defaulted func that returns this host's coarse tamper-evidence
	// report (sibling-observer origins, drifted AI-tool names, and versioned
	// capture-behavior checks). It is injected
	// by cmd/observer so the client never imports internal/diag or
	// internal/proxyroute (the boundary), and it is consulted ONLY inside
	// PushLoop and ONLY for a managed node — so it rides the existing push cycle
	// (no new timer/host/connection, the announce.go discipline) and the
	// individual plane never computes or sends an integrity signal. Nil = an
	// exact no-op. Set via SetIntegrityCollector.
	integrityCollector func() orgcontract.ManagedIntegrityReport

	// routingReloadSink is the P0-7 router hot-reload trigger (docs/plans/
	// plane-a-p0-7-guard-router-hotreload-plan.md §2.2/§4.5): a nil-defaulted
	// additive seam invoked AFTER a routing policy is accepted + cached
	// (rfStageAccepted, both newly-cached and already-current arms — SF7), so
	// the caller can apply it to the live router in-process. Independent of
	// routingOutcomeSink (one owner per concern: that sink updates the P0-6
	// reporter slot, this one reloads the live router). Nil = today's exact
	// no-op. Set via SetRoutingReloadSink.
	routingReloadSink func(ctx context.Context)

	// orgIdentityChangedSink is the Plane-A P0-5 Phase W enrolment-transition
	// hook (plan §6.9): fired synchronously from Enroll/Unenroll AFTER the
	// durable org_enrolment_generation bump/tombstone commits, so a caller
	// that holds a live obs.AdmissionService IN THE SAME PROCESS (e.g. a
	// future dashboard-driven enroll/unenroll path) can ClearOrg both
	// families immediately rather than waiting for
	// AdmissionService's own short-TTL identity recheck. orgclient must not
	// import internal/obs (the boundary), so this is a plain func — nil
	// (today's only real call path: the separate `observer enroll`/
	// `observer unenroll` CLI processes, which hold no live
	// AdmissionService) is an exact no-op. The cross-process case — a
	// running daemon observing an unenrol/re-enrol performed by a SEPARATE
	// `observer` invocation — is NOT this sink; it self-heals via
	// AdmissionService's own activeEnrolmentIdentity cache instead (bounded
	// by identityCheckTTL), which is what actually matters today. Set via
	// SetOrgIdentityChangedSink.
	orgIdentityChangedSink func()

	// policyResourceCacheDir is the base directory for the generation-scoped
	// on-disk policy-resource cache tree (plan §6.2). Set via
	// SetPolicyResourceCacheDir; when non-empty, Enroll/Unenroll remove the
	// org_key subtree so identity transitions do not leave stale envelopes
	// (Codex SF3). Empty = no filesystem cleanup (tests that never install).
	policyResourceCacheDir string

	// policyResourceKick wakes PolicyResourcePollLoop for an immediate fetch
	// cycle when a push acknowledgment reports a newer published policy
	// version (the 2026-09-01 propagation nudge). Buffered(1) + non-blocking
	// send: coalescing wake-ups is exactly right, one fetch cycle covers any
	// number of publishes. The kick only ADVANCES the poll — every gate the
	// fetch itself applies (signature, pin, accept_families) is unchanged.
	policyResourceKick chan struct{}

	// lastPolicyVersions is the most recent policy_versions map seen on a
	// push acknowledgment, compared under policyVersMu to detect a version
	// advance. In-memory only: on boot it is nil and the FIRST ack never
	// kicks, because PolicyResourcePollLoop already fetches immediately on
	// start.
	policyVersMu       sync.Mutex
	lastPolicyVersions map[string]int64

	// railPinDriftOnce keeps the "a fetch rail still holds the older key"
	// notice to ONE line per process (orgSigningKey). The condition is
	// self-healing — the rail re-pins on its next accepted document — so
	// repeating it on every 30-second poll would be noise, and staying
	// silent about it would hide a real cut-over in progress.
	railPinDriftOnce sync.Once

	// updates is the Enterprise Update Management manifest rail's node-side
	// cache (§3.5, update.go). It holds the last VERIFIED manifest, the
	// posture that verification produced, the org key this rail has seen, and
	// the last update_versions nudge — so a fetch happens only when the
	// server is genuinely ahead and the steady state adds no requests at all.
	//
	// In-memory in W2; agent migration 105's update_state gives it durability
	// in W3. A restart resetting the accepted ordinal is safe: only the replay
	// rule reads it, and the downgrade rule compares against the INSTALLED
	// binary, which a restart does not change.
	updates updateCache

	// shareProvider resolves the share posture PushOnce ships under
	// (admin-controlled Plane B, Phase 1b §2.4). Nil means "use the config
	// this client was constructed with", which is byte-identical to Phase
	// 1a — so a build with no governance wiring behaves exactly as before.
	//
	// It exists because share directives are LOWERING-ONLY and must be HOT:
	// a node that keeps shipping content for hours after the org said stop
	// is precisely the failure the directive exists to prevent, and Client
	// holds cfg from construction. One owner (store.ShareOptions), two feed
	// paths (TOML, governance) — the pattern CLAUDE.md #4 blesses.
	shareProvider func() store.ShareOptions

	// governanceSidecarPath is the node-local governance sidecar, removed by
	// Unenroll (§1.4 step 2b). Empty = nothing to remove (the solo case and
	// every test that never wires governance).
	governanceSidecarPath string

	// featuresSidecarPath is the node-local node.features LKG sidecar (the P7
	// gateway-arc tools.disallow state), removed by Unenroll the same way as
	// the governance sidecar so a one-shot CLI launcher spawned a millisecond
	// after unenrol reads no stale disallow list. Empty = nothing to remove.
	// The daemon-side WRITER lives in cmd/observer (the node.features poller);
	// this field only tracks the path for deletion, mirroring
	// governanceSidecarPath. Empty in the solo case and in every test that
	// never wires node.features.
	featuresSidecarPath string

	// renewalSink receives the classified outcome of every authenticated
	// agent request (§4.2). Nil = today's exact behaviour.
	renewalSink func(RenewalOutcome)

	// budget is the org BUDGET rail's node-side hot cache (budgetpolicy.go,
	// wave W3b): the last VERIFIED per-caller body plus its ETag and exact
	// enrollment identity. The signed document is also persisted for restart.
	budget budgetCache
	// budgetSink receives every budget poll's typed outcome so the caller can
	// recompose the guard's effective thresholds in-process. Nil-defaulted
	// additive seam (R6-1): with no sink installed the fetch still runs and
	// caches, and nothing downstream changes. Set via SetBudgetSink.
	budgetSink func(BudgetFetchOutcome)
	// budgetMaxAge is the freshness window applied to a budget document's
	// signed issued_at ([guard.budget].max_document_age, finding M3). Zero
	// means orgcontract.BudgetPolicyDefaultMaxAge. Set via
	// SetBudgetMaxDocumentAge; the guard config does not reach this package's
	// constructor, and threading it through OrgClientConfig would put one
	// knob in two config sections.
	budgetMaxAge time.Duration
	// budgetNow is the clock the freshness check reads. Nil means time.Now.
	// A seam rather than a direct call so a test can age a document without
	// sleeping — the only way to exercise a one-hour window.
	budgetNow func() time.Time

	// pricing is the org PRICING rail's in-memory mirror of the PERSISTED
	// document (pricingpolicy.go, wave W2). Unlike the budget rail's cache
	// this one has a durable twin (org_pricing_cache, agent migration 106):
	// a mis-priced captured turn is permanent, so a restart must not re-price
	// at list rates while it waits for the first poll.
	pricing pricingCache
	// pricingEnabled is the ruling-R2 gate, [guard.budget].from_org. Nil = the
	// rail is OFF and makes no request at all.
	pricingEnabled func() bool
	// pricingAuthoritative resolves the live tenancy flag (managed +
	// enforce.budget). Nil = never authoritative, which is every
	// individual/BYO node.
	pricingAuthoritative func() bool
	// pricingSink receives every pricing poll's typed outcome so the caller
	// can re-compose the live cost engine in-process. Nil-defaulted additive
	// seam, exactly like budgetSink.
	pricingSink func(PricingFetchOutcome)

	// intelEnabled is the org-served-cloud-intelligence RESULT-pull gate
	// ([intelligence].org_enrichment, org-served-cloud-intelligence plan
	// §2.1/§2.4, W3). Nil = the rail is OFF and FetchIntelResults makes no
	// request at all (the opt-in default). A func rather than a bool so a
	// config reload / managed raise (W5) can turn it on without a restart.
	// Set via SetIntelRail.
	intelEnabled func() bool
	// intelSince is the in-memory pagination cursor for the result pull: the
	// NextCursor the server last returned. LOOP-OWNED — touched only by
	// FetchIntelResults, which runs on the single push-loop goroutine. Not
	// persisted: a restart re-pages from the start and org_intel_cache's
	// UNIQUE(session_id, job_id) dedups the re-fetch.
	intelSince string
	// intelCursorOrgID is the org id the in-memory intelSince cursor (and any
	// cached rows) belong to. FetchIntelResults resets the cursor and drops
	// foreign-org cached rows when the live enrolment's org id no longer matches
	// this (a re-enrol, possibly to a different org), so org A's cursor/results
	// can never bleed into org B (adversarial finding 6). LOOP-OWNED, like
	// intelSince.
	intelCursorOrgID string
	// intelNotSupportedLogged silences the 404 "pre-feature server" WARN to
	// once per daemon lifetime (the pricing rail's not-supported posture).
	intelNotSupportedLogged bool
	// intelRejects counts CONSECUTIVE cycles in which one result row could not
	// be persisted, keyed by the (session, job) pair that is also the cache's
	// UNIQUE key. It is the bounded dead-letter's only state: a row that keeps
	// being rejected (schema drift, or a narrative item the node-side SafeText
	// gate refuses) would otherwise hold the cursor back forever and FREEZE the
	// rail, because the same page would be re-fetched and re-rejected every
	// cycle. A successful persist deletes the key, so the count really is
	// consecutive, and a dead-lettered row deletes it too — so the map only
	// ever holds rows currently failing, bounded by one page.
	// LOOP-OWNED like intelSince: touched only by FetchIntelResults on the
	// single push-loop goroutine, so it needs no lock. NOT persisted — a
	// restart re-pages from the start and re-attempts every row from zero,
	// which is the fail-open behaviour we want.
	intelRejects map[intelRowKey]int
}

// SetShareProvider installs the hot share-posture resolver (§2.4). Passing
// nil restores the cfg-derived default.
func (c *Client) SetShareProvider(fn func() store.ShareOptions) {
	if c == nil {
		return
	}
	c.shareProvider = fn
}

// SetGovernanceSidecarPath tells Unenroll which sidecar to delete. Safe to
// leave unset.
func (c *Client) SetGovernanceSidecarPath(path string) {
	if c == nil {
		return
	}
	c.governanceSidecarPath = path
}

// GovernanceSidecarPath reports the sidecar Unenroll would delete. It
// exists so the cmd layer can PIN its wiring (the 2026-08-15 smoke found
// only start.go set the path, leaving CLI unenrolls orphaning the file).
func (c *Client) GovernanceSidecarPath() string {
	if c == nil {
		return ""
	}
	return c.governanceSidecarPath
}

// SetFeaturesSidecarPath tells Unenroll which node.features LKG sidecar to
// delete (the P7 gateway-arc tools.disallow state). Safe to leave unset;
// mirrors SetGovernanceSidecarPath.
func (c *Client) SetFeaturesSidecarPath(path string) {
	if c == nil {
		return
	}
	c.featuresSidecarPath = path
}

// FeaturesSidecarPath reports the node.features sidecar Unenroll would delete,
// so the cmd layer can pin its wiring the same way it pins the governance one.
func (c *Client) FeaturesSidecarPath() string {
	if c == nil {
		return ""
	}
	return c.featuresSidecarPath
}

// removeFeaturesSidecar deletes the node-local node.features LKG sidecar on
// unenrol so a one-shot CLI launcher spawned immediately after reads no stale
// tools.disallow list. Best-effort and logged; never an unenrol failure —
// mirrors removeGovernanceSidecar.
func (c *Client) removeFeaturesSidecar() {
	if c == nil || c.featuresSidecarPath == "" {
		return
	}
	if err := os.Remove(c.featuresSidecarPath); err != nil && !os.IsNotExist(err) {
		c.logger.Warn("unenroll: could not remove the node.features sidecar — a stale tools.disallow list may briefly gate one-shot launchers until it is overwritten or expires",
			"path", c.featuresSidecarPath, "err", err)
	}
}

// shareOptions resolves the share posture for one push. The DEFAULT is
// exactly the cfg-derived value Phase 1a built inline, so the seam is inert
// until something installs a provider.
func (c *Client) shareOptions() store.ShareOptions {
	if c.shareProvider != nil {
		return c.shareProvider()
	}
	return ShareOptionsFromConfig(c.cfg)
}

// ShareOptionsFromConfig maps an [org_client] config block onto the push
// share posture. It is the ONE definition of that mapping; the governance
// provider in cmd/observer LOWERS the result rather than rebuilding it, so
// the two can never disagree about which keys exist.
func ShareOptionsFromConfig(cfg config.OrgClientConfig) store.ShareOptions {
	return store.ShareOptions{
		FullContent:           cfg.Share.FullContent,
		TargetActionAllowlist: cfg.Share.TargetActionAllowlist,
		AdminManaged:          cfg.Share.AdminManaged,
		FullToolBodies:        cfg.Share.FullToolBodies,
		RoutingSummary:        cfg.Share.RoutingSummary,
		CacheDetail:           cfg.Share.CacheDetail,
		RoutingDetail:         cfg.Share.RoutingDetail,
		LimitGauge:            cfg.Share.LimitGauge,
		CodeintelDetail:       cfg.Share.CodeintelDetail,
		ProcessDetail:         cfg.Share.ProcessDetail,
		TerminalDetail:        cfg.Share.TerminalDetail,
		TaskDetail:            cfg.Share.TaskDetail,
		ToolAccountDetail:     cfg.Share.ToolAccountDetail,
		ObsSummary:            cfg.Share.Obs.Summary,
		ObsTraces:             cfg.Share.Obs.Traces,
		ObsContent:            cfg.Share.Obs.Content,
		ObsEvalSummary:        cfg.Share.Obs.EvalSummary,
		ObsAdmission:          cfg.Share.Obs.Admission,
		ObsEvalItems:          cfg.Share.Obs.EvalItems,
		ObsEgress:             cfg.Share.Obs.Egress,
	}
}

// SetOrgIdentityChangedSink injects the Phase W enrolment-transition hook
// (see the field's doc comment). Safe to leave unset.
func (c *Client) SetOrgIdentityChangedSink(fn func()) { c.orgIdentityChangedSink = fn }

// SetPolicyResourceCacheDir sets the on-disk policy-resource cache base
// (Codex SF3). Safe to leave unset.
func (c *Client) SetPolicyResourceCacheDir(dir string) { c.policyResourceCacheDir = dir }

// removeGovernanceSidecar deletes the node-local governance sidecar (§1.4
// unenrol step 2b). Best-effort and logged; never an unenrol failure.
func (c *Client) removeGovernanceSidecar() {
	if c == nil || c.governanceSidecarPath == "" {
		return
	}
	if err := os.Remove(c.governanceSidecarPath); err != nil && !os.IsNotExist(err) {
		c.logger.Warn("unenroll: could not remove the governance sidecar — pinned settings will lift at the next hook once the grant's own expiry passes",
			"path", c.governanceSidecarPath, "err", err)
	}
}

// clearPolicyResourceCacheTree removes <cacheDir>/<orgKey>/ best-effort.
func (c *Client) clearPolicyResourceCacheTree(orgKey string) {
	if c == nil || c.policyResourceCacheDir == "" || orgKey == "" {
		return
	}
	_ = os.RemoveAll(filepath.Join(c.policyResourceCacheDir, orgKey))
}

// New constructs a push Client. httpClient may be nil (a default with a sane
// timeout is used); logger may be nil (slog.Default). agentVersion is stamped
// into each push envelope for server-side diagnostics.
func New(cfg config.OrgClientConfig, st *store.Store, bearers BearerStore, agentVersion string, httpClient *http.Client, logger *slog.Logger) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	if logger == nil {
		logger = slog.Default()
	}
	c := &Client{
		cfg:                cfg,
		store:              st,
		bearers:            bearers,
		httpClient:         httpClient,
		logger:             logger,
		agentVersion:       agentVersion,
		policyResourceKick: make(chan struct{}, 1),
	}
	// Lever 2 of the steady-state CPU remediation (plan Track R2): the PUSH
	// LOOP owns the snapshot cadence, the store only applies it. Installed once
	// here rather than per tick because it is a property of this client's
	// config, not of any individual batch.
	if st != nil {
		st.SetOrgSnapshotInterval(c.snapshotInterval())
	}
	return c
}

// EnrolmentState is a read-only snapshot of the agent's enrolment for the CLI
// and dashboard. LastPush is nil when the agent has never pushed.
type EnrolmentState struct {
	Enrolled     bool
	OrgID        string
	OrgName      string
	OrgServerURL string
	UserID       string
	UserEmail    string
	EnrolledAt   string
	Backend      string // bearer-store backend: "keychain" | "file"
	LastPush     *store.PushLogEntry
	// PushPaused is non-nil ONLY while the oversized-batch circuit is open:
	// the composed rollup exceeded the accepted push limit, so the loop is
	// parked (oversizedBatchBackoff) and no telemetry is reaching the org
	// server. Nil is the normal case — pushes are running or simply idle.
	PushPaused *store.PushBreakerState
}

// PushResult summarises one push attempt for the CLI / loop.
type PushResult struct {
	Empty        bool  // nothing above the cursor; no network call was made
	RowCount     int   // rows in the batch
	Bytes        int   // gzip wire bytes shipped
	AcceptedRows int64 // server-reported newly-stored rows
	DedupedRows  int64 // server-reported already-present rows
}

// Enroll exchanges a one-time compound token for a long-lived bearer. It
// generates a fresh Ed25519 keypair, posts the public half, and on success
// persists the bearer + private key (keychain), seeds the push cursor from the
// current high-water ids (so only post-enrolment activity is ever shared), and
// writes the org_enrolment row. The keychain and cursor are written BEFORE the
// enrolment row so that a concurrently-running push loop, which keys off the
// enrolment row, never observes an enrolled state with an un-seeded cursor.
func (c *Client) Enroll(ctx context.Context, orgURL, token string) (*store.Enrolment, *GrantOffer, error) {
	orgURL = strings.TrimRight(strings.TrimSpace(orgURL), "/")
	if orgURL == "" {
		return nil, nil, errors.New("orgclient.Enroll: org server URL is required")
	}
	if strings.TrimSpace(token) == "" {
		return nil, nil, errors.New("orgclient.Enroll: enrolment token is required")
	}

	// Snapshot the OLD enrolment (nil on a fresh install) before it is
	// overwritten below, so a re-enrolment can tombstone the old identity's
	// policy-resource generation (plan §6.9) after the new one activates.
	oldEnr, _ := c.store.LoadEnrolment(ctx) //nolint:errcheck // best-effort snapshot; a read failure just skips old-identity cleanup

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("orgclient.Enroll: keygen: %w", err)
	}

	gc, err := c.genClient(orgURL)
	if err != nil {
		return nil, nil, fmt.Errorf("orgclient.Enroll: %w", err)
	}
	resp, err := gc.EnrollAgentWithResponse(ctx, gen.EnrollRequest{
		OneTimeToken:   token,
		AgentPublicKey: base64.RawURLEncoding.EncodeToString(pub),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("orgclient.Enroll: post: %w", err)
	}
	switch resp.StatusCode() {
	case http.StatusOK:
		// fall through
	case http.StatusUnauthorized, http.StatusForbidden:
		// The server's pending-member path (handlers.go EnrollAgent) answers
		// 403 with {"error":"member_not_active", ...} and deliberately does
		// NOT burn the token: the account behind it just is not active yet,
		// and the same compound token will exchange successfully once it is.
		// That is a materially different outcome from "invalid or expired" —
		// telling the developer to go ask their admin for a NEW token here
		// would send them back for a replacement that fails the exact same
		// way, when running the exact same command again (after signing in)
		// is what actually works.
		var eb struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(resp.Body, &eb)
		if resp.StatusCode() == http.StatusForbidden && eb.Error == "member_not_active" {
			msg := eb.Message
			if msg == "" {
				msg = "your organisation account is not active yet"
			}
			return nil, nil, fmt.Errorf("orgclient.Enroll: %w: %s"+
				" (your enrolment token is still valid; run the same command again after you have signed in)",
				ErrMemberNotActive, msg)
		}
		return nil, nil, fmt.Errorf("orgclient.Enroll: %w: invalid or expired enrolment token"+
			" (the link may have expired or already been used; ask your admin for a new one, or use --idp)", ErrAuthFailed)
	default:
		return nil, nil, fmt.Errorf("orgclient.Enroll: server returned %d: %s", resp.StatusCode(), strings.TrimSpace(string(resp.Body)))
	}
	er := resp.JSON200
	if er == nil || er.Bearer == "" {
		return nil, nil, errors.New("orgclient.Enroll: server returned no bearer")
	}

	// Seed the cursor + persist secrets BEFORE the enrolment row (see doc).
	maxIDs, err := c.store.CurrentMaxIDs(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("orgclient.Enroll: seed cursor: %w", err)
	}
	if err := c.store.SavePushCursor(ctx, maxIDs); err != nil {
		return nil, nil, fmt.Errorf("orgclient.Enroll: save cursor: %w", err)
	}
	// Wipe any prior-run last-push state so `observer org status` after
	// a re-enroll reports "(none yet)" instead of a stale timestamp.
	// N5 in docs/audits/teams-test-regression-2026-06-03.md.
	if err := c.store.ClearLastPushState(ctx); err != nil {
		return nil, nil, fmt.Errorf("orgclient.Enroll: clear last-push state: %w", err)
	}
	if err := c.bearers.SaveAgentKey(priv); err != nil {
		return nil, nil, fmt.Errorf("orgclient.Enroll: %w", err)
	}
	if err := c.bearers.SaveBearer(er.Bearer); err != nil {
		return nil, nil, fmt.Errorf("orgclient.Enroll: %w", err)
	}

	enr := store.Enrolment{
		OrgID:        er.OrgID,
		OrgName:      er.OrgName,
		OrgServerURL: orgURL,
		UserID:       er.UserID,
		UserEmail:    er.UserEmail,
		EnrolledAt:   time.Now().UTC().Format(time.RFC3339),
		BearerKeyID:  c.cfg.KeychainID,
		// Tenancy rides on the enrol response at the same authenticated-TLS
		// trust level as OrgID/OrgName; empty is normalised to individual by
		// WriteEnrolment. Managed makes the govern resolver honour the
		// managed authorities carried in the SIGNED grant (ConsentMode set in
		// evaluateGrantOffer).
		Tenancy: er.Tenancy,
	}

	// Plane-A P0-5 (plan §6.9 / R6-B2 / R3-B2 / Codex B1): activate the new
	// identity's policy-resource generation BEFORE WriteEnrolment so a
	// concurrent FetchAndAccept never observes enrolled-without-generation
	// (missing gen ≡ ErrNotEnrolled). Fail-closed on bump/clear errors —
	// never leave enrolment visible without an active generation row. On
	// any re-enrolment (same or different org key), clear prior
	// policy-resource state so CAS cannot wedge on a stale generation
	// column (Codex B3).
	newOrgKey := OrgKey(orgURL, er.OrgID)
	if oldEnr != nil {
		oldOrgKey := OrgKey(oldEnr.OrgServerURL, oldEnr.OrgID)
		if oldOrgKey != newOrgKey {
			if _, err := c.store.BumpEnrolmentGeneration(ctx, oldOrgKey, true); err != nil {
				return nil, nil, fmt.Errorf("orgclient.Enroll: tombstone old enrolment generation: %w", err)
			}
		}
		if err := c.store.ClearPolicyResourceState(ctx, oldOrgKey); err != nil {
			return nil, nil, fmt.Errorf("orgclient.Enroll: clear old policy-resource state: %w", err)
		}
		c.clearPolicyResourceCacheTree(oldOrgKey)
	}
	generation, err := c.store.BumpEnrolmentGeneration(ctx, newOrgKey, false)
	if err != nil {
		return nil, nil, fmt.Errorf("orgclient.Enroll: activate enrolment generation: %w", err)
	}
	// A budget document is signed for one member and one enrollment epoch.
	// Clear the singleton after advancing the durable generation and before
	// publishing the replacement enrollment. Any late save from the old epoch
	// now fails its generation predicate; a cold process cannot restore the old
	// member's cap under the new identity.
	c.budget.clear()
	if err := c.store.ClearOrgBudget(ctx); err != nil {
		return nil, nil, fmt.Errorf("orgclient.Enroll: clear prior org budget: %w", err)
	}
	if err := c.store.WriteEnrolment(ctx, enr); err != nil {
		return nil, nil, fmt.Errorf("orgclient.Enroll: write enrolment: %w", err)
	}
	if c.orgIdentityChangedSink != nil {
		c.orgIdentityChangedSink()
	}

	// Pin the org POLICY signing key when the server delivered one
	// (guard spec §14.2 — the pin every fetched bundle's embedded key
	// is checked against; guard_policy_state is the pin home, append-
	// only so rotations stay auditable and a re-enrol records the new
	// key). A pre-G13 server omits the field: the first bundle fetch
	// then pins trust-on-first-fetch instead. A malformed key is a
	// server bug, WARN-only — enrolment's primary job (the push
	// channel) must not fail over it; the fetch path will TOFU-pin.
	pinnedKeyHash := ""
	if er.OrgPolicyPublicKey != "" {
		if keyHash, perr := pinBase64Key(er.OrgPolicyPublicKey); perr != nil {
			c.logger.Warn("org policy key not pinned", "err", perr)
		} else if _, perr := c.store.RecordGuardPolicyState(ctx, store.GuardPolicyStateRow{
			Layer: "org",
			Path:  PolicyKeyPinPath(orgURL),
			// PROVENANCE (C1). Enroll is the only writer that stamps this:
			// the policy-bundle and policy-resource rails write the same row
			// by trust-on-first-fetch with an empty version, and a pin this
			// node did not receive over the enrolment channel must never be
			// promoted to the trust root.
			Version:     enrolmentPinProvenance,
			ContentHash: keyHash,
			LoadedAt:    time.Now().UTC(),
		}); perr != nil {
			c.logger.Warn("org policy key not pinned", "err", perr)
		} else {
			pinnedKeyHash = keyHash
			c.logger.Info("org policy signing key pinned at enrolment", "key_sha256", keyHash)
		}
		// R1(b)/(d): the hash pin above cannot VERIFY anything, so the key
		// ITSELF is persisted beside it (orgpin.go, OrgKeyMaterialSuffix) —
		// this is the trust root every other rail is resolved and
		// cross-checked against. Written unconditionally whenever the
		// response carries a key, so a re-enrol against a rotated key wins
		// over whatever a fetch rail pinned in between; an EMPTY response
		// field still leaves the previous row alone (a server that stopped
		// delivering a key is not a server that revoked one).
		if keyStd, perr := c.recordEnrolmentKeyMaterial(ctx, orgURL, er.OrgPolicyPublicKey); perr != nil {
			c.logger.Warn("org policy key material not stored (budget/pricing rails will fall back to the fetch-rail pins)", "err", perr)
		} else {
			c.logger.Info("org distribution key stored at enrolment",
				"key_sha256_prefix", prefix12(pinnedKeyHash), "key_prefix", prefix8(keyStd))
		}
	}

	// Admin-controlled Plane B (spec §2.3, adversarial review A3/A4): the
	// grant is evaluated ONLY AFTER the org policy key was actually pinned,
	// and it is RETURNED, never written here. Two reasons this ordering is
	// load-bearing:
	//
	//   - The pin write above is best-effort by design (enrolment's primary
	//     job, the push channel, must not fail over it). A grant accepted
	//     without a pin would be authority bound to nothing: the NEXT policy
	//     fetch would TOFU-pin whatever key it saw, which need not be the key
	//     the grant was signed under. So a missing/failed pin REFUSES the
	//     grant, loudly, instead of storing it unverified.
	//   - orgclient has no TTY, and by this point the bearer is saved, the
	//     enrolment is written and the generation is bumped — there is no
	//     honest place here to ask a human anything. cmd/observer/org.go owns
	//     the confirmation and the store write.
	offer := c.evaluateGrantOffer(er, orgURL, newOrgKey, generation, pinnedKeyHash)

	c.logger.Info("enrolled in org", "org", enr.OrgName, "org_id", enr.OrgID,
		"user_email", enr.UserEmail, "server", orgURL, "store", c.bearers.Backend())
	return &enr, offer, nil
}

// GrantOffer is a VERIFIED enrolment grant plus the identity facts the node
// needs in order to store it. Enroll returns one only when every gate passed;
// a nil offer means "enrolled, ungoverned", which is exactly today's
// behaviour and what every pre-governance server produces.
type GrantOffer struct {
	Grant        orgcontract.EnrolmentGrant
	OrgKey       string
	Generation   int64
	KeyPinSHA256 string
	ReceiptHash  string
	// Tenancy is the enrolment class from the enrol response (individual vs
	// managed). The node-side grant writer maps managed → govern
	// ConsentMode=managed, which is the signal the govern resolver branches
	// on to honour the managed-only authorities carried in this grant.
	Tenancy string
	// ConsentMode / ConsentActor are the ACP-P6c consent evidence, resolved
	// ONCE here so cmd/observer records a single answer rather than choosing
	// between two sources of it.
	//
	// PREFERENCE ORDER, and why it matters: the copy bound into the SIGNED
	// grant wins, because by the time this struct exists that copy has been
	// verified under the key this very enrolment pinned. The enrol response's
	// envelope fields are the fallback — they ride at plain authenticated-TLS
	// trust, so anything able to rewrite them could equally have rewritten
	// the tenancy. Preferring the signed copy means the strongest statement
	// available is the one the node writes down and shows an auditor.
	//
	// Both empty is the token rail, where the node resolves its consent mode
	// from Tenancy exactly as it did before P6c.
	ConsentMode  string
	ConsentActor string
}

// evaluateGrantOffer runs the accept gates for an offered grant. EVERY
// refusal is logged with a named reason (adversarial review A3: a silently
// skipped grant leaves the admin staring at a permanently ungoverned node
// with no diagnosis) and returns nil, which enrols the node ungoverned.
func (c *Client) evaluateGrantOffer(er *orgcontract.EnrollResponse, orgURL, orgKey string, generation int64, pinnedKeyHash string) *GrantOffer {
	if er.Grant == nil {
		return nil
	}
	g := *er.Grant
	switch {
	case er.OrgPolicyPublicKey == "":
		c.logger.Warn("enrolment grant REFUSED: the server offered governance but sent no org policy signing key, so the grant cannot be bound to any key — enrolling ungoverned")
		return nil
	case pinnedKeyHash == "":
		c.logger.Warn("enrolment grant REFUSED: the org policy signing key could not be pinned, so a grant would be authority bound to nothing — enrolling ungoverned")
		return nil
	case g.KeyPinSHA256 == "" || g.KeyPinSHA256 != pinnedKeyHash:
		c.logger.Warn("enrolment grant REFUSED: the grant names a different org policy signing key than the one this enrolment pinned — enrolling ungoverned",
			"grant_key_sha256", g.KeyPinSHA256, "pinned_key_sha256", pinnedKeyHash)
		return nil
	case g.OrgID != er.OrgID:
		c.logger.Warn("enrolment grant REFUSED: the grant names a different org than the enrolment — enrolling ungoverned",
			"grant_org_id", g.OrgID, "enrolment_org_id", er.OrgID)
		return nil
	case strings.TrimRight(strings.TrimSpace(g.OrgServerURL), "/") != orgURL:
		c.logger.Warn("enrolment grant REFUSED: the grant names a different org server than the one being enrolled with — enrolling ungoverned",
			"grant_server", g.OrgServerURL, "enrolment_server", orgURL)
		return nil
	}
	pubRaw, derr := base64.RawURLEncoding.DecodeString(er.OrgPolicyPublicKey)
	if derr != nil {
		c.logger.Warn("enrolment grant REFUSED: org policy public key did not decode — enrolling ungoverned", "err", derr)
		return nil
	}
	if verr := orgcontract.VerifyEnrolmentGrant(g, ed25519.PublicKey(pubRaw)); verr != nil {
		c.logger.Warn("enrolment grant REFUSED: signature did not verify under the pinned org policy key — enrolling ungoverned", "err", verr)
		return nil
	}
	if g.ExpiresAt != "" {
		exp, perr := time.Parse(time.RFC3339, g.ExpiresAt)
		if perr != nil {
			c.logger.Warn("enrolment grant REFUSED: expires_at is not RFC3339 — enrolling ungoverned", "expires_at", g.ExpiresAt)
			return nil
		}
		if !time.Now().UTC().Before(exp) {
			c.logger.Warn("enrolment grant REFUSED: it is already expired — enrolling ungoverned", "expires_at", g.ExpiresAt)
			return nil
		}
	}
	consentMode, consentActor := g.ConsentMode, g.ConsentActor
	if consentMode == "" {
		// No evidence inside the verified grant: fall back to the response
		// envelope. See GrantOffer.ConsentMode for why this order and not the
		// other one.
		consentMode, consentActor = er.ConsentMode, er.ConsentActor
	}
	return &GrantOffer{
		Grant:        g,
		OrgKey:       orgKey,
		Generation:   generation,
		KeyPinSHA256: pinnedKeyHash,
		ReceiptHash:  orgcontract.EnrolmentGrantReceiptHash(g),
		Tenancy:      er.Tenancy,
		ConsentMode:  consentMode,
		ConsentActor: consentActor,
	}
}

// Unenroll deletes the local enrolment row and clears the keychain secrets.
// The enrolment row is removed first so a concurrent push loop, which re-reads
// the row each cycle, stops pushing as soon as it observes the absence. Absent
// state is not an error (idempotent).
func (c *Client) Unenroll(ctx context.Context) error {
	// Snapshot first, then tombstone the generation BEFORE deleting the
	// enrolment row (plan §6.9 / Codex B1): a concurrent fetch must observe
	// tombstoned (or missing gen after clear) rather than a live enrolment
	// with a still-active generation.
	enr, _ := c.store.LoadEnrolment(ctx) //nolint:errcheck // best-effort snapshot; absent is fine

	if enr != nil {
		orgKey := OrgKey(enr.OrgServerURL, enr.OrgID)
		if _, err := c.store.BumpEnrolmentGeneration(ctx, orgKey, true); err != nil {
			return fmt.Errorf("orgclient.Unenroll: tombstone enrolment generation: %w", err)
		}
		// Admin-controlled Plane B (spec §5.1): delete the enrolment GRANT
		// in the same fail-closed prefix as the tombstone, BEFORE the
		// policy-resource state and the enrolment row. Revocation must
		// leave nothing behind that could govern this machine, and the
		// grant is the only artifact that could.
		if err := c.store.DeleteEnrolmentGrant(ctx, orgKey); err != nil {
			return fmt.Errorf("orgclient.Unenroll: delete enrolment grant: %w", err)
		}
		// Step 2b (Phase 1b §1.4): remove the governance sidecar, so a hook
		// or MCP process spawned a millisecond later reads no pins. It is
		// BEST-EFFORT because step 1 already tombstoned the generation and
		// because the reader's own expiry rule is the backstop that makes a
		// failed delete converge anyway — but leaving it would keep pinning
		// keys in short-lived processes until the grant lapsed, which is a
		// bad enough surprise to be worth the attempt and the log line.
		c.removeGovernanceSidecar()
		c.removeFeaturesSidecar()
		if err := c.store.ClearPolicyResourceState(ctx, orgKey); err != nil {
			return fmt.Errorf("orgclient.Unenroll: clear policy-resource state: %w", err)
		}
		c.clearPolicyResourceCacheTree(orgKey)
	}
	// Belt-and-braces: an unenrol running against a DB whose enrolment row
	// is already gone cannot derive an org_key, and an orphan grant is
	// authority with no owner. Clearing unconditionally is safe — a grant
	// only ever exists for the current enrolment.
	if err := c.store.DeleteAllEnrolmentGrants(ctx); err != nil {
		return fmt.Errorf("orgclient.Unenroll: delete enrolment grants: %w", err)
	}

	if err := c.store.DeleteEnrolment(ctx); err != nil {
		return fmt.Errorf("orgclient.Unenroll: %w", err)
	}
	c.budget.clear()
	if err := c.bearers.Clear(); err != nil {
		return fmt.Errorf("orgclient.Unenroll: %w", err)
	}
	c.clearBreakGlass()
	if c.orgIdentityChangedSink != nil {
		c.orgIdentityChangedSink()
	}

	c.logger.Info("unenrolled from org")
	return nil
}

// Status returns a snapshot of the agent's enrolment for the CLI / dashboard.
func (c *Client) Status(ctx context.Context) (EnrolmentState, error) {
	st := EnrolmentState{Backend: c.bearers.Backend()}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return st, fmt.Errorf("orgclient.Status: %w", err)
	}
	if enr == nil {
		return st, nil
	}
	st.Enrolled = true
	st.OrgID, st.OrgName, st.OrgServerURL = enr.OrgID, enr.OrgName, enr.OrgServerURL
	st.UserID, st.UserEmail, st.EnrolledAt = enr.UserID, enr.UserEmail, enr.EnrolledAt
	last, err := c.store.LastPushLog(ctx)
	if err != nil {
		return st, fmt.Errorf("orgclient.Status: %w", err)
	}
	st.LastPush = last
	// Surface an OPEN oversized-batch circuit. A parked push loop is otherwise
	// invisible except as a 'failed' row in org_push_log, which reads like any
	// other transient failure rather than "telemetry has stopped for an hour".
	paused, err := c.store.LoadPushBreaker(ctx)
	if err != nil {
		return st, fmt.Errorf("orgclient.Status: %w", err)
	}
	st.PushPaused = paused
	return st, nil
}

// LastPayload returns the JSON of the most recent successfully-pushed envelope
// (the content-free rollup, byte-for-byte as it went on the wire), or nil when
// the agent has never pushed. The dashboard serves it verbatim so a developer
// can audit exactly what was shared.
func (c *Client) LastPayload(ctx context.Context) ([]byte, error) {
	return c.store.LoadLastPushPayload(ctx)
}

// PushOnce ships at most one batch of content-free rows above the local push
// cursor to the org server. An empty batch makes no network call and writes no
// log row. On HTTP 200 it advances + persists the cursor and records an "ok"
// push-log row; on an auth failure it records "failed" and returns
// ErrAuthFailed; on any other failure (network, 5xx, 429, 4xx) it records
// "retry" and returns a (retryable) error.
func (c *Client) PushOnce(ctx context.Context) (PushResult, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: %w", err)
	}
	if enr == nil {
		return PushResult{}, ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if errors.Is(err, ErrNoSecret) {
		return PushResult{}, ErrNotEnrolled
	}
	if err != nil {
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: load bearer: %w", err)
	}
	signKey, err := c.bearers.LoadAgentKey()
	if errors.Is(err, ErrNoSecret) {
		return PushResult{}, ErrNotEnrolled
	}
	if err != nil {
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: load signing key: %w", err)
	}

	cur, err := c.store.LoadPushCursor(ctx)
	if err != nil {
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: load cursor: %w", err)
	}
	batch, err := c.store.SelectUnpushedSince(
		ctx, cur, c.maxPushBytes(), enr.OrgID, enr.UserEmail,
		c.shareOptions(),
		store.ScopeOptions{
			ProjectRootAllowlist: c.cfg.Scope.ProjectRootAllowlist,
			ProjectRootDenylist:  c.cfg.Scope.ProjectRootDenylist,
		},
	)
	if err != nil {
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: select: %w", err)
	}
	if batch.Empty() {
		// Nothing to deliver, so every snapshot family composed this tick is
		// as delivered as it can be: commit, or a family that legitimately
		// recomputes to zero rows would re-probe as dirty forever.
		c.store.CommitPushedSnapshots()
		return PushResult{Empty: true}, nil
	}

	env := orgcontract.PushEnvelope{
		AgentVersion: c.agentVersion,
		// Managed tenancy only: ManagedMachineIdentity returns "" for an
		// individual/BYO enrolment, an unresolvable machine id, or any load
		// error, and the field is omitempty — so an unmanaged node's envelope
		// stays byte-identical to the pre-feature shape. Reusing the SAME
		// accessor PostPolicyState uses keeps one definition of "this node's
		// machine identity" (the server keys on it across both rails).
		MachineIdentity:           c.ManagedMachineIdentity(ctx),
		CursorFrom:                maxCursor(cur),
		CursorTo:                  maxCursor(batch.Cursor),
		Sessions:                  batch.Sessions,
		Actions:                   batch.Actions,
		APITurns:                  batch.APITurns,
		TokenUsage:                batch.TokenUsage,
		RoutingSummaries:          batch.RoutingSummaries,
		CacheSummaries:            batch.CacheSummaries,
		CodeintelSummaries:        batch.CodeintelSummaries,
		ProcessSummaries:          batch.ProcessSummaries,
		SessionVerbositySummaries: batch.SessionVerbositySummaries,
		SessionCacheSummaries:     batch.SessionCacheSummaries,
		// Trickle-up wires (W2/W3/item 6b, 2026-09-11). Composed by their own
		// store seams under their share tiers; nil/empty otherwise. Every
		// PushBatch slice family with a same-named PushEnvelope field MUST be
		// mapped here - TestPushEnvelopeMapsEveryBatchFamily fails by name when
		// one is composed but never mapped (the class that dropped the obs
		// slices once and these four a second time).
		SessionCacheEvents:     batch.SessionCacheEvents,
		SessionTaskItems:       batch.SessionTaskItems,
		SessionTaskTransitions: batch.SessionTaskTransitions,
		SessionToolAccounts:    batch.SessionToolAccounts,
		SessionProcesses:       batch.SessionProcesses,
		SessionNetworkEvents:   batch.SessionNetworkEvents,
		SessionLOC:             batch.SessionLOC,
		LOCDays:                batch.LOCDays,
		AdvisorSuggestions:     batch.AdvisorSuggestions,
		ProjectPatterns:        batch.ProjectPatterns,
		BenchmarkRuns:          batch.BenchmarkRuns,
		BenchmarkAttempts:      batch.BenchmarkAttempts,
		CompressionStats:       batch.CompressionStats,
		RoutingDevRows:         batch.RoutingDevRows,
		CodeintelDevRows:       batch.CodeintelDevRows,
		TerminalRuns:           batch.TerminalRuns,
		TerminalCommands:       batch.TerminalCommands,
		RemoteAudit:            batch.RemoteAudit,
		GuardPins:              batch.GuardPins,
		GuardApprovals:         batch.GuardApprovals,
		TerminalSummaries:      batch.TerminalSummaries,
		RemoteAuditSummaries:   batch.RemoteAuditSummaries,
		RoutingDetails:         batch.RoutingDetails,
		LimitGauges:            batch.LimitGauges,
		GuardEvents:            batch.GuardEvents,
		OTelContent:            batch.OTelContent,
		// Org-tier observability (obs-org-tier plan). Each slice is
		// composed by orgpush.go::composeObsTiers only under its own
		// [org_client.share] flag; nil/empty when the node hasn't opted
		// in, so this mapping is inert for non-obs-sharing nodes.
		ObsSummaries:  batch.ObsSummaries,
		ObsTraces:     batch.ObsTraces,
		ObsSpans:      batch.ObsSpans,
		ObsSpanEvents: batch.ObsSpanEvents,
		ObsContent:    batch.ObsContent,
		ObsEvalRuns:   batch.ObsEvalRuns,
		// T5 per-end-user spend — composed only under ObsSummary &&
		// shipsRawContent() (end-user PII); nil/empty otherwise.
		ObsEndUserSpend: batch.ObsEndUserSpend,
		// T6 input-admission verdicts + policy snapshots — composed only
		// under the [org_client.share.obs] admission opt-in; nil/empty
		// otherwise. Verdict PII/prose is gated by shipsRawContent() in
		// composeObsTiers; policy Body always ships.
		ObsAdmissionEvents:   batch.ObsAdmissionEvents,
		ObsAdmissionPolicies: batch.ObsAdmissionPolicies,
		// T7 per-item eval scores — composed only under the
		// [org_client.share.obs] eval_items opt-in; nil/empty otherwise. Item
		// content excerpts are gated by shipsRawContent() in composeObsTiers;
		// the score metadata + content_hash always ship.
		ObsEvalItems:       batch.ObsEvalItems,
		ObsEgressDecisions: batch.ObsEgressDecisions, // T8
		// The node's own enum-only update posture (enterprise-update-management
		// plan §3.5). nil until cmd/observer wires the posture environment, and
		// the field is omitempty, so an envelope from a node without the
		// feature stays byte-identical to the pre-feature shape.
		UpdatePosture: batch.UpdatePosture,
		// The node's own enum-only BUDGET posture (org-budget plan §3.3d):
		// enforcement point, guard mode, where the effective numbers came
		// from, the last fetch state, and the proxy-only coverage limit. No
		// cap value, no resolved scope. nil until cmd/observer wires the
		// provider, and omitempty, so a node without the feature pushes a
		// byte-identical envelope.
		BudgetPosture: batch.BudgetPosture,
	}
	// The posture's freshness horizon on the server is a function of how often
	// this node reports, and the CLIENT is the one owner of that fact — the
	// store composes the posture but does not tick the loop, and the server
	// cannot derive a cadence from arrival gaps without mistaking one missed
	// push for a slow node (SF-19). Stamped here rather than plumbed into the
	// provider seam so "this node's cadence" keeps exactly one definition:
	// pushInterval(), the same resolver the loop itself uses.
	if env.BudgetPosture != nil {
		stamped := *env.BudgetPosture
		stamped.PushIntervalSeconds = int(c.pushInterval() / time.Second)
		env.BudgetPosture = &stamped
	}
	raw, err := json.Marshal(env)
	if err != nil {
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), 0, "failed", err.Error())
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: marshal: %w", err)
	}
	if err := validatePushBodySize(raw, c.maxPushBytes()); err != nil {
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), int64(len(raw)), "failed", err.Error())
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: %w", err)
	}
	wire, err := gzipBytes(raw)
	if err != nil {
		// A marshal/gzip failure is local and not retryable, but recording it
		// keeps the dashboard honest about why nothing shipped.
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), 0, "failed", err.Error())
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: encode: %w", err)
	}

	ts := time.Now().Unix()
	sig := ed25519.Sign(signKey, orgcontract.PushSigningMessage(ts, wire))
	localFP := orgcontract.AgentKeyFingerprint(signKey.Public().(ed25519.PublicKey))

	gc, err := c.genClient(enr.OrgServerURL)
	if err != nil {
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: %w", err)
	}
	// P2b: report the grant-replacement generation this node has adopted so the
	// server's fleet-ACK gate can converge. 0 (no grant, or no replacement yet)
	// still registers the node in the fleet registry. Best-effort: a read
	// failure just leaves the ACK at 0.
	ackGen := c.currentReplacementGeneration(ctx, enr)
	params := &gen.PushBatchParams{
		XSBOTimestamp:      &ts,
		XSBOAgentSignature: strPtr(base64.RawURLEncoding.EncodeToString(sig)),
	}
	// G1-BREAKGLASS: publish this node's seal key (signed, bound to org+node)
	// and report any redeemed leases the server has not heard about yet.
	bgAcks := c.pendingBreakGlassAcks()
	resp, err := gc.PushBatchWithBodyWithResponse(ctx, params, "application/json", bytes.NewReader(wire),
		bearerEditor(bearer), gzipEncodingEditor, agentKeyFingerprintEditor(localFP),
		grantReplacementAckEditor(ackGen), sealKeyEditor(signKey, enr.OrgID, enr.UserID),
		breakGlassAckEditor(bgAcks))
	if err != nil {
		c.noteRenewal(RenewalPathPush, 0, err)
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), int64(len(wire)), "retry", err.Error())
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: post: %w", err)
	}
	// The renewal signal (§4.2) is keyed off the PUSH path's own
	// authorization, which is the requirement parent §11.3 states: an org
	// that revokes push permission but leaves the policy poll working must
	// not keep governing the machine indefinitely.
	c.noteRenewal(RenewalPathPush, resp.StatusCode(), nil)

	switch resp.StatusCode() {
	case http.StatusOK:
		// Compare-and-swap against the cursor THIS cycle loaded, never a blind
		// save: an enrolment re-seed or an `observer org backfill` reset that
		// landed while this batch was in flight owns the stored cursor, and
		// overwriting it would either replay the node's whole pre-enrolment
		// history (the 2026-09-07 re-enrol regression) or undo the operator's
		// deliberate reset. The rows this cycle did deliver are absorbed by the
		// server's dedup, so keeping the stored cursor loses nothing.
		saved, err := c.store.SavePushCursorIfUnchanged(ctx, cur, batch.Cursor)
		if err != nil {
			return PushResult{}, fmt.Errorf("orgclient.PushOnce: save cursor: %w", err)
		}
		if !saved {
			c.logger.Info("push cursor moved underneath this cycle (enrol or backfill); keeping the stored cursor")
		}
		// Snapshot families are "delivered" only once the server has ACCEPTED
		// the batch — every other exit path leaves them dirty so the next tick
		// recomposes what this one failed to ship (plan Track R2 constraint 4).
		c.store.CommitPushedSnapshots()
		// Persist the exact rollup that was shared so the dashboard can show it
		// (best-effort: a failure here never fails an accepted push).
		_ = c.store.SaveLastPushPayload(ctx, raw)
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), int64(len(wire)), "ok", "")
		res := PushResult{RowCount: batch.RowCount(), Bytes: len(wire)}
		if resp.JSON200 != nil {
			res.AcceptedRows = resp.JSON200.AcceptedRows
			res.DedupedRows = resp.JSON200.DedupedRows
		}
		// P2b grant-replacement delivery (design §5.3, Sol S4). An out-of-band
		// authority change may ride the push response. The generated 200 struct
		// does not carry the field, so decode it from the RAW body and feed the
		// already-built, independently-tested accept path. Best-effort: a
		// delivery or accept failure never fails an otherwise-accepted push.
		c.maybeApplyGrantReplacement(ctx, resp.Body)
		// The server has now heard the ACKs this push carried; then redeem any
		// newly delivered leases / drop early-revoked ones (best-effort).
		c.markBreakGlassAcked(bgAcks)
		c.maybeRedeemBreakGlassLeases(ctx, resp.Body, signKey, enr)
		c.maybeKickPolicyResourceFetch(resp.Body)
		// Enterprise Update Management nudge (§3.5). Same raw-body,
		// best-effort shape as the seams above: the response may name a newer
		// published manifest version per channel, and only then does the node
		// fetch the SIGNED manifest with a separate authenticated GET. An org
		// that has published nothing adds ZERO requests to this cycle.
		c.noteUpdateNudge(resp.Body)
		// An accepted push proves this node is not below the org's floor, so
		// a previously-recorded 426 refusal is stale the instant we get here.
		c.clearAgentTooOld()
		return res, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		msg := c.reportAuthFailure(resp.Body, resp.StatusCode(), localFP, enr.OrgServerURL)
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), int64(len(wire)), "failed", msg)
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: %w: %s", ErrAuthFailed, msg)
	case http.StatusRequestEntityTooLarge:
		msg := serverError(resp.Body, resp.StatusCode())
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), int64(len(wire)), "failed", msg)
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: %w: %s", ErrBatchTooLarge, msg)
	case http.StatusUpgradeRequired:
		// Enterprise update management W5: the org refuses pushes from agents
		// below [server].min_agent_version. Recorded as FAILED (not "retry")
		// with the version-naming message, because this is not a transient
		// condition an operator should wait out — it clears when the node is
		// updated, and the node dashboard's update banner reads exactly this
		// record to say so.
		msg := c.noteAgentTooOld(resp.Body, resp.StatusCode())
		c.logger.Error("org push refused: this node is below the org's minimum agent version", "detail", msg)
		// A refused node is exactly the node that most needs an update, so
		// the update rail is armed HERE rather than only on the 200 path. The
		// server's 426 body carries the same update_versions nudge an
		// accepted push does (an additive, optional field), and the channel
		// is marked pending regardless so a server too old to send it still
		// lifts this node over the floor. Without this the one mechanism that
		// can fix the condition was gated behind the push the condition
		// refuses.
		c.noteUpdateNudge(resp.Body)
		c.markUpdateChannelPendingAfterRefusal(ctx)
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), int64(len(wire)), "failed", msg)
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: %w: %s", ErrAgentTooOld, msg)
	default:
		msg := serverError(resp.Body, resp.StatusCode())
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), int64(len(wire)), "retry", msg)
		// A typed error (not a bare fmt.Errorf string) so normalizeFailureKey
		// can key runLoop's dedup on the status code alone via errors.As —
		// msg is the server's response body, which routinely carries a
		// fresh request id or timestamp that would otherwise re-arm a WARN
		// every single retry.
		return PushResult{}, &httpStatusError{op: "orgclient.PushOnce", status: resp.StatusCode(), body: msg}
	}
}

// failureDeduper tracks whether the CURRENT failure in a retry loop is new
// or a repeat of the immediately-preceding one, so a wedged remote (a dead
// org server, a persistent 5xx, ...) logs ONE WARN naming the remedy
// instead of one WARN per retry forever. That was the actual 2026-09-07
// complaint: a dev box enrolled against a now-dead localhost:8443 org
// server logged 316 WARN lines in the first hour after every restart.
//
// Pure and stateful, no I/O of its own — see warnOnce for the logging
// policy built on top of it. A caller owns one failureDeduper PER
// independent failure stream it wants deduplicated (e.g. one for the
// generic push failure, a separate one for auth failures, since those
// already run on separate backoff tracks) and must call observe("") on
// every cycle that did NOT fail, so a later failure — even one identical
// to the last — is treated as fresh and re-WARNs (a recovery re-arms it).
type failureDeduper struct {
	// lastKind is normalizeFailureKey(err) for the most recent failure
	// this deduper has seen, or "" if the tracker is currently clear
	// (either nothing has failed yet, or the last observed cycle
	// succeeded). Deliberately NOT err.Error(): the raw message embeds
	// variable payload (a server-echoed request id, a decode error's
	// byte offset, an OS-specific syscall rendering) that would compare
	// unequal between two occurrences of the SAME class of failure and
	// re-arm a WARN every single cycle — the exact bug class this type
	// exists to prevent, just one level down.
	lastKind string
	// repeats counts consecutive identical failures, INCLUDING the
	// current one — so the first sighting of a kind reports 1, not 0.
	repeats int
	// lastWarnAt is when warnOnce last actually emitted a WARN (zero
	// until the first one). It backstops a normalization gap: a failure
	// whose key keeps changing every cycle (because normalizeFailureKey
	// hasn't learned to collapse whatever varies in it) must still
	// degrade to "at most one WARN every warnBackstopInterval", not fall
	// back to per-cycle spam.
	lastWarnAt time.Time
}

// observe records one cycle's outcome. kind == "" means the cycle did NOT
// fail (success, or not applicable) and always clears the tracker. A
// non-empty kind identical to the previous failing cycle's kind is a
// REPEAT; a changed kind, or the first failure after a clear/success, is
// NOT a repeat (it deserves a fresh WARN, subject to warnOnce's time
// backstop). Returns (isRepeat, repeats).
func (d *failureDeduper) observe(kind string) (isRepeat bool, repeats int) {
	if kind == "" {
		d.lastKind = ""
		d.repeats = 0
		return false, 0
	}
	if kind == d.lastKind {
		d.repeats++
		return true, d.repeats
	}
	d.lastKind = kind
	d.repeats = 1
	return false, 1
}

// warnBackstopInterval bounds how often warnOnce will emit a fresh WARN
// even when the dedup key changes every cycle. It exists for the case
// normalizeFailureKey does NOT fully solve: a class of failure whose
// message keeps mutating in a way the normalizer hasn't learned to
// collapse. Without this, that gap would regress all the way back to
// one WARN per retry — the original 316-lines-an-hour complaint — just
// gated on a subtler trigger. clockNow is swappable in tests.
const warnBackstopInterval = 10 * time.Minute

var clockNow = time.Now

// warnOnce logs err through d: the FIRST sighting of a given failure kind
// (by normalizeFailureKey(err), not the raw message — see failureDeduper's
// doc comment) — including a CHANGED kind, or the first failure after a
// recovery — logs at WARN with msg and args, UNLESS the previous WARN from
// this same deduper landed less than warnBackstopInterval ago, in which
// case it too logs at DEBUG (the time backstop). Every IDENTICAL repeat of
// the immediately-preceding failure logs at DEBUG instead, tagged with a
// running "repeat_count" so the operator can still tell how long it's been
// going without one line per cycle. Callers must clear d (d.observe(""))
// on a successful cycle so the next failure — even an identical one —
// gets a fresh WARN.
func warnOnce(logger *slog.Logger, d *failureDeduper, err error, msg string, args ...any) {
	isRepeat, repeats := d.observe(normalizeFailureKey(err))
	fields := append(append([]any{}, args...), "err", err)
	if isRepeat {
		logger.Debug(msg+" (repeat, suppressed to DEBUG — see the first WARN for the remedy)", append(fields, "repeat_count", repeats)...)
		return
	}
	now := clockNow()
	if !d.lastWarnAt.IsZero() && now.Sub(d.lastWarnAt) < warnBackstopInterval {
		logger.Debug(msg+" (dedup key changed but within the WARN backstop window — suppressed to DEBUG)", fields...)
		return
	}
	d.lastWarnAt = now
	logger.Warn(msg, fields...)
}

// httpStatusError carries an HTTP status code separately from the
// (often server-controlled, and frequently variable — a request id, a
// timestamp) response body text, so normalizeFailureKey can key on the
// STATUS alone via errors.As instead of the full rendered message, which
// would otherwise re-arm a WARN every cycle the server's error body
// varies even slightly.
type httpStatusError struct {
	op     string
	status int
	body   string
}

func (e *httpStatusError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("%s: server returned %d", e.op, e.status)
	}
	return fmt.Sprintf("%s: server returned %d: %s", e.op, e.status, e.body)
}

// longDigitRun matches a run of 4+ consecutive digits — long enough to
// catch a request id, a unix timestamp, or a byte offset, short enough to
// leave a 1-3 digit HTTP status code embedded in prose (e.g. "returned
// 503") untouched.
var longDigitRun = regexp.MustCompile(`\d{4,}`)

// maxFailureKeyMsgLen bounds the fallback message tier of
// normalizeFailureKey so an unusually long error string doesn't grow the
// dedup key without bound.
const maxFailureKeyMsgLen = 120

// normalizeFailureKey derives failureDeduper's comparison key from err,
// collapsing variable payload that would otherwise make two occurrences
// of the SAME class of failure compare as different and re-arm a WARN
// every cycle. Three tiers, most to least specific:
//
//  1. A *url.Error — the shape net/http.Client wraps every transport
//     failure in — keys on Op plus a coarse network-error CLASS via
//     errors.Is/errors.As (timeout vs connection-refused vs "other"),
//     never the message text, which can carry a resolved address or an
//     OS-specific syscall rendering that varies harmlessly between
//     attempts while the underlying class does not.
//  2. An *httpStatusError (see PushOnce) keys on the status code alone —
//     never the echoed response body, which is exactly the variable
//     payload this function exists to strip. A genuine status change
//     (500 → 503) DOES yield a different key: that is an
//     operator-meaningful change, not noise.
//  3. Anything else falls back to the first maxFailureKeyMsgLen bytes of
//     the message with digit runs of 4+ collapsed to a single '#' (see
//     longDigitRun) — long enough to catch a request id / unix
//     timestamp / byte offset, short enough to leave a short HTTP status
//     embedded in prose untouched.
func normalizeFailureKey(err error) string {
	if err == nil {
		return ""
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return "net:" + uerr.Op + ":" + classifyNetError(uerr.Err)
	}
	var serr *httpStatusError
	if errors.As(err, &serr) {
		return fmt.Sprintf("status:%d", serr.status)
	}
	msg := err.Error()
	if len(msg) > maxFailureKeyMsgLen {
		msg = msg[:maxFailureKeyMsgLen]
	}
	return "msg:" + longDigitRun.ReplaceAllString(msg, "#")
}

// classifyNetError buckets a *url.Error's wrapped cause into a coarse,
// stable class (timeout / connection-refused / connection-reset / other)
// via errors.Is/errors.As rather than string matching, so an OS-specific
// rendering of the same syscall never produces a different class.
func classifyNetError(err error) string {
	switch {
	case err == nil:
		return "unknown"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "conn-refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "conn-reset"
	case errors.Is(err, syscall.ETIMEDOUT):
		return "timeout"
	default:
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return "timeout"
		}
		return "other"
	}
}

// errIdle signals that a cycle did no work because the agent is not enrolled
// (or the enrolment row could not be read). The loop keeps its normal interval
// cadence rather than backing off — there is nothing failing, only nothing to
// do — so an enrol on a running daemon is picked up within one interval.
var errIdle = errors.New("orgclient: idle cycle")

// PushLoop runs the push cycle until ctx is cancelled (clean ctx-cancel
// returns ctx.Err); it does not otherwise return (P1, never break the host
// tool). Each cycle waits one interval, then re-reads the enrolment state AND
// its credentials, so an `observer enroll`/`unenroll`/rotation on a running
// daemon takes effect within one interval WITHOUT a restart — including
// recovery from a rejected credential (ErrAuthFailed is retryable, not
// terminal; see runLoop). Retryable failures shorten the next wait to the
// current backoff (exponential, jittered); a success resets the backoff.
func (c *Client) PushLoop(ctx context.Context) error {
	// One failureDeduper PER independent failure stream, scoped to this
	// single PushLoop call (a fresh set every time PushLoop is invoked,
	// same lifetime as the closure below) — the enrolment-read, routing-
	// policy, and announcement fetches ride PushLoop's cycle but are
	// logged directly here rather than through runLoop's own switch, so
	// runLoop's local dedupers (scoped to ITS invocation) can't cover
	// them.
	var enrolReadDeduper, routingDeduper, announcementDeduper failureDeduper
	// RUN THE FIRST CYCLE IMMEDIATELY (org-observer fundamentals finding H3b).
	// Every cycle carries the governance rails — routing, BUDGET, pricing,
	// announcements — and sleeping a full interval before the first one meant
	// a restarted daemon spent that interval with no answer from the org at
	// all. On a node whose budget is org-REQUIRED that window is either a
	// block or a bypass, depending only on what it had in memory; on every
	// other node it is simply a push interval of stale governance for no
	// reason. A pre-armed single-slot kick is the smallest expression of
	// "start now, then settle into the interval".
	kick := make(chan struct{}, 1)
	kick <- struct{}{}
	return c.runLoopKick(ctx, c.pushInterval(), kick, func(ctx context.Context) error {
		enr, err := c.store.LoadEnrolment(ctx)
		if err != nil {
			warnOnce(c.logger, &enrolReadDeduper, err, "org push: enrolment read failed")
			return errIdle
		}
		enrolReadDeduper.observe("")
		if enr == nil {
			return errIdle // not enrolled (yet, or unenrolled while running)
		}
		_, err = c.PushOnce(ctx)
		if errors.Is(err, ErrNotEnrolled) {
			return errIdle
		}
		// Oversized-batch circuit bookkeeping lives HERE, not in runLoop's
		// timing switch: runLoop is shared with the policy-poll loops, and a
		// poll succeeding while the push is parked must not close the push
		// circuit. This is the one owner of that state.
		switch {
		case errors.Is(err, ErrBatchTooLarge):
			c.noteOversizedBatch(ctx, err)
		case err == nil:
			if cerr := c.store.ClearPushBreaker(ctx); cerr != nil {
				c.logger.Warn("org push: could not clear the oversized-batch pause record", "err", cerr)
			}
		}
		// Best-effort §R19.1 policy sync rides the same cycle: a fetch
		// failure never affects push health (P1 — the policy cache
		// just stays at its last verified version).
		_, routingOutcome, perr := c.FetchRoutingPolicy(ctx)
		// Forward the TOTAL typed outcome (§2.5b) to the P0-6 reporter. A nil
		// outcome is a skip (context.Canceled — a shutdown, not a verdict); a
		// nil sink (the default) is today's exact no-op (R6-1).
		if routingOutcome != nil && c.routingOutcomeSink != nil {
			c.routingOutcomeSink(*routingOutcome)
		}
		switch {
		case perr != nil && !errors.Is(perr, ErrNotEnrolled):
			warnOnce(c.logger, &routingDeduper, perr,
				"org routing policy fetch failed — if this persists, check the org server, or run `observer unenroll` / set [org_client].enabled = false to stop trying")
		default:
			routingDeduper.observe("")
		}
		// The org BUDGET rail (org-budget plan §3.3c) rides the SAME cycle,
		// for the same reason as routing above: no new timer, no new host, no
		// new connection. It is a conditional GET (If-None-Match over the
		// document digest, not the version — a team-membership change moves a
		// cap without moving the version), so the steady state is a 304. Every
		// failure is FAIL-OPEN: the sink is poked with the typed state and the
		// guard keeps the node's own [guard.budget] numbers.
		budgetOutcome, berr := c.FetchBudgetPolicy(ctx)
		// The cadence this loop is actually ticking at rides with every
		// outcome (bundle BUD-N): the composition boundary derives the
		// cross-machine baseline's staleness window from it, and the loop is
		// the one place that resolves it.
		budgetOutcome.PushInterval = c.pushInterval()
		if c.budgetSink != nil && !errors.Is(berr, context.Canceled) {
			c.budgetSink(budgetOutcome)
		}
		if berr != nil && !errors.Is(berr, ErrNotEnrolled) && !errors.Is(berr, context.Canceled) {
			c.logger.Warn("org budget policy fetch failed", "state", budgetOutcome.State, "err", berr)
		}
		// The org PRICING rail (enterprise-pricing plan §3.3) rides the SAME
		// cycle, immediately after the budget rail and for the same reasons:
		// no new timer, no new host, no new connection, and a conditional GET
		// whose steady state is a 304.
		//
		// It is polled BESIDE the budget rather than on its own schedule
		// because the two are one governance fact: a cap and the rate it is
		// measured in. A node that refreshed one without the other would spend
		// the gap enforcing this quarter's cap against last quarter's prices.
		// Ruling R2 gates both on the same [guard.budget].from_org switch, and
		// a disabled rail makes no request at all.
		//
		// The SINK is notified by FetchPricingPolicy itself, not here — the
		// one place this rail's wiring diverges from the budget rail's, and
		// deliberately. The pricing sink must also fire on the COLD-START
		// path (LoadPersistedPricing, minutes before the first poll), and a
		// loop that owned the notification would leave that path silently
		// un-notified: the engine would hold the persisted rates while the
		// posture said nothing had been applied.
		pricingOutcome, prerr := c.FetchPricingPolicy(ctx)
		if prerr != nil && !errors.Is(prerr, ErrNotEnrolled) && !errors.Is(prerr, context.Canceled) {
			c.logger.Warn("org pricing policy fetch failed", "state", pricingOutcome.State, "err", prerr)
		}
		// The org-served Cloud Intelligence RESULT rail (org-served-cloud-
		// intelligence plan §2.4, W3) rides the SAME cycle for the same reason:
		// no new timer, no new host, no new connection. It is a PULL (the org's
		// derived results coming back), gated internally by
		// [intelligence].org_enrichment — a node that has not opted in makes no
		// request at all, so this call is inert on every individual/unopted
		// node. Every failure is FAIL-OPEN: the node keeps its cached results.
		intelOutcome, ierr := c.FetchIntelResults(ctx)
		if ierr != nil && !errors.Is(ierr, ErrNotEnrolled) && !errors.Is(ierr, context.Canceled) {
			c.logger.Warn("org intelligence results fetch failed", "state", intelOutcome.State, "err", ierr)
		}
		// Rail R3 of the dashboard-announcements plan (§4) rides the
		// SAME cycle for the same reason: no new timer, no new host, no
		// new connection — and a fetch failure never affects push
		// health (P1), it just leaves the banner at its last verified
		// version.
		_, aerr := c.FetchOrgAnnouncement(ctx)
		switch {
		case aerr != nil && !errors.Is(aerr, ErrNotEnrolled):
			warnOnce(c.logger, &announcementDeduper, aerr,
				"org announcement fetch failed — if this persists, check the org server, or run `observer unenroll` / set [org_client].enabled = false to stop trying")
		default:
			announcementDeduper.observe("")
		}
		// Arc 4 P6b managed-integrity probe rides the SAME cycle (plan §9,
		// announce.go discipline: no new timer/host/connection). MANAGED nodes
		// only — an individual node never computes a fingerprint or a signal, so
		// the individual plane is untouched by construction. A report failure
		// never affects push health (P1).
		// Enterprise Update Management (§3.5) rides the SAME cycle, for the
		// same reason as rail R3 above: no new timer, no new host, no new
		// connection. It fetches ONLY the channels the push acknowledgment
		// just said the server is ahead on, so a fleet with nothing published
		// makes no extra request at all. A fetch failure never affects push
		// health — it leaves the update card at its last verified manifest.
		c.FetchPendingUpdateManifests(ctx)
		if c.integrityCollector != nil && enr.IsManaged() {
			report := c.integrityCollector()
			if _, ierr := c.ReportIntegrity(ctx, report); ierr != nil &&
				!errors.Is(ierr, ErrNotEnrolled) && !errors.Is(ierr, ErrManagedIntegrityUnbound) {
				c.logger.Warn("org managed-integrity report failed", "err", ierr)
			}
		}
		return err
	})
}

// noteOversizedBatch is the ONE owner of the ErrBatchTooLarge circuit state. It
// does the two things a silent park does not: it says out loud, at Error level,
// that org telemetry has STOPPED and for how long, and it persists the pause so
// the dashboard and `observer org push-status` — which run in other processes —
// can show it instead of the operator having to read org_push_log by hand.
//
// Persisting is best-effort: failing to write the record must never escalate a
// parked push into a broken daemon (P1).
func (c *Client) noteOversizedBatch(ctx context.Context, err error) {
	until := time.Now().UTC().Add(oversizedBatchBackoff)
	c.logger.Error("org push PAUSED — the composed rollup is larger than the accepted push limit, "+
		"so NOTHING is reaching the org server until this clears",
		"err", err,
		"paused_for", oversizedBatchBackoff.String(),
		"resumes_at", until.Format(time.RFC3339),
		"what_to_check", "raise [org_client].max_push_bytes, narrow [org_client.scope] to fewer "+
			"projects, or turn off a large [org_client.share] tier — the org server also enforces "+
			"its own body limit, so a node-side raise alone may not be enough")
	if serr := c.store.OpenPushBreaker(ctx, until, err.Error()); serr != nil {
		c.logger.Warn("org push: could not record the oversized-batch pause for the dashboard", "err", serr)
	}
}

// SetIntegrityCollector installs the Arc 4 P6b managed-integrity evidence
// collector (plan §9). It must be called before PushLoop starts. The collector
// is consulted only inside PushLoop and only for a managed node; see the
// integrityCollector field comment.
func (c *Client) SetIntegrityCollector(fn func() orgcontract.ManagedIntegrityReport) {
	c.integrityCollector = fn
}

// runLoop is the timing core of PushLoop, parameterised on the per-cycle
// action so the backoff/interval/stop behaviour can be tested with a pure
// scripted action under testing/synctest (no real I/O). The action's return
// drives the next wait: nil (success) → interval + backoff reset; errIdle →
// interval (no backoff); ErrAuthFailed → capped-backoff retry on a dedicated
// track (never terminal — self-heals on a re-enrol/rotation without a restart);
// any other error → jittered exponential backoff.
//
// The generic-failure and auth-failure branches each dedup their own WARN
// through a failureDeduper SCOPED TO THIS runLoop CALL (declared as local
// variables below, same lifetime as backoff/authBackoff) — see
// failureDeduper's doc comment. runLoop is shared by every org poll loop
// (push, guard policy poll, policy-resource poll), so this benefits all of
// them: a wedged remote no longer produces one WARN per retry forever,
// only one WARN then DEBUG-with-counter until the error changes or a
// cycle succeeds.
func (c *Client) runLoop(ctx context.Context, interval time.Duration, action func(context.Context) error) error {
	return c.runLoopKick(ctx, interval, nil, action)
}

// runLoopKick is runLoop with an optional wake channel: a receive on kick
// runs the next cycle immediately (the 2026-09-01 policy-propagation nudge).
// A nil kick blocks forever in the select, making this byte-identical to the
// plain loop — every existing caller passes nil via runLoop.
func (c *Client) runLoopKick(ctx context.Context, interval time.Duration, kick <-chan struct{}, action func(context.Context) error) error {
	backoff := initialBackoff
	authBackoff := initialBackoff
	sleep := interval
	var failDeduper, authFailDeduper failureDeduper
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		case <-kick:
		}

		err := action(ctx)
		switch {
		case errors.Is(err, context.Canceled):
			return ctx.Err()
		case errors.Is(err, errIdle):
			sleep = interval
		case errors.Is(err, ErrAuthFailed):
			// A rejected credential is RETRYABLE, not terminal. Each cycle
			// re-reads the bearer + signing key from the store, so a re-enrol or
			// key rotation writes fresh credentials that the next cycle loads and
			// recovers from WITHOUT a process restart — the proxy/data plane is
			// never bounced. Back off on a dedicated, higher-capped track so a
			// genuinely-revoked node settles to a slow cadence instead of
			// spamming, while a prompt re-enrol still recovers within the first
			// (fast) retries.
			warnOnce(c.logger, &authFailDeduper, err,
				"org push: authentication failed, retrying (re-enrol or rotate to recover)",
				"backoff", authBackoff.String())
			sleep = jitter(authBackoff)
			authBackoff = nextBackoffCapped(authBackoff, authFailMaxBackoff)
		case errors.Is(err, ErrBatchTooLarge):
			// Deliberately silent: PushLoop's own handler (noteOversizedBatch)
			// already logged the operator-facing explanation on this same cycle
			// AND persisted the pause for the dashboard / CLI. Logging again
			// here would double-report it with strictly less detail.
			sleep = oversizedBatchBackoff
		case err != nil:
			warnOnce(c.logger, &failDeduper, err,
				"org push failed, backing off — if the org server stays unreachable, fix it, run `observer unenroll`, or set [org_client].enabled = false to stop retrying",
				"backoff", backoff.String())
			sleep = jitter(backoff)
			backoff = nextBackoff(backoff)
		default:
			sleep = interval
			backoff = initialBackoff
			authBackoff = initialBackoff
			// A successful cycle is a recovery: re-arm both trackers so a
			// LATER failure — even one identical to whatever failed before
			// — gets a fresh WARN instead of being mistaken for the same
			// ongoing outage.
			failDeduper.observe("")
			authFailDeduper.observe("")
		}
	}
}

// genClient builds a generated API client bound to server, reusing the
// configured HTTP doer.
func (c *Client) genClient(server string) (*gen.ClientWithResponses, error) {
	return gen.NewClientWithResponses(server, gen.WithHTTPClient(c.httpClient))
}

// snapshotInterval resolves [org_client] snapshot_interval_seconds: the
// shortest gap between two recomputes of the same SNAPSHOT wire family. Unset
// (0) resolves to DefaultSnapshotIntervalMultiple × the EFFECTIVE push interval
// — computed here rather than stored as an absolute so a node that retunes
// push_interval_seconds keeps the same ratio. A negative value disables the
// throttle (every changed family recomputes on every tick).
func (c *Client) snapshotInterval() time.Duration {
	secs := c.cfg.SnapshotIntervalSeconds
	if secs < 0 {
		return 0
	}
	if secs == 0 {
		return time.Duration(config.DefaultSnapshotIntervalMultiple) * c.pushInterval()
	}
	return time.Duration(secs) * time.Second
}

func (c *Client) pushInterval() time.Duration {
	secs := c.cfg.PushIntervalSeconds
	if secs <= 0 {
		secs = config.DefaultPushIntervalSeconds
	}
	return time.Duration(secs) * time.Second
}

// maxPushBytes returns the configured uncompressed batch ceiling, defaulted and
// clamped to the contract bounds.
func (c *Client) maxPushBytes() int64 {
	mb := c.cfg.MaxPushBytes
	if mb <= 0 {
		mb = config.DefaultMaxPushBytes
	}
	if mb > config.MaxPushBytesCeiling {
		mb = config.MaxPushBytesCeiling
	}
	return mb
}

func validatePushBodySize(raw []byte, maxBytes int64) error {
	if maxBytes <= 0 {
		return nil
	}
	if int64(len(raw)) > maxBytes {
		return fmt.Errorf("%w: serialized_bytes=%d limit_bytes=%d", ErrBatchTooLarge, len(raw), maxBytes)
	}
	return nil
}

// --- helpers ---------------------------------------------------------------

// agentKeyFingerprintEditor advertises this agent's own public-key fingerprint
// so the SERVER can tell "your signature is corrupt" from "you are signing with
// a key this member no longer has bound" and name the difference in its 401.
//
// It carries no authority: the server uses it only to sharpen a rejection
// reason, never to grant anything (the Ed25519 signature remains the sole
// authenticator). A server that predates the header ignores it, which is why
// this is a plain RequestEditorFn rather than a generated parameter — the
// OpenAPI contract is unchanged and no client/server regeneration is implied.
func agentKeyFingerprintEditor(fingerprint string) gen.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		if fingerprint != "" {
			req.Header.Set(orgcontract.HeaderAgentKeyFingerprint, fingerprint)
		}
		return nil
	}
}

// grantReplacementAckEditor reports (via HeaderGrantReplacementAck) the highest
// grant-replacement generation this node has adopted, so the server's fleet-ACK
// gate learns the node is converged. Like the fingerprint editor it is a plain
// header on an already-authenticated push (no OpenAPI change); the header can
// only report the node's own adoption and never widens access.
func grantReplacementAckEditor(generation int64) gen.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		req.Header.Set(orgcontract.HeaderGrantReplacementAck, strconv.FormatInt(generation, 10))
		return nil
	}
}

// authFailure is the ADDITIVE discriminator half of a 401/403 body. Both fields
// are absent from a v1.8-class server's response, so every consumer must treat
// the zero value as "the server did not say".
type authFailure struct {
	Reason              string `json:"reason"`
	BoundKeyFingerprint string `json:"bound_key_fingerprint"`
}

// parseAuthFailure extracts the discriminator from an error body. A body that
// carries none (an older server, or a proxy's own error page) yields the zero
// value rather than an error: this is diagnosis, and failing to diagnose must
// never change the outcome of the push.
func parseAuthFailure(body []byte) authFailure {
	var f authFailure
	if err := json.Unmarshal(body, &f); err != nil {
		return authFailure{}
	}
	return f
}

// reportAuthFailure logs WHY a push was rejected and returns the message string
// recorded against the push (and shown by `observer org status`).
//
// Before this, a stranded node reported only "unauthorized: invalid per-push
// signature" — indistinguishable from a clock skew, a revoked bearer, or the
// key-binding collision that actually caused the 2026-08-26/27 incident, where
// a second machine enrolling under the same org member silently took over the
// binding and left this node 401ing forever.
//
// Two sources are combined. The server's `reason` is authoritative when
// present. Independently, comparing our own key fingerprint against the
// `bound_key_fingerprint` the server reports proves a binding conflict LOCALLY
// — which is what lets a current agent diagnose the collision even against a
// server too old to name it.
func (c *Client) reportAuthFailure(body []byte, status int, localFP, orgURL string) string {
	msg := serverError(body, status)
	f := parseAuthFailure(body)

	reason := f.Reason
	// The local proof outranks a server that could only say "the signature did
	// not verify": if the server holds a DIFFERENT key than ours, the cause is
	// not a bad signature, it is a displaced binding.
	if f.BoundKeyFingerprint != "" && localFP != "" && f.BoundKeyFingerprint != localFP &&
		(reason == "" || reason == orgcontract.AuthReasonSignatureMismatch) {
		reason = orgcontract.AuthReasonBindingConflict
	}

	attrs := []any{
		"status", status,
		"detail", msg,
		"org_server", orgURL,
		"local_key_fingerprint", localFP,
	}
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	if f.BoundKeyFingerprint != "" {
		attrs = append(attrs, "server_bound_key_fingerprint", f.BoundKeyFingerprint)
	}
	if remedy := authFailureRemedy(reason); remedy != "" {
		attrs = append(attrs, "remedy", remedy)
	}
	c.logger.Warn("org push rejected", attrs...)

	if reason != "" {
		// Fold the reason into the RECORDED message too: `observer org status`
		// and the dashboard read this string, and they are where an operator
		// looks before they ever see a daemon log.
		return reason + ": " + msg
	}
	return msg
}

// authFailureRemedy maps a reason to the one action that resolves it. A table,
// not a conditional ladder (CLAUDE.md #5); an unknown reason yields "" so a
// future server-side reason never produces confidently wrong advice.
func authFailureRemedy(reason string) string {
	switch reason {
	case orgcontract.AuthReasonBindingConflict:
		return "another machine enrolled under this org member and took the key binding; re-enrol this node, or give each machine its own member"
	case orgcontract.AuthReasonUnknownKey:
		return "no agent key is bound for this member; re-enrol this node"
	case orgcontract.AuthReasonTimestampSkew:
		return "this host's clock is outside the server's allowed skew; sync time"
	case orgcontract.AuthReasonMissingSignature, orgcontract.AuthReasonMalformedSignature:
		return "the per-push signature headers did not reach the server intact; check for an intermediate proxy stripping X-SBO-* headers"
	case orgcontract.AuthReasonSignatureMismatch:
		return "the signature did not verify against the bound key; re-enrol this node if it persists"
	default:
		return ""
	}
}

// bearerEditor sets the Authorization header on the outgoing push request.
func bearerEditor(bearer string) gen.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+bearer)
		return nil
	}
}

// gzipEncodingEditor declares the body's content coding so the server reads it
// through a gzip reader. The body bytes (and thus the signature) are the gzip
// bytes — Content-Encoding describes them, it does not transform them.
func gzipEncodingEditor(_ context.Context, req *http.Request) error {
	req.Header.Set("Content-Encoding", "gzip")
	return nil
}

// gzipBytes gzip-compresses raw, returning the wire bytes.
func gzipBytes(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// maxCursor flattens the per-table push cursor to a single representative
// scalar (the highest id across the four tables) for the envelope's
// cursor_from/cursor_to. The authoritative cursor is per-table and persisted
// locally; this scalar is a server-side progress hint only.
func maxCursor(c store.PushCursor) int64 {
	m := c.Sessions
	for _, v := range []int64{c.Actions, c.APITurns, c.TokenUsage, c.GuardEvents, c.OTelContent} {
		if v > m {
			m = v
		}
	}
	return m
}

// nextBackoff doubles d, capped at maxBackoff.
func nextBackoff(d time.Duration) time.Duration {
	return nextBackoffCapped(d, maxBackoff)
}

// nextBackoffCapped doubles d, capped at ceiling. It backs the two runLoop
// backoff tracks: retryable errors climb to maxBackoff, rejected credentials
// (ErrAuthFailed) climb to the slower authFailMaxBackoff.
func nextBackoffCapped(d, ceiling time.Duration) time.Duration {
	d *= backoffFactor
	if d > ceiling {
		d = ceiling
	}
	return d
}

// jitter applies ±jitterFraction uniform jitter to d.
func jitter(d time.Duration) time.Duration {
	delta := (mrand.Float64()*2 - 1) * jitterFraction //nolint:gosec // G404: backoff jitter is not security-sensitive; math/rand is the right tool.
	j := time.Duration(float64(d) * (1 + delta))
	if j < 0 {
		j = 0
	}
	return j
}

// serverError renders a concise error string from a JSON error body, falling
// back to the status code when the body is empty/unparseable.
func serverError(body []byte, status int) string {
	var e struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		if e.Message != "" {
			return e.Error + ": " + e.Message
		}
		return e.Error
	}
	if s := strings.TrimSpace(string(body)); s != "" {
		return s
	}
	return http.StatusText(status)
}

func strPtr(s string) *string { return &s }
