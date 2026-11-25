package orgclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"log/slog"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern/sidecar"
	"github.com/marmutapp/superbased-observer/internal/integration"
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
var ErrMemberNotActive = errors.New("orgclient: organization account not active yet")

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
	// reconsent is the latest push's re-consent advisory reason
	// (reconsent.go), a string; "" or unset for none.
	reconsent atomic.Value
	// bg owns the node-side break-glass lease state (breakglass.go).
	bg breakGlassState
	// pushCeiling is the live org push-interval ceiling (resolved signed
	// node-governance pin; 0 = none). nil = the configured interval alone.
	// pushLocal is the node's own pre-governance interval it composes with.
	pushCeiling func() int64
	pushLocal   int64
	// drainRetryDelay is DrainPending's pause before retrying a transient
	// failure (drain.go); zero = defaultDrainRetryDelay. Tests shorten it.
	drainRetryDelay time.Duration
	// messages is the admin messaging rail's state (orgmessages.go).
	messages orgMessagesState
	// Per-rail 404 backoff (railbackoff.go): rails whose 404 means "none
	// published / not offered" are re-asked on a doubling interval.
	routingNotFound, announcementNotFound, intelNotFound notFoundBackoff
	cfg                                                  config.OrgClientConfig
	store                                                *store.Store
	bearers                                              BearerStore
	// agentAccessKeys is the per-device agent-access key slot (P1); nil
	// until cmd/observer wires it (SetAgentAccessKeyStore), in which case no
	// SourceNodeKey is derived and the envelope stays pre-P4-shaped.
	agentAccessKeys AgentAccessKeyStore
	// machineKeys is the machine key slot (T-656, machinekey.go); nil until
	// cmd/observer wires it (SetMachineKeyStore), in which case no machine
	// proof is sent, exactly like a released node.
	machineKeys     MachineKeyStore
	machineKeyState machineKeyState
	// machineProofSink receives each change of the machine-proof outcome
	// (SetMachineProofSink); nil keeps it in memory only.
	machineProofSink func(MachineProofState)
	// noticeDir is the observer dir whose notices/ markers make a routine
	// warning print once per install and state (notice_once.go); "" keeps
	// the per-process behaviour.
	noticeDir string
	// credentialState is this process's last view of its own org
	// credential and credentialSink receives each change (credential.go).
	credentialState credentialView
	credentialSink  func(CredentialState)
	httpClient      *http.Client
	logger          *slog.Logger
	agentVersion    string

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
	// exact no-op. Set via SetIntegrityCollector. Since T-849 it is also
	// consulted on the daemon's policy-state heartbeat through
	// ReportManagedIntegrity, the one owner of "probe and report";
	// integrityMu serializes the two cadences.
	integrityCollector func() orgcontract.ManagedIntegrityReport
	integrityMu        sync.Mutex
	// switchedBound and managedHereAfter are guarded by integrityMu: a node
	// managed by its org's switch binds its machine once per process, and
	// a 403 from the managed routes silences both until managedHereAfter.
	switchedBound    bool
	managedHereAfter time.Time

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
	// policyBundleKick wakes PolicyPollLoop (the guard bundle) when the
	// policy-freshness probe reports the bundle rail moved (P2).
	policyBundleKick chan struct{}
	// freshActivity carries node activity into the policy-freshness checker
	// (P2, policyfreshness.go). Buffered(1) + non-blocking sends: bursts
	// coalesce.
	freshActivity chan struct{}
	// freshDispatch wakes the checker to fetch rails a push ack reported
	// moved that the push cycle does not refresh itself (policyfreshness.go
	// recordRailVersions).
	freshDispatch chan struct{}
	// pushActivity carries "new pushable rows committed" into PushLoop's
	// scheduler (P3, pushloop.go). Buffered(1) + non-blocking sends.
	pushActivity chan struct{}
	// pushWake is an operator's explicit "push now" (WakePushLoop): unlike
	// pushActivity it runs a cycle at once, past a failure pause.
	pushWake chan struct{}
	// serverPushMin is the org's X-SBO-Push-Min-Interval hint from the last
	// accepted push, as a time.Duration (0 = none).
	serverPushMin atomic.Int64
	// cycleRails is true while a push cycle that refreshes the
	// pushCycleRails is running, so its own ack does not re-queue them.
	cycleRails atomic.Bool
	// fresh is the policy-freshness checker's state (policyfreshness.go).
	fresh freshState
	// railsMu serialises the rail fetches the push loop and the freshness
	// checker can both trigger, so one rail is never fetched twice
	// concurrently.
	railsMu sync.Mutex

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
	// binary, which a restart does not change. In a build without the
	// org.update component (-tags sbo_omit_org_update) it is an empty struct
	// (update_omitted.go) and the rail does nothing.
	updates updateCache

	// tooOld is the last 426 min-version refusal the push rail received
	// (agenttooold.go). It is core, not part of the update rail: a node built
	// without self-update can still be refused by the org's version floor and
	// must still say so.
	tooOld agentTooOldState

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

	// scopeProvider resolves the project scope PushOnce selects under
	// (control-coverage audit CG-13): the node's [org_client.scope] lists,
	// raised by a managed node's org (govern.RaiseScope*), plus whether the
	// org governs scope (guard verdicts then ship whatever the lists say).
	// Nil means the cfg lists, as before. Settle is always the client's own.
	scopeProvider func() store.ScopeOptions

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

	// guardBundleCachePath is the org guard bundle file ([guard.rules]
	// org_bundle), removed by Enroll when a re-enrolment changes the org or the
	// member: the bundle is signed for one member (binding v2), and a bound
	// bundle left behind would make the next org's unbound bundles refused as
	// a downgrade. Empty = nothing to remove.
	guardBundleCachePath string

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
	// managedPullNow is the managed-pull kit's clock (managedpull.go); nil
	// means time.Now. A seam so a test can expire a document.
	managedPullNow func() time.Time
	// managedPullRails is the managed-pull kit's rail registration, polled
	// by pollManagedPullRails beside refreshBudgetRails (managedpull_poll.go).
	managedPullRails managedPullRailSet

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
	// displayPolicySink is called after a NEW display-policy version was
	// verified and cached, so the daemon's developer surfaces that render
	// from a precomputed file (the budget-warning messages) re-render in the
	// new display without waiting for their idle tick. Nil-defaulted
	// additive seam; set via SetDisplayPolicySink.
	displayPolicySink func()
	// accessGrantSink is called after a NEW access-grants version was
	// verified and cached (accessgrants.go). Nil-safe.
	accessGrantSink func()
	// agentConfigGate keeps the org AI tool policy rail OFF unless this node
	// is managed with a live grant (agentconfigpolicy.go); agentConfigSink
	// runs after a NEW version was cached. Both nil-defaulted additive seams.
	agentConfigGate func(ctx context.Context) bool
	agentConfigSink func()

	// intelEnabled is the org-served-cloud-intelligence RESULT-pull gate
	// ([intelligence].org_enrichment, org-served-cloud-intelligence plan
	// §2.1/§2.4, W3). Nil = the rail is OFF and FetchIntelResults makes no
	// request at all (the opt-in default). A func rather than a bool so a
	// config reload / managed raise (W5) can turn it on without a restart.
	// Set via SetIntelRail.
	intelEnabled func() bool
	// intelConsentSource resolves the node's current Cloud Intelligence
	// consent posture for the consent report rail (intelconsent.go); nil
	// disables reporting. intelConsentReported is the dedup key of the last
	// report the server accepted (loop-owned, like intelSince).
	intelConsentSource   func(ctx context.Context) (orgcontract.IntelConsentReport, bool)
	intelConsentReported string
	// intelSubmitSource queues the background org-plane submissions each
	// cycle (Cloud Intelligence parity phase 2; nil = no background sweep).
	intelSubmitSource func(ctx context.Context) error
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
	// intelTombstoneApplied is the body hash of the last purge-tombstone set
	// this daemon verified and applied in full, so an unchanged set is not
	// re-applied every cycle. LOOP-OWNED like intelSince; NOT persisted (a
	// restart re-applies the set once, which is idempotent).
	intelTombstoneApplied string
}

// SetShareProvider installs the hot share-posture resolver (§2.4). Passing
// nil restores the cfg-derived default.
func (c *Client) SetShareProvider(fn func() store.ShareOptions) {
	if c == nil {
		return
	}
	c.shareProvider = fn
}

// SetScopeProvider installs the hot scope resolver (CG-13). Passing nil
// restores the cfg-derived lists.
func (c *Client) SetScopeProvider(fn func() store.ScopeOptions) {
	if c == nil {
		return
	}
	c.scopeProvider = fn
}

// scopeOptions resolves the project scope for one push: the provider's
// answer, or the cfg lists, with the client's own settle holdback.
func (c *Client) scopeOptions() store.ScopeOptions {
	out := store.ScopeOptions{
		ProjectRootAllowlist: c.cfg.Scope.ProjectRootAllowlist,
		ProjectRootDenylist:  c.cfg.Scope.ProjectRootDenylist,
	}
	if c.scopeProvider != nil {
		out = c.scopeProvider()
	}
	// S10-SPEED: hold a transcript-timed token row back until its
	// generation duration is stamped (or the window elapses).
	out.Settle = store.PushSettle{
		Tools:  integration.TranscriptTimedTools(),
		Window: store.DefaultPushSettleWindow,
	}
	return out
}

// SetGuardBundleCachePath tells Enroll which org guard bundle file to remove
// when a re-enrolment changes the org or the member (T-393). Safe to leave
// unset: the next accepted bundle fetch overwrites the file.
func (c *Client) SetGuardBundleCachePath(path string) {
	if c == nil {
		return
	}
	c.guardBundleCachePath = path
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
		c.logger.Warn("unenroll: could not remove the node.features sidecar - a stale tools.disallow list may briefly gate one-shot launchers until it is overwritten or expires",
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
		HookActivity:          cfg.Share.HookActivity,
		MCPActivity:           cfg.Share.MCPActivity,
		Security:              cfg.Share.Security,
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
		c.logger.Warn("unenroll: could not remove the governance sidecar - pinned settings will lift at the next hook once the grant's own expiry passes",
			"path", c.governanceSidecarPath, "err", err)
	}
	// Its feature-access exceptions file goes with it (request-grants G8).
	// Left behind it would lift nothing (it is bound to the removed
	// sidecar's posture), so this is tidiness, not a guarantee.
	if ex := sidecar.ExceptionsPath(c.governanceSidecarPath); ex != "" {
		if err := os.Remove(ex); err != nil && !os.IsNotExist(err) {
			c.logger.Warn("unenroll: could not remove the feature-access exceptions file", "path", ex, "err", err)
		}
	}
}

// clearPolicyResourceCacheTree removes <cacheDir>/<orgKey>/ best-effort.
func (c *Client) clearPolicyResourceCacheTree(orgKey string) {
	if c == nil || c.policyResourceCacheDir == "" || orgKey == "" {
		return
	}
	_ = os.RemoveAll(filepath.Join(c.policyResourceCacheDir, orgKey))
}

// New constructs a push Client. httpClient may be nil (the default is the org
// transport of transport.go: a 30 s request bound plus dead-connection
// detection, so a connection the network forgot during an outage is dropped
// within about 45 s, T-899); logger may be nil (slog.Default). agentVersion
// is stamped into each push envelope for server-side diagnostics.
func New(cfg config.OrgClientConfig, st *store.Store, bearers BearerStore, agentVersion string, httpClient *http.Client, logger *slog.Logger) *Client {
	if httpClient == nil {
		httpClient = newOrgHTTPClient(defaultConnHealth, nil)
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
		policyBundleKick:   make(chan struct{}, 1),
		freshActivity:      make(chan struct{}, 1),
		freshDispatch:      make(chan struct{}, 1),
		pushActivity:       make(chan struct{}, 1),
		pushWake:           make(chan struct{}, 1),
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
// plain loop: every existing caller passes nil via runLoop. While the last
// cycle failed on the retryable ladder the kick is held until the backoff
// elapses (it stays queued and coalesced, so the wake is not lost): a kick
// shortens an idle wait, never a failure backoff (D-704).
func (c *Client) runLoopKick(ctx context.Context, interval time.Duration, kick <-chan struct{}, action func(context.Context) error) error {
	return c.runLoopKickFn(ctx, func() time.Duration { return interval }, kick, action)
}

// runLoopKickFn is runLoopKick with the interval re-read after every cycle,
// so a live change (the push loop's governance ceiling) takes effect on the
// next wait without restarting the loop.
func (c *Client) runLoopKickFn(ctx context.Context, intervalFn func() time.Duration, kick <-chan struct{}, action func(context.Context) error) error {
	retry := newLoopRetry()
	sleep := intervalFn()
	for {
		wake := kick
		if retry.backingOff {
			wake = nil // a nil channel never fires: the kick waits out the backoff
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		case <-wake:
		}
		err := action(ctx)
		var stop bool
		sleep, stop, _ = retry.after(c, err, intervalFn())
		if stop {
			return ctx.Err()
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

// pushInterval is the push CEILING: the longest the loop waits between two
// cycles when nothing kicks it. It is the node's own
// [org_client].push_interval_seconds (default 120 s), lowered LIVE by the
// org's signed node-governance ceiling when one is in force
// (org_client.push_interval_seconds, a hot lowering-only pin) through the
// same config.GovernanceLowerInt the restart-time overlay uses — so the
// value a restarted daemon reads and the value a running one applies can
// never disagree.
func (c *Client) pushInterval() time.Duration {
	secs := int64(c.cfg.PushIntervalSeconds)
	if c.pushCeiling != nil {
		// Compose against the node's OWN (pre-governance) value, never the
		// overlaid one the config carried at startup: composing against the
		// overlaid value would ratchet, so an org that RAISED its ceiling
		// (60 -> 300) would leave a running node at 60 until a restart.
		secs = c.pushLocal
	}
	if secs <= 0 {
		secs = config.DefaultPushIntervalSeconds
	}
	if c.pushCeiling != nil {
		secs = config.GovernanceLowerInt(secs, c.pushCeiling())
	}
	return time.Duration(secs) * time.Second
}

// SetPushIntervalGovernance installs the live org push-interval ceiling
// (the resolved node-governance pin; the reader returns 0 when none is in
// force) together with the node's own pre-governance interval it composes
// against (0 = the default). It must be called before PushLoop starts; a nil
// reader restores the configured interval alone.
func (c *Client) SetPushIntervalGovernance(local int64, ceiling func() int64) {
	c.pushLocal = local
	c.pushCeiling = ceiling
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

func strPtr(s string) *string { return &s }
