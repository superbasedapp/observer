package orgclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient/gen"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Org policy-bundle channel, agent side (guard spec §14.2, G13). The
// agent polls GET /api/v1/policy-bundle on `observer start` and every
// [org_client].policy_poll_interval_seconds, verifies the envelope
// against the §14.2 acceptance gate, and on success atomically
// replaces the local bundle cache ([guard.rules].org_bundle) that the
// guard's org layer loads from. The channel DISTRIBUTES policy
// (server → agent) — nothing flows back, and nothing here touches the
// push pipeline's privacy seam.
//
// Acceptance gate, in order (a failed step REJECTS the fetch and the
// previous cache stays in place):
//
//  1. Ed25519 signature over the canonical message verifies against
//     the envelope's embedded key (orgcontract.VerifyPolicyBundle).
//  2. The embedded key's hash matches the pin recorded at enrolment
//     in guard_policy_state ("#policy-key" row). Missing pin =
//     trust-on-first-fetch: the key is pinned NOW (pre-G13 enrolments
//     have no enrol-time pin; the TLS+bearer channel anchoring this
//     first fetch is the same trust that anchored enrolment itself).
//  3. The bundle version is not lower than the last verified version
//     (downgrade protection — rollback is publishing old content as a
//     NEW version).
//  4. The TOML passes the CONSUMER check for an org-layer policy file
//     (guard.AcceptOrgBundleTOML, with the escalate-only floor
//     checks), so a malformed or floor-violating bundle never evicts a
//     good cache. Keys this binary does not understand are NOT fatal
//     here — they are logged and the bundle is accepted, because the
//     server may be newer than the node (GUARD-FWD-1); the publish
//     gate is the strict one.
//
// A rejection is a RESULT, not an error: the caller (cmd layer) turns
// PolicyRejected into an R-205 guard event; transport failures return
// errors and ride the poll loop's backoff.

// PolicyKeyPinSuffix tags the guard_policy_state row that pins the org
// policy public key: Path = <org-server-url> + PolicyKeyPinSuffix,
// ContentHash = orgcontract.PublicKeyPinHash of the raw key bytes.
// guard_policy_state is the pin home per §14.2 — append-only, so key
// rotation history stays auditable; re-enrolment appends the new pin.
const PolicyKeyPinSuffix = "#policy-key"

// PolicyKeyPinPath returns the guard_policy_state path identity of the
// key-pin row for an org server.
func PolicyKeyPinPath(orgURL string) string { return orgURL + PolicyKeyPinSuffix }

// policyBundleStatePath returns the guard_policy_state path identity
// of the fetched-bundle row (one row per verified version, distinct
// from the load-time row guard records against the cache file path).
func policyBundleStatePath(orgURL string) string { return orgURL + policyBundleStateSuffix }

// policyBundleStateSuffix ends every fetched-bundle row's path identity.
const policyBundleStateSuffix = "/api/v1/policy-bundle"

// IsPolicyBundleStatePath reports whether a guard_policy_state path is a
// fetched-bundle row: one row per verified version this node ACCEPTED. The
// guard composition reads it to know that a missing bundle file is a
// deletion rather than "nothing published" (T-864 gap 1).
func IsPolicyBundleStatePath(path string) bool {
	return strings.HasSuffix(path, policyBundleStateSuffix)
}

// PolicyBundleStateOrg returns the org server URL a fetched-bundle row's path
// identity names (the inverse of policyBundleStatePath).
func PolicyBundleStateOrg(path string) string {
	return strings.TrimSuffix(path, policyBundleStateSuffix)
}

// PolicyStatus classifies one policy-bundle poll outcome.
type PolicyStatus string

// PolicyStatus values.
const (
	// PolicyApplied — a new version passed the acceptance gate and the
	// local cache was replaced. Effective at the next guard
	// construction (hook processes: their next invocation; the
	// daemon's engines: next start).
	PolicyApplied PolicyStatus = "applied"
	// PolicyUnchanged — 304: the cache already holds the current version.
	PolicyUnchanged PolicyStatus = "unchanged"
	// PolicyNone — 404: no bundle published, or a pre-G13 server
	// without the endpoint. The agent runs local-only policy; an
	// existing cache is deliberately kept (withdrawing a bundle is
	// publishing an empty rule set as a new version, never an
	// ambiguous 404).
	PolicyNone PolicyStatus = "none"
	// PolicyRejected — the envelope failed the acceptance gate. The
	// previous cache stays; the caller records an R-205 guard event.
	PolicyRejected PolicyStatus = "rejected"
)

// PolicyRejectCode is the TYPED reason a delivered policy bundle failed the
// §14.2 acceptance gate (P0-6 §2.5). It rides the reverse channel as the
// PolicyStateRow.Reason for a delivered_unaccepted row — never PolicyResult.Detail
// (human log only, never on the wire). The empty value means "no rejection".
type PolicyRejectCode string

// PolicyRejectCode values — one per acceptance gate (§2.5).
const (
	// RejectNone means the bundle was not rejected (accepted / unchanged / none).
	RejectNone PolicyRejectCode = ""
	// RejectSigInvalid — gate 1: the envelope signature did not verify.
	RejectSigInvalid PolicyRejectCode = "sig_invalid"
	// RejectKeyPinMismatch — gate 2: the signing key did not match the pin.
	RejectKeyPinMismatch PolicyRejectCode = "key_pin_mismatch"
	// RejectVersionDowngrade — gate 3: the served version was below the last verified.
	RejectVersionDowngrade PolicyRejectCode = "version_downgrade"
	// RejectLintFailed — gate 4: the TOML did not lint as an org policy file.
	RejectLintFailed PolicyRejectCode = "lint_failed"
	// RejectVersionReplay — gate 3 (equal-version arm, B6/SF-B): the served
	// version equals the cached version but the content differs — a
	// non-monotonic republish (misconfig/replay). A good cache is never
	// evicted; the operator must bump the version to change content.
	RejectVersionReplay PolicyRejectCode = "version_replay"
)

// PolicyResult summarises one policy-bundle poll for the CLI / loop /
// R-205 emission.
type PolicyResult struct {
	Status     PolicyStatus
	Version    int64            // served version (0 when none/unchanged-by-etag)
	Detail     string           // human-readable specifics for rejected/none — MUST NOT ride the wire
	RejectCode PolicyRejectCode // typed reject reason; set at the failing gate (§2.5), "" otherwise
	// CachedVersion is the node-local cache file's bundle version on an
	// Unchanged outcome (0 when the cache is absent/unreadable). It lets
	// the guard reload trigger (policyBundleRunner.onResult) detect a
	// cold-recovery DIVERGENCE — a live running version behind the cache
	// — and converge it without a restart (SF7), while a steady-state
	// running==cached poll skips the reload (no re-verify churn).
	CachedVersion int64
	// DisplacedTo is where an Applied fetch moved a non-regular entry it
	// found at the cache path before writing the bundle ("" when nothing
	// was moved; D-704, displaceForeignCacheEntry). Node-local, like Detail:
	// it MUST NOT ride the wire.
	DisplacedTo string
	// RepairedCache is what an Applied fetch found wrong with the cached
	// bundle it re-materialised: CacheRepairTampered when the file no longer
	// verified, CacheRepairMissing when it was gone (or unreadable as the
	// bundle file) although this node had accepted a bundle, and
	// CacheRepairNone otherwise (a clean upgrade, a first fetch, or an I/O
	// fault that made the pre-fetch check indecisive). It lets the daemon
	// record the tamper the poll repaired before the posture check saw it.
	// Node-local, like Detail: it MUST NOT ride the wire.
	RepairedCache CacheRepair
	// RepairedCode is the typed reason a CacheRepairTampered cache failed
	// verification (sig_invalid or key_pin_mismatch; "" otherwise).
	// Node-local: it MUST NOT ride the wire.
	RepairedCode PolicyRejectCode
}

// CacheRepair names what an Applied fetch repaired in the node's cached
// org bundle (PolicyResult.RepairedCache). The empty value means nothing was
// wrong with it.
type CacheRepair string

// CacheRepair values (a closed set; cacheRepairByIntegrity is the one
// mapping from the on-disk check).
const (
	// CacheRepairNone: the cache verified, was never accepted, or the
	// pre-fetch check could not decide (an I/O fault is never a tamper).
	CacheRepairNone CacheRepair = ""
	// CacheRepairTampered: the cache no longer verified (edited, re-signed
	// with another key, corrupt) and the fetch wrote the org's bundle back.
	CacheRepairTampered CacheRepair = "tampered"
	// CacheRepairMissing: the cache was gone (or unreadable as the bundle
	// file) although this node had accepted a bundle, and the fetch wrote
	// the org's bundle back.
	CacheRepairMissing CacheRepair = "missing"
)

// cacheRepairByIntegrity maps the pre-fetch on-disk verdict to the repair an
// Applied fetch performs, one row per integrity value that is a tamper.
// Every other verdict (verified, absent) is CacheRepairNone.
var cacheRepairByIntegrity = map[string]CacheRepair{
	orgcontract.BundleIntegrityTampered: CacheRepairTampered,
	orgcontract.BundleIntegrityMissing:  CacheRepairMissing,
}

// cacheRepairFor classifies the pre-fetch on-disk check. A check that failed
// (a genuine I/O or store fault) is never a tamper.
func cacheRepairFor(check CachedBundleCheck, err error) (CacheRepair, PolicyRejectCode) {
	if err != nil {
		return CacheRepairNone, RejectNone
	}
	repair := cacheRepairByIntegrity[check.Integrity]
	if repair == CacheRepairNone {
		return CacheRepairNone, RejectNone
	}
	return repair, check.RejectCode
}

// GuardFetchOutcome is the TOTAL, typed classification of ONE guard
// policy-bundle poll cycle (P0-6 §2.5c). PolicyPollLoop invokes onResult only
// on an accepted/delivered success, so transport/5xx/auth/local failures never
// reach the bundle runner and stale_lkg is otherwise unimplementable. This
// outcome classifies EVERY concrete FetchPolicyBundle return branch so the
// reporter can resolve the honest state (§3.2) without re-inferring anything
// from a bare error (which cannot distinguish a local SQLite failure from a
// transport failure, R4-B2).
type GuardFetchOutcome struct {
	OK            bool             // fetch succeeded; bundle accepted OR delivered-rejected (see RejectCode)
	Unreachable   bool             // transport error / 5xx — control plane down (Reached=false)
	AuthFailed    bool             // ErrAuthFailed (401/403) — reached, credential rejected
	Indeterminate bool             // cache/decode/local error — non-decisive
	Reached       bool             // TRUE iff an HTTP response arrived (R5-B3/R5-B5). Any Reached outcome CLEARS a prior Unreachable.
	RejectCode    PolicyRejectCode // gate rejection carried up from the successful poll's PolicyResult
	Version       int64            // accepted or rejected version; 0 if none
}

// Guard fetch-outcome classification sentinels. FetchPolicyBundle tags each
// non-decisive error branch with one of these so classifyGuardFetch can build a
// TOTAL GuardFetchOutcome via errors.Is — a bare error cannot distinguish a
// local SQLite failure from a transport failure (R4-B2). These are UNEXPORTED:
// the classifier and its mutation-proof test share the package.
var (
	// errPolicyTransport tags a transport error / timeout / 5xx: the control
	// plane is down. Reached=false → Unreachable.
	errPolicyTransport = errors.New("orgclient: policy fetch transport failure")
	// errPolicyReachedIndeterminate tags a REACHED-but-non-decisive branch: an
	// other HTTP status (3xx non-304 / non-auth 4xx / 429) or a local error
	// after a received body. Reached=true → Indeterminate.
	errPolicyReachedIndeterminate = errors.New("orgclient: policy fetch reached but indeterminate")
	// errPolicyLocalPreResponse tags a local error pre/independent of a response
	// (enrolment / bearer / client construction / pin read/write / version-state
	// read / cache marshal/write / state record). Reached=false → Indeterminate.
	errPolicyLocalPreResponse = errors.New("orgclient: policy fetch local error before response")
)

// classifyGuardFetch maps one FetchPolicyBundle (PolicyResult, error) return to
// a TOTAL GuardFetchOutcome (§2.5c). The second result reports whether an
// outcome should be EMITTED to the sink at all — context.Canceled and the
// idle/not-enrolled classes are shutdown/no-op signals, not fetch verdicts, and
// emit=false (today's exact no-op). Every other branch maps to exactly one
// state, and Reached is set correctly so the reporter's overwrite discipline
// (§2.5c) can clear a stale Unreachable. It reads TYPED sentinels the source
// attached — it never infers Unreachable-vs-Indeterminate from a bare error.
func classifyGuardFetch(res PolicyResult, err error) (GuardFetchOutcome, bool) {
	switch {
	case errors.Is(err, context.Canceled):
		return GuardFetchOutcome{}, false
	case errors.Is(err, ErrNotEnrolled) || errors.Is(err, errIdle):
		return GuardFetchOutcome{}, false
	case errors.Is(err, ErrAuthFailed):
		return GuardFetchOutcome{AuthFailed: true, Reached: true}, true
	case errors.Is(err, errPolicyTransport):
		return GuardFetchOutcome{Unreachable: true, Reached: false}, true
	case errors.Is(err, errPolicyReachedIndeterminate):
		return GuardFetchOutcome{Indeterminate: true, Reached: true}, true
	case errors.Is(err, errPolicyLocalPreResponse):
		return GuardFetchOutcome{Indeterminate: true, Reached: false}, true
	case err != nil:
		// Any unclassified error is conservatively local + non-decisive: it
		// must never fabricate Unreachable/stale_lkg (R4-B2).
		return GuardFetchOutcome{Indeterminate: true, Reached: false}, true
	default:
		// A successful poll: accepted / unchanged / none(404) / delivered-
		// rejected. OK with a non-empty RejectCode is a delivered rejection.
		return GuardFetchOutcome{
			OK:         true,
			Reached:    true,
			RejectCode: res.RejectCode,
			Version:    res.Version,
		}, true
	}
}

// SetGuardOutcomeSink installs a callback that receives the typed
// GuardFetchOutcome (§2.5c) for every decisive guard poll cycle. It is a
// nil-defaulted seam (R6-1): with no sink installed, PolicyPollLoop behaves
// EXACTLY as before (no-op). The P0-6 reporter installs its recorder here.
func (c *Client) SetGuardOutcomeSink(sink func(GuardFetchOutcome)) {
	c.guardOutcomeSink = sink
}

// FetchPolicyBundle performs one poll of GET /api/v1/policy-bundle and
// runs the §14.2 acceptance gate. cachePath is the resolved
// [guard.rules].org_bundle location the verified envelope is written
// to (atomic replace; 0600). Returns ErrNotEnrolled when the agent has
// no enrolment, ErrAuthFailed on 401/403, and a retryable error on
// transport/5xx failures.
func (c *Client) FetchPolicyBundle(ctx context.Context, cachePath string) (PolicyResult, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return PolicyResult{}, fmt.Errorf("orgclient.FetchPolicyBundle: %w: %w", errPolicyLocalPreResponse, err)
	}
	if enr == nil {
		return PolicyResult{}, ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if errors.Is(err, ErrNoSecret) {
		return PolicyResult{}, ErrNotEnrolled
	}
	if err != nil {
		return PolicyResult{}, fmt.Errorf("orgclient.FetchPolicyBundle: load bearer: %w: %w", errPolicyLocalPreResponse, err)
	}

	// If-None-Match only when the cache file exists AND still verifies
	// (signature, key pin, body hash). A stored ETag with a deleted cache
	// must re-download, not 304 into nothing; and a cache that was edited on
	// disk must re-download too (T-846, guard tamper audit row b2): a 304
	// would keep the tampered file, and the hooks would run without the org
	// layer until the org next published a NEW version. The same check names
	// what an Applied fetch repairs (RepairedCache), so the daemon records
	// the tamper even when this poll restores the file before the posture
	// check sees it (T-869).
	params := &gen.GetPolicyBundleParams{}
	check, verr := c.VerifyCachedPolicyBundle(ctx, cachePath)
	repaired, repairedCode := cacheRepairFor(check, verr)
	if etag, eerr := c.store.LoadOrgPolicyETag(ctx); eerr == nil && etag != "" {
		if verr == nil && check.Integrity == orgcontract.BundleIntegrityVerified && projectFilesPresent(cachePath) {
			params.IfNoneMatch = &etag
		}
	}

	gc, err := c.genClient(enr.OrgServerURL)
	if err != nil {
		return PolicyResult{}, fmt.Errorf("orgclient.FetchPolicyBundle: %w: %w", errPolicyLocalPreResponse, err)
	}

	b, early, hasEarly, etag, err := c.receiveBundle(ctx, gc, params, bearer)
	if err != nil {
		return PolicyResult{}, err
	}
	if hasEarly {
		// SF7: on a 304/Unchanged, surface the cache file's version so the
		// guard reload trigger can detect a running-vs-cached divergence
		// (cold recovery) without a restart. Best-effort — an unreadable
		// cache just leaves CachedVersion 0 (the trigger then no-ops).
		if early.Status == PolicyUnchanged {
			if v, _, ok, _ := c.readCachedBundle(ctx, cachePath, enr.OrgServerURL); ok {
				early.CachedVersion = v
			}
			// The org just confirmed the bundle it holds, and with it the
			// project mapping's offline lifetime restarts (projectaudience.go).
			confirmProjectMapping(cachePath, time.Now())
		}
		return early, nil
	}

	if rej, rejected, err := c.applyBundleGates(ctx, b, enr, cachePath); err != nil {
		return PolicyResult{}, err
	} else if rejected {
		return rej, nil
	}

	// Accepted: write the project half of a v3 delivery first (the bundle
	// file that names it lands last), then atomically replace the cache,
	// record the version row, remember the ETag. The cached bundle never
	// carries the projects field: the hook's org layer reads it on every
	// call, and the envelopes live in their own files.
	if err := c.writeProjectAudience(ctx, b, cachePath, enr.OrgServerURL, time.Now()); err != nil {
		return PolicyResult{}, fmt.Errorf("orgclient.FetchPolicyBundle: %w: %w", errPolicyLocalPreResponse, err)
	}
	b.Projects = nil
	raw, err := json.Marshal(b)
	if err != nil {
		return PolicyResult{}, fmt.Errorf("orgclient.FetchPolicyBundle: marshal cache: %w: %w", errPolicyLocalPreResponse, err)
	}
	// A directory (or other non-regular entry) planted at the cache path
	// blocks the atomic write forever; move it aside first (D-704: nothing
	// is deleted, see displaceForeignCacheEntry).
	aside, derr := displaceForeignCacheEntry(cachePath, time.Now())
	if derr != nil {
		return PolicyResult{}, fmt.Errorf("orgclient.FetchPolicyBundle: clear cache path: %w: %w", errPolicyLocalPreResponse, derr)
	}
	if aside != "" {
		c.logger.Warn("org policy: the bundle cache path held something that is not the bundle file; moved it aside (nothing deleted) to restore the organization's bundle",
			"path", cachePath, "moved_to", aside)
	}
	if err := writeFileAtomic(cachePath, raw); err != nil {
		return PolicyResult{}, fmt.Errorf("orgclient.FetchPolicyBundle: write cache: %w: %w", errPolicyLocalPreResponse, err)
	}
	sum := sha256.Sum256([]byte(b.BundleTOML))
	if _, err := c.store.RecordGuardPolicyState(ctx, store.GuardPolicyStateRow{
		Layer:       "org",
		Path:        policyBundleStatePath(enr.OrgServerURL),
		Version:     strconv.FormatInt(b.Version, 10),
		ContentHash: hex.EncodeToString(sum[:]),
		Signature:   b.Signature,
		LoadedAt:    time.Now().UTC(),
	}); err != nil {
		return PolicyResult{}, fmt.Errorf("orgclient.FetchPolicyBundle: record state: %w: %w", errPolicyLocalPreResponse, err)
	}
	if etag != "" {
		if err := c.store.SaveOrgPolicyETag(ctx, etag); err != nil {
			c.logger.Warn("org policy: etag save failed (next poll re-downloads)", "err", err)
		}
	}
	c.logger.Info("org policy: bundle applied", "version", b.Version,
		"effective", "next guard construction (hooks: next tool call; daemon: next start)")
	return PolicyResult{
		Status: PolicyApplied, Version: b.Version, DisplacedTo: aside,
		RepairedCache: repaired, RepairedCode: repairedCode,
	}, nil
}

// receiveBundle performs the raw GET (gc.GetPolicyBundle — the transport-only
// (*http.Response, error) shape, NOT the typed WithResponse wrapper, whose
// generated parser returns (nil, err) for a body-read failure OR a
// json.Unmarshal failure on a RECEIVED 200/401/404 body, which would
// misclassify a reached-but-corrupt response as transport Unreachable —
// Blocker 1 / R5-B5) and classifies the reached-vs-transport disposition of
// the result. err is transport-only (no response arrived) or one of the
// errPolicy* sentinels tagged via fmt.Errorf. hasEarly reports a decisive
// PolicyResult (304/404/401/403/5xx/other-reached-status) that FetchPolicyBundle
// must return immediately, without running the acceptance gates. On a 200,
// bundle is the decoded body and etag is the response's ETag header (read
// before the deferred body Close, which does not invalidate the already-parsed
// header map).
func (c *Client) receiveBundle(ctx context.Context, gc *gen.ClientWithResponses, params *gen.GetPolicyBundleParams, bearer string) (bundle gen.PolicyBundle, early PolicyResult, hasEarly bool, etag string, err error) {
	resp, err := gc.GetPolicyBundle(ctx, params, bearerEditor(bearer), policyBindingCapsEditor)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		// context.Canceled is a shutdown, not a fetch verdict (classify skips
		// it); any other Do error is transport-class → Unreachable.
		if errors.Is(err, context.Canceled) {
			return gen.PolicyBundle{}, PolicyResult{}, false, "", fmt.Errorf("orgclient.FetchPolicyBundle: get: %w", err)
		}
		return gen.PolicyBundle{}, PolicyResult{}, false, "", fmt.Errorf("orgclient.FetchPolicyBundle: get: %w: %w", errPolicyTransport, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// An older server's page answers as 404 (railreply.go).
	switch c.railStatus(policyBundleRail, resp) {
	case http.StatusOK:
		// fall through to body decode below
	case http.StatusNotModified:
		return gen.PolicyBundle{}, PolicyResult{Status: PolicyUnchanged}, true, "", nil
	case http.StatusNotFound:
		return gen.PolicyBundle{}, PolicyResult{Status: PolicyNone, Detail: "no bundle published (or pre-guard server)"}, true, "", nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return gen.PolicyBundle{}, PolicyResult{}, false, "", fmt.Errorf("orgclient.FetchPolicyBundle: %w", ErrAuthFailed)
	default:
		// 5xx is transport-class (control plane down → Unreachable); every
		// OTHER reached status (3xx non-304 / non-auth 4xx / 429) proves the
		// control plane answered → reached-Indeterminate (R5-B5).
		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			return gen.PolicyBundle{}, PolicyResult{}, false, "", fmt.Errorf("orgclient.FetchPolicyBundle: server returned %d: %w", resp.StatusCode, errPolicyTransport)
		}
		return gen.PolicyBundle{}, PolicyResult{}, false, "", fmt.Errorf("orgclient.FetchPolicyBundle: server returned %d: %w", resp.StatusCode, errPolicyReachedIndeterminate)
	}

	// A response ARRIVED (200): a body-read or decode failure past this point
	// still PROVES the control plane answered — reached-Indeterminate, never
	// Unreachable (Blocker 1 / R5-B3/R5-B5).
	bodyBytes, rerr := io.ReadAll(io.LimitReader(resp.Body, policyBundleMaxBody))
	if rerr != nil {
		return gen.PolicyBundle{}, PolicyResult{}, false, "", fmt.Errorf("orgclient.FetchPolicyBundle: read body: %w: %w", errPolicyReachedIndeterminate, rerr)
	}
	var b gen.PolicyBundle
	if uerr := json.Unmarshal(bodyBytes, &b); uerr != nil {
		return gen.PolicyBundle{}, PolicyResult{}, false, "", fmt.Errorf("orgclient.FetchPolicyBundle: decode: %w: %w", errPolicyReachedIndeterminate, uerr)
	}
	if b.Version == 0 && b.BundleTOML == "" {
		return gen.PolicyBundle{}, PolicyResult{}, false, "", fmt.Errorf("orgclient.FetchPolicyBundle: 200 with no bundle body: %w", errPolicyReachedIndeterminate)
	}
	return b, PolicyResult{}, false, resp.Header.Get("ETag"), nil
}

// applyBundleGates runs the §14.2 acceptance gates (signature, key
// pin, monotonic version, lint) on a received bundle b for enrolment
// enr. It returns (rejection, true, nil) when a gate REJECTS (a
// delivered-but-rejected poll — nil error so the caller returns the
// rejection straight to onResult), (PolicyResult{}, false, err) on a
// LOCAL gate error (tagged errPolicyLocalPreResponse), and
// (PolicyResult{}, false, nil) when every gate PASSES, at which point
// the caller proceeds to atomically apply the cache.
func (c *Client) applyBundleGates(ctx context.Context, b gen.PolicyBundle, enr *store.Enrolment, cachePath string) (PolicyResult, bool, error) {
	// Gate 1: self-contained signature check.
	pub, err := orgcontract.VerifyPolicyBundle(b)
	if err != nil {
		return PolicyResult{
			Status: PolicyRejected, Version: b.Version, RejectCode: RejectSigInvalid,
			Detail: fmt.Sprintf("signature verification failed: %v", err),
		}, true, nil
	}

	// Gate 1b, the v2 BINDING (pass-2 review C156-15, orgcontract/
	// policybinding.go): a bound bundle must be bound to THIS node's org and
	// member (another member's composed team bundle is refused even though the
	// org signed it); an unbound one is refused once this node holds a bound
	// one (a signature downgrade). Before that an unbound bundle is accepted,
	// which keeps an older server working. RejectSigInvalid on purpose: the
	// reject code rides the policy-state wire, a closed set on older servers.
	cachedBound := heldBundleBound(cachePath)
	// Gate 1c, the v3 PROJECT AUDIENCE (projectaudience.go): a project
	// binding must name this org and member, carry a mapping bound by digest
	// and epoch, and envelopes of this delivery only; a lower epoch than one
	// accepted is refused, and once a v3 delivery was held a v2 or v1 one is a
	// downgrade.
	if rej, rejected, err := c.projectGate(ctx, b, enr, cachePath, pub); err != nil || rejected {
		return rej, rejected, err
	}
	switch {
	case b.Binding != nil && *b.Binding != (orgcontract.PolicyBinding{OrgID: enr.OrgID, Subject: enr.UserID}):
		return PolicyResult{
			Status: PolicyRejected, Version: b.Version, RejectCode: RejectSigInvalid,
			Detail: "the bundle is signed for a different org or member than this node",
		}, true, nil
	case b.Binding == nil && b.ProjectBinding == nil && cachedBound:
		return PolicyResult{
			Status: PolicyRejected, Version: b.Version, RejectCode: RejectSigInvalid,
			Detail: "an unbound (v1) bundle after this node held a bound (v2) one: refused as a signature downgrade",
		}, true, nil
	}

	// Gate 2: key pin (TOFU when no pin exists yet).
	keyHash := orgcontract.PublicKeyPinHash(pub)
	pinned, err := c.loadKeyPin(ctx, enr.OrgServerURL)
	if err != nil {
		return PolicyResult{}, false, fmt.Errorf("orgclient.FetchPolicyBundle: read key pin: %w: %w", errPolicyLocalPreResponse, err)
	}
	offered := base64.StdEncoding.EncodeToString(pub)
	switch {
	case pinned == "":
		// C1: this rail's trust-on-first-fetch writes the SAME `#policy-key`
		// row the enrolment channel writes, so before establishing one it must
		// agree with every trust the node already holds. Without this check a
		// network attacker who reaches an unpinned node can plant his key here
		// and have another rail promote it to the trust root.
		if err := c.checkOrgKeyIdentity(ctx, policyBundleRail, offered); err != nil {
			if errors.Is(err, errPinStoreRead) {
				return PolicyResult{}, false, fmt.Errorf("orgclient.FetchPolicyBundle: pin key: %w: %w", errPolicyLocalPreResponse, err)
			}
			return PolicyResult{
				Status: PolicyRejected, Version: b.Version, RejectCode: RejectKeyPinMismatch,
				Detail: err.Error(),
			}, true, nil
		}
		// Stamped railPinProvenance: this row was established by a FETCH,
		// not by the enrolment channel, and must never promote (C1).
		if _, err := c.store.RecordGuardPolicyState(ctx, store.GuardPolicyStateRow{
			Layer:       "org",
			Path:        PolicyKeyPinPath(enr.OrgServerURL),
			Version:     railPinProvenance,
			ContentHash: keyHash,
			LoadedAt:    time.Now().UTC(),
		}); err != nil {
			return PolicyResult{}, false, fmt.Errorf("orgclient.FetchPolicyBundle: pin key: %w: %w", errPolicyLocalPreResponse, err)
		}
		c.logger.Info("org policy: signing key pinned on first fetch", "key_sha256", keyHash)
	case pinned != keyHash:
		return PolicyResult{
			Status: PolicyRejected, Version: b.Version, RejectCode: RejectKeyPinMismatch,
			Detail: "signing key does not match the enrolment pin (re-enrol if the org key legitimately rotated)",
		}, true, nil
	default:
		// M4: this rail holds the PROVEN key bytes behind the pin hash — the
		// bundle's own signature verified under them. A node whose enrolment
		// stored only the hash can therefore learn its key here, without
		// waiting for a routing or announcement document. adoptEnrolmentKeyMaterial
		// re-checks provenance (C1), so a hash this rail itself TOFU-established
		// is never promoted.
		c.adoptEnrolmentKeyMaterial(ctx, offered)
	}

	// Gate 3: monotonic version. The baseline is the MAX of the
	// guard_policy_state row AND the verified cached envelope's version
	// — the state-log's hash-only dedup (store/guard.go
	// RecordGuardPolicyState) suppresses a row when only the version
	// changed and the hash is identical, so after an identical-content
	// v1→v2 bump the DB baseline can stay at 1 while the cache is v2.
	// Using the DB alone would then accept a replayed signed v1
	// (1 < 1 is false; equal-arm compares against cache v2 ≠ 1 and falls
	// through) and overwrite the v2 cache — a monotonic regression.
	lastVersion, err := c.lastBundleVersion(ctx, enr.OrgServerURL)
	if err != nil {
		return PolicyResult{}, false, fmt.Errorf("orgclient.FetchPolicyBundle: read last version: %w: %w", errPolicyLocalPreResponse, err)
	}
	cachedVer, cachedHash, cacheOK, herr := c.readCachedBundle(ctx, cachePath, enr.OrgServerURL)
	if herr != nil {
		return PolicyResult{}, false, fmt.Errorf("orgclient.FetchPolicyBundle: read cache baseline: %w: %w", errPolicyLocalPreResponse, herr)
	}
	if cacheOK && cachedVer > lastVersion {
		lastVersion = cachedVer
	}
	if b.Version < lastVersion {
		return PolicyResult{
			Status: PolicyRejected, Version: b.Version, RejectCode: RejectVersionDowngrade,
			Detail: fmt.Sprintf("version regression: served %d after %d (rollback = publish old content as a new version)", b.Version, lastVersion),
		}, true, nil
	}

	// Equal-version arm (B6/SF-B): a re-served version must carry
	// IDENTICAL content. The content baseline is the VERIFIED CACHED
	// ENVELOPE's hash (already loaded above), not the guard_policy_state
	// row. The incoming hash is sha256hex(BundleTOML), byte-identical to
	// the guard's PolicyState.ContentHash so equal content compares equal.
	if lastVersion > 0 && b.Version == lastVersion {
		if cacheOK && cachedVer == b.Version {
			incoming := sha256.Sum256([]byte(b.BundleTOML))
			if hex.EncodeToString(incoming[:]) != cachedHash {
				// Same version, different content → non-monotonic republish.
				return PolicyResult{
					Status: PolicyRejected, Version: b.Version, RejectCode: RejectVersionReplay,
					Detail: fmt.Sprintf("version replay: served version %d with content differing from the cached bundle (non-monotonic republish - bump the version to change content)", b.Version),
				}, true, nil
			}
			if incoming, held := bundleBindingKind(b), heldBindingKind(cachePath); incoming == bindingNone || incoming == held {
				// Identical content already current → no reload (SF-B). A v3
				// delivery still re-materialises its project files, which a
				// 200 at an equal version means were missing.
				if err := c.writeProjectAudience(ctx, b, cachePath, enr.OrgServerURL, time.Now()); err != nil {
					return PolicyResult{}, false, fmt.Errorf("orgclient.FetchPolicyBundle: %w: %w", errPolicyLocalPreResponse, err)
				}
				return PolicyResult{Status: PolicyUnchanged, Version: b.Version, CachedVersion: cachedVer}, true, nil
			}
			// The same content now arrives BOUND over an unbound cache (the
			// first poll after the server learned to bind, C156-15), or
			// project-bound (v3) over a v2 one: fall through and re-cache it
			// with its ETag, so the binding sticks and the next poll is a 304
			// instead of a re-download.
		}
		// No usable cached baseline (cache absent/corrupt/unverifiable)
		// at an equal recorded version: fall through to accept so the
		// missing cache is re-materialised (SF7 corrupt-cache redownload
		// stays a documented residual, but a MISSING cache must be
		// rewritten).
	}

	// Gate 4: the TOML must pass the CONSUMER check for an org-layer
	// policy file so a malformed or floor-violating bundle never evicts
	// a good cache.
	//
	// guard.AcceptOrgBundleTOML, NOT guard.Lint — this is a consumer
	// gate, and running the authoring lint here was the fetch-side half
	// of GUARD-FWD-1 (docs/security.md). A node may be older than the
	// server that signed the bundle, so a key it does not know is a key
	// from the FUTURE, not a defect: refusing it here rejected the
	// bundle before it was ever cached, which left a node with an old
	// cache permanently stale and a freshly enrolled node with no org
	// layer at all — fail-OPEN, since the org layer is escalate-only.
	// The server still refuses an unknown key at publish
	// (api.LintOrgBundle → guard.Lint("org")), which is where a typo
	// belongs. Accepted-with-notes is a WARN, never a rejection.
	problems, notes := guard.AcceptOrgBundleTOML([]byte(b.BundleTOML))
	if len(problems) > 0 {
		return PolicyResult{
			Status: PolicyRejected, Version: b.Version, RejectCode: RejectLintFailed,
			Detail: fmt.Sprintf("bundle does not lint as an org policy file: %s", problems[0]),
		}, true, nil
	}
	if len(notes) > 0 {
		// Same wording as the loader's PolicyState.Notes line, so the
		// daemon log and `observer guard status` say the same thing.
		c.logger.Warn(fmt.Sprintf("org bundle: ignored %d unknown key(s): %s (newer server; update the node binary)",
			len(notes), strings.Join(notes, ", ")), "version", b.Version)
	}

	return PolicyResult{}, false, nil
}

// PolicyPollLoop fetches the policy bundle once immediately (§14.2:
// the poll fires on `observer start`), then on every poll interval,
// until ctx is cancelled or an auth failure stops it (same loop
// contract as PushLoop). onResult, when non-nil, receives every
// successful poll outcome — the cmd layer uses it to emit R-205 on
// PolicyRejected. Transport failures ride the shared jittered backoff.
func (c *Client) PolicyPollLoop(ctx context.Context, cachePath string, onResult func(PolicyResult)) error {
	cycle := func(ctx context.Context) error {
		res, err := c.FetchPolicyBundle(ctx, cachePath)
		// SF8: on a SUCCESSFUL poll, run onResult (which hot-reloads the
		// LIVE guard on an accepted/divergent outcome) BEFORE poking the
		// P0-6 reporter, so the poked report() observes POST-reload guard
		// state instead of a stale pending_restart that only self-corrects
		// at the next heartbeat. Error cycles skip onResult (as before) but
		// still poke the sink. Same res/err feed the classification.
		if err == nil && onResult != nil {
			onResult(res)
		}
		// Forward the TOTAL typed outcome (§2.5c) to the P0-6 reporter on every
		// decisive cycle — INCLUDING the transport/5xx/auth/local error paths
		// that onResult never sees, which is the only way stale_lkg becomes
		// reachable. Nil sink (the default) is today's exact no-op (R6-1).
		if c.guardOutcomeSink != nil {
			if outcome, emit := classifyGuardFetch(res, err); emit {
				c.guardOutcomeSink(outcome)
			}
		}
		if errors.Is(err, ErrNotEnrolled) {
			return errIdle // not enrolled (yet, or unenrolled while running)
		}
		if err != nil {
			return err
		}
		return nil
	}
	// Immediate first fetch; its failure classes anyway repeat through
	// the loop, so a failure here only logs (auth failures still stop).
	if err := cycle(ctx); errors.Is(err, ErrAuthFailed) {
		c.logger.Error("org policy: authentication failed, stopping policy poll", "err", err)
		return nil
	} else if err != nil && !errors.Is(err, errIdle) && !errors.Is(err, context.Canceled) {
		c.logger.Warn("org policy: initial fetch failed", "err", err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// policyBundleKick is the policy-freshness checker's wake-up (P2,
	// policyfreshness.go): a moved "bundle" rail version fetches now
	// instead of at the next hourly poll.
	return c.runLoopKick(ctx, c.policyPollInterval(), c.policyBundleKick, cycle)
}

// policyPollInterval returns the configured poll cadence, defaulted.
func (c *Client) policyPollInterval() time.Duration {
	secs := c.cfg.PolicyPollIntervalSeconds
	if secs <= 0 {
		secs = config.DefaultPolicyPollIntervalSeconds
	}
	return time.Duration(secs) * time.Second
}

// loadKeyPin returns the pinned policy-key hash for orgURL, or ""
// when no pin row exists (pre-G13 enrolment).
func (c *Client) loadKeyPin(ctx context.Context, orgURL string) (string, error) {
	states, err := c.store.LatestGuardPolicyStates(ctx)
	if err != nil {
		return "", err
	}
	pinPath := PolicyKeyPinPath(orgURL)
	for _, st := range states {
		if st.Layer == "org" && st.Path == pinPath {
			return st.ContentHash, nil
		}
	}
	return "", nil
}

// lastBundleVersion returns the version of the last verified bundle
// for orgURL, or 0 when none was ever applied (or the recorded
// version string predates versioning and does not parse).
func (c *Client) lastBundleVersion(ctx context.Context, orgURL string) (int64, error) {
	states, err := c.store.LatestGuardPolicyStates(ctx)
	if err != nil {
		return 0, err
	}
	bundlePath := policyBundleStatePath(orgURL)
	for _, st := range states {
		if st.Layer == "org" && st.Path == bundlePath {
			v, perr := strconv.ParseInt(st.Version, 10, 64)
			if perr != nil {
				return 0, nil //nolint:nilerr // unparseable = no version baseline; the check degrades open by design
			}
			return v, nil
		}
	}
	return 0, nil
}

// readCachedBundle reads the node-local bundle cache envelope and
// returns its version + the sha256hex of its BundleTOML — the SF-B
// content baseline the equal-version gate compares against, and (after
// P0-7 BLOCKER 2) the version half of the monotonic baseline.
//
// The cache is verified-at-write on the accept path; this reader
// RE-VERIFIES signature + enrolment pin (defense-in-depth now that the
// cached envelope is load-bearing for the monotonic baseline). A
// tampered/corrupt/pin-mismatched cache returns ok=false (nil error) —
// "no reliable baseline" — so the caller re-materialises rather than
// rejecting on a phantom mismatch or accepting a forged baseline. That
// failure direction is fail-safe (availability, never a false accept).
// A path that holds something unreadable as the bundle file (a planted
// directory, a file this user may not read; cacheReadUnusable, D-704) is
// the same "no reliable baseline" as a corrupt cache, so the accept path
// can restore the bundle; only a genuine I/O fault is returned, so the
// caller classifies it as a local, non-decisive failure. The hash uses the
// SAME canonical bytes ([]byte(BundleTOML)) the accept path and the
// guard's PolicyState.ContentHash use, so equal content compares
// byte-equal.
func (c *Client) readCachedBundle(ctx context.Context, cachePath, orgURL string) (version int64, contentHash string, ok bool, err error) {
	raw, rerr := os.ReadFile(cachePath)
	if rerr != nil {
		if classifyCacheReadError(cachePath, rerr) == cacheReadIOError {
			return 0, "", false, rerr
		}
		return 0, "", false, nil
	}
	var cached gen.PolicyBundle
	if uerr := json.Unmarshal(raw, &cached); uerr != nil {
		return 0, "", false, nil // corrupt cache — no reliable baseline
	}
	// Re-verify signature (same gate 1 the accept path uses).
	pub, verr := orgcontract.VerifyPolicyBundle(cached)
	if verr != nil {
		return 0, "", false, nil // tampered/unsigned — no reliable baseline
	}
	// Re-check enrolment pin when one exists (same gate 2). A missing
	// pin (pre-TOFU) degrades open — signature alone is enough; we do
	// NOT pin on a cache read.
	if orgURL != "" {
		keyHash := orgcontract.PublicKeyPinHash(pub)
		pinned, perr := c.loadKeyPin(ctx, orgURL)
		if perr != nil {
			return 0, "", false, perr
		}
		if pinned != "" && pinned != keyHash {
			return 0, "", false, nil // pin mismatch — treat as unreliable
		}
	}
	sum := sha256.Sum256([]byte(cached.BundleTOML))
	return cached.Version, hex.EncodeToString(sum[:]), true, nil
}

// CachedBundleCheck is the result of re-verifying the org policy bundle ON
// DISK (VerifyCachedPolicyBundle). Integrity is one of
// orgcontract.BundleIntegrity*; RejectCode is the typed reason a tampered
// file failed (sig_invalid or key_pin_mismatch); Version is the version the
// file claims (0 when it does not decode).
type CachedBundleCheck struct {
	Integrity  string
	RejectCode PolicyRejectCode
	Version    int64
}

// VerifyCachedPolicyBundle re-verifies the org policy bundle at cachePath the
// way the acceptance gate verified it when it was written (T-846): the
// envelope signature, the enrolment key pin, and the BODY HASH against the
// content hash this node recorded for that version when it accepted it
// (guard_policy_state, the fetched-bundle row). It is the ONE on-disk check
// both consumers use: the policy poll (a cache that fails it is never kept
// on a 304) and the policy-state reporter (a cache that fails it reads
// "tampered", not "effective").
//
// A missing file is BundleIntegrityMissing when this node recorded an
// accepted bundle (a deletion), BundleIntegrityAbsent otherwise. A path that
// holds something the node cannot read as the bundle file (a directory or
// other non-regular entry planted there, or a file this user may not read;
// D-704) reads the same way: the hooks cannot read it either, so the org
// layer in the hook path is the last verified copy exactly as after a
// deletion, and the poll re-fetches at once. Reporting it as an error instead
// made the policy-state reporter skip every snapshot while the path stayed
// blocked, freezing the organization's view on the last good report. A file
// that does not decode, whose signature fails, whose body does not match the
// recorded hash, or whose key does not match the pin is
// BundleIntegrityTampered. A genuine I/O fault or a store error (a locked DB)
// is returned as an error so a caller never reports tamper on an I/O hiccup.
func (c *Client) VerifyCachedPolicyBundle(ctx context.Context, cachePath string) (CachedBundleCheck, error) {
	raw, rerr := os.ReadFile(cachePath)
	if rerr != nil {
		if classifyCacheReadError(cachePath, rerr) == cacheReadIOError {
			return CachedBundleCheck{}, fmt.Errorf("orgclient.VerifyCachedPolicyBundle: read: %w", rerr)
		}
		return c.missingOrAbsent(ctx)
	}
	tampered := func(code PolicyRejectCode, version int64) (CachedBundleCheck, error) {
		return CachedBundleCheck{Integrity: orgcontract.BundleIntegrityTampered, RejectCode: code, Version: version}, nil
	}
	var cached gen.PolicyBundle
	if err := json.Unmarshal(raw, &cached); err != nil {
		return tampered(RejectSigInvalid, 0)
	}
	pub, verr := orgcontract.VerifyPolicyBundle(cached)
	if verr != nil {
		return tampered(RejectSigInvalid, cached.Version)
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return CachedBundleCheck{}, fmt.Errorf("orgclient.VerifyCachedPolicyBundle: %w", err)
	}
	if enr != nil {
		pinned, perr := c.loadKeyPin(ctx, enr.OrgServerURL)
		if perr != nil {
			return CachedBundleCheck{}, fmt.Errorf("orgclient.VerifyCachedPolicyBundle: key pin: %w", perr)
		}
		if pinned != "" && pinned != orgcontract.PublicKeyPinHash(pub) {
			return tampered(RejectKeyPinMismatch, cached.Version)
		}
		recVersion, recHash, herr := c.recordedBundleHash(ctx, enr.OrgServerURL)
		if herr != nil {
			return CachedBundleCheck{}, fmt.Errorf("orgclient.VerifyCachedPolicyBundle: recorded hash: %w", herr)
		}
		if recVersion == cached.Version && recHash != "" {
			sum := sha256.Sum256([]byte(cached.BundleTOML))
			if hex.EncodeToString(sum[:]) != recHash {
				return tampered(RejectSigInvalid, cached.Version)
			}
		}
	}
	return CachedBundleCheck{Integrity: orgcontract.BundleIntegrityVerified, Version: cached.Version}, nil
}

// missingOrAbsent classifies a cache path with no usable file (T-864 gap 1,
// and D-704's unreadable path): MISSING
// when this node recorded an accepted bundle for its org (a deletion: the
// policy poll re-downloads at once, and the report says so), ABSENT when it
// never accepted one (nothing was published, or the node is not enrolled).
func (c *Client) missingOrAbsent(ctx context.Context) (CachedBundleCheck, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return CachedBundleCheck{}, fmt.Errorf("orgclient.VerifyCachedPolicyBundle: %w", err)
	}
	if enr == nil {
		return CachedBundleCheck{Integrity: orgcontract.BundleIntegrityAbsent}, nil
	}
	recVersion, _, herr := c.recordedBundleHash(ctx, enr.OrgServerURL)
	if herr != nil {
		return CachedBundleCheck{}, fmt.Errorf("orgclient.VerifyCachedPolicyBundle: recorded hash: %w", herr)
	}
	if recVersion > 0 {
		return CachedBundleCheck{Integrity: orgcontract.BundleIntegrityMissing}, nil
	}
	return CachedBundleCheck{Integrity: orgcontract.BundleIntegrityAbsent}, nil
}

// recordedBundleHash returns the version and content hash of the last
// verified bundle this node recorded for orgURL (the fetched-bundle row),
// or (0, "") when none was recorded or the version does not parse.
func (c *Client) recordedBundleHash(ctx context.Context, orgURL string) (int64, string, error) {
	states, err := c.store.LatestGuardPolicyStates(ctx)
	if err != nil {
		return 0, "", err
	}
	bundlePath := policyBundleStatePath(orgURL)
	for _, st := range states {
		if st.Layer == "org" && st.Path == bundlePath {
			v, perr := strconv.ParseInt(st.Version, 10, 64)
			if perr != nil {
				return 0, "", nil
			}
			return v, st.ContentHash, nil
		}
	}
	return 0, "", nil
}

// KickPolicyBundlePoll wakes PolicyPollLoop now instead of at the next
// interval. Nonblocking and coalescing (the kick channel holds one). The
// policy-state reporter calls it when the on-disk bundle no longer
// verifies, so the repair (a re-download, T-846) does not wait up to an
// hour for the next poll.
func (c *Client) KickPolicyBundlePoll() {
	if c == nil || c.policyBundleKick == nil {
		return
	}
	select {
	case c.policyBundleKick <- struct{}{}:
	default:
	}
}

// heldBundleBound reports whether the bundle cached at path carries a v2
// binding. Any read or decode failure answers false (no binding to keep).
func heldBundleBound(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var held struct {
		Binding        *orgcontract.PolicyBinding  `json:"binding"`
		ProjectBinding *orgcontract.ProjectBinding `json:"project_binding"`
	}
	return json.Unmarshal(raw, &held) == nil && (held.Binding != nil || held.ProjectBinding != nil)
}

// Binding kinds of a bundle (bundleBindingKind, heldBindingKind).
const (
	bindingNone = ""
	bindingV2   = "v2"
	bindingV3   = "v3"
)

// bundleBindingKind names b's signature binding.
func bundleBindingKind(b orgcontract.PolicyBundle) string {
	switch {
	case b.ProjectBinding != nil:
		return bindingV3
	case b.Binding != nil:
		return bindingV2
	}
	return bindingNone
}

// heldBindingKind names the binding of the bundle cached at path (none when
// absent or unreadable).
func heldBindingKind(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return bindingNone
	}
	var held orgcontract.PolicyBundle
	if json.Unmarshal(raw, &held) != nil {
		return bindingNone
	}
	return bundleBindingKind(held)
}

// policyBindingCapsEditor asks the guard-bundle GET for a v2 (org- and
// member-bound) signature (orgcontract.PolicyBindingCapability). A plain query
// marker, not a generated parameter: a server that predates it ignores it and
// keeps serving v1.
func policyBindingCapsEditor(_ context.Context, req *http.Request) error {
	q := req.URL.Query()
	q.Add("policy_caps", orgcontract.PolicyBindingCapability)
	// binding-v3: the project audience (projectaudience.go). A server whose
	// org has no project-scoped bundle answers exactly as for binding-v2.
	q.Add("policy_caps", orgcontract.PolicyBindingV3Capability)
	if projectFamiliesAdvertised() {
		// project-families-v1 (lane sec-p3): the project envelopes may
		// carry family sections. A server whose org has none answers
		// exactly as for binding-v3 alone.
		q.Add("policy_caps", orgcontract.ProjectFamiliesCapability)
	}
	req.URL.RawQuery = q.Encode()
	return nil
}

// projectFamiliesAdvertised reports whether this build reads project family
// sections: the security.scanning compiler is linked (a build without the
// security module never asks, so it is never served a member it would drop).
// A test swaps it.
var projectFamiliesAdvertised = func() bool {
	return policyfam.IsFamilyLinked(policyfam.FamilySecurityScanning)
}

// writeFileAtomic writes data to path via a same-directory temp file +
// rename so the guard never reads a half-written envelope. 0600: the
// bundle is policy, not a secret, but it gates enforcement decisions —
// least privilege costs nothing here.
func writeFileAtomic(path string, data []byte) error {
	return fsatomic.WriteFile(path, data, fsatomic.Options{TempPattern: ".org-policy-bundle-*.tmp"})
}

// pinBase64Key decodes a base64url Ed25519 public key and returns its
// pin hash, validating the length. Shared by Enroll (enrol-time pin)
// and tests.
func pinBase64Key(b64 string) (string, error) {
	pub, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decode org policy public key: %w", err)
	}
	if len(pub) != 32 {
		return "", fmt.Errorf("org policy public key is %d bytes, want 32", len(pub))
	}
	return orgcontract.PublicKeyPinHash(pub), nil
}
