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
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient/gen"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
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
//  4. The TOML lints as an org-layer policy file (guard.Lint with the
//     escalate-only floor checks), so a malformed or floor-violating
//     bundle never evicts a good cache.
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
func policyBundleStatePath(orgURL string) string { return orgURL + "/api/v1/policy-bundle" }

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

	// If-None-Match only when the cache file actually exists — a stored
	// ETag with a deleted cache must re-download, not 304 into nothing.
	params := &gen.GetPolicyBundleParams{}
	if etag, eerr := c.store.LoadOrgPolicyETag(ctx); eerr == nil && etag != "" {
		if _, serr := os.Stat(cachePath); serr == nil {
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
		}
		return early, nil
	}

	if rej, rejected, err := c.applyBundleGates(ctx, b, enr, cachePath); err != nil {
		return PolicyResult{}, err
	} else if rejected {
		return rej, nil
	}

	// Accepted: atomically replace the cache, record the version row,
	// remember the ETag.
	raw, err := json.Marshal(b)
	if err != nil {
		return PolicyResult{}, fmt.Errorf("orgclient.FetchPolicyBundle: marshal cache: %w: %w", errPolicyLocalPreResponse, err)
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
	return PolicyResult{Status: PolicyApplied, Version: b.Version}, nil
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
	resp, err := gc.GetPolicyBundle(ctx, params, bearerEditor(bearer))
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

	switch resp.StatusCode {
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
	bodyBytes, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
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
			if hex.EncodeToString(incoming[:]) == cachedHash {
				// Identical content already current → no reload (SF-B).
				return PolicyResult{Status: PolicyUnchanged, Version: b.Version, CachedVersion: cachedVer}, true, nil
			}
			// Same version, different content → non-monotonic republish.
			return PolicyResult{
				Status: PolicyRejected, Version: b.Version, RejectCode: RejectVersionReplay,
				Detail: fmt.Sprintf("version replay: served version %d with content differing from the cached bundle (non-monotonic republish — bump the version to change content)", b.Version),
			}, true, nil
		}
		// No usable cached baseline (cache absent/corrupt/unverifiable)
		// at an equal recorded version: fall through to accept so the
		// missing cache is re-materialised (SF7 corrupt-cache redownload
		// stays a documented residual, but a MISSING cache must be
		// rewritten).
	}

	// Gate 4: the TOML must lint as an org-layer policy file so a
	// malformed or floor-violating bundle never evicts a good cache.
	if problems := guard.Lint([]byte(b.BundleTOML), "org"); len(problems) > 0 {
		return PolicyResult{
			Status: PolicyRejected, Version: b.Version, RejectCode: RejectLintFailed,
			Detail: fmt.Sprintf("bundle does not lint as an org policy file: %s", problems[0]),
		}, true, nil
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
	return c.runLoop(ctx, c.policyPollInterval(), cycle)
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
// A genuine read error (permissions) is returned so the caller
// classifies it as a local, non-decisive failure. The hash uses the
// SAME canonical bytes ([]byte(BundleTOML)) the accept path and the
// guard's PolicyState.ContentHash use, so equal content compares
// byte-equal.
func (c *Client) readCachedBundle(ctx context.Context, cachePath, orgURL string) (version int64, contentHash string, ok bool, err error) {
	raw, rerr := os.ReadFile(cachePath)
	switch {
	case os.IsNotExist(rerr):
		return 0, "", false, nil
	case rerr != nil:
		return 0, "", false, rerr
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
