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
	"path/filepath"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/policyfam/admission"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Plane-A P0-5 unified policy resource, agent side (docs/plane-a/
// unified-policy-resource.md §6-7; docs/plans/
// plane-a-p0-5-unified-policy-resource-v1-plan.md §6.3-§6.10). This file
// generalizes internal/orgclient/policy.go's guard-bundle four-gate accept
// into the family-tagged SignedPolicyResource rail: GET
// /api/agent/policy/{family}, verify, decode/compile via internal/policyfam,
// and durably CAS-write the accepted envelope under a generation fence
// (internal/store/policyresource.go).
//
// Phase-A scope: this file implements FETCH + ACCEPT + the durable cache/
// state write. It does NOT install into any live orgLayer/AdmissionService
// — that wiring (PublishOrg, start.go LKG-before-listener, Check's
// generation-fence recheck) is Phase W. A caller here gets back a
// PolicyResourceResult describing exactly what was verified/cached/rejected
// and can act on EnforceAllowed/InertReason once that wiring exists.
//
// Manual HTTP GET (not the generated gen.ClientWithResponses client): the
// server-side /api/agent/policy/{family} endpoint is Phase S's addition to
// the OpenAPI spec and generated client. Wiring it here now, by hand,
// avoids a merge collision with that generated-code regeneration while
// still exercising the exact wire contract (SignedPolicyResource JSON,
// ETag/If-None-Match) Phase S will implement server-side.

// DefaultMaxPolicyResourceBodyBytes bounds the decoded Body size handed to
// policyfam's decode/compile step when PolicyResourceOptions.MaxBodyBytes
// is unset.
const DefaultMaxPolicyResourceBodyBytes int64 = 1 << 20 // 1 MiB

// NormalizeOrgURL trims trailing slashes/whitespace the same way Enroll
// does, so OrgKey is computed identically regardless of how the caller
// spells the org server URL.
func NormalizeOrgURL(url string) string {
	return strings.TrimRight(strings.TrimSpace(url), "/")
}

// OrgKey returns the plan §6.2 enrolment-identity key:
// hex(SHA256(normalizedOrgURL + "\x00" + OrgID)). This is deliberately NOT
// just the server URL — two organisations enrolled through one
// control-plane URL must never share replay floors, cached envelopes, or
// ETags.
func OrgKey(orgURL, orgID string) string {
	sum := sha256.Sum256([]byte(NormalizeOrgURL(orgURL) + "\x00" + orgID))
	return hex.EncodeToString(sum[:])
}

// PolicyResourceStatus classifies one policy-resource fetch+accept cycle
// for a single family (design doc §7's four-gate accept, generalized from
// PolicyStatus above for the P0-5 unified resource).
type PolicyResourceStatus string

const (
	// PRApplied — a new version passed every gate, needs no
	// preauthorization (or is preauthorized), and the durable cache +
	// state were replaced.
	PRApplied PolicyResourceStatus = "applied"
	// PRAppliedInert — the version passed every gate and WAS durably
	// cached, but its family/mode combination is not preauthorized for
	// live enforcement (EnforceAllowed=false, InertReason=not_preauthorized,
	// plan §6.4). Distinct from a capability_mismatch rejection: this body
	// is fully runnable, just not operator-authorized to enforce yet.
	PRAppliedInert PolicyResourceStatus = "applied_inert"
	// PRUnchanged — 304, or a 200 whose version equals the durable floor
	// with an identical signing-message digest (no reinstall needed).
	PRUnchanged PolicyResourceStatus = "unchanged"
	// PRNone — 404: no resource published for this family (or a pre-P0-5
	// server).
	PRNone PolicyResourceStatus = "none"
	// PRDeliveredUnaccepted — gates 1-5 (signature, pin, closed envelope,
	// decode/compile, capabilities) passed, but the family is not in
	// [org_client.policy].accept_families: fetched and verified, but never
	// cached/installed (plan §6.6 — "poll both families whenever enrolled,
	// independent of accept_families").
	PRDeliveredUnaccepted PolicyResourceStatus = "delivered_unaccepted"
	// PRRejected — a gate failed, or the durable CAS fence detected a
	// concurrent identity/floor change. The previous cache/state is
	// untouched.
	PRRejected PolicyResourceStatus = "rejected"
)

// PolicyResourceRejectCode is the typed reason a delivered policy resource
// failed the four-gate accept (mirrors PolicyRejectCode above for the
// guard-bundle rail).
type PolicyResourceRejectCode string

// PolicyResourceRejectCode values — one per accept gate, in gate order
// (see acceptPolicyResource).
const (
	PRRejectNone               PolicyResourceRejectCode = ""
	PRRejectSigInvalid         PolicyResourceRejectCode = "sig_invalid"
	PRRejectKeyPinMismatch     PolicyResourceRejectCode = "key_pin_mismatch"
	PRRejectClosedEnvelope     PolicyResourceRejectCode = "closed_envelope_violation"
	PRRejectDecodeFailed       PolicyResourceRejectCode = "decode_failed"
	PRRejectCapabilityMismatch PolicyResourceRejectCode = "capability_mismatch"
	// PRRejectVersionDowngrade and PRRejectVersionReplay are evaluated
	// INSIDE the durable CAS fence (store.WithPolicyResourceFence), against
	// the re-read floor/digest — never the pre-transaction snapshot.
	PRRejectVersionDowngrade PolicyResourceRejectCode = "version_downgrade"
	PRRejectVersionReplay    PolicyResourceRejectCode = "version_replay"
	// PRRejectIdentityChanged fires when the fenced re-read finds the
	// enrolment generation advanced (or was tombstoned) between the start
	// of this fetch and the commit attempt — a concurrent unenrol/re-enrol
	// raced this poll (plan §6.9/§6.10).
	PRRejectIdentityChanged PolicyResourceRejectCode = "identity_changed"
	// PRRejectSelectorMismatch is the P0-10 Phase B targeting-corroboration
	// rejection (docs/plans/policy-targeting-rollback-design-2026-08-13.md
	// §2): the envelope's signed selectors CONTRADICT an attribute this node
	// has locally configured. The prior LKG is retained. Distinct from the
	// grammar gate (PRRejectClosedEnvelope) — the envelope is well-formed
	// and correctly signed, it just is not addressed to this node.
	PRRejectSelectorMismatch PolicyResourceRejectCode = "selector_mismatch"
	// PRRejectFamilyNotAccepted is the gen2 P4-2 reject code: the envelope
	// verified, decoded, and passed every capability/selector gate, but this
	// node's own [org_client.policy].accept_families allow-list does not
	// name the family — the node declined it, as opposed to being unable to
	// honor it. Distinct from PRRejectCapabilityMismatch, which stays
	// reserved for true capability/version-subset failures (and the earlier
	// closed-envelope/decode gates keep their own codes) — conflating a
	// deliberate opt-out with an incapability would corrupt the honest
	// accounting orgcontract.ReasonFamilyNotAccepted exists to give. It
	// pairs with PRDeliveredUnaccepted only (see acceptPolicyResource).
	PRRejectFamilyNotAccepted PolicyResourceRejectCode = "family_not_accepted"
)

// PolicyResourceResult summarises one policy-resource fetch+accept cycle.
type PolicyResourceResult struct {
	Status     PolicyResourceStatus
	Version    int64
	RejectCode PolicyResourceRejectCode
	Detail     string // human-readable specifics — MUST NOT ride any wire
	// EnforceAllowed / InertReason are only meaningful on PRApplied /
	// PRAppliedInert; both are the zero value otherwise.
	EnforceAllowed bool
	InertReason    string
	// CachePath is the generation-scoped file the verified envelope was
	// (or already was) durably written to.
	CachePath string
	// Family is the family this result was fetched for — carried on the
	// result itself (rather than requiring every caller to thread the
	// family string alongside it) so a Phase W poller iterating both v1
	// families can dispatch on the result alone.
	Family string
	// OrgKey / Generation are the enrolment identity this fetch was
	// captured under (plan §6.10) — the Phase W caller passes these
	// straight into obs.OrgLayerMeta when calling PublishOrg*, without
	// re-deriving them or re-reading the store.
	OrgKey     string
	Generation int64
	// BodyHash is the org-published body's content hash
	// (SignedPolicyResource.BodyHash), only meaningful on PRApplied /
	// PRAppliedInert / PRUnchanged (an unchanged fetch still knows the
	// durable hash from the fence).
	BodyHash string
	// Spec is the compiled family spec (as returned by
	// policyfam.CompileFamilyBody — an `any` here so this package need not
	// import policyfam's admission/egress subpackages or internal/obs;
	// callers that downcast do so at their own boundary, exactly like
	// policyfam.SpecRequestsEnforceMode's contract). Populated on
	// PRApplied / PRAppliedInert only — a caller must not read it on any
	// other status.
	Spec any
}

// PolicyResourceOptions parameterizes FetchAndAcceptPolicyResource.
type PolicyResourceOptions struct {
	// CacheDir is the base directory for the generation-scoped cache tree
	// (plan §6.2): <CacheDir>/<org_key>/<generation>/<family>.json.
	CacheDir string
	// LiveCapabilities is the SET of capability tokens this node's runtime
	// currently advertises for `family` (plan §6.6's closed capability
	// registry — resolved by the CALLER, not this package, since it is a
	// property of the live AdmissionService/egress engine Phase W wires
	// in). A resource whose RequiredCapabilities is not a subset of this
	// set is rejected capability_mismatch. Nil/empty means no capabilities
	// advertised — a resource with ANY required capability then always
	// fails, which is the correct fail-closed default before Phase W wires
	// a real capability source.
	LiveCapabilities []string
	// AcceptFamilies is [org_client.policy].accept_families — the closed
	// set of families this node installs into its durable cache. A family
	// outside this set is still fetched, verified, and reported, but never
	// cached (PRDeliveredUnaccepted).
	AcceptFamilies []string
	// PreauthorizeEnforce is [org_client.policy].preauthorize_enforce — the
	// subset of AcceptFamilies preauthorized for live "enforce" mode
	// (config.Validate enforces the subset relationship at load time).
	PreauthorizeEnforce []string
	// MaxBodyBytes bounds the decoded Body size handed to policyfam's
	// decode/compile step. 0 = DefaultMaxPolicyResourceBodyBytes.
	MaxBodyBytes int64
	// NodeAttrs are this node's LOCALLY-CONFIGURED targeting attributes
	// ([org_client.policy] node_workspace/node_environment/node_service).
	// They are CORROBORATION input only, never authorization: the server
	// resolves the authoritative attributes from the verified bearer's
	// identity and decides which resource to serve, and this check can only
	// narrow what the node then installs (design §2). The zero value = no
	// attributes configured = accept every targeted envelope, logging it as
	// uncorroborated — that is what keeps an upgrade from breaking a fleet
	// that has not configured attributes yet.
	NodeAttrs orgcontract.Selectors
}

// Fetch-outcome classification sentinels (mirrors errPolicyTransport /
// errPolicyReachedIndeterminate in policy.go). Phase A collapses the guard
// rail's three-way local/reached split into two: no P0-6-style reporter
// consumes ClassifyPolicyResourceFetch yet, so the finer Reached=false-vs-
// true distinction for local errors has no observer this milestone. Phase W
// can split errPolicyResourceIndeterminate the same way if/when it wires a
// reporter for this rail.
var (
	// errPolicyResourceTransport tags a transport error / timeout / 5xx.
	errPolicyResourceTransport = errors.New("orgclient: policy-resource fetch transport failure")
	// errPolicyResourceIndeterminate tags every other non-decisive local or
	// reached-but-ambiguous failure (decode errors, local store errors, an
	// other-reached HTTP status).
	errPolicyResourceIndeterminate = errors.New("orgclient: policy-resource fetch indeterminate")
)

// PolicyResourceFetchOutcome is the TOTAL, typed classification of one
// FetchAndAcceptPolicyResource call (mirrors GuardFetchOutcome).
type PolicyResourceFetchOutcome struct {
	OK            bool
	Unreachable   bool
	AuthFailed    bool
	Indeterminate bool
	Reached       bool
	Cleared       bool // ErrNotEnrolled — wipe prior slot (Codex SF4)
	RejectCode    PolicyResourceRejectCode
	Version       int64
}

// ClassifyPolicyResourceFetch maps one FetchAndAcceptPolicyResource
// (PolicyResourceResult, error) return to a TOTAL PolicyResourceFetchOutcome.
// The second result reports whether an outcome should be emitted to a sink
// at all — context.Canceled is a shutdown/no-op signal. ErrNotEnrolled emits
// Cleared=true so reporters wipe stale slots (Codex SF4).
func ClassifyPolicyResourceFetch(res PolicyResourceResult, err error) (PolicyResourceFetchOutcome, bool) {
	switch {
	case errors.Is(err, context.Canceled):
		return PolicyResourceFetchOutcome{}, false
	case errors.Is(err, ErrNotEnrolled):
		// Codex SF4: still emit a Cleared outcome so the reporter drops stale
		// reject/unreachable slots when identity is gone (not a silent skip).
		return PolicyResourceFetchOutcome{Cleared: true}, true
	case errors.Is(err, ErrAuthFailed):
		return PolicyResourceFetchOutcome{AuthFailed: true, Reached: true}, true
	case errors.Is(err, errPolicyResourceTransport):
		return PolicyResourceFetchOutcome{Unreachable: true}, true
	case errors.Is(err, errPolicyResourceIndeterminate):
		return PolicyResourceFetchOutcome{Indeterminate: true, Reached: true}, true
	case err != nil:
		return PolicyResourceFetchOutcome{Indeterminate: true}, true
	default:
		return PolicyResourceFetchOutcome{OK: true, Reached: true, RejectCode: res.RejectCode, Version: res.Version}, true
	}
}

// FetchAndAcceptPolicyResource performs one poll of
// GET /api/agent/policy/{family} and runs the four-gate accept (plan
// §6.3-§6.10). Returns ErrNotEnrolled when the agent has no enrolment (or
// its enrolment identity is tombstoned), ErrAuthFailed on 401/403, and a
// retryable error (tagged errPolicyResourceTransport) on transport/5xx
// failures.
func (c *Client) FetchAndAcceptPolicyResource(ctx context.Context, family string, opts PolicyResourceOptions) (PolicyResourceResult, error) {
	if !policyfam.IsSupportedFamily(family) {
		return PolicyResourceResult{}, fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: unsupported family %q", family)
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return PolicyResourceResult{}, fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: %w: %w", errPolicyResourceIndeterminate, err)
	}
	if enr == nil {
		return PolicyResourceResult{}, ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if errors.Is(err, ErrNoSecret) {
		return PolicyResourceResult{}, ErrNotEnrolled
	}
	if err != nil {
		return PolicyResourceResult{}, fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: load bearer: %w: %w", errPolicyResourceIndeterminate, err)
	}

	orgKey := OrgKey(enr.OrgServerURL, enr.OrgID)
	genRow, ok, err := c.store.LoadEnrolmentGeneration(ctx, orgKey)
	if err != nil {
		return PolicyResourceResult{}, fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: load generation: %w: %w", errPolicyResourceIndeterminate, err)
	}
	// Plan §6.9 / R6-B2: a missing generation row is fail-closed (never
	// treat as generation 0) — Enroll must have activated one, and a
	// corrupt/incomplete state must not install policy.
	if !ok {
		return PolicyResourceResult{}, fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: %w: no enrolment generation row", ErrNotEnrolled)
	}
	if genRow.Tombstoned {
		return PolicyResourceResult{}, fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: %w: enrolment identity is tombstoned", ErrNotEnrolled)
	}
	capturedGeneration := genRow.Generation

	cachePath := filepath.Join(opts.CacheDir, orgKey, strconv.FormatInt(capturedGeneration, 10), family+".json")
	etag, err := c.store.LoadPolicyResourceETag(ctx, orgKey, capturedGeneration, family)
	if err != nil {
		return PolicyResourceResult{}, fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: load etag: %w: %w", errPolicyResourceIndeterminate, err)
	}

	resource, early, hasEarly, rawBody, respETag, err := c.receivePolicyResource(ctx, enr.OrgServerURL, family, bearer, etag, cachePath)
	if err != nil {
		return PolicyResourceResult{}, err
	}
	if hasEarly {
		early.Family, early.OrgKey, early.Generation = family, orgKey, capturedGeneration
		return early, nil
	}

	res, err := c.acceptPolicyResource(ctx, enr, orgKey, capturedGeneration, family, resource, rawBody, respETag, cachePath, opts)
	// Phase W convenience (§6.10): every non-error result carries the
	// identity/family it was fetched under, so the caller (the
	// cmd/observer poller) can call PublishOrg*/ClearOrg without
	// re-deriving OrgKey or re-reading the generation row itself.
	res.Family, res.OrgKey, res.Generation = family, orgKey, capturedGeneration
	return res, err
}

// receivePolicyResource performs the raw GET and classifies the
// reached-vs-transport disposition, mirroring receiveBundle in policy.go.
func (c *Client) receivePolicyResource(ctx context.Context, orgURL, family, bearer, etag, cachePath string) (
	resource orgcontract.SignedPolicyResource, early PolicyResourceResult, hasEarly bool, rawBody []byte, respETag string, err error,
) {
	// The URL (including the R2 selector-capability marker) is composed by
	// policyResourceFetchURL — see its comment for why self-declaring the
	// capability is safe.
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, policyResourceFetchURL(orgURL, family), nil)
	if rerr != nil {
		return orgcontract.SignedPolicyResource{}, PolicyResourceResult{}, false, nil, "",
			fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: build request: %w: %w", errPolicyResourceIndeterminate, rerr)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if etag != "" {
		if _, statErr := os.Stat(cachePath); statErr == nil {
			req.Header.Set("If-None-Match", etag)
		}
	}
	resp, derr := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, derr)
	if derr != nil {
		if errors.Is(derr, context.Canceled) {
			return orgcontract.SignedPolicyResource{}, PolicyResourceResult{}, false, nil, "",
				fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: get: %w", derr)
		}
		return orgcontract.SignedPolicyResource{}, PolicyResourceResult{}, false, nil, "",
			fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: get: %w: %w", errPolicyResourceTransport, derr)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// fall through to body decode below
	case http.StatusNotModified:
		// Plan §4.4 / Codex SF1: a 304 still re-validates the on-disk envelope
		// through the full accept gates (signature/pin/closed-envelope/…).
		// Load the cache as if it were a 200 body so acceptPolicyResource runs;
		// missing/corrupt cache is indeterminate (caller blanks ETag + refetch).
		raw, rerr := os.ReadFile(cachePath)
		if rerr != nil {
			return orgcontract.SignedPolicyResource{}, PolicyResourceResult{}, false, nil, "",
				fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: 304 but cache unreadable: %w: %w", errPolicyResourceIndeterminate, rerr)
		}
		var cached orgcontract.SignedPolicyResource
		if uerr := json.Unmarshal(raw, &cached); uerr != nil {
			return orgcontract.SignedPolicyResource{}, PolicyResourceResult{}, false, nil, "",
				fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: 304 but cache corrupt: %w: %w", errPolicyResourceIndeterminate, uerr)
		}
		return cached, PolicyResourceResult{}, false, raw, resp.Header.Get("ETag"), nil
	case http.StatusNotFound:
		return orgcontract.SignedPolicyResource{}, PolicyResourceResult{Status: PRNone, Detail: "no resource published for this family"}, true, nil, "", nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return orgcontract.SignedPolicyResource{}, PolicyResourceResult{}, false, nil, "",
			fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: %w", ErrAuthFailed)
	default:
		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			return orgcontract.SignedPolicyResource{}, PolicyResourceResult{}, false, nil, "",
				fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: server returned %d: %w", resp.StatusCode, errPolicyResourceTransport)
		}
		return orgcontract.SignedPolicyResource{}, PolicyResourceResult{}, false, nil, "",
			fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: server returned %d: %w", resp.StatusCode, errPolicyResourceIndeterminate)
	}

	body, rerr2 := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if rerr2 != nil {
		return orgcontract.SignedPolicyResource{}, PolicyResourceResult{}, false, nil, "",
			fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: read body: %w: %w", errPolicyResourceIndeterminate, rerr2)
	}
	var r orgcontract.SignedPolicyResource
	if uerr := json.Unmarshal(body, &r); uerr != nil {
		return orgcontract.SignedPolicyResource{}, PolicyResourceResult{}, false, nil, "",
			fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: decode: %w: %w", errPolicyResourceIndeterminate, uerr)
	}
	return r, PolicyResourceResult{}, false, body, resp.Header.Get("ETag"), nil
}

// acceptPolicyResourceGates runs signature/pin/closed-envelope/compile/
// capability/accept-list gates (plan §6.3–§6.6). On success returns the
// compiled spec plus preauthorization posture for the CAS install.
func (c *Client) acceptPolicyResourceGates(
	ctx context.Context, enr *store.Enrolment, family string,
	resource orgcontract.SignedPolicyResource, opts PolicyResourceOptions,
) (spec any, enforceAllowed bool, inertReason string, early PolicyResourceResult, hasEarly bool, err error) {
	pub, verr := orgcontract.VerifyPolicyResource(resource)
	if verr != nil {
		return nil, false, "", PolicyResourceResult{
			Status: PRRejected, Version: resource.Version, RejectCode: PRRejectSigInvalid,
			Detail: fmt.Sprintf("signature verification failed: %v", verr),
		}, true, nil
	}
	keyHash := orgcontract.PublicKeyPinHash(pub)
	pinned, perr := c.loadKeyPin(ctx, enr.OrgServerURL)
	if perr != nil {
		return nil, false, "", PolicyResourceResult{}, false, fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: read key pin: %w: %w", errPolicyResourceIndeterminate, perr)
	}
	// Gate 2 (TOFU key pin). The read above is only a fast path for the
	// steady state (already pinned); it is NOT the decision. When it reports
	// no pin, establishment goes through the store's atomic
	// compare-if-absent primitive, which returns whatever pin is
	// authoritative after its commit — this call's key when it won the race,
	// the winner's key when it did not (review finding B-B6: the previous
	// read-then-append let two concurrent first-accepts pin DIFFERENT keys
	// and both proceed). Either way the verification below runs against the
	// authoritative pin, never against this goroutine's own snapshot.
	racedPin := false
	offeredKey := base64.StdEncoding.EncodeToString(pub)
	if pinned == "" {
		// C1: establishing the shared `#policy-key` row is a trust decision
		// this rail must not make alone — it writes the very row the enrolment
		// channel writes. Cross-check against every pin the node already holds
		// first; a disagreement is refused, not TOFU'd.
		if idErr := c.checkOrgKeyIdentity(ctx, policyResourceRail, offeredKey); idErr != nil {
			if errors.Is(idErr, errPinStoreRead) {
				return nil, false, "", PolicyResourceResult{}, false, fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: pin key: %w: %w", errPolicyResourceIndeterminate, idErr)
			}
			return nil, false, "", PolicyResourceResult{
				Status: PRRejected, Version: resource.Version, RejectCode: PRRejectKeyPinMismatch,
				Detail: idErr.Error(),
			}, true, nil
		}
		authoritative, established, pinErr := c.store.EstablishOrgPolicyKeyPin(ctx, PolicyKeyPinPath(enr.OrgServerURL), keyHash, railPinProvenance)
		if pinErr != nil {
			return nil, false, "", PolicyResourceResult{}, false, fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: pin key: %w: %w", errPolicyResourceIndeterminate, pinErr)
		}
		pinned = authoritative
		racedPin = !established
		if established {
			c.logger.Info("org policy resource: signing key pinned on first fetch", "key_sha256", keyHash, "family", family)
		}
	}
	if pinned == keyHash {
		// M4: the resource's signature verified under these key BYTES and they
		// match the pin, so a hash-only enrolment can learn its key here too.
		// Provenance is re-checked inside (C1).
		c.adoptEnrolmentKeyMaterial(ctx, offeredKey)
	}
	if pinned != keyHash {
		detail := "signing key does not match the enrolment pin (re-enrol if the org key legitimately rotated)"
		if racedPin {
			detail += "; a concurrent first fetch established a different key"
		}
		return nil, false, "", PolicyResourceResult{
			Status: PRRejected, Version: resource.Version, RejectCode: PRRejectKeyPinMismatch,
			Detail: detail,
		}, true, nil
	}
	if resource.ID != "default" || resource.Family != family ||
		resource.Version <= 0 || resource.CompilerVersion != "v1" {
		return nil, false, "", PolicyResourceResult{
			Status: PRRejected, Version: resource.Version, RejectCode: PRRejectClosedEnvelope,
			Detail: fmt.Sprintf("v1 closed envelope violation: id=%q family=%q version=%d compiler=%q (want id=%q family=%q version>0 compiler=%q)",
				resource.ID, resource.Family, resource.Version, resource.CompilerVersion,
				"default", family, "v1"),
		}, true, nil
	}
	// Gate 3b (P0-10 Phase B, design §2 step 1): the targeting field's VALUE
	// is open, its GRAMMAR is not. selectors_json must be within the size
	// bound and byte-identical to its own canonical form — a semantically
	// equal but non-canonical spelling is a closed-envelope violation, never
	// something this side normalizes away.
	selectors, selErr := orgcontract.ValidateCanonicalSelectorsJSON(resource.SelectorsJSON)
	if selErr != nil {
		return nil, false, "", PolicyResourceResult{
			Status: PRRejected, Version: resource.Version, RejectCode: PRRejectClosedEnvelope,
			Detail: fmt.Sprintf("v1 closed envelope violation: %v", selErr),
		}, true, nil
	}
	// Gate 3c (design §2 step 2): soft-strict targeting corroboration
	// against locally-configured node attributes. A CONTRADICTED attribute
	// rejects (prior LKG retained); an attribute this node has not
	// configured is uncorroborated — logged, never blocking.
	if mismatched, uncorroborated := orgcontract.CorroborateSelectors(selectors, opts.NodeAttrs); len(mismatched) > 0 {
		return nil, false, "", PolicyResourceResult{
			Status: PRRejected, Version: resource.Version, RejectCode: PRRejectSelectorMismatch,
			Detail: fmt.Sprintf("selectors %s contradict this node's configured [org_client.policy] attributes on %s",
				resource.SelectorsJSON, strings.Join(mismatched, ",")),
		}, true, nil
	} else if len(uncorroborated) > 0 {
		c.logger.Info("org policy resource: targeted envelope accepted without local corroboration",
			"family", family, "version", resource.Version, "selectors", resource.SelectorsJSON,
			"uncorroborated_attrs", strings.Join(uncorroborated, ","))
	}
	maxBytes := opts.MaxBodyBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxPolicyResourceBodyBytes
	}
	spec, _, cerr := policyfam.CompileFamilyBody(family, []byte(resource.Body), maxBytes)
	if cerr != nil {
		return nil, false, "", PolicyResourceResult{
			Status: PRRejected, Version: resource.Version, RejectCode: PRRejectDecodeFailed,
			Detail: fmt.Sprintf("body failed to decode/compile: %v", cerr),
		}, true, nil
	}
	if adm, ok := spec.(admission.PolicySpec); ok {
		if vcap := admission.ValidateRuntimeCaps(adm, stringInSet("judge", opts.LiveCapabilities)); vcap != nil {
			return nil, false, "", PolicyResourceResult{
				Status: PRRejected, Version: resource.Version, RejectCode: PRRejectCapabilityMismatch,
				Detail: vcap.Error(),
			}, true, nil
		}
	}
	if !capabilitiesSubset(resource.RequiredCapabilities, opts.LiveCapabilities) {
		return nil, false, "", PolicyResourceResult{
			Status: PRRejected, Version: resource.Version, RejectCode: PRRejectCapabilityMismatch,
			Detail: fmt.Sprintf("required capabilities %v are not a subset of live capabilities %v", resource.RequiredCapabilities, opts.LiveCapabilities),
		}, true, nil
	}
	if !stringInSet(family, opts.AcceptFamilies) {
		return nil, false, "", PolicyResourceResult{
			Status: PRDeliveredUnaccepted, Version: resource.Version,
			RejectCode: PRRejectFamilyNotAccepted,
			Detail:     "family verified but not in [org_client.policy].accept_families — not installed",
		}, true, nil
	}
	enforceAllowed = true
	if policyfam.SpecRequestsEnforceMode(family, spec) && !stringInSet(family, opts.PreauthorizeEnforce) {
		enforceAllowed = false
		inertReason = "not_preauthorized"
	}
	return spec, enforceAllowed, inertReason, PolicyResourceResult{}, false, nil
}

// acceptPolicyResource runs the four-gate accept (signature, pin, closed
// envelope, decode/compile, capabilities, acceptance configuration,
// preauthorization) and — only when every gate up to and including
// acceptance configuration passes — the durable CAS-fenced install
// (plan §6.10).
func (c *Client) acceptPolicyResource(
	ctx context.Context, enr *store.Enrolment, orgKey string, capturedGeneration int64, family string,
	resource orgcontract.SignedPolicyResource, rawBody []byte, respETag, cachePath string, opts PolicyResourceOptions,
) (PolicyResourceResult, error) {
	spec, enforceAllowed, inertReason, early, hasEarly, err := c.acceptPolicyResourceGates(ctx, enr, family, resource, opts)
	if err != nil {
		return PolicyResourceResult{}, err
	}
	if hasEarly {
		return early, nil
	}

	digest, derr := orgcontract.PolicyResourceMessageDigest(resource)
	if derr != nil {
		return PolicyResourceResult{}, fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: digest: %w: %w", errPolicyResourceIndeterminate, derr)
	}

	var result PolicyResourceResult
	fenceErr := c.store.WithPolicyResourceFence(ctx, orgKey, family, func(_ context.Context, fence store.PolicyResourceFence) (*store.PolicyResourceCommit, error) {
		if fence.Tombstoned || fence.Generation != capturedGeneration {
			result = PolicyResourceResult{
				Status: PRRejected, Version: resource.Version, RejectCode: PRRejectIdentityChanged,
				Detail: "enrolment identity changed during fetch (a concurrent unenrol/re-enrol raced this poll)",
			}
			return nil, nil
		}
		if resource.Version < fence.FloorVersion {
			result = PolicyResourceResult{
				Status: PRRejected, Version: resource.Version, RejectCode: PRRejectVersionDowngrade,
				Detail: fmt.Sprintf("version regression: served %d after %d (rollback = publish old content as a new version)", resource.Version, fence.FloorVersion),
			}
			return nil, nil
		}
		if resource.Version == fence.FloorVersion && fence.HasState {
			if digest != fence.MsgDigest {
				result = PolicyResourceResult{
					Status: PRRejected, Version: resource.Version, RejectCode: PRRejectVersionReplay,
					Detail: fmt.Sprintf("version replay: served version %d with a signing-message digest differing from the durable one (non-monotonic republish — bump the version to change content)", resource.Version),
				}
				return nil, nil
			}
			// Plan §6.5 / R5-B2: equal-floor + matching digest must still
			// rematerialize a missing on-disk cache (floor-without-cache is
			// not permanently non-executable).
			if _, statErr := os.Stat(cachePath); statErr != nil {
				if err := writeFileAtomicFsync(cachePath, rawBody); err != nil {
					return nil, fmt.Errorf("rematerialize cache: %w", err)
				}
			}
			result = PolicyResourceResult{
				Status: PRUnchanged, Version: resource.Version, CachePath: cachePath,
				Spec: spec, BodyHash: resource.BodyHash, EnforceAllowed: enforceAllowed, InertReason: inertReason,
			}
			return nil, nil
		}

		if err := writeFileAtomicFsync(cachePath, rawBody); err != nil {
			return nil, fmt.Errorf("write cache: %w", err)
		}

		status := PRApplied
		if !enforceAllowed {
			status = PRAppliedInert
		}
		result = PolicyResourceResult{
			Status: status, Version: resource.Version, EnforceAllowed: enforceAllowed,
			InertReason: inertReason, CachePath: cachePath,
			Spec: spec, BodyHash: resource.BodyHash,
		}
		return &store.PolicyResourceCommit{
			Generation: fence.Generation, FloorVersion: resource.Version, LastVersion: resource.Version,
			BodyHash: resource.BodyHash, MsgDigest: digest,
		}, nil
	})
	if fenceErr != nil {
		if errors.Is(fenceErr, store.ErrPolicyResourceFenceStale) {
			return PolicyResourceResult{
				Status: PRRejected, Version: resource.Version, RejectCode: PRRejectIdentityChanged,
				Detail: "durable state changed concurrently during commit",
			}, nil
		}
		return PolicyResourceResult{}, fmt.Errorf("orgclient.FetchAndAcceptPolicyResource: %w: %w", errPolicyResourceIndeterminate, fenceErr)
	}

	if result.Status == PRApplied || result.Status == PRAppliedInert {
		if err := c.store.SavePolicyResourceETag(ctx, orgKey, capturedGeneration, family, respETag); err != nil {
			c.logger.Warn("org policy resource: etag save failed (next poll re-downloads)", "err", err, "family", family)
		}
		c.logger.Info("org policy resource: applied", "family", family, "version", resource.Version,
			"enforce_allowed", enforceAllowed, "inert_reason", inertReason)
	}
	return result, nil
}

// capabilitiesSubset reports whether every token in required also appears
// in live. An empty required list is trivially satisfied.
func capabilitiesSubset(required, live []string) bool {
	if len(required) == 0 {
		return true
	}
	liveSet := make(map[string]bool, len(live))
	for _, c := range live {
		liveSet[c] = true
	}
	for _, c := range required {
		if !liveSet[c] {
			return false
		}
	}
	return true
}

// stringInSet reports whether s appears in set.
func stringInSet(s string, set []string) bool {
	for _, v := range set {
		if v == s {
			return true
		}
	}
	return false
}

// writeFileAtomicFsync durably writes data to path via a same-directory
// temp file: write, fsync the file, atomic rename, then fsync the
// containing directory (plan §6.3/§6.10 — "write ... and fsync the file;
// rename it atomically ... and fsync the containing directory"). Called
// from INSIDE the store.WithPolicyResourceFence transaction, so the
// database's write lock is held for the whole sequence — the ordering, not
// merely the fsyncs, is what the plan requires (no concurrent commit can
// advance the generation or floor while this file is becoming the
// installable cache). 0600: policy is not a secret, but it gates
// enforcement decisions.
func writeFileAtomicFsync(path string, data []byte) error {
	return fsatomic.WriteFile(path, data, fsatomic.Options{TempPattern: ".policy-resource-*.tmp", Fsync: true})
}
