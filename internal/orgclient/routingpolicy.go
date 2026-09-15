package orgclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// RoutingFetchOutcome is the TOTAL, typed classification of ONE routing-policy
// poll cycle (P0-6 §2.5b). FetchRoutingPolicy returns at nine distinct sites
// (transport, 404, non-200, decode, cache-read, key-change, key-identity,
// sig-verify, cache-write); a bare (bool, error) cannot classify them honestly,
// so the reporter would misreport auth/local failures as control_plane_unreachable.
// Every return site maps to exactly one state here.
type RoutingFetchOutcome struct {
	OK            bool             // accepted+cached / already-current / 404 none-published
	Unreachable   bool             // transport error / timeout / 5xx — control plane down (Reached=false)
	AuthFailed    bool             // HTTP 401/403 — control plane REACHED, our credential rejected
	Indeterminate bool             // decode / cache / non-auth-4xx / pre-wire local — non-decisive
	Reached       bool             // TRUE iff any HTTP response was received (R5-B3). Any Reached outcome CLEARS a prior Unreachable.
	RejectCode    PolicyRejectCode // key_pin_mismatch / sig_invalid — the served body failed a gate
	Version       int64            // served version that failed a gate; 0 if none/unknown
}

// routingFetchStage identifies WHERE in FetchRoutingPolicy a branch returned so
// classification is a pure table over stages (classifyRoutingFetch) rather than
// error-string sniffing. Classifying at the source is what lets the total,
// testable classifier map every branch to exactly one RoutingFetchOutcome.
type routingFetchStage int

const (
	rfStageSkip            routingFetchStage = iota // context.Canceled — no outcome (shutdown, not a verdict)
	rfStagePreWire                                  // enrolment / bearer / request-construction — Indeterminate, not reached
	rfStageTransport                                // Do error / timeout — Unreachable, not reached
	rfStageHTTPStatus                               // classify by HTTP status (404/401/403/5xx/other)
	rfStageDecode                                   // JSON decode of a RECEIVED body — Indeterminate, reached
	rfStageCacheReadLocal                           // cache read — Indeterminate, not reached (local)
	rfStagePinStoreLocal                            // pin-store DB read — Indeterminate, not reached (local)
	rfStageKeyMismatch                              // cross-rail / own-rail key change — RejectKeyPinMismatch, reached
	rfStageSigInvalid                               // signature verify fail — RejectSigInvalid, reached
	rfStageCacheWriteLocal                          // cache write after verified body — Indeterminate, reached
	rfStageAccepted                                 // accepted / already-current — OK, reached
)

// routingFetchSignal is the outcome-relevant classification input from one
// FetchRoutingPolicy branch. classifyRoutingFetch turns it into a total outcome.
type routingFetchSignal struct {
	stage   routingFetchStage
	status  int   // HTTP status when stage == rfStageHTTPStatus
	version int64 // served version for reject / accepted branches
}

// classifyRoutingFetch maps one FetchRoutingPolicy branch signal to a TOTAL
// RoutingFetchOutcome (§2.5b). The second result reports whether an outcome
// should be EMITTED at all — context.Canceled is a shutdown, not a fetch
// verdict, so it emits nothing. Reached is set per §2.5b so the reporter's
// overwrite discipline can clear a stale Unreachable: auth/reached-local/reject
// are NEVER Unreachable — only genuine transport/timeout/5xx is.
func classifyRoutingFetch(sig routingFetchSignal) (RoutingFetchOutcome, bool) {
	switch sig.stage {
	case rfStageSkip:
		return RoutingFetchOutcome{}, false
	case rfStagePreWire:
		return RoutingFetchOutcome{Indeterminate: true, Reached: false}, true
	case rfStageTransport:
		return RoutingFetchOutcome{Unreachable: true, Reached: false}, true
	case rfStageHTTPStatus:
		return classifyRoutingHTTPStatus(sig.status), true
	case rfStageDecode:
		return RoutingFetchOutcome{Indeterminate: true, Reached: true}, true
	case rfStageCacheReadLocal, rfStagePinStoreLocal:
		return RoutingFetchOutcome{Indeterminate: true, Reached: false}, true
	case rfStageKeyMismatch:
		return RoutingFetchOutcome{RejectCode: RejectKeyPinMismatch, Reached: true, Version: sig.version}, true
	case rfStageSigInvalid:
		return RoutingFetchOutcome{RejectCode: RejectSigInvalid, Reached: true, Version: sig.version}, true
	case rfStageCacheWriteLocal:
		return RoutingFetchOutcome{Indeterminate: true, Reached: true}, true
	case rfStageAccepted:
		return RoutingFetchOutcome{OK: true, Reached: true, Version: sig.version}, true
	default:
		// Unreachable in practice; conservatively local + non-decisive.
		return RoutingFetchOutcome{Indeterminate: true, Reached: false}, true
	}
}

// classifyRoutingHTTPStatus maps a reached HTTP status to its outcome (§2.5b):
// 404 → OK (none published), 401/403 → AuthFailed, 5xx → Unreachable, every
// OTHER reached status (non-auth 4xx / 3xx / 429) → reached-Indeterminate (the
// control plane ANSWERED — NOT unavailable).
func classifyRoutingHTTPStatus(status int) RoutingFetchOutcome {
	switch {
	case status == http.StatusNotFound:
		return RoutingFetchOutcome{OK: true, Reached: true}
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return RoutingFetchOutcome{AuthFailed: true, Reached: true}
	case status >= 500 && status <= 599:
		return RoutingFetchOutcome{Unreachable: true, Reached: false}
	default:
		return RoutingFetchOutcome{Indeterminate: true, Reached: true}
	}
}

// SetRoutingOutcomeSink installs a callback that receives the typed
// RoutingFetchOutcome (§2.5b) for every decisive routing poll cycle. It is a
// nil-defaulted seam (R6-1): with no sink installed, PushLoop behaves EXACTLY
// as before (no-op). The P0-6 reporter installs its recorder here.
func (c *Client) SetRoutingOutcomeSink(sink func(RoutingFetchOutcome)) {
	c.routingOutcomeSink = sink
}

// SetRoutingReloadSink installs the P0-7 router hot-reload trigger, invoked
// AFTER a routing policy is accepted + cached (both the newly-cached and the
// already-current accepted arms — SF7 cold-recovery), so the caller can apply
// it to the live router in-process. Nil-defaulted additive seam (CLAUDE.md #6):
// with no sink installed, FetchRoutingPolicy behaves EXACTLY as before. It
// fires from INSIDE the fetch, before PushLoop pokes the P0-6 outcome sink
// (SF8 ordering).
func (c *Client) SetRoutingReloadSink(sink func(ctx context.Context)) {
	c.routingReloadSink = sink
}

// fireRoutingReload invokes the P0-7 reload sink when installed (no-op
// otherwise). Called on the accepted arms of fetchRoutingPolicy so the reload
// runs before the outcome sink poke (SF8).
func (c *Client) fireRoutingReload(ctx context.Context) {
	if c.routingReloadSink != nil {
		c.routingReloadSink(ctx)
	}
}

// FetchRoutingPolicy pulls the org's latest routing policy (§R19.1)
// over the enrolment bearer, caches it node-side after verifying:
//
//   - body hash matches,
//   - the Ed25519 signature verifies against the PINNED server key —
//     TOFU: the first received key is pinned with the cache row; a
//     later key change is REFUSED loudly (re-enrol to rotate trust).
//     WHICH signature is verified depends on what the document offers:
//     a doc carrying SignatureV2 is checked against the version-bound
//     v2 message and never falls back; a doc from a pre-v2 server is
//     checked against the legacy body-only signature
//     (docs/security.md ROUTING-SIG-1).
//   - a SERVED VERSION LOWER than the cached one is WARN-logged before
//     the monotonic short-circuit swallows it — visible in the routing
//     logs regardless of signature rail.
//
// Caching a policy never enables anything (§R23): the composer ignores
// enabled/mode keys; the node's own [routing] config is the only
// enforce switch. Returns changed=false when no policy is published.
//
// The second return is the TOTAL typed fetch outcome (§2.5b) for the P0-6
// reverse channel: non-nil on every DECISIVE cycle, nil to skip (context
// cancellation — a shutdown, not a fetch verdict). It is classified AT THE
// SOURCE so the caller never re-infers a verdict from the bare error.
func (c *Client) FetchRoutingPolicy(ctx context.Context) (bool, *RoutingFetchOutcome, error) {
	changed, sig, err := c.fetchRoutingPolicy(ctx)
	// ANY context.Canceled — not just the one tagged at the Do error site —
	// is a shutdown, not a fetch verdict: skip (no outcome). LoadEnrolment,
	// LoadBearer, NewRequestWithContext, the JSON decode, GetOrgRoutingPolicy,
	// checkOrgKeyIdentity (pin-store), and UpsertOrgRoutingPolicy can all
	// surface a wrapped context.Canceled on shutdown too; without this
	// universal guard they fall through to their stage's Indeterminate
	// classification instead of skipping (Blocker 2 / R5-NIT). errors.Is is
	// correctly false for context.DeadlineExceeded, so a timeout still
	// classifies as Unreachable via the stage table below, unaffected.
	if errors.Is(err, context.Canceled) {
		return changed, nil, err
	}
	outcome, emit := classifyRoutingFetch(sig)
	if !emit {
		return changed, nil, err
	}
	return changed, &outcome, err
}

// fetchRoutingPolicy is the inner poll: it performs the fetch + acceptance gate
// and tags each return with the classification signal for the exported wrapper.
// Splitting the classification out keeps the branch logic readable and makes
// classifyRoutingFetch unit-testable in isolation.
func (c *Client) fetchRoutingPolicy(ctx context.Context) (bool, routingFetchSignal, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return false, routingFetchSignal{stage: rfStagePreWire}, fmt.Errorf("orgclient.FetchRoutingPolicy: enrolment: %w", err)
	}
	if enr == nil {
		return false, routingFetchSignal{stage: rfStagePreWire}, ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return false, routingFetchSignal{stage: rfStagePreWire}, fmt.Errorf("orgclient.FetchRoutingPolicy: bearer: %w", err)
	}
	url := strings.TrimRight(enr.OrgServerURL, "/") + "/api/agent/routing-policy"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, routingFetchSignal{stage: rfStagePreWire}, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		// context.Canceled is a shutdown (skip), not a fetch verdict; any other
		// Do error is transport-class → Unreachable.
		if errors.Is(err, context.Canceled) {
			return false, routingFetchSignal{stage: rfStageSkip}, fmt.Errorf("orgclient.FetchRoutingPolicy: %w", err)
		}
		return false, routingFetchSignal{stage: rfStageTransport}, fmt.Errorf("orgclient.FetchRoutingPolicy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return false, routingFetchSignal{stage: rfStageHTTPStatus, status: resp.StatusCode}, nil // no policy published — fine
	}
	if resp.StatusCode != http.StatusOK {
		return false, routingFetchSignal{stage: rfStageHTTPStatus, status: resp.StatusCode},
			fmt.Errorf("orgclient.FetchRoutingPolicy: server returned %d", resp.StatusCode)
	}
	var doc orgcontract.RoutingPolicyDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return false, routingFetchSignal{stage: rfStageDecode}, fmt.Errorf("orgclient.FetchRoutingPolicy: decode: %w", err)
	}

	cached, hasCached, err := c.store.GetOrgRoutingPolicy(ctx)
	if err != nil {
		return false, routingFetchSignal{stage: rfStageCacheReadLocal}, err
	}
	pinned := doc.PublicKey // TOFU on first receipt
	// repinned records that this cycle ADOPTED a changed key because it is
	// the enrolment key (R1(c)). It has to reach the cache write, so it
	// suppresses the already-current short-circuit below for an equal or
	// newer version: otherwise the rail would agree the key changed and then
	// never write the new one down.
	repinned := false
	if hasCached {
		if cached.ServerPubkey != doc.PublicKey {
			if err := c.acceptOfferedKeyChange(ctx, routingPolicyRail, cached.ServerPubkey, doc.PublicKey); err != nil {
				return false, routingFetchSignal{stage: rfStageKeyMismatch, version: doc.Version},
					fmt.Errorf("orgclient.FetchRoutingPolicy: %w", err)
			}
			repinned = true
		}
		pinned = doc.PublicKey
		if !repinned {
			pinned = cached.ServerPubkey
		}
		if doc.Version < cached.Version {
			// INDEPENDENT of which signature rail the document rides:
			// a genuine org server's version is monotonic, so a LOWER
			// version means either a rollback the admin performed
			// out-of-band or a replay of an older document. Neither is
			// silently ignorable, and until now the monotonic
			// short-circuit below swallowed both without a word. This
			// WARN is deliberately not an error — the short-circuit
			// still correctly keeps the newer cached policy — but it
			// makes the regression VISIBLE in the routing logs
			// (docs/security.md ROUTING-SIG-1, the mitigation that
			// holds even for a pre-v2 server).
			c.logger.Warn("org routing policy version REGRESSION — server served an OLDER version than the node has cached; keeping the cached policy",
				"served_version", doc.Version, "cached_version", cached.Version)
		}
		if cached.Version >= doc.Version && !(repinned && doc.Version >= cached.Version) {
			// SF7: fire the reload on the already-current arm too — a boot that
			// rejected the cache then gets an already-current poll must still
			// converge the live router (the reload no-ops when already running).
			c.fireRoutingReload(ctx)
			return false, routingFetchSignal{stage: rfStageAccepted, version: cached.Version}, nil // already current
		}
	}
	// ONE org distribution identity across rails (orgpin.go). Symmetric
	// with FetchOrgAnnouncement on purpose: this rail's first fetch on a
	// node that already pinned the key elsewhere must present THAT key,
	// not merely some key. Cheap (one single-row read of a table this
	// package already owns) and non-breaking (the org server signs both
	// rails with the same key, so the pins can only disagree when the
	// key genuinely changed — which this rail already refuses once it
	// has a pin of its own).
	if err := c.checkOrgKeyIdentity(ctx, routingPolicyRail, doc.PublicKey); err != nil {
		// A pin-STORE read failure is a LOCAL error (Indeterminate), NOT a pin
		// mismatch (Reject) — the typed sentinel is the only honest
		// discriminator (R5-B6).
		if errors.Is(err, errPinStoreRead) {
			return false, routingFetchSignal{stage: rfStagePinStoreLocal}, fmt.Errorf("orgclient.FetchRoutingPolicy: %w", err)
		}
		return false, routingFetchSignal{stage: rfStageKeyMismatch, version: doc.Version}, fmt.Errorf("orgclient.FetchRoutingPolicy: %w", err)
	}
	// Rail selection is by PRESENCE, and it is one-way: a document that
	// carries a v2 signature is verified against the DOMAIN-SEPARATED,
	// VERSION-BOUND message and is NEVER re-tried on the v1 rail if that
	// fails. Falling back would restore exactly the replay v2 refuses (a
	// genuinely signed old body re-presented under an inflated version) by
	// letting an attacker strip nothing at all — just serve a broken v2.
	// The v1 leg remains only for a pre-078 org server, whose documents
	// carry no v2 signature at all (docs/security.md ROUTING-SIG-1).
	verify := orgcontract.VerifyRoutingPolicy
	if doc.SignatureV2 != "" {
		verify = orgcontract.VerifyRoutingPolicyV2
	}
	if err := verify(doc, pinned); err != nil {
		return false, routingFetchSignal{stage: rfStageSigInvalid, version: doc.Version}, fmt.Errorf("orgclient.FetchRoutingPolicy: %w", err)
	}
	if err := c.store.UpsertOrgRoutingPolicy(ctx, store.OrgRoutingPolicyRow{
		Version: doc.Version, Body: doc.Body, BodyHash: doc.BodyHash,
		Signature: doc.Signature, SignatureV2: doc.SignatureV2,
		ServerPubkey: pinned, ReceivedAt: time.Now().UTC(),
	}); err != nil {
		return false, routingFetchSignal{stage: rfStageCacheWriteLocal}, err
	}
	// M3: the trust root is mutated ONLY here — after the signature verified
	// and the rail cache write succeeded. A node whose enrolment stored only
	// the pin hash writes the key itself down now, so the rails that cannot
	// TOFU (budget, pricing) have a key to verify against.
	if repinned || !hasCached {
		c.adoptEnrolmentKeyMaterial(ctx, pinned)
	}
	c.logger.Info("org routing policy cached", "version", doc.Version, "hash", doc.BodyHash[:12])
	// SF7/§4.5: fire the reload AFTER the cache upsert succeeds so the live
	// router recomposes from the just-written cache (RunningVersion post-reload
	// == CachedAcceptedVersion). Before the outcome-sink poke (SF8).
	c.fireRoutingReload(ctx)
	return true, routingFetchSignal{stage: rfStageAccepted, version: doc.Version}, nil
}

func prefix8(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
