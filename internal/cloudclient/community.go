package cloudclient

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// community.go is the W5 cohort-benchmarking contribution upload leg
// (divergence-remediation plan §3 W5 "contribution-upload path"). It mirrors
// structural.go's discipline exactly: the node hands over the EXACT canonical
// bytes cloudevidence.SerializeCommunity produced and the client sends them
// verbatim. There is no re-serialization anywhere on this path.
//
// A community contribution carries the FULL standing-grant binding beside the
// body, exactly as a structural snapshot does: consent generation, data-
// dictionary digest, source-window rule AND declared timezone (Sol re-review
// N1/N5 — the rule used to be local receipt text only, and the timezone was
// recorded on the receipt but never transmitted, so the hosted grant carried
// ""). The server registers/validates the standing grant against all four.

// communityPath is the device-API route community contributions are POSTed to.
const communityPath = "/v1/community/contribution"

// communityFeature is the SBO-Feature label carried on a community upload.
const communityFeature = "community_contribution"

// headerDeclaredTimezone carries the standing grant's declared timezone. It
// joins the SBO-* grant-binding family (structural.go) — the same header
// convention the server's structural intake already reads for the other three
// values. The source-window rule reuses headerSourceWindowRule verbatim.
//
// ALIGNED with the hosted community intake
// (docs/plans/arc2-sol-rereview-server-fixes-notes-2026-09-02.md §N5): the
// server reads SBO-Declared-Timezone (must be "UTC" when present) and
// SBO-Source-Window-Rule (must equal cloudcontract.CommunitySourceWindowRule),
// refusing either mismatch with 403 grant_terms_mismatch.
const headerDeclaredTimezone = "SBO-Declared-Timezone"

// CommunityUploadRequest carries ONE immutable contribution for one
// (cohort, metric, version, window). Payload MUST be the exact bytes
// cloudevidence.SerializeCommunity produced and the store persisted; the
// client never re-serializes.
type CommunityUploadRequest struct {
	// Payload is the canonical contribution bytes, sent verbatim as the body.
	Payload []byte
	// Digest is the contribution's own NON-SELF-REFERENTIAL content digest
	// (over the canonical preimage with the digest field absent). As with
	// StructuralUploadRequest.Digest, it is not compared against a body digest
	// here — the final bytes embed the digest, so byte equality is proven
	// server-side by recomputing it from the bytes received.
	Digest string
	// ConsentGeneration is the monotonic terms-changed counter of the STANDING
	// community_cohort_benchmarking grant this contribution is being sent
	// under. The server refuses an upload declaring an older generation than
	// the one it has registered.
	ConsentGeneration int
	// DataDictionaryDigest is the schema-level digest the standing grant bound
	// (cloudcontract.CommunityDataDictionaryDigest at grant time). The server
	// refuses a digest that is not the one it currently serves.
	DataDictionaryDigest string
	// SourceWindowRule is the versioned rule the standing grant bound —
	// cloudcontract.CommunitySourceWindowRule at grant time — naming WHICH
	// activity a contribution covers (the in-progress UTC month). REQUIRED.
	SourceWindowRule string
	// DeclaredTimezone is the timezone the standing grant bound. The community
	// purpose is UTC-fixed (cloudcontract.CommunityDeclaredTimezone), and the
	// server records exactly what is declared here. REQUIRED.
	DeclaredTimezone string
	// PreAttempt, when non-nil, is invoked immediately before EVERY physical
	// HTTP attempt — the same FD3 authorization re-check hook Upload and
	// UploadStructural carry.
	PreAttempt func() error
	// DispatchGuard, when non-nil, is the cross-process dispatch lease taken
	// after PreAttempt and released after the attempt (Sol re-review N2). The
	// consent-gated seam requires it; here it is optional so the wire client
	// stays a plain transport.
	DispatchGuard DispatchGuard
}

// CommunityUploadResponse is the service's acknowledgement of a stored (or
// replay-acked) contribution.
type CommunityUploadResponse struct {
	ContributionID string `json:"contribution_id"`
	Status         string `json:"status"`
	// Replay reports that the server already held this exact (key, digest) and
	// re-acked rather than storing again.
	Replay bool `json:"replay"`
	// IdempotencyKey is the client key sent for this upload (set by the client
	// for the caller's observability; not part of the wire response).
	IdempotencyKey string `json:"-"`
}

// CommunityEndpoint returns the immutable absolute URL this client POSTs
// community contributions to.
func (c *Client) CommunityEndpoint() string { return c.baseURL + communityPath }

// UploadCommunity submits one immutable cohort-benchmarking contribution with
// device proof-of-possession. The Idempotency-Key binds device + digest, so a
// retry of the same contribution carries the same key and the server
// replay-acks instead of storing a duplicate.
//
// The SERVER ROUTE MAY NOT EXIST YET. A 404 or 501 is therefore a
// route-absence condition, not a rejection of the contribution: the caller
// classifies it as retryable rather than terminal, same as UploadStructural.
func (c *Client) UploadCommunity(ctx context.Context, req CommunityUploadRequest) (CommunityUploadResponse, error) {
	const pfx = "cloudclient.UploadCommunity"
	if len(req.Payload) == 0 {
		return CommunityUploadResponse{}, fmt.Errorf("%s: empty payload", pfx)
	}
	if req.Digest == "" {
		return CommunityUploadResponse{}, fmt.Errorf("%s: empty digest", pfx)
	}
	// The standing-grant binding is REQUIRED, not optional: a contribution sent
	// without it is one the server cannot check against what the developer
	// agreed to, and shipping it "so the upload succeeds" would be the consent
	// check failing open. Refuse here, before anything leaves.
	if req.ConsentGeneration < 1 {
		return CommunityUploadResponse{}, fmt.Errorf("%s: consent generation %d is not positive — a standing-grant upload must carry the grant's generation", pfx, req.ConsentGeneration)
	}
	if req.DataDictionaryDigest == "" {
		return CommunityUploadResponse{}, fmt.Errorf("%s: empty data-dictionary digest — a standing-grant upload must carry the schema digest the grant bound", pfx)
	}
	if req.SourceWindowRule == "" {
		return CommunityUploadResponse{}, fmt.Errorf("%s: empty source-window rule — a standing-grant upload must declare the window rule the grant bound", pfx)
	}
	if req.DeclaredTimezone == "" {
		return CommunityUploadResponse{}, fmt.Errorf("%s: empty declared timezone — a standing-grant upload must declare the timezone the grant bound", pfx)
	}

	idem := communityIdempotencyKey(c.dev.thumbprint, req.Digest)

	raw, err := c.sendAuthed(ctx, req.PreAttempt, req.DispatchGuard, func(int) (*http.Request, error) {
		return c.buildAuthed(ctx, http.MethodPost, communityPath, req.Payload, map[string]string{
			"Content-Type":             "application/json",
			headerIdempotency:          idem,
			headerFeature:              communityFeature,
			headerConsentGeneration:    strconv.Itoa(req.ConsentGeneration),
			headerDataDictionaryDigest: req.DataDictionaryDigest,
			headerSourceWindowRule:     req.SourceWindowRule,
			headerDeclaredTimezone:     req.DeclaredTimezone,
		})
	})
	if err != nil {
		return CommunityUploadResponse{}, fmt.Errorf("%s: %w", pfx, err)
	}
	var out CommunityUploadResponse
	// A route that answers 2xx with an empty body is acknowledged rather than
	// treated as a decode failure: the acknowledgement fields are observability,
	// not authorization.
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return CommunityUploadResponse{}, fmt.Errorf("%s: decode response: %w", pfx, err)
		}
	}
	out.IdempotencyKey = idem
	return out, nil
}

// communityIdempotencyKey derives the retry key for one contribution: a
// deterministic hash over device thumbprint + the contribution's own content
// digest. Unlike structuralIdempotencyKey there is no separate window key to
// fold in — the digest already covers the full (cohort, metric, version,
// window, value) identity, so hashing it alongside the device is sufficient.
func communityIdempotencyKey(deviceThumbprint, digest string) string {
	h := sha256.New()
	for _, part := range []string{deviceThumbprint, digest} {
		h.Write([]byte(part))
		h.Write([]byte{0x1f}) // unit separator: unambiguous field boundary
	}
	return "sbo-idem-community-" + b64.EncodeToString(h.Sum(nil))
}
