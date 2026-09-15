package cloudclient

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// structural.go is the structural-insights upload leg (divergence-remediation
// plan rev 4.1 §3 W2 "Node half" sync path). It is deliberately thin: the node
// hands over the EXACT stored canonical bytes and the client sends them
// verbatim, exactly as Upload does for a session envelope. There is no
// re-serialization anywhere on this path.

// structuralPath is the device-API route structural snapshots are POSTed to.
const structuralPath = "/v1/structural-insights"

// structuralFeature is the SBO-Feature label carried on a structural upload.
const structuralFeature = "structural_insights"

// The STANDING-GRANT binding headers (divergence-remediation plan rev 4.1 §2
// R1 + §3 W2 "Server half"). The server validates the upload against the
// account's registered standing grant, and the three values it needs — which
// consent generation the terms were agreed at, which schema-level data
// dictionary the grant bound, and which versioned source-window rule it covers
// — describe the GRANT, not the window.
//
// They ride as REQUEST HEADERS rather than snapshot fields on purpose: the
// snapshot's canonical bytes are what the digest covers, and adding grant
// metadata to them would (a) change every existing digest and the pinned
// data-dictionary digest itself, and (b) put mutable consent state inside an
// IMMUTABLE window — a snapshot queued under generation 4 would become
// unsendable the moment the developer re-confirmed to generation 5, even though
// nothing about the window changed. The body stays exactly the stored canonical
// bytes; the grant binding travels beside it.
//
// They are not covered by the proof-of-possession signature (which binds
// method, URL and BODY digest), and they do not need to be: the request as a
// whole is authenticated by the bearer + PoP pair, so only the device itself
// can put a value in them, and the server treats every one of them as a claim
// to be checked against its own registration rather than as an authorization.
const (
	headerConsentGeneration    = "SBO-Consent-Generation"
	headerDataDictionaryDigest = "SBO-Data-Dictionary-Digest"
	headerSourceWindowRule     = "SBO-Source-Window-Rule"
)

// StructuralUploadRequest carries ONE immutable snapshot window. Payload MUST be
// the exact bytes cloudevidence.SerializeStructural produced and the store
// persisted; the client never re-serializes.
type StructuralUploadRequest struct {
	// Payload is the canonical snapshot bytes, sent verbatim as the body.
	Payload []byte
	// Period is the "YYYY-MM-DD" window in the account's declared timezone.
	Period string
	// PeriodRuleVersion versions the activity→period mapping rule.
	PeriodRuleVersion int
	// SchemaVersion is the snapshot schema the bytes were built against.
	SchemaVersion string
	// Revision is the 1-based revision of this window.
	Revision int
	// Digest is the snapshot's own NON-SELF-REFERENTIAL content digest (over the
	// canonical preimage with the digest field absent).
	//
	// It is deliberately NOT compared against a body digest here, and that is a
	// real difference from Upload: a session envelope's UploadDigest IS the
	// digest of the final bytes, so the client can and does verify the caller
	// did not re-serialize. A structural snapshot's digest covers the preimage,
	// which by construction differs from the final bytes (the final bytes embed
	// the digest). The server recomputes this value from the bytes it received
	// using the same preimage rule, so byte equality is still proven — just
	// server-side, from the received bytes, rather than by a client self-check.
	Digest string
	// ConsentGeneration is the monotonic terms-changed counter of the STANDING
	// grant this window is being sent under. The server refuses an upload
	// declaring an older generation than the one it has registered.
	ConsentGeneration int
	// DataDictionaryDigest is the schema-level digest the standing grant bound
	// (cloudcontract.StructuralDataDictionaryDigest at grant time). The server
	// refuses a digest that is not the one it currently serves.
	DataDictionaryDigest string
	// SourceWindowRule is the versioned rule naming WHICH activity the standing
	// grant covers. Recorded on the server's registration as part of the R1
	// binding set; it is not itself a gate.
	SourceWindowRule string
	// PreAttempt, when non-nil, is invoked immediately before EVERY physical
	// HTTP attempt — the same FD3 authorization re-check hook Upload carries.
	PreAttempt func() error
	// DispatchGuard, when non-nil, is the cross-process dispatch lease taken
	// after PreAttempt and released after the attempt (Sol re-review N2). The
	// consent-gated seam (internal/cloudgateway) requires it; here it is
	// optional so the wire client stays a plain transport.
	DispatchGuard DispatchGuard
}

// StructuralUploadResponse is the service's acknowledgement of a stored (or
// replay-acked) snapshot window.
type StructuralUploadResponse struct {
	SnapshotID string `json:"snapshot_id"`
	Status     string `json:"status"`
	// Replay reports that the server already held this exact (key, digest) and
	// re-acked rather than storing again.
	Replay bool `json:"replay"`
	// IdempotencyKey is the client key sent for this upload (set by the client
	// for the caller's observability; not part of the wire response).
	IdempotencyKey string `json:"-"`
}

// StructuralEndpoint returns the immutable absolute URL this client POSTs
// structural snapshots to. store.PrepareStructuralSend compares it against the
// standing receipt's bound endpoint, so a snapshot can only ever go to the
// origin+path the developer consented to (FD1).
func (c *Client) StructuralEndpoint() string { return c.baseURL + structuralPath }

// UploadStructural submits one immutable snapshot window with device
// proof-of-possession. The Idempotency-Key binds device + window key + revision
// + digest, so a retry of the same snapshot carries the same key and the server
// replay-acks instead of storing a duplicate.
//
// The SERVER ROUTE MAY NOT EXIST YET (it lands with the W2 server half). A 404
// or 501 is therefore a route-absence condition, not a rejection of the
// snapshot: the caller classifies it as retryable rather than terminal, so a
// node that syncs before the server ships keeps its queued windows instead of
// burning them.
func (c *Client) UploadStructural(ctx context.Context, req StructuralUploadRequest) (StructuralUploadResponse, error) {
	const pfx = "cloudclient.UploadStructural"
	if len(req.Payload) == 0 {
		return StructuralUploadResponse{}, fmt.Errorf("%s: empty payload", pfx)
	}
	if req.Period == "" {
		return StructuralUploadResponse{}, fmt.Errorf("%s: empty period", pfx)
	}
	if req.PeriodRuleVersion < 1 {
		return StructuralUploadResponse{}, fmt.Errorf("%s: period rule version %d is not positive", pfx, req.PeriodRuleVersion)
	}
	if req.Revision < 1 {
		return StructuralUploadResponse{}, fmt.Errorf("%s: revision %d is not positive", pfx, req.Revision)
	}
	if req.SchemaVersion == "" {
		return StructuralUploadResponse{}, fmt.Errorf("%s: empty schema version", pfx)
	}
	if req.Digest == "" {
		return StructuralUploadResponse{}, fmt.Errorf("%s: empty digest", pfx)
	}
	// The standing-grant binding is REQUIRED, not optional: a snapshot sent
	// without it is a snapshot the server cannot check against what the
	// developer agreed to, and shipping it "so the upload succeeds" would be the
	// consent check failing open. Refuse here, before anything leaves.
	if req.ConsentGeneration < 1 {
		return StructuralUploadResponse{}, fmt.Errorf("%s: consent generation %d is not positive — a standing-grant upload must carry the grant's generation", pfx, req.ConsentGeneration)
	}
	if req.DataDictionaryDigest == "" {
		return StructuralUploadResponse{}, fmt.Errorf("%s: empty data-dictionary digest — a standing-grant upload must carry the schema digest the grant bound", pfx)
	}

	idem := structuralIdempotencyKey(c.dev.thumbprint, req.Period, req.PeriodRuleVersion,
		req.SchemaVersion, req.Revision, req.Digest)

	raw, err := c.sendAuthed(ctx, req.PreAttempt, req.DispatchGuard, func(int) (*http.Request, error) {
		return c.buildAuthed(ctx, http.MethodPost, structuralPath, req.Payload, map[string]string{
			"Content-Type":             "application/json",
			headerIdempotency:          idem,
			headerFeature:              structuralFeature,
			headerConsentGeneration:    strconv.Itoa(req.ConsentGeneration),
			headerDataDictionaryDigest: req.DataDictionaryDigest,
			headerSourceWindowRule:     req.SourceWindowRule,
		})
	})
	if err != nil {
		return StructuralUploadResponse{}, fmt.Errorf("%s: %w", pfx, err)
	}
	var out StructuralUploadResponse
	// A route that answers 2xx with an empty body is acknowledged rather than
	// treated as a decode failure: the acknowledgement fields are observability,
	// not authorization.
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return StructuralUploadResponse{}, fmt.Errorf("%s: decode response: %w", pfx, err)
		}
	}
	out.IdempotencyKey = idem
	return out, nil
}

// structuralIdempotencyKey derives the retry key for one snapshot window: a
// deterministic hash over device thumbprint + the full window key + revision +
// digest. It mirrors idempotencyKey's construction (unit-separated fields) but
// over the structural key set — a window has no cloud session id, and its
// revision is load-bearing.
func structuralIdempotencyKey(deviceThumbprint, period string, periodRuleVersion int, schemaVersion string, revision int, digest string) string {
	h := sha256.New()
	for _, part := range []string{
		deviceThumbprint,
		period,
		strconv.Itoa(periodRuleVersion),
		schemaVersion,
		strconv.Itoa(revision),
		digest,
	} {
		h.Write([]byte(part))
		h.Write([]byte{0x1f}) // unit separator: unambiguous field boundary
	}
	return "sbo-idem-struct-" + b64.EncodeToString(h.Sum(nil))
}
