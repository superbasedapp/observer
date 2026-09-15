package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// BodyV1 is the org-wire v1 body for the gateway.providers family
// (docs/plans/gateway-config-plane-spec-2026-08-15.md Phase 3): the exact
// JSON shape an org publisher POSTs and an agent later finds inside a
// fetched SignedPolicyResource.Body:
//
//	{"upstreams":{"<lane-id>":{"base_url":"https://..."}},"auto_default_lane":"<lane-id>"}
type BodyV1 struct {
	Upstreams       map[string]UpstreamBodyV1 `json:"upstreams,omitempty"`
	AutoDefaultLane string                    `json:"auto_default_lane,omitempty"`
	// Mode / ModeSchemaVersion / Gateway are the OPTIONAL org-wide routing
	// mode block (Plane B P5b, Luna L14). Absent block ⇒ the body says
	// nothing about mode and the install seam preserves the live org-route
	// (byte-identical to a pre-P5b lane-only body). CLOSED-decoder note
	// (Sol S3): because DecodeBody uses DisallowUnknownFields, an OLDER agent
	// that predates these fields REFUSES the whole body and keeps routing
	// direct — which is exactly why Gateway Mode ships as a capability-gated
	// staged rollout (the server refuses activation until every active node
	// ACKs mode capability).
	//
	//   Mode              "" (absent — preserve) | "node" | "gateway"
	//   ModeSchemaVersion the mode-block schema version (>=1 when Mode set);
	//                     a value above SupportedModeSchemaVersion is rejected
	//                     reject-keep-last (Sol S3 unknown-version path).
	//   Gateway           the Gateway-Mode destination, required iff
	//                     Mode == "gateway".
	Mode              string         `json:"mode,omitempty"`
	ModeSchemaVersion int            `json:"mode_schema_version,omitempty"`
	Gateway           *GatewayBodyV1 `json:"gateway,omitempty"`
}

// UpstreamBodyV1 is the wire shape of one lane's upstream definition. It is
// a one-field object (rather than a bare string) so the wire shape can grow
// per-lane fields later (e.g. headers, timeouts) without a breaking change.
type UpstreamBodyV1 struct {
	BaseURL string `json:"base_url"`
}

// GatewayBodyV1 is the wire shape of the Gateway-Mode destination + fallback
// ladder (Sol S10). The ladder is a VALIDATED state machine, not a list:
// `try-gateways[]` (Primary first, then each Fallbacks entry in order) →
// exactly ONE terminal policy (TerminalPolicy). It is compiled and validated
// at publish AND at node-accept time (both run through CompileBody), so an
// inconsistent ladder is rejected as a body, never partially applied. Each
// URL is an absolute http/https base URL.
type GatewayBodyV1 struct {
	Primary   string   `json:"primary"`
	Fallbacks []string `json:"fallbacks,omitempty"`
	// TerminalPolicy is the ONE terminal rung reached after every gateway
	// endpoint in the try[] is exhausted (Sol S10):
	//   "hold"        (default) — fail-closed queue-and-hold: the node proxy
	//                  returns a structured rung/remedy error the agent can
	//                  act on, retries with backoff, and the dashboard raises
	//                  a fleet alert. Custody is preserved.
	//   "break_glass" — the body carries only the PERMISSION for break-glass
	//                  direct credentials; the credentials themselves are
	//                  per-machine secret leases delivered on the enrolment
	//                  rail, never in this org-wide-readable body.
	//   "direct"      — auto-fallback-to-direct: custody becomes convention
	//                  while active. OFF by default and requires an explicit
	//                  DirectFallbackCustodyAck so it can never be enabled
	//                  without acknowledging the custody downgrade.
	// Empty ⇒ "hold" (the safe default).
	TerminalPolicy string `json:"terminal_policy,omitempty"`
	// DirectFallbackCustodyAck must be true when TerminalPolicy == "direct":
	// the publisher explicitly acknowledges that enabling auto-fallback-to-
	// direct converts custody into convention while the fallback is active
	// (it needs standing pre-provisioned node-side credentials, so it weakens
	// custody even while the gateway is healthy). Ignored for other policies.
	DirectFallbackCustodyAck bool `json:"direct_fallback_custody_ack,omitempty"`
}

// ToPolicyInput maps the wire body onto the pure engine's input, including
// the optional mode block.
func (b BodyV1) ToPolicyInput() PolicyInput {
	in := PolicyInput{
		AutoDefaultLane:   b.AutoDefaultLane,
		Mode:              b.Mode,
		ModeSchemaVersion: b.ModeSchemaVersion,
	}
	if len(b.Upstreams) > 0 {
		in.Upstreams = make(map[string]string, len(b.Upstreams))
		for id, u := range b.Upstreams {
			in.Upstreams[id] = u.BaseURL
		}
	}
	if b.Gateway != nil {
		in.GatewayPrimary = b.Gateway.Primary
		in.GatewayFallbacks = b.Gateway.Fallbacks
		in.TerminalPolicy = b.Gateway.TerminalPolicy
		in.DirectFallbackCustodyAck = b.Gateway.DirectFallbackCustodyAck
	}
	return in
}

// BodyV1FromPolicyInput is the inverse of ToPolicyInput, letting a server
// GET surface or a config-derived body reconstruct the wire shape.
func BodyV1FromPolicyInput(in PolicyInput) BodyV1 {
	b := BodyV1{
		AutoDefaultLane:   in.AutoDefaultLane,
		Mode:              in.Mode,
		ModeSchemaVersion: in.ModeSchemaVersion,
	}
	if len(in.Upstreams) > 0 {
		b.Upstreams = make(map[string]UpstreamBodyV1, len(in.Upstreams))
		for id, base := range in.Upstreams {
			b.Upstreams[id] = UpstreamBodyV1{BaseURL: base}
		}
	}
	if in.Mode == ModeGateway || in.GatewayPrimary != "" || len(in.GatewayFallbacks) > 0 {
		b.Gateway = &GatewayBodyV1{
			Primary:                  in.GatewayPrimary,
			Fallbacks:                in.GatewayFallbacks,
			TerminalPolicy:           in.TerminalPolicy,
			DirectFallbackCustodyAck: in.DirectFallbackCustodyAck,
		}
	}
	return b
}

// DecodeBody strictly decodes raw org-wire JSON bytes into a BodyV1: unknown
// fields are rejected (DisallowUnknownFields), the document must not exceed
// maxBytes, and any byte after the JSON value is rejected — the same
// closed-document discipline as policyfam/admission.DecodeBody, reimplemented
// here so this package stays free of an orgcontract import and can compile a
// body standalone for internal/orgserver/internal/orgclient callers.
func DecodeBody(raw []byte, maxBytes int64) (BodyV1, error) {
	if maxBytes <= 0 {
		return BodyV1{}, fmt.Errorf("policyfam/providers.DecodeBody: cap must be positive, got %d", maxBytes)
	}
	if int64(len(raw)) > maxBytes {
		return BodyV1{}, fmt.Errorf("policyfam/providers.DecodeBody: body is %d bytes, exceeds the %d-byte cap", len(raw), maxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var body BodyV1
	if err := dec.Decode(&body); err != nil {
		return BodyV1{}, fmt.Errorf("policyfam/providers.DecodeBody: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return BodyV1{}, fmt.Errorf("policyfam/providers.DecodeBody: trailing bytes after the document")
	}
	return body, nil
}

// CanonicalJSON re-encodes a decoded BodyV1 deterministically. encoding/json
// marshals map keys in sorted order, so the lane table's key order never
// depends on how the original bytes were formatted; BodyHash is computed
// over exactly this output, never over whatever bytes a publisher happened
// to submit — so two semantically-equal bodies published a character apart
// (extra whitespace, reordered keys) hash identically.
func CanonicalJSON(b BodyV1) ([]byte, error) {
	out, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("policyfam/providers.CanonicalJSON: %w", err)
	}
	return out, nil
}

// CompileBody decodes and canonicalizes raw org-wire JSON, then compiles it
// into a ready PolicySpec. It returns the canonical JSON bytes the caller
// should sign/hash as the resource's Body — so BodyHash is always computed
// over exactly the bytes DecodeBody would reproduce from that Body, never
// over the publisher's raw submission.
func CompileBody(raw []byte, maxBytes int64) (spec PolicySpec, canonicalBody []byte, err error) {
	body, err := DecodeBody(raw, maxBytes)
	if err != nil {
		return PolicySpec{}, nil, err
	}
	canon, err := CanonicalJSON(body)
	if err != nil {
		return PolicySpec{}, nil, err
	}
	spec, err = Compile(body.ToPolicyInput())
	if err != nil {
		return PolicySpec{}, nil, fmt.Errorf("policyfam/providers.CompileBody: %w", err)
	}
	return spec, canon, nil
}
