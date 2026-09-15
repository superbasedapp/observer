package providers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// reservedAutoLaneID mirrors internal/proxy's autoLaneID constant. "auto" is
// the virtual model-prefix-routed lane (gateway-config-plane-spec-2026-08-15
// Phase 2); a dashboard-managed body can never define or default to a lane
// by that name. The two constants are intentionally duplicated rather than
// shared — this package must not import internal/proxy (purity,
// imports_test.go).
const reservedAutoLaneID = "auto"

// Mode-block vocabulary (Plane B P5b, Luna L14 — the versioned mode body,
// docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md §3.2).
// The gateway.providers body's optional mode block carries the org-wide
// routing mode. Three body states, chosen so a lane-only body preserves a
// node-local [proxy.org_route] bootstrap rather than clobbering it:
//
//	Mode == ""        the body says nothing about mode → the install seam
//	                  PRESERVES the currently-live org-route (bootstrap or a
//	                  prior org mode). Byte-identical to a pre-P5b lane body.
//	Mode == "node"    the org EXPLICITLY selects Node Mode → clear the
//	                  org-route (default-lane traffic goes direct).
//	Mode == "gateway" the org selects Gateway Mode → repoint default-lane
//	                  traffic at Gateway.Primary with the fallback ladder.
//
// ModeNode maps to internal/proxy's orgModeNode ("") and ModeGateway to its
// orgModeGateway ("gateway") at the install seam — the two vocabularies are
// deliberately kept distinct (this package must not import internal/proxy).
const (
	ModeUnset   = ""
	ModeNode    = "node"
	ModeGateway = "gateway"
)

// Fallback-ladder terminal policies (Sol S10). The ladder is try-gateways[]
// → exactly one of these. TerminalHold is the safe default (fail-closed
// queue-and-hold); TerminalBreakGlass carries only the permission (leases
// ride the enrolment rail); TerminalDirect (auto-fallback-to-direct) requires
// an explicit custody-downgrade acknowledgment.
const (
	TerminalHold       = "hold"
	TerminalBreakGlass = "break_glass"
	TerminalDirect     = "direct"
)

// SupportedModeSchemaVersion is the highest mode-block schema this build
// understands. A body whose mode_schema_version exceeds it is REJECTED and
// the node keeps its last-good policy (reject-keep-last), surfacing an
// R-205-style rejection event — the Sol S3 "unknown-version" path. Bump this
// only when the mode block gains a new understood shape.
const SupportedModeSchemaVersion = 1

// ErrUnknownModeSchemaVersion is returned by Compile when a mode body's
// schema version exceeds SupportedModeSchemaVersion. The node-accept path
// maps it to reject-keep-last + an R-205-style event; callers test for it
// with errors.Is.
var ErrUnknownModeSchemaVersion = errors.New("providers: unknown mode_schema_version (reject-keep-last)")

// PolicySpec is the compiled, ready-to-apply gateway.providers policy: a
// validated lane table plus an optional default lane for the virtual "auto"
// lane's fallback. Hash is the content address of the policy (audit
// provenance; mirrors policyfam/admission.PolicySpec.Hash).
type PolicySpec struct {
	// Upstreams maps lane id -> validated absolute http/https base URL
	// string. Kept as strings (not net.URL) because the only consumer,
	// internal/proxy.Proxy.SetLaneTable, re-parses and re-validates its own
	// input independently — this package's job is to reject a malformed
	// body before it is ever signed/published, not to hand the proxy a
	// pre-parsed value it must trust.
	Upstreams map[string]string
	// AutoDefaultLane names the lane the virtual "auto" lane falls back to
	// when a request's model prefix matches no configured lane. Empty means
	// no default is configured (the "auto" lane then behaves as an unknown
	// upstream — fail-open per Phase 2).
	AutoDefaultLane string
	// Mode is the compiled org-wide routing mode (ModeUnset / ModeNode /
	// ModeGateway). ModeUnset means the body carried no mode block — the
	// install seam preserves the live org-route. See the mode constants.
	Mode string
	// GatewayPrimary / GatewayFallbacks are the validated Gateway-Mode
	// destination and fallback ladder (absolute http/https URLs). Non-empty
	// only when Mode == ModeGateway.
	GatewayPrimary   string
	GatewayFallbacks []string
	// TerminalPolicy is the compiled terminal rung (TerminalHold /
	// TerminalBreakGlass / TerminalDirect), defaulted to TerminalHold.
	// DirectFallbackCustodyAck echoes the publisher's custody-downgrade
	// acknowledgment (meaningful only for TerminalDirect). Both are empty/
	// false unless Mode == ModeGateway.
	TerminalPolicy           string
	DirectFallbackCustodyAck bool
	Hash                     string
}

// TryLadder returns the ordered gateway endpoints the runtime fallback state
// machine walks (Primary first, then each fallback), followed by the terminal
// policy. It is the compiled shape a node-side executor consumes (Sol S10):
// walk each entry in order; on exhaustion apply TerminalPolicy.
func (s PolicySpec) TryLadder() (endpoints []string, terminal string) {
	if s.Mode != ModeGateway {
		return nil, ""
	}
	endpoints = make([]string, 0, 1+len(s.GatewayFallbacks))
	endpoints = append(endpoints, s.GatewayPrimary)
	endpoints = append(endpoints, s.GatewayFallbacks...)
	terminal = s.TerminalPolicy
	if terminal == "" {
		terminal = TerminalHold
	}
	return endpoints, terminal
}

// OrgRoute returns the compiled org-route in the vocabulary
// internal/proxy.Proxy.SetOrgGatewayRoute / SetRoutingSnapshot accept: mode
// is "" (node — proxy orgModeNode) or "gateway" (proxy orgModeGateway), with
// primary + fallbacks meaningful only in gateway mode. ModeUnset maps to ""
// (the install seam distinguishes "preserve" from "clear" by consulting
// HasModeBlock, not this — this reports the mode the body would install).
func (s PolicySpec) OrgRoute() (mode, primary string, fallbacks []string) {
	switch s.Mode {
	case ModeGateway:
		return "gateway", s.GatewayPrimary, s.GatewayFallbacks
	default:
		return "", "", nil
	}
}

// HasModeBlock reports whether the body explicitly carried a mode block
// (ModeNode or ModeGateway). When false (ModeUnset) the install seam PRESERVES
// the live org-route rather than clearing it — the lane-only-body compat path.
func (s PolicySpec) HasModeBlock() bool {
	return s.Mode == ModeNode || s.Mode == ModeGateway
}

// UpstreamsAsStringMap returns a defensive copy of the compiled lane table
// (lane id -> base_url) — the exact shape internal/proxy.Proxy.SetLaneTable
// accepts, so the cmd/observer install seam never has to know this
// package's internal representation.
func (s PolicySpec) UpstreamsAsStringMap() map[string]string {
	out := make(map[string]string, len(s.Upstreams))
	for id, base := range s.Upstreams {
		out[id] = base
	}
	return out
}

// PolicyInput is the plain, pre-compile policy. It mirrors BodyV1 field for
// field; the only difference is BodyV1 carries JSON tags and this package
// never imports encoding/json opinions into the compile step itself.
type PolicyInput struct {
	Upstreams       map[string]string
	AutoDefaultLane string
	// Mode / GatewayPrimary / GatewayFallbacks / ModeSchemaVersion carry the
	// optional mode block (P5b). Mode is ModeUnset / ModeNode / ModeGateway.
	// ModeSchemaVersion is the mode-block schema discriminant — present iff a
	// mode block is set; a value above SupportedModeSchemaVersion is rejected
	// by Compile with ErrUnknownModeSchemaVersion (reject-keep-last).
	Mode                     string
	GatewayPrimary           string
	GatewayFallbacks         []string
	ModeSchemaVersion        int
	TerminalPolicy           string
	DirectFallbackCustodyAck bool
}

// Compile validates a PolicyInput and produces a ready PolicySpec. It
// enforces the wire-shape invariants frozen by the spec:
//
//   - at least one upstream is required;
//   - every lane id is nonempty and not the reserved "auto" id;
//   - every base_url parses as an absolute http/https URL;
//   - auto_default_lane, when set, must name a key of upstreams (which,
//     since "auto" can never be a key, also rejects "auto" as a default).
//
// A malformed body is a hard error so it is caught at compile/publish time,
// never at request time on the proxy hot path.
func Compile(in PolicyInput) (PolicySpec, error) {
	// Validate the optional mode block first (P5b). A mode body may carry NO
	// /up lanes (the org-route alone repoints default-lane traffic), so the
	// "at least one upstream" rule below is waived when a mode block is set.
	mode, gwPrimary, gwFallbacks, terminal, err := compileMode(in)
	if err != nil {
		return PolicySpec{}, err
	}
	hasMode := mode == ModeNode || mode == ModeGateway
	if len(in.Upstreams) == 0 && !hasMode {
		return PolicySpec{}, fmt.Errorf("providers.Compile: at least one upstream is required")
	}
	upstreams := make(map[string]string, len(in.Upstreams))
	for id, raw := range in.Upstreams {
		id = strings.TrimSpace(id)
		if id == "" {
			return PolicySpec{}, fmt.Errorf("providers.Compile: upstream lane id must not be empty")
		}
		if id == reservedAutoLaneID {
			return PolicySpec{}, fmt.Errorf("providers.Compile: %q is a reserved lane id", reservedAutoLaneID)
		}
		if err := validateBaseURL(raw); err != nil {
			return PolicySpec{}, fmt.Errorf("providers.Compile: lane %q: %w", id, err)
		}
		upstreams[id] = raw
	}
	if in.AutoDefaultLane != "" {
		if _, ok := upstreams[in.AutoDefaultLane]; !ok {
			return PolicySpec{}, fmt.Errorf("providers.Compile: auto_default_lane %q does not name a configured upstream", in.AutoDefaultLane)
		}
	}
	return PolicySpec{
		Upstreams:                upstreams,
		AutoDefaultLane:          in.AutoDefaultLane,
		Mode:                     mode,
		GatewayPrimary:           gwPrimary,
		GatewayFallbacks:         gwFallbacks,
		TerminalPolicy:           terminal,
		DirectFallbackCustodyAck: in.DirectFallbackCustodyAck && mode == ModeGateway,
		Hash:                     hashPolicy(in),
	}, nil
}

// compileMode validates the optional mode block and returns the canonical
// mode + gateway destination. The three body states are enforced here:
//
//   - ModeUnset ("") — no mode block: Gateway* must be empty and
//     ModeSchemaVersion must be 0 (a version with no mode is malformed).
//   - ModeNode ("node") — explicit Node Mode: Gateway* must be empty;
//     ModeSchemaVersion must be a supported version.
//   - ModeGateway ("gateway") — Gateway Mode: GatewayPrimary is required and
//     must be a valid absolute http/https URL; every fallback likewise;
//     ModeSchemaVersion must be a supported version.
//
// A ModeSchemaVersion above SupportedModeSchemaVersion returns
// ErrUnknownModeSchemaVersion (reject-keep-last). An unknown mode string is
// a hard error.
func compileMode(in PolicyInput) (mode, primary string, fallbacks []string, terminal string, err error) {
	switch in.Mode {
	case ModeUnset:
		if in.GatewayPrimary != "" || len(in.GatewayFallbacks) > 0 {
			return "", "", nil, "", fmt.Errorf("providers.Compile: gateway primary/fallbacks require mode %q or %q", ModeNode, ModeGateway)
		}
		if in.ModeSchemaVersion != 0 {
			return "", "", nil, "", fmt.Errorf("providers.Compile: mode_schema_version set without a mode block")
		}
		if in.TerminalPolicy != "" {
			return "", "", nil, "", fmt.Errorf("providers.Compile: terminal_policy set without a mode block")
		}
		return ModeUnset, "", nil, "", nil
	case ModeNode:
		if err := checkModeSchemaVersion(in.ModeSchemaVersion); err != nil {
			return "", "", nil, "", err
		}
		if in.GatewayPrimary != "" || len(in.GatewayFallbacks) > 0 {
			return "", "", nil, "", fmt.Errorf("providers.Compile: gateway primary/fallbacks are not allowed in mode %q", ModeNode)
		}
		if in.TerminalPolicy != "" {
			return "", "", nil, "", fmt.Errorf("providers.Compile: terminal_policy is not allowed in mode %q", ModeNode)
		}
		return ModeNode, "", nil, "", nil
	case ModeGateway:
		if err := checkModeSchemaVersion(in.ModeSchemaVersion); err != nil {
			return "", "", nil, "", err
		}
		if err := validateBaseURL(in.GatewayPrimary); err != nil {
			return "", "", nil, "", fmt.Errorf("providers.Compile: gateway primary: %w", err)
		}
		fbs := make([]string, 0, len(in.GatewayFallbacks))
		for i, fb := range in.GatewayFallbacks {
			if err := validateBaseURL(fb); err != nil {
				return "", "", nil, "", fmt.Errorf("providers.Compile: gateway fallback[%d]: %w", i, err)
			}
			fbs = append(fbs, strings.TrimSpace(fb))
		}
		term, err := compileTerminalPolicy(in.TerminalPolicy, in.DirectFallbackCustodyAck)
		if err != nil {
			return "", "", nil, "", err
		}
		return ModeGateway, strings.TrimSpace(in.GatewayPrimary), fbs, term, nil
	default:
		return "", "", nil, "", fmt.Errorf("providers.Compile: unknown mode %q (want %q, %q, or %q)", in.Mode, ModeUnset, ModeNode, ModeGateway)
	}
}

// compileTerminalPolicy validates the Sol S10 fallback-ladder terminal rung:
// the vocabulary is closed (hold | break_glass | direct, empty ⇒ hold), and
// TerminalDirect (auto-fallback-to-direct) REFUSES to compile without an
// explicit DirectFallbackCustodyAck so custody can never silently become
// convention. break_glass carries only the permission; the credentials are
// per-machine leases on the enrolment rail, never in this body.
func compileTerminalPolicy(raw string, directAck bool) (string, error) {
	switch raw {
	case "", TerminalHold:
		return TerminalHold, nil
	case TerminalBreakGlass:
		return TerminalBreakGlass, nil
	case TerminalDirect:
		if !directAck {
			return "", fmt.Errorf("providers.Compile: terminal_policy %q requires direct_fallback_custody_ack (enabling auto-fallback-to-direct converts custody into convention)", TerminalDirect)
		}
		return TerminalDirect, nil
	default:
		return "", fmt.Errorf("providers.Compile: unknown terminal_policy %q (want %q, %q, or %q)", raw, TerminalHold, TerminalBreakGlass, TerminalDirect)
	}
}

// checkModeSchemaVersion enforces the versioned-schema gate: a version at or
// below SupportedModeSchemaVersion is accepted, 0 is malformed (a mode block
// must declare its schema version), and anything higher is the Sol S3
// unknown-version reject-keep-last path.
func checkModeSchemaVersion(v int) error {
	if v <= 0 {
		return fmt.Errorf("providers.Compile: a mode block requires mode_schema_version >= 1")
	}
	if v > SupportedModeSchemaVersion {
		return fmt.Errorf("providers.Compile: mode_schema_version %d > supported %d: %w", v, SupportedModeSchemaVersion, ErrUnknownModeSchemaVersion)
	}
	return nil
}

// validateBaseURL enforces "absolute http/https URL": a scheme of http or
// https and a nonempty host. url.Parse alone is too permissive (it happily
// parses a bare relative path or a non-network scheme like "file:"), so both
// are checked explicitly.
func validateBaseURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("base_url must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("base_url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("base_url %q must be an absolute http or https URL", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("base_url %q must include a host", raw)
	}
	return nil
}

// hashPolicy computes a stable content hash over the semantic policy fields
// so the same policy always yields the same Hash (audit provenance). A
// lane-only body (no mode block) hashes IDENTICALLY to HashLaneTable so the
// P0-6 effective-state reporter's local-vs-org-rail match is unchanged; a
// mode body extends that hash with the mode fields so a mode change is a
// distinct content address.
func hashPolicy(in PolicyInput) string {
	base := HashLaneTable(in.Upstreams, in.AutoDefaultLane)
	if in.Mode != ModeGateway && in.Mode != ModeNode {
		return base
	}
	h := sha256.New()
	writeField := func(parts ...string) {
		for _, p := range parts {
			_, _ = h.Write([]byte(p))
			_, _ = h.Write([]byte{0x1e})
		}
	}
	writeField("lanes", base)
	writeField("mode", in.Mode)
	if in.Mode == ModeGateway {
		writeField("gateway_primary", in.GatewayPrimary)
		for _, fb := range in.GatewayFallbacks {
			writeField("gateway_fallback", fb)
		}
		term := in.TerminalPolicy
		if term == "" {
			term = TerminalHold
		}
		writeField("terminal_policy", term)
		if in.DirectFallbackCustodyAck {
			writeField("direct_fallback_custody_ack", "1")
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// HashLaneTable computes the stable 64-hex content address of a lane table
// (lane id -> base URL, plus the auto-default lane id). Field order is fixed
// and lanes are sorted by id so the hash never depends on Go map iteration
// order; the same table always yields the same hash.
//
// It is exported because the P0-6 effective-policy-state reporter needs the
// SAME content address for a lane table the node configured LOCALLY (which
// never passes through Compile and so has no PolicySpec.Hash) as for one
// that arrived over the org rail
// (docs/plans/policy-state-v2-gateway-providers-spec-2026-08-15.md §2.2).
// One algorithm, two call sites, rather than a second hash that could drift.
func HashLaneTable(upstreams map[string]string, autoDefaultLane string) string {
	h := sha256.New()
	writeField := func(parts ...string) {
		for _, p := range parts {
			_, _ = h.Write([]byte(p))
			_, _ = h.Write([]byte{0x1e})
		}
	}
	ids := make([]string, 0, len(upstreams))
	for id := range upstreams {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		writeField("upstream", id, upstreams[id])
	}
	if autoDefaultLane != "" {
		writeField("auto_default_lane", autoDefaultLane)
	}
	return hex.EncodeToString(h.Sum(nil))
}
