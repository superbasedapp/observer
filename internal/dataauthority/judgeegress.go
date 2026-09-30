package dataauthority

import (
	"net"
	"net/url"
	"strings"
)

// JudgeEgressAllowed decides whether a node-local LLM judge call may run
// against data of the given authority (JUDGE-1, docs/security.md).
//
// The concrete consumer today is [observability.judge] — a plain,
// node-authored TOML binding (any OpenAI-compatible host, an operator's
// own API key) reused by the Projects-page commit-alignment grader's
// tier J (cmd/observer/alignment_wire.go::alignmentJudgeFor) and by
// internal/obs admission/eval for THEIR OWN, separate data class. Unlike
// Cloud Intelligence (internal/dataauthority already gates that path via
// EligibleForPersonalEnrichment/EligibleForOrgEnrichment), a judge call
// had no data-authority check at all: a developer on a full-content
// managed node could point it at any personal endpoint and ship
// (scrubbed) org-authority session content there with no org visibility
// or consent.
//
// The rule:
//
//   - AuthorityPersonal: always allowed. The data belongs to the
//     developer's own personal plane; a personally-configured judge
//     endpoint is exactly the trust boundary that data already lives in.
//   - AuthorityOrg, or anything else (including the zero value, treated
//     the same as an unknown/unclassified authority — see
//     dataauthority.Authority's own "unknown refused" convention in
//     EligibleForOrgEnrichment): allowed ONLY if the call never leaves
//     this machine (endpoint is loopback — the model runs locally, so
//     there is no third party to consent), OR the org itself has
//     authored/approved this judge configuration (orgPinned) — e.g. the
//     org distributed [observability.judge] through node governance, or
//     the call is routed through the org's own relay. Otherwise refused,
//     with an operator-facing reason.
//
// This is a pure decision: it takes the endpoint and the org-pinned fact
// as plain values (the same discipline as EnrolmentState) — the caller
// resolves "is this endpoint loopback" and "did the org pin this config"
// from its own state (base URL string, node governance) and never from
// anything read here.
func JudgeEgressAllowed(authority Authority, endpoint string, orgPinned bool) (ok bool, reason string) {
	if authority == AuthorityPersonal {
		return true, ""
	}
	// AuthorityOrg or unknown: the developer's own node-configured judge
	// endpoint has no standing to receive this session's content unless
	// the call stays on this machine, or the org has explicitly approved
	// this exact judge configuration.
	if IsLoopbackJudgeEndpoint(endpoint) {
		return true, ""
	}
	if orgPinned {
		return true, ""
	}
	return false, "this session's data belongs to the org; the local judge endpoint is not org-approved"
}

// IsLoopbackJudgeEndpoint reports whether endpoint (a judge base URL)
// points at the loopback interface — i.e. the model runs on this
// machine, so no content actually leaves the node. This is the ONE owner
// of loopback detection for judge egress: cmd/observer/judgeclient.go's
// isLoopbackJudgeURL delegates here instead of keeping its own copy, so
// there is a single grammar for "is this endpoint local" across both the
// egress-gate decision above and the live client's credential/num_ctx
// gating.
//
// endpoint is parsed as a URL and only the HOST component is examined,
// checked against an exact allow-list — never a substring test. A
// substring test is bypassable by construction: "https://localhost.
// attacker.example/v1" contains the literal text "localhost" but its
// host is attacker.example, a fully remote endpoint (JUDGE-1 finding 2,
// docs/security.md). Accepted, exactly:
//
//   - the hostname "localhost" (case-insensitive; DNS names are
//     case-insensitive so a raw string compare after case-folding is
//     correct here, unlike a substring test)
//   - any literal IPv4 address in the 127.0.0.0/8 loopback block, not
//     just 127.0.0.1 — net.IP.IsLoopback covers the whole block
//   - the literal IPv6 loopback address ::1 (with or without the URL's
//     bracket syntax; url.Hostname strips brackets)
//
// 0.0.0.0 is deliberately NOT treated as loopback. It is the IPv4
// "unspecified"/bind-wildcard address: a server bound there accepts
// connections from any interface, including the LAN, so it is not a
// guarantee the peer is local — the opposite of what this predicate
// promises. A judge actually configured to listen on 0.0.0.0 needs an
// org-pinned config or an explicit loopback address (127.0.0.1/localhost)
// to satisfy this gate, same as any other non-local bind.
//
// A hostname that merely embeds a loopback-looking string
// ("127.0.0.1.attacker.example", "localhost.attacker.example") is
// correctly rejected: it fails net.ParseIP (not a literal IP) and fails
// the exact "localhost" comparison (not equal, only a suffix/prefix
// match), so it falls through to false.
func IsLoopbackJudgeEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}
