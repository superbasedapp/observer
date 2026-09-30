package localpdp

import (
	"context"
	"encoding/json"

	"github.com/marmutapp/superbased-observer/internal/mcpaccess"
)

// Verdict is the node PDP's FINAL outcome for one request, distinct from
// the matched grant's Effect (the gateway PDP's vocabulary, node-scoped:
// there is no "mutated" verdict because the relay never rewrites params).
type Verdict string

// Verdicts.
const (
	// VerdictPass forwards the call to the local server.
	VerdictPass Verdict = "pass"
	// VerdictDeny refuses the call with Decision.Error.
	VerdictDeny Verdict = "deny"
	// VerdictError refuses the call for a NON-policy reason (unknown or
	// stripped method, no table loaded, bad params). It blocks in observe
	// AND enforce mode (R8.27.h: only POLICY verdicts are would-deny).
	VerdictError Verdict = "error"
)

// DecisionClass partitions methods exactly as the gateway PDP does (doc3
// §3.2 mcp_decision): GOVERNED methods execute upstream behaviour and their
// verdict is authoritative before Pass; CATALOGUE methods are listings.
type DecisionClass string

// Decision classes.
const (
	ClassGoverned  DecisionClass = "governed"
	ClassCatalogue DecisionClass = "catalogue"
)

// Mode is the compiled table's enforcement mode (the tools.mcp_access
// body's `mode`). Observe is would-deny for POLICY verdicts only.
type Mode string

// Modes.
const (
	ModeObserve Mode = "observe"
	ModeEnforce Mode = "enforce"
)

// Transport is the relay's OWN observation of how the client reached it.
// It is the one input the node can vouch for without a token, and it is
// what the client-attestation rank is derived from (table in attest.go):
// a product-scoped grant is honoured only at process_attested / ipc_bound
// (R2), i.e. only for the stdio wrapper and the owner-only IPC path.
type Transport string

// Transports, in descending attestation order.
const (
	// TransportStdioWrapper: the relay IS the process the client spawned
	// (`observer mcp-relay stdio`), so the client is the parent process.
	TransportStdioWrapper Transport = "stdio_wrapper"
	// TransportIPC: the owner-only unix socket / named pipe.
	TransportIPC Transport = "ipc"
	// TransportLoopbackHTTP: the loopback HTTP listener a rewritten client
	// config points at — reachable by any same-user process, so the
	// product identity is configured, not attested.
	TransportLoopbackHTTP Transport = "loopback_http"
	// TransportUnknown: anything the relay cannot classify (claimed).
	TransportUnknown Transport = "unknown"
)

// Attestation names in the R2 client-attestation vocabulary
// (mcpaccess.ClientAttestationRanks). Re-exported here so callers that
// build a Principal by hand never spell them ad hoc.
const (
	AttestProcess    = "process_attested"
	AttestIPC        = "ipc_bound"
	AttestConfigured = "configured"
	AttestClaimed    = "claimed"
)

// Principal is the caller as the NODE knows it: the minted at+jwt claims
// when the relay holds an exchanged token (W4b's TokenClient), or the
// enrolled node's self-assertion for a token-less local stdio call (see
// NodePrincipal). The field vocabulary is mcpaccess.Principal's, plus the
// Transport the relay observed. ClientAttestation is an INPUT ceiling only:
// the engine replaces it with EffectiveAttestation(Transport, claimed),
// which can lower a claim but never raise one.
type Principal struct {
	// Issuer / Org / Audience / PolicyGen feed the require invariants the
	// compiled table checks before any grant (issuer, org, exact single
	// audience, policy_gen floor).
	Issuer    string   `json:"issuer,omitempty"`
	Org       string   `json:"org,omitempty"`
	Audience  []string `json:"audience,omitempty"`
	PolicyGen int64    `json:"policy_gen,omitempty"`
	// Subject is jwt.sub; MemberID the human member ("" machine-to-machine);
	// MachineFP the enrolled node's machine fingerprint.
	Subject   string `json:"subject,omitempty"`
	MemberID  string `json:"member_id,omitempty"`
	MachineFP string `json:"machine_fp,omitempty"`
	// ClientID is jwt.client_id (the agent definition's registered client);
	// Product / AgentKind are act.sbo_product / act.sbo_kind.
	ClientID  string `json:"client_id,omitempty"`
	Product   string `json:"product,omitempty"`
	AgentKind string `json:"agent_kind,omitempty"`
	// Env / Workspace / Groups are sbo_env / sbo_ws / sbo_groups.
	Env       string   `json:"env,omitempty"`
	Workspace string   `json:"ws,omitempty"`
	Groups    []string `json:"groups,omitempty"`
	// CredAssurance is act.sbo_cred_assurance.
	CredAssurance string `json:"cred_assurance,omitempty"`
	// ClientAttestation is the CLAIMED attestation (token or caller). The
	// effective value is derived from Transport; see EffectiveAttestation.
	ClientAttestation string `json:"client_attestation,omitempty"`
	// Transport is what the relay observed. The zero value is
	// TransportUnknown (claimed).
	Transport Transport `json:"transport,omitempty"`
	// Session / Run are sbo_session / sbo_run (audit correlation only).
	Session string `json:"session,omitempty"`
	Run     string `json:"run,omitempty"`
	// TeamIDs / TeamsKnown / ProjectHash are the P11(e) ABAC context in the
	// compiler's vocabulary (mcpaccess.Principal): the node relay has no
	// server-side roster (TeamsKnown stays false, so team grants fail closed
	// locally) and attests the project itself when it knows the session's
	// working directory.
	TeamIDs     []string `json:"team_ids,omitempty"`
	TeamsKnown  bool     `json:"teams_known,omitempty"`
	ProjectHash string   `json:"project_hash,omitempty"`
	// TeamsOverflow mirrors mcpaccess.Principal.TeamsOverflow (P11 fold
	// PF2): every team subject untrusted.
	TeamsOverflow bool `json:"teams_overflow,omitempty"`
}

// Access renders the principal in the compiler's vocabulary with the
// EFFECTIVE client attestation (transport-derived, never raised by a claim).
func (p Principal) Access() mcpaccess.Principal {
	return mcpaccess.Principal{
		Issuer:            p.Issuer,
		Org:               p.Org,
		Audience:          append([]string(nil), p.Audience...),
		PolicyGen:         p.PolicyGen,
		Subject:           p.Subject,
		ClientID:          p.ClientID,
		Product:           p.Product,
		AgentKind:         p.AgentKind,
		Env:               p.Env,
		Workspace:         p.Workspace,
		Groups:            append([]string(nil), p.Groups...),
		CredAssurance:     p.CredAssurance,
		ClientAttestation: EffectiveAttestation(p.Transport, p.ClientAttestation),
		TeamIDs:           append([]string(nil), p.TeamIDs...),
		TeamsKnown:        p.TeamsKnown,
		TeamsOverflow:     p.TeamsOverflow,
		ProjectHash:       p.ProjectHash,
	}
}

// Request is one JSON-RPC request the relay asks the node PDP to decide.
// It is shaped like the gateway PDP's request but node-scoped: no org
// token-kind plumbing, no upstream credential selection (a local stdio
// server has none) and no task binding (tasks are stripped, R8.27.b).
type Request struct {
	// VServerID is the virtual server the approved registry entry the
	// relay is fronting belongs to.
	VServerID string `json:"vserver_id"`
	// Method is the JSON-RPC method; Tool an already-resolved governed name
	// (tool / prompt name, resource URI) — when empty the dispatch table
	// reads it from Params; Params is the raw params object (only the
	// addressed-name fields are read, never argument values).
	Method string          `json:"method"`
	Tool   string          `json:"tool,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	// Server is the backend target (mcp_server.id or its target name) the
	// relay resolved from its approved entry ("" = unknown).
	Server string `json:"server,omitempty"`
	// Principal is the caller.
	Principal Principal `json:"principal"`
	// CallID / JSONRPCID are audit correlation ids the relay stamps on the
	// mcp_relay_record row (Lane N-M's store); the PDP only echoes them.
	CallID    string `json:"call_id,omitempty"`
	JSONRPCID string `json:"jsonrpc_id,omitempty"`
}

// RPCError is the JSON-RPC error the relay renders on a refusal.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// JSON-RPC error codes (the gateway PDP's numbers, so a client sees the
// same code whether the gateway or the node relay refused it).
const (
	CodeMethodNotFound   = -32601
	CodeInvalidParams    = -32602
	CodeForbidden        = -32003
	CodeApprovalRequired = -32052
	CodeUnavailable      = -32050
)

// Decision is the node PDP's answer for one Request.
type Decision struct {
	Verdict Verdict `json:"verdict"`
	// Effect is the matched grant's effect (allow / deny / ask; deny when
	// nothing matched); EffectClass the mcp_decision.effect_class value;
	// DecisionClass governed / catalogue.
	Effect        string        `json:"effect"`
	EffectClass   string        `json:"effect_class"`
	DecisionClass DecisionClass `json:"decision_class"`
	// Action / VServer / Server / Name are the resolved request coordinates.
	Action  mcpaccess.Action `json:"action,omitempty"`
	VServer string           `json:"vserver,omitempty"`
	Server  string           `json:"server,omitempty"`
	Name    string           `json:"name,omitempty"`
	// MatchedGrant / Reason are the grant id and the human reason.
	MatchedGrant string `json:"matched_grant,omitempty"`
	Reason       string `json:"reason"`
	// Mode is the table's mode; WouldDeny marks an observe-mode policy
	// verdict that would have denied in enforce (the call still forwards).
	Mode      Mode `json:"mode,omitempty"`
	WouldDeny bool `json:"would_deny,omitempty"`
	// Attestation is the EFFECTIVE client attestation the verdict was
	// evaluated at (transport-derived).
	Attestation string `json:"attestation,omitempty"`
	// PolicyGen / PolicyHash / PolicyVersion identify the table the verdict
	// came from (the audit record's policy columns).
	PolicyGen     int64  `json:"policy_gen"`
	PolicyHash    string `json:"policy_hash,omitempty"`
	PolicyVersion int64  `json:"policy_version,omitempty"`
	// StrictAudit is true when the matched grant's audit_class is strict or
	// the vserver is marked strict: the relay must block on an audit-append
	// failure regardless of [mcp_relay].audit_mode (§12.4).
	StrictAudit bool `json:"strict_audit,omitempty"`
	// Stripped marks a method the node relay strips in v1 (tasks/*, R8.27.b):
	// refused with CodeMethodNotFound, never forwarded, never a policy verdict.
	Stripped bool `json:"stripped,omitempty"`
	// Visible is the catalogue filter for a ToolScoped listing (tools/list):
	// the tool names the principal may call. nil when not a listing.
	Visible []string `json:"visible,omitempty"`
	// Error is set on VerdictDeny / VerdictError.
	Error *RPCError `json:"error,omitempty"`
}

// Forwardable reports whether the relay may forward the request.
func (d Decision) Forwardable() bool { return d.Verdict == VerdictPass }

// Ask reports the ask effect in enforce mode (the relay renders an
// approval_required result instead of a plain forbidden error).
func (d Decision) Ask() bool {
	return d.Effect == string(mcpaccess.EffectAsk) && !d.WouldDeny && !d.Forwardable()
}

// Decider is the seam the relay (Lane W4b) and the proxy/hook seam (Lane
// W4d) call in-process. It never imports internal/mcpgw.
type Decider interface {
	// CheckRequest decides req. It never returns an error: an unavailable
	// or unloaded table is a VerdictError decision, so a caller cannot
	// fail open by mistaking an error for "no opinion".
	CheckRequest(ctx context.Context, req Request) Decision
}

// Filterer is the response-phase catalogue filter (tools/list,
// resources/list, prompts/list).
type Filterer interface {
	// Filter keeps the names the principal's governed call/read would be
	// allowed or asked. In observe mode nothing is filtered. nil when the
	// method is not a catalogue listing or no table is loaded.
	Filter(req Request, names []string) []string
}

// Meta is what the four-gate accept knows about the verified envelope the
// table was compiled from (orgclient.PolicyResourceResult, carried as plain
// values so this package stays free of orgclient/store).
type Meta struct {
	// Version is the signed resource version; BodyHash its body hash;
	// OrgKey / Generation the enrolment identity it was accepted under.
	Version    int64  `json:"version"`
	BodyHash   string `json:"body_hash"`
	OrgKey     string `json:"org_key"`
	Generation int64  `json:"generation"`
	// EnforceAllowed is the accept result's preauthorization posture: a
	// body asking for enforce that the node has not preauthorized runs
	// observe (PRAppliedInert), never enforce.
	EnforceAllowed bool `json:"enforce_allowed"`
}

// Table is the compiled, hot-swappable node decision table plus the
// identity the audit record needs. Build it with Compile; swap it into a
// Holder; persist it with Cache.
type Table struct {
	Meta Meta `json:"meta"`
	// Mode is the effective mode (the body's mode, lowered to observe when
	// Meta.EnforceAllowed is false).
	Mode Mode `json:"mode"`
	// Node is the compiled first-match-wins table.
	Node mcpaccess.NodeDecisionTable `json:"node"`
	// AuditStrict marks vservers a signed policy flagged audit_strict
	// (none in the v1 wire body; callers may set it from a later body).
	AuditStrict map[string]bool `json:"audit_strict,omitempty"`
	// Grants indexes the normalized grants by id (strict-audit lookup).
	Grants map[string]mcpaccess.Grant `json:"-"`
}
