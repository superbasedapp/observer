package mcpaccess

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentid"
)

// Effect is a grant's effect (mcp_grant.effect CHECK).
type Effect string

// Effects. EffectJudge is in the DDL vocabulary but rejected by every v1
// compiler with a feature_unavailable lint error (R8.1).
const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
	EffectAsk   Effect = "ask"
	EffectJudge Effect = "judge"
)

// effectPrecedence is the default-deny precedence table (plan §10 "deny >
// ask/judge > allow; unmatched = deny"): a lower number wins.
var effectPrecedence = map[Effect]int{EffectDeny: 0, EffectAsk: 1, EffectAllow: 2}

// Action is the enumerated MCP action class (mcp_grant.action). There is NO
// wildcard (R8.30.g): a future method needs an explicit row.
type Action string

// Actions.
const (
	ActionDiscover    Action = "discover"
	ActionList        Action = "list"
	ActionCall        Action = "call"
	ActionRead        Action = "read"
	ActionSubscribe   Action = "subscribe"
	ActionTasksGet    Action = "tasks/get"
	ActionTasksUpdate Action = "tasks/update"
	ActionTasksCancel Action = "tasks/cancel"
)

// Actions is the closed, ordered action vocabulary.
var Actions = []Action{ActionDiscover, ActionList, ActionCall, ActionRead, ActionSubscribe, ActionTasksGet, ActionTasksUpdate, ActionTasksCancel}

// actionResource is the per-action capability table: the agentgateway CEL
// resource object the grant's Name selects (crates/agentgateway/src/mcp/
// rbac.rs ResourceType: mcp.tool / mcp.prompt / mcp.resource / mcp.task,
// each with .name and .target), the mcp_decision.effect_class value, whether
// the action's name is checked against the member server's APPROVED
// SNAPSHOT (R9.8 drift: only tool names are snapshotted), and whether the
// CEL target can distinguish the action at all (grantable).
//
// An empty celObject means the action is PDP-owned (response-phase
// visibility filtering, R8.23.h) and is not rendered into CEL.
//
// grantable=false marks the three task actions: on the pinned agentgateway
// v1.5.0 the mcpAuthorization CEL context is built from the RBAC resource
// alone (crates/agentgateway/src/mcp/rbac.rs McpAuthorizationSet::validate
// -> MCPInfo::from(&ResourceType), which leaves method_name None) and
// tasks/get, tasks/update and tasks/cancel all call the SAME
// authorize_task_request with an identical ResourceType::Task{target, id}
// (crates/agentgateway/src/mcp/session.rs). There is NO method
// discriminator a CEL rule could conjoin, so a grant on one task action
// would compile to a rule covering all three - a silent widening R8.30.g
// forbids. Lint therefore refuses every task-action grant with a typed
// feature_unavailable ERROR, from all four compilers identically (R8.1).
// The actions stay in the vocabulary (a request naming them evaluates to
// default-deny on every target) so the A2 front's method table and the
// mcp_decision rows keep their names.
var actionResource = map[Action]struct {
	celObject      string
	effectClass    string
	snapshotScoped bool
	celUngrantable bool
}{
	ActionDiscover:    {celObject: "", effectClass: "discover"},
	ActionList:        {celObject: "", effectClass: "list"},
	ActionCall:        {celObject: "tool", effectClass: "write", snapshotScoped: true},
	ActionRead:        {celObject: "resource", effectClass: "read"},
	ActionSubscribe:   {celObject: "", effectClass: "subscribe"},
	ActionTasksGet:    {celObject: "task", effectClass: "tasks", celUngrantable: true},
	ActionTasksUpdate: {celObject: "task", effectClass: "tasks", celUngrantable: true},
	ActionTasksCancel: {celObject: "task", effectClass: "tasks", celUngrantable: true},
}

// CELApplicable reports whether a is rendered into (and evaluable by) the
// agentgateway CEL target. The PDP-owned actions (discover, list, subscribe)
// are decided by the three PDP targets only.
func CELApplicable(a Action) bool { return actionResource[a].celObject != "" }

// SnapshotScoped reports whether a grant on a is matched against the member
// server's approved snapshot (its tool list) before it can apply: the
// snapshot-membership guard of R9.8 (a newly-named tool default-denies under
// ALERT drift until adopted). Only tools/call is snapshot-scoped in v1.
func SnapshotScoped(a Action) bool { return actionResource[a].snapshotScoped }

// CELUngrantable reports whether a is an action the CEL target cannot
// express as an authority distinct from its siblings (the three task
// actions, see actionResource). A grant on such an action is refused by
// Lint with feature_unavailable.
func CELUngrantable(a Action) bool { return actionResource[a].celUngrantable }

// SubjectKind is the grant subject selector kind. Each kind maps onto ONE
// minted at+jwt claim (internal/agentid/claims.go) in subjectClaims below.
type SubjectKind string

// Subject kinds. The plan also names role / app selectors; no minted claim
// carries them in v1, so they are typed unsupported_subject_kind lint errors
// (never a guessed claim). team and project are the P11(e) ABAC kinds
// (R10.9): team = the SERVER-SIDE roster claim sbo_team_ids, project = the
// RELAY-ATTESTED sbo_project_hash (or, for a caller with no attested project,
// the vserver's DECLARED project scope). Both are FAIL-CLOSED when the
// trusted context is absent: an allow never matches, a deny / ask always does
// (subjectMatches).
const (
	SubjectAny       SubjectKind = "any"
	SubjectUser      SubjectKind = "user"
	SubjectProduct   SubjectKind = "product"
	SubjectAgentDef  SubjectKind = "agent_def"
	SubjectAgentKind SubjectKind = "agent_kind"
	SubjectEnv       SubjectKind = "env"
	SubjectWorkspace SubjectKind = "ws"
	SubjectGroup     SubjectKind = "group"
	SubjectTeam      SubjectKind = "team"
	SubjectProject   SubjectKind = "project"
)

// subjectClaimRule is one row of the subject-kind -> claim table.
type subjectClaimRule struct {
	kind SubjectKind
	// path is the CEL claim path.
	path string
	// list marks a list-valued claim (membership, not equality).
	list bool
	// attested marks a product-scoped kind: honoured only at
	// process_attested / ipc_bound (R2).
	attested bool
	// get reads the matching value(s) from a Principal.
	get func(p Principal) []string
	// present, when set, marks a CONTEXT-GATED kind (P11(e) team / project):
	// it reports whether the principal carries the trusted claim at all. An
	// absent claim is NOT "no value" - the kind then falls back to declared
	// (when set) or evaluates fail-closed (subjectMatches).
	present func(p Principal) bool
	// declared, when set, is the vserver-declared scope a caller WITHOUT the
	// trusted claim is evaluated under (the project kind: a direct client
	// gets only the vserver's declared project scope, R10.9).
	declared func(v VServer) []string
	// untrustedPath, when set, is the CEL path of a marker claim whose
	// PRESENCE makes the context claim untrusted even if it is present (the
	// team kind: sbo_team_overflow, P11 fold PF2). present() already folds
	// the marker in for the PDP targets; the CEL target renders it as a
	// has() guard so all four targets agree on a token carrying both.
	untrustedPath string
}

var subjectClaims = []subjectClaimRule{
	{kind: SubjectUser, path: "jwt.sub", get: func(p Principal) []string { return one(p.Subject) }},
	{kind: SubjectProduct, path: "jwt.act.sbo_product", attested: true, get: func(p Principal) []string { return one(p.Product) }},
	{kind: SubjectAgentDef, path: "jwt.client_id", get: func(p Principal) []string { return one(p.ClientID) }},
	{kind: SubjectAgentKind, path: "jwt.act.sbo_kind", get: func(p Principal) []string { return one(p.AgentKind) }},
	{kind: SubjectEnv, path: "jwt.sbo_env", get: func(p Principal) []string { return one(p.Env) }},
	{kind: SubjectWorkspace, path: "jwt.sbo_ws", get: func(p Principal) []string { return one(p.Workspace) }},
	{kind: SubjectGroup, path: "jwt.sbo_groups", list: true, get: func(p Principal) []string { return p.Groups }},
	{
		kind: SubjectTeam, path: "jwt.sbo_team_ids", list: true, untrustedPath: "jwt.sbo_team_overflow",
		get:     func(p Principal) []string { return p.TeamIDs },
		present: func(p Principal) bool { return p.TeamsKnown && !p.TeamsOverflow },
	},
	{
		kind: SubjectProject, path: "jwt.sbo_project_hash",
		get:      func(p Principal) []string { return one(p.ProjectHash) },
		present:  func(p Principal) bool { return p.ProjectHash != "" },
		declared: func(v VServer) []string { return v.Projects },
	},
}

// contextGated reports whether r is a P11(e) context-gated kind.
func (r subjectClaimRule) contextGated() bool { return r.present != nil }

// failClosedEffect reports whether an effect MATCHES when the trusted ABAC
// context is absent: deny and ask do (the more restrictive outcome - a
// caller that withholds its project can never slip past a project deny),
// allow never does (R10.9 "fail project-scoped grants CLOSED").
func failClosedEffect(e Effect) bool { return e == EffectDeny || e == EffectAsk }

// ValidSubjectValue reports whether value is well-formed for kind (the lint
// row CodeInvalidSubjectValue): a project value must be a project hash, a
// team id is bounded like the minted roster entries.
func ValidSubjectValue(kind SubjectKind, value string) bool {
	switch kind {
	case SubjectProject:
		return agentid.ValidProjectHash(value)
	case SubjectTeam:
		return value != "" && len(value) <= agentid.MaxTeamIDBytes
	}
	return true
}

func one(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func subjectRule(k SubjectKind) (subjectClaimRule, bool) {
	for _, r := range subjectClaims {
		if r.kind == k {
			return r, true
		}
	}
	return subjectClaimRule{}, false
}

// Subject is the grant's subject selector (mcp_grant.subject_json).
type Subject struct {
	Kind  SubjectKind `json:"kind"`
	Value string      `json:"value,omitempty"`
}

// Resource is the grant's resource selector (mcp_grant.resource_json).
// VServer is the virtual server id (required); Server optionally narrows to
// one backend target (mcp.<kind>.target); Name is the tool name / resource
// URI / task id the action addresses, "" or "*" meaning any.
type Resource struct {
	VServer string `json:"vserver"`
	Server  string `json:"server,omitempty"`
	Name    string `json:"name,omitempty"`
}

// AnyName reports whether the selector matches every name.
func (r Resource) AnyName() bool { return r.Name == "" || r.Name == "*" }

// Conditions is the typed subset of mcp_grant.conditions_json v1 enforces.
// The floors are MINIMUM ranks (R8.23.i) the compiler expands to accepted-
// value sets. Taint and RequiresMFA are decoded so they can be REFUSED with
// a typed feature_unavailable error (R8.1) rather than dropped.
type Conditions struct {
	RequiresCredAssurance     string `json:"requires_cred_assurance,omitempty"`
	RequiresClientAttestation string `json:"requires_client_attestation,omitempty"`
	// ExpiresAt is a unix-seconds grant expiry; 0 = none. An expired grant is
	// dropped at Normalize with an expired_grant WARN.
	ExpiresAt int64 `json:"expires_at,omitempty"`
	// Taint is any taint/toxic-flow condition (v1.x, P6b): feature_unavailable.
	Taint bool `json:"taint,omitempty"`
	// RequiresMFA needs a fresh user assertion no v1 token carries (R6):
	// feature_unavailable.
	RequiresMFA bool `json:"requires_mfa,omitempty"`
}

// Grant mirrors one mcp_grant row.
type Grant struct {
	ID             string     `json:"id"`
	Ord            int        `json:"ord"`
	Subject        Subject    `json:"subject"`
	Resource       Resource   `json:"resource"`
	Action         Action     `json:"action"`
	Effect         Effect     `json:"effect"`
	HierarchyLevel int        `json:"hierarchy_level"`
	AuditClass     string     `json:"audit_class,omitempty"`
	Conditions     Conditions `json:"conditions"`
	Enabled        bool       `json:"enabled"`
}

// ApprovedSnapshot is a member server's ACTIVE approved snapshot as the
// compiler sees it (mcp_server_snapshot, plan §11.4 W2a): the snapshot id
// and the approved tool names in the EXPOSED namespace (the snapshot's
// explicit native_to_exposed_map applied; a native name absent from the map
// is exposed under its own name). It is the R9.8 drift guard's input: a
// snapshot-scoped grant (tools/call) matches a name ONLY when the member
// that serves it approves that name, so under ALERT drift a previously
// approved KNOWN tool keeps flowing while a NEWLY-named one default-denies
// until an admin adopts a snapshot that lists it.
//
// The pin is LIVE registry state, not authored policy: every compile /
// policy reload reads the current active snapshot through the registry
// view, and the family's canonical (signed, hashed) body strips it, so
// adopting a snapshot never changes a publication's compiled_hash - the
// next reload picks the new set up, no republish. The id is carried so a
// rendered rule set names the snapshot it was compiled against.
type ApprovedSnapshot struct {
	ID string `json:"id"`
	// Tools is the approved exposed tool list (sorted at the boundary;
	// membership is order-independent). Empty = approved with NO tools:
	// every snapshot-scoped grant on the member is unmatchable.
	Tools []string `json:"tools"`
}

// Approves reports whether name is in the approved set.
func (s *ApprovedSnapshot) Approves(name string) bool {
	return s != nil && contains(s.Tools, name)
}

// Server is one mcp_server the registry view exposes to the compiler: the
// backend target reference inside its vserver (Target: the registry-side
// reference, the server id in the registry view - the name AGENTGATEWAY
// sees is TargetName(Target), applied wherever a target is rendered for the
// gateway, so Target itself, and every compiled_hash over it, never
// changes shape), the upstream credential mode
// (R14.11 lint) and, when the server has an active approved snapshot, that
// snapshot's tool set (the R9.8 drift guard). A nil Snapshot means the
// registry holds no active snapshot for the member: nothing is pinned, so
// no membership is enforced (the pre-adoption state; the data plane's
// routability gate fences a server that was never approved).
type Server struct {
	ID             string            `json:"id"`
	Target         string            `json:"target"`
	CredentialMode string            `json:"credential_mode,omitempty"`
	Snapshot       *ApprovedSnapshot `json:"snapshot,omitempty"`
}

// Pinned reports whether the server carries an approved snapshot.
func (s Server) Pinned() bool { return s.Snapshot != nil }

// VServer is one published virtual server (mcp_virtual_server).
type VServer struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	// Audience is the canonical aud = <gateway_base_uri>/mcp/<slug> (R8.25.g);
	// when empty it is derived from Registry.GatewayBaseURI.
	Audience         string   `json:"audience,omitempty"`
	SenderConstraint string   `json:"sender_constraint"`
	Servers          []Server `json:"servers,omitempty"`
	// Projects is the vserver-DECLARED project scope (P11(e), R10.9): the
	// project hashes a caller WITHOUT a relay-attested sbo_project_hash (a
	// direct OAuth / API-key client) is evaluated under. Empty = no declared
	// scope: such a caller has no project context and every project-scoped
	// grant evaluates fail-closed for it.
	Projects []string `json:"projects,omitempty"`
}

// Registry is the compiler's view of the org registry: the require-invariant
// inputs (issuer, org, policy_gen floor) plus the vservers grants may name.
type Registry struct {
	Issuer         string    `json:"issuer"`
	Org            string    `json:"org"`
	GatewayBaseURI string    `json:"gateway_base_uri,omitempty"`
	PolicyGen      int64     `json:"policy_gen"`
	VServers       []VServer `json:"vservers"`
}

// ServerByRef resolves a member by its id or its backend target name.
func (v VServer) ServerByRef(ref string) (Server, bool) {
	if ref == "" {
		return Server{}, false
	}
	for _, s := range v.Servers {
		if s.ID == ref || s.Target == ref {
			return s, true
		}
	}
	return Server{}, false
}

// VServerByID resolves a vserver id.
func (r Registry) VServerByID(id string) (VServer, bool) {
	for _, v := range r.VServers {
		if v.ID == id {
			return v, true
		}
	}
	return VServer{}, false
}

// AudienceOf returns the vserver's canonical audience.
func (r Registry) AudienceOf(v VServer) string {
	if v.Audience != "" {
		return v.Audience
	}
	return strings.TrimRight(r.GatewayBaseURI, "/") + "/mcp/" + v.Slug
}

// Spec is the one compiler input: the grant set plus its registry view.
type Spec struct {
	Registry Registry `json:"registry"`
	Grants   []Grant  `json:"grants"`
}

// Principal is the evaluated caller, in the vocabulary of the minted claims
// (internal/agentid/claims.go). Org / Issuer / Audience / PolicyGen feed the
// require invariants; the rest feed subject selectors and condition floors.
type Principal struct {
	Issuer    string   `json:"issuer,omitempty"`
	Org       string   `json:"org,omitempty"`
	Audience  []string `json:"audience,omitempty"`
	PolicyGen int64    `json:"policy_gen,omitempty"`
	// Subject is jwt.sub; ClientID is jwt.client_id (the agent definition's
	// registered client, R8.23.l).
	Subject   string   `json:"subject,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Product   string   `json:"product,omitempty"`
	AgentKind string   `json:"agent_kind,omitempty"`
	Env       string   `json:"env,omitempty"`
	Workspace string   `json:"ws,omitempty"`
	Groups    []string `json:"groups,omitempty"`
	// CredAssurance / ClientAttestation are act.sbo_cred_assurance /
	// act.sbo_client_attestation.
	CredAssurance     string `json:"cred_assurance,omitempty"`
	ClientAttestation string `json:"client_attestation,omitempty"`
	// TeamIDs is jwt.sbo_team_ids; TeamsKnown reports the claim was PRESENT
	// (a server-side roster, possibly empty). !TeamsKnown = no trusted team
	// context: team-scoped grants evaluate fail-closed (P11(e)).
	TeamIDs    []string `json:"team_ids,omitempty"`
	TeamsKnown bool     `json:"teams_known,omitempty"`
	// TeamsOverflow is jwt.sbo_team_overflow (P11 fold PF2): the member's
	// roster exceeded the claim bound, so EVERY team subject is untrusted
	// for this token - a team allow never matches, a team deny / ask always
	// does - even if a roster were also present.
	TeamsOverflow bool `json:"teams_overflow,omitempty"`
	// ProjectHash is the relay-attested jwt.sbo_project_hash ("" = absent;
	// the vserver's declared scope then applies, else fail-closed).
	ProjectHash string `json:"project_hash,omitempty"`
}

// EvalInput is one request to decide.
type EvalInput struct {
	Principal Principal `json:"principal"`
	VServer   string    `json:"vserver"`
	Action    Action    `json:"action"`
	// Server is the backend target the request resolves to ("" = unknown).
	Server string `json:"server,omitempty"`
	// Name is the tool name / resource URI / task id.
	Name string `json:"name,omitempty"`
}

// Decision is a target's verdict. Effect is deny when nothing matched
// (default-deny). EffectClass is the mcp_decision.effect_class vocabulary
// value for the action.
type Decision struct {
	Effect       Effect `json:"effect"`
	MatchedGrant string `json:"matched_grant,omitempty"`
	EffectClass  string `json:"effect_class,omitempty"`
	Reason       string `json:"reason"`
}

// Denied reports the default-deny outcome.
func (d Decision) Denied() bool { return d.Effect == EffectDeny }

// Credential-assurance and client-attestation ranks (R8.23.i), highest
// first. A grant floor at rank i accepts every value at index <= i.
var (
	CredAssuranceRanks     = []string{"hardware_bound", "node_enrolled", "workload_bound", "shared_secret", "user_session_only", "claimed"}
	ClientAttestationRanks = []string{"process_attested", "ipc_bound", "configured", "claimed"}
	// ProductAttestations is the attested set product-scoped grants require.
	ProductAttestations = []string{"process_attested", "ipc_bound"}
)

// AcceptedAtLeast expands a minimum rank to the accepted-value set (the
// values ranked at or above floor), or nil when floor is unknown.
func AcceptedAtLeast(ranks []string, floor string) []string {
	for i, r := range ranks {
		if r == floor {
			out := make([]string, i+1)
			copy(out, ranks[:i+1])
			return out
		}
	}
	return nil
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// AuditClasses is the mcp_grant.audit_class vocabulary.
var AuditClasses = []string{"normal", "strict"}

// SenderConstraints is the mcp_virtual_server.sender_constraint vocabulary.
var SenderConstraints = []string{"bearer", "dpop", "mtls", "dpop_or_mtls"}

// CredentialModes is the mcp_server.credential_mode vocabulary.
var CredentialModes = []string{"vault_user", "service", "passthrough", "forward_idp", "obo", "none"}
