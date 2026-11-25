package platformcontract

// OrgKind is the closed vocabulary of an organization's kind (plan 06 5.4):
// a personal org has one member and individual tenancy; a team org is the
// shared kind. The tenant host decides an enrolment's tenancy from it (plan 06
// 19.3 rule 6). It is an additive v1 field: a reader that does not know it
// ignores it, and a host treats an absent kind as OrgKindTeam.
type OrgKind string

// Organization kinds.
const (
	// OrgKindTeam is a shared organization: managed tenancy by default.
	OrgKindTeam OrgKind = "team"
	// OrgKindPersonal is one user's own organization: individual tenancy.
	OrgKindPersonal OrgKind = "personal"
)

// KnownOrgKinds lists every OrgKind.
var KnownOrgKinds = []OrgKind{OrgKindTeam, OrgKindPersonal}

// Valid reports whether k is a known kind ("" is not: a caller that reads an
// absent kind as team does so explicitly).
func (k OrgKind) Valid() bool { return containsStr(KnownOrgKinds, k) }

// CreateTenantRequest is POST /tenants. Create is idempotent on IdempotencyKey:
// a repeat with the same key and TenantID answers CreateReplayed.
type CreateTenantRequest struct {
	// IdempotencyKey is the control plane's outbox row key.
	IdempotencyKey string `json:"idempotency_key"`
	// TenantID is the org id the control plane minted.
	TenantID string `json:"tenant_id"`
	// Name is the org display name.
	Name string `json:"name"`
	// OwnerSub is the WorkOS subject of the owner member.
	OwnerSub string `json:"owner_sub"`
	// OwnerEmail is the owner's email. It is a display hint: the owner is
	// bound by OwnerSub, and the address is unverified unless
	// OwnerEmailVerified says otherwise.
	OwnerEmail string `json:"owner_email"`
	// OwnerEmailVerified is true only when the control plane vouches that
	// OwnerEmail is verified. Optional on the wire (additive); absent means
	// unverified, so a host never matches anything by an unvouched address
	// (lead decision W14-D2: the control plane sends it false while L-31 is
	// unruled).
	OwnerEmailVerified bool `json:"owner_email_verified,omitempty"`
	// Entitlements is the first signed entitlement document.
	Entitlements EntitlementDocument `json:"entitlements"`
	// Slug is the org's platform slug, served at <slug>.<host base> (plan 06
	// 5.5). Optional on the wire (additive); a pooled host that routes by
	// slug refuses a create without one, because it could not serve it.
	Slug string `json:"slug,omitempty"`
	// Kind is the org's kind. Optional on the wire (additive); absent means
	// OrgKindTeam.
	Kind OrgKind `json:"kind,omitempty"`
}

// CreateTenantResponse answers a create.
type CreateTenantResponse struct {
	// TenantID echoes the request.
	TenantID string `json:"tenant_id"`
	// Outcome is ready, replayed or failed.
	Outcome CreateOutcome `json:"outcome"`
	// State is the tenant's lifecycle state after the call.
	State TenantState `json:"state"`
	// LifecycleGen is the tenant's lifecycle generation.
	LifecycleGen int64 `json:"lifecycle_gen"`
}

// SetStateRequest is PUT /tenants/{id}/state, a lifecycle intent. The host
// applies it only if LifecycleGen is newer than its own.
type SetStateRequest struct {
	// TenantID must match the path id.
	TenantID string `json:"tenant_id"`
	// State is the intended state.
	State TenantState `json:"state"`
	// LifecycleGen is the control plane's generation for this transition.
	LifecycleGen int64 `json:"lifecycle_gen"`
}

// SetStateResponse answers a state intent.
type SetStateResponse struct {
	// State is the state now in force.
	State TenantState `json:"state"`
	// LifecycleGen is the generation now in force.
	LifecycleGen int64 `json:"lifecycle_gen"`
	// Applied is false when the intent was stale and ignored.
	Applied bool `json:"applied"`
}

// EntitlementDocument is the opaque signed, capability-keyed document (plan 06
// 5.8.4). The host verifies it; this package never interprets Body.
type EntitlementDocument struct {
	// Version is the monotonic document version.
	Version int64 `json:"version"`
	// Body is the signed document bytes (base64 in JSON).
	Body []byte `json:"body"`
	// Signature is the document signature (base64 in JSON).
	Signature []byte `json:"signature"`
	// KeyID names the signer key.
	KeyID string `json:"key_id"`
}

// SetEntitlementsRequest is PUT /tenants/{id}/entitlements.
type SetEntitlementsRequest struct {
	// TenantID must match the path id.
	TenantID string `json:"tenant_id"`
	// Document is the new signed document.
	Document EntitlementDocument `json:"document"`
}

// SetEntitlementsResponse answers an entitlements push.
type SetEntitlementsResponse struct {
	// Version is the document version now in force.
	Version int64 `json:"version"`
	// Applied is false when the version was not newer.
	Applied bool `json:"applied"`
}

// SetAvailabilityRequest is PUT /availability: the platform availability
// envelope (plan 06 18.3.5), pushed to every host on the same path as an
// org's entitlements. The host verifies it (VerifyAvailability, then the
// body's own rules) and applies it only when its version is newer. Additive
// in v1 (M7a.6): a host without the verb answers unknown_route.
type SetAvailabilityRequest struct {
	// Document is the new signed envelope.
	Document AvailabilityDocument `json:"document"`
}

// SetAvailabilityResponse answers an availability push.
type SetAvailabilityResponse struct {
	// Version is the envelope version now in force on the host.
	Version int64 `json:"version"`
	// Applied is false when the version was not newer.
	Applied bool `json:"applied"`
}

// DeactivateMemberRequest is POST /tenants/{id}/members/deactivate, by WorkOS sub.
type DeactivateMemberRequest struct {
	// TenantID must match the path id.
	TenantID string `json:"tenant_id"`
	// Sub is the WorkOS subject to deactivate.
	Sub string `json:"sub"`
	// IdempotencyKey makes the durable retry safe.
	IdempotencyKey string `json:"idempotency_key"`
}

// DeactivateMemberResponse answers a deactivate. Unknown subs are not an error.
type DeactivateMemberResponse struct {
	// Deactivated is true when a member was found and deactivated.
	Deactivated bool `json:"deactivated"`
}

// EvictRequest is POST /tenants/{id}/evict, a lifecycle broadcast asking the
// host to drop the tenant's runtime.
type EvictRequest struct {
	// TenantID must match the path id.
	TenantID string `json:"tenant_id"`
	// LifecycleGen is the generation the host must not build below.
	LifecycleGen int64 `json:"lifecycle_gen"`
}

// EvictResponse answers an evict.
type EvictResponse struct {
	// Evicted is true when a live runtime was dropped.
	Evicted bool `json:"evicted"`
}

// UsageRequest is GET /usage?day=YYYY-MM-DD, carried here as a value.
type UsageRequest struct {
	// Day is the server receipt day, YYYY-MM-DD (UTC).
	Day string `json:"day"`
}

// TenantUsage is one tenant's usage for a day (plan 06 5.8.5).
type TenantUsage struct {
	// TenantID is the org id.
	TenantID string `json:"tenant_id"`
	// ActiveSeatMemberIDs are distinct member ids whose enrolled node pushed at
	// least one AI session that receipt day; backfill excluded. Machine
	// identities are never listed.
	ActiveSeatMemberIDs []string `json:"active_seat_member_ids"`
	// MachineIdentities counts active machine identities (not seats).
	MachineIdentities int64 `json:"machine_identities"`
	// Sessions counts AI sessions received that day.
	Sessions int64 `json:"sessions"`
	// Members is the current member count.
	Members int64 `json:"members"`
	// AIGWRequests is the hosted AI gateway's forwarded model calls in the
	// UTC calendar month of the report's day, as counted when the host read
	// the report (month to date: the meter is monthly; hosted AI gateway plan
	// 3.13, lane L4). Absent (0) when the org made none. Additive: an older
	// host never sends it and an older control plane ignores it.
	AIGWRequests int64 `json:"aigw_requests,omitempty"`
	// AIGWRefusals are the AI gateway usage gate's refusals in the same
	// month by reason (refused_plan, refused_quota, refused_concurrency,
	// refused_unavailable), for the staff usage card; absent when none.
	AIGWRefusals map[string]int64 `json:"aigw_refusals,omitempty"`
}

// UsageResponse is the signed daily report body.
type UsageResponse struct {
	// Day echoes the request.
	Day string `json:"day"`
	// Tenants holds one entry per tenant on the host.
	Tenants []TenantUsage `json:"tenants"`
}

// RouteCheckRequest is POST /route-check: does this host serve the tenant?
type RouteCheckRequest struct {
	// TenantID is the org id to check.
	TenantID string `json:"tenant_id"`
}

// RouteCheckResponse answers a route check.
type RouteCheckResponse struct {
	// Served is true when this host holds the tenant.
	Served bool `json:"served"`
	// State is the tenant's state on this host, empty when not served.
	State TenantState `json:"state,omitempty"`
	// LifecycleGen is the tenant's generation, zero when not served.
	LifecycleGen int64 `json:"lifecycle_gen,omitempty"`
}

// HealthResponse is GET /tenants/{id}/health. It is enum-only: no free text,
// no content, so staff need no support grant to read it.
type HealthResponse struct {
	// TenantID is the org id.
	TenantID string `json:"tenant_id"`
	// Status is the overall verdict.
	Status HealthStatus `json:"status"`
	// LastPush buckets the time since the last accepted push.
	LastPush PushRecency `json:"last_push"`
	// Backlog buckets the unapplied backlog.
	Backlog BacklogLevel `json:"backlog"`
	// Quota is the quota posture.
	Quota QuotaState `json:"quota"`
	// Error is the class of the latest failure.
	Error ErrorClass `json:"error"`
}
