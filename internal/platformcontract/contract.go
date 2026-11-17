package platformcontract

import "strings"

// Version is the contract version carried in BasePath.
const Version = "v1"

// BasePath is the root of every host-API route.
const BasePath = "/platform/" + Version

// Route paths. Routes with a tenant id use the PathTenant* helpers.
const (
	// PathTenants is POST (idempotent tenant create).
	PathTenants = BasePath + "/tenants"
	// PathUsage is GET with a ?day=YYYY-MM-DD query.
	PathUsage = BasePath + "/usage"
	// PathRouteCheck is POST.
	PathRouteCheck = BasePath + "/route-check"
	// PathAvailability is PUT: the platform availability envelope, pushed to
	// every host (plan 06 18.3.5; additive in v1, M7a.6).
	PathAvailability = BasePath + "/availability"
)

// PathTenantState returns PUT /tenants/{id}/state.
func PathTenantState(id string) string { return PathTenants + "/" + id + "/state" }

// PathTenantEntitlements returns PUT /tenants/{id}/entitlements.
func PathTenantEntitlements(id string) string { return PathTenants + "/" + id + "/entitlements" }

// PathTenantMembersDeactivate returns POST /tenants/{id}/members/deactivate.
func PathTenantMembersDeactivate(id string) string {
	return PathTenants + "/" + id + "/members/deactivate"
}

// PathTenantEvict returns POST /tenants/{id}/evict.
func PathTenantEvict(id string) string { return PathTenants + "/" + id + "/evict" }

// PathTenantHealth returns GET /tenants/{id}/health.
func PathTenantHealth(id string) string { return PathTenants + "/" + id + "/health" }

// TenantState is the closed tenant lifecycle vocabulary (plan 06 5.3.10).
type TenantState string

// Tenant lifecycle states.
const (
	StateProvisioning    TenantState = "provisioning"
	StateActive          TenantState = "active"
	StateSuspended       TenantState = "suspended"
	StatePendingDeletion TenantState = "pending_deletion"
	StatePurging         TenantState = "purging"
	StatePurged          TenantState = "purged"
)

// KnownTenantStates lists every TenantState in lifecycle order.
var KnownTenantStates = []TenantState{
	StateProvisioning, StateActive, StateSuspended,
	StatePendingDeletion, StatePurging, StatePurged,
}

// Valid reports whether s is a known state.
func (s TenantState) Valid() bool { return containsStr(KnownTenantStates, s) }

// HealthStatus is the overall verdict of the health verb.
type HealthStatus string

// Health verdicts.
const (
	HealthHealthy   HealthStatus = "healthy"
	HealthDegraded  HealthStatus = "degraded"
	HealthUnhealthy HealthStatus = "unhealthy"
	HealthUnknown   HealthStatus = "unknown"
)

// KnownHealthStatuses lists every HealthStatus.
var KnownHealthStatuses = []HealthStatus{HealthHealthy, HealthDegraded, HealthUnhealthy, HealthUnknown}

// Valid reports whether h is known.
func (h HealthStatus) Valid() bool { return containsStr(KnownHealthStatuses, h) }

// PushRecency buckets the time since the tenant's last accepted push.
type PushRecency string

// Push recency buckets.
const (
	PushRecent PushRecency = "recent"
	PushStale  PushRecency = "stale"
	PushNone   PushRecency = "none"
)

// KnownPushRecencies lists every PushRecency.
var KnownPushRecencies = []PushRecency{PushRecent, PushStale, PushNone}

// Valid reports whether p is known.
func (p PushRecency) Valid() bool { return containsStr(KnownPushRecencies, p) }

// BacklogLevel buckets the tenant's unapplied-record backlog.
type BacklogLevel string

// Backlog levels.
const (
	BacklogClear    BacklogLevel = "clear"
	BacklogBuilding BacklogLevel = "building"
	BacklogParked   BacklogLevel = "parked"
)

// KnownBacklogLevels lists every BacklogLevel.
var KnownBacklogLevels = []BacklogLevel{BacklogClear, BacklogBuilding, BacklogParked}

// Valid reports whether b is known.
func (b BacklogLevel) Valid() bool { return containsStr(KnownBacklogLevels, b) }

// QuotaState is the tenant's quota posture.
type QuotaState string

// Quota states.
const (
	QuotaOK       QuotaState = "ok"
	QuotaNear     QuotaState = "near"
	QuotaExceeded QuotaState = "exceeded"
	QuotaPaused   QuotaState = "paused"
)

// KnownQuotaStates lists every QuotaState.
var KnownQuotaStates = []QuotaState{QuotaOK, QuotaNear, QuotaExceeded, QuotaPaused}

// Valid reports whether q is known.
func (q QuotaState) Valid() bool { return containsStr(KnownQuotaStates, q) }

// ErrorClass is the enum-only class of the tenant's most recent failure.
type ErrorClass string

// Error classes.
const (
	ErrNone         ErrorClass = "none"
	ErrRuntimeBuild ErrorClass = "runtime_build"
	ErrPoolBudget   ErrorClass = "pool_budget"
	ErrDatabase     ErrorClass = "database"
	ErrStorage      ErrorClass = "storage"
	ErrOther        ErrorClass = "other"
)

// KnownErrorClasses lists every ErrorClass.
var KnownErrorClasses = []ErrorClass{ErrNone, ErrRuntimeBuild, ErrPoolBudget, ErrDatabase, ErrStorage, ErrOther}

// Valid reports whether e is known.
func (e ErrorClass) Valid() bool { return containsStr(KnownErrorClasses, e) }

// CreateOutcome tells whether an idempotent create made the tenant or replayed.
type CreateOutcome string

// Create outcomes.
const (
	CreateReady    CreateOutcome = "ready"
	CreateReplayed CreateOutcome = "replayed"
	CreateFailed   CreateOutcome = "failed"
)

// KnownCreateOutcomes lists every CreateOutcome.
var KnownCreateOutcomes = []CreateOutcome{CreateReady, CreateReplayed, CreateFailed}

// Valid reports whether c is known.
func (c CreateOutcome) Valid() bool { return containsStr(KnownCreateOutcomes, c) }

func containsStr[T ~string](list []T, v T) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func blank(s string) bool { return strings.TrimSpace(s) == "" }
