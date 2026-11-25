package vendorsurface

import (
	"fmt"
	"regexp"
	"strings"
)

// Axis is one orthogonal dimension of plan 4.5 (R-E-02). A supply's reporting
// DataClass maps to exactly one (Axis, Value, Subtype) triple through the
// dimension table, and back, so coverage summaries never double count.
type Axis string

// Axes.
const (
	AxisResource Axis = "resource"
	AxisMeasure  Axis = "measure"
	AxisEvent    Axis = "event"
	AxisArtifact Axis = "artifact"
	AxisPolicy   Axis = "policy"
)

// Dimension is the orthogonal classification of one supply.
type Dimension struct {
	Axis    Axis   `json:"axis"`
	Value   string `json:"value"`
	Subtype string `json:"subtype,omitempty"`
}

// dimensionTable is the one pure mapping between the 21 reporting classes and
// the orthogonal dimensions (ResourceClass Principal, Container, Entitlement,
// CredentialMetadata, Role, Policy, Limit; MeasureClass Usage, Cost, LOC,
// Commits, Adoption; EventClass Session, Request, Audit; ArtifactClass
// BillingExport, Content). Telemetry is a Request event; Retention is a Policy
// resource with subtype retention. It must stay a bijection
// (TestDimensionTableIsBijective).
var dimensionTable = []struct {
	Class DataClass
	Dim   Dimension
}{
	{ClassIdentity, Dimension{AxisResource, "Principal", "user"}},
	{ClassGroups, Dimension{AxisResource, "Principal", "group"}},
	{ClassServiceAccounts, Dimension{AxisResource, "Principal", "service_account"}},
	{ClassProjects, Dimension{AxisResource, "Container", ""}},
	{ClassCredentials, Dimension{AxisResource, "CredentialMetadata", ""}},
	{ClassRoles, Dimension{AxisResource, "Role", ""}},
	{ClassSeats, Dimension{AxisResource, "Entitlement", ""}},
	{ClassLimits, Dimension{AxisResource, "Limit", "spend"}},
	{ClassRateLimits, Dimension{AxisResource, "Limit", "rate"}},
	{ClassPolicy, Dimension{AxisPolicy, "Policy", ""}},
	{ClassRetention, Dimension{AxisPolicy, "Policy", "retention"}},
	{ClassUsage, Dimension{AxisMeasure, "Usage", ""}},
	{ClassCost, Dimension{AxisMeasure, "Cost", ""}},
	{ClassLOC, Dimension{AxisMeasure, "LOC", ""}},
	{ClassCommits, Dimension{AxisMeasure, "Commits", ""}},
	{ClassAdoption, Dimension{AxisMeasure, "Adoption", ""}},
	{ClassSessions, Dimension{AxisEvent, "Session", ""}},
	{ClassTelemetry, Dimension{AxisEvent, "Request", ""}},
	{ClassAudit, Dimension{AxisEvent, "Audit", ""}},
	{ClassBillingExport, Dimension{AxisArtifact, "BillingExport", ""}},
	{ClassContent, Dimension{AxisArtifact, "Content", ""}},
}

// DataClasses returns the 21 reporting classes in plan order.
func DataClasses() []DataClass {
	return []DataClass{
		ClassIdentity, ClassGroups, ClassProjects, ClassServiceAccounts, ClassCredentials,
		ClassRoles, ClassSeats, ClassUsage, ClassCost, ClassBillingExport, ClassLimits, ClassRateLimits, ClassSessions,
		ClassLOC, ClassCommits, ClassAdoption, ClassAudit, ClassContent, ClassTelemetry, ClassPolicy, ClassRetention,
	}
}

// ResourceKind is a normalized resource superkind of the enterprise resource
// graph (plan 4.0, 4.5 R-E-03).
type ResourceKind string

// Resource superkinds.
const (
	KindOrg            ResourceKind = "Org"
	KindContainer      ResourceKind = "Container"
	KindGroup          ResourceKind = "Group"
	KindUser           ResourceKind = "User"
	KindInvite         ResourceKind = "Invite"
	KindSeat           ResourceKind = "Seat"
	KindServiceAccount ResourceKind = "ServiceAccount"
	KindCredential     ResourceKind = "Credential"
	KindRole           ResourceKind = "Role"
	KindPolicy         ResourceKind = "Policy"
	KindLimit          ResourceKind = "Limit"
)

// ContainerKind types a Container so a Cursor billing group and an OpenAI
// project land in the same table without a vendor branch.
type ContainerKind string

// Container kinds.
const (
	ContainerWorkspace    ContainerKind = "workspace"
	ContainerProject      ContainerKind = "project"
	ContainerTeam         ContainerKind = "team"
	ContainerBillingGroup ContainerKind = "billing_group"
	ContainerCostCenter   ContainerKind = "cost_center"
	ContainerNamespace    ContainerKind = "namespace"
	ContainerRepository   ContainerKind = "repository"
)

// EdgeKind is a typed, directional graph edge (plan 4.5 R-E-03).
type EdgeKind string

// Edge kinds.
const (
	EdgeContains       EdgeKind = "contains"
	EdgeMemberOf       EdgeKind = "member_of"
	EdgeAssignedRole   EdgeKind = "assigned_role"
	EdgeLicensedTo     EdgeKind = "licensed_to"
	EdgeInvitedTo      EdgeKind = "invited_to"
	EdgeOwnsCredential EdgeKind = "owns_credential" //nolint:gosec // G101: an edge kind, not a credential
	EdgeTargets        EdgeKind = "targets"
	EdgeInheritsFrom   EdgeKind = "inherits_from"
	EdgeSyncedFrom     EdgeKind = "synced_from"
	EdgeBilledThrough  EdgeKind = "billed_through"
	EdgeGovernedBy     EdgeKind = "governed_by"
)

// ResourceType is a namespaced resource subtype: a normalized superkind plus a
// catalog-authored "<vendor>.<subtype>/v<N>" (for example
// "Container/github.repository/v1", "Credential/anthropic.wif_rule/v1").
type ResourceType string

var resourceTypeRE = regexp.MustCompile(`^([A-Z][A-Za-z]+)/([a-z0-9]+\.[a-z0-9_]+)/v([1-9][0-9]*)$`)

// ParseResourceType splits and validates a namespaced resource type.
func ParseResourceType(t ResourceType) (ResourceKind, string, error) {
	m := resourceTypeRE.FindStringSubmatch(string(t))
	if m == nil {
		return "", "", fmt.Errorf("vendorsurface.ParseResourceType: %q is not Kind/vendor.subtype/vN", t)
	}
	k := ResourceKind(m[1])
	if !resourceKinds[k] {
		return "", "", fmt.Errorf("vendorsurface.ParseResourceType: unknown superkind %q", m[1])
	}
	return k, m[2], nil
}

// ExternalID is a vendor id with its namespace; ids from different namespaces
// never compare equal (plan 4.5 R-E-03, R-E-04).
type ExternalID struct {
	Namespace string `json:"namespace"`
	Value     string `json:"value"`
}

// Valid reports whether both parts are present and the namespace is a dotted
// lower-case name.
func (e ExternalID) Valid() bool {
	return e.Value != "" && strings.Contains(e.Namespace, ".") && strings.ToLower(e.Namespace) == e.Namespace
}

var resourceKinds = map[ResourceKind]bool{
	KindOrg: true, KindContainer: true, KindGroup: true, KindUser: true,
	KindInvite: true, KindSeat: true, KindServiceAccount: true, KindCredential: true, KindRole: true, KindPolicy: true,
	KindLimit: true,
}
