package cognition

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// The enterprise inventory reads of lane ENTAPI-L16B (T-708): organizations,
// roles, service users, IdP groups and the Devin ACU limits. All five are
// v3 PaginatedResponse lists on the enterprise credential (end_cursor
// paging, first up to 200), so a complete page set is authoritative for its
// scope. Every write the catalog rows mention (create, patch, delete) stays
// unbuilt: these are reads.
const (
	SurfaceOrganizations vs.SurfaceID = "cognition.devin_v3.organizations"
	SurfaceRoles         vs.SurfaceID = "cognition.devin_v3.roles"
	SurfaceServiceUsers  vs.SurfaceID = "cognition.devin_v3.service_users"
	SurfaceIdPGroups     vs.SurfaceID = "cognition.devin_v3.idp_groups"
	SurfaceACULimits     vs.SurfaceID = "cognition.devin_v3.acu_limits_org"
)

// Inventory vocabulary.
const (
	InventoryContract = "cognition.devin_v3.inventory/v1 v3-openapi 3.0.0 (2026-10-08)"

	OrganizationType vs.ResourceType = "Container/cognition.organization/v1"
	RoleType         vs.ResourceType = "Role/cognition.role/v1"
	ServiceUserType  vs.ResourceType = "ServiceAccount/cognition.service_user/v1"
	IdPGroupType     vs.ResourceType = "Group/cognition.idp_group/v1"
	ACULimitType     vs.ResourceType = "Limit/cognition.acu_limit/v1"

	NamespaceOrg         = "cognition.org"
	NamespaceRole        = "cognition.role"
	NamespaceServiceUser = "cognition.service_user"
	NamespaceIdPGroup    = "cognition.idp_group"
	NamespaceACULimit    = "cognition.acu_limit"
)

// listSpec is one row of the inventory table: the surface, its path, the
// snapshot scope and the item parser. parse returns the observation of one
// item and its key, or an error naming the drift.
type listSpec struct {
	surface  vs.SurfaceID
	path     string
	pageSet  string
	scope    vendorapi.ScopeKey
	supplies []vs.DataClass
	known    []string
}

func (l listSpec) driver(parse func(r vendorapi.Response) (vendorapi.Page, error)) vendorapi.Driver {
	return vendorapi.Driver{
		Surface:               l.surface,
		Build:                 l.build,
		ParseResponse:         parse,
		Auth:                  bearerAuth,
		ContentTypes:          []string{"application/json"},
		Supplies:              l.supplies,
		AuthoritativeSnapshot: true,
		ContractVersion:       InventoryContract,
		KnownPaths:            l.known,
	}
}

func (l listSpec) build(_ vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	q := map[string][]string{}
	if err := pageQuery(l.surface, q, cursor); err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: l.path, Query: q}, nil
}

func (l listSpec) page(next string) vendorapi.Page {
	return vendorapi.Page{NextCursor: next, Snapshot: &vendorapi.SnapshotManifest{
		Scope: []vendorapi.ScopeKey{l.scope}, SelectorDigest: "enterprise", PageSet: l.pageSet,
		ContractVersion: InventoryContract,
	}}
}

// listItems decodes one page of a list and walks its items through each,
// refusing a repeated key.
func listItems[T any](l listSpec, r vendorapi.Response, each func(i int, it T) (vendorapi.ResourceObservation, error)) (vendorapi.Page, error) {
	var doc paginated[T]
	next, err := envelope(l.surface, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := l.page(next)
	seen := map[string]bool{}
	for i, it := range *doc.Items {
		obs, err := each(i, it)
		if err != nil {
			return vendorapi.Page{}, err
		}
		if seen[obs.ID.Value] {
			return vendorapi.Page{}, vendorapi.Drift(l.surface, "items[%d] repeats a key", i)
		}
		seen[obs.ID.Value] = true
		page.Resources = append(page.Resources, obs)
	}
	return page, nil
}

// timeAttr renders an optional integer timestamp as RFC 3339 into attrs; a
// value that is not a Unix time is drift.
func timeAttr(s vs.SurfaceID, attrs map[string]string, name string, n *num, i int) error {
	if n == nil {
		return nil
	}
	t, ok := unixSeconds(n)
	if !ok {
		return vendorapi.Drift(s, "items[%d].%s is not a Unix time", i, name)
	}
	attrs[name] = t.Format(time.RFC3339)
	return nil
}

// countAttr renders an optional non-negative integer into attrs.
func countAttr(s vs.SurfaceID, attrs map[string]string, name string, n *num, i int) error {
	if n == nil {
		return nil
	}
	v, err := strconv.ParseInt(string(*n), 10, 64)
	if err != nil || v < 0 {
		return vendorapi.Drift(s, "items[%d].%s is not a non-negative integer", i, name)
	}
	attrs[name] = strconv.FormatInt(v, 10)
	return nil
}

// Organizations ---------------------------------------------------------

var orgList = listSpec{
	surface: SurfaceOrganizations, path: "/v3/enterprise/organizations", pageSet: "enterprise_organizations",
	scope:    vendorapi.ScopeKey{Namespace: NamespaceOrg, Kind: vs.KindContainer},
	supplies: []vs.DataClass{vs.ClassProjects, vs.ClassLimits},
	known: listKnown("created_at", "max_cycle_acu_limit", "max_session_acu_limit", "name", "org_id",
		"updated_at"),
}

// Organizations returns the driver of cognition.devin_v3.organizations.
//
// Contract (v3 OpenAPI, "List organizations in the enterprise"): GET
// /v3/enterprise/organizations, first and after; items OrganizationResponse
// {org_id, name, created_at, updated_at, max_session_acu_limit|null,
// max_cycle_acu_limit|null}, every member required. A null limit is "no
// limit set" and is absent, never zero.
func Organizations() vendorapi.Driver { return orgList.driver(parseOrganizations) }

type organization struct {
	OrgID        *string `json:"org_id"`
	Name         *string `json:"name"`
	CreatedAt    *num    `json:"created_at"`
	UpdatedAt    *num    `json:"updated_at"`
	SessionLimit *num    `json:"max_session_acu_limit"`
	CycleLimit   *num    `json:"max_cycle_acu_limit"`
}

func parseOrganizations(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceOrganizations
	return listItems(orgList, r, func(i int, o organization) (vendorapi.ResourceObservation, error) {
		if o.OrgID == nil || *o.OrgID == "" || o.Name == nil || o.CreatedAt == nil || o.UpdatedAt == nil {
			return vendorapi.ResourceObservation{}, vendorapi.Drift(s, "items[%d] misses a required member", i)
		}
		attrs := map[string]string{}
		for _, a := range []struct {
			name string
			n    *num
			time bool
		}{
			{"created_at", o.CreatedAt, true},
			{"updated_at", o.UpdatedAt, true},
			{"max_session_acu_limit", o.SessionLimit, false},
			{"max_cycle_acu_limit", o.CycleLimit, false},
		} {
			f := countAttr
			if a.time {
				f = timeAttr
			}
			if err := f(s, attrs, a.name, a.n, i); err != nil {
				return vendorapi.ResourceObservation{}, err
			}
		}
		return vendorapi.ResourceObservation{
			Type: OrganizationType, ID: vs.ExternalID{Namespace: NamespaceOrg, Value: *o.OrgID},
			ContainerKind: vs.ContainerWorkspace, DisplayName: *o.Name, Attrs: attrs,
		}, nil
	})
}

// Roles -----------------------------------------------------------------

var roleList = listSpec{
	surface: SurfaceRoles, path: "/v3/enterprise/roles", pageSet: "enterprise_roles",
	scope:    vendorapi.ScopeKey{Namespace: NamespaceRole, Kind: vs.KindRole},
	supplies: []vs.DataClass{vs.ClassRoles},
	known:    listKnown("role_id", "role_name", "role_type"),
}

// Roles returns the driver of cognition.devin_v3.roles.
//
// Contract (v3 OpenAPI, "Get roles for this enterprise"): GET
// /v3/enterprise/roles; items Role {role_id, role_name, role_type
// enterprise|org}, all required.
func Roles() vendorapi.Driver { return roleList.driver(parseRoles) }

type role struct {
	RoleID   *string `json:"role_id"`
	RoleName *string `json:"role_name"`
	RoleType *string `json:"role_type"`
}

func parseRoles(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceRoles
	return listItems(roleList, r, func(i int, ro role) (vendorapi.ResourceObservation, error) {
		if ro.RoleID == nil || *ro.RoleID == "" || ro.RoleName == nil || ro.RoleType == nil {
			return vendorapi.ResourceObservation{}, vendorapi.Drift(s, "items[%d] misses a required member", i)
		}
		if *ro.RoleType != "enterprise" && *ro.RoleType != "org" {
			return vendorapi.ResourceObservation{}, vendorapi.Drift(s, "items[%d].role_type is not a documented value", i)
		}
		return vendorapi.ResourceObservation{
			Type: RoleType, ID: vs.ExternalID{Namespace: NamespaceRole, Value: *ro.RoleID},
			DisplayName: *ro.RoleName, Attrs: map[string]string{"role_type": *ro.RoleType},
		}, nil
	})
}

// Service users ----------------------------------------------------------

var serviceUserList = listSpec{
	surface: SurfaceServiceUsers, path: "/v3/enterprise/members/service-users", pageSet: "enterprise_service_users",
	scope:    vendorapi.ScopeKey{Namespace: NamespaceServiceUser, Kind: vs.KindServiceAccount},
	supplies: []vs.DataClass{vs.ClassServiceAccounts, vs.ClassRoles},
	known: listKnown("deleted_at", "expires_at", "name", "role_assignments", "role_assignments[]",
		"role_assignments[].org_id", "role_assignments[].role", "role_assignments[].role.role_id",
		"role_assignments[].role.role_name", "role_assignments[].role.role_type", "service_user_id"),
}

// ServiceUsers returns the driver of cognition.devin_v3.service_users.
//
// Contract (v3 OpenAPI, "List service users in the enterprise"): GET
// /v3/enterprise/members/service-users with include_inactive at its
// documented default (false); items ServiceUser {service_user_id, name,
// expires_at|null, deleted_at|null, role_assignments}, all required. A
// service user is an agent identity: never a credential, and the API key
// list (service_user_api_keys) is a separate, unbuilt surface.
func ServiceUsers() vendorapi.Driver { return serviceUserList.driver(parseServiceUsers) }

type serviceUser struct {
	ID              *string           `json:"service_user_id"`
	Name            *string           `json:"name"`
	ExpiresAt       *num              `json:"expires_at"`
	DeletedAt       *num              `json:"deleted_at"`
	RoleAssignments *[]roleAssignment `json:"role_assignments"`
}

func parseServiceUsers(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceServiceUsers
	return listItems(serviceUserList, r, func(i int, u serviceUser) (vendorapi.ResourceObservation, error) {
		if u.ID == nil || *u.ID == "" || u.Name == nil || u.RoleAssignments == nil {
			return vendorapi.ResourceObservation{}, vendorapi.Drift(s, "items[%d] misses a required member", i)
		}
		attrs, err := roleAttrs(s, *u.RoleAssignments, i)
		if err != nil {
			return vendorapi.ResourceObservation{}, err
		}
		for _, a := range []struct {
			name string
			n    *num
		}{{"expires_at", u.ExpiresAt}, {"deleted_at", u.DeletedAt}} {
			if err := timeAttr(s, attrs, a.name, a.n, i); err != nil {
				return vendorapi.ResourceObservation{}, err
			}
		}
		return vendorapi.ResourceObservation{
			Type: ServiceUserType, ID: vs.ExternalID{Namespace: NamespaceServiceUser, Value: *u.ID},
			DisplayName: *u.Name, Attrs: attrs,
		}, nil
	})
}

// roleAttrs reduces role assignments to flat values: the sorted
// enterprise-level role names and the count of org-level assignments (the
// same reduction the enterprise member list uses).
func roleAttrs(s vs.SurfaceID, ras []roleAssignment, i int) (map[string]string, error) {
	attrs := map[string]string{}
	var ent []string
	orgRoles := 0
	for j, ra := range ras {
		if ra.Role == nil || ra.Role.RoleName == nil || ra.Role.RoleType == nil || ra.Role.RoleID == nil {
			return nil, vendorapi.Drift(s, "items[%d].role_assignments[%d].role misses a required member", i, j)
		}
		switch *ra.Role.RoleType {
		case "enterprise":
			ent = append(ent, *ra.Role.RoleName)
		case "org":
			orgRoles++
		default:
			return nil, vendorapi.Drift(s, "items[%d].role_assignments[%d].role.role_type is not a documented value", i, j)
		}
	}
	if len(ent) > 0 {
		sort.Strings(ent)
		attrs["enterprise_roles"] = strings.Join(ent, ",")
	}
	attrs["org_role_count"] = strconv.Itoa(orgRoles)
	return attrs, nil
}

// IdP groups -------------------------------------------------------------

var idpGroupList = listSpec{
	surface: SurfaceIdPGroups, path: "/v3/enterprise/idp-groups", pageSet: "enterprise_idp_groups",
	scope:    vendorapi.ScopeKey{Namespace: NamespaceIdPGroup, Kind: vs.KindGroup},
	supplies: []vs.DataClass{vs.ClassGroups},
	known:    listKnown("idp_group_name"),
}

// IdPGroups returns the driver of cognition.devin_v3.idp_groups.
//
// Contract (v3 OpenAPI, "List IDP groups registered with this enterprise"):
// GET /v3/enterprise/idp-groups; items IdpGroupResponse {idp_group_name},
// the group's only member and its key.
func IdPGroups() vendorapi.Driver { return idpGroupList.driver(parseIdPGroups) }

type idpGroup struct {
	Name *string `json:"idp_group_name"`
}

func parseIdPGroups(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceIdPGroups
	return listItems(idpGroupList, r, func(i int, g idpGroup) (vendorapi.ResourceObservation, error) {
		if g.Name == nil || *g.Name == "" {
			return vendorapi.ResourceObservation{}, vendorapi.Drift(s, "items[%d].idp_group_name is missing", i)
		}
		return vendorapi.ResourceObservation{
			Type: IdPGroupType, ID: vs.ExternalID{Namespace: NamespaceIdPGroup, Value: *g.Name}, DisplayName: *g.Name,
		}, nil
	})
}

// ACU limits -------------------------------------------------------------

var aculimitList = listSpec{
	surface: SurfaceACULimits, path: "/v3/enterprise/consumption/acu-limits/devin", pageSet: "enterprise_acu_limits_devin",
	scope:    vendorapi.ScopeKey{Namespace: NamespaceACULimit, Kind: vs.KindLimit},
	supplies: []vs.DataClass{vs.ClassLimits},
	known:    listKnown("cycle_acu_limit", "org_id", "scope", "user_id"),
}

// ACULimits returns the driver of cognition.devin_v3.acu_limits_org.
//
// Contract (v3 OpenAPI, "Get all org-level Devin ACU limits for this
// enterprise"): GET /v3/enterprise/consumption/acu-limits/devin; items
// ACULimitResponse {cycle_acu_limit, scope enterprise|org|user,
// org_id|null, user_id|null}. A limit is keyed by its scope and owner:
// "enterprise", "org:<org_id>" or "user:<org_id>:<user_id>" (the org id empty
// when the schema's nullable org_id is null). The limit is a
// count of ACUs per billing cycle, never money, and the mirror is read only:
// the PUT and DELETE writes stay unbuilt.
func ACULimits() vendorapi.Driver { return aculimitList.driver(parseACULimits) }

type acuLimit struct {
	Limit  *num    `json:"cycle_acu_limit"`
	Scope  *string `json:"scope"`
	OrgID  *string `json:"org_id"`
	UserID *string `json:"user_id"`
}

func parseACULimits(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceACULimits
	return listItems(aculimitList, r, func(i int, l acuLimit) (vendorapi.ResourceObservation, error) {
		if l.Limit == nil || l.Scope == nil {
			return vendorapi.ResourceObservation{}, vendorapi.Drift(s, "items[%d] misses cycle_acu_limit or scope", i)
		}
		attrs := map[string]string{"scope": *l.Scope, "unit": UnitACU}
		if err := countAttr(s, attrs, "cycle_acu_limit", l.Limit, i); err != nil {
			return vendorapi.ResourceObservation{}, err
		}
		org, user := vendorapi.Str(l.OrgID), vendorapi.Str(l.UserID)
		var key string
		switch {
		case *l.Scope == "enterprise" && org == "" && user == "":
			key = "enterprise"
		case *l.Scope == "org" && org != "" && user == "":
			key = "org:" + org
		case *l.Scope == "user" && user != "":
			key = "user:" + org + ":" + user
		default:
			return vendorapi.ResourceObservation{}, vendorapi.Drift(s, "items[%d] scope and owner ids disagree or the scope is undocumented", i)
		}
		if org != "" {
			attrs["org_id"] = org
		}
		if user != "" {
			attrs["user_id"] = user
		}
		return vendorapi.ResourceObservation{
			Type: ACULimitType, ID: vs.ExternalID{Namespace: NamespaceACULimit, Value: key}, Attrs: attrs,
		}, nil
	})
}

// listKnown returns the known paths of a v3 list whose items carry the given
// members (the corpus field ledger of its pages).
func listKnown(members ...string) []string {
	out := []string{"end_cursor", "has_next_page", "items", "items[]", "total"}
	for _, m := range members {
		out = append(out, "items[]."+m)
	}
	return out
}
