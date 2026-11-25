package cognition

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceEnterpriseUsers is the catalog id of the surface.
const SurfaceEnterpriseUsers vs.SurfaceID = "cognition.devin_v3.ent_users"

// Enterprise user vocabulary.
const (
	UsersContract = "cognition.devin_v3.ent_users/v1 v3-openapi 3.0.0 (2026-10-08)"

	// UserType is the namespaced resource type of one enterprise member.
	UserType vs.ResourceType = "User/cognition.enterprise_user/v1"
	// NamespaceUser keys a member by the Devin user id (user_...), the join
	// key the consumption and audit surfaces share.
	NamespaceUser = "cognition.user"
)

// EnterpriseUsers returns the driver of cognition.devin_v3.ent_users.
//
// Contract (v3 OpenAPI, "List Enterprise Users"): GET
// /v3/enterprise/members/users with first (1 to 200) and after; response
// PaginatedResponse[EnterpriseUser] {items: [{user_id, email, name,
// role_assignments: [{org_id, role: {role_id, role_name, role_type}}],
// enterprise_joined_at}], has_next_page, end_cursor, total}. The enterprise
// credential sees every member (permission ViewAccountMembership), so a
// complete page set is authoritative for deletion. The email filter is never
// sent.
func EnterpriseUsers() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:               SurfaceEnterpriseUsers,
		Build:                 buildUsers,
		ParseResponse:         parseUsers,
		Auth:                  bearerAuth,
		ContentTypes:          []string{"application/json"},
		Supplies:              []vs.DataClass{vs.ClassIdentity, vs.ClassRoles},
		AuthoritativeSnapshot: true,
		ContractVersion:       UsersContract,
		KnownPaths:            usersKnownPaths,
	}
}

func buildUsers(_ vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	q := map[string][]string{}
	if err := pageQuery(SurfaceEnterpriseUsers, q, cursor); err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: "/v3/enterprise/members/users", Query: q}, nil
}

type enterpriseUser struct {
	UserID          *string           `json:"user_id"`
	Email           *string           `json:"email"`
	Name            *string           `json:"name"`
	RoleAssignments *[]roleAssignment `json:"role_assignments"`
	JoinedAt        *num              `json:"enterprise_joined_at"`
}

type roleAssignment struct {
	OrgID *string `json:"org_id"`
	Role  *struct {
		RoleID   *string `json:"role_id"`
		RoleName *string `json:"role_name"`
		RoleType *string `json:"role_type"`
	} `json:"role"`
}

func parseUsers(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceEnterpriseUsers
	var doc paginated[enterpriseUser]
	next, err := envelope(s, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{NextCursor: next, Snapshot: &vendorapi.SnapshotManifest{
		Scope:           []vendorapi.ScopeKey{{Namespace: NamespaceUser, Kind: vs.KindUser}},
		SelectorDigest:  "enterprise",
		PageSet:         "enterprise_members_users",
		ContractVersion: UsersContract,
	}}
	seen := map[string]bool{}
	for i, u := range *doc.Items {
		if u.UserID == nil || *u.UserID == "" {
			return vendorapi.Page{}, vendorapi.Drift(s, "items[%d].user_id is missing", i)
		}
		if seen[*u.UserID] {
			return vendorapi.Page{}, vendorapi.Drift(s, "items[%d] repeats a member", i)
		}
		seen[*u.UserID] = true
		if u.RoleAssignments == nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "items[%d].role_assignments is missing", i)
		}
		attrs := map[string]string{}
		if e := vendorapi.Str(u.Email); e != "" {
			attrs["email"] = e
		}
		var entRoles []string
		orgRoles := 0
		for j, ra := range *u.RoleAssignments {
			if ra.Role == nil || ra.Role.RoleName == nil || ra.Role.RoleType == nil || ra.Role.RoleID == nil {
				return vendorapi.Page{}, vendorapi.Drift(s, "items[%d].role_assignments[%d].role misses a required member", i, j)
			}
			switch *ra.Role.RoleType {
			case "enterprise":
				entRoles = append(entRoles, *ra.Role.RoleName)
			case "org":
				orgRoles++
			default:
				return vendorapi.Page{}, vendorapi.Drift(s, "items[%d].role_assignments[%d].role.role_type is not a documented value", i, j)
			}
		}
		if len(entRoles) > 0 {
			sort.Strings(entRoles)
			attrs["enterprise_roles"] = strings.Join(entRoles, ",")
		}
		attrs["org_role_count"] = strconv.Itoa(orgRoles)
		if u.JoinedAt != nil {
			t, ok := unixSeconds(u.JoinedAt)
			if !ok {
				return vendorapi.Page{}, vendorapi.Drift(s, "items[%d].enterprise_joined_at is not a Unix time", i)
			}
			attrs["enterprise_joined_at"] = t.Format(time.RFC3339)
		}
		page.Resources = append(page.Resources, vendorapi.ResourceObservation{
			Type: UserType, ID: vs.ExternalID{Namespace: NamespaceUser, Value: *u.UserID}, DisplayName: vendorapi.Str(u.Name), Attrs: attrs,
		})
	}
	return page, nil
}

// usersKnownPaths are the documented response paths (the corpus field ledger
// of the member list).
var usersKnownPaths = []string{
	"end_cursor", "has_next_page", "items", "items[]", "items[].email", "items[].enterprise_joined_at", "items[].name",
	"items[].role_assignments", "items[].role_assignments[]", "items[].role_assignments[].org_id",
	"items[].role_assignments[].role", "items[].role_assignments[].role.role_id",
	"items[].role_assignments[].role.role_name", "items[].role_assignments[].role.role_type", "items[].user_id", "total",
}
