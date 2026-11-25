package anthropic

import (
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceUsers is the catalog id of the surface.
const SurfaceUsers vs.SurfaceID = "anthropic.console.users"

// Users vocabulary.
const (
	UsersContract = "anthropic.console.users/v1 admin-api 2023-06-01 (2026-10-07)"

	// UserType is the namespaced resource type of one organization member.
	UserType vs.ResourceType = "User/anthropic.console_user/v1"
	// NamespaceUser keys a member by the Console user id (user_...).
	NamespaceUser = "anthropic.user"

	// UsersPageLimit is the documented maximum page size (1 to 1000).
	UsersPageLimit = 1000
)

// Users returns the driver of anthropic.console.users.
//
// Contract (Admin API reference, "List Users"): GET /v1/organizations/users
// with limit and after_id; response {"data": [{id, type, email, name, role,
// added_at}], "has_more", "first_id", "last_id"}. The Admin key is
// organization-scoped, so a complete page set lists every member and a
// complete run is authoritative for deletion.
func Users() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:               SurfaceUsers,
		Build:                 buildUsers,
		ParseResponse:         parseUsers,
		Auth:                  adminAuth,
		Headers:               headers(),
		ContentTypes:          []string{"application/json"},
		Supplies:              []vs.DataClass{vs.ClassIdentity, vs.ClassRoles},
		AuthoritativeSnapshot: true,
		ContractVersion:       UsersContract,
		KnownPaths:            usersKnownPaths,
	}
}

func buildUsers(_ vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	q := map[string][]string{"limit": {strconv.Itoa(UsersPageLimit)}}
	if cursor != "" {
		if !cursorRE.MatchString(cursor) {
			return vendorapi.Request{}, vendorapi.Drift(SurfaceUsers, "cursor is not a user id")
		}
		q["after_id"] = []string{cursor}
	}
	return vendorapi.Request{Method: "GET", Path: "/v1/organizations/users", Query: q}, nil
}

type usersDoc struct {
	Data    *[]userRecord `json:"data"`
	HasMore *bool         `json:"has_more"`
	LastID  *string       `json:"last_id"`
}

type userRecord struct {
	ID      *string `json:"id"`
	Type    *string `json:"type"`
	Email   *string `json:"email"`
	Name    *string `json:"name"`
	Role    *string `json:"role"`
	AddedAt *string `json:"added_at"`
}

func parseUsers(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, vendorapi.Drift(SurfaceUsers, "status %d is not the documented 200", r.Status)
	}
	var doc usersDoc
	if err := vendorapi.DecodeNumbers(r.Body, &doc); err != nil {
		return vendorapi.Page{}, vendorapi.Drift(SurfaceUsers, "body does not decode as the documented list")
	}
	if doc.Data == nil || doc.HasMore == nil {
		return vendorapi.Page{}, vendorapi.Drift(SurfaceUsers, "required field data or has_more is missing")
	}
	page := vendorapi.Page{Snapshot: &vendorapi.SnapshotManifest{
		Scope:           []vendorapi.ScopeKey{{Namespace: NamespaceUser, Kind: vs.KindUser}},
		SelectorDigest:  "organization",
		PageSet:         "organizations_users",
		ContractVersion: UsersContract,
	}}
	if *doc.HasMore {
		if doc.LastID == nil || !cursorRE.MatchString(*doc.LastID) {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceUsers, "has_more is true without a usable last_id")
		}
		page.NextCursor = *doc.LastID
	}
	seen := map[string]bool{}
	for i, u := range *doc.Data {
		if u.ID == nil || *u.ID == "" {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceUsers, "data[%d].id is missing", i)
		}
		if seen[*u.ID] {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceUsers, "data[%d] repeats a user", i)
		}
		seen[*u.ID] = true
		attrs := map[string]string{}
		for k, v := range map[string]*string{"email": u.Email, "role": u.Role, "added_at": u.AddedAt, "type": u.Type} {
			if v != nil && *v != "" {
				attrs[k] = *v
			}
		}
		page.Resources = append(page.Resources, vendorapi.ResourceObservation{
			Type: UserType, ID: vs.ExternalID{Namespace: NamespaceUser, Value: *u.ID}, DisplayName: vendorapi.Str(u.Name), Attrs: attrs,
		})
	}
	return page, nil
}

// usersKnownPaths are the documented response paths (the corpus field
// ledgers of "List Users").
var usersKnownPaths = []string{
	"data", "data[]", "data[].added_at", "data[].email", "data[].id", "data[].name", "data[].role", "data[].type",
	"first_id", "has_more", "last_id",
}
