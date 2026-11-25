package openai

import (
	"encoding/json"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceUsers is the catalog id of the surface.
const SurfaceUsers vs.SurfaceID = "openai.platform.users"

// Users vocabulary.
const (
	UsersContract = "openai.platform.users/v1 openai-python admin types (2026-10-07)"

	// UserType is the namespaced resource type of one organization user.
	UserType vs.ResourceType = "User/openai.platform_user/v1"
	// NamespaceUser keys a user by the Platform user id (user-...).
	NamespaceUser = "openai.user"
)

// Users returns the driver of openai.platform.users.
//
// Contract (openai-python organization_user type and the users list): GET
// /v1/organization/users with limit (1 to 100) and after; response
// {"object": "list", "data": [{object, id, name, email, role, added_at,
// is_service_account, is_scim_managed, api_key_last_used_at}], "first_id",
// "last_id", "has_more"}. The Admin key is organization-scoped, so a complete
// page set lists every user and a complete run is authoritative for deletion.
func Users() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:               SurfaceUsers,
		Build:                 buildUsers,
		ParseResponse:         parseUsers,
		Auth:                  adminAuth,
		ContentTypes:          []string{"application/json"},
		Supplies:              []vs.DataClass{vs.ClassIdentity},
		AuthoritativeSnapshot: true,
		ClosedDTO:             true,
		ContractVersion:       UsersContract,
		KnownPaths:            usersKnownPaths,
	}
}

func buildUsers(_ vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	q, err := listQuery(SurfaceUsers, cursor)
	if err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: "/v1/organization/users", Query: q}, nil
}

// userRecord is the closed DTO of one organization user.
type userRecord struct {
	ID               *string      `json:"id"`
	Name             *string      `json:"name"`
	Email            *string      `json:"email"`
	Role             *string      `json:"role"`
	AddedAt          *json.Number `json:"added_at"`
	IsServiceAccount *bool        `json:"is_service_account"`
	IsSCIMManaged    *bool        `json:"is_scim_managed"`
	APIKeyLastUsedAt *json.Number `json:"api_key_last_used_at"`
}

func parseUsers(r vendorapi.Response) (vendorapi.Page, error) {
	var doc listDoc[userRecord]
	next, err := listEnvelope(SurfaceUsers, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{NextCursor: next, Snapshot: &vendorapi.SnapshotManifest{
		Scope:           []vendorapi.ScopeKey{{Namespace: NamespaceUser, Kind: vs.KindUser}},
		SelectorDigest:  "organization",
		PageSet:         "organization_users",
		ContractVersion: UsersContract,
	}}
	seen := map[string]bool{}
	for i, u := range *doc.Data {
		if u.ID == nil || *u.ID == "" {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceUsers, "data[%d].id is missing", i)
		}
		if seen[*u.ID] {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceUsers, "data[%d] repeats a user", i)
		}
		seen[*u.ID] = true
		added, ok1 := unixRFC3339(u.AddedAt)
		lastUsed, ok2 := unixRFC3339(u.APIKeyLastUsedAt)
		if !ok1 || !ok2 {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceUsers, "data[%d] has a timestamp that is not Unix seconds", i)
		}
		attrs := map[string]string{}
		for k, v := range map[string]string{
			"email": vendorapi.Str(u.Email), "role": vendorapi.Str(u.Role), "added_at": added, "key_last_used_at": lastUsed,
		} {
			if v != "" {
				attrs[k] = v
			}
		}
		if u.IsServiceAccount != nil {
			attrs["is_service_account"] = strconv.FormatBool(*u.IsServiceAccount)
		}
		if u.IsSCIMManaged != nil {
			attrs["is_scim_managed"] = strconv.FormatBool(*u.IsSCIMManaged)
		}
		page.Resources = append(page.Resources, vendorapi.ResourceObservation{
			Type: UserType, ID: vs.ExternalID{Namespace: NamespaceUser, Value: *u.ID}, DisplayName: vendorapi.Str(u.Name), Attrs: attrs,
		})
	}
	return page, nil
}

// usersKnownPaths are the documented response paths (the corpus field ledgers).
var usersKnownPaths = []string{
	"data", "data[]", "data[].added_at", "data[].api_key_last_used_at", "data[].email", "data[].id",
	"data[].is_scim_managed", "data[].is_service_account", "data[].name", "data[].object", "data[].role",
	"first_id", "has_more", "last_id", "object",
}
