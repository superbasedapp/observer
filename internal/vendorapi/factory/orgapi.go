package factory

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// The Factory Public API organization reads (OpenAPI 3.0.1, info.version
// 0.1.0, https://docs.factory.com/openapi.json): the member list and the
// per-user credit limits. Same host and bearer key as the analytics API.
const (
	SurfaceOrgUsers    vs.SurfaceID = "factory.api.org_users"
	SurfaceLimitsUsers vs.SurfaceID = "factory.api.limits_users"

	OrgAPIContract = "factory.api.organization/v1 openapi 0.1.0 (2026-10-08)"

	// OrgUserType is one organization member (a WorkOS user id).
	OrgUserType vs.ResourceType = "User/factory.org_user/v1"
	// CreditLimitType is one credit limit: the organization's global
	// per-user limit or one user's override.
	CreditLimitType vs.ResourceType = "Limit/factory.credit_limit/v1" //nolint:gosec // G101: a resource type name, not a credential

	NamespaceUser        = "factory.user"
	NamespaceCreditLimit = "factory.credit_limit"
	// OrgUsersPageSize is the documented maximum of limit (1 to 100).
	OrgUsersPageSize = 100
)

// OrgUsers returns the driver of factory.api.org_users.
//
// Contract (OpenAPI listOrganizationUsers): GET /api/v0/organization/users
// with limit (1 to 100) and cursor; 200 {users: [{id, email, firstName,
// lastName, createdAt, lastSignInAt, metadata}], pagination: {hasMore,
// nextCursor|null}}, users[] requiring id, email, createdAt and metadata.
// metadata is open custom data: the driver never decodes it (closed DTO),
// which is why the row is may_return_secret and still runs. The schema has
// no role field, so no role lands.
func OrgUsers() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:               SurfaceOrgUsers,
		Build:                 buildOrgUsers,
		ParseResponse:         parseOrgUsers,
		Auth:                  bearerAuth,
		ContentTypes:          []string{"application/json"},
		Supplies:              []vs.DataClass{vs.ClassIdentity},
		AuthoritativeSnapshot: true,
		ClosedDTO:             true,
		ContractVersion:       OrgAPIContract,
		KnownPaths: []string{
			"pagination", "pagination.hasMore", "pagination.nextCursor", "users", "users[]", "users[].createdAt",
			"users[].email", "users[].firstName", "users[].id", "users[].lastName", "users[].lastSignInAt",
			"users[].metadata",
		},
	}
}

func buildOrgUsers(_ vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	q := map[string][]string{"limit": {strconv.Itoa(OrgUsersPageSize)}}
	if cursor != "" {
		if !cursorRE.MatchString(cursor) {
			return vendorapi.Request{}, fmt.Errorf("%s: cursor is not opaque", SurfaceOrgUsers)
		}
		q["cursor"] = []string{cursor}
	}
	return vendorapi.Request{Method: "GET", Path: "/api/v0/organization/users", Query: q}, nil
}

type orgUsersDoc struct {
	Users *[]struct {
		ID           *string `json:"id"`
		Email        *string `json:"email"`
		FirstName    *string `json:"firstName"`
		LastName     *string `json:"lastName"`
		CreatedAt    *string `json:"createdAt"`
		LastSignInAt *string `json:"lastSignInAt"`
	} `json:"users"`
	Pagination *struct {
		HasMore    *bool   `json:"hasMore"`
		NextCursor *string `json:"nextCursor"`
	} `json:"pagination"`
}

func rfc3339(s string) (string, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return "", false
	}
	return t.UTC().Format(time.RFC3339), true
}

func parseOrgUsers(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceOrgUsers
	if r.Status != 200 {
		return vendorapi.Page{}, vendorapi.Drift(s, "status %d is not the documented 200", r.Status)
	}
	var doc orgUsersDoc
	if err := vendorapi.DecodeNumbers(r.Body, &doc); err != nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "body does not decode as the documented response")
	}
	if doc.Users == nil || doc.Pagination == nil || doc.Pagination.HasMore == nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "required field users or pagination.hasMore is missing")
	}
	page := vendorapi.Page{Snapshot: &vendorapi.SnapshotManifest{
		Scope:          []vendorapi.ScopeKey{{Namespace: NamespaceUser, Kind: vs.KindUser}},
		SelectorDigest: "organization", PageSet: "organization_users", ContractVersion: OrgAPIContract,
	}}
	if *doc.Pagination.HasMore {
		nc := vendorapi.Str(doc.Pagination.NextCursor)
		if !cursorRE.MatchString(nc) {
			return vendorapi.Page{}, vendorapi.Drift(s, "pagination.hasMore is true without a usable nextCursor")
		}
		if r.Cursor != "" && nc == r.Cursor {
			return vendorapi.Page{}, vendorapi.Drift(s, "pagination.nextCursor repeats the cursor the page was asked with")
		}
		page.NextCursor = nc
	}
	seen := map[string]bool{}
	for i, u := range *doc.Users {
		if u.ID == nil || *u.ID == "" || u.Email == nil || u.CreatedAt == nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "users[%d] misses id, email or createdAt", i)
		}
		if seen[*u.ID] {
			return vendorapi.Page{}, vendorapi.Drift(s, "users[%d] repeats a user", i)
		}
		seen[*u.ID] = true
		attrs := map[string]string{"email": *u.Email}
		created, ok := rfc3339(*u.CreatedAt)
		if !ok {
			return vendorapi.Page{}, vendorapi.Drift(s, "users[%d].createdAt is not ISO 8601", i)
		}
		attrs["created_at"] = created
		if u.LastSignInAt != nil {
			t, ok := rfc3339(*u.LastSignInAt)
			if !ok {
				return vendorapi.Page{}, vendorapi.Drift(s, "users[%d].lastSignInAt is not ISO 8601", i)
			}
			attrs["last_sign_in_at"] = t
		}
		name := strings.TrimSpace(vendorapi.Str(u.FirstName) + " " + vendorapi.Str(u.LastName))
		page.Resources = append(page.Resources, vendorapi.ResourceObservation{
			Type: OrgUserType, ID: vs.ExternalID{Namespace: NamespaceUser, Value: *u.ID}, DisplayName: name, Attrs: attrs,
		})
	}
	return page, nil
}

// LimitsUsers returns the driver of factory.api.limits_users.
//
// Contract (OpenAPI getUserLimits): GET /api/v0/organization/usage/limits/users,
// not paged; 200 {globalLimit: integer|null, userLimits: [{email, limit:
// integer|null}]}, all required. The global limit (also served alone by
// limits/global, which this driver makes redundant) lands as the "global"
// limit and each override as "user:<email>"; a null limit is absent (the
// global default applies, or no global limit is configured), never zero.
// Limits are Factory Standard Credits, never money, and the mirror is read
// only: the PUT writes are not built and nothing here feeds a budget.
func LimitsUsers() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:               SurfaceLimitsUsers,
		Build:                 buildLimitsUsers,
		ParseResponse:         parseLimitsUsers,
		Auth:                  bearerAuth,
		ContentTypes:          []string{"application/json"},
		Supplies:              []vs.DataClass{vs.ClassLimits},
		AuthoritativeSnapshot: true,
		ContractVersion:       OrgAPIContract,
		KnownPaths:            []string{"globalLimit", "userLimits", "userLimits[]", "userLimits[].email", "userLimits[].limit"},
	}
}

func buildLimitsUsers(_ vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the surface is not paged", SurfaceLimitsUsers)
	}
	return vendorapi.Request{Method: "GET", Path: "/api/v0/organization/usage/limits/users"}, nil
}

type limitsDoc struct {
	GlobalLimit *num `json:"globalLimit"`
	UserLimits  *[]struct {
		Email *string `json:"email"`
		Limit *num    `json:"limit"`
	} `json:"userLimits"`
}

func creditAttrs(s vs.SurfaceID, n *num, where string) (map[string]string, error) {
	attrs := map[string]string{"unit": UnitCredits}
	if n == nil {
		attrs["state"] = "unset"
		return attrs, nil
	}
	v, err := strconv.ParseInt(string(*n), 10, 64)
	if err != nil || v < 0 {
		return nil, vendorapi.Drift(s, "%s is not a non-negative integer", where)
	}
	attrs["limit"] = strconv.FormatInt(v, 10)
	attrs["state"] = "set"
	return attrs, nil
}

func parseLimitsUsers(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceLimitsUsers
	if r.Status != 200 {
		return vendorapi.Page{}, vendorapi.Drift(s, "status %d is not the documented 200", r.Status)
	}
	var raw map[string]any
	if err := vendorapi.DecodeNumbers(r.Body, &raw); err != nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "body is not a JSON object")
	}
	if _, ok := raw["globalLimit"]; !ok {
		return vendorapi.Page{}, vendorapi.Drift(s, "required field globalLimit is missing")
	}
	var doc limitsDoc
	if err := vendorapi.DecodeNumbers(r.Body, &doc); err != nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "body does not decode as the documented response")
	}
	if doc.UserLimits == nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "required field userLimits is missing")
	}
	page := vendorapi.Page{SourceRecords: len(*doc.UserLimits), Snapshot: &vendorapi.SnapshotManifest{
		Scope:          []vendorapi.ScopeKey{{Namespace: NamespaceCreditLimit, Kind: vs.KindLimit}},
		SelectorDigest: "organization", PageSet: "organization_usage_limits_users", ContractVersion: OrgAPIContract,
	}}
	g, err := creditAttrs(s, doc.GlobalLimit, "globalLimit")
	if err != nil {
		return vendorapi.Page{}, err
	}
	g["scope"] = "global"
	page.Resources = append(page.Resources, vendorapi.ResourceObservation{
		Type: CreditLimitType, ID: vs.ExternalID{Namespace: NamespaceCreditLimit, Value: "global"}, Attrs: g,
	})
	seen := map[string]bool{}
	for i, u := range *doc.UserLimits {
		e := strings.TrimSpace(vendorapi.Str(u.Email))
		if e == "" {
			return vendorapi.Page{}, vendorapi.Drift(s, "userLimits[%d].email is missing", i)
		}
		if seen[e] {
			return vendorapi.Page{}, vendorapi.Drift(s, "userLimits[%d] repeats a user", i)
		}
		seen[e] = true
		a, err := creditAttrs(s, u.Limit, fmt.Sprintf("userLimits[%d].limit", i))
		if err != nil {
			return vendorapi.Page{}, err
		}
		a["scope"] = "user"
		a["email"] = e
		if u.Limit == nil {
			a["state"] = "inherits_global"
		}
		page.Resources = append(page.Resources, vendorapi.ResourceObservation{
			Type: CreditLimitType, ID: vs.ExternalID{Namespace: NamespaceCreditLimit, Value: "user:" + e}, Attrs: a,
		})
	}
	return page, nil
}
