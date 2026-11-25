package openrouter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceOrgMembers is the catalog id of the organization member list.
const SurfaceOrgMembers vs.SurfaceID = "openrouter.mgmt.org_members"

// Member list vocabulary.
const (
	OrgMembersContract = "openrouter.mgmt.org_members/v1 openapi listOrganizationMembers (2026-10-08)"

	// MemberType is one organization member.
	MemberType vs.ResourceType = "User/openrouter.org_member/v1"
	// NamespaceUser keys a member by its OpenRouter user id.
	NamespaceUser = "openrouter.user"
	// PageSize is the documented maximum of limit.
	PageSize = 100
)

var bearerAuth = vendorapi.AuthContract{Kind: vs.AuthBearer, Scheme: vendorapi.SchemeBearer, Header: "Authorization"}

// memberRoles is the documented role enum.
var memberRoles = map[string]bool{"org:admin": true, "org:member": true}

// OrgMembers returns the driver of openrouter.mgmt.org_members.
//
// Contract (OpenAPI listOrganizationMembers): GET /api/v1/organization/members
// with offset (default 0) and limit (max 100); response {data: [{id, email,
// first_name|null, last_name|null, role org:admin|org:member}], total_count}.
// Offset paging: the cursor carries the next offset and a digest of the page's
// last member, and a page repeating that member is a paging loop
// (vendorapi.OffsetLoop). A complete page set is authoritative.
func OrgMembers() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:               SurfaceOrgMembers,
		Build:                 buildOrgMembers,
		ParseResponse:         parseOrgMembers,
		Auth:                  bearerAuth,
		ContentTypes:          []string{"application/json"},
		Supplies:              []vs.DataClass{vs.ClassIdentity, vs.ClassRoles},
		AuthoritativeSnapshot: true,
		ClosedDTO:             true,
		ContractVersion:       OrgMembersContract,
		KnownPaths: []string{
			"data", "data[]", "data[].email", "data[].first_name", "data[].id", "data[].last_name", "data[].role",
			"total_count",
		},
	}
}

func buildOrgMembers(_ vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	off, ok := vendorapi.OffsetOf(cursor)
	if !ok {
		return vendorapi.Request{}, fmt.Errorf("%s: cursor is not an offset cursor", SurfaceOrgMembers)
	}
	return vendorapi.Request{Method: "GET", Path: "/api/v1/organization/members", Query: map[string][]string{
		"offset": {strconv.Itoa(off)}, "limit": {strconv.Itoa(PageSize)},
	}}, nil
}

// count is a JSON integer; a quoted, fractional or exponent value is a type
// change and fails the page.
type count int64

// UnmarshalJSON accepts a bare JSON integer only.
func (c *count) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == "" || strings.ContainsAny(s, `".eE+`) {
		return fmt.Errorf("openrouter: %.16q is not a JSON integer", b)
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*c = count(v)
	return nil
}

type membersDoc struct {
	Data *[]struct {
		ID        *string `json:"id"`
		Email     *string `json:"email"`
		FirstName *string `json:"first_name"`
		LastName  *string `json:"last_name"`
		Role      *string `json:"role"`
	} `json:"data"`
	TotalCount *count `json:"total_count"`
}

func decode(r vendorapi.Response, s vs.SurfaceID, v any) error {
	if r.Status != 200 {
		return vendorapi.Drift(s, "status %d is not the documented 200", r.Status)
	}
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return vendorapi.Drift(s, "body does not decode as the documented response")
	}
	return nil
}

func parseOrgMembers(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceOrgMembers
	var doc membersDoc
	if err := decode(r, s, &doc); err != nil {
		return vendorapi.Page{}, err
	}
	if doc.Data == nil || doc.TotalCount == nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "required field data or total_count is missing")
	}
	off, ok := vendorapi.OffsetOf(r.Cursor)
	if !ok {
		return vendorapi.Page{}, vendorapi.Drift(s, "the page was asked with a cursor that is not an offset cursor")
	}
	page := vendorapi.Page{Snapshot: &vendorapi.SnapshotManifest{
		Scope:          []vendorapi.ScopeKey{{Namespace: NamespaceUser, Kind: vs.KindUser}},
		SelectorDigest: "organization", PageSet: "organization_members", ContractVersion: OrgMembersContract,
	}}
	ids := make([]string, 0, len(*doc.Data))
	seen := map[string]bool{}
	for i, m := range *doc.Data {
		id := vendorapi.TrimStr(m.ID)
		if id == "" || m.Email == nil || m.Role == nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "data[%d] misses id, email or role", i)
		}
		if seen[id] {
			return vendorapi.Page{}, vendorapi.Drift(s, "data[%d] repeats a member", i)
		}
		seen[id] = true
		if !memberRoles[*m.Role] {
			return vendorapi.Page{}, vendorapi.Drift(s, "data[%d].role is not a documented value", i)
		}
		ids = append(ids, id)
		attrs := map[string]string{"role": *m.Role}
		if e := vendorapi.TrimStr(m.Email); e != "" {
			attrs["email"] = e
		}
		name := strings.TrimSpace(vendorapi.TrimStr(m.FirstName) + " " + vendorapi.TrimStr(m.LastName))
		page.Resources = append(page.Resources, vendorapi.ResourceObservation{
			Type: MemberType, ID: vs.ExternalID{Namespace: NamespaceUser, Value: id}, DisplayName: name, Attrs: attrs,
		})
	}
	if vendorapi.OffsetLoop(r.Cursor, ids) {
		return vendorapi.Page{}, vendorapi.Drift(s, "the page repeats the previous page's last member (offset paging loop)")
	}
	next, ok := vendorapi.NextOffsetCursor(off, int(*doc.TotalCount), ids)
	if !ok {
		return vendorapi.Page{}, vendorapi.Drift(s, "total_count %d does not cover offset %d plus %d members", *doc.TotalCount, off, len(ids))
	}
	page.NextCursor = next
	return page, nil
}
