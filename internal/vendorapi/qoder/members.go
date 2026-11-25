package qoder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceMembers is the catalog id of the member list.
const SurfaceMembers vs.SurfaceID = "qoder.oapi.members_list"

// Member list vocabulary.
const (
	MembersContract = "qoder.oapi.members_list/v1 teams-openapi members (2026-10-08)"

	// ParamOrganization is the connection parameter naming the Qoder
	// organization (the {organization_id} path segment).
	ParamOrganization = "organization_id"
	// MemberType is one organization member.
	MemberType vs.ResourceType = "User/qoder.member/v1"
	// NamespaceMember keys a member by its member id (member_...).
	NamespaceMember = "qoder.member"
	// PageSize is the documented maximum of maxResults.
	PageSize = 100
)

var bearerAuth = vendorapi.AuthContract{Kind: vs.AuthBearer, Scheme: vendorapi.SchemeBearer, Header: "Authorization"}

var (
	orgRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	tokenRE = regexp.MustCompile(`^[A-Za-z0-9_=+/.:-]{1,512}$`)
)

// memberStatuses is the documented status enum.
var memberStatuses = map[string]bool{
	"ENABLED": true, "DISABLED": true, "UNACTIVATED": true, "APPROVE_PENDING": true, "APPROVE_DECLINED": true,
	"DELETED": true,
}

// Members returns the driver of qoder.oapi.members_list.
//
// Contract (Qoder Teams OpenAPI, "List members"): GET
// /v1/organizations/{organization_id}/members with maxResults (max 100) and
// nextToken; response {members: [{id, userId, name, email (may be absent),
// role, status, joinedAt, deletedAt (deleted members only)}], maxResults,
// nextToken (omitted on the last page)}. The default query lists active
// members only (includeDeleted is never sent), so a complete page set is
// authoritative for them. The userId and email filters are never sent.
func Members() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:               SurfaceMembers,
		Build:                 buildMembers,
		ParseResponse:         parseMembers,
		Auth:                  bearerAuth,
		ContentTypes:          []string{"application/json"},
		Supplies:              []vs.DataClass{vs.ClassIdentity, vs.ClassRoles},
		AuthoritativeSnapshot: true,
		ClosedDTO:             true,
		ContractVersion:       MembersContract,
		KnownPaths: []string{
			"maxResults", "members", "members[]", "members[].email", "members[].id", "members[].joinedAt",
			"members[].name", "members[].role", "members[].status", "members[].userId", "nextToken",
		},
	}
}

func buildMembers(p vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	o := p[ParamOrganization]
	if !orgRE.MatchString(o) {
		return vendorapi.Request{}, fmt.Errorf("%s: connection parameter %s is missing or not an organization id", SurfaceMembers, ParamOrganization)
	}
	q := map[string][]string{"maxResults": {strconv.Itoa(PageSize)}}
	if cursor != "" {
		if !tokenRE.MatchString(cursor) {
			return vendorapi.Request{}, fmt.Errorf("%s: cursor is not an opaque token", SurfaceMembers)
		}
		q["nextToken"] = []string{cursor}
	}
	return vendorapi.Request{Method: "GET", Path: "/v1/organizations/" + o + "/members", Query: q}, nil
}

type membersDoc struct {
	Members *[]struct {
		ID        *string `json:"id"`
		UserID    *string `json:"userId"`
		Name      *string `json:"name"`
		Email     *string `json:"email"`
		Role      *string `json:"role"`
		Status    *string `json:"status"`
		JoinedAt  *string `json:"joinedAt"`
		DeletedAt *string `json:"deletedAt"`
	} `json:"members"`
	NextToken *string `json:"nextToken"`
}

func drift(format string, a ...any) error {
	return vendorapi.Drift(SurfaceMembers, format, a...)
}

func isoTime(s string) (string, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return "", false
	}
	return t.UTC().Format(time.RFC3339), true
}

func parseMembers(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, drift("status %d is not the documented 200", r.Status)
	}
	var doc membersDoc
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return vendorapi.Page{}, drift("body does not decode as the documented response")
	}
	if doc.Members == nil {
		return vendorapi.Page{}, drift("required field members is missing")
	}
	page := vendorapi.Page{Snapshot: &vendorapi.SnapshotManifest{
		Scope:          []vendorapi.ScopeKey{{Namespace: NamespaceMember, Kind: vs.KindUser}},
		SelectorDigest: "organization_active", PageSet: "organization_members", ContractVersion: MembersContract,
	}}
	if tok := vendorapi.Str(doc.NextToken); tok != "" {
		if !tokenRE.MatchString(tok) {
			return vendorapi.Page{}, drift("nextToken is not an opaque token")
		}
		if r.Cursor != "" && tok == r.Cursor {
			return vendorapi.Page{}, drift("nextToken repeats the token the page was asked with")
		}
		page.NextCursor = tok
	}
	seen := map[string]bool{}
	for i, m := range *doc.Members {
		id := vendorapi.Str(m.ID)
		if id == "" || m.Status == nil || m.JoinedAt == nil {
			return vendorapi.Page{}, drift("members[%d] misses id, status or joinedAt", i)
		}
		if seen[id] {
			return vendorapi.Page{}, drift("members[%d] repeats a member", i)
		}
		seen[id] = true
		if !memberStatuses[*m.Status] {
			return vendorapi.Page{}, drift("members[%d].status is not a documented value", i)
		}
		attrs := map[string]string{"status": *m.Status}
		joined, ok := isoTime(*m.JoinedAt)
		if !ok {
			return vendorapi.Page{}, drift("members[%d].joinedAt is not ISO 8601", i)
		}
		attrs["joined_at"] = joined
		if m.DeletedAt != nil {
			t, ok := isoTime(*m.DeletedAt)
			if !ok {
				return vendorapi.Page{}, drift("members[%d].deletedAt is not ISO 8601", i)
			}
			attrs["deleted_at"] = t
		}
		for k, v := range map[string]string{"user_id": vendorapi.Str(m.UserID), "email": strings.TrimSpace(vendorapi.Str(m.Email)), "role": vendorapi.Str(m.Role)} {
			if v != "" {
				attrs[k] = v
			}
		}
		page.Resources = append(page.Resources, vendorapi.ResourceObservation{
			Type: MemberType, ID: vs.ExternalID{Namespace: NamespaceMember, Value: id}, DisplayName: vendorapi.Str(m.Name), Attrs: attrs,
		})
	}
	return page, nil
}
