package prime

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

// SurfaceTeamMembers is the catalog id of the team member list.
const SurfaceTeamMembers vs.SurfaceID = "prime.teams.members"

// Team member vocabulary.
const (
	TeamMembersContract = "prime.teams.members/v1 openapi list_team_members (2026-10-08)"

	// ParamTeam is the connection parameter naming the Prime team (the
	// {team_id} path segment).
	ParamTeam = "team_id"
	// MemberType is one team member.
	MemberType vs.ResourceType = "User/prime.team_member/v1"
	// NamespaceUser keys a member by its Prime user id.
	NamespaceUser = "prime.user"
	// PageSize is the documented default limit (no maximum is documented).
	PageSize = 100
)

var (
	bearerAuth = vendorapi.AuthContract{Kind: vs.AuthBearer, Scheme: vendorapi.SchemeBearer, Header: "Authorization"}
	teamRE     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	// teamRoles is the documented TeamRoleEnum.
	teamRoles = map[string]bool{"ADMIN": true, "MEMBER": true}
)

// TeamMembers returns the driver of prime.teams.members.
//
// Contract (OpenAPI list_team_members): GET /api/v1/teams/{team_id}/members
// with offset (default 0) and limit (default 100); response
// GenericPaginationResponse {total_count, offset, limit, data:
// [TeamMemberDetail {userId, userName|null, userEmail|null, role ADMIN|MEMBER,
// joinedAt date-time}], status|null}. The team comes from the connection
// parameter team_id, validated before it becomes a path segment. Offset
// paging with the loop rule of vendorapi.OffsetLoop. A complete page set is
// authoritative for the team.
func TeamMembers() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:               SurfaceTeamMembers,
		Build:                 buildTeamMembers,
		ParseResponse:         parseTeamMembers,
		Auth:                  bearerAuth,
		ContentTypes:          []string{"application/json"},
		Supplies:              []vs.DataClass{vs.ClassIdentity, vs.ClassRoles},
		AuthoritativeSnapshot: true,
		ClosedDTO:             true,
		ContractVersion:       TeamMembersContract,
		KnownPaths: []string{
			"data", "data[]", "data[].joinedAt", "data[].role", "data[].userEmail", "data[].userId", "data[].userName",
			"limit", "offset", "status", "total_count",
		},
	}
}

func buildTeamMembers(p vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	t := p[ParamTeam]
	if !teamRE.MatchString(t) {
		return vendorapi.Request{}, fmt.Errorf("%s: connection parameter %s is missing or not a team id", SurfaceTeamMembers, ParamTeam)
	}
	off, ok := vendorapi.OffsetOf(cursor)
	if !ok {
		return vendorapi.Request{}, fmt.Errorf("%s: cursor is not an offset cursor", SurfaceTeamMembers)
	}
	return vendorapi.Request{Method: "GET", Path: "/api/v1/teams/" + t + "/members", Query: map[string][]string{
		"offset": {strconv.Itoa(off)}, "limit": {strconv.Itoa(PageSize)},
	}}, nil
}

// count is a JSON integer; a quoted, fractional or exponent value fails the
// page.
type count int64

// UnmarshalJSON accepts a bare JSON integer only.
func (c *count) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == "" || strings.ContainsAny(s, `".eE+`) {
		return fmt.Errorf("prime: %.16q is not a JSON integer", b)
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*c = count(v)
	return nil
}

type membersDoc struct {
	TotalCount *count `json:"total_count"`
	Offset     *count `json:"offset"`
	Data       *[]struct {
		UserID    *string `json:"userId"`
		UserName  *string `json:"userName"`
		UserEmail *string `json:"userEmail"`
		Role      *string `json:"role"`
		JoinedAt  *string `json:"joinedAt"`
	} `json:"data"`
}

func drift(format string, a ...any) error {
	return vendorapi.Drift(SurfaceTeamMembers, format, a...)
}

func parseTeamMembers(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, drift("status %d is not the documented 200", r.Status)
	}
	var doc membersDoc
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return vendorapi.Page{}, drift("body does not decode as the documented response")
	}
	// total_count has a schema default, but paging cannot be decided without
	// it: a page that omits it is drift.
	if doc.Data == nil || doc.TotalCount == nil {
		return vendorapi.Page{}, drift("required field data or total_count is missing")
	}
	off, ok := vendorapi.OffsetOf(r.Cursor)
	if !ok {
		return vendorapi.Page{}, drift("the page was asked with a cursor that is not an offset cursor")
	}
	if doc.Offset != nil && int(*doc.Offset) != off {
		return vendorapi.Page{}, drift("the page answers offset %d, asked for %d", *doc.Offset, off)
	}
	page := vendorapi.Page{Snapshot: &vendorapi.SnapshotManifest{
		Scope:          []vendorapi.ScopeKey{{Namespace: NamespaceUser, Kind: vs.KindUser}},
		SelectorDigest: "team:" + r.Params[ParamTeam], PageSet: "team_members", ContractVersion: TeamMembersContract,
	}}
	ids := make([]string, 0, len(*doc.Data))
	seen := map[string]bool{}
	for i, m := range *doc.Data {
		id := vendorapi.TrimStr(m.UserID)
		if id == "" || m.Role == nil || m.JoinedAt == nil {
			return vendorapi.Page{}, drift("data[%d] misses userId, role or joinedAt", i)
		}
		if seen[id] {
			return vendorapi.Page{}, drift("data[%d] repeats a member", i)
		}
		seen[id] = true
		if !teamRoles[*m.Role] {
			return vendorapi.Page{}, drift("data[%d].role is not a documented value", i)
		}
		joined, err := time.Parse(time.RFC3339Nano, *m.JoinedAt)
		if err != nil {
			return vendorapi.Page{}, drift("data[%d].joinedAt is not a date-time", i)
		}
		ids = append(ids, id)
		attrs := map[string]string{"role": *m.Role, "joined_at": joined.UTC().Format(time.RFC3339)}
		if e := vendorapi.TrimStr(m.UserEmail); e != "" {
			attrs["email"] = e
		}
		page.Resources = append(page.Resources, vendorapi.ResourceObservation{
			Type: MemberType, ID: vs.ExternalID{Namespace: NamespaceUser, Value: id}, DisplayName: vendorapi.TrimStr(m.UserName), Attrs: attrs,
		})
	}
	if vendorapi.OffsetLoop(r.Cursor, ids) {
		return vendorapi.Page{}, drift("the page repeats the previous page's last member (offset paging loop)")
	}
	next, ok := vendorapi.NextOffsetCursor(off, int(*doc.TotalCount), ids)
	if !ok {
		return vendorapi.Page{}, drift("total_count %d does not cover offset %d plus %d members", *doc.TotalCount, off, len(ids))
	}
	page.NextCursor = next
	return page, nil
}
