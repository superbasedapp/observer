package cursor

import (
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// Surface ids and vocabulary of the Cursor drivers.
const (
	SurfaceMembers   vs.SurfaceID = "cursor.admin.members"
	SurfaceAuditLogs vs.SurfaceID = "cursor.admin.audit_logs"

	// MemberType is the namespaced resource type of one team member.
	MemberType vs.ResourceType = "User/cursor.member/v1"
	// NamespaceUser keys a member by Cursor's user id (user_...).
	NamespaceUser = "cursor.user"
	// AuditNamespace is the vendor audit namespace of the team audit log.
	AuditNamespace = "cursor.audit"

	// MembersContract and AuditContract are recorded on every run.
	MembersContract = "cursor.admin.members/v1 admin-api 2026-10-07"
	AuditContract   = "cursor.admin.audit_logs/v1 admin-api 2026-10-07"

	// Tool is the registry tool these surfaces report on.
	Tool = "cursor"
)

// basicAuth is the documented Admin API auth: HTTP Basic with the team API
// key as the user name and an empty password.
var basicAuth = vendorapi.AuthContract{Kind: vs.AuthBasic, Scheme: vendorapi.SchemeBasicUser, Header: "Authorization"}

// Members returns the driver of cursor.admin.members.
//
// Contract (Cursor Admin API, "Get Team Members"): GET /teams/members, no
// paging, response {"teamMembers": [{id, name, email, role, isRemoved}]}.
// The key is team-scoped, so one complete response lists every member of
// the team and a complete run is authoritative for deletion.
func Members() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:               SurfaceMembers,
		Build:                 buildMembers,
		ParseResponse:         parseMembers,
		Auth:                  basicAuth,
		ContentTypes:          []string{"application/json"},
		Supplies:              []vs.DataClass{vs.ClassIdentity, vs.ClassRoles},
		AuthoritativeSnapshot: true,
		ContractVersion:       MembersContract,
		KnownPaths:            membersKnownPaths,
		Tool:                  Tool,
	}
}

func buildMembers(_ vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("cursor.admin.members: the surface is not paged")
	}
	return vendorapi.Request{Method: "GET", Path: "/teams/members"}, nil
}

type membersDoc struct {
	TeamMembers *[]member `json:"teamMembers"`
}

type member struct {
	ID        *string `json:"id"`
	Name      *string `json:"name"`
	Email     *string `json:"email"`
	Role      *string `json:"role"`
	IsRemoved *bool   `json:"isRemoved"`
}

func parseMembers(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, vendorapi.Drift(SurfaceMembers, "status %d is not the documented 200", r.Status)
	}
	var doc membersDoc
	if err := vendorapi.DecodeNumbers(r.Body, &doc); err != nil {
		return vendorapi.Page{}, vendorapi.Drift(SurfaceMembers, "body does not decode as the documented object")
	}
	if doc.TeamMembers == nil {
		return vendorapi.Page{}, vendorapi.Drift(SurfaceMembers, "required field teamMembers is missing")
	}
	page := vendorapi.Page{Snapshot: &vendorapi.SnapshotManifest{
		Scope:           []vendorapi.ScopeKey{{Namespace: NamespaceUser, Kind: vs.KindUser}},
		SelectorDigest:  "team",
		PageSet:         "teams_members",
		ContractVersion: MembersContract,
	}}
	seen := map[string]bool{}
	for i, m := range *doc.TeamMembers {
		if m.ID == nil || *m.ID == "" {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceMembers, "teamMembers[%d].id is missing", i)
		}
		if seen[*m.ID] {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceMembers, "teamMembers[%d] repeats a member", i)
		}
		seen[*m.ID] = true
		attrs := map[string]string{}
		if m.Email != nil && *m.Email != "" {
			attrs["email"] = *m.Email
		}
		if m.Role != nil && *m.Role != "" {
			attrs["role"] = *m.Role
		}
		if m.IsRemoved != nil {
			attrs["is_removed"] = fmt.Sprint(*m.IsRemoved)
		}
		name := ""
		if m.Name != nil {
			name = *m.Name
		}
		page.Resources = append(page.Resources, vendorapi.ResourceObservation{
			Type: MemberType, ID: vs.ExternalID{Namespace: NamespaceUser, Value: *m.ID}, DisplayName: name, Attrs: attrs,
		})
	}
	return page, nil
}

// epochMillis renders a window bound the way the Admin API's date
// parameters take it (milliseconds since the Unix epoch).
func epochMillis(t time.Time) string { return fmt.Sprint(t.UTC().UnixMilli()) }

// membersKnownPaths are the documented response paths (the corpus field
// ledger of "Get Team Members").
var membersKnownPaths = []string{
	"teamMembers", "teamMembers[]", "teamMembers[].email", "teamMembers[].id", "teamMembers[].isRemoved",
	"teamMembers[].name", "teamMembers[].role",
}
