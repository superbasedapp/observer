package kilo

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceMembers is the catalog id of the organization member list.
const SurfaceMembers vs.SurfaceID = "kilo.org.members_list_public"

// Member list vocabulary.
const (
	MembersContract = "kilo.org.members_list_public/v1 openapi organizations.members.listPublic (2026-10-08)"

	// MemberType is one active organization member.
	MemberType vs.ResourceType = "User/kilo.org_member/v1"
	// NamespaceMember keys a member by its Kilo user id.
	NamespaceMember = "kilo.member"
)

// membersInput is the closed input of organizations.members.listPublic.
type membersInput struct {
	OrganizationID string `json:"organizationId"`
}

func (membersInput) procedure() string { return "organizations.members.listPublic" }

// memberRoles is the documented role enum.
var memberRoles = map[string]bool{"owner": true, "admin": true, "member": true, "billing_manager": true}

// inviteStatuses is the documented invite e-mail status enum.
var inviteStatuses = map[string]bool{"pending": true, "sending": true, "delivered": true, "failed": true}

// Members returns the driver of kilo.org.members_list_public.
//
// Contract (OpenAPI organizations_members_listPublic): GET
// /api/trpc/organizations.members.listPublic?input={"organizationId":...};
// answer {result: {data: [member]}}, each member one of two documented
// shapes: active {id, name, email, role, status "active", inviteDate|null,
// imageUrl?|null} or invited {email, role, inviteDate|null, status
// "invited", emailStatus|null} (invite tokens and URLs are omitted by the
// vendor). Active members land as resources; an invited row has no user id
// and is counted, never landed. The image URL is never read. The list is
// unpaged and a complete answer is authoritative for the active members.
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
			"result", "result.data", "result.data[]", "result.data[].email", "result.data[].emailStatus",
			"result.data[].id", "result.data[].inviteDate", "result.data[].name", "result.data[].role",
			"result.data[].status",
		},
	}
}

func buildMembers(p vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the list is not paged", SurfaceMembers)
	}
	o := p[ParamOrganization]
	if !uuidRE.MatchString(o) {
		return vendorapi.Request{}, fmt.Errorf("%s: connection parameter %s is missing or not an organization UUID", SurfaceMembers, ParamOrganization)
	}
	return encodeTRPC(membersInput{OrganizationID: o})
}

type member struct {
	ID          *string `json:"id"`
	Name        *string `json:"name"`
	Email       *string `json:"email"`
	Role        *string `json:"role"`
	Status      *string `json:"status"`
	EmailStatus *string `json:"emailStatus"`
}

func parseMembers(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceMembers
	raw, err := unwrapTRPC(s, r)
	if err != nil {
		return vendorapi.Page{}, err
	}
	var rows []member
	if err := decodeData(s, raw, &rows); err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{SourceRecords: 1, Snapshot: &vendorapi.SnapshotManifest{
		Scope:          []vendorapi.ScopeKey{{Namespace: NamespaceMember, Kind: vs.KindUser}},
		SelectorDigest: "organization_active", PageSet: "organization_members", ContractVersion: MembersContract,
	}}
	seen := map[string]bool{}
	for i, m := range rows {
		if m.Email == nil || m.Role == nil || m.Status == nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "data[%d] misses email, role or status", i)
		}
		if !memberRoles[*m.Role] {
			return vendorapi.Page{}, vendorapi.Drift(s, "data[%d].role is not a documented value", i)
		}
		switch *m.Status {
		case "invited":
			if m.EmailStatus != nil && !inviteStatuses[*m.EmailStatus] {
				return vendorapi.Page{}, vendorapi.Drift(s, "data[%d].emailStatus is not a documented value", i)
			}
			continue
		case "active":
		default:
			return vendorapi.Page{}, vendorapi.Drift(s, "data[%d].status is not active or invited", i)
		}
		id := ""
		if m.ID != nil {
			id = strings.TrimSpace(*m.ID)
		}
		if id == "" || m.Name == nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "data[%d] is an active member without id or name", i)
		}
		if seen[id] {
			return vendorapi.Page{}, vendorapi.Drift(s, "data[%d] repeats a member", i)
		}
		seen[id] = true
		attrs := map[string]string{"role": *m.Role, "status": "active"}
		if e := strings.TrimSpace(*m.Email); e != "" {
			attrs["email"] = e
		}
		page.Resources = append(page.Resources, vendorapi.ResourceObservation{
			Type: MemberType, ID: vs.ExternalID{Namespace: NamespaceMember, Value: id}, DisplayName: strings.TrimSpace(*m.Name),
			Attrs: attrs,
		})
	}
	return page, nil
}
