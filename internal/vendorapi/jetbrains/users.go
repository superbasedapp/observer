package jetbrains

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceUsers is the catalog id of the IDE Services user list.
const SurfaceUsers vs.SurfaceID = "jetbrains.ideservices.users_list"

// User list vocabulary.
const (
	UsersContract = "jetbrains.ideservices.users_list/v1 ide-services public rest (2026-10-08)"

	// UserType is one IDE Services user.
	UserType vs.ResourceType = "User/jetbrains.ideservices_user/v1"
	// NamespaceUser keys a user by its IDE Services id (a UUID).
	NamespaceUser = "jetbrains.ideservices_user"
	// AutomationPrefix is the documented Authorization prefix of an IDE
	// Services automation token ("Authorization: Automation <token>").
	AutomationPrefix = "Automation"
)

// automationAuth is the documented automation-token contract: the token in
// Authorization behind the literal "Automation" prefix (not "Bearer"). An
// OAuth 2.0 token from the customer's own provider is the other documented
// option and is not supported (it is the customer IdP's token, not a key).
var automationAuth = vendorapi.AuthContract{
	Kind: vs.AuthHeaderKey, Scheme: vendorapi.SchemePrefixed, Header: "Authorization", Prefix: AutomationPrefix,
}

// Users returns the driver of jetbrains.ideservices.users_list.
//
// Contract (IDE Services public REST API, "User management"): GET
// /api/v1/users on the customer's IDE Services server (a customer_host
// surface: the connection declares the tuple) with an automation token as
// "Authorization: Automation <token>"; the documented behaviour is a full
// list of current users. The reference shows no list response: that it is a
// JSON array of the user object of the POST /api/v1/users response example
// ({id, createdDate, createdBy, email, username, role, isActive}) is Inferred,
// so every rung is at most assumption_tested and any other shape is schema
// drift. Lands one resource per user: email, role, whether active and the
// creation time; the username is the display name; createdBy is not landed.
// A complete list is authoritative. Read only: user create, delete and
// profile assignment are not built.
func Users() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:               SurfaceUsers,
		Build:                 buildUsers,
		ParseResponse:         parseUsers,
		Auth:                  automationAuth,
		ContentTypes:          []string{"application/json"},
		Supplies:              []vs.DataClass{vs.ClassIdentity},
		AuthoritativeSnapshot: true,
		ClosedDTO:             true,
		ContractVersion:       UsersContract,
		KnownPaths: []string{
			"[]", "[].createdBy", "[].createdDate", "[].email", "[].id", "[].isActive", "[].role", "[].username",
		},
	}
}

func buildUsers(_ vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the surface is not paged", SurfaceUsers)
	}
	return vendorapi.Request{Method: "GET", Path: "/api/v1/users"}, nil
}

type userRow struct {
	ID          *string `json:"id"`
	CreatedDate *string `json:"createdDate"`
	Email       *string `json:"email"`
	Username    *string `json:"username"`
	Role        *string `json:"role"`
	IsActive    *bool   `json:"isActive"`
}

func drift(format string, a ...any) error {
	return vendorapi.Drift(SurfaceUsers, format, a...)
}

func parseUsers(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, drift("status %d is not 200", r.Status)
	}
	var rows []userRow
	if err := json.NewDecoder(bytes.NewReader(r.Body)).Decode(&rows); err != nil || rows == nil {
		return vendorapi.Page{}, drift("body is not a JSON array of users")
	}
	page := vendorapi.Page{SourceRecords: len(rows), Snapshot: &vendorapi.SnapshotManifest{
		Scope:          []vendorapi.ScopeKey{{Namespace: NamespaceUser, Kind: vs.KindUser}},
		SelectorDigest: "server_all", PageSet: "server_users", ContractVersion: UsersContract,
	}}
	seen := map[string]bool{}
	for i, u := range rows {
		if u.ID == nil || *u.ID == "" || u.Username == nil || u.Role == nil || u.IsActive == nil {
			return vendorapi.Page{}, drift("[%d] misses id, username, role or isActive (required on the user object)", i)
		}
		if seen[*u.ID] {
			return vendorapi.Page{}, drift("[%d] repeats a user", i)
		}
		seen[*u.ID] = true
		attrs := map[string]string{"role": *u.Role, "is_active": strconv.FormatBool(*u.IsActive)}
		if u.Email != nil && strings.TrimSpace(*u.Email) != "" {
			attrs["email"] = strings.TrimSpace(*u.Email)
		}
		if u.CreatedDate != nil {
			t, err := time.Parse(time.RFC3339Nano, *u.CreatedDate)
			if err != nil {
				return vendorapi.Page{}, drift("[%d].createdDate is not an offset date-time", i)
			}
			attrs["created_at"] = t.UTC().Format(time.RFC3339)
		}
		page.Resources = append(page.Resources, vendorapi.ResourceObservation{
			Type: UserType, ID: vs.ExternalID{Namespace: NamespaceUser, Value: *u.ID}, DisplayName: *u.Username, Attrs: attrs,
		})
	}
	return page, nil
}
