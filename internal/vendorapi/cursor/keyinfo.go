package cursor

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// The Cloud Agents API key-info call (cloud agents arc, lane CA-C8). The
// node connector (lane CA-B2) reads it as its connect probe; since lane CA-C8
// an org connection reads it too, so the org projection can attribute every
// agent a USER key lists to that key's owner (List Agents returns the
// authenticated user's agents only). One parser serves both: ParseKeyInfo.
const (
	SurfaceCloudAgentMeta vs.SurfaceID = "cursor.cloudagent.meta"

	CloudAgentMetaContract = "cursor.cloudagent.meta/v1 cloud-agents-api v1 2026-10-07"

	// CloudAgentKeyClass is the snapshot class of the key's owner as the
	// key-info call states it; its subject is CloudAgentKeySubject (a
	// connection reads one key).
	CloudAgentKeyClass   = "cursor.cloud_agent_key"
	CloudAgentKeySubject = "api_key"

	// KeyKindUser: the key-info call names a user (a numeric user id and an
	// e-mail): a user API key, whose agents are that user's.
	KeyKindUser = "user"
	// KeyKindNoUser: the key-info call names no user. A service-account key
	// is expected here (not live-checked), and so is any key whose owner the
	// response does not state; neither attributes an agent to anyone.
	KeyKindNoUser = "no_user"

	cursorMePath = "/v1/me"
)

// KeyOwner is what the key-info call says about the key's owner.
type KeyOwner struct {
	// Kind is KeyKindUser or KeyKindNoUser.
	Kind string
	// UserID is the vendor's immutable numeric user id (0 when none is
	// stated).
	UserID int64
	// Email is the e-mail as the vendor wrote it, trimmed ("" when none is
	// stated); callers fold or bound it at their own boundary and use it as
	// an identity only when Kind is KeyKindUser.
	Email string
}

// keyInfoDoc is the closed shape of GET /v1/me: only the immutable user id
// and the e-mail are read. The key name and the user's names are never
// decoded (they are in the corpus ledger, so the shape digest keeps them).
type keyInfoDoc struct {
	UserID    *int64  `json:"userId"`
	UserEmail *string `json:"userEmail"`
}

// ParseKeyInfo parses a GET /v1/me body: the one parser of the key-info call
// for the node connector (cloudagents.ParseAPIIdentity) and the org driver.
// A body that does not decode is an error. UserID and Email carry what the
// body states (the node connector keys its account on the user id alone);
// Kind is KeyKindUser only when the body names both a positive user id and an
// e-mail shaped like an address, else KeyKindNoUser, never a guess.
func ParseKeyInfo(body []byte) (KeyOwner, error) {
	var doc keyInfoDoc
	if err := decode(body, &doc); err != nil {
		return KeyOwner{}, drift(SurfaceCloudAgentMeta, "body does not decode as the documented object")
	}
	o := KeyOwner{Kind: KeyKindNoUser, Email: strings.TrimSpace(str(doc.UserEmail))}
	if doc.UserID != nil && *doc.UserID > 0 {
		o.UserID = *doc.UserID
	}
	if o.UserID > 0 && emailShaped(o.Email) {
		o.Kind = KeyKindUser
	}
	return o, nil
}

// emailShaped is the minimal address shape: one @ with a dotted domain, no
// space, bounded, valid UTF-8 and every rune printable (no control, bidi or
// other formatting character a terminal or page would act on).
func emailShaped(s string) bool {
	at := strings.IndexByte(s, '@')
	return len(s) <= 254 && at > 0 && at == strings.LastIndexByte(s, '@') &&
		strings.Contains(s[at+1:], ".") && !strings.ContainsAny(s, " \t\r\n<>\"") &&
		utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) < 0
}

// CloudAgentMeta returns the driver of cursor.cloudagent.meta.
//
// Contract (Cloud Agents API v1, "API Key Info", reference source CU01): GET
// /v1/me, one document {apiKeyName, createdAt, userEmail, userId,
// userFirstName, userLastName}. Live 2026-11-01 on a user key: 200 with the
// e-mail and the numeric user id. The driver lands one snapshot of class
// cursor.cloud_agent_key: the key kind, and for a user key the user id and
// the folded e-mail. The key name and the user's names never land.
func CloudAgentMeta() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceCloudAgentMeta,
		Build:           buildCloudAgentMeta,
		ParseResponse:   parseCloudAgentMeta,
		Auth:            basicAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassCredentials},
		ClosedDTO:       true,
		ContractVersion: CloudAgentMetaContract,
		Tool:            Tool,
		KnownPaths:      cloudAgentMetaKnownPaths,
	}
}

func buildCloudAgentMeta(_ vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the key-info document has one page", SurfaceCloudAgentMeta)
	}
	return vendorapi.Request{Method: "GET", Path: cursorMePath}, nil
}

func parseCloudAgentMeta(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, drift(SurfaceCloudAgentMeta, "status %d is not the documented 200", r.Status)
	}
	owner, err := ParseKeyInfo(r.Body)
	if err != nil {
		return vendorapi.Page{}, err
	}
	body := map[string]string{"key_kind": owner.Kind}
	if owner.Kind == KeyKindUser {
		body["user_id"] = strconv.FormatInt(owner.UserID, 10)
		body["user_email"] = vendorapi.FoldEmail(owner.Email)
	}
	return vendorapi.Page{
		SourceRecords: 1,
		Snapshots:     []vendorapi.VendorSnapshot{{Class: CloudAgentKeyClass, Subject: CloudAgentKeySubject, Body: body}},
	}, nil
}

// cloudAgentMetaKnownPaths are the documented response paths (the corpus
// field ledger of "API Key Info").
var cloudAgentMetaKnownPaths = []string{"apiKeyName", "createdAt", "userEmail", "userFirstName", "userId", "userLastName"}
