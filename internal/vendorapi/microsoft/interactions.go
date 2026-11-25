package microsoft

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// ---- aiInteractionHistory: getAllEnterpriseInteractions (lane L15) ----

// SurfaceInteractions is the Microsoft 365 Copilot interaction history, a
// CONTENT surface (enterprise vendor API plan lane L15 = F17, T-618): the
// runner fetches it only while the connection's content is on with a
// recorded consent, and its items land only under that policy.
const SurfaceInteractions vs.SurfaceID = "microsoft.m365.interactions"

// InteractionsContract is the driver contract recorded on every run.
const InteractionsContract = "microsoft.m365.interactions/v1 graph v1.0 getAllEnterpriseInteractions 2026-10-08"

// LegacyInteractions is the legacy poller rail that already reads this
// endpoint (m365copilotanalytics, graph rail): while it owns the surface the
// runner never runs it (invariant I8).
const LegacyInteractions = "m365copilotanalytics.graph"

// MaxInteractionUsers caps the users one connection fans out over.
const MaxInteractionUsers = 25

const interactionsPathFmt = "/v1.0/copilot/users/%s/interactionHistory/getAllEnterpriseInteractions"

// guidRE is an Entra object id (the documented {id} of the path).
var guidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// interactionUsers reads the connection parameter user_ids: a comma
// separated list of Entra user object ids (lower-case GUIDs), at most
// MaxInteractionUsers, no repeats. The endpoint is per user and has no
// tenant-wide form, so the admin names the users the connection reads.
func interactionUsers(p vendorapi.Params) ([]string, error) {
	raw := strings.TrimSpace(p["user_ids"])
	if raw == "" {
		return nil, fmt.Errorf("%s: the user_ids parameter is required (the endpoint is per user)", SurfaceInteractions)
	}
	seen := map[string]bool{}
	var out []string
	for _, u := range strings.Split(raw, ",") {
		u = strings.TrimSpace(u)
		if !guidRE.MatchString(u) || seen[u] {
			return nil, fmt.Errorf("%s: user_ids holds a value that is not a distinct lower-case Entra object id", SurfaceInteractions)
		}
		seen[u] = true
		out = append(out, u)
	}
	if len(out) > MaxInteractionUsers {
		return nil, fmt.Errorf("%s: user_ids names more than %d users", SurfaceInteractions, MaxInteractionUsers)
	}
	return out, nil
}

// allowedInteractionsNext is the closed set of query members a next link
// may carry.
var allowedInteractionsNext = map[string]bool{"$top": true, "$filter": true, "$skiptoken": true, "$format": true}

// The cursor names the user being read and, after the first page of that
// user, the next link's path and query: "<index>" or "<index>|<path>?<query>".
func splitInteractionsCursor(c string) (int, string, error) {
	if c == "" {
		return 0, "", nil
	}
	idx, rest, _ := strings.Cut(c, "|")
	n, err := strconv.Atoi(idx)
	if err != nil || n < 0 {
		return 0, "", fmt.Errorf("%s: the cursor does not parse", SurfaceInteractions)
	}
	return n, rest, nil
}

func buildInteractions(p vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	users, err := interactionUsers(p)
	if err != nil {
		return vendorapi.Request{}, err
	}
	idx, next, err := splitInteractionsCursor(cursor)
	if err != nil {
		return vendorapi.Request{}, err
	}
	if idx >= len(users) {
		return vendorapi.Request{}, fmt.Errorf("%s: the cursor names no configured user", SurfaceInteractions)
	}
	path := fmt.Sprintf(interactionsPathFmt, users[idx])
	if next == "" {
		if w.From.IsZero() || !w.To.After(w.From) {
			return vendorapi.Request{}, fmt.Errorf("%s: a non-empty window is required", SurfaceInteractions)
		}
		// The reference asks for both bounds when filtering on
		// createdDateTime; $top 100 is its recommended page size.
		filter := "createdDateTime gt " + w.From.UTC().Format(time.RFC3339) + " and createdDateTime lt " +
			w.To.UTC().Format(time.RFC3339)
		return vendorapi.Request{Method: "GET", Path: path, Query: map[string][]string{"$top": {"100"}, "$filter": {filter}}}, nil
	}
	np, raw, ok := strings.Cut(next, "?")
	if !ok || !strings.EqualFold(np, path) {
		return vendorapi.Request{}, fmt.Errorf("%s: the cursor is not this user's next link", SurfaceInteractions)
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return vendorapi.Request{}, fmt.Errorf("%s: the next link query does not parse", SurfaceInteractions)
	}
	for k := range q {
		if !allowedInteractionsNext[k] {
			return vendorapi.Request{}, fmt.Errorf("%s: the next link carries an undocumented query member", SurfaceInteractions)
		}
	}
	if q.Get("$skiptoken") == "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the next link carries no $skiptoken", SurfaceInteractions)
	}
	return vendorapi.Request{Method: "GET", Path: np, Query: q}, nil
}

// interactionRoles maps the documented aiInteractionType members onto the
// content role vocabulary. unknownFutureValue (and any later member) is not
// a role: such an item is skipped, never guessed.
var interactionRoles = map[string]string{"userPrompt": "prompt", "aiResponse": "response"}

type interactionsDoc struct {
	Value    *[]interaction `json:"value"`
	NextLink *string        `json:"@odata.nextLink"`
}

type interaction struct {
	ID              *string `json:"id"`
	SessionID       *string `json:"sessionId"`
	InteractionType *string `json:"interactionType"`
	CreatedDateTime *string `json:"createdDateTime"`
	Body            *struct {
		Content *string `json:"content"`
	} `json:"body"`
}

// Interactions returns the driver of microsoft.m365.interactions.
//
// Contract (aiInteractionHistory: getAllEnterpriseInteractions, v1.0,
// application permission AiEnterpriseInteraction.Read.All): GET
// /v1.0/copilot/users/{id}/interactionHistory/getAllEnterpriseInteractions
// with $top=100 and a createdDateTime filter carrying both bounds; the
// answer is {"value": [aiInteraction], "@odata.nextLink"}. Each interaction
// whose interactionType is userPrompt or aiResponse lands as ONE content item
// (item id "<user id>:<id>", role prompt or response, the body's content as
// the text, sessionId as the session, the queried user as the identity,
// kind user_id). The body's HTML is kept as text (the sanitizer scrubs and
// caps it); attachments, links, mentions, contexts and the sender's display
// name are never read. Interactions of Copilot Studio agents are not served
// by the endpoint (reference note).
func Interactions() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceInteractions,
		Build:           buildInteractions,
		ParseResponse:   parseInteractions,
		Auth:            clientCredentials,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassContent},
		ClosedDTO:       true,
		ContractVersion: InteractionsContract,
		Tool:            Tool,
		LegacyPoller:    LegacyInteractions,
		KnownPaths:      interactionsKnownPaths,
	}
}

func parseInteractions(r vendorapi.Response) (vendorapi.Page, error) {
	const s = SurfaceInteractions
	if r.Status != 200 {
		return vendorapi.Page{}, vendorapi.Drift(s, "status %d is not the documented 200", r.Status)
	}
	var doc interactionsDoc
	if err := vendorapi.DecodeNumbers(r.Body, &doc); err != nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "body does not decode as the documented object")
	}
	if doc.Value == nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "required field value is missing")
	}
	users, err := interactionUsers(r.Params)
	if err != nil {
		return vendorapi.Page{}, err
	}
	idx, _, err := splitInteractionsCursor(r.Cursor)
	if err != nil || idx >= len(users) {
		return vendorapi.Page{}, fmt.Errorf("%s: the response names no configured user", s)
	}
	user := users[idx]
	link, err := nextCursor(s, r, doc.NextLink)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{SourceRecords: len(*doc.Value)}
	switch {
	case link != "":
		page.NextCursor = strconv.Itoa(idx) + "|" + link
	case idx+1 < len(users):
		page.NextCursor = strconv.Itoa(idx + 1)
	}
	seen := map[string]bool{}
	for i, it := range *doc.Value {
		if it.ID == nil || *it.ID == "" || it.CreatedDateTime == nil || it.InteractionType == nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "value[%d] misses id, createdDateTime or interactionType", i)
		}
		at, err := time.Parse(time.RFC3339Nano, *it.CreatedDateTime)
		if err != nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "value[%d].createdDateTime is not a date-time", i)
		}
		role, ok := interactionRoles[*it.InteractionType]
		if !ok {
			continue
		}
		id := user + ":" + *it.ID
		if seen[id] {
			return vendorapi.Page{}, vendorapi.Drift(s, "value[%d] repeats an id", i)
		}
		seen[id] = true
		text := ""
		if it.Body != nil && it.Body.Content != nil {
			text = *it.Body.Content
		}
		page.Content = append(page.Content, vendorapi.ContentItem{
			ItemID: id, At: at.UTC(), IdentityKind: "user_id", Identity: user, SessionRef: strOf(it.SessionID),
			Role: role, Text: text,
		})
	}
	return page, nil
}

// interactionsKnownPaths are the documented response paths (the corpus
// field ledger of getAllEnterpriseInteractions).
var interactionsKnownPaths = []string{
	"value", "value[]", "value[].appClass", "value[].attachments", "value[].body", "value[].body.content",
	"value[].body.contentType", "value[].contexts", "value[].conversationType", "value[].createdDateTime", "value[].etag",
	"value[].from", `value[].from.@odata\.type`, "value[].from.application", "value[].from.device", "value[].from.user",
	`value[].from.user.@odata\.type`, "value[].from.user.displayName", "value[].from.user.id", "value[].from.user.tenantId",
	"value[].from.user.userIdentityType", "value[].id", "value[].interactionType", "value[].links", "value[].locale",
	"value[].mentions", "value[].requestId", "value[].sessionId",
}
