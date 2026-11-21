package vendormock

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/vendorapi/fixturecorpus"
	"github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// AuthScheme is how a credential is presented.
type AuthScheme string

// Auth schemes the four vendors document for their admin planes.
const (
	// SchemeRawHeader sends the key as the whole value of AuthHeader
	// (Anthropic X-Api-Key).
	SchemeRawHeader AuthScheme = "raw_header"
	// SchemeBearer sends "Authorization: Bearer <token>".
	SchemeBearer AuthScheme = "bearer"
	// SchemeBasicUser sends HTTP Basic with the key as the user name and an
	// empty password (Cursor).
	SchemeBasicUser AuthScheme = "basic_user"
	// SchemePrefixed sends "<AuthPrefix> <token>" in AuthHeader (JetBrains
	// IDE Services "Authorization: Automation <token>"; lane ENTAPI-L16C).
	SchemePrefixed AuthScheme = "prefixed"
	// SchemeAWSSigV4 is an AWS Signature Version 4 request: the mock
	// recomputes the signature over the request it received with the valid
	// token as the secret access key and the profile's Region and signing
	// name (lane ENTAPI-L16D).
	SchemeAWSSigV4 AuthScheme = "aws_sigv4"
)

// Token grants of a TokenScope profile.
const (
	// GrantClientCredentials is the Microsoft identity platform
	// client-credentials form at /{tenant}/oauth2/v2.0/token (the default).
	GrantClientCredentials = "client_credentials"
	// GrantJWTBearer is Google's RFC 7523 JWT bearer assertion at /token: the
	// mock verifies the RS256 signature with the public half of
	// ServiceAccountKey of the valid (or wrong-plane) token (lane
	// ENTAPI-L16D).
	GrantJWTBearer = "jwt_bearer"
)

// Profile is one row of the vendor mechanics table: the documented request
// contract of every surface whose id starts with Prefix. Rows are matched
// longest prefix first. Source is the public page the row was read from on
// 2026-10-07; nothing here was observed from a live response.
type Profile struct {
	Prefix     string
	AuthHeader string
	Scheme     AuthScheme
	// Required lists request headers the reference examples always send; the
	// mock answers 400 with the vendor body when one is missing.
	Required map[string]string
	// AfterParam is the request parameter that carries a last_id cursor
	// (Anthropic after_id, OpenAI after).
	AfterParam string
	// TokenScope, when set, puts an OAuth 2.0 client-credentials token step
	// in front of the API (Microsoft identity platform): the mock starts a
	// token host that mints an access token for a client secret, and the API
	// accepts only that minted token as the bearer (lane ENTAPI-D3).
	TokenScope string
	// AuthPrefix is the literal scheme token of SchemePrefixed.
	AuthPrefix string
	// TokenGrant selects the token step's grant ("" is client credentials).
	TokenGrant string
	// SigV4Region and SigV4Service scope a SchemeAWSSigV4 signature.
	SigV4Region, SigV4Service string
	Source                    string
}

// Profiles is the mechanics table. A surface no row matches has no profile
// and the conformance suite refuses it (TestEverySurfaceHasAProfile).
var Profiles = []Profile{
	{
		Prefix: "anthropic.enterprise.compliance.", AuthHeader: "Authorization", Scheme: SchemeBearer,
		Required: map[string]string{"anthropic-version": "2023-06-01"}, AfterParam: "after_id",
		Source: "https://platform.claude.com/docs/en/api/compliance.md",
	},
	{
		Prefix: "anthropic.console.activity_feed", AuthHeader: "Authorization", Scheme: SchemeBearer,
		Required: map[string]string{"anthropic-version": "2023-06-01"}, AfterParam: "after_id",
		Source: "https://platform.claude.com/docs/en/api/compliance.md",
	},
	{
		Prefix: "anthropic.", AuthHeader: "X-Api-Key", Scheme: SchemeRawHeader,
		Required: map[string]string{"anthropic-version": "2023-06-01"}, AfterParam: "after_id",
		Source: "https://platform.claude.com/docs/en/api/beta/organization.md",
	},
	{
		Prefix: "openai.", AuthHeader: "Authorization", Scheme: SchemeBearer, AfterParam: "after",
		Source: "https://raw.githubusercontent.com/openai/openai-openapi/master/openapi.yaml",
	},
	{
		Prefix: "github.", AuthHeader: "Authorization", Scheme: SchemeBearer, AfterParam: "after",
		Source: "https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api",
	},
	{
		Prefix: "cursor.origin.", AuthHeader: "Authorization", Scheme: SchemeBearer, AfterParam: "after",
		Source: "https://cursor.com/docs/api/origin/openapi.yaml",
	},
	{
		Prefix: "cursor.", AuthHeader: "Authorization", Scheme: SchemeBasicUser, AfterParam: "after",
		Source: "https://cursor.com/docs/api.md",
	},
	// Lane CA-A4 (cloud agents arc): the Cloud Agents API v1 pages with
	// limit and cursor, answering nextCursor (omitted on the last page). The
	// user or service-account key is accepted as Basic (the catalog auth
	// kind) or Bearer.
	{
		Prefix: "cursor.cloudagent.", AuthHeader: "Authorization", Scheme: SchemeBasicUser, AfterParam: "cursor",
		Source: "https://cursor.com/docs/cloud-agent/api/endpoints",
	},
	// Lane ENTAPI-L16 (T-619): the Phase 8 long tail.
	{
		Prefix: "cognition.devin_v3.", AuthHeader: "Authorization", Scheme: SchemeBearer, AfterParam: "after",
		Source: "https://docs.devin.ai/v3-openapi.yaml",
	},
	{
		Prefix: "factory.analytics.", AuthHeader: "Authorization", Scheme: SchemeBearer, AfterParam: "cursor",
		Source: "https://docs.factory.com/api-reference/analytics.md",
	},
	// Lane ENTAPI-L16B (T-708): the xAI Management API (a management key as
	// Bearer on management-api.x.ai, distinct from the inference key).
	{
		Prefix: "xai.mgmt.", AuthHeader: "Authorization", Scheme: SchemeBearer, AfterParam: "pageToken",
		Source: "https://docs.x.ai/developers/management-api-guide.md",
	},
	{
		Prefix: "qoder.oapi.", AuthHeader: "Authorization", Scheme: SchemeBearer, AfterParam: "nextToken",
		Source: "https://docs.qoder.com/account/teams/openapi/members.md",
	},
	// Lane CA-V2 (cloud agents arc): the Qoder Cloud Agents managed API (a
	// personal access token as Bearer on api.qoder.com), paged with page and
	// answering has_more plus next_page (null on the last page).
	{
		Prefix: "qoder.ca.", AuthHeader: "Authorization", Scheme: SchemeBearer, AfterParam: "page",
		Source: "https://github.com/QoderAI/qoder-cloud-agents-sdk-python",
	},
	{
		Prefix: "perplexity.ent.", AuthHeader: "Authorization", Scheme: SchemeBearer,
		Source: "https://docs.perplexity.ai/api-reference/computer-analytics-usage-v2-get.md",
	},
	// Lane ENTAPI-L16B (T-708): the Factory Public API OpenAPI rows.
	{
		Prefix: "factory.api.", AuthHeader: "Authorization", Scheme: SchemeBearer, AfterParam: "cursor",
		Source: "https://docs.factory.com/openapi.json",
	},
	// Lane ENTAPI-L16C (T-710): OpenCode Console (a service account key as
	// Bearer) and Charm Hyper (an sk-hyper- key as Bearer).
	{
		Prefix: "opencode.console.", AuthHeader: "Authorization", Scheme: SchemeBearer,
		Source: "https://opencode.ai/v2/docs/console/api/budgets/",
	},
	{
		Prefix: "charm.hyper.", AuthHeader: "Authorization", Scheme: SchemeBearer,
		Source: "https://hyper.charm.land/docs/api/credits.html",
	},
	// Lane ENTAPI-L16C (T-710): JetBrains IDE Services, customer-hosted, an
	// automation token behind the literal "Automation" prefix.
	{
		Prefix: "jetbrains.ideservices.", AuthHeader: "Authorization", Scheme: SchemePrefixed, AuthPrefix: "Automation",
		Source: "https://www.jetbrains.com/help/ide-services/rest-api.html",
	},
	// Lane ENTAPI-L16E (T-717): customer-hosted drivers. JetBrains Hub SCIM
	// 2.0 (a Hub permanent token as Bearer, 1-based startIndex) and the
	// customer-deployed LiteLLM gateway in front of Poolside (a key as Bearer).
	{
		Prefix: "jetbrains.hub.", AuthHeader: "Authorization", Scheme: SchemeBearer, AfterParam: "startIndex",
		Source: "https://www.jetbrains.com/help/ide-services-cloud/azure-ad-auth-module.html",
	},
	{
		Prefix: "poolside.gateway.", AuthHeader: "Authorization", Scheme: SchemeBearer,
		Source: "https://docs.litellm.ai/docs/proxy/cost_tracking.md",
	},
	// Lane ENTAPI-L16C (T-710): OpenRouter management API (a management key as
	// Bearer), Prime Intellect platform API (HTTPBearer) and Kilo Code tRPC
	// reads (bearerAuth).
	{
		Prefix: "openrouter.mgmt.", AuthHeader: "Authorization", Scheme: SchemeBearer, AfterParam: "offset",
		Source: "https://openrouter.ai/docs/api/api-reference/organization/list-organization-members.md",
	},
	{
		Prefix: "prime.", AuthHeader: "Authorization", Scheme: SchemeBearer, AfterParam: "offset",
		Source: "https://api.primeintellect.ai/openapi.json",
	},
	{
		Prefix: "kilo.", AuthHeader: "Authorization", Scheme: SchemeBearer,
		Source: "https://app.kilo.ai/api/openapi.json",
	},
	// Lane CA-A4 (cloud agents arc): OpenHands Cloud V1 app gateway (a Cloud
	// API key as Bearer on app.all-hands.dev), paged with page_id and
	// answering next_page_id (null on the last page).
	{
		Prefix: "openhands.", AuthHeader: "Authorization", Scheme: SchemeBearer, AfterParam: "page_id",
		Source: "https://docs.openhands.dev/openhands/usage/cloud/cloud-api",
	},
	// Lane CA-V1 (cloud agents arc): the Warp Agent API (a Warp API key as
	// Bearer on app.warp.dev/api/v1), the runs list paged with cursor and
	// answering page_info.has_next_page / page_info.next_cursor.
	{
		Prefix: "warp.", AuthHeader: "Authorization", Scheme: SchemeBearer, AfterParam: "cursor",
		Source: "https://github.com/warpdotdev/docs/blob/4aa3f1207664a44ab3c4c5626ae0999ef03bbf14/developers/agent-api-openapi.yaml",
	},
	{ //nolint:gosec // G101: not a credential (fixed header names / wording)
		Prefix: "microsoft.", AuthHeader: "Authorization", Scheme: SchemeBearer,
		TokenScope: "https://graph.microsoft.com/.default",
		Source:     "https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow",
	},
	// Lane ENTAPI-L16D (T-713): AWS CloudTrail (AWS JSON 1.1, SigV4, the
	// NextToken in the request body) and Google Cloud Logging (a service
	// account JWT bearer token, then Bearer; pageToken in the request body).
	{
		Prefix: "aws.cloudtrail.", AuthHeader: "Authorization", Scheme: SchemeAWSSigV4, AfterParam: "NextToken",
		Required:    map[string]string{"X-Amz-Target": "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"},
		SigV4Region: "us-east-1", SigV4Service: "cloudtrail",
		Source: "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html",
	},
	{ //nolint:gosec // G101: not a credential (fixed header names / wording)
		Prefix: "google.", AuthHeader: "Authorization", Scheme: SchemeBearer, AfterParam: "pageToken",
		TokenScope: "https://www.googleapis.com/auth/logging.read", TokenGrant: GrantJWTBearer,
		Source: "https://developers.google.com/identity/protocols/oauth2/service-account",
	},
	// Lane CA-V6 (cloud agents arc): Cline Cloud sessions on api.cline.bot,
	// the account token as Bearer (@cline/core 0.2.0 CloudSessionApi; an
	// undocumented surface observed in the vendor client). Not paged.
	{
		Prefix: "cline.cloud.", AuthHeader: "Authorization", Scheme: SchemeBearer,
		Source: "https://registry.npmjs.org/@cline/core/-/core-0.2.0.tgz",
	},
}

// ProfileFor returns the longest-prefix profile of a surface.
func ProfileFor(id vendorsurface.SurfaceID) (Profile, bool) {
	best, ok := Profile{}, false
	for _, p := range Profiles {
		if strings.HasPrefix(string(id), p.Prefix) && len(p.Prefix) > len(best.Prefix) {
			best, ok = p, true
		}
	}
	return best, ok
}

// PagingFamily is the documented pagination family a surface's fixtures show.
type PagingFamily string

// Paging families, classified from the fixtures (never from a vendor name).
const (
	// FamilyNone is a single document with no paging signal.
	FamilyNone PagingFamily = "none"
	// FamilyNextPage is has_more plus an opaque next_page token sent back as
	// the page parameter (Anthropic reports, OpenAI usage and costs).
	FamilyNextPage PagingFamily = "next_page"
	// FamilyAfterID is has_more plus last_id sent back as the profile's
	// AfterParam (Anthropic lists, OpenAI lists).
	FamilyAfterID PagingFamily = "after_id"
	// FamilyLink is the RFC 8288 Link header with rel="next" (GitHub).
	FamilyLink PagingFamily = "link"
	// FamilyBodyPage is a pagination object with hasNextPage and a page
	// number sent in the JSON request body (Cursor).
	FamilyBodyPage PagingFamily = "body_page"
	// FamilyODataNext is the OData @odata.nextLink: an absolute URL to the
	// next page in the body, used whole (Microsoft Graph; lane ENTAPI-D3).
	FamilyODataNext PagingFamily = "odata_next"
	// FamilyEndCursor is has_next_page plus an opaque end_cursor sent back as
	// the profile's AfterParam (Cognition Devin v3 PaginatedResponse; lane
	// ENTAPI-L16).
	FamilyEndCursor PagingFamily = "end_cursor"
	// FamilyNestedCursor is a flag and an opaque cursor inside a nested
	// paging object, the cursor sent back as the profile's AfterParam (Factory
	// analytics meta.has_more / meta.next_cursor, Factory Public API
	// pagination.hasMore / pagination.nextCursor; lane ENTAPI-L16B). The
	// spellings are the closed nestedCursors table.
	FamilyNestedCursor PagingFamily = "nested_cursor"
	// FamilyNextToken is a top-level page token, present and non-empty while
	// more pages exist and omitted on the last, sent back as the profile's
	// AfterParam (xAI Management API nextPageToken, Qoder Teams OpenAPI
	// nextToken; lane ENTAPI-L16B; Cursor Cloud Agents nextCursor and
	// OpenHands Cloud next_page_id, lane CA-A4). The spellings are the closed
	// nextTokenKeys table.
	FamilyNextToken PagingFamily = "next_token"
	// FamilyOffset is a record offset plus a page size with the total in the
	// body: the next page is asked with the profile's AfterParam set to the
	// number of records already served (OpenRouter organization members,
	// Prime team members; lane ENTAPI-L16C). An offset cannot repeat like a
	// token, so the loop scenario serves page one again at the second offset
	// and the driver must refuse a page that repeats the previous page's last
	// record (vendorapi.OffsetLoop). The spellings are the closed
	// offsetSpellings table.
	FamilyOffset PagingFamily = "offset"
	// FamilyReport is the two-step report: a JSON document of signed
	// download links, each fetched from a second host without the API
	// credential (GitHub Copilot usage metrics).
	FamilyReport PagingFamily = "report"
)

// Classify derives the paging family from a surface's first-page fixture.
func Classify(sf *SurfaceFixtures) PagingFamily {
	if sf.Has(fixturecorpus.ScenarioReportLink) {
		return FamilyReport
	}
	first, ok := sf.Success()
	if !ok {
		return FamilyNone
	}
	if _, ok := headerValue(first.Sidecar.HTTP.Headers, "link"); ok {
		return FamilyLink
	}
	doc, err := decodeJSON(first.Body)
	if err != nil {
		return FamilyNone
	}
	m, isObj := doc.(map[string]any)
	if !isObj {
		return FamilyNone
	}
	if _, ok := m["@odata.nextLink"]; ok {
		return FamilyODataNext
	}
	if _, ok := m["has_more"]; ok {
		if _, ok := m["next_page"]; ok {
			return FamilyNextPage
		}
		if _, ok := m["last_id"]; ok {
			return FamilyAfterID
		}
	}
	if pg, ok := m["pagination"].(map[string]any); ok {
		if _, ok := pg["hasNextPage"]; ok {
			return FamilyBodyPage
		}
	}
	if _, ok := m["has_next_page"]; ok {
		if _, ok := m["end_cursor"]; ok {
			return FamilyEndCursor
		}
	}
	if _, _, ok := nestedCursor(m); ok {
		return FamilyNestedCursor
	}
	// A page token is a paging signal only when the first page hands one
	// out: a first page whose token is null or empty is a single document
	// (Cursor's grokbot computer operation answers nextCursor null).
	if k, ok := nextTokenKey(m); ok && scalarString(m[k]) != "" {
		return FamilyNextToken
	}
	if s, ok := offsetSpelled(m); ok && (s.Base == 0 || partialFirstPage(m, s)) {
		return FamilyOffset
	}
	return FamilyNone
}

// offsetSpelling is one documented spelling of the offset family: the total
// member, the record container it counts and the index of the first record
// (0 for an offset, 1 for SCIM's startIndex).
type offsetSpelling struct {
	Total, Records string
	Base           int
}

// offsetSpellings is the closed table of offset spellings.
var offsetSpellings = []offsetSpelling{
	{Total: "total_count", Records: "data"}, // OpenRouter listOrganizationMembers, Prime GenericPaginationResponse
	// SCIM 2.0 ListResponse (RFC 7644 3.4.2): startIndex is 1-based (lane
	// ENTAPI-L16E, JetBrains Hub).
	{Total: "totalResults", Records: "Resources", Base: 1},
}

// offsetSpelled returns a page's offset spelling when both the numeric total
// and the record array are present.
func offsetSpelled(doc map[string]any) (offsetSpelling, bool) {
	for _, s := range offsetSpellings {
		_, isNum := doc[s.Total].(json.Number)
		_, isArr := doc[s.Records].([]any)
		if isNum && isArr {
			return s, true
		}
	}
	return offsetSpelling{}, false
}

// partialFirstPage reports that a first page serves fewer records than its
// total. A SCIM ListResponse is the offset family only then: GitHub's SCIM
// fixtures are one complete page (totalResults equals the records served) and
// stay a single document (lane ENTAPI-L16E).
func partialFirstPage(doc map[string]any, s offsetSpelling) bool {
	recs, _ := doc[s.Records].([]any)
	total, err := strconv.Atoi(scalarString(doc[s.Total]))
	return err == nil && total > len(recs)
}

// nextTokenKeys is the closed table of top-level page token spellings.
var nextTokenKeys = []string{
	"nextPageToken", // xAI Management API, Google Cloud Logging entries.list
	"nextToken",     // Qoder Teams OpenAPI
	"NextToken",     // AWS JSON protocol (CloudTrail LookupEvents)
	"nextCursor",    // Cursor Cloud Agents API v1 (omitted on the last page; lane CA-A4)
	"next_page_id",  // OpenHands Cloud V1 app-conversations and events search (null on the last page; lane CA-A4)
}

// nextTokenKey returns the page token member a page carries.
func nextTokenKey(doc map[string]any) (string, bool) {
	for _, k := range nextTokenKeys {
		if _, ok := doc[k]; ok {
			return k, true
		}
	}
	return "", false
}

// nestedCursorSpelling is one documented spelling of the nested cursor family:
// the paging object's key, its boolean flag and its cursor member.
type nestedCursorSpelling struct{ Object, Flag, Cursor string }

// nestedCursors is the closed table of nested cursor spellings, walked top
// down.
var nestedCursors = []nestedCursorSpelling{
	{Object: "meta", Flag: "has_more", Cursor: "next_cursor"},           // Factory analytics /users
	{Object: "pagination", Flag: "hasMore", Cursor: "nextCursor"},       // Factory Public API v0 lists
	{Object: "page_info", Flag: "has_next_page", Cursor: "next_cursor"}, // Warp Agent API runs list (lane CA-V1)
}

// nestedCursor returns a page's nested paging object and its spelling when
// both the flag and the cursor member are present.
func nestedCursor(doc map[string]any) (map[string]any, nestedCursorSpelling, bool) {
	for _, s := range nestedCursors {
		pg, ok := doc[s.Object].(map[string]any)
		if !ok {
			continue
		}
		_, hasFlag := pg[s.Flag]
		_, hasCursor := pg[s.Cursor]
		if hasFlag && hasCursor {
			return pg, s, true
		}
	}
	return nil, nestedCursorSpelling{}, false
}

func headerValue(h map[string]string, name string) (string, bool) {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

func decodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// recordKeys is the preference order for a page's record container. A page
// with none of these takes its first array-valued member.
var recordKeys = []string{
	"data", "items", "seats", "teamMembers", "usageEvents", "events", "results", "members",
	"commits", "changes", "groups", "users", "agents", "budgets", "Resources",
}

// RecordPath returns the key of the record container of a page ("" for a
// top-level array) and whether the page has a container at all. A single
// object with no array member is one record (container false).
func RecordPath(doc any) (string, bool) {
	switch v := doc.(type) {
	case []any:
		return "", true
	case map[string]any:
		for _, k := range recordKeys {
			if _, ok := v[k].([]any); ok {
				return k, true
			}
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, ok := v[k].([]any); ok {
				return k, true
			}
		}
	}
	return "", false
}
