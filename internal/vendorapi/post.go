package vendorapi

import (
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

// Reviewed read-only POST bodies (lane ENTAPI-D3, T-692). Some vendors put a
// read query in a POST body (Cursor's /teams/filtered-usage-events,
// /teams/daily-usage-data and /teams/spend). A driver never hands the egress
// seam raw bytes: it builds one of the closed body types below, the egress
// seam checks the body's kind against its closed POST table (one row per
// catalog surface and path) and encodes it here. PostBody is sealed: its
// unexported method means no type outside this package can implement it, so
// the set of bodies that can ever be sent is exactly this file.

// PostKind names one closed body shape.
type PostKind string

// Body kinds.
const (
	// PostEpochRange is {"startDate", "endDate"} in epoch milliseconds.
	PostEpochRange PostKind = "epoch_range"
	// PostEpochRangePage is {"startDate", "endDate", "page", "pageSize"}.
	PostEpochRangePage PostKind = "epoch_range_page"
	// PostPage is {"page", "pageSize"}.
	PostPage PostKind = "page"
	// PostEpochRangePageHosting is {"startDate", "endDate", "page",
	// "pageSize", "hostingType"}: an EpochRangePage narrowed to one hosting
	// type from a closed table (cloud agents arc, lane CA-C8: Cursor's
	// filtered-usage-events read for cloud-hosted agents only).
	PostEpochRangePageHosting PostKind = "epoch_range_page_hosting"
	// PostUserSpendLimitSet is {"userEmail", "spendLimitDollars"} with a
	// whole, non-negative dollar amount: the one vendor WRITE body (lane
	// ENTAPI-L14, T-617, Cursor "Set User Spend Limit"). It is never a read
	// query: the egress seam's read POST table never lists it and its closed
	// write table lists it for exactly one operation. There is no null form:
	// the vendor's null removes a limit, which is a loosening and therefore
	// cannot be expressed here at all (never-loosen, structurally).
	PostUserSpendLimitSet PostKind = "user_spend_limit_set"
	// PostCloudTrailLookup is the AWS CloudTrail LookupEvents request (lane
	// ENTAPI-L16D, T-713): one EventSource lookup attribute from a closed
	// table, StartTime and EndTime in epoch seconds, MaxResults and the
	// previous page's NextToken. A read: LookupEvents only reads Event history.
	PostCloudTrailLookup PostKind = "cloudtrail_lookup"
	// PostCloudAuditLogQuery is the Google Cloud Logging entries.list request
	// (lane ENTAPI-L16D, T-713) for one project's Cloud Audit Logs of one
	// service from a closed table: resourceNames, a filter this file composes
	// (never a caller), orderBy "timestamp asc", pageSize and pageToken. A
	// read: entries.list only lists.
	PostCloudAuditLogQuery PostKind = "cloud_audit_log_query"
)

// WriteKind reports whether a body kind changes vendor state. The egress
// seam refuses every write kind on its read path.
func WriteKind(k PostKind) bool { return k == PostUserSpendLimitSet }

// MaxSpendLimitDollars bounds a written per-user limit (far above any real
// cap; it only keeps the encoded number sane).
const MaxSpendLimitDollars int64 = 1_000_000_000

// MaxPostPageSize bounds the page size any POST body may ask for (Cursor
// documents 1,000 as the usage-events maximum).
const MaxPostPageSize = 1000

// ErrBadPostBody is every refusal of EncodePostBody.
var ErrBadPostBody = errors.New("vendorapi: post body outside its closed shape")

// PostBody is one closed read-query body. Only this package implements it.
type PostBody interface {
	// PostKind names the body's shape (the egress POST table keys on it).
	PostKind() PostKind
	encode() ([]byte, error)
}

// EpochRange is a millisecond range with both bounds as the vendor documents
// them (the driver decides inclusive or exclusive; this type only checks the
// range is ordered and positive).
type EpochRange struct {
	StartMillis int64
	EndMillis   int64
}

// EpochRangePage is an EpochRange plus a 1-based page and a page size.
type EpochRangePage struct {
	StartMillis int64
	EndMillis   int64
	Page        int
	PageSize    int
}

// EpochRangePageHosting is an EpochRangePage plus one hosting type from the
// closed hostingTypes table (lane CA-C8). The vendor ANDs the filter with the
// range, so the body only narrows what an EpochRangePage would read.
type EpochRangePageHosting struct {
	StartMillis int64
	EndMillis   int64
	Page        int
	PageSize    int
	HostingType string
}

// HostingCloud is Cursor's hostingType filter value for cloud-hosted agents
// (Admin API "Get Usage Events Data": hostingType CLOUD or SELF_HOSTED).
const HostingCloud = "CLOUD"

// hostingTypes is the closed table of hosting types a body may name. Only
// CLOUD is reviewed: the one read lane CA-C8 needs.
var hostingTypes = map[string]bool{HostingCloud: true}

// PageQuery is a 1-based page and a page size alone.
type PageQuery struct {
	Page     int
	PageSize int
}

// UserSpendLimitSet is the closed write body of Cursor's "Set User Spend
// Limit": one team member's email (lower case, as the spend surface lands it)
// and a whole-dollar limit. LimitDollars is an int64, so the vendor's null
// (remove the limit) has no representation.
type UserSpendLimitSet struct {
	UserEmail    string
	LimitDollars int64
}

// PostKind implements PostBody.
func (UserSpendLimitSet) PostKind() PostKind { return PostUserSpendLimitSet }

// writeEmailRE is the address shape a write may name: lower case, one @, a
// dotted domain, no space, quote or control character.
var writeEmailRE = regexp.MustCompile(`^[a-z0-9._%+-]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,63}$`)

func (b UserSpendLimitSet) encode() ([]byte, error) {
	if len(b.UserEmail) > 254 || !writeEmailRE.MatchString(b.UserEmail) || b.LimitDollars < 0 || b.LimitDollars > MaxSpendLimitDollars {
		return nil, ErrBadPostBody
	}
	return json.Marshal(struct {
		UserEmail         string `json:"userEmail"`
		SpendLimitDollars int64  `json:"spendLimitDollars"`
	}{b.UserEmail, b.LimitDollars})
}

// PostKind implements PostBody.
func (EpochRange) PostKind() PostKind { return PostEpochRange }

// PostKind implements PostBody.
func (EpochRangePage) PostKind() PostKind { return PostEpochRangePage }

// PostKind implements PostBody.
func (PageQuery) PostKind() PostKind { return PostPage }

// PostKind implements PostBody.
func (EpochRangePageHosting) PostKind() PostKind { return PostEpochRangePageHosting }

func validRange(start, end int64) bool { return start > 0 && end >= start }

func validPage(page, size int) bool { return page >= 1 && size >= 1 && size <= MaxPostPageSize }

func (b EpochRange) encode() ([]byte, error) {
	if !validRange(b.StartMillis, b.EndMillis) {
		return nil, ErrBadPostBody
	}
	return json.Marshal(struct {
		StartDate int64 `json:"startDate"`
		EndDate   int64 `json:"endDate"`
	}{b.StartMillis, b.EndMillis})
}

func (b EpochRangePage) encode() ([]byte, error) {
	if !validRange(b.StartMillis, b.EndMillis) || !validPage(b.Page, b.PageSize) {
		return nil, ErrBadPostBody
	}
	return json.Marshal(struct {
		StartDate int64 `json:"startDate"`
		EndDate   int64 `json:"endDate"`
		Page      int   `json:"page"`
		PageSize  int   `json:"pageSize"`
	}{b.StartMillis, b.EndMillis, b.Page, b.PageSize})
}

func (b EpochRangePageHosting) encode() ([]byte, error) {
	if !validRange(b.StartMillis, b.EndMillis) || !validPage(b.Page, b.PageSize) || !hostingTypes[b.HostingType] {
		return nil, ErrBadPostBody
	}
	return json.Marshal(struct {
		StartDate   int64  `json:"startDate"`
		EndDate     int64  `json:"endDate"`
		Page        int    `json:"page"`
		PageSize    int    `json:"pageSize"`
		HostingType string `json:"hostingType"`
	}{b.StartMillis, b.EndMillis, b.Page, b.PageSize, b.HostingType})
}

func (b PageQuery) encode() ([]byte, error) {
	if !validPage(b.Page, b.PageSize) {
		return nil, ErrBadPostBody
	}
	return json.Marshal(struct {
		Page     int `json:"page"`
		PageSize int `json:"pageSize"`
	}{b.Page, b.PageSize})
}

// CloudTrail LookupEvents limits (AWS CloudTrail API Reference,
// LookupEvents): at most 50 results per page; a token is opaque.
const (
	MaxCloudTrailResults = 50
	// MaxCloudLogPageSize bounds an entries.list page (the Logging API's
	// documented maximum is 1000).
	MaxCloudLogPageSize = 1000
)

// cloudTrailEventSources is the closed table of CloudTrail event sources a
// lookup may name. Each row is a vendor's documented event source.
var cloudTrailEventSources = map[string]bool{
	// Amazon Q Developer (and the Kiro subscriptions it bills): "Logging
	// Amazon Q Developer API calls using AWS CloudTrail", eventSource
	// q.amazonaws.com.
	"q.amazonaws.com": true,
}

// cloudAuditServices is the closed table of Google Cloud services whose audit
// log a query may read.
var cloudAuditServices = map[string]bool{
	// Gemini for Google Cloud / Gemini Code Assist ("cloudaicompanion API
	// audit logging").
	"cloudaicompanion.googleapis.com": true,
}

var (
	// opaqueTokenRE bounds an opaque page token copied back from a response.
	opaqueTokenRE = regexp.MustCompile(`^[A-Za-z0-9+/=_.:~-]+$`)
	// gcpProjectRE is a Google Cloud project id (6 to 30 characters, lower
	// case letters, digits and hyphens, starting with a letter, not ending
	// with a hyphen).
	gcpProjectRE = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
)

// ValidGCPProject reports whether s is a Google Cloud project id.
func ValidGCPProject(s string) bool { return gcpProjectRE.MatchString(s) }

// maxOpaqueToken bounds an opaque page token.
const maxOpaqueToken = 4096

// ValidOpaqueToken reports whether s is a usable opaque page token.
func ValidOpaqueToken(s string) bool { return len(s) <= maxOpaqueToken && opaqueTokenRE.MatchString(s) }

// CloudTrailLookup is the closed LookupEvents body: one event source from the
// closed table, the window in epoch seconds (start inclusive, end inclusive
// as the reference states), a page size and the previous page's token.
type CloudTrailLookup struct {
	EventSource  string
	StartSeconds int64
	EndSeconds   int64
	MaxResults   int
	NextToken    string
}

// PostKind implements PostBody.
func (CloudTrailLookup) PostKind() PostKind { return PostCloudTrailLookup }

func (b CloudTrailLookup) encode() ([]byte, error) {
	if !cloudTrailEventSources[b.EventSource] || !validRange(b.StartSeconds, b.EndSeconds) || b.MaxResults < 1 ||
		b.MaxResults > MaxCloudTrailResults || (b.NextToken != "" && !ValidOpaqueToken(b.NextToken)) {
		return nil, ErrBadPostBody
	}
	type attr struct {
		AttributeKey   string `json:"AttributeKey"`
		AttributeValue string `json:"AttributeValue"`
	}
	return json.Marshal(struct {
		LookupAttributes []attr `json:"LookupAttributes"`
		StartTime        int64  `json:"StartTime"`
		EndTime          int64  `json:"EndTime"`
		MaxResults       int    `json:"MaxResults"`
		NextToken        string `json:"NextToken,omitempty"`
	}{[]attr{{"EventSource", b.EventSource}}, b.StartSeconds, b.EndSeconds, b.MaxResults, b.NextToken})
}

// CloudAuditLogQuery is the closed entries.list body for one project's Cloud
// Audit Logs (Admin Activity and Data Access) of one service from the closed
// table over a half-open UTC window. The filter is composed here from these
// fields only: no caller ever writes a Logging query.
type CloudAuditLogQuery struct {
	Project   string
	Service   string
	From, To  time.Time
	PageSize  int
	PageToken string
}

// PostKind implements PostBody.
func (CloudAuditLogQuery) PostKind() PostKind { return PostCloudAuditLogQuery }

// Filter renders the Logging query of the body (also what the mock checks).
func (b CloudAuditLogQuery) Filter() (string, error) {
	if !gcpProjectRE.MatchString(b.Project) || !cloudAuditServices[b.Service] || b.From.IsZero() || !b.To.After(b.From) {
		return "", ErrBadPostBody
	}
	logs := "projects/" + b.Project + "/logs/cloudaudit.googleapis.com%2F"
	return `(logName="` + logs + `activity" OR logName="` + logs + `data_access") AND protoPayload.serviceName="` +
		b.Service + `" AND timestamp>="` + b.From.UTC().Format(time.RFC3339) + `" AND timestamp<"` +
		b.To.UTC().Format(time.RFC3339) + `"`, nil
}

func (b CloudAuditLogQuery) encode() ([]byte, error) {
	f, err := b.Filter()
	if err != nil || b.PageSize < 1 || b.PageSize > MaxCloudLogPageSize ||
		(b.PageToken != "" && !ValidOpaqueToken(b.PageToken)) {
		return nil, ErrBadPostBody
	}
	return json.Marshal(struct {
		ResourceNames []string `json:"resourceNames"`
		Filter        string   `json:"filter"`
		OrderBy       string   `json:"orderBy"`
		PageSize      int      `json:"pageSize"`
		PageToken     string   `json:"pageToken,omitempty"`
	}{[]string{"projects/" + b.Project}, f, "timestamp asc", b.PageSize, b.PageToken})
}

// EncodePostBody renders a closed body as the JSON the egress seam sends. A
// nil body or one outside its shape is refused.
func EncodePostBody(b PostBody) ([]byte, error) {
	if b == nil {
		return nil, ErrBadPostBody
	}
	return b.encode()
}
