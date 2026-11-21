package cursor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// The three read-only POST surfaces of the Admin API (lane ENTAPI-D3,
// T-692): each sends its read query as a closed vendorapi body the egress
// seam's POST table lists for exactly this surface and path.
const (
	SurfaceUsageEvents vs.SurfaceID = "cursor.admin.usage_events"
	SurfaceDailyUsage  vs.SurfaceID = "cursor.admin.daily_usage"
	SurfaceSpend       vs.SurfaceID = "cursor.admin.spend"

	// UsageNamespace and UsageJoinKind key one usage event. The Admin API
	// has no per-call id, so the join value is a digest of the fields the
	// Era 1 poller's DedupKey composes (member email or service account,
	// conversation id, the call's millisecond, model, output tokens).
	UsageNamespace = "cursor.usage"
	UsageJoinKind  = "usage_event_key"
	// SpendSnapshotClass is the snapshot class of one member's current-cycle
	// spend and limits.
	SpendSnapshotClass = "cursor.member_spend"
	// LegacyUsageKey is the legacy poller surface usage events replace (the
	// cursoradminpoll Admin API usage poller): the runner never fetches
	// the surface while that poller owns it (invariant I8).
	LegacyUsageKey = "cursoradminpoll.usage"

	UsageEventsContract = "cursor.admin.usage_events/v1 admin-api 2026-10-07"
	DailyUsageContract  = "cursor.admin.daily_usage/v1 admin-api 2026-10-07"
	SpendContract       = "cursor.admin.spend/v1 admin-api 2026-10-07"

	// UsagePageSize is the documented usage-events maximum page size.
	UsagePageSize = 1000
	// SpendPageSize is the spend page size asked for (the reference
	// documents no maximum; 100 is the usage-events default).
	SpendPageSize = 100
	// DailyMaxWindow is the documented daily-usage limit: "Date range
	// cannot exceed 30 days".
	DailyMaxWindow = 30 * 24 * time.Hour
	// UsageMaxWindow caps a usage-events request. The reference states no
	// limit; the daily-usage limit is used (an assumption, recorded in the
	// live-validation checklist).
	UsageMaxWindow = 30 * 24 * time.Hour
)

// UsageEvents returns the driver of cursor.admin.usage_events.
//
// Contract (Cursor Admin API, "Get Usage Events Data"): POST
// /teams/filtered-usage-events with {"startDate", "endDate", "page",
// "pageSize"} (epoch milliseconds, both bounds inclusive, so the driver sends
// the last millisecond before the window end; page size at most 1000) and no
// filter, so editor, CLI and cloud-agent events all return (EA-F1). The
// response is {"usageEvents": [...], "pagination": {"currentPage",
// "hasNextPage", ...}}. Each event lands as one per-call usage row: tokens
// from tokenUsage, chargedCents as the charge in cents (it already includes
// the Cursor Token Rate), and the EA-F2 billing breakdown (T-630). Display
// only: nothing here reaches spend (invariant I4).
func UsageEvents() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceUsageEvents,
		Build:           buildUsageEvents,
		ParseResponse:   parseUsageEvents,
		Auth:            basicAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassUsage, vs.ClassCost},
		LegacyPoller:    LegacyUsageKey,
		ClosedDTO:       true,
		ContractVersion: UsageEventsContract,
		Tool:            Tool,
		MaxWindow:       UsageMaxWindow,
		KnownPaths:      usageEventsKnownPaths,
	}
}

// pageCursor reads a page-number cursor ("" is page 1).
func pageCursor(surface vs.SurfaceID, cursor string) (int, error) {
	if cursor == "" {
		return 1, nil
	}
	n, err := strconv.Atoi(cursor)
	if err != nil || n < 2 || strconv.Itoa(n) != cursor {
		return 0, fmt.Errorf("%s: cursor must be a page number", surface)
	}
	return n, nil
}

// inclusiveRange renders [From, To) as the vendor's inclusive millisecond
// bounds.
func inclusiveRange(surface vs.SurfaceID, w vendorapi.Window, max time.Duration) (int64, int64, error) {
	if w.From.IsZero() || !w.To.After(w.From) {
		return 0, 0, fmt.Errorf("%s: a non-empty window is required", surface)
	}
	if w.To.Sub(w.From) > max {
		return 0, 0, fmt.Errorf("%s: the window exceeds %s", surface, max)
	}
	return w.From.UTC().UnixMilli(), w.To.UTC().UnixMilli() - 1, nil
}

func buildUsageEvents(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	start, end, err := inclusiveRange(SurfaceUsageEvents, w, UsageMaxWindow)
	if err != nil {
		return vendorapi.Request{}, err
	}
	page, err := pageCursor(SurfaceUsageEvents, cursor)
	if err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{
		Method: "POST", Path: "/teams/filtered-usage-events",
		Body: vendorapi.EpochRangePage{StartMillis: start, EndMillis: end, Page: page, PageSize: UsagePageSize},
	}, nil
}

// usageEventsDoc is the closed DTO of one usage-events page.
type usageEventsDoc struct {
	UsageEvents *[]usageEvent `json:"usageEvents"`
	Pagination  *struct {
		CurrentPage *json.Number `json:"currentPage"`
		HasNextPage *bool        `json:"hasNextPage"`
	} `json:"pagination"`
}

type usageEvent struct {
	Timestamp          *json.RawMessage `json:"timestamp"`
	UserEmail          *string          `json:"userEmail"`
	ServiceAccountID   *string          `json:"serviceAccountId"`
	ServiceAccountName *string          `json:"serviceAccountName"`
	AutomationID       *string          `json:"automationId"`
	CloudAgentID       *string          `json:"cloudAgentId"`
	ConversationID     *string          `json:"conversationId"`
	Model              *string          `json:"model"`
	Kind               *string          `json:"kind"`
	MaxMode            *bool            `json:"maxMode"`
	RequestsCosts      *json.Number     `json:"requestsCosts"`
	IsTokenBasedCall   *bool            `json:"isTokenBasedCall"`
	IsChargeable       *bool            `json:"isChargeable"`
	IsHeadless         *bool            `json:"isHeadless"`
	ChargedCents       *json.Number     `json:"chargedCents"`
	CursorTokenFee     *json.Number     `json:"cursorTokenFee"`
	TokenUsage         *struct {
		InputTokens        *json.Number `json:"inputTokens"`
		OutputTokens       *json.Number `json:"outputTokens"`
		CacheWriteTokens   *json.Number `json:"cacheWriteTokens"`
		CacheReadTokens    *json.Number `json:"cacheReadTokens"`
		TotalCents         *json.Number `json:"totalCents"`
		DiscountPercentOff *json.Number `json:"discountPercentOff"`
	} `json:"tokenUsage"`
}

// eventMillis reads the documented epoch-ms timestamp, sent as a string (the
// reference's shape) or a number.
func eventMillis(raw *json.RawMessage) (time.Time, bool) {
	if raw == nil {
		return time.Time{}, false
	}
	s := strings.Trim(strings.TrimSpace(string(*raw)), `"`)
	ms, err := strconv.ParseInt(s, 10, 64)
	if err != nil || ms <= 0 {
		return time.Time{}, false
	}
	return time.UnixMilli(ms).UTC(), true
}

// count reads a non-negative whole JSON number (0 when absent).
func count(n *json.Number) (int64, bool) {
	if n == nil {
		return 0, true
	}
	v, err := n.Int64()
	return v, err == nil && v >= 0
}

// micros reads an optional non-negative decimal as micro-units (nil when
// absent).
func micros(n *json.Number) (*int64, bool) {
	if n == nil {
		return nil, true
	}
	v, ok := vendorapi.DecimalMicros(n.String(), 0)
	if !ok || v < 0 {
		return nil, false
	}
	return &v, true
}

func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// usageJoinValue is the digest of an event's composite key; n > 0 marks the
// n-th repeat of the same composite inside one page.
func usageJoinValue(identity, conversation string, at time.Time, model string, output int64, n int) string {
	key := strings.Join([]string{
		identity, conversation, strconv.FormatInt(at.UnixMilli(), 10), model,
		strconv.FormatInt(output, 10),
	}, "|")
	if n > 0 {
		key += "|" + strconv.Itoa(n)
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16])
}

func parseUsageEvents(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, drift(SurfaceUsageEvents, "status %d is not the documented 200", r.Status)
	}
	var doc usageEventsDoc
	if err := decode(r.Body, &doc); err != nil {
		return vendorapi.Page{}, drift(SurfaceUsageEvents, "body does not decode as the documented object")
	}
	if doc.UsageEvents == nil || doc.Pagination == nil || doc.Pagination.CurrentPage == nil || doc.Pagination.HasNextPage == nil {
		return vendorapi.Page{}, drift(SurfaceUsageEvents, "required field usageEvents, pagination.currentPage or pagination.hasNextPage is missing")
	}
	current, err := doc.Pagination.CurrentPage.Int64()
	if err != nil || current < 1 {
		return vendorapi.Page{}, drift(SurfaceUsageEvents, "pagination.currentPage is not a page number")
	}
	page := vendorapi.Page{}
	if *doc.Pagination.HasNextPage {
		page.NextCursor = strconv.FormatInt(current+1, 10)
	}
	repeats := map[string]int{}
	for i, e := range *doc.UsageEvents {
		at, ok := eventMillis(e.Timestamp)
		if !ok || e.Model == nil || *e.Model == "" {
			return vendorapi.Page{}, drift(SurfaceUsageEvents, "usageEvents[%d] misses timestamp or model", i)
		}
		u := vendorapi.UsageRow{
			JoinKind: UsageJoinKind, JoinNamespace: UsageNamespace, At: at, Model: *e.Model,
			SessionRef: str(e.ConversationID), Flags: map[string]string{},
		}
		switch {
		case str(e.UserEmail) != "":
			u.IdentityKind, u.Identity = "email", vendorapi.FoldEmail(*e.UserEmail)
		case str(e.ServiceAccountID) != "":
			u.IdentityKind, u.Identity = "account_id", *e.ServiceAccountID
		default:
			return vendorapi.Page{}, drift(SurfaceUsageEvents, "usageEvents[%d] names neither userEmail nor serviceAccountId", i)
		}
		if e.TokenUsage != nil {
			var oks [4]bool
			u.InputTokens, oks[0] = count(e.TokenUsage.InputTokens)
			u.OutputTokens, oks[1] = count(e.TokenUsage.OutputTokens)
			u.CacheWriteTokens, oks[2] = count(e.TokenUsage.CacheWriteTokens)
			u.CacheReadTokens, oks[3] = count(e.TokenUsage.CacheReadTokens)
			if !oks[0] || !oks[1] || !oks[2] || !oks[3] {
				return vendorapi.Page{}, drift(SurfaceUsageEvents, "usageEvents[%d].tokenUsage has a count that is not a whole non-negative number", i)
			}
		}
		charged, ok := micros(e.ChargedCents)
		if !ok {
			return vendorapi.Page{}, drift(SurfaceUsageEvents, "usageEvents[%d].chargedCents is not a non-negative decimal", i)
		}
		if charged != nil {
			u.ChargedUnit, u.ChargedMicros = "cents", *charged
		}
		b := &vendorapi.UsageBilling{
			Category: str(e.Kind), MaxMode: e.MaxMode, Chargeable: e.IsChargeable,
			ServiceAccountName: str(e.ServiceAccountName), AutomationID: str(e.AutomationID),
		}
		var oks [4]bool
		b.RequestUnitsMicros, oks[0] = micros(e.RequestsCosts)
		b.FeeMicros, oks[1] = micros(e.CursorTokenFee)
		oks[2], oks[3] = true, true
		if e.TokenUsage != nil {
			b.ModelCostMicros, oks[2] = micros(e.TokenUsage.TotalCents)
			b.DiscountPercentMicros, oks[3] = micros(e.TokenUsage.DiscountPercentOff)
		}
		if !oks[0] || !oks[1] || !oks[2] || !oks[3] {
			return vendorapi.Page{}, drift(SurfaceUsageEvents, "usageEvents[%d] has a billing amount that is not a non-negative decimal", i)
		}
		u.Billing = b
		if e.IsHeadless != nil {
			u.Flags["is_headless"] = strconv.FormatBool(*e.IsHeadless)
		}
		// isTokenBasedCall lands as billing_basis: an attribute key may not
		// carry the secret-shaped fragment "token" (vendorapi.secretShaped).
		if e.IsTokenBasedCall != nil {
			u.Flags["billing_basis"] = map[bool]string{true: "tokens", false: "requests"}[*e.IsTokenBasedCall]
		}
		composite := u.Identity + "\x00" + u.SessionRef + "\x00" + strconv.FormatInt(at.UnixMilli(), 10) + "\x00" + u.Model +
			"\x00" + strconv.FormatInt(u.OutputTokens, 10)
		u.JoinValue = usageJoinValue(u.Identity, u.SessionRef, at, u.Model, u.OutputTokens, repeats[composite])
		repeats[composite]++
		page.Usage = append(page.Usage, u)
	}
	return page, nil
}

// usageEventsKnownPaths are the documented response paths (the corpus field
// ledgers of "Get Usage Events Data").
var usageEventsKnownPaths = []string{
	"pagination", "pagination.currentPage", "pagination.hasNextPage", "pagination.hasPreviousPage",
	"pagination.numPages", "pagination.pageSize", "period", "period.endDate", "period.startDate",
	"totalUsageEventsCount", "usageEvents", "usageEvents[]", "usageEvents[].chargedCents",
	"usageEvents[].conversationId", "usageEvents[].cursorTokenFee", "usageEvents[].isChargeable",
	"usageEvents[].isHeadless", "usageEvents[].isTokenBasedCall", "usageEvents[].kind", "usageEvents[].maxMode",
	"usageEvents[].model", "usageEvents[].requestsCosts", "usageEvents[].serviceAccountId",
	"usageEvents[].serviceAccountName", "usageEvents[].timestamp", "usageEvents[].tokenUsage",
	"usageEvents[].tokenUsage.cacheReadTokens", "usageEvents[].tokenUsage.cacheWriteTokens",
	"usageEvents[].tokenUsage.discountPercentOff", "usageEvents[].tokenUsage.inputTokens",
	"usageEvents[].tokenUsage.outputTokens", "usageEvents[].tokenUsage.totalCents", "usageEvents[].userEmail",
}

// DailyUsage returns the driver of cursor.admin.daily_usage.
//
// Contract (Cursor Admin API, "Get Daily Usage Data"): POST
// /teams/daily-usage-data with {"startDate", "endDate"} (epoch ms; the
// range at most 30 days). Without page and pageSize the endpoint answers the
// ACTIVE users only, in one document {"data": [...], "period": {...}}; the
// driver uses that documented unpaged form (a user with no activity has no
// value to land). Each record is one user-day; each documented numeric
// field lands as one fact over that UTC day keyed by the member's email
// (lines added and deleted, accepted lines, applies, accepts, rejects, Tab
// completions, request counts by kind). The day is read as a UTC date (the
// reference states no zone: Inferred, recorded in the checklist).
func DailyUsage() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceDailyUsage,
		Build:           buildDailyUsage,
		ParseResponse:   parseDailyUsage,
		Auth:            basicAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassUsage, vs.ClassLOC, vs.ClassAdoption},
		ClosedDTO:       true,
		ContractVersion: DailyUsageContract,
		Tool:            Tool,
		MaxWindow:       DailyMaxWindow,
		KnownPaths:      dailyUsageKnownPaths,
	}
}

func buildDailyUsage(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the unpaged form has one page", SurfaceDailyUsage)
	}
	start, end, err := inclusiveRange(SurfaceDailyUsage, w, DailyMaxWindow)
	if err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{
		Method: "POST", Path: "/teams/daily-usage-data",
		Body: vendorapi.EpochRange{StartMillis: start, EndMillis: end},
	}, nil
}

// dailyMetric maps one documented numeric field to a fact metric and unit.
type dailyMetric struct {
	field, metric, unit string
}

// dailyMetrics is the closed field table of a daily-usage record.
var dailyMetrics = []dailyMetric{
	{"totalLinesAdded", "lines_added", "lines"},
	{"totalLinesDeleted", "lines_deleted", "lines"},
	{"acceptedLinesAdded", "accepted_lines_added", "lines"},
	{"acceptedLinesDeleted", "accepted_lines_deleted", "lines"},
	{"totalApplies", "applies", "count"},
	{"totalAccepts", "accepts", "count"},
	{"totalRejects", "rejects", "count"},
	{"totalTabsShown", "tabs_shown", "count"},
	{"totalTabsAccepted", "tabs_accepted", "count"},
	{"composerRequests", "composer_requests", "requests"},
	{"chatRequests", "chat_requests", "requests"},
	{"agentRequests", "agent_requests", "requests"},
	{"cmdkUsages", "cmdk_usages", "count"},
	{"subscriptionIncludedReqs", "subscription_included_requests", "requests"},
	{"apiKeyReqs", "api_key_requests", "requests"},
	{"usageBasedReqs", "usage_based_requests", "requests"},
	{"bugbotUsages", "bugbot_usages", "count"},
}

type dailyDoc struct {
	Data *[]map[string]json.RawMessage `json:"data"`
}

func parseDailyUsage(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, drift(SurfaceDailyUsage, "status %d is not the documented 200", r.Status)
	}
	var doc dailyDoc
	if err := decode(r.Body, &doc); err != nil {
		return vendorapi.Page{}, drift(SurfaceDailyUsage, "body does not decode as the documented object")
	}
	if doc.Data == nil {
		return vendorapi.Page{}, drift(SurfaceDailyUsage, "required field data is missing")
	}
	page := vendorapi.Page{SourceRecords: len(*doc.Data)}
	seen := map[string]bool{}
	for i, rec := range *doc.Data {
		var day, email string
		if err := scalarInto(rec["day"], &day); err != nil || day == "" {
			return vendorapi.Page{}, drift(SurfaceDailyUsage, "data[%d].day is missing or not a string", i)
		}
		start, err := time.Parse("2006-01-02", day)
		if err != nil {
			return vendorapi.Page{}, drift(SurfaceDailyUsage, "data[%d].day is not an ISO date", i)
		}
		if err := scalarInto(rec["email"], &email); err != nil || email == "" {
			return vendorapi.Page{}, drift(SurfaceDailyUsage, "data[%d].email is missing or not a string", i)
		}
		email = vendorapi.FoldEmail(email)
		if seen[email+"\x00"+day] {
			return vendorapi.Page{}, drift(SurfaceDailyUsage, "data[%d] repeats a user and day", i)
		}
		seen[email+"\x00"+day] = true
		for _, m := range dailyMetrics {
			raw, ok := rec[m.field]
			if !ok || string(raw) == "null" {
				continue
			}
			var n json.Number
			if err := scalarInto(raw, &n); err != nil {
				return vendorapi.Page{}, drift(SurfaceDailyUsage, "data[%d].%s is not a number", i, m.field)
			}
			v, err := n.Int64()
			if err != nil || v < 0 {
				return vendorapi.Page{}, drift(SurfaceDailyUsage, "data[%d].%s is not a whole non-negative number", i, m.field)
			}
			mv, ok := vendorapi.CountMicros(v)
			if !ok {
				return vendorapi.Page{}, drift(SurfaceDailyUsage, "data[%d].%s overflows", i, m.field)
			}
			page.Facts = append(page.Facts, vendorapi.FactRow{
				IntervalStart: start.UTC(), IntervalEnd: start.UTC().Add(24 * time.Hour), SourceTZ: "UTC",
				CoverageDomain: "cursor.team", IdentityKind: "email", Identity: email,
				Metric: m.metric, Unit: m.unit, ValueMicros: mv,
			})
		}
	}
	return page, nil
}

// scalarInto decodes one JSON scalar into a string or a json.Number, refusing
// a value of the other type (a quoted number is not a number).
func scalarInto(raw json.RawMessage, into any) error {
	if len(raw) == 0 {
		return fmt.Errorf("absent")
	}
	switch v := into.(type) {
	case *string:
		if raw[0] != '"' {
			return fmt.Errorf("not a string")
		}
		return json.Unmarshal(raw, v)
	case *json.Number:
		if raw[0] == '"' {
			return fmt.Errorf("a quoted number")
		}
		return decode(raw, v)
	}
	return fmt.Errorf("unsupported")
}

// dailyUsageKnownPaths are the documented response paths (the corpus field
// ledger of "Get Daily Usage Data").
var dailyUsageKnownPaths = []string{
	"data", "data[]", "data[].acceptedLinesAdded", "data[].acceptedLinesDeleted", "data[].agentRequests",
	"data[].apiKeyReqs", "data[].applyMostUsedExtension", "data[].bugbotUsages", "data[].chatRequests",
	"data[].clientVersion", "data[].cmdkUsages", "data[].composerRequests", "data[].date", "data[].day",
	"data[].email", "data[].isActive", "data[].mostUsedModel", "data[].subscriptionIncludedReqs",
	"data[].tabMostUsedExtension", "data[].totalAccepts", "data[].totalApplies", "data[].totalLinesAdded",
	"data[].totalLinesDeleted", "data[].totalRejects", "data[].totalTabsAccepted", "data[].totalTabsShown",
	"data[].usageBasedReqs", "data[].userId", "period", "period.endDate", "period.startDate",
}

// Spend returns the driver of cursor.admin.spend.
//
// Contract (Cursor Admin API, "Get Spending Data"): POST /teams/spend with
// {"page", "pageSize"} (no search term, no sort override); the response is
// {"teamMemberSpend": [...], "subscriptionCycleStart", "totalMembers",
// "totalPages"} and does not echo the page it answered, so the driver reads
// its position from the request cursor (Response.Cursor) and asks the next
// page while it is below totalPages. Each member lands as one snapshot of
// class cursor.member_spend keyed by email: current-cycle on-demand and
// overall spend in cents, the usage-based premium request count and the
// three limit fields in dollars. A snapshot is stored only when it changed.
// Display only: never on a spend, budget or alert path (invariant I4).
func Spend() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceSpend,
		Build:           buildSpend,
		ParseResponse:   parseSpend,
		Auth:            basicAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassCost, vs.ClassLimits},
		ClosedDTO:       true,
		ContractVersion: SpendContract,
		Tool:            Tool,
		KnownPaths:      spendKnownPaths,
	}
}

func buildSpend(_ vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	page, err := pageCursor(SurfaceSpend, cursor)
	if err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{
		Method: "POST", Path: "/teams/spend", Body: vendorapi.PageQuery{Page: page, PageSize: SpendPageSize},
	}, nil
}

type spendDoc struct {
	TeamMemberSpend        *[]memberSpend `json:"teamMemberSpend"`
	SubscriptionCycleStart *json.Number   `json:"subscriptionCycleStart"`
	TotalPages             *json.Number   `json:"totalPages"`
}

type memberSpend struct {
	UserID                       *string      `json:"userId"`
	Email                        *string      `json:"email"`
	Role                         *string      `json:"role"`
	SpendCents                   *json.Number `json:"spendCents"`
	OverallSpendCents            *json.Number `json:"overallSpendCents"`
	FastPremiumRequests          *json.Number `json:"fastPremiumRequests"`
	HardLimitOverrideDollars     *json.Number `json:"hardLimitOverrideDollars"`
	MonthlyLimitDollars          *json.Number `json:"monthlyLimitDollars"`
	EffectivePerUserLimitDollars *json.Number `json:"effectivePerUserLimitDollars"`
}

// decimalText checks a non-negative decimal and renders it canonically.
func decimalText(n *json.Number) (string, bool) {
	v, ok := micros(n)
	if !ok || v == nil {
		return "", ok
	}
	return n.String(), true
}

func parseSpend(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, drift(SurfaceSpend, "status %d is not the documented 200", r.Status)
	}
	var doc spendDoc
	if err := decode(r.Body, &doc); err != nil {
		return vendorapi.Page{}, drift(SurfaceSpend, "body does not decode as the documented object")
	}
	if doc.TeamMemberSpend == nil || doc.TotalPages == nil || doc.SubscriptionCycleStart == nil {
		return vendorapi.Page{}, drift(SurfaceSpend, "required field teamMemberSpend, totalPages or subscriptionCycleStart is missing")
	}
	total, err := doc.TotalPages.Int64()
	if err != nil || total < 0 {
		return vendorapi.Page{}, drift(SurfaceSpend, "totalPages is not a page count")
	}
	cycle, err := doc.SubscriptionCycleStart.Int64()
	if err != nil || cycle <= 0 {
		return vendorapi.Page{}, drift(SurfaceSpend, "subscriptionCycleStart is not epoch milliseconds")
	}
	current, err := pageCursor(SurfaceSpend, r.Cursor)
	if err != nil {
		return vendorapi.Page{}, drift(SurfaceSpend, "the request cursor is not a page number")
	}
	page := vendorapi.Page{}
	if int64(current) < total {
		page.NextCursor = strconv.Itoa(current + 1)
	}
	seen := map[string]bool{}
	for i, m := range *doc.TeamMemberSpend {
		email := vendorapi.FoldEmail(str(m.Email))
		if email == "" {
			return vendorapi.Page{}, drift(SurfaceSpend, "teamMemberSpend[%d].email is missing", i)
		}
		if seen[email] {
			return vendorapi.Page{}, drift(SurfaceSpend, "teamMemberSpend[%d] repeats a member", i)
		}
		seen[email] = true
		body := map[string]string{"cycle_start": time.UnixMilli(cycle).UTC().Format(time.RFC3339)}
		if v := str(m.UserID); v != "" {
			body["user_id"] = v
		}
		if v := str(m.Role); v != "" {
			body["role"] = v
		}
		for _, f := range []struct {
			key string
			n   *json.Number
		}{
			{"spend_cents", m.SpendCents},
			{"overall_spend_cents", m.OverallSpendCents},
			{"fast_premium_requests", m.FastPremiumRequests},
			{"hard_limit_override_dollars", m.HardLimitOverrideDollars},
			{"monthly_limit_dollars", m.MonthlyLimitDollars},
			{"effective_per_user_limit_dollars", m.EffectivePerUserLimitDollars},
		} {
			v, ok := decimalText(f.n)
			if !ok {
				return vendorapi.Page{}, drift(SurfaceSpend, "teamMemberSpend[%d].%s is not a non-negative decimal", i, f.key)
			}
			if v != "" {
				body[f.key] = v
			}
		}
		page.Snapshots = append(page.Snapshots, vendorapi.VendorSnapshot{Class: SpendSnapshotClass, Subject: email, Body: body})
	}
	return page, nil
}

// spendKnownPaths are the documented response paths (the corpus field ledger
// of "Get Spending Data").
var spendKnownPaths = []string{
	"subscriptionCycleStart", "teamMemberSpend", "teamMemberSpend[]", "teamMemberSpend[].effectivePerUserLimitDollars",
	"teamMemberSpend[].email", "teamMemberSpend[].fastPremiumRequests", "teamMemberSpend[].hardLimitOverrideDollars",
	"teamMemberSpend[].monthlyLimitDollars", "teamMemberSpend[].name", "teamMemberSpend[].overallSpendCents",
	"teamMemberSpend[].role", "teamMemberSpend[].spendCents", "teamMemberSpend[].userId", "totalMembers", "totalPages",
}
