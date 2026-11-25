package anthropic

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceUserCost is the catalog id of the surface.
const SurfaceUserCost vs.SurfaceID = "anthropic.enterprise.analytics.user_cost_report"

// Claude Enterprise per-user cost vocabulary.
const (
	UserCostContract = "anthropic.enterprise.analytics.user_cost_report/v1 analytics-api 2023-06-01 (2026-10-08)"

	// UserCostPageLimit is the documented maximum rows per page.
	UserCostPageLimit = 1000
	// UserCostLookback is the documented history: starting_at within the
	// last 365 days.
	UserCostLookback = 365 * day
	// userCostSettleLag widens every request back by the documented
	// freshness of the Analytics API (typically within 4 hours, up to 24
	// hours), so a day is read again after it settles. It is separate from
	// the Console reports' settleLag on purpose.
	userCostSettleLag = 24 * time.Hour
	// userCostCoverage is the coverage domain of every fact: only seat-user
	// cost is in this report (org-wide totals including API keys are on the
	// analytics cost_report).
	userCostCoverage = "anthropic.enterprise.seat_users"
)

// userCostFloor is the documented earliest starting_at
// (2026-01-01T00:00:00Z).
var userCostFloor = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// UserCostReport returns the driver of
// anthropic.enterprise.analytics.user_cost_report.
//
// Contract (Analytics API reference, beta organization analytics, read
// 2026-10-08): GET /v1/organizations/analytics/user_cost_report on a Claude
// Enterprise org, an Analytics API key (scope read:analytics) as the whole
// X-Api-Key value and anthropic-version on every request. starting_at is
// inclusive, within the last 365 days and no earlier than 2026-01-01;
// ending_at is exclusive and at most 31 days later; bucket_width=1d makes each
// row one UTC day; group_by[]=product splits a user's day by product; limit
// is at most 1000 and page is the opaque next_page cursor. Each row is one
// user_actor (user_id, email_address, name, deleted), amount and list_amount
// (decimal strings in cents of USD, amount after discounts and before
// credits), currency (always USD) and requests (null when grouped by cost or
// token type). Data is fresh within 24 hours and can be revised until about
// 7 days after the calendar month ends.
//
// The actor's name and the deprecated actor.email are never read. The
// identity is the ASCII-folded e-mail, or the user id when the e-mail is
// null (a deleted account), empty or not pure ASCII (security ledger
// VCONN-6). There is no LegacyPoller: the ccanalytics enterprise kind reads
// /v1/organizations/analytics/users and writes no cost, so no legacy reader
// of this surface exists.
func UserCostReport() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceUserCost,
		Build:           buildUserCost,
		ParseResponse:   parseUserCost,
		Auth:            adminAuth,
		Headers:         headers(),
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassCost},
		ContractVersion: UserCostContract,
		Tool:            Tool,
		MaxWindow:       ReportMaxWindow,
		MaxLookback:     UserCostLookback,
		KnownPaths:      userCostKnownPaths,
	}
}

func buildUserCost(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if w.From.IsZero() || !w.To.After(w.From) {
		return vendorapi.Request{}, fmt.Errorf("%s: a non-empty window is required", SurfaceUserCost)
	}
	end := w.To.UTC()
	if !end.After(userCostFloor) {
		return vendorapi.Request{}, fmt.Errorf("%s: the window ends before the documented earliest start %s",
			SurfaceUserCost, userCostFloor.Format(time.RFC3339))
	}
	start := w.From.UTC().Add(-userCostSettleLag).Truncate(day)
	if start.Before(userCostFloor) {
		start = userCostFloor
	}
	q := map[string][]string{
		"starting_at":  {start.Format(time.RFC3339)},
		"ending_at":    {end.Format(time.RFC3339)},
		"bucket_width": {"1d"},
		"group_by[]":   {"product"},
		"limit":        {strconv.Itoa(UserCostPageLimit)},
	}
	if err := pageQuery(SurfaceUserCost, q, cursor); err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: "/v1/organizations/analytics/user_cost_report", Query: q}, nil
}

// userCostRow reads only what lands. actor.name and the deprecated
// actor.email have no field here, so they are never decoded.
type userCostRow struct {
	Actor *struct {
		Type   *string `json:"type"`
		UserID *string `json:"user_id"`
		Email  *string `json:"email_address"`
	} `json:"actor"`
	Amount     *string      `json:"amount"`
	ListAmount *string      `json:"list_amount"`
	Currency   *string      `json:"currency"`
	StartingAt *string      `json:"starting_at"`
	EndingAt   *string      `json:"ending_at"`
	Product    *string      `json:"product"`
	Requests   *json.Number `json:"requests"`
}

// asciiEmail folds a vendor e-mail with an ASCII-only lower. ok is false for
// an empty value or one carrying any non-ASCII byte (strings.ToLower would
// map the Kelvin sign U+212A onto k, security ledger VCONN-6).
func asciiEmail(s string) (string, bool) {
	s = vendorapi.FoldEmail(s)
	if s == "" || len(s) > vendorapi.MaxIDLen {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return "", false
		}
	}
	return s, true
}

// userCostIdentity resolves a row's identity: the ASCII e-mail when there is
// one, else the user id. Anything else is not a documented actor.
func userCostIdentity(r userCostRow) (string, string, bool) {
	a := r.Actor
	if a == nil || a.Type == nil || *a.Type != "user_actor" {
		return "", "", false
	}
	id := strings.TrimSpace(vendorapi.Str(a.UserID))
	if id == "" || len(id) > vendorapi.MaxIDLen {
		return "", "", false
	}
	if e, ok := asciiEmail(vendorapi.Str(a.Email)); ok {
		return "email", e, true
	}
	return "user_id", id, true
}

func parseUserCost(r vendorapi.Response) (vendorapi.Page, error) {
	var doc reportDoc[userCostRow]
	next, err := envelope(SurfaceUserCost, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{NextCursor: next, SourceRecords: len(*doc.Data)}
	seen := map[string]bool{}
	for i, row := range *doc.Data {
		start, end, err := bucketInterval(SurfaceUserCost, i, row.StartingAt, row.EndingAt)
		if err != nil {
			return vendorapi.Page{}, err
		}
		kind, id, ok := userCostIdentity(row)
		if !ok {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceUserCost, "data[%d].actor is not a documented user actor", i)
		}
		if row.Currency == nil || !strings.EqualFold(*row.Currency, "USD") {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceUserCost, "data[%d] currency is not USD", i)
		}
		if row.Amount == nil || row.ListAmount == nil {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceUserCost, "data[%d] misses amount or list_amount", i)
		}
		cost, ok1 := vendorapi.DecimalMicros(*row.Amount, 2)
		list, ok2 := vendorapi.DecimalMicros(*row.ListAmount, 2)
		if !ok1 || !ok2 {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceUserCost, "data[%d] amount or list_amount is not a decimal in cents", i)
		}
		feature := "product:" + vendorapi.Str(row.Product)
		key := start.Format(time.DateOnly) + "\x00" + kind + "\x00" + id + "\x00" + feature
		if seen[key] {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceUserCost, "data[%d] repeats a user day and product", i)
		}
		seen[key] = true
		fact := func(metric, unit string, micros int64) vendorapi.FactRow {
			return vendorapi.FactRow{
				IntervalStart: start, IntervalEnd: end, SourceTZ: "UTC", CoverageDomain: userCostCoverage,
				IdentityKind: kind, Identity: id, Feature: feature, Metric: metric, Unit: unit, ValueMicros: micros,
			}
		}
		page.Facts = append(page.Facts, fact("cost", "usd", cost), fact("list_cost", "usd", list))
		if row.Requests != nil {
			n, ok := count(row.Requests)
			if !ok {
				return vendorapi.Page{}, vendorapi.Drift(SurfaceUserCost, "data[%d].requests is not a non-negative integer", i)
			}
			page.Facts = append(page.Facts, fact("requests", "count", n))
		}
	}
	return page, nil
}

// userCostKnownPaths are the documented response paths (the corpus field
// ledger of the user cost report).
var userCostKnownPaths = []string{
	"data", "data[]", "data[].actor", "data[].actor.deleted", "data[].actor.email", "data[].actor.email_address",
	"data[].actor.name", "data[].actor.type", "data[].actor.user_id", "data[].amount", "data[].claude_tag_category",
	"data[].claude_tag_user_id", "data[].context_window", "data[].cost_type", "data[].currency", "data[].ending_at",
	"data[].inference_geo", "data[].list_amount", "data[].model", "data[].product", "data[].rbac_group_id",
	"data[].requests", "data[].slack_channel_id", "data[].speed", "data[].starting_at", "data[].token_type",
	"data_refreshed_at", "has_more", "next_page", "organization_id",
}
