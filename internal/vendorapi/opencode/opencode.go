package opencode

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

// Surfaces of the opencode vendor group (lane ENTAPI-L16C, T-710).
const (
	SurfaceBudgets      vs.SurfaceID = "opencode.console.budgets_api"
	SurfaceHyperCredits vs.SurfaceID = "charm.hyper.credits_api" //nolint:gosec // G101: a surface id, not a credential

	BudgetsContract      = "opencode.console.budgets_api/v1 console-api budgets (2026-10-08)"
	HyperCreditsContract = "charm.hyper.credits_api/v1 hyper-api credits (2026-10-08)" //nolint:gosec // G101: a contract label, not a credential

	// Tool is the registry tool the OpenCode Console budgets apply to.
	Tool = "opencode"
	// BudgetSnapshotClass is one member's effective monthly budget and the
	// month's spend.
	BudgetSnapshotClass = "opencode.member_budget"
	// HyperBalanceClass is the team's Hypercredit balance.
	HyperBalanceClass = "charm.hyper_balance"
	// HyperSubject is the snapshot subject of the team balance (the key
	// authenticates one team; the response names none).
	HyperSubject = "team"
)

var bearerAuth = vendorapi.AuthContract{Kind: vs.AuthBearer, Scheme: vendorapi.SchemeBearer, Header: "Authorization"}

var (
	// microRE is a decimal string of microcents (non-negative, no sign, no
	// fraction, at most 19 digits so it fits an int64).
	microRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})$`)
	// userRE bounds an OpenCode user id (user_...).
	userRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
)

// budgetSources is the documented source vocabulary (null means unlimited).
var budgetSources = map[string]bool{"custom": true, "default": true}

// Budgets returns the driver of opencode.console.budgets_api.
//
// Contract (OpenCode Console Budgets API, "List member budgets"): GET
// /console/api/v1/budgets/members on https://opencode.ai with a service
// account key (oc_sk_, All permission, bound to one workspace) as Bearer;
// response: a JSON array of every current member ordered by email, each
// {user_id, email, limit_micro_cents (decimal string or null), spent_micro_cents
// (decimal string), exceeded, resets_at, source (custom, default or null),
// updated_at (null without a custom override)}. 100,000,000 microcents per
// US dollar; spend and reset cover the current UTC calendar month. Not paged.
// Lands one snapshot per member (class opencode.member_budget, subject the
// e-mail): the limit state (custom, default or unlimited), the limit and the
// month's spend in microcents, exceeded, the reset time and the override's
// update time. Read only: the PUT and DELETE overrides are not built.
func Budgets() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceBudgets,
		Build:           buildBudgets,
		ParseResponse:   parseBudgets,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassLimits, vs.ClassCost},
		ClosedDTO:       true,
		ContractVersion: BudgetsContract,
		Tool:            Tool,
		KnownPaths: []string{
			"[]", "[].email", "[].exceeded", "[].limit_micro_cents", "[].resets_at", "[].source",
			"[].spent_micro_cents", "[].updated_at", "[].user_id",
		},
	}
}

// HyperCredits returns the driver of charm.hyper.credits_api.
//
// Contract (Charm Hyper API, "Credits"): GET /v1/credits on
// https://hyper.charm.land with a Hyper key (sk-hyper-) as Bearer; response
// {balance}: the authenticated team's current Hypercredit balance (a unit of
// account, never money). Lands one snapshot (class charm.hyper_balance,
// subject team). The balance is the team's, across every agent routed through
// Hyper, so it carries no registry tool.
func HyperCredits() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceHyperCredits,
		Build:           buildHyper,
		ParseResponse:   parseHyper,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassCost},
		ClosedDTO:       true,
		ContractVersion: HyperCreditsContract,
		KnownPaths:      []string{"balance"},
	}
}

func buildBudgets(_ vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the surface is not paged", SurfaceBudgets)
	}
	return vendorapi.Request{Method: "GET", Path: "/console/api/v1/budgets/members"}, nil
}

func buildHyper(_ vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the surface is not paged", SurfaceHyperCredits)
	}
	return vendorapi.Request{Method: "GET", Path: "/v1/credits"}, nil
}

func driftOf(s vs.SurfaceID) func(string, ...any) error {
	return func(format string, a ...any) error {
		return vendorapi.Drift(s, format, a...)
	}
}

func isoTime(s string) (string, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return "", false
	}
	return t.UTC().Format(time.RFC3339), true
}

// jsonNull reports whether a raw member is absent or null.
func jsonNull(b json.RawMessage) bool { return len(b) == 0 || string(b) == "null" }

type budgetRow struct {
	UserID    *string         `json:"user_id"`
	Email     *string         `json:"email"`
	Limit     json.RawMessage `json:"limit_micro_cents"`
	Spent     *string         `json:"spent_micro_cents"`
	Exceeded  *bool           `json:"exceeded"`
	ResetsAt  *string         `json:"resets_at"`
	Source    json.RawMessage `json:"source"`
	UpdatedAt json.RawMessage `json:"updated_at"`
}

// nullableString decodes a member that is a string or null; ok false is a
// member of another type.
func nullableString(b json.RawMessage) (string, bool, bool) {
	if jsonNull(b) {
		return "", false, true
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return "", false, false
	}
	return s, true, true
}

func parseBudgets(r vendorapi.Response) (vendorapi.Page, error) {
	drift := driftOf(SurfaceBudgets)
	if r.Status != 200 {
		return vendorapi.Page{}, drift("status %d is not the documented 200", r.Status)
	}
	var rows []budgetRow
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	if err := dec.Decode(&rows); err != nil || rows == nil {
		return vendorapi.Page{}, drift("body is not the documented array of member budgets")
	}
	page := vendorapi.Page{SourceRecords: len(rows)}
	seen := map[string]bool{}
	for i, m := range rows {
		if m.UserID == nil || !userRE.MatchString(*m.UserID) || m.Email == nil || strings.TrimSpace(*m.Email) == "" ||
			m.Spent == nil || m.Exceeded == nil || m.ResetsAt == nil {
			return vendorapi.Page{}, drift("[%d] misses user_id, email, spent_micro_cents, exceeded or resets_at", i)
		}
		if seen[*m.UserID] {
			return vendorapi.Page{}, drift("[%d] repeats a member", i)
		}
		seen[*m.UserID] = true
		if !microRE.MatchString(*m.Spent) {
			return vendorapi.Page{}, drift("[%d].spent_micro_cents is not a decimal string of microcents", i)
		}
		resets, ok := isoTime(*m.ResetsAt)
		if !ok {
			return vendorapi.Page{}, drift("[%d].resets_at is not ISO 8601", i)
		}
		limit, hasLimit, ok1 := nullableString(m.Limit)
		source, hasSource, ok2 := nullableString(m.Source)
		updated, hasUpdated, ok3 := nullableString(m.UpdatedAt)
		if !ok1 || !ok2 || !ok3 {
			return vendorapi.Page{}, drift("[%d] has a nullable member of the wrong type", i)
		}
		body := map[string]string{
			"user_id": *m.UserID, "spent_micro_cents": *m.Spent, "exceeded": strconv.FormatBool(*m.Exceeded),
			"resets_at": resets,
		}
		// A null limit and a null source mean unlimited (documented); one
		// without the other is undocumented.
		switch {
		case !hasLimit && !hasSource:
			body["limit_state"] = "unlimited"
		case hasLimit && hasSource && budgetSources[source]:
			if !microRE.MatchString(limit) {
				return vendorapi.Page{}, drift("[%d].limit_micro_cents is not a decimal string of microcents", i)
			}
			body["limit_state"] = source
			body["limit_micro_cents"] = limit
		default:
			return vendorapi.Page{}, drift("[%d]: limit and source disagree or the source is undocumented", i)
		}
		if hasUpdated {
			t, ok := isoTime(updated)
			if !ok {
				return vendorapi.Page{}, drift("[%d].updated_at is not ISO 8601", i)
			}
			body["updated_at"] = t
		}
		page.Snapshots = append(page.Snapshots, vendorapi.VendorSnapshot{
			Class: BudgetSnapshotClass, Subject: vendorapi.FoldEmail(*m.Email), Body: body,
		})
	}
	return page, nil
}

func parseHyper(r vendorapi.Response) (vendorapi.Page, error) {
	drift := driftOf(SurfaceHyperCredits)
	if r.Status != 200 {
		return vendorapi.Page{}, drift("status %d is not the documented 200", r.Status)
	}
	var doc struct {
		Balance json.RawMessage `json:"balance"`
	}
	if err := json.Unmarshal(r.Body, &doc); err != nil || jsonNull(doc.Balance) {
		return vendorapi.Page{}, drift("required field balance is missing")
	}
	// A bare JSON number only: a quoted balance is a type change.
	if b := doc.Balance[0]; b != '-' && (b < '0' || b > '9') {
		return vendorapi.Page{}, drift("balance is not a JSON number")
	}
	v, ok := vendorapi.DecimalMicros(string(doc.Balance), 0)
	if !ok {
		return vendorapi.Page{}, drift("balance is not a plain decimal number")
	}
	// A negative balance (a team over its credits) is kept as reported.
	neg := v < 0
	if neg {
		v = -v
	}
	whole, frac := v/1_000_000, v%1_000_000
	s := strconv.FormatInt(whole, 10)
	if frac != 0 {
		s = strings.TrimRight(fmt.Sprintf("%d.%06d", whole, frac), "0")
	}
	if neg {
		s = "-" + s
	}
	return vendorapi.Page{SourceRecords: 1, Snapshots: []vendorapi.VendorSnapshot{{
		Class: HyperBalanceClass, Subject: HyperSubject, Body: map[string]string{"balance": s, "unit": "hypercredits"},
	}}}, nil
}
