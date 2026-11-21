package planlimits

import (
	"encoding/json"
	"sort"
	"time"
)

// usage.go is the daily usage reconciliation of a plan that reports its
// account-wide token activity per day (docs/plans-and-limits.md "Daily usage
// reconciliation"). Today that is one source: the Codex app-server method
// account/usage/read, read in the same session as the rate limits. The
// vendor's daily total covers every surface and device on the login (Codex
// cloud chats included); Observer's captured tokens cover only the sessions
// it ran on, on this node, for any login. The reconciliation sets the two
// side by side per UTC day and names the difference "not captured here",
// never "cloud usage": the daily total cannot say where the rest ran.
//
// Pure: no SQL, no I/O. The store seam persists UsageDay rows and reads the
// captured side; the service composes the two through Reconcile.

// UsageDayLayout is the day format on both sides: a UTC calendar date.
const UsageDayLayout = "2006-01-02"

// MaxUsageDays caps how many daily buckets one reading keeps (the newest).
// The live account returned 160; this leaves years of headroom while bounding
// a malformed or hostile response.
const MaxUsageDays = 1100

// maxUsageTokens bounds one day's token count. A larger value is not a real
// day of use and is dropped rather than stored.
const maxUsageTokens = int64(1) << 50

// UsageDay is one day's account-wide token total as the vendor reports it.
type UsageDay struct {
	Day    string `json:"day"` // UsageDayLayout, UTC
	Tokens int64  `json:"tokens"`
}

// UsageReport is the daily usage one reading carried. Days is sorted by day
// ascending, one entry per day.
type UsageReport struct {
	Days []UsageDay `json:"days"`
}

// appServerUsage is the documented account/usage/read result. Only the daily
// buckets are read; summary and threadUsage are tolerated and ignored.
type appServerUsage struct {
	DailyUsageBuckets []struct {
		StartDate *string          `json:"startDate"`
		Tokens    *json.RawMessage `json:"tokens"`
	} `json:"dailyUsageBuckets"`
}

// ParseAppServerUsage maps an account/usage/read result onto a UsageReport.
// It is tolerant by design, because the caller treats any failure as "no
// usage this time" and never fails the rate-limit reading over it: null or
// absent buckets give ok=false, a bucket with a malformed date, a missing,
// negative, fractional or absurd token count is dropped, unknown keys are
// ignored, and a repeated day keeps its last value. ok is true when the
// result had the documented shape (an empty bucket list included).
func ParseAppServerUsage(raw []byte) (UsageReport, bool) {
	var r appServerUsage
	if len(raw) == 0 || json.Unmarshal(raw, &r) != nil || r.DailyUsageBuckets == nil {
		return UsageReport{}, false
	}
	byDay := map[string]int64{}
	for _, b := range r.DailyUsageBuckets {
		if b.StartDate == nil || b.Tokens == nil {
			continue
		}
		day, ok := normalizeUsageDay(*b.StartDate)
		if !ok {
			continue
		}
		var n int64
		if json.Unmarshal(*b.Tokens, &n) != nil || n < 0 || n > maxUsageTokens {
			continue
		}
		byDay[day] = n
	}
	out := UsageReport{Days: make([]UsageDay, 0, len(byDay))}
	for d, n := range byDay {
		out.Days = append(out.Days, UsageDay{Day: d, Tokens: n})
	}
	sort.Slice(out.Days, func(i, j int) bool { return out.Days[i].Day < out.Days[j].Day })
	if len(out.Days) > MaxUsageDays {
		out.Days = out.Days[len(out.Days)-MaxUsageDays:]
	}
	return out, true
}

// normalizeUsageDay accepts a YYYY-MM-DD date (the documented shape) and
// returns it canonical; anything else is refused.
func normalizeUsageDay(s string) (string, bool) {
	t, err := time.Parse(UsageDayLayout, s)
	if err != nil || t.Year() < 2000 || t.Year() > 9999 {
		return "", false
	}
	return t.Format(UsageDayLayout), true
}

// ReconcileDay is one day of the reconciliation. VendorTokens is the
// vendor's account-wide total (0 when the vendor reported no bucket for the
// day); CapturedTokens is what this node captured for the provider's tools;
// UncapturedTokens is the vendor total minus the captured total, never below
// zero. Ratio is captured / vendor, present only when the vendor reported a
// positive total.
type ReconcileDay struct {
	Day              string   `json:"day"`
	VendorReported   bool     `json:"vendor_reported"`
	VendorTokens     int64    `json:"vendor_tokens"`
	CapturedTokens   int64    `json:"captured_tokens"`
	UncapturedTokens int64    `json:"uncaptured_tokens"`
	Ratio            *float64 `json:"ratio,omitempty"`
}

// ReconcileTotals sums a window. UncapturedTokens is the sum of the per-day
// gaps, so a day Observer over-counted (another login, a day boundary) never
// hides a day it missed.
type ReconcileTotals struct {
	VendorTokens     int64    `json:"vendor_tokens"`
	CapturedTokens   int64    `json:"captured_tokens"`
	UncapturedTokens int64    `json:"uncaptured_tokens"`
	Ratio            *float64 `json:"ratio,omitempty"`
}

// Reconciliation is the per-day comparison over a window of UTC days,
// newest day first.
type Reconciliation struct {
	From   string          `json:"from"`
	To     string          `json:"to"`
	Days   []ReconcileDay  `json:"days"`
	Totals ReconcileTotals `json:"totals"`
}

// Reconcile compares the vendor's daily totals with the node's captured
// tokens over the inclusive UTC day window [from, to]. A day appears when
// either side has a positive figure for it; days outside the window are
// ignored. Both inputs are by UTC day; the vendor does not document its own
// day boundary, which the surfaces say.
func Reconcile(vendor []UsageDay, captured map[string]int64, from, to string) Reconciliation {
	out := Reconciliation{From: from, To: to, Days: []ReconcileDay{}}
	in := func(d string) bool { return d >= from && d <= to }
	days := map[string]*ReconcileDay{}
	get := func(d string) *ReconcileDay {
		if r, ok := days[d]; ok {
			return r
		}
		r := &ReconcileDay{Day: d}
		days[d] = r
		return r
	}
	for _, v := range vendor {
		if !in(v.Day) || v.Tokens < 0 {
			continue
		}
		r := get(v.Day)
		r.VendorReported = true
		r.VendorTokens = v.Tokens
	}
	for d, n := range captured {
		if !in(d) || n <= 0 {
			continue
		}
		get(d).CapturedTokens = n
	}
	for _, r := range days {
		if r.VendorTokens == 0 && r.CapturedTokens == 0 {
			continue
		}
		r.UncapturedTokens = max(r.VendorTokens-r.CapturedTokens, 0)
		r.Ratio = usageRatio(r.CapturedTokens, r.VendorTokens)
		out.Days = append(out.Days, *r)
		out.Totals.VendorTokens += r.VendorTokens
		out.Totals.CapturedTokens += r.CapturedTokens
		out.Totals.UncapturedTokens += r.UncapturedTokens
	}
	sort.Slice(out.Days, func(i, j int) bool { return out.Days[i].Day > out.Days[j].Day })
	out.Totals.Ratio = usageRatio(out.Totals.CapturedTokens, out.Totals.VendorTokens)
	return out
}

func usageRatio(captured, vendor int64) *float64 {
	if vendor <= 0 {
		return nil
	}
	return F(float64(captured) / float64(vendor))
}

// UsageWindow returns the inclusive UTC day window of the last n days ending
// on now's UTC date. n is clamped to [1, 366].
func UsageWindow(now time.Time, n int) (from, to string) {
	n = min(max(n, 1), 366)
	end := now.UTC()
	return end.AddDate(0, 0, -(n - 1)).Format(UsageDayLayout), end.Format(UsageDayLayout)
}
