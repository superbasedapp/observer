package planlimits

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseAppServerUsage(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		ok   bool
		want []UsageDay
	}{
		{
			name: "live shape", ok: true, raw: `{"summary":{"lifetimeTokens":900,"peakDailyTokens":500,"longestRunningTurnSec":null,"currentStreakDays":2,"longestStreakDays":9},
			"dailyUsageBuckets":[{"startDate":"2026-10-30","tokens":136533390},{"startDate":"2026-10-29","tokens":12}],"threadUsage":null}`,
			want: []UsageDay{{"2026-10-29", 12}, {"2026-10-30", 136533390}},
		},
		{name: "null buckets", raw: `{"summary":null,"dailyUsageBuckets":null,"threadUsage":null}`},
		{name: "absent buckets", raw: `{"summary":{"lifetimeTokens":1}}`},
		{name: "not an object", raw: `[1,2]`},
		{name: "empty body", raw: ``},
		{name: "empty list", raw: `{"dailyUsageBuckets":[]}`, ok: true, want: []UsageDay{}},
		{
			name: "unknown keys ignored", ok: true, raw: `{"dailyUsageBuckets":[{"startDate":"2026-01-02","tokens":5,"credits":"1.2","model":"x"}],"extra":{"a":1}}`,
			want: []UsageDay{{"2026-01-02", 5}},
		},
		{
			name: "malformed dates dropped", ok: true, raw: `{"dailyUsageBuckets":[{"startDate":"2026-13-01","tokens":1},{"startDate":"yesterday","tokens":2},
			{"startDate":"2026-10-30T00:00:00Z","tokens":3},{"startDate":"","tokens":4},{"tokens":5},{"startDate":null,"tokens":6},{"startDate":"1999-12-31","tokens":7},{"startDate":"2026-02-03","tokens":8}]}`,
			want: []UsageDay{{"2026-02-03", 8}},
		},
		{
			name: "bad tokens dropped", ok: true, raw: `{"dailyUsageBuckets":[{"startDate":"2026-01-01","tokens":-1},{"startDate":"2026-01-02","tokens":1.5},
			{"startDate":"2026-01-03","tokens":"9"},{"startDate":"2026-01-04","tokens":null},{"startDate":"2026-01-05"},{"startDate":"2026-01-06","tokens":2000000000000000000},
			{"startDate":"2026-01-07","tokens":0}]}`,
			want: []UsageDay{{"2026-01-07", 0}},
		},
		{
			name: "repeated day keeps last", ok: true, raw: `{"dailyUsageBuckets":[{"startDate":"2026-01-01","tokens":1},{"startDate":"2026-01-01","tokens":3}]}`,
			want: []UsageDay{{"2026-01-01", 3}},
		},
		{name: "bucket list of wrong type", raw: `{"dailyUsageBuckets":{"startDate":"2026-01-01"}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ParseAppServerUsage([]byte(c.raw))
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if !c.ok {
				return
			}
			if !reflect.DeepEqual(got.Days, c.want) {
				t.Errorf("days = %+v, want %+v", got.Days, c.want)
			}
		})
	}
}

func TestParseAppServerUsageCapsDays(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"dailyUsageBuckets":[`)
	start := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	n := MaxUsageDays + 10
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"startDate":"` + start.AddDate(0, 0, i).Format(UsageDayLayout) + `","tokens":1}`)
	}
	b.WriteString(`]}`)
	got, ok := ParseAppServerUsage([]byte(b.String()))
	if !ok || len(got.Days) != MaxUsageDays {
		t.Fatalf("ok=%v days=%d", ok, len(got.Days))
	}
	if got.Days[len(got.Days)-1].Day != start.AddDate(0, 0, n-1).Format(UsageDayLayout) {
		t.Errorf("the newest days must be kept, got last %s", got.Days[len(got.Days)-1].Day)
	}
}

func TestReconcile(t *testing.T) {
	cases := []struct {
		name     string
		vendor   []UsageDay
		captured map[string]int64
		want     []ReconcileDay
		totals   ReconcileTotals
	}{
		{name: "nothing", want: []ReconcileDay{}},
		{
			name:     "all local, a little short",
			vendor:   []UsageDay{{"2026-10-08", 100}},
			captured: map[string]int64{"2026-10-08": 94},
			want:     []ReconcileDay{{Day: "2026-10-08", VendorReported: true, VendorTokens: 100, CapturedTokens: 94, UncapturedTokens: 6, Ratio: F(0.94)}},
			totals:   ReconcileTotals{VendorTokens: 100, CapturedTokens: 94, UncapturedTokens: 6, Ratio: F(0.94)},
		},
		{
			name:   "nothing captured that day",
			vendor: []UsageDay{{"2026-10-30", 500}},
			want:   []ReconcileDay{{Day: "2026-10-30", VendorReported: true, VendorTokens: 500, UncapturedTokens: 500, Ratio: F(0)}},
			totals: ReconcileTotals{VendorTokens: 500, UncapturedTokens: 500, Ratio: F(0)},
		},
		{
			name:     "captured more than reported never goes negative",
			vendor:   []UsageDay{{"2026-10-01", 50}},
			captured: map[string]int64{"2026-10-01": 80},
			want:     []ReconcileDay{{Day: "2026-10-01", VendorReported: true, VendorTokens: 50, CapturedTokens: 80, UncapturedTokens: 0, Ratio: F(1.6)}},
			totals:   ReconcileTotals{VendorTokens: 50, CapturedTokens: 80, UncapturedTokens: 0, Ratio: F(1.6)},
		},
		{
			name:     "captured day with no vendor bucket has no ratio",
			captured: map[string]int64{"2026-10-02": 40},
			want:     []ReconcileDay{{Day: "2026-10-02", CapturedTokens: 40}},
			totals:   ReconcileTotals{CapturedTokens: 40},
		},
		{
			name:     "an over-captured day does not hide a missed one",
			vendor:   []UsageDay{{"2026-10-01", 50}, {"2026-10-02", 100}},
			captured: map[string]int64{"2026-10-01": 80, "2026-10-02": 70},
			want: []ReconcileDay{
				{Day: "2026-10-02", VendorReported: true, VendorTokens: 100, CapturedTokens: 70, UncapturedTokens: 30, Ratio: F(0.7)},
				{Day: "2026-10-01", VendorReported: true, VendorTokens: 50, CapturedTokens: 80, UncapturedTokens: 0, Ratio: F(1.6)},
			},
			totals: ReconcileTotals{VendorTokens: 150, CapturedTokens: 150, UncapturedTokens: 30, Ratio: F(1)},
		},
		{
			name:     "outside the window and empty days are dropped",
			vendor:   []UsageDay{{"2026-09-30", 9}, {"2026-10-03", 0}, {"2026-11-01", 9}, {"2026-10-04", -3}},
			captured: map[string]int64{"2026-09-29": 5, "2026-10-05": 0, "2026-10-06": -2},
			want:     []ReconcileDay{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Reconcile(c.vendor, c.captured, "2026-10-01", "2026-10-31")
			if got.From != "2026-10-01" || got.To != "2026-10-31" {
				t.Errorf("window %s..%s", got.From, got.To)
			}
			if !reflect.DeepEqual(got.Days, c.want) {
				t.Errorf("days\n got %s\nwant %s", js(got.Days), js(c.want))
			}
			if !reflect.DeepEqual(got.Totals, c.totals) {
				t.Errorf("totals\n got %s\nwant %s", js(got.Totals), js(c.totals))
			}
		})
	}
}

func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestUsageWindow(t *testing.T) {
	now := time.Date(2026, 11, 3, 23, 30, 0, 0, time.FixedZone("x", -5*3600)) // 04:30 UTC on the 4th
	cases := []struct {
		n        int
		from, to string
	}{
		{1, "2026-11-04", "2026-11-04"},
		{30, "2026-10-06", "2026-11-04"},
		{0, "2026-11-04", "2026-11-04"},
		{10000, "2025-11-04", "2026-11-04"},
	}
	for _, c := range cases {
		from, to := UsageWindow(now, c.n)
		if from != c.from || to != c.to {
			t.Errorf("n=%d: %s..%s, want %s..%s", c.n, from, to, c.from, c.to)
		}
	}
}

const appServerRL = `{"rateLimits":{"limitId":"codex",
	"primary":{"usedPercent":12,"windowDurationMins":300,"resetsAt":1766948068},
	"secondary":{"usedPercent":43,"windowDurationMins":10080,"resetsAt":1767407914}}}`

// TestAppServerUsageIsFailSoft pins that account/usage/read never changes the
// rate-limit reading: whatever the usage call answers, the snapshot's JSON
// (what is stored and served) is byte-identical to the reading without it.
func TestAppServerUsageIsFailSoft(t *testing.T) {
	base := map[string]string{"initialize": `{}`, "account/read": acctChatGPT, "account/rateLimits/read": appServerRL}
	ref, _, err := runAppServer(t, base)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Usage != nil {
		t.Fatal("method not found must leave Usage nil")
	}
	refJSON, _ := json.Marshal(ref)
	cases := []struct {
		name  string
		usage string
		days  int // -1: Usage must be nil
	}{
		{"valid", `{"summary":{"lifetimeTokens":1},"dailyUsageBuckets":[{"startDate":"2026-10-30","tokens":7}],"threadUsage":null}`, 1},
		{"null buckets", `{"summary":null,"dailyUsageBuckets":null}`, -1},
		{"unknown shape", `{"something":"else"}`, -1},
		{"scalar", `42`, -1},
		{"all buckets malformed", `{"dailyUsageBuckets":[{"startDate":"x","tokens":-1}]}`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := map[string]string{"account/usage/read": c.usage}
			for k, v := range base {
				res[k] = v
			}
			snap, seen, err := runAppServer(t, res)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := json.Marshal(snap)
			if !bytes.Equal(got, refJSON) {
				t.Errorf("snapshot changed by the usage call:\n%s\n%s", got, refJSON)
			}
			switch {
			case c.days < 0 && snap.Usage != nil:
				t.Errorf("usage = %+v, want nil", snap.Usage)
			case c.days >= 0 && (snap.Usage == nil || len(snap.Usage.Days) != c.days):
				t.Errorf("usage = %+v, want %d days", snap.Usage, c.days)
			}
			last := seen[len(seen)-1]
			if last != "account/usage/readnull" {
				t.Errorf("usage call must come last with null params, got %q", last)
			}
		})
	}
}

func TestReadAppServerUsageClosedPipe(t *testing.T) {
	s := newRPCSession(io.Discard, strings.NewReader(""))
	if u := readAppServerUsage(s); u != nil {
		t.Errorf("closed pipe: %+v", u)
	}
	s = newRPCSession(errWriter{}, strings.NewReader(""))
	if u := readAppServerUsage(s); u != nil {
		t.Errorf("write error: %+v", u)
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
