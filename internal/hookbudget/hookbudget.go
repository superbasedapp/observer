package hookbudget

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
)

// ID names one budget row.
type ID string

const (
	// HookCold is a whole `observer hook` launch, process start to exit,
	// in a fresh home with no database yet (the first hook after install).
	HookCold ID = "hook_cold"
	// HookWarm is the same launch with the database and config in place.
	HookWarm ID = "hook_warm"
	// Seam is the hook context seam's own cost per event: the host entry
	// point and its fill with today's (nil) providers.
	Seam ID = "seam"
	// SeamProviders is the seam's fixed tax per wired provider: the same
	// fill with three no-op providers (a goroutine and a deadline per
	// call), what a Phase A or C provider costs before its own work.
	SeamProviders ID = "seam_providers"
	// Sidecar is the posture sidecar read, verification and dirty-marker
	// check (security plan section 4.8, section 6.4 row 2).
	Sidecar ID = "sidecar"
	// Detectors is the native detectors on a proposed write at the default
	// 16 KiB cap (section 4.7 item 3.1, section 6.4 row 3).
	Detectors ID = "detectors"
	// QuickScan is the commit-gate quick scan the hook waits on (section
	// 4.8, section 6.4 commit-gate row); the individual-node budget is the
	// target, the managed floor's default 10 s is noted.
	QuickScan ID = "quick_scan"
	// Feedback is the post-tool feedback request the hook asks the daemon
	// (security plan sections 5.11 (c) and 6.2 step 2, lane sec-h): one
	// round trip over the owner-only endpoint, answered from the store.
	Feedback ID = "feedback"
	// ProjectMatch is the project audience on the hook path: resolving the
	// matched org projects for the event's project root (the daemon's match
	// record, else the mapping) and loading that project's envelope as an
	// org layer (security plan section 6.4, revision 2.4 [JSP-10]).
	ProjectMatch ID = "project_match"
	// Relay is the sandbox capture relay's own channel overhead on top of
	// the host path (security plan section 6.4 relay row; roadmap spike
	// JSP-2; sandbox plan section 5.2).
	Relay ID = "relay"
)

// Kind is a budget's kind (security plan section 6.4 keeps them separate
// on purpose, PR6).
type Kind string

const (
	// KindEndToEnd is a whole hook launch.
	KindEndToEnd Kind = "end_to_end"
	// KindAddedWork is work added inside an ordinary hook.
	KindAddedWork Kind = "added_work"
	// KindCommitGate is the disclosed wait at a commit or push.
	KindCommitGate Kind = "commit_gate"
	// KindRelay is the relay channel's overhead.
	KindRelay Kind = "relay"
)

// Budget is one row of the budget table.
type Budget struct {
	ID   ID
	Kind Kind
	// P99 is the plan's p99 target; zero means "measured, then held to the
	// re-baseline" (no fixed number yet).
	P99 time.Duration
	// Source cites the plan section the target comes from.
	Source string
	// Note says what the row measures and, for a slot, who fills it.
	Note string
}

// Budgets is the one budget table, walked in order by the report.
var Budgets = []Budget{
	{
		ID: HookCold, Kind: KindEndToEnd, Source: "security plan 6.4 (whole ordinary hook)",
		Note: "process start to exit, fresh home, no database yet",
	},
	{
		ID: HookWarm, Kind: KindEndToEnd, Source: "security plan 6.4 (whole ordinary hook)",
		Note: "process start to exit, database and config in place",
	},
	{
		ID: Seam, Kind: KindAddedWork, Source: "roadmap F0-3",
		Note: "hookctx.Host plus Fill with today's nil providers; must stay a negligible share of every added-work budget",
	},
	{
		ID: SeamProviders, Kind: KindAddedWork, Source: "roadmap F0-3",
		Note: "the same fill with three no-op providers wired; the fixed cost a provider adds before its own work",
	},
	{
		ID: Sidecar, Kind: KindAddedWork, P99: 2 * time.Millisecond, Source: "security plan 4.8, 6.4",
		Note: "posture sidecar read, HMAC verification, seen mark and dirty-marker raise (internal/secposture, warm in process, tests/hookbudget); the fresh-process figure on native Windows and WSL is owed (JSP-2: 2 ms once the three opens are one, else 3 ms on Windows)",
	},
	{
		ID: Detectors, Kind: KindAddedWork, P99: 5 * time.Millisecond, Source: "security plan 4.7 item 3.1, 6.4",
		Note: "native detectors on a 16 KiB proposed write; probe owed by security Phase C",
	},
	{
		ID: QuickScan, Kind: KindCommitGate, P99: 2 * time.Second, Source: "security plan 4.8, 6.4 (D-764 Q21)",
		Note: "quick scan the hook waits on, individual node (managed floor default 10 s); probe owed by security Phase C",
	},
	{
		ID: Feedback, Kind: KindAddedWork, P99: 50 * time.Millisecond, Source: "security plan 5.11 (c), 6.2 step 2 (lane sec-h)",
		Note: "post-tool feedback round trip to the daemon over the owner-only endpoint, the daemon's answer bounded at 50 ms (internal/secipc feedback_test.go, warm in process); a miss gives the agent no context, never a block",
	},
	{
		ID: ProjectMatch, Kind: KindAddedWork, P99: 2 * time.Millisecond, Source: "security plan 6.4 (revision 2.4, JSP-10), 7.11",
		Note: "project match and project-section load: guard construction plus one evaluation in a matched project root, minus the same with the plain composed bundle, paired runs warm in process (tests/hookbudget/projectmatch_probe_test.go, lane sec-p); since lane sec-p2a a matched hook builds one engine, not two, and the built-in table is read once per process (cloud VM: p50 0.16 ms, p99 1.02 ms, was p50 0.49 ms, p99 1.28 ms on the same VM); native Windows and the WSL bridge are owed",
	},
	{
		ID: Relay, Kind: KindRelay, Source: "security plan 6.4 relay row; roadmap JSP-2; sandbox plan 5.2",
		Note: "relay channel overhead over the host path at 16 KiB; probe built by sandbox P2 (tests/hookbudget/relay_probe_test.go); JSP-2 budget 2 ms p99 up to 16 KiB",
	},
}

// Lookup returns the budget row for id.
func Lookup(id ID) (Budget, bool) {
	for _, b := range Budgets {
		if b.ID == id {
			return b, true
		}
	}
	return Budget{}, false
}

// Stats summarizes a sample set (nearest-rank percentiles).
type Stats struct {
	N             int
	Min, P50, P95 time.Duration
	P99, Max      time.Duration
}

// Summarize computes Stats over samples (which it does not modify).
func Summarize(samples []time.Duration) Stats {
	if len(samples) == 0 {
		return Stats{}
	}
	s := slices.Clone(samples)
	slices.Sort(s)
	rank := func(p float64) time.Duration {
		i := int(float64(len(s))*p+0.999999) - 1
		return s[min(max(i, 0), len(s)-1)]
	}
	return Stats{N: len(s), Min: s[0], P50: rank(0.50), P95: rank(0.95), P99: rank(0.99), Max: s[len(s)-1]}
}

// Verdict is a row's outcome.
type Verdict string

const (
	// VerdictNotBuilt: no probe exists for the row yet.
	VerdictNotBuilt Verdict = "not_built"
	// VerdictMeasured: measured; the row has no fixed target.
	VerdictMeasured Verdict = "measured"
	// VerdictWithin: the p99 is within the target.
	VerdictWithin Verdict = "within"
	// VerdictOver: the p99 is over the target (reported, never a failure
	// by itself; see docs/hook-budget-harness.md).
	VerdictOver Verdict = "over"
)

// verdictRules is the verdict table, walked top to bottom.
var verdictRules = []struct {
	when func(b Budget, s Stats) bool
	v    Verdict
}{
	{func(_ Budget, s Stats) bool { return s.N == 0 }, VerdictNotBuilt},
	{func(b Budget, _ Stats) bool { return b.P99 == 0 }, VerdictMeasured},
	{func(b Budget, s Stats) bool { return s.P99 <= b.P99 }, VerdictWithin},
	{func(Budget, Stats) bool { return true }, VerdictOver},
}

// Judge returns the verdict for a row's stats.
func Judge(b Budget, s Stats) Verdict {
	for _, r := range verdictRules {
		if r.when(b, s) {
			return r.v
		}
	}
	return VerdictOver
}

// Row is one report line.
type Row struct {
	Budget  Budget
	Stats   Stats
	Verdict Verdict
}

// Report is one harness run: where it ran, the clock it was timed with and
// every budget row.
type Report struct {
	Platform string
	Note     string
	Clock    ClockInfo
	Rows     []Row
}

// NewReport builds a report over every budget row from the samples given
// per row; a row without samples is "not built".
func NewReport(platform, note string, samples map[ID][]time.Duration) Report {
	r := Report{Platform: platform, Note: note, Clock: CurrentClock()}
	for _, b := range Budgets {
		s := Summarize(samples[b.ID])
		r.Rows = append(r.Rows, Row{Budget: b, Stats: s, Verdict: Judge(b, s)})
	}
	return r
}

// Text renders the report as an aligned table.
func (r Report) Text(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "hook budget report: %s\n", r.Platform); err != nil {
		return fmt.Errorf("hookbudget.Report.Text: %w", err)
	}
	if r.Note != "" {
		if _, err := fmt.Fprintf(w, "%s\n", r.Note); err != nil {
			return fmt.Errorf("hookbudget.Report.Text: %w", err)
		}
	}
	if r.Clock.Source != "" {
		if _, err := fmt.Fprintf(w, "clock: %s, %d Hz, resolution %s (Go monotonic step here %s)\n",
			r.Clock.Source, r.Clock.FrequencyHz, r.Clock.Resolution, r.Clock.GoMonotonicStep); err != nil {
			return fmt.Errorf("hookbudget.Report.Text: %w", err)
		}
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "budget\tkind\tn\tp50\tp95\tp99\tmax\ttarget p99\tverdict\tsource")
	for _, row := range r.Rows {
		target := "measured"
		if row.Budget.P99 > 0 {
			target = row.Budget.P99.String()
		}
		cells := []string{string(row.Budget.ID), string(row.Budget.Kind), "-", "-", "-", "-", "-", target, string(row.Verdict), row.Budget.Source}
		if row.Stats.N > 0 {
			cells[2] = fmt.Sprint(row.Stats.N)
			cells[3], cells[4], cells[5], cells[6] = round(row.Stats.P50), round(row.Stats.P95), round(row.Stats.P99), round(row.Stats.Max)
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("hookbudget.Report.Text: %w", err)
	}
	return nil
}

// round keeps a duration readable: tens of nanoseconds below a
// millisecond (the seam rows), otherwise tenths of a millisecond.
func round(d time.Duration) string {
	if d < time.Millisecond {
		return d.Round(10 * time.Nanosecond).String()
	}
	return d.Round(100 * time.Microsecond).String()
}

// jsonRow is the machine-readable form of one row (nanoseconds, and the
// same figures in ticks of the report's clock).
type jsonRow struct {
	ID       ID      `json:"id"`
	Kind     Kind    `json:"kind"`
	N        int     `json:"n"`
	P50      int64   `json:"p50_ns"`
	P95      int64   `json:"p95_ns"`
	P99      int64   `json:"p99_ns"`
	Max      int64   `json:"max_ns"`
	P50Ticks int64   `json:"p50_ticks"`
	P99Ticks int64   `json:"p99_ticks"`
	MaxTicks int64   `json:"max_ticks"`
	Target   int64   `json:"target_p99_ns"`
	Verdict  Verdict `json:"verdict"`
	Source   string  `json:"source"`
}

// jsonClock is the machine-readable clock description.
type jsonClock struct {
	Source            string `json:"source"`
	FrequencyHz       int64  `json:"frequency_hz"`
	ResolutionNs      int64  `json:"resolution_ns"`
	GoMonotonicStepNs int64  `json:"go_monotonic_step_ns"`
}

// JSON writes the report as JSON, for the spike that compares platforms.
func (r Report) JSON(w io.Writer) error {
	out := struct {
		Platform string    `json:"platform"`
		Note     string    `json:"note,omitempty"`
		Clock    jsonClock `json:"clock"`
		Rows     []jsonRow `json:"rows"`
	}{Platform: r.Platform, Note: r.Note, Clock: jsonClock{
		Source: r.Clock.Source, FrequencyHz: r.Clock.FrequencyHz,
		ResolutionNs: int64(r.Clock.Resolution), GoMonotonicStepNs: int64(r.Clock.GoMonotonicStep),
	}}
	ticks := func(d time.Duration) int64 { return DurationToTicks(d, r.Clock.FrequencyHz) }
	for _, row := range r.Rows {
		out.Rows = append(out.Rows, jsonRow{
			ID: row.Budget.ID, Kind: row.Budget.Kind, N: row.Stats.N,
			P50: int64(row.Stats.P50), P95: int64(row.Stats.P95), P99: int64(row.Stats.P99), Max: int64(row.Stats.Max),
			P50Ticks: ticks(row.Stats.P50), P99Ticks: ticks(row.Stats.P99), MaxTicks: ticks(row.Stats.Max),
			Target: int64(row.Budget.P99), Verdict: row.Verdict, Source: row.Budget.Source,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("hookbudget.Report.JSON: %w", err)
	}
	return nil
}
