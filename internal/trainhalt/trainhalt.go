package trainhalt

import (
	"fmt"
	"sort"
	"strings"
)

// Phase names the window being judged. Each has a minimum length: a window
// judged before it has run that long is inconclusive (it cannot promote).
type Phase string

// The phases of plan 06 18.2.6 (canary 45 minutes, post-promotion 30) and
// the nightly staging soak (plan 06 18.2.3 step 7, two hours).
const (
	PhaseCanary   Phase = "canary"
	PhasePromoted Phase = "promoted"
	PhaseSoak     Phase = "soak"
)

// PhaseMinSeconds is how long each phase must run before a final judgement.
var PhaseMinSeconds = map[Phase]float64{
	PhaseCanary:   45 * 60,
	PhasePromoted: 30 * 60,
	PhaseSoak:     120 * 60,
}

// Thresholds of the table (plan 06 18.2.6). Changing one is a reviewed edit
// of this file and its test row.
const (
	// TelemetryStaleSeconds: health telemetry missing this long is a halt.
	TelemetryStaleSeconds = 5 * 60
	// MinPushSuccess is the lowest canary push success ratio over 15 minutes.
	MinPushSuccess = 0.99
	// MinPushes is the push volume below which push success is inconclusive.
	MinPushes = 100
	// Max5xxBaselineMultiple: the API 5xx rate may not exceed this multiple
	// of the 7-day baseline over 10 minutes.
	Max5xxBaselineMultiple = 2.0
	// Min5xxBaselineRate is the floor the baseline is raised to before the
	// multiple applies, so a zero baseline does not halt on a single 5xx in
	// 500 requests (a lane choice, ledger TRAINHALT-2).
	Min5xxBaselineRate = 0.001
	// MinAPIRequests is the request volume below which the 5xx rule is
	// inconclusive.
	MinAPIRequests = 500
	// MaxApplyBacklogSeconds: an ingest apply backlog above this for the
	// whole of the last 10 minutes (its minimum over the range) is a halt.
	MaxApplyBacklogSeconds = 60
)

// Window is one judging window's signals, measured on candidate-served
// traffic only (roll.sh's queries filter on the canary host), so N-1
// traffic cannot make up the volume. A nil pointer means the query
// returned nothing: that signal is inconclusive.
type Window struct {
	Phase Phase `json:"phase"`
	// ElapsedSeconds is how long the phase has run when judged.
	ElapsedSeconds float64 `json:"elapsed_seconds"`
	// TelemetryAgeSeconds is the age of the newest health sample (the
	// readiness series of the candidate).
	TelemetryAgeSeconds *float64 `json:"telemetry_age_seconds"`
	// IsolationProbeFailures counts failed canary isolation probes in the
	// window.
	IsolationProbeFailures *float64 `json:"isolation_probe_failures"`
	// MigrationErrors counts errors of the migrate-only job for this roll.
	MigrationErrors *float64 `json:"migration_errors"`
	// PushesTotal and PushesOK are the canary's pushes over 15 minutes.
	PushesTotal *float64 `json:"pushes_total"`
	PushesOK    *float64 `json:"pushes_ok"`
	// APIRequests and API5xx are the candidate's API requests over 10
	// minutes; API5xxBaselineRate is the 7-day 5xx ratio of the fleet.
	APIRequests        *float64 `json:"api_requests"`
	API5xx             *float64 `json:"api_5xx"`
	API5xxBaselineRate *float64 `json:"api_5xx_baseline_rate"`
	// ApplyBacklogMinSeconds is the minimum of the ingest apply backlog age
	// over the last 10 minutes: above the limit means above it throughout.
	ApplyBacklogMinSeconds *float64 `json:"apply_backlog_min_seconds"`
}

// Result is one row's outcome.
type Result string

// The outcomes, from best to worst.
const (
	ResultOK           Result = "ok"
	ResultInconclusive Result = "inconclusive"
	ResultHalt         Result = "halt"
)

// Action is what the train does on a verdict.
type Action string

// The actions roll.sh carries out.
const (
	// ActionRollback routes the canary hosts back to N-1 and redeploys
	// N-1 where the candidate runs.
	ActionRollback Action = "rollback"
	// ActionPage pages the operator.
	ActionPage Action = "page"
	// ActionFreeze freezes the train until the operator clears it.
	ActionFreeze Action = "freeze"
	// ActionStopNow ends the window at once, without waiting for its end
	// (the isolation probe).
	ActionStopNow Action = "stop_now"
)

// Rule is one row of the halt table.
type Rule struct {
	ID     string
	Signal string
	// Halt is the plan's "halt when" text; MinVolume the volume floor.
	Halt, MinVolume string
	// OnHalt are the actions of a halt of this row (in addition to the
	// common rollback, page and freeze).
	OnHalt []Action
	eval   func(w Window) (Result, string)
}

// Outcome is one row evaluated on a window.
type Outcome struct {
	Rule   string `json:"rule"`
	Signal string `json:"signal"`
	Result Result `json:"result"`
	Reason string `json:"reason"`
}

// Verdict is the train's decision for a window.
type Verdict string

// The verdicts. Continue is only given to an interim judgement: nothing has
// halted yet, and the window is not over.
const (
	VerdictPromote      Verdict = "promote"
	VerdictHalt         Verdict = "halt"
	VerdictInconclusive Verdict = "inconclusive"
	VerdictContinue     Verdict = "continue"
)

// Judgement is [Judge]'s answer.
type Judgement struct {
	Verdict  Verdict   `json:"verdict"`
	Phase    Phase     `json:"phase"`
	Interim  bool      `json:"interim"`
	Actions  []Action  `json:"actions"`
	Outcomes []Outcome `json:"outcomes"`
}

func missing(name string) (Result, string) {
	return ResultInconclusive, name + " missing (the query returned nothing)"
}

// Rules is the halt table, in the order of plan 06 18.2.6. Every row is
// evaluated on every window.
var Rules = []Rule{
	{
		ID: "isolation_probe", Signal: "canary isolation probe", Halt: "any failure", MinVolume: "none",
		OnHalt: []Action{ActionStopNow},
		eval: func(w Window) (Result, string) {
			if w.IsolationProbeFailures == nil {
				return missing("isolation_probe_failures")
			}
			if *w.IsolationProbeFailures > 0 {
				return ResultHalt, fmt.Sprintf("%g isolation probe failure(s): halt, roll back, page and freeze immediately", *w.IsolationProbeFailures)
			}
			return ResultOK, "no isolation probe failure"
		},
	},
	{
		ID: "telemetry_missing", Signal: "health telemetry", Halt: "missing for 5 minutes", MinVolume: "none",
		eval: func(w Window) (Result, string) {
			if w.TelemetryAgeSeconds == nil {
				return ResultHalt, "no health telemetry at all: treated as a halt"
			}
			if *w.TelemetryAgeSeconds >= TelemetryStaleSeconds {
				return ResultHalt, fmt.Sprintf("health telemetry %.0fs old (limit %ds): treated as a halt", *w.TelemetryAgeSeconds, TelemetryStaleSeconds)
			}
			return ResultOK, fmt.Sprintf("health telemetry %.0fs old", *w.TelemetryAgeSeconds)
		},
	},
	{
		ID: "push_success", Signal: "canary push success", Halt: "below 99% over 15 minutes", MinVolume: "100 pushes",
		eval: func(w Window) (Result, string) {
			if w.PushesTotal == nil || w.PushesOK == nil {
				return missing("pushes_total/pushes_ok")
			}
			n, ok := *w.PushesTotal, *w.PushesOK
			if ok > n || ok < 0 {
				return ResultInconclusive, fmt.Sprintf("pushes_ok %g is outside 0..pushes_total %g", ok, n)
			}
			if n < MinPushes {
				return ResultInconclusive, fmt.Sprintf("%g pushes, below the minimum volume of %d", n, MinPushes)
			}
			if r := ok / n; r < MinPushSuccess {
				return ResultHalt, fmt.Sprintf("push success %.2f%% over %g pushes, below %.0f%%", r*100, n, MinPushSuccess*100)
			}
			return ResultOK, fmt.Sprintf("push success %.2f%% over %g pushes", ok/n*100, n)
		},
	},
	{
		ID: "api_5xx", Signal: "API 5xx rate", Halt: "more than twice the 7-day baseline over 10 minutes", MinVolume: "500 requests",
		eval: func(w Window) (Result, string) {
			if w.APIRequests == nil || w.API5xx == nil || w.API5xxBaselineRate == nil {
				return missing("api_requests/api_5xx/api_5xx_baseline_rate")
			}
			n, e, base := *w.APIRequests, *w.API5xx, *w.API5xxBaselineRate
			if e > n || e < 0 || base < 0 {
				return ResultInconclusive, fmt.Sprintf("api_5xx %g / api_requests %g / baseline %g are inconsistent", e, n, base)
			}
			if n < MinAPIRequests {
				return ResultInconclusive, fmt.Sprintf("%g API requests, below the minimum volume of %d", n, MinAPIRequests)
			}
			limit := Max5xxBaselineMultiple * maxf(base, Min5xxBaselineRate)
			if r := e / n; r > limit {
				return ResultHalt, fmt.Sprintf("5xx rate %.3f%% over %g requests, above %.3f%% (twice the baseline %.3f%%, floored at %.1f%%)", r*100, n, limit*100, base*100, Min5xxBaselineRate*100)
			}
			return ResultOK, fmt.Sprintf("5xx rate %.3f%% over %g requests (limit %.3f%%)", e/n*100, n, limit*100)
		},
	},
	{
		ID: "apply_backlog", Signal: "ingest apply backlog", Halt: "above 60 s for 10 minutes", MinVolume: "none",
		eval: func(w Window) (Result, string) {
			if w.ApplyBacklogMinSeconds == nil {
				return missing("apply_backlog_min_seconds")
			}
			if *w.ApplyBacklogMinSeconds > MaxApplyBacklogSeconds {
				return ResultHalt, fmt.Sprintf("apply backlog above %ds for the last 10 minutes (minimum %.0fs)", MaxApplyBacklogSeconds, *w.ApplyBacklogMinSeconds)
			}
			return ResultOK, fmt.Sprintf("apply backlog minimum %.0fs over 10 minutes", *w.ApplyBacklogMinSeconds)
		},
	},
	{
		ID: "migration_job", Signal: "migration job", Halt: "any error", MinVolume: "none",
		eval: func(w Window) (Result, string) {
			if w.MigrationErrors == nil {
				return missing("migration_errors")
			}
			if *w.MigrationErrors > 0 {
				return ResultHalt, fmt.Sprintf("%g migration job error(s)", *w.MigrationErrors)
			}
			return ResultOK, "no migration job error"
		},
	},
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// windowRow is the extra row every final judgement carries: a phase that
// has not run its minimum length cannot promote.
func windowRow(w Window) Outcome {
	o := Outcome{Rule: "window_length", Signal: "judging window"}
	minS, ok := PhaseMinSeconds[w.Phase]
	switch {
	case !ok:
		o.Result, o.Reason = ResultInconclusive, fmt.Sprintf("unknown phase %q", w.Phase)
	case w.ElapsedSeconds < minS:
		o.Result, o.Reason = ResultInconclusive, fmt.Sprintf("the %s window ran %.0fs of its %.0fs", w.Phase, w.ElapsedSeconds, minS)
	default:
		o.Result, o.Reason = ResultOK, fmt.Sprintf("the %s window ran %.0fs (minimum %.0fs)", w.Phase, w.ElapsedSeconds, minS)
	}
	return o
}

// Judge evaluates every row on w. A final judgement (interim false) is
// promote only when every row and the window length are ok; any halt row
// halts; anything else is inconclusive. An interim judgement (taken while
// the window still runs) is halt on any halt row and continue otherwise:
// an incomplete volume is not yet a verdict.
func Judge(w Window, interim bool) Judgement {
	j := Judgement{Phase: w.Phase, Interim: interim}
	worst := ResultOK
	acts := map[Action]bool{}
	for _, r := range Rules {
		res, why := r.eval(w)
		j.Outcomes = append(j.Outcomes, Outcome{Rule: r.ID, Signal: r.Signal, Result: res, Reason: why})
		if res == ResultHalt {
			for _, a := range r.OnHalt {
				acts[a] = true
			}
		}
		worst = worse(worst, res)
	}
	if !interim {
		o := windowRow(w)
		j.Outcomes = append(j.Outcomes, o)
		worst = worse(worst, o.Result)
	}
	switch {
	case worst == ResultHalt:
		j.Verdict = VerdictHalt
		acts[ActionRollback], acts[ActionPage], acts[ActionFreeze] = true, true, true
	case interim:
		j.Verdict = VerdictContinue
	case worst == ResultInconclusive:
		// Plan 06 18.2.6: below a minimum volume the train does not promote
		// and the operator is paged. The canary goes back to N-1 (TRAINHALT-3).
		j.Verdict = VerdictInconclusive
		acts[ActionRollback], acts[ActionPage] = true, true
	default:
		j.Verdict = VerdictPromote
	}
	for a := range acts {
		j.Actions = append(j.Actions, a)
	}
	sort.Slice(j.Actions, func(a, b int) bool { return j.Actions[a] < j.Actions[b] })
	if j.Actions == nil {
		j.Actions = []Action{}
	}
	return j
}

func worse(a, b Result) Result {
	rank := map[Result]int{ResultOK: 0, ResultInconclusive: 1, ResultHalt: 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// Text renders a judgement for a terminal and for roll.sh: the first line
// is "VERDICT <verdict>", the second "ACTIONS <a,b>" ("-" when none).
func (j Judgement) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "VERDICT %s\n", j.Verdict)
	acts := make([]string, 0, len(j.Actions))
	for _, a := range j.Actions {
		acts = append(acts, string(a))
	}
	if len(acts) == 0 {
		acts = []string{"-"}
	}
	fmt.Fprintf(&b, "ACTIONS %s\n", strings.Join(acts, ","))
	mode := "final"
	if j.Interim {
		mode = "interim"
	}
	fmt.Fprintf(&b, "phase %s (%s)\n", j.Phase, mode)
	for _, o := range j.Outcomes {
		fmt.Fprintf(&b, "  %-12s %-18s %s\n", o.Result, o.Rule, o.Reason)
	}
	return b.String()
}
