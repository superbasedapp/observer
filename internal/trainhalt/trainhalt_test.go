package trainhalt

import (
	"reflect"
	"strings"
	"testing"
)

func f(v float64) *float64 { return &v }

// healthy is a canary window where every row is ok and the window ran its
// full 45 minutes.
func healthy() Window {
	return Window{
		Phase:                  PhaseCanary,
		ElapsedSeconds:         45 * 60,
		TelemetryAgeSeconds:    f(15),
		IsolationProbeFailures: f(0),
		MigrationErrors:        f(0),
		PushesTotal:            f(160),
		PushesOK:               f(160),
		APIRequests:            f(800),
		API5xx:                 f(1),
		API5xxBaselineRate:     f(0.002),
		ApplyBacklogMinSeconds: f(4),
	}
}

func outcome(t *testing.T, j Judgement, rule string) Outcome {
	t.Helper()
	for _, o := range j.Outcomes {
		if o.Rule == rule {
			return o
		}
	}
	t.Fatalf("no outcome for rule %s", rule)
	return Outcome{}
}

// TestHaltTable is one case per row of plan 06 18.2.6's table (each row's
// halt, its minimum volume where it has one, and a missing signal), plus
// the inconclusive window. Each case edits the healthy window and states
// the row's result and the final verdict.
func TestHaltTable(t *testing.T) {
	cases := []struct {
		name    string
		rule    string
		edit    func(w *Window)
		result  Result
		verdict Verdict
	}{
		{"isolation probe: any failure halts", "isolation_probe", func(w *Window) { w.IsolationProbeFailures = f(1) }, ResultHalt, VerdictHalt},
		{"isolation probe: none is ok", "isolation_probe", func(w *Window) {}, ResultOK, VerdictPromote},
		{"isolation probe: missing is inconclusive", "isolation_probe", func(w *Window) { w.IsolationProbeFailures = nil }, ResultInconclusive, VerdictInconclusive},
		{"telemetry: 5 minutes missing halts", "telemetry_missing", func(w *Window) { w.TelemetryAgeSeconds = f(300) }, ResultHalt, VerdictHalt},
		{"telemetry: 4m59s is ok", "telemetry_missing", func(w *Window) { w.TelemetryAgeSeconds = f(299) }, ResultOK, VerdictPromote},
		{"telemetry: no series at all halts", "telemetry_missing", func(w *Window) { w.TelemetryAgeSeconds = nil }, ResultHalt, VerdictHalt},
		{"push success: below 99% halts", "push_success", func(w *Window) { w.PushesTotal, w.PushesOK = f(200), f(197) }, ResultHalt, VerdictHalt},
		{"push success: exactly 99% is ok", "push_success", func(w *Window) { w.PushesTotal, w.PushesOK = f(200), f(198) }, ResultOK, VerdictPromote},
		{"push success: under 100 pushes is inconclusive", "push_success", func(w *Window) { w.PushesTotal, w.PushesOK = f(99), f(99) }, ResultInconclusive, VerdictInconclusive},
		{"push success: under 100 pushes with failures is still inconclusive, not a halt", "push_success", func(w *Window) { w.PushesTotal, w.PushesOK = f(50), f(10) }, ResultInconclusive, VerdictInconclusive},
		{"push success: ok above total is inconclusive", "push_success", func(w *Window) { w.PushesOK = f(161) }, ResultInconclusive, VerdictInconclusive},
		{"push success: missing is inconclusive", "push_success", func(w *Window) { w.PushesOK = nil }, ResultInconclusive, VerdictInconclusive},
		{"5xx: above twice the baseline halts", "api_5xx", func(w *Window) { w.APIRequests, w.API5xx, w.API5xxBaselineRate = f(1000), f(5), f(0.002) }, ResultHalt, VerdictHalt},
		{"5xx: exactly twice the baseline is ok", "api_5xx", func(w *Window) { w.APIRequests, w.API5xx, w.API5xxBaselineRate = f(1000), f(4), f(0.002) }, ResultOK, VerdictPromote},
		{"5xx: a zero baseline is floored, one error in 1000 is ok", "api_5xx", func(w *Window) { w.APIRequests, w.API5xx, w.API5xxBaselineRate = f(1000), f(1), f(0) }, ResultOK, VerdictPromote},
		{"5xx: a zero baseline still halts above twice the floor", "api_5xx", func(w *Window) { w.APIRequests, w.API5xx, w.API5xxBaselineRate = f(1000), f(3), f(0) }, ResultHalt, VerdictHalt},
		{"5xx: under 500 requests is inconclusive", "api_5xx", func(w *Window) { w.APIRequests, w.API5xx = f(499), f(0) }, ResultInconclusive, VerdictInconclusive},
		{"5xx: missing baseline is inconclusive", "api_5xx", func(w *Window) { w.API5xxBaselineRate = nil }, ResultInconclusive, VerdictInconclusive},
		{"apply backlog: above 60s for 10 minutes halts", "apply_backlog", func(w *Window) { w.ApplyBacklogMinSeconds = f(61) }, ResultHalt, VerdictHalt},
		{"apply backlog: 60s is ok", "apply_backlog", func(w *Window) { w.ApplyBacklogMinSeconds = f(60) }, ResultOK, VerdictPromote},
		{"apply backlog: missing is inconclusive", "apply_backlog", func(w *Window) { w.ApplyBacklogMinSeconds = nil }, ResultInconclusive, VerdictInconclusive},
		{"migration job: any error halts", "migration_job", func(w *Window) { w.MigrationErrors = f(1) }, ResultHalt, VerdictHalt},
		{"migration job: missing is inconclusive", "migration_job", func(w *Window) { w.MigrationErrors = nil }, ResultInconclusive, VerdictInconclusive},
		{"inconclusive window: the canary judged after 44 minutes cannot promote", "window_length", func(w *Window) { w.ElapsedSeconds = 44 * 60 }, ResultInconclusive, VerdictInconclusive},
		{"window: post-promotion needs 30 minutes", "window_length", func(w *Window) { w.Phase, w.ElapsedSeconds = PhasePromoted, 30*60 }, ResultOK, VerdictPromote},
		{"window: soak needs two hours", "window_length", func(w *Window) { w.Phase, w.ElapsedSeconds = PhaseSoak, 119*60 }, ResultInconclusive, VerdictInconclusive},
		{"window: an unknown phase is inconclusive", "window_length", func(w *Window) { w.Phase = "nightly" }, ResultInconclusive, VerdictInconclusive},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := healthy()
			c.edit(&w)
			j := Judge(w, false)
			if o := outcome(t, j, c.rule); o.Result != c.result {
				t.Fatalf("%s = %s (%s), want %s", c.rule, o.Result, o.Reason, c.result)
			}
			if j.Verdict != c.verdict {
				t.Fatalf("verdict %s, want %s\n%s", j.Verdict, c.verdict, j.Text())
			}
		})
	}
}

// TestEveryRuleHasACase keeps the table and its tests in step: a new row
// without a case above fails here.
func TestEveryRuleHasACase(t *testing.T) {
	want := []string{"isolation_probe", "telemetry_missing", "push_success", "api_5xx", "apply_backlog", "migration_job"}
	var got []string
	for _, r := range Rules {
		got = append(got, r.ID)
		if r.Signal == "" || r.Halt == "" || r.MinVolume == "" || r.eval == nil {
			t.Errorf("rule %s is incomplete", r.ID)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rules %v, want %v (add a TestHaltTable case for a new row)", got, want)
	}
}

// TestInconclusiveBlocksPromotion: an inconclusive window is never
// promote, it pages and sends the canary back to N-1, and it does not
// freeze (only a halt freezes).
func TestInconclusiveBlocksPromotion(t *testing.T) {
	w := healthy()
	w.PushesTotal, w.PushesOK = f(20), f(20)
	j := Judge(w, false)
	if j.Verdict != VerdictInconclusive {
		t.Fatalf("verdict %s", j.Verdict)
	}
	if !reflect.DeepEqual(j.Actions, []Action{ActionPage, ActionRollback}) {
		t.Fatalf("actions %v", j.Actions)
	}
}

// TestHaltActions: every halt rolls back, pages and freezes; only the
// isolation probe also stops the window at once.
func TestHaltActions(t *testing.T) {
	w := healthy()
	w.MigrationErrors = f(2)
	if got := Judge(w, false).Actions; !reflect.DeepEqual(got, []Action{ActionFreeze, ActionPage, ActionRollback}) {
		t.Fatalf("migration halt actions %v", got)
	}
	w = healthy()
	w.IsolationProbeFailures = f(1)
	if got := Judge(w, false).Actions; !reflect.DeepEqual(got, []Action{ActionFreeze, ActionPage, ActionRollback, ActionStopNow}) {
		t.Fatalf("isolation halt actions %v", got)
	}
	if got := Judge(healthy(), false).Actions; len(got) != 0 {
		t.Fatalf("promote actions %v", got)
	}
}

// TestInterim: during the window a low volume is not yet a verdict
// (continue), but a halt row halts at once.
func TestInterim(t *testing.T) {
	w := healthy()
	w.ElapsedSeconds, w.PushesTotal, w.PushesOK = 600, f(10), f(10)
	if j := Judge(w, true); j.Verdict != VerdictContinue {
		t.Fatalf("interim low volume: %s", j.Verdict)
	}
	w.IsolationProbeFailures = f(1)
	if j := Judge(w, true); j.Verdict != VerdictHalt {
		t.Fatalf("interim isolation failure: %s", j.Verdict)
	}
}

func TestTextFirstLines(t *testing.T) {
	out := Judge(healthy(), false).Text()
	if !strings.HasPrefix(out, "VERDICT promote\nACTIONS -\n") {
		t.Fatalf("text:\n%s", out)
	}
}
