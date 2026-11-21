package cloudsession

import (
	"strings"
	"testing"
	"time"
)

// TestClassifyDelivery: one case per row of the delivery table, top-down.
func TestClassifyDelivery(t *testing.T) {
	cases := []struct {
		name  string
		in    DeliveryOutcome
		want  CoverageReason
		state CoverageState
	}{
		{"proxy refused the CONNECT", DeliveryOutcome{Attempted: true, Failed: true, NetworkBlocked: true}, ReasonNetworkBlocked, CoverageNotEstablished},
		{"blocked wins over a status", DeliveryOutcome{Attempted: true, Failed: true, NetworkBlocked: true, Status: 403}, ReasonNetworkBlocked, CoverageNotEstablished},
		{"destination 401", DeliveryOutcome{Attempted: true, Failed: true, Status: 401}, ReasonTokenRefused, CoveragePermissionRequired},
		{"destination 403", DeliveryOutcome{Attempted: true, Failed: true, Status: 403}, ReasonTokenRefused, CoveragePermissionRequired},
		{"503 retryable", DeliveryOutcome{Attempted: true, Failed: true, Status: 503, Retryable: true, Pending: true}, ReasonUnreachable, CoverageDelayedReporting},
		{"no answer", DeliveryOutcome{Attempted: true, Failed: true, Retryable: true}, ReasonUnreachable, CoverageDelayedReporting},
		{"413", DeliveryOutcome{Attempted: true, Failed: true, Status: 413}, ReasonDestinationRefused, CoverageNotEstablished},
		{"accepted with rows left", DeliveryOutcome{Attempted: true, Pending: true}, ReasonRowsPending, CoveragePartialHistory},
		{"accepted", DeliveryOutcome{Attempted: true}, ReasonDelivered, CoverageVerified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, ok := ClassifyDelivery(tc.in)
			if !ok || r != tc.want {
				t.Fatalf("ClassifyDelivery = %q, %v; want %q", r, ok, tc.want)
			}
			c, err := NewCoverage(r, "org.example.com", "cse_x", TriggerPrompt, time.Unix(0, 0))
			if err != nil || c.State != tc.state {
				t.Fatalf("coverage = %+v, %v; want state %q", c, err, tc.state)
			}
		})
	}
	if _, ok := ClassifyDelivery(DeliveryOutcome{}); ok {
		t.Error("a flush that sent nothing changed the coverage")
	}
}

func TestCoverageMessages(t *testing.T) {
	for _, r := range CoverageReasons() {
		c, err := NewCoverage(r, "org.example.com", "", TriggerStart, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		m := c.Message()
		if m == "" || strings.Contains(m, "%!") {
			t.Errorf("%s: message %q", r, m)
		}
	}
	c, _ := NewCoverage(ReasonNetworkBlocked, "org.example.com", "", TriggerStart, time.Now())
	if want := "Not established: environment network level blocks org.example.com"; !strings.HasPrefix(c.Message(), want) {
		t.Errorf("network-blocked message = %q, want it to start %q", c.Message(), want)
	}
	if _, err := NewCoverage("nope", "", "", "", time.Now()); err == nil {
		t.Error("unknown reason accepted")
	}
}

// TestSkipDelivery: only prompt and periodic skip, only for the same host
// and the same vendor session, only after a network-level block.
func TestSkipDelivery(t *testing.T) {
	blocked := &Coverage{Reason: ReasonNetworkBlocked, Host: "org.example.com", VendorRef: "cse_a"}
	unreachable := &Coverage{Reason: ReasonUnreachable, Host: "org.example.com", VendorRef: "cse_a"}
	cases := []struct {
		trig      Trigger
		prev      *Coverage
		host, ref string
		skip      bool
	}{
		{TriggerPrompt, blocked, "org.example.com", "cse_a", true},
		{TriggerPeriodic, blocked, "org.example.com", "cse_a", true},
		{TriggerStart, blocked, "org.example.com", "cse_a", false},
		{TriggerFinal, blocked, "org.example.com", "cse_a", false},
		{TriggerPrompt, blocked, "other.example.com", "cse_a", false},
		{TriggerPrompt, blocked, "org.example.com", "cse_b", false},
		{TriggerPrompt, unreachable, "org.example.com", "cse_a", false},
		{TriggerPrompt, nil, "org.example.com", "cse_a", false},
	}
	for _, tc := range cases {
		spec, err := TriggerSpecFor(tc.trig)
		if err != nil {
			t.Fatal(err)
		}
		if got := SkipDelivery(spec, tc.prev, tc.host, tc.ref); got != tc.skip {
			t.Errorf("%s prev=%v host=%s ref=%s: skip=%v want %v", tc.trig, tc.prev, tc.host, tc.ref, got, tc.skip)
		}
	}
}

// TestTriggerTable pins the cadence decisions of each trigger.
func TestTriggerTable(t *testing.T) {
	want := map[Trigger]struct{ periodic, starts, skip, report bool }{
		TriggerStart:    {false, true, false, true},
		TriggerPrompt:   {false, false, true, false},
		TriggerPeriodic: {true, false, true, false},
		TriggerFinal:    {false, false, false, false},
	}
	if len(Triggers()) != len(want) {
		t.Fatalf("triggers = %v", Triggers())
	}
	for trig, w := range want {
		s, err := TriggerSpecFor(trig)
		if err != nil {
			t.Fatal(err)
		}
		if s.Periodic != w.periodic || s.StartsSession != w.starts || s.SkipWhenBlocked != w.skip || s.ReportsMisconfig != w.report {
			t.Errorf("%s = %+v", trig, s)
		}
		if s.Budget <= 0 || time.Duration(s.HookTimeoutSeconds)*time.Second <= s.Budget {
			t.Errorf("%s: hook timeout %ds must exceed the flush budget %s", trig, s.HookTimeoutSeconds, s.Budget)
		}
	}
}
