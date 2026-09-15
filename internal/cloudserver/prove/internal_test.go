package prove

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/foundry"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// These tests live INSIDE the package because Fixture's envelope field is
// unexported — which is itself the point: no code outside this package can
// construct a Fixture, so no client-supplied evidence can enter the lane. The
// only way to exercise the fixture-validation step's FAILURE path is from here.

type stubControl struct {
	route  store.RouteInfo
	reads  int
	dreads int
}

func (c *stubControl) RouteByID(context.Context, string) (store.RouteInfo, error) {
	c.reads++
	return c.route, nil
}

func (c *stubControl) DialectVerified(context.Context, store.RouteInfo, time.Time) (bool, error) {
	c.dreads++
	return true, nil
}

type okAttestor struct{ calls int }

func (a *okAttestor) Attest(context.Context, store.RouteInfo, time.Time) (jobs.Attestation, error) {
	a.calls++
	return jobs.Attestation{Verified: true, Reason: "ok"}, nil
}

// TestMalformedFixtureFailsBeforeAnythingLeaves proves the first gate: a fixture
// that does not satisfy the envelope schema fails at fixture_validate, and the
// route is never resolved, the attestation never taken, and the provider never
// called. A malformed compiled-in fixture must cost nothing.
func TestMalformedFixtureFailsBeforeAnythingLeaves(t *testing.T) {
	broken := Fixture{
		Name:    "broken_on_purpose",
		Purpose: "a fixture that violates the envelope schema",
		// Empty envelope: wrong schema_version, empty ids, unparseable
		// started_at_bucket — Validate rejects it on the first bound.
		envelope: cloudcontract.Envelope{},
	}
	control := &stubControl{}
	att := &okAttestor{}
	provider := &foundry.FakeProvider{Response: foundry.Response{Content: "{}"}}

	rep, err := Run(context.Background(), Options{
		FoundryAPIKey: "prove-key",
		RouteID:       "r1",
		Control:       control,
		Attestor:      att,
		Provider:      provider,
		Fixtures:      []Fixture{broken},
	})
	if err != nil {
		t.Fatalf("Run returned a configuration error, want a reported step failure: %v", err)
	}
	if rep.Passed() {
		t.Fatal("a malformed fixture passed the run")
	}
	fr := rep.Fixtures[0]
	if fr.Steps[0].Step != StepFixture || fr.Steps[0].Status != StatusFail {
		t.Fatalf("first step = %+v, want fixture_validate FAIL", fr.Steps[0])
	}
	for _, s := range fr.Steps[1:] {
		if s.Status != StatusSkip {
			t.Fatalf("step %s after the fixture failure = %q, want SKIP", s.Step, s.Status)
		}
	}
	if control.reads != 0 || att.calls != 0 || len(provider.Requests) != 0 {
		t.Fatalf("a malformed fixture reached downstream: routes=%d attest=%d provider=%d",
			control.reads, att.calls, len(provider.Requests))
	}
	if rep.Dialect != "unresolved" {
		t.Fatalf("dialect = %q, want the honest %q when the route never resolved", rep.Dialect, "unresolved")
	}
}

// TestSkipTailCoversEveryLaterStep pins the report contract that makes a
// failure readable: after a FAIL, every remaining step is present and SKIP —
// never absent (which would read as "not applicable") and never PASS.
func TestSkipTailCoversEveryLaterStep(t *testing.T) {
	for i, failAt := range Steps() {
		fx := &fixtureRun{}
		fx.fail(failAt, "synthetic")
		if len(fx.report.Steps) != len(Steps())-i {
			t.Fatalf("failing at %s recorded %d steps, want %d (the failure plus every later step)",
				failAt, len(fx.report.Steps), len(Steps())-i)
		}
		if fx.report.Steps[0].Step != failAt || fx.report.Steps[0].Status != StatusFail {
			t.Fatalf("first recorded step = %+v, want %s FAIL", fx.report.Steps[0], failAt)
		}
		for _, s := range fx.report.Steps[1:] {
			if s.Status != StatusSkip {
				t.Fatalf("step %s = %q, want SKIP", s.Step, s.Status)
			}
		}
		if fx.report.Passed() {
			t.Fatalf("a report containing a FAIL at %s reported Passed()", failAt)
		}
	}
}

// TestJSONSafeTokenCannotBreakTheAuditDetail pins that a hostile route id
// cannot escape the small JSON audit detail the lane writes.
func TestJSONSafeTokenCannotBreakTheAuditDetail(t *testing.T) {
	for _, in := range []string{`a"b`, "a\\b", "a\nb", "a\x00b", "", `","injected":"`} {
		got := jsonSafeToken(in)
		for _, bad := range []rune{'"', '\\', '\n', 0} {
			for _, r := range got {
				if r == bad {
					t.Fatalf("jsonSafeToken(%q) = %q — still contains %q", in, got, bad)
				}
			}
		}
	}
	if got := jsonSafeToken(strings.Repeat("x", 500)); len(got) != 128 {
		t.Fatalf("jsonSafeToken did not bound its output: %d bytes", len(got))
	}
	// And the detail it produces is still valid JSON with a hostile route id.
	rep := Report{Fixtures: []FixtureReport{{Steps: []StepResult{{Status: StatusPass}}}}}
	var captured string
	ok, _ := recordAudit(context.Background(), Options{
		RouteID: `evil","escaped":"yes`,
		Audit: func(_ context.Context, _, detail string) error {
			captured = detail
			return nil
		},
	}, rep)
	if !ok {
		t.Fatal("recordAudit reported no write despite an auditor")
	}
	if !json.Valid([]byte(captured)) {
		t.Fatalf("audit detail is not valid JSON with a hostile route id: %q", captured)
	}
	if strings.Contains(captured, `"escaped"`) {
		t.Fatalf("a hostile route id escaped into its own JSON key: %q", captured)
	}
}
