package secexcept

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql", "net/http", "net", "os", "os/exec",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
		},
		Reason: "internal/secexcept is the pure exception and baseline core",
	})
}

var t0 = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

func TestPlanRefusalTable(t *testing.T) {
	t.Parallel()
	open := FindingFacts{Found: true, Status: policy.FindingStatusOpen, FileHash: "abc"}
	ok := Request{FindingID: "F1", Reason: "false_positive", Expiry: "7d", Origin: OriginCLI}
	cases := []struct {
		name string
		req  Request
		f    FindingFacts
		want Refusal
	}{
		{"no origin (an agent, a repository file)", Request{FindingID: "F1", Reason: "false_positive", Expiry: "7d"}, open, RefuseOrigin},
		{"a project layer origin", Request{FindingID: "F1", Reason: "false_positive", Expiry: "7d", Origin: "project"}, open, RefuseOrigin},
		{"unknown finding", ok, FindingFacts{}, RefuseNoFinding},
		{"suppressed already", ok, FindingFacts{Found: true, Status: policy.FindingStatusSuppressed}, RefuseNotOpen},
		{"free-text reason", Request{FindingID: "F1", Reason: "because", Expiry: "7d", Origin: OriginCLI}, open, RefuseReason},
		{"perpetual", Request{FindingID: "F1", Reason: "false_positive", Expiry: "never", Origin: OriginCLI}, open, RefuseExpiry},
		{
			"until change, file unreadable",
			Request{FindingID: "F1", Reason: "test_fixture", Expiry: "until_change", Origin: OriginDashboard},
			FindingFacts{Found: true, Status: policy.FindingStatusOpen},
			RefuseNoFileHash,
		},
		{"granted", ok, open, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Plan(c.req, c.f, t0)
			if c.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			r, ok := AsRefusal(err)
			if !ok || r.Refusal != c.want {
				t.Fatalf("got %v, want %s", err, c.want)
			}
		})
	}
}

func TestPlanGrant(t *testing.T) {
	t.Parallel()
	g, err := Plan(Request{FindingID: "F", Reason: "accepted_risk", Expiry: "30d", Origin: OriginCLI},
		FindingFacts{Found: true, Status: policy.FindingStatusOpen, FileHash: "h"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if g.Reason.Status != policy.FindingStatusAcceptedRisk || !g.ExpiresAt.Equal(t0.Add(30*24*time.Hour)) || g.FileHash != "" {
		t.Fatalf("grant %+v", g)
	}
	g, err = Plan(Request{FindingID: "F", Reason: "test_fixture", Expiry: "until_change", Origin: OriginCLI},
		FindingFacts{Found: true, Status: policy.FindingStatusOpen, FileHash: "h"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if g.FileHash != "h" || !g.ExpiresAt.Equal(t0.Add(UntilChangeCeiling)) || g.Reason.Status != policy.FindingStatusSuppressed {
		t.Fatalf("until_change grant %+v", g)
	}
}

func TestEveryPickerRowIsReachable(t *testing.T) {
	t.Parallel()
	for _, r := range Reasons {
		if got, ok := ReasonFor(string(r.ID)); !ok || got != r || r.Label == "" || r.Status == policy.FindingStatusOpen {
			t.Errorf("reason row %+v", r)
		}
	}
	for _, e := range Expiries {
		if got, ok := ExpiryFor(string(e.ID)); !ok || got != e || e.After <= 0 || e.Label == "" {
			t.Errorf("expiry row %+v", e)
		}
	}
}

func TestJudgeTable(t *testing.T) {
	t.Parallel()
	dated := Exception{Expiry: Expiry7Days, ExpiresAt: t0.Add(time.Hour)}
	watch := Exception{Expiry: ExpiryUntilChange, ExpiresAt: t0.Add(time.Hour), FileHash: "h1"}
	cases := []struct {
		name string
		e    Exception
		now  time.Time
		o    Observed
		want Outcome
	}{
		{"dated, before expiry", dated, t0, Observed{}, OutcomeActive},
		{"dated, at expiry", dated, t0.Add(time.Hour), Observed{}, OutcomeExpired},
		{"dated, file changed does not matter", dated, t0, Observed{FileKnown: true, FileHash: "x"}, OutcomeActive},
		{"no expiry recorded is expired", Exception{Expiry: Expiry1Day}, t0, Observed{}, OutcomeExpired},
		{"until change, same file", watch, t0, Observed{FileKnown: true, FileHash: "h1"}, OutcomeActive},
		{"until change, edited", watch, t0, Observed{FileKnown: true, FileHash: "h2"}, OutcomeFileChanged},
		{"until change, deleted", watch, t0, Observed{FileKnown: true}, OutcomeFileChanged},
		{"until change, cannot look", watch, t0, Observed{}, OutcomeActive},
		{"until change, ceiling", watch, t0.Add(2 * time.Hour), Observed{FileKnown: true, FileHash: "h1"}, OutcomeExpired},
	}
	for _, c := range cases {
		if got := Judge(c.e, c.now, c.o); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestCheckBaselineCommit(t *testing.T) {
	t.Parallel()
	good := strings.Repeat("a1", 20)
	for _, s := range []string{good, strings.Repeat("0f", 32)} {
		if err := CheckBaselineCommit(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"", "main", "HEAD~1", good[:12], strings.ToUpper(good), good + "0", "g" + good[1:]} {
		if CheckBaselineCommit(s) == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestPropose(t *testing.T) {
	t.Parallel()
	a, b, c := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	got := Propose(Commit{SHA: b, Subject: "base"}, []Commit{
		{SHA: a, Subject: "fix\x1b[31m red‮"}, {SHA: b}, {SHA: "nope"}, {SHA: c, Subject: strings.Repeat("x", 200)},
	})
	if len(got) != 3 || got[0].SHA != b || !got[0].MergeBase || got[1].SHA != a || got[1].MergeBase || got[2].SHA != c {
		t.Fatalf("proposal %+v", got)
	}
	if got[1].Subject != "fix[31m red" {
		t.Errorf("subject not stripped: %q", got[1].Subject)
	}
	if len([]rune(got[2].Subject)) != 83 {
		t.Errorf("subject not cut: %d", len(got[2].Subject))
	}
	var many []Commit
	for i := 0; i < 30; i++ {
		many = append(many, Commit{SHA: strings.Repeat(string(rune('a'+i%6)), 39) + string(rune('0'+i%10))})
	}
	if n := len(Propose(Commit{}, many)); n > MaxProposed {
		t.Errorf("%d commits proposed", n)
	}
}
