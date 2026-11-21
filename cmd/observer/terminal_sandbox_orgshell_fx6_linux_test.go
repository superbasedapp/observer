//go:build linux && !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// TestOrgShellHeldHintNamesTheBoxKey (lane FX6, F-P7-3): a resume asked by
// a resumed run's own id (the box's active id, which the organization now
// accepts) is held again; the hint names the box's ledger key the mint
// answered, never the id the member typed, which the next resume makes
// stale.
func TestOrgShellHeldHintNamesTheBoxKey(t *testing.T) {
	cases := []struct {
		name    string
		mintBox string
		resumed string
		want    string
	}{
		{"resumed by the active id", "ORIGORIGORIGORIGORIG00", "ACTIVEACTIVEACTIVE0000", "ORIGORIGORIGORIGORIG00"},
		{"resumed by the held id", "ORIGORIGORIGORIGORIG00", "ORIGORIGORIGORIGORIG00", "ORIGORIGORIGORIGORIG00"},
		{"an older server's mint names nothing", "", "ACTIVEACTIVEACTIVE0000", "ACTIVEACTIVEACTIVE0000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldR, oldH := orgShellReport, orgShellHeldList
			orgShellReport = func(context.Context, *orgclient.Client, string, orgclient.OpenShellEnded) (orgclient.OpenShellEndedAnswer, error) {
				return orgclient.OpenShellEndedAnswer{Outcome: "hold"}, nil
			}
			orgShellHeldList = func(context.Context, *orgclient.Client) ([]orgclient.OpenShellHeldBox, error) { return nil, nil }
			t.Cleanup(func() { orgShellReport, orgShellHeldList = oldR, oldH })
			r := orgShellTestRun(t, &scriptBox{answer: orgShellAnswers})
			r.plan.ResumeBoxRunID = tc.resumed
			var out strings.Builder
			r.t.out = &out
			r.rec = sandboxremote.NewIntent(r.plan.RunID, r.plan.Provider, "https://sandbox.example.com", "", r.plan.RunID, r.now(), time.Hour)
			r.rec.VendorID = "obsbox"
			_ = r.rec.Apply(sandboxremote.EvCreateOK)
			r.rec.State = sandboxremote.StateGone
			r.cutStream(errors.New("openshellorg: Internal: stream terminated by RST_STREAM"))
			orgShellRunState.Store(r.plan.RunID, &orgShellRun{tokens: &orgShellTokens{first: orgclient.OpenShellMint{
				ReturnToNode: true, HoldPolicy: "on_disconnect", BoxRunID: tc.mintBox,
			}}})
			if !orgShellEndRun(context.Background(), r) {
				t.Fatal("the end branch did not run")
			}
			if s := out.String(); !strings.Contains(s, "org-shell resume "+tc.want+"`") {
				t.Errorf("terminal said (want resume %s): %s", tc.want, s)
			}
		})
	}
}

// TestHostedLastSessionChecksTheBoxsValue (fold delta audit N2): the
// session a resume continues comes from the box's own sessions.json, so it
// is checked with hostedSessionIDOK (the write side's rule) before it can
// reach the agent's argv. A hostile value is refused, never passed.
func TestHostedLastSessionChecksTheBoxsValue(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		code    int
		err     error
		last    string
		refused bool
	}{
		{"a session id", `{"sessions":["a"],"last":"36f75772-1f0e-4c4e-9d2b-0123456789ab"}`, 0, nil, "36f75772-1f0e-4c4e-9d2b-0123456789ab", false},
		{"a leading dash", `{"last":"--dangerously-skip-permissions"}`, 0, nil, "", true},
		{"a space", `{"last":"abc def"}`, 0, nil, "", true},
		{"a newline", `{"last":"abc\ndef"}`, 0, nil, "", true},
		{"over 128 bytes", `{"last":"` + strings.Repeat("a", 129) + `"}`, 0, nil, "", true},
		{"no last", `{"sessions":[]}`, 0, nil, "", false},
		{"not JSON", `nope`, 0, nil, "", false},
		{"no file", ``, 1, nil, "", false},
		{"the read failed", ``, 0, errors.New("exec failed"), "", false},
	}
	for _, tc := range cases {
		last, refused := hostedLastSession([]byte(tc.out), tc.code, tc.err)
		if last != tc.last || refused != tc.refused {
			t.Errorf("%s: %q %v, want %q %v", tc.name, last, refused, tc.last, tc.refused)
		}
	}
}

// TestOrgShellEndWordsNeverContradict (lane FX6, F-P7-6): when the
// organization ended the run (a revoke, a drain) and the box's diff did
// not come home, the terminal said "the work stays in it for your
// organization to hold or collect", then "nothing is held". Both lines now
// come from one fate table: the first says nothing of a hold, the second
// says nothing is held.
func TestOrgShellEndWordsNeverContradict(t *testing.T) {
	for _, reason := range []string{"org_signin_revoked", "org_openshell_draining"} {
		t.Run(reason, func(t *testing.T) {
			oldR, oldH := orgShellReport, orgShellHeldList
			orgShellReport = func(context.Context, *orgclient.Client, string, orgclient.OpenShellEnded) (orgclient.OpenShellEndedAnswer, error) {
				return orgclient.OpenShellEndedAnswer{Outcome: "ended_unreturned", Reason: reason}, nil
			}
			orgShellHeldList = func(context.Context, *orgclient.Client) ([]orgclient.OpenShellHeldBox, error) { return nil, nil }
			t.Cleanup(func() { orgShellReport, orgShellHeldList = oldR, oldH })
			// The box was stopped by the organization: the return's diff fails.
			r := orgShellTestRun(t, stoppedBox{})
			var out strings.Builder
			r.t.out = &out
			r.rec = sandboxremote.NewIntent(r.plan.RunID, r.plan.Provider, "https://sandbox.example.com", "", r.plan.RunID, r.now(), time.Hour)
			r.rec.VendorID = "obsbox"
			_ = r.rec.Apply(sandboxremote.EvCreateOK)
			r.rec.State = sandboxremote.StateGone
			orgShellRunState.Store(r.plan.RunID, &orgShellRun{tokens: &orgShellTokens{first: orgclient.OpenShellMint{ReturnToNode: true, HoldPolicy: "off"}}})
			if !orgShellEndRun(context.Background(), r) {
				t.Fatal("the end branch did not run")
			}
			s := out.String()
			if !strings.Contains(s, "NOT saved as a diff") || !strings.Contains(s, hostedBoxFateWords[hostedFateOrgEnded]) {
				t.Fatalf("terminal said: %s", s)
			}
			if rest := strings.ReplaceAll(s, "nothing is held", ""); strings.Contains(rest, "hold") || strings.Contains(rest, "held") {
				t.Errorf("a line speaks of a hold the organization ended: %s", s)
			}
			if strings.Index(s, "NOT saved as a diff") > strings.Index(s, "your organization ended the run") {
				t.Errorf("the diff line came after the organization's answer: %s", s)
			}
		})
	}
}

// TestHostedBoxFateTable: every fate has its words, and only the org-ended
// fate speaks of a hold (to say there is none).
func TestHostedBoxFateTable(t *testing.T) {
	for _, f := range []hostedBoxFate{hostedFateUndecided, hostedFateCollected, hostedFateOrgEnded, hostedFateDeletedHere} {
		w, ok := hostedBoxFateWords[f]
		if !ok || w == "" {
			t.Fatalf("fate %d has no words", f)
		}
		if f != hostedFateOrgEnded && strings.Contains(w, "hold") {
			t.Errorf("fate %d speaks of a hold: %q", f, w)
		}
	}
}

// TestHostedEndCodeAfterAHold (lane FX6, F-P8 observation, ruling FX6-R4):
// once the organization lists the box HELD, only the hold's own stop exits
// 0 (a cut stream with no agent exit, or SIGTERM's 143); every other agent
// code is kept (137, 139, an agent's own exit); a box that is not held, or
// only holding, keeps the run's code.
func TestHostedEndCodeAfterAHold(t *testing.T) {
	for _, tc := range []struct {
		name              string
		code              int
		held, agentExited bool
		want              int
	}{
		{"held, the stream cut by the hold", 1, true, false, 0},
		{"held, the agent ended by the stop's SIGTERM", 143, true, true, 0},
		{"held, an out-of-memory kill is kept", 137, true, true, 137},
		{"held, a crash is kept", 139, true, true, 139},
		{"held on end after the agent's own exit", 3, true, true, 3},
		{"held on end after a clean exit", 0, true, true, 0},
		{"not held, a cut", 1, false, false, 1},
		{"not held, a signal", 143, false, true, 143},
	} {
		if got := hostedEndCode(tc.code, tc.held, tc.agentExited); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
	// The end branch marks the run held when the organization lists its
	// box held (an explicit `org-shell hold` from another terminal).
	oldR, oldH := orgShellReport, orgShellHeldList
	orgShellReport = func(context.Context, *orgclient.Client, string, orgclient.OpenShellEnded) (orgclient.OpenShellEndedAnswer, error) {
		return orgclient.OpenShellEndedAnswer{Outcome: "ended_unreturned"}, nil
	}
	t.Cleanup(func() { orgShellReport, orgShellHeldList = oldR, oldH })
	r := orgShellTestRun(t, stoppedBox{})
	r.t.out = io.Discard
	orgShellHeldList = func(context.Context, *orgclient.Client) ([]orgclient.OpenShellHeldBox, error) {
		return []orgclient.OpenShellHeldBox{{RunID: r.plan.RunID, State: "held"}}, nil
	}
	r.rec = sandboxremote.NewIntent(r.plan.RunID, r.plan.Provider, "https://sandbox.example.com", "", r.plan.RunID, r.now(), time.Hour)
	r.rec.VendorID = "obsbox"
	_ = r.rec.Apply(sandboxremote.EvCreateOK)
	r.rec.State = sandboxremote.StateGone
	orgShellRunState.Store(r.plan.RunID, &orgShellRun{tokens: &orgShellTokens{first: orgclient.OpenShellMint{ReturnToNode: true, HoldPolicy: "off"}}})
	if !orgShellEndRun(context.Background(), r) || !r.heldAtEnd {
		t.Fatalf("the run's box is held, but the run is not marked held (held=%v)", r.heldAtEnd)
	}
	// A box the organization lists holding (not yet held) does not mark the
	// run held.
	r2 := orgShellTestRun(t, stoppedBox{})
	r2.t.out = io.Discard
	orgShellHeldList = func(context.Context, *orgclient.Client) ([]orgclient.OpenShellHeldBox, error) {
		return []orgclient.OpenShellHeldBox{{RunID: r2.plan.RunID, State: "holding"}}, nil
	}
	r2.rec = sandboxremote.NewIntent(r2.plan.RunID, r2.plan.Provider, "https://sandbox.example.com", "", r2.plan.RunID, r2.now(), time.Hour)
	r2.rec.VendorID = "obsbox"
	_ = r2.rec.Apply(sandboxremote.EvCreateOK)
	r2.rec.State = sandboxremote.StateGone
	orgShellRunState.Store(r2.plan.RunID, &orgShellRun{tokens: &orgShellTokens{first: orgclient.OpenShellMint{ReturnToNode: true, HoldPolicy: "off"}}})
	if !orgShellEndRun(context.Background(), r2) || r2.heldAtEnd {
		t.Fatalf("a holding box marked the run held (held=%v)", r2.heldAtEnd)
	}
}

// TestHostedHoldAnswerMarksHeldOnlyWhenListedHeld (lane FX6, ruling
// FX6-R4): the organization's "hold" answer to the end report alone does
// not mark the run held for its exit code; only its listing of the box as
// HELD does (holding is not yet held, and an unanswered listing is not
// held).
func TestHostedHoldAnswerMarksHeldOnlyWhenListedHeld(t *testing.T) {
	oldR, oldH := orgShellReport, orgShellHeldList
	t.Cleanup(func() { orgShellReport, orgShellHeldList = oldR, oldH })
	orgShellReport = func(context.Context, *orgclient.Client, string, orgclient.OpenShellEnded) (orgclient.OpenShellEndedAnswer, error) {
		return orgclient.OpenShellEndedAnswer{Outcome: "hold"}, nil
	}
	for _, tc := range []struct {
		name   string
		state  string
		err    error
		marked bool
	}{
		{"listed held", "held", nil, true},
		{"listed holding", "holding", nil, false},
		{"listing unanswered", "", errors.New("unreachable"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := orgShellTestRun(t, stoppedBox{})
			r.t.out = io.Discard
			orgShellHeldList = func(context.Context, *orgclient.Client) ([]orgclient.OpenShellHeldBox, error) {
				if tc.err != nil {
					return nil, tc.err
				}
				return []orgclient.OpenShellHeldBox{{RunID: r.plan.RunID, State: tc.state}}, nil
			}
			r.rec = sandboxremote.NewIntent(r.plan.RunID, r.plan.Provider, "https://sandbox.example.com", "", r.plan.RunID, r.now(), time.Hour)
			r.rec.VendorID = "obsbox"
			_ = r.rec.Apply(sandboxremote.EvCreateOK)
			r.rec.State = sandboxremote.StateGone
			// return_to_node false: the end branch holds.
			orgShellRunState.Store(r.plan.RunID, &orgShellRun{tokens: &orgShellTokens{first: orgclient.OpenShellMint{ReturnToNode: false, HoldPolicy: "on_disconnect"}}})
			if !orgShellEndRun(context.Background(), r) {
				t.Fatal("the end branch did not run")
			}
			if r.heldAtEnd != tc.marked {
				t.Fatalf("heldAtEnd %v, want %v", r.heldAtEnd, tc.marked)
			}
		})
	}
}
