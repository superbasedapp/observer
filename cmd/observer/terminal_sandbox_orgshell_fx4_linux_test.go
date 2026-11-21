//go:build linux && !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestOrgShellEndWordsFromTheHeldState (FX4 item 5, F-P6-4 and F-P6-5):
// the terminal's last words come from the organization's own held list, and
// name the id that list carries.
//   - a cut that outlasted the hold delay: the org already held the box
//     (H2), so the node's hold report is answered hold_unavailable; the
//     terminal said the org "collects the work, then deletes the box";
//   - an explicit `org-shell hold` (H3) from another terminal: the launching
//     terminal's end without a return said the same;
//   - a resumed run held again: the hint named the resumed run's own id,
//     not the held run's id `org-shell held` lists.
func TestOrgShellEndWordsFromTheHeldState(t *testing.T) {
	cases := []struct {
		name     string
		cut      bool
		resumed  string
		answer   orgclient.OpenShellEndedAnswer
		held     []orgclient.OpenShellHeldBox
		wantHeld string // the id the words must name; "" means no held words
	}{
		{
			"a long cut, held already (H2)", true, "",
			orgclient.OpenShellEndedAnswer{Outcome: "unreturned", Reason: "hold_unavailable"},
			[]orgclient.OpenShellHeldBox{{RunID: "RUN", State: "held", Reason: "H2"}},
			"RUN",
		},
		{
			"an explicit hold (H3)", false, "",
			orgclient.OpenShellEndedAnswer{Outcome: "unreturned"},
			[]orgclient.OpenShellHeldBox{{RunID: "RUN", State: "holding", Reason: "H3"}},
			"RUN",
		},
		{"a resumed run held again", true, "ORIG", orgclient.OpenShellEndedAnswer{Outcome: "hold"}, nil, "ORIG"},
		{
			"a resumed run held already", true, "ORIG",
			orgclient.OpenShellEndedAnswer{Outcome: "unreturned", Reason: "hold_unavailable"},
			[]orgclient.OpenShellHeldBox{{RunID: "ORIG", State: "held"}},
			"ORIG",
		},
		{
			"not held: the org collects", true, "",
			orgclient.OpenShellEndedAnswer{Outcome: "unreturned", Reason: "hold_unavailable"},
			[]orgclient.OpenShellHeldBox{{RunID: "OTHER", State: "held"}, {RunID: "RUN", State: "collect_failed"}},
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldR, oldH := orgShellReport, orgShellHeldList
			orgShellReport = func(context.Context, *orgclient.Client, string, orgclient.OpenShellEnded) (orgclient.OpenShellEndedAnswer, error) {
				return tc.answer, nil
			}
			orgShellHeldList = func(context.Context, *orgclient.Client) ([]orgclient.OpenShellHeldBox, error) { return tc.held, nil }
			t.Cleanup(func() { orgShellReport, orgShellHeldList = oldR, oldH })
			var box sandboxremote.Client = &scriptBox{answer: orgShellAnswers}
			if !tc.cut {
				box = stoppedBox{} // the explicit hold stopped it: the return finds nothing
			}
			r := orgShellTestRun(t, box)
			for i := range tc.held {
				if tc.held[i].RunID == "RUN" {
					tc.held[i].RunID = r.plan.RunID
				}
			}
			want := tc.wantHeld
			if want == "RUN" {
				want = r.plan.RunID
			}
			r.plan.ResumeBoxRunID = tc.resumed
			var out strings.Builder
			r.t.out = &out
			r.rec = sandboxremote.NewIntent(r.plan.RunID, r.plan.Provider, "https://sandbox.example.com", "", r.plan.RunID, r.now(), time.Hour)
			r.rec.VendorID = "obsbox"
			_ = r.rec.Apply(sandboxremote.EvCreateOK)
			r.rec.State = sandboxremote.StateGone
			policy := "off"
			if tc.cut {
				policy = "on_disconnect"
				r.cutStream(errors.New("openshellorg: Internal: stream terminated by RST_STREAM"))
			}
			orgShellRunState.Store(r.plan.RunID, &orgShellRun{tokens: &orgShellTokens{first: orgclient.OpenShellMint{ReturnToNode: true, HoldPolicy: policy}}})
			if !orgShellEndRun(context.Background(), r) {
				t.Fatal("the end branch did not run")
			}
			s := out.String()
			if want == "" {
				if strings.Contains(s, "held by your organization") || !strings.Contains(s, "collects") {
					t.Errorf("terminal said: %s", s)
				}
				return
			}
			if !strings.Contains(s, "held by your organization") || !strings.Contains(s, "org-shell resume "+want) || strings.Contains(s, "then deletes the box") {
				t.Errorf("terminal said (want held, resume %s): %s", want, s)
			}
			if tc.resumed != "" && strings.Contains(s, "org-shell resume "+r.plan.RunID) {
				t.Errorf("the hint names the resumed run's own id: %s", s)
			}
		})
	}
}

// TestDiffApplyWhere (FX4 item 5, F-P6-7): a box-side clone's diff is
// against the repository the box cloned, so the hint names a checkout of it,
// never the launch directory alone; a workspace upload's diff applies in the
// launch directory.
func TestDiffApplyWhere(t *testing.T) {
	up := hostedPlanFile{Root: "/home/dev/proj"}
	if got := hostedDiffApplyWhere(up); got != "/home/dev/proj" {
		t.Errorf("upload: %q", got)
	}
	clone := hostedPlanFile{Root: "/home/dev/proj", Delivery: hostedDeliveryRemoteClone, CloneURL: "https://git.example.com/org/repo.git"}
	if got := hostedDiffApplyWhere(clone); !strings.HasPrefix(got, "a checkout of https://git.example.com/org/repo.git") {
		t.Errorf("clone: %q", got)
	}
}

// stoppedBox is a box an explicit hold stopped: every exec is refused.
type stoppedBox struct{ sandboxremote.Client }

func (stoppedBox) Exec(context.Context, string, sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	return nil, errors.New("FailedPrecondition: sandbox is not running")
}

func (stoppedBox) Get(context.Context, string) (sandboxremote.BoxInfo, error) {
	return sandboxremote.BoxInfo{ID: "obsbox"}, nil
}

// TestOrgShellEndWordsWhenTheOrgEndedTheRun (FX4 fix round 1, F-P6B-1):
// after an admin revoke (or a drain) the box's stop cut the stream and the
// terminal said the box was held; the organization now answers the end
// report with the reason it ended the run, and the terminal says so, never
// that the box is held or that the organization "could not hold" it.
func TestOrgShellEndWordsWhenTheOrgEndedTheRun(t *testing.T) {
	cases := []struct {
		name     string
		cut      bool
		returnTo bool
		policy   string
		reason   string
	}{
		{"admin revoke, cut stream (H2 asked)", true, true, "on_disconnect", "org_signin_revoked"},
		{"admin revoke, return_to_node false (H1)", true, false, "on_disconnect", "org_signin_revoked"},
		{"drain, no hold policy, the return fails", false, true, "off", "org_openshell_draining"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldR, oldH := orgShellReport, orgShellHeldList
			orgShellReport = func(context.Context, *orgclient.Client, string, orgclient.OpenShellEnded) (orgclient.OpenShellEndedAnswer, error) {
				return orgclient.OpenShellEndedAnswer{Outcome: "ended_unreturned", Reason: tc.reason}, nil
			}
			orgShellHeldList = func(context.Context, *orgclient.Client) ([]orgclient.OpenShellHeldBox, error) { return nil, nil }
			t.Cleanup(func() { orgShellReport, orgShellHeldList = oldR, oldH })
			r := orgShellTestRun(t, stoppedBox{})
			var out strings.Builder
			r.t.out = &out
			r.rec = sandboxremote.NewIntent(r.plan.RunID, r.plan.Provider, "https://sandbox.example.com", "", r.plan.RunID, r.now(), time.Hour)
			r.rec.VendorID = "obsbox"
			_ = r.rec.Apply(sandboxremote.EvCreateOK)
			r.rec.State = sandboxremote.StateGone
			if tc.cut {
				r.cutStream(errors.New("openshellorg: exec relay closed before the command reported an exit status"))
			}
			orgShellRunState.Store(r.plan.RunID, &orgShellRun{tokens: &orgShellTokens{first: orgclient.OpenShellMint{ReturnToNode: tc.returnTo, HoldPolicy: tc.policy}}})
			if !orgShellEndRun(context.Background(), r) {
				t.Fatal("the end branch did not run")
			}
			s := out.String()
			if !strings.Contains(s, "your organization ended the run ("+tc.reason+")") {
				t.Errorf("the terminal did not say the organization ended the run: %s", s)
			}
			if strings.Contains(s, "held by your organization") || strings.Contains(s, "could not hold") || strings.Contains(s, "org-shell resume") {
				t.Errorf("the terminal still speaks of a hold: %s", s)
			}
		})
	}
}

// TestResumeFindsTheAgentsSessionAfterAPull (FX4 fix round 1, F-P6B-2b):
// live, the box's sessions.json named no session even after a completed
// turn, so a resume always started fresh. Nothing wrote it: the design had
// the guest relay record each hook frame's session id, which was never
// built, and an org box runs no hook by default. Now a transcript pull
// records the agent's own session ids (from the transcripts it ingested) in
// the box run dir's sessions.json, and a resume's native tail names the
// last one.
func TestResumeFindsTheAgentsSessionAfterAPull(t *testing.T) {
	ctx := context.Background()
	d, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	src, err := os.ReadFile(filepath.Join("..", "..", "testdata", "claudecode", "simple-session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorOpenShellOrg)
	c := newFakeBoxClient()
	info, err := c.Create(ctx, sandboxremote.BoxSpec{})
	if err != nil {
		t.Fatal(err)
	}
	lay := v.Layout(t.TempDir())
	c.boxes[info.ID].files[path.Join(lay.Home, ".claude", "projects", "-sandbox-workspace", "sess-001.jsonl")] = src
	var written string
	c.execs = func(_ *fakeBox, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
		switch {
		case len(spec.Argv) == 6 && spec.Argv[0] == "sh" && spec.Argv[2] == hostedWriteSessionsScript:
			if spec.Argv[4] != path.Join(lay.RunDir, "sessions.json") {
				t.Errorf("sessions.json written at %s", spec.Argv[4])
			}
			written = spec.Argv[5]
		case len(spec.Argv) == 3 && spec.Argv[0] == "cat":
			if written == "" {
				return newFakeProcess("", 1), nil
			}
			return newFakeProcess(written, 0), nil
		}
		return newFakeProcess("", 0), nil
	}
	var out strings.Builder
	r := &hostedRun{
		plan:   hostedPlanFile{RunID: "RunFxFourSessionsAAAAA", Provider: sandboxremote.VendorOpenShellOrg, Tool: "claude-code", ToolStateRel: []string{".claude"}, ObserverDir: t.TempDir()},
		client: c, layout: lay, now: time.Now, t: hostedTerm{out: &out},
		ingest: func(context.Context) (hostedIngester, func(), error) {
			return hostedIngestPulled(store.New(d)), func() {}, nil
		},
	}
	r.rec.VendorID = info.ID
	inner := []string{"/sandbox/run/bin/observer", "claude"}
	if got := r.withResumeArgs(inner); slices.Contains(got, "sess-001") {
		t.Fatalf("a resume before any pull named a session: %v", got)
	}
	r.pullAndIngest(ctx)
	var doc struct {
		Sessions []string `json:"sessions"`
		Last     string   `json:"last"`
	}
	if err := json.Unmarshal([]byte(written), &doc); err != nil || doc.Last != "sess-001" || !slices.Equal(doc.Sessions, []string{"sess-001"}) {
		t.Fatalf("sessions.json %q (%v)", written, err)
	}
	if got := r.withResumeArgs(inner); !slices.Contains(got, "sess-001") {
		t.Fatalf("the resume tail does not name the agent's session: %v (said %s)", got, out.String())
	}
}

// TestHostedSessionOrder: the session ids a pull records are ordered by
// their last event (the last is the one a resume continues), filtered to one
// printable token, and bounded to the newest hostedMaxSessions.
func TestHostedSessionOrder(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	last := map[string]time.Time{"b": t0.Add(2 * time.Second), "a": t0.Add(time.Second), "c": t0.Add(2 * time.Second), "-x": t0.Add(9 * time.Second), "a b": t0, "p|q": t0, strings.Repeat("z", 129): t0}
	if got := hostedSessionOrder(last); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("order %v", got)
	}
	many := map[string]time.Time{}
	for i := range 40 {
		many[fmt.Sprintf("s%02d", i)] = t0.Add(time.Duration(i) * time.Second)
	}
	got := hostedSessionOrder(many)
	if len(got) != hostedMaxSessions || got[0] != "s08" || got[len(got)-1] != "s39" {
		t.Fatalf("bounded %d: %v", len(got), got)
	}
}
