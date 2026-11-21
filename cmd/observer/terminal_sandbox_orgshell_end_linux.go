//go:build linux && !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"time"

	osorg "github.com/marmutapp/superbased-observer/internal/openshellorg"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// terminal_sandbox_orgshell_end_linux.go is the org-hosted row's end of a
// run (g1-design.md section 3.2 step 10, G1-R30, G1-R37, lane G4). The
// helper pulls the last transcripts and takes one of three branches, read
// from the run's recorded return_to_node and hold_policy (the first mint's
// answer) and the member's own hold_on_end:
//
//   - hold (H1): no return, nothing deleted; the end report asks for the
//     hold and the org's worker stops the box;
//   - return and delete: a return token, the staged diff and the commits
//     bundle saved home (never applied), a teardown token, the delete
//     through the front confirmed gone, then the end report with
//     returned = true;
//   - end without a return: the return failed (or cannot be held); the
//     helper reports the end and never deletes a box it has not returned:
//     the org collects, then deletes.
//
// A dropped stream never assumes the in-box process survived (OB-079): the
// branch reads only the recorded facts and what the box still answers.

// orgShellEndBranch is one end branch.
type orgShellEndBranch string

// The closed end branches.
const (
	orgShellEndHold     orgShellEndBranch = "hold"
	orgShellEndReturn   orgShellEndBranch = "return_and_delete"
	orgShellEndNoReturn orgShellEndBranch = "end_without_return"
)

// orgShellEndFacts are what the branch table reads.
type orgShellEndFacts struct {
	ReturnToNode bool
	HoldPolicy   string
	HoldOnEnd    bool
	// StreamCut: the agent's stream ended without the agent's exit (a cut
	// connection, a front refusal), not the run's end (FX3 item 9).
	StreamCut bool
}

// orgShellEndRows is the branch table, walked top-down (one test case per
// row).
var orgShellEndRows = []struct {
	name   string
	match  func(orgShellEndFacts) bool
	branch orgShellEndBranch
}{
	// The one case the server forces: the work stays off this machine.
	{"return_to_node false", func(f orgShellEndFacts) bool { return !f.ReturnToNode }, orgShellEndHold},
	// A cut stream is not the run's end: held as a disconnect (H2) wherever
	// the organization holds at all, never returned and deleted from here.
	{"stream cut with a hold policy", func(f orgShellEndFacts) bool {
		return f.StreamCut && f.HoldPolicy != "" && f.HoldPolicy != string(osorg.HoldOff)
	}, orgShellEndHold},
	// The member's own preference, honoured only where the org holds on end.
	{"hold_on_end with on_disconnect_and_end", func(f orgShellEndFacts) bool {
		return f.HoldOnEnd && f.HoldPolicy == string(osorg.HoldOnDisconnectAndEnd)
	}, orgShellEndHold},
	{"otherwise return and delete", func(orgShellEndFacts) bool { return true }, orgShellEndReturn},
}

// orgShellEndBranchFor picks the branch.
func orgShellEndBranchFor(f orgShellEndFacts) orgShellEndBranch {
	for _, r := range orgShellEndRows {
		if r.match(f) {
			return r.branch
		}
	}
	return orgShellEndNoReturn
}

// orgShellReport is the end report seam (a variable for tests).
var orgShellReport = func(ctx context.Context, c *orgclient.Client, run string, rep orgclient.OpenShellEnded) (orgclient.OpenShellEndedAnswer, error) {
	return c.OpenShellEndedReport(ctx, run, rep)
}

// orgShellEndRun takes the run's end branch; false leaves the shared
// teardown to run (no org-shell state for the run).
func orgShellEndRun(ctx context.Context, r *hostedRun) bool {
	v, ok := orgShellRunState.LoadAndDelete(r.plan.RunID)
	if !ok {
		return false
	}
	st := v.(*orgShellRun)
	first := st.tokens.First()
	// The node ledger's unit, so both ledgers settle alike (F-L3P4-3).
	minutes := sandboxremote.RanMinutes(r.now().Sub(r.start))
	if r.rec.State == sandboxremote.StateRunning || r.rec.State == sandboxremote.StateCreated {
		_ = r.rec.Apply(sandboxremote.EvPullBegin)
		_ = hostedSaveRecord(r.plan.ObserverDir, r.rec)
		pctx, cancel := context.WithTimeout(ctx, hostedTeardownPullTimeout)
		r.pullAndIngest(pctx)
		cancel()
	}
	facts := orgShellEndFacts{ReturnToNode: first.ReturnToNode, HoldPolicy: first.HoldPolicy, HoldOnEnd: st.holdOnEnd, StreamCut: r.streamCut != nil}
	branch := orgShellEndBranchFor(facts)
	switch branch {
	case orgShellEndHold:
		ans, err := orgShellReport(ctx, st.client, r.plan.RunID, orgclient.OpenShellEnded{Hold: true, Disconnected: facts.StreamCut, BoxMinutes: minutes})
		switch {
		case err == nil && ans.Outcome == "hold":
			r.heldAtEnd = r.orgShellListedHeld(ctx, st.client, first.BoxRunID)
			r.say("the box is held by your organization (resume it with `observer sandbox org-shell resume %s` from any of your managed machines)", r.orgShellHeldID(first.BoxRunID))
		case err == nil && orgShellOrgEnded(ans.Reason):
			// The organization ended the run (an admin revoke, a drain): the
			// cut was its box's stop, nothing is held (F-P6B-1).
			r.orgShellSayOrgEnded(ans.Reason)
		case r.orgShellSayHeld(ctx, st.client, first.BoxRunID):
			// Held already (the front's disconnect, H2, or an explicit
			// hold, H3): the held state's own facts said so (F-P6-4).
		case err != nil && facts.StreamCut:
			// A cut often takes the report with it; the organization still
			// holds on the disconnect it saw (FX3 item 7, F-L3P4-7).
			r.say("the end report did not reach your organization (%v); it holds the box on the disconnect its front saw: resume it with `observer sandbox org-shell resume %s`, or, if it was not held, its reaper collects the work", err, r.orgShellHeldID(first.BoxRunID))
		case err != nil:
			r.say("the end report did not reach your organization (%v); its reaper settles the box", err)
		default:
			r.say("your organization could not hold the box (%s); %s", ans.Reason, hostedBoxFateWords[hostedFateCollected])
		}
		r.handOver()
		return true
	case orgShellEndReturn:
		if r.orgShellReturn(ctx) {
			if err := r.orgShellDelete(ctx); err == nil {
				if _, err := orgShellReport(ctx, st.client, r.plan.RunID, orgclient.OpenShellEnded{Returned: true, BoxMinutes: minutes}); err != nil {
					r.say("the end report did not reach your organization (%v); its reaper settles the box", err)
				}
				_ = r.rec.Apply(sandboxremote.EvDeleteConfirm)
				_ = hostedRemoveRecord(r.plan.ObserverDir, r.rec)
				r.settle()
				r.say("the %s box was deleted (confirmed by your organization's front)", r.vendor.Name)
				return true
			}
		}
	}
	// End without a return: never delete a box whose work did not come home.
	ans, err := orgShellReport(ctx, st.client, r.plan.RunID, orgclient.OpenShellEnded{BoxMinutes: minutes})
	switch {
	case err != nil:
		r.say("the end report did not reach your organization (%v); its reaper settles the box", err)
	case orgShellOrgEnded(ans.Reason):
		r.orgShellSayOrgEnded(ans.Reason)
		r.handOver()
		return true
	}
	if !r.orgShellSayHeld(ctx, st.client, first.BoxRunID) {
		r.say("the box's work did not come home here; %s", hostedBoxFateWords[hostedFateCollected])
	}
	r.handOver()
	return true
}

// orgShellHeldID is the run id the organization holds this run's box
// under, the id `org-shell held` lists: a resumed run's box keeps the held
// run's id (F-P6-5: the hint named the resumed run's own id). box is the id
// the organization's mint named the box under (its ledger key) and wins
// when well-formed (lane FX6, F-P7-3): a resume asked by a resumed run's
// own id still names the box's ledger key, which every verb accepts.
func (r *hostedRun) orgShellHeldID(box string) string {
	if id, err := orgShellRunArg([]string{box}); err == nil {
		return id
	}
	if r.plan.ResumeBoxRunID != "" {
		return r.plan.ResumeBoxRunID
	}
	return r.plan.RunID
}

// orgShellHeldList is the member's held-box listing (a variable for
// tests).
var orgShellHeldList = func(ctx context.Context, c *orgclient.Client) ([]orgclient.OpenShellHeldBox, error) {
	if c == nil {
		return nil, nil
	}
	return c.OpenShellHeld(ctx)
}

// orgShellSayHeld says the box is held when the organization lists this
// run's box as holding or held, with the reason it records and the id to
// resume (F-P6-4: after a long network cut, or an explicit `org-shell
// hold`, the terminal said the organization collects and deletes a box it
// held). It reports whether it said so (and marks the run held at its end
// when the state is held, hostedEndCode); an unanswered listing says
// nothing.
func (r *hostedRun) orgShellSayHeld(ctx context.Context, c *orgclient.Client, box string) bool {
	lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	boxes, err := orgShellHeldList(lctx, c)
	if err != nil {
		return false
	}
	id := r.orgShellHeldID(box)
	for _, b := range boxes {
		if b.RunID != id || (b.State != string(osorg.BoxHolding) && b.State != string(osorg.BoxHeld)) {
			continue
		}
		why := ""
		if b.Reason != "" {
			why = " (" + b.Reason + ")"
		}
		r.say("the box is held by your organization%s; resume it with `observer sandbox org-shell resume %s` from any of your managed machines", why, id)
		// Only a box the organization lists HELD (stopped and kept) marks the
		// run held at its end; holding is not yet held (FX6-R4).
		r.heldAtEnd = b.State == string(osorg.BoxHeld)
		return true
	}
	return false
}

// orgShellReturn takes the return with a return token: the staged diff and
// the commits bundle, saved home owner-only and never applied. It reports
// whether the diff was saved (the bundle is best effort: no commits is not a
// failure).
func (r *hostedRun) orgShellReturn(ctx context.Context) bool {
	rctx := sandboxremote.WithTokenPurpose(ctx, string(osorg.PurposeReturn))
	pctx, cancel := context.WithTimeout(rctx, hostedTeardownPullTimeout)
	defer cancel()
	r.rec.DiffError = ""
	r.saveStagedDiff(pctx)
	if r.rec.DiffError != "" {
		return false
	}
	out, code, err := hostedExecOutputIn(pctx, r.client, r.rec.VendorID, sandboxremote.ExecSpec{
		Argv: []string{r.layout.Binary, "sandbox-guest", guestBundleFlag}, Env: r.boxEnv(), Cwd: r.layout.Workspace,
	}, guestReturnMax)
	return r.orgShellSaveBundle(out, code, err)
}

// orgShellSaveBundle saves the commits bundle the box answered. A bundle
// that failed, was cut at its cap or could not be saved is a failed return
// (fix round 1, A12): the box is then not deleted from here, so its commit
// history is collected by the organization instead of lost. No commits
// since the baseline (exit 2, or no bytes) is a return with nothing to save.
func (r *hostedRun) orgShellSaveBundle(out []byte, code int, err error) bool {
	switch {
	case err != nil:
		r.say("the box's commits were not saved (%v); the box is kept for your organization to collect", err)
		return false
	case code == 2 || (code == 0 && len(out) == 0):
		return true
	case code != 0:
		r.say("the box's commits were not saved (the bundle exited %d, 3 means over its size cap); the box is kept for your organization to collect", code)
		return false
	}
	dir := filepath.Join(hostedStateDir(r.plan.ObserverDir), "returns")
	p := filepath.Join(dir, r.plan.RunID+".bundle")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		r.say("the box's commits were not saved (%v); the box is kept for your organization to collect", err)
		return false
	}
	if err := os.WriteFile(p, out, 0o600); err != nil {
		r.say("the box's commits were not saved (%v); the box is kept for your organization to collect", err)
		return false
	}
	r.say("the box's commits are saved as a git bundle at %s (not applied; `git fetch %s` it into a repository to review)", p, p)
	return true
}

// orgShellDelete deletes the box through the front with a teardown token
// (the wire client's Delete names that purpose) and confirms it gone.
func (r *hostedRun) orgShellDelete(ctx context.Context) error {
	_ = r.rec.Apply(sandboxremote.EvDeleteSent)
	_ = hostedSaveRecord(r.plan.ObserverDir, r.rec)
	dctx, cancel := context.WithTimeout(ctx, hostedTeardownDeleteTimeout)
	defer cancel()
	if err := hostedDeleteConfirmed(dctx, r.client, r.rec.VendorID); err != nil {
		_ = r.rec.Apply(sandboxremote.EvDeleteFailed)
		r.rec.LastError = err.Error()
		_ = hostedSaveRecord(r.plan.ObserverDir, r.rec)
		r.say("the box could not be deleted (%v); your organization's reaper collects and deletes it", err)
		return err
	}
	return nil
}

// orgShellOrgEndedReasons are the end-report answers that say the
// organization itself ended the run before the report (FX4 fix round 1,
// F-P6B-1): an admin revoke, a drain, a disabled member. No hold is
// accepted then; the organization collects the work, then deletes the box.
var orgShellOrgEndedReasons = map[string]bool{
	string(osorg.ReasonSigninRevoked):    true,
	string(osorg.ReasonDraining):         true,
	string(osorg.ReasonMemberNotAllowed): true,
}

// orgShellOrgEnded reports whether an end-report reason is one of them.
func orgShellOrgEnded(reason string) bool { return orgShellOrgEndedReasons[reason] }

// orgShellSayOrgEnded says the organization ended the run, as the logout
// path's refusal does, and what happens to the box.
func (r *hostedRun) orgShellSayOrgEnded(reason string) {
	r.say("your organization ended the run (%s); %s", reason, hostedBoxFateWords[hostedFateOrgEnded])
}

// orgShellListedHeld reports whether the organization lists this run's box
// HELD (stopped and kept; holding is not yet held), saying nothing: what
// marks a run held at its end for its exit code (lane FX6, FX6-R4).
func (r *hostedRun) orgShellListedHeld(ctx context.Context, c *orgclient.Client, box string) bool {
	lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	boxes, err := orgShellHeldList(lctx, c)
	if err != nil {
		return false
	}
	id := r.orgShellHeldID(box)
	for _, b := range boxes {
		if b.RunID == id && b.State == string(osorg.BoxHeld) {
			return true
		}
	}
	return false
}
