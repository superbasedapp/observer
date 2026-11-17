//go:build !sbo_omit_security

package dashboard

import (
	"net/http"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
)

// security_assess_retest.go is the dashboard side of the retest and the red team
// exercise's objective (depth plan W7.2 and W7.3, decision D38: labels only).
//
// A retest is a run of its own kind (pentest_retest) that replays the stored,
// validated requests of findings from an earlier penetration test or red team
// run. This file turns the request's of_run and finding ids into the basis the
// task is built from and the model is held to, answers the choices that cannot
// be used with a code of its own, and joins a run's retest labels onto its model
// answer at read time. Nothing here writes to the earlier run, closes a finding
// or changes any store status: a label is shown beside the finding and that is
// all it does.

// The refusals of a retest request. The words are the server's own sentence;
// the dialog shows it (web ASSESS_REFUSALS).
const (
	codeRetestRunUnknown  = "retest_run_unknown"
	codeRetestRunMismatch = "retest_run_mismatch"
	codeRetestNoModel     = "retest_no_model"
	codeRetestFindings    = "retest_findings"
	codeRetestHelper      = "retest_helper"
	codeRetestTooLarge    = "retest_too_large"
	// codeRetestNoExport is the refusal of an export of a retest run: its labels
	// are on the findings of the run it replayed, and it has no export of its own.
	codeRetestNoExport = "retest_no_export"
)

// The sentences of the refusals above.
const (
	reasonRetestRunUnknown  = "The run to retest is not in the run history, so nothing was started. Open the penetration test or red team run again and start the retest from there."
	reasonRetestRunMismatch = "That run belongs to another project, or it was not a penetration test or red team run, so it cannot be retested here. Nothing was started."
	reasonRetestNoModel     = "That run has no checked model kept, so there are no stored requests to replay. Check the run's model first. Nothing was started."
	reasonRetestChoose      = "Choose between 1 and 8 findings that have a stored request to replay. Nothing was started."
	reasonRetestHelper      = "A retest needs the request helper: it sends the stored requests and logs them, and a label with no log behind it is not worth a run. The helper is off, or was left out because python3 was not found, so nothing was started. Turn on \"" + secassess.LabelProbeHelper + "\" in " + secassess.WhereSettings + ", and install python3 on this machine if it was left out."
	reasonRetestTooLarge    = "The stored requests of these findings do not fit the request helper's settings file. Choose fewer findings. Nothing was started."
	reasonRetestNoExport    = "A retest has no export of its own: its labels are shown on the findings of the run it replayed."
)

// reasonRetestFinding is the sentence for one finding the retest cannot replay,
// by the code BuildRetestBasis gave it.
func reasonRetestFinding(r secassess.RetestRefusal) string {
	switch r.Code {
	case secassess.RetestNoRequest:
		return "The finding " + r.Finding + " has no stored request to replay (its reproduction is code or text only). Leave it out. Nothing was started."
	case secassess.RetestTooMany:
		return "A retest replays at most " + strconv.Itoa(secassess.MaxRetestFindings) + " findings. Leave " + r.Finding + " out, or run it in another retest. Nothing was started."
	case secassess.RetestDuplicate:
		return "The finding " + r.Finding + " was chosen twice. Nothing was started."
	}
	return "The finding " + r.Finding + " is not in the run's checked model. Nothing was started."
}

// securityAssessRetestGround is what a plan or a launch learned about the
// retest it was asked for: the earlier run, its replayable findings, the basis
// built from the ones chosen, and the first refusal, if any.
type securityAssessRetestGround struct {
	// ofID is the run id the request named (kept when the run is not found).
	ofID        string
	of          secassesssvc.Run
	requestable []secassess.RetestFinding
	basis       *secassess.RetestBasis
	refused     []secassess.RetestRefusal
	// code and reason are the first refusal ("" when the choices are usable).
	code, reason string
}

// securityAssessRetestGroundOf reads the earlier run and its stored model and
// builds the basis. The earlier run must be in the same project and a
// penetration test or red team run (the contract says which), and its stored
// model must have kept its findings. defaultAll takes the findings it can replay
// in full when none were chosen (secassess.DefaultRetestIDs; the plan's first
// answer, and a launch never does).
func (s *Server) securityAssessRetestGroundOf(in securityAssessGroundIn, defaultAll bool) *securityAssessRetestGround {
	g := &securityAssessRetestGround{ofID: in.Choices.RetestOf}
	runs := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath))
	of, ok := runs.Get(in.Choices.RetestOf)
	switch {
	case in.Choices.RetestOf == "" || !ok:
		g.code, g.reason = codeRetestRunUnknown, reasonRetestRunUnknown
		return g
	case of.ProjectRootHash != in.Hash || secassess.Contract(of.Contract) != secassess.ContractPentest || !of.IsStarted():
		g.code, g.reason = codeRetestRunMismatch, reasonRetestRunMismatch
		return g
	}
	g.of = of
	rec, ok := secassesssvc.ReadModel(runs.Side(), of.ID)
	if !ok || rec.Result.PT == nil || rec.Result.Report.State == secassess.ValidationInvalid {
		g.code, g.reason = codeRetestNoModel, reasonRetestNoModel
		return g
	}
	g.requestable = secassess.RetestRequestable(rec.Result.PT)
	ids := in.Choices.RetestFindings
	if len(ids) == 0 && defaultAll {
		// The findings the replay can send in full: one with a hidden value is
		// replayed without it, so most of a real run's findings are not chosen
		// for the developer (N-21); each can still be chosen by id.
		ids = secassess.DefaultRetestIDs(g.requestable, secassess.MaxRetestFindings)
	}
	basis, refused := secassess.BuildRetestBasis(of.ID, rec.Result.PT, ids)
	g.basis, g.refused = &basis, refused
	switch {
	case len(refused) > 0:
		g.code, g.reason = codeRetestFindings, reasonRetestFinding(refused[0])
	case len(basis.Findings) == 0:
		g.code, g.reason = codeRetestFindings, reasonRetestChoose
	case !secassesssvc.ReplayFits(basis.ReplaySet()):
		g.code, g.reason = codeRetestTooLarge, reasonRetestTooLarge
	}
	return g
}

// usable says the choices can start a run: an earlier run and a non-empty basis
// with no refusal.
func (g *securityAssessRetestGround) usable() bool {
	return g != nil && g.code == "" && g.basis != nil && len(g.basis.Findings) > 0
}

// replaySet is the helper's replay settings for the basis, nil when the retest
// is not usable (a run that is not a retest has none).
func (g *securityAssessRetestGround) replaySet() map[string]secassess.ReplayEntry {
	if !g.usable() {
		return nil
	}
	return g.basis.ReplaySet()
}

// ---- the plan's block ------------------------------------------------------

// securityAssessRetestFindingJS is one finding of the earlier run that a retest
// could replay: what the earlier run's checked model stored for it. Title and
// Condition are the earlier agent's own words (already redacted when stored),
// shown through the display redactor.
type securityAssessRetestFindingJS struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category,omitempty"`
	// Steps is how many stored requests the finding has, HasCondition says a
	// response condition was stored for it (without one no label can be backed)
	// and Condition says it in words.
	Steps        int    `json:"steps"`
	HasCondition bool   `json:"has_condition"`
	Condition    string `json:"condition,omitempty"`
	// Hidden says a stored request had a value hidden when it was kept, so the
	// replay may differ from the original request and a "not reproduced" label for
	// the finding is not backed by the log.
	Hidden bool `json:"hidden,omitempty"`
}

// securityAssessRetestRefusalJS names a finding the retest cannot replay and
// the closed word for why (no_request, unknown_finding, too_many, duplicate).
type securityAssessRetestRefusalJS struct {
	Finding string `json:"finding"`
	Code    string `json:"code"`
}

// securityAssessRetestPlanJS is the retest block of the plan.
type securityAssessRetestPlanJS struct {
	OfRun  string `json:"of_run"`
	OfKind string `json:"of_kind,omitempty"`
	// OfTarget is the target the earlier run confirmed, offered as the retest's
	// target to confirm again (it is never filled in for the developer).
	OfTarget string                          `json:"of_target,omitempty"`
	Findings []securityAssessRetestFindingJS `json:"findings"`
	Selected []string                        `json:"selected"`
	Max      int                             `json:"max"`
	Refused  []securityAssessRetestRefusalJS `json:"refused,omitempty"`
}

// securityAssessObjectiveJS is the objective block of the plan for a kind that
// asks for an exercise: the objective in force (cleaned) and its bound.
type securityAssessObjectiveJS struct {
	Text string `json:"text"`
	Max  int    `json:"max"`
}

// securityAssessRetestPlanView builds the retest block of the plan. redact is
// the display redactor (nil: hiding is off).
func securityAssessRetestPlanView(g *securityAssessRetestGround, redact func(string) string) *securityAssessRetestPlanJS {
	hide := func(s string) string {
		if redact == nil {
			return s
		}
		return redact(s)
	}
	out := &securityAssessRetestPlanJS{Findings: []securityAssessRetestFindingJS{}, Selected: []string{}, Max: secassess.MaxRetestFindings}
	if g == nil {
		return out
	}
	out.OfRun, out.OfKind, out.OfTarget = g.ofID, g.of.Kind, g.of.Target
	for _, f := range g.requestable {
		js := securityAssessRetestFindingJS{ID: f.ID, Title: hide(f.Title), Category: f.Category, Steps: len(f.Steps), Hidden: f.Hidden}
		if f.When != nil {
			js.HasCondition, js.Condition = true, hide(secassess.MatchWords(f.When))
		}
		out.Findings = append(out.Findings, js)
	}
	if g.basis != nil {
		out.Selected = g.basis.IDs()
	}
	for _, r := range g.refused {
		out.Refused = append(out.Refused, securityAssessRetestRefusalJS{Finding: r.Finding, Code: r.Code})
	}
	return out
}

// ---- reading a retest's file and a run's retests ---------------------------

// securityAssessRetestBasisOf rebuilds the basis a retest run is held to from
// the earlier run's stored model and the finding ids the retest recorded at
// launch, nil when the run is not a retest or the earlier model is gone (the
// validator then refuses the file in words rather than label against nothing).
func securityAssessRetestBasisOf(runs *secassesssvc.Store, run secassesssvc.Run) *secassess.RetestBasis {
	if run.RetestOf == "" || len(run.RetestFindings) == 0 {
		return nil
	}
	rec, ok := secassesssvc.ReadModel(runs.Side(), run.RetestOf)
	if !ok || rec.Result.PT == nil {
		return nil
	}
	basis, refused := secassess.BuildRetestBasis(run.RetestOf, rec.Result.PT, run.RetestFindings)
	if len(refused) > 0 || len(basis.Findings) == 0 {
		return nil
	}
	return &basis
}

// attachRetests adds the retests of a run to the model answer: for a run whose
// contract is the penetration test's, the labels its retest runs gave, newest
// first, through the display redactor (the agent's note is the only free text).
func (m *securityAssessModelJS) attachRetests(runs *secassesssvc.Store, runID string, redact func(string) string) {
	if m.Record.Contract != secassess.ContractPentest {
		return
	}
	views := secassesssvc.ReadRetests(runs.Side(), runs.All(), runID)
	if redact != nil {
		for i := range views {
			for j := range views[i].Results {
				n, hidden := secassess.RedactValue(views[i].Results[j].Note, redact)
				views[i].Results[j].Note = n
				m.Redaction.Hidden += hidden
			}
		}
	}
	m.Retests = views
}

// securityAssessRefuseExport answers an export of a run that has none (a
// retest) and says so (true).
func securityAssessRefuseExport(w http.ResponseWriter, run secassesssvc.Run) bool {
	k, ok := secassess.KindByID(run.Kind)
	if !ok || !k.FromRun() {
		return false
	}
	writeJSONStatus(w, http.StatusConflict, map[string]string{"error": reasonRetestNoExport, "code": codeRetestNoExport})
	return true
}
