//go:build !sbo_omit_security

package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
)

// security_assess_model.go is the model part of the Security assessments routes
// (docs/plans/security-assessments-depth-plan-2026-11-14.md, W1b): the agent of
// a threat model, penetration test or red team run writes an assessment.json;
// Observer reads it through the confined reader, checks its structure and the
// file references in it against the project, and keeps a checked copy beside
// the run record.
//
//	POST /api/security/assessments/validate  validates a run's assessment.json
//	GET  /api/security/assessments/model     reads the stored, checked copy, with
//	                                        the reading, the diagram source and,
//	                                        with since=, the comparison
//
// Both are owner-local: validating reads project files, and the stored copy
// holds the agent's words about the code.
//
// What the model answer carries beyond the stored copy (depth plan W5a and
// W6a) is computed here from that copy and nothing else: the clean-reading
// sentence and the coverage line, the data-flow diagram source (a threat
// model), the vocabulary the web needs to name categories, and the comparison
// with an earlier run of the same project and kind (secassess.DiffModels).
// Every string of the answer passes the redactor in force (setting
// display_redaction); the files in the project are never touched.

// Machine codes of a refused validation.
const (
	codeNoModelContract = "no_model_contract"
	codeModelNotStarted = "not_started"
	codeRunStillRunning = "run_running"
	codeNoModelFile     = "no_model"
	codeProjectGone     = "project_gone"
)

// securityAssessValidationJS is the run row's view of the last validation:
// numbers and enums only; the sentences are the web's.
type securityAssessValidationJS struct {
	// State is valid, partial or invalid (secassess.ValidationState).
	State string    `json:"state"`
	At    time.Time `json:"at"`
	// Fatal is the closed reason code of a refused file.
	Fatal string `json:"fatal,omitempty"`
	// Anyway: validated before the run ended.
	Anyway bool `json:"anyway,omitempty"`
	// Stale: assessment.json changed after this validation.
	Stale   bool               `json:"stale,omitempty"`
	Refs    secassess.RefTally `json:"refs"`
	Issues  int                `json:"issues,omitempty"`
	Refused int                `json:"refused,omitempty"`
	// RefWindowLines is the match window the references were checked under
	// (setting ref_match_window_lines) and RefTextHidden how many references
	// quoted text the redactor changed and did not read found: the conditions of
	// Refs. Absent for a check that predates them.
	RefWindowLines int `json:"ref_window_lines,omitempty"`
	RefTextHidden  int `json:"ref_text_hidden,omitempty"`
}

// securityAssessValidationView returns the run's validation for the row, nil
// when it has none.
func securityAssessValidationView(r secassesssvc.Run, v secassesssvc.View) *securityAssessValidationJS {
	rec := r.Validation
	if rec == nil {
		return nil
	}
	return &securityAssessValidationJS{
		State: rec.State, At: rec.At, Fatal: rec.Fatal, Anyway: rec.Anyway, Stale: v.ModelStale,
		Refs: rec.Refs, Issues: rec.Issues, Refused: rec.Refused,
		RefWindowLines: rec.RefWindow, RefTextHidden: rec.RefTextHidden,
	}
}

type securityAssessValidateBody struct {
	Run string `json:"run"`
	// Anyway validates a run whose terminal has not ended; the model may be
	// partial and the record says so.
	Anyway bool `json:"anyway,omitempty"`
}

// handleSecurityAssessValidate serves POST /api/security/assessments/validate
// {run, anyway}: it validates the run's assessment.json, keeps the checked copy
// and the run's scalar outcome, and answers with the run's row.
func (s *Server) handleSecurityAssessValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	var body securityAssessValidateBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, securityAssessBodyMax)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	run, root, found, err := s.securityAssessRunRoot(ctx, body.Run)
	if err != nil {
		s.writeSecurityAssessRunErr(w, err)
		return
	}
	if !found {
		http.Error(w, "unknown run", http.StatusNotFound)
		return
	}
	if root == "" {
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "the project's folder is no longer on this machine", "code": codeProjectGone})
		return
	}
	runs := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath))
	_, rec, err := secassesssvc.ValidateRun(ctx, runs.Side(), secassesssvc.ModelInput{
		ProjectRoot: root, Run: run, Options: s.securityAssessValidateOptions(run), Anyway: body.Anyway, Now: time.Now(),
		Budget:      securityAssessRefBudget(s.securityAssessConfig().Security.Assessments),
		PreviousRun: run.PreviousRun, Previous: secassesssvc.PreviousModel(runs.Side(), run.PreviousRun),
		Retest: securityAssessRetestBasisOf(runs, run),
	})
	if err != nil {
		s.writeSecurityAssessValidateError(w, err)
		return
	}
	if err := runs.SetValidation(run.ID, rec); err != nil {
		writeErrStatus(w, err, http.StatusInternalServerError)
		return
	}
	run.Validation = &rec
	if secassess.ReportValidation(secassess.Tenancy(run.Tenancy), run.Reported, s.securityAssessConfig().Security.Assessments.ReportValidationToOrg) {
		s.securityAssessAudit(ctx, true, "validated", run.ProjectRootHash, "", securityAssessValidatedDetail(run.ID, rec))
	}
	writeJSON(w, map[string]any{"run": s.securityAssessRunViewFull(ctx, run, root)})
}

// writeSecurityAssessValidateError maps a refused validation to its status and
// machine code, one row each.
func (s *Server) writeSecurityAssessValidateError(w http.ResponseWriter, err error) {
	rows := []struct {
		err    error
		status int
		code   string
		msg    string
	}{
		{secassesssvc.ErrNoModelContract, http.StatusConflict, codeNoModelContract, "this run was not started under a result contract that has a model to validate"},
		{secassesssvc.ErrRunNotStarted, http.StatusConflict, codeModelNotStarted, "the run has not started"},
		{secassesssvc.ErrRunRunning, http.StatusConflict, codeRunStillRunning, "the run has not ended, so its model may still be written; validate again when it ends, or validate anyway"},
		{secassesssvc.ErrAbsent, http.StatusConflict, codeNoModelFile, "the run has not written assessment.json yet"},
		{secassesssvc.ErrValidationTimeout, http.StatusGatewayTimeout, "validation_timeout", "the validation did not finish in time"},
	}
	for _, row := range rows {
		if errors.Is(err, row.err) {
			writeJSONStatus(w, row.status, map[string]string{"error": row.msg, "code": row.code})
			return
		}
	}
	writeErrStatus(w, err, http.StatusInternalServerError)
}

// The redaction header and marker: the report route says how many places it
// hid in the text it served (absent when hiding is off), counted by the
// redactor's own marker.
const (
	redactedHeader = "X-Observer-Redacted"
	redactedMarker = "[REDACTED"
)

// Machine codes of a refused comparison.
const (
	codeSinceUnknown  = "since_unknown"
	codeSinceMismatch = "since_mismatch"
	codeSinceNoModel  = "since_no_model"
	codeSinceNotTM    = "since_not_threat_model"
	// codeSinceLater: the run to compare with was started after this run, and
	// the comparison reads "what changed since": earlier run to later.
	codeSinceLater = "since_not_earlier"
)

// securityAssessRedactionJS says whether the answer's strings were redacted and
// how many were changed.
type securityAssessRedactionJS struct {
	On     bool `json:"on"`
	Hidden int  `json:"hidden"`
}

// securityAssessModelJS is the stored, checked copy with what has changed since.
type securityAssessModelJS struct {
	Record secassesssvc.ModelRecord `json:"record"`
	// Stale: assessment.json is not the file that was validated.
	Stale bool `json:"stale"`
	// Drift lists the project files the references were checked against that
	// read differently now.
	Drift []string `json:"drift,omitempty"`
	// Reading is secassess.CleanReading: set only when the model holds no
	// threat and no finding, and then always with what that does not mean.
	Reading string `json:"reading,omitempty"`
	// CoverageLine is secassess.CoverageLine: what the agent covered.
	CoverageLine string `json:"coverage_line,omitempty"`
	// Mermaid is the data-flow diagram source (a threat model only).
	Mermaid *secassess.MermaidDiagram `json:"mermaid,omitempty"`
	// Vocab names the categories of the closed word lists.
	Vocab     secassess.ModelVocabulary `json:"vocab"`
	Redaction securityAssessRedactionJS `json:"redaction"`
	// Since is the comparison with the earlier run the request named.
	Since *secassess.ModelDiff `json:"since,omitempty"`
	// Probes are the log records the checked model cites, as Observer stored
	// them (redacted again when hiding is on), and ProbeLog says how many the
	// log held and how many this answer carries (a pen test or red team run
	// that had the request helper).
	Probes   []secassess.ProbeRecord   `json:"probes,omitempty"`
	ProbeLog *securityAssessProbeLogJS `json:"probe_log,omitempty"`
	// Retests are the labels the retests of this run gave its findings, newest
	// retest first (a penetration test or red team run; depth plan W7.2). They
	// are read from the retest runs' own stored copies and change nothing here.
	Retests []secassesssvc.RetestView `json:"retests,omitempty"`
}

// securityAssessProbeLogJS is how much of the helper's log an answer carries.
type securityAssessProbeLogJS struct {
	Records   int  `json:"records"`
	Shown     int  `json:"shown"`
	Truncated bool `json:"truncated"`
}

// attachProbes adds the stored copy of the cited log records to the answer,
// through the same redactor as the rest of it (nil: hiding is off).
func (m *securityAssessModelJS) attachProbes(side *secassesssvc.SideData, runID string, redact func(string) string) {
	rec, ok := secassesssvc.ReadProbes(side, runID)
	if !ok {
		return
	}
	probes, n := secassess.ShownProbes(rec.Probes, redact)
	m.Redaction.Hidden += n
	m.Probes = probes
	m.ProbeLog = &securityAssessProbeLogJS{Records: rec.Records, Shown: len(probes), Truncated: rec.Truncated || rec.Cited > len(probes)}
}

// writeSinceRefused answers a comparison that cannot be made, in words.
func writeSinceRefused(w http.ResponseWriter, code, msg string) {
	writeJSONStatus(w, http.StatusConflict, map[string]string{"error": msg, "code": code})
}

// handleSecurityAssessModel serves GET /api/security/assessments/model?run=[&since=]:
// the stored copy of the run's validation, built by Observer (never the
// agent's file as written), what changed in the project since, the reading and
// diagram computed from it, and, when asked, the comparison with an earlier
// run.
func (s *Server) handleSecurityAssessModel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	run, root, found, err := s.securityAssessRunRoot(ctx, r.URL.Query().Get("run"))
	if err != nil {
		s.writeSecurityAssessRunErr(w, err)
		return
	}
	if !found {
		http.Error(w, "unknown run", http.StatusNotFound)
		return
	}
	side := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath)).Side()
	rec, ok := secassesssvc.ReadModel(side, run.ID)
	if !ok {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "no stored model for this run", "code": "no_stored_model"})
		return
	}
	cfg := s.securityAssessConfig()
	a := cfg.Security.Assessments
	out := securityAssessModelJS{Record: rec, Vocab: secassess.ModelVocab()}
	if root != "" {
		out.Stale = secassesssvc.Describe(root, run).ModelStale
		out.Drift, _ = secassesssvc.StampsDriftWithin(root, rec.Files, securityAssessRefBudget(a))
	}
	if since := r.URL.Query().Get("since"); since != "" {
		diff, code, msg := s.securityAssessDiff(side, run, rec, since)
		if code != "" {
			writeSinceRefused(w, code, msg)
			return
		}
		out.Since = &diff
	}
	redact, identity := securityAssessRedactorOf(cfg)
	res, hidden := s.displayResult(rec, redact, identity)
	out.finish(res, hidden, redact, a)
	out.attachProbes(side, run.ID, redact)
	out.attachRetests(secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath)), run.ID, redact)
	writeJSON(w, out)
}

// securityAssessDiff compares the run's stored threat model with an earlier
// run's of the same project and kind. A refusal comes back as a code and the
// words for it; the comparison is made from the two stored copies, and nothing
// of the earlier model goes to an agent.
func (s *Server) securityAssessDiff(side *secassesssvc.SideData, run secassesssvc.Run, cur secassesssvc.ModelRecord, since string) (secassess.ModelDiff, string, string) {
	runs := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath))
	prev, ok := runs.Get(since)
	switch {
	case !ok || prev.ID == run.ID:
		return secassess.ModelDiff{}, codeSinceUnknown, "the run to compare with is not listed, or it is this run"
	case prev.ProjectRootHash != run.ProjectRootHash || prev.Kind != run.Kind:
		return secassess.ModelDiff{}, codeSinceMismatch, "a run can be compared only with an earlier run of the same project and the same kind of assessment"
	case prev.CreatedAt.After(run.CreatedAt):
		return secassess.ModelDiff{}, codeSinceLater, "the run to compare with was started after this run; compare a run with an earlier one"
	case secassess.Contract(run.Contract) != secassess.ContractThreatModel || cur.Result.TM == nil:
		return secassess.ModelDiff{}, codeSinceNotTM, "only a threat model with a kept model can be compared with an earlier run"
	}
	old, ok := secassesssvc.ReadModel(side, prev.ID)
	if !ok || old.Result.TM == nil {
		return secassess.ModelDiff{}, codeSinceNoModel, "the earlier run has no stored model to compare with (it was deleted, or its model was not kept)"
	}
	diff := secassess.DiffModels(old.Result.TM, cur.Result.TM)
	diff.PrevRun = prev.ID
	return diff, "", ""
}
