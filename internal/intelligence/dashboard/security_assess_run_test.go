//go:build !sbo_omit_security

package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
)

// TestSecurityAssessLimitsFor: the time box, the deadline action and the audit
// switch in force come from the config, one case per row.
func TestSecurityAssessLimitsFor(t *testing.T) {
	cases := []struct {
		name   string
		kind   secassess.ID
		mutate func(a *config.SecurityAssessmentsConfig)
		want   securityAssessLimits
	}{
		{
			"defaults: threat model", secassess.ThreatModel, func(*config.SecurityAssessmentsConfig) {},
			securityAssessLimits{Minutes: 60, Action: secassess.TimeBoxStopButton, AuditOn: true},
		},
		{
			"defaults: pen test", secassess.PentestLocal, func(*config.SecurityAssessmentsConfig) {},
			securityAssessLimits{Minutes: 45, Action: secassess.TimeBoxStopButton, AuditOn: true},
		},
		{
			"defaults: red team", secassess.RedTeamLocal, func(*config.SecurityAssessmentsConfig) {},
			securityAssessLimits{Minutes: 60, Action: secassess.TimeBoxStopButton, AuditOn: true},
		},
		{
			"a configured pen test box", secassess.PentestLocal, func(a *config.SecurityAssessmentsConfig) { a.TimeBoxPentestLocalMinutes = 90 },
			securityAssessLimits{Minutes: 90, Action: secassess.TimeBoxStopButton, AuditOn: true},
		},
		{
			"a configured box is for its own kind only", secassess.ThreatModel, func(a *config.SecurityAssessmentsConfig) { a.TimeBoxPentestLocalMinutes = 90 },
			securityAssessLimits{Minutes: 60, Action: secassess.TimeBoxStopButton, AuditOn: true},
		},
		{
			"auto close", secassess.RedTeamLocal, func(a *config.SecurityAssessmentsConfig) { a.TimeBoxAction = secassess.TimeBoxAutoClose },
			securityAssessLimits{Minutes: 60, Action: secassess.TimeBoxAutoClose, AuditOn: true},
		},
		{
			"an unknown action reads as the stop button", secassess.RedTeamLocal, func(a *config.SecurityAssessmentsConfig) { a.TimeBoxAction = "kill" },
			securityAssessLimits{Minutes: 60, Action: secassess.TimeBoxStopButton, AuditOn: true},
		},
		{
			"the audit off", secassess.ThreatModel, func(a *config.SecurityAssessmentsConfig) { a.BoundaryAudit = false },
			securityAssessLimits{Minutes: 60, Action: secassess.TimeBoxStopButton, AuditOn: false},
		},
		{
			"a zero box falls back to the kind's default", secassess.PentestLocal, func(a *config.SecurityAssessmentsConfig) { a.TimeBoxPentestLocalMinutes = 0 },
			securityAssessLimits{Minutes: 45, Action: secassess.TimeBoxStopButton, AuditOn: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k, ok := secassess.KindByID(string(tc.kind))
			if !ok {
				t.Fatalf("no kind %q", tc.kind)
			}
			a := config.Default().Security.Assessments
			tc.mutate(&a)
			if got := securityAssessLimitsFor(k, a); got != tc.want {
				t.Fatalf("limits = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestSecurityAssessLimitsView: the plan's "settings in force" block says an
// approval ends first when the time box is longer than the relaxation window,
// and says nothing of the kind otherwise.
func TestSecurityAssessLimitsView(t *testing.T) {
	pt, _ := secassess.KindByID(string(secassess.PentestLocal))
	tm, _ := secassess.KindByID(string(secassess.ThreatModel))
	cases := []struct {
		name  string
		kind  secassess.Kind
		mins  int
		relax int
		note  string
	}{
		{"inside the window", pt, 45, 60, ""},
		{"longer than the window", pt, 90, 60, "approvals end at your cap, 60 minutes in"},
		{"the same as the window", pt, 60, 60, ""},
		{"a kind with no relaxation never says it", tm, 120, 60, ""},
		{"no window", pt, 90, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := securityAssessLimitsView(tc.kind, securityAssessLimits{Minutes: tc.mins, Action: secassess.TimeBoxStopButton, AuditOn: true}, tc.relax)
			if v.RelaxationNote != tc.note || v.TimeBoxMinutes != tc.mins || !v.BoundaryAudit {
				t.Fatalf("view = %+v", v)
			}
			if v.AuditLimits != secassess.AuditLimits || v.AuditPolicy != string(tc.kind.TreePolicy) {
				t.Fatalf("audit words = %+v", v)
			}
		})
	}
}

// TestSecurityAssessTimeView: the run row's deadline, over-time-box flag, Stop
// and audit words are derived from the run record alone.
func TestSecurityAssessTimeView(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	started := now.Add(-50 * time.Minute)
	base := secassesssvc.Run{ID: secassesssvc.NewRunID(), Kind: "pentest_local", Handle: "H1", ConfirmedAt: started, TimeBoxMinutes: 45}
	cases := []struct {
		name   string
		mutate func(r *secassesssvc.Run)
		check  func(t *testing.T, v securityAssessTimeJS)
	}{
		{"a live run past its box offers Stop", func(*secassesssvc.Run) {}, func(t *testing.T, v securityAssessTimeJS) {
			if !v.OverTimeBox || !v.CanStop || v.Deadline == nil || !v.Deadline.Equal(started.Add(45*time.Minute)) {
				t.Fatalf("view = %+v", v)
			}
			if v.Audit != auditPending || v.TimeBoxAction != secassess.TimeBoxStopButton {
				t.Fatalf("audit = %q action = %q", v.Audit, v.TimeBoxAction)
			}
		}},
		{"a live run inside its box", func(r *secassesssvc.Run) { r.ConfirmedAt = now.Add(-10 * time.Minute) }, func(t *testing.T, v securityAssessTimeJS) {
			if v.OverTimeBox || !v.CanStop {
				t.Fatalf("view = %+v", v)
			}
		}},
		{"a run that ended inside its box is not over it", func(r *secassesssvc.Run) { r.EndedAt = started.Add(30 * time.Minute) }, func(t *testing.T, v securityAssessTimeJS) {
			if v.OverTimeBox || v.CanStop {
				t.Fatalf("view = %+v", v)
			}
			if v.Audit != auditUnrecorded {
				t.Fatalf("an ended run with no recorded verdict: %q", v.Audit)
			}
		}},
		{"a run that ended past its box stays over it", func(r *secassesssvc.Run) { r.EndedAt = started.Add(48 * time.Minute) }, func(t *testing.T, v securityAssessTimeJS) {
			if !v.OverTimeBox {
				t.Fatalf("view = %+v", v)
			}
		}},
		{"a recorded verdict is shown with its words and limits", func(r *secassesssvc.Run) {
			r.EndedAt = started.Add(30 * time.Minute)
			r.Audit, r.AuditAt = string(secassess.AuditNoChange), started.Add(31*time.Minute)
		}, func(t *testing.T, v securityAssessTimeJS) {
			if v.Audit != string(secassess.AuditNoChange) || v.AuditWords == "" || v.AuditLimits != secassess.AuditLimits || v.AuditAt == nil {
				t.Fatalf("view = %+v", v)
			}
		}},
		{"a run recorded before the depth work has nothing to say", func(r *secassesssvc.Run) { r.TimeBoxMinutes = 0; r.EndedAt = started.Add(5 * time.Minute) }, func(t *testing.T, v securityAssessTimeJS) {
			if v.Audit != "" || v.Deadline != nil || v.OverTimeBox {
				t.Fatalf("view = %+v", v)
			}
		}},
		{"a held run has not started", func(r *secassesssvc.Run) { r.Phase, r.Handle, r.ConfirmedAt = secassesssvc.PhaseHeld, "", time.Time{} }, func(t *testing.T, v securityAssessTimeJS) {
			if v.CanStop || v.Audit != "" {
				t.Fatalf("view = %+v", v)
			}
		}},
		{"a run with no handle cannot be stopped", func(r *secassesssvc.Run) { r.Handle = "" }, func(t *testing.T, v securityAssessTimeJS) {
			if v.CanStop {
				t.Fatalf("view = %+v", v)
			}
		}},
		{"the end reason is carried", func(r *secassesssvc.Run) { r.EndWhy = secassess.EndStopped }, func(t *testing.T, v securityAssessTimeJS) {
			if v.EndWhy != secassess.EndStopped {
				t.Fatalf("view = %+v", v)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.mutate(&r)
			tc.check(t, securityAssessTimeView(r, now, true))
		})
	}
	if v := securityAssessTimeView(base, now, false); v.HasData {
		t.Errorf("has_data without stored evidence: %+v", v)
	}
}

// TestSecurityAssessPlanLimits: the plan carries the settings in force and the
// prompt carries the time box.
func TestSecurityAssessPlanLimits(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		h := newRelaxHarness(t, "")
		p := h.plan("")
		if p.Limits == nil || p.Limits.TimeBoxMinutes != 45 || p.Limits.TimeBoxAction != secassess.TimeBoxStopButton || !p.Limits.BoundaryAudit {
			t.Fatalf("limits = %+v", p.Limits)
		}
		if p.Limits.RelaxationNote != "" {
			t.Errorf("a note on the defaults: %q", p.Limits.RelaxationNote)
		}
		if !strings.Contains(p.Prompt, "45 minutes") {
			t.Errorf("the prompt does not state the time box:\n%s", p.Prompt)
		}
	})
	t.Run("a box longer than the relaxation window says an approval ends first", func(t *testing.T) {
		h := newRelaxHarness(t, relaxOn+"time_box_pentest_local_minutes = 90\n")
		p := h.plan("&relax=" + secassess.RuleScanner)
		if p.Limits == nil || p.Limits.TimeBoxMinutes != 90 || p.Limits.RelaxationNote == "" {
			t.Fatalf("limits = %+v", p.Limits)
		}
		if !strings.Contains(p.Prompt, "90 minutes") {
			t.Errorf("the prompt does not state the configured box")
		}
	})
	t.Run("audit off", func(t *testing.T) {
		h := newRelaxHarness(t, "boundary_audit = false\ntime_box_action = \"auto_close\"\n")
		p := h.plan("")
		if p.Limits == nil || p.Limits.BoundaryAudit || p.Limits.TimeBoxAction != secassess.TimeBoxAutoClose {
			t.Fatalf("limits = %+v", p.Limits)
		}
	})
}

// TestSecurityAssessLaunchRecordsLimits: a launch records the time box and the
// action in force on the run (so a later settings change never moves them),
// writes the run folder and its .gitignore, stores the launch snapshot, and
// carries the effective values in the launch audit row.
func TestSecurityAssessLaunchRecordsLimits(t *testing.T) {
	h := newRelaxHarness(t, "time_box_pentest_local_minutes = 30\ntime_box_action = \"auto_close\"\nreport_to_org = true\n")
	id := secassesssvc.NewRunID()
	code, body := h.launch(h.launchBody(id, nil))
	if code != http.StatusOK {
		t.Fatalf("launch: %d %v", code, body)
	}
	run, _ := h.runs.Get(id)
	if run.TimeBoxMinutes != 30 || run.TimeBoxAction != secassess.TimeBoxAutoClose || run.Audit != "" {
		t.Fatalf("run = %+v", run)
	}
	if !strings.Contains(h.lm.lastFreshSpec.TaskPrompt, "30 minutes") {
		t.Errorf("the prompt does not state the 30-minute box")
	}
	// The run folder and its .gitignore exist before the agent starts.
	gi := filepath.Join(h.root, filepath.FromSlash(secassess.ResultPaths(id).Dir), ".gitignore")
	if b, err := os.ReadFile(gi); err != nil || string(b) != "*\n" {
		t.Errorf(".gitignore = %q, %v", b, err)
	}
	// The launch snapshot is stored; whether it could be taken depends on git, but
	// the file says either way and never reads as clean.
	data, ok := h.runs.Side().Get(id, secassesssvc.SideTree)
	if !ok {
		t.Fatalf("no launch snapshot stored")
	}
	var rec secassess.TreeRecord
	if err := json.Unmarshal(data, &rec); err != nil || rec.Before == nil || rec.After != nil {
		t.Fatalf("tree.json = %s (%v)", data, err)
	}
	// The run row.
	var list securityAssessListJS
	if c := getAssessJSON(t, h.s.handleSecurityAssess, "/api/security/assessments", &list); c != http.StatusOK || len(list.Runs) != 1 {
		t.Fatalf("list: %d %+v", c, list.Runs)
	}
	v := list.Runs[0]
	if v.TimeBoxMinutes != 30 || v.Deadline == nil || !v.HasData || v.Audit != auditPending || !v.CanStop {
		t.Fatalf("run row = %+v", v.securityAssessTimeJS)
	}
	// The launch audit row carries the values the run started under.
	var detail string
	row := h.s.db().QueryRow(`SELECT COALESCE(reason,'') FROM guard_events WHERE event_kind = 'audit' ORDER BY id DESC LIMIT 1`)
	if err := row.Scan(&detail); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	for _, want := range []string{"time_box_minutes=30", "time_box_action=auto_close", "boundary_audit=on"} {
		if !strings.Contains(detail, want) {
			t.Errorf("audit detail lacks %q: %s", want, detail)
		}
	}
}

// TestSecurityAssessLaunchAuditOff: with the audit off the run says so at
// launch and no snapshot is stored.
func TestSecurityAssessLaunchAuditOff(t *testing.T) {
	h := newRelaxHarness(t, "boundary_audit = false\n")
	id := secassesssvc.NewRunID()
	if code, body := h.launch(h.launchBody(id, nil)); code != http.StatusOK {
		t.Fatalf("launch: %d %v", code, body)
	}
	run, _ := h.runs.Get(id)
	if run.Audit != string(secassess.AuditOff) {
		t.Fatalf("audit = %q", run.Audit)
	}
	if _, ok := h.runs.Side().Get(id, secassesssvc.SideTree); ok {
		t.Errorf("a snapshot was stored with the audit off")
	}
}

// TestSecurityAssessInitialAudit: the run records at launch the verdict that is
// already known: not checked (audit off) or not audited (the kind), else none.
func TestSecurityAssessInitialAudit(t *testing.T) {
	for _, tc := range []struct {
		kind  string
		on    bool
		want  string
		label string
	}{
		{string(secassess.ThreatModel), true, "", "audited kind, audit on"},
		{string(secassess.ThreatModel), false, string(secassess.AuditOff), "audit off"},
	} {
		k, ok := secassess.KindByID(tc.kind)
		if !ok {
			t.Fatalf("no kind %q", tc.kind)
		}
		if got := securityAssessInitialAudit(k, securityAssessLimits{AuditOn: tc.on}); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.label, got, tc.want)
		}
	}
	notAudited := secassess.Kind{ID: "x", TreePolicy: secassess.TreeNotAudited}
	if got := securityAssessInitialAudit(notAudited, securityAssessLimits{AuditOn: true}); got != string(secassess.AuditNotAudited) {
		t.Errorf("not-audited kind: %q", got)
	}
}

// TestSecurityAssessStopRoute: the Stop action, one case per outcome.
func TestSecurityAssessStopRoute(t *testing.T) {
	h := newRelaxHarness(t, "")
	stop := func(body map[string]any, confirm bool) *httptest.ResponseRecorder {
		return postAssess(t, h.s.handleSecurityAssessStop, "/api/security/assessments/stop", body, confirm)
	}
	id := secassesssvc.NewRunID()
	if code, body := h.launch(h.launchBody(id, nil)); code != http.StatusOK {
		t.Fatalf("launch: %d %v", code, body)
	}
	run, _ := h.runs.Get(id)
	if w := stop(map[string]any{"run": id}, false); w.Code != http.StatusForbidden {
		t.Fatalf("no confirm token: %d", w.Code)
	}
	if len(h.lm.closed) != 0 {
		t.Fatalf("a refused request closed a terminal: %v", h.lm.closed)
	}
	if w := stop(map[string]any{"run": "00000000deadbeef"}, true); w.Code != http.StatusNotFound {
		t.Fatalf("unknown run: %d", w.Code)
	}
	w := stop(map[string]any{"run": id}, true)
	if w.Code != http.StatusOK {
		t.Fatalf("stop: %d %s", w.Code, w.Body)
	}
	if len(h.lm.closed) != 1 || h.lm.closed[0] != run.Handle {
		t.Fatalf("closed = %v, want [%s]", h.lm.closed, run.Handle)
	}
	var out struct {
		Run securityAssessRunJS `json:"run"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Run.EndWhy != secassess.EndStopped {
		t.Fatalf("response = %s (%v)", w.Body, err)
	}
	if got, _ := h.runs.Get(id); got.EndWhy != secassess.EndStopped {
		t.Fatalf("recorded end reason = %q", got.EndWhy)
	}
	// A second Stop on the same run is not an error and keeps the first reason.
	if w := stop(map[string]any{"run": id}, true); w.Code != http.StatusOK {
		t.Fatalf("second stop: %d %s", w.Code, w.Body)
	}
	if got, _ := h.runs.Get(id); got.EndWhy != secassess.EndStopped {
		t.Fatalf("the reason moved: %q", got.EndWhy)
	}
	// A GET is refused.
	r := httptest.NewRecorder()
	h.s.handleSecurityAssessStop(r, httptest.NewRequest(http.MethodGet, "/api/security/assessments/stop", nil))
	if r.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", r.Code)
	}
}

// TestSecurityAssessStopNeedsATerminal: a run that never started has nothing to
// stop, and a stop that cannot reach the launcher says so.
func TestSecurityAssessStopNeedsATerminal(t *testing.T) {
	h := newRelaxHarness(t, "")
	held := secassesssvc.NewRunID()
	if _, err := h.runs.Record(secassesssvc.Run{ID: held, Kind: "pentest_local", Phase: secassesssvc.PhaseHeld, ProjectRootHash: h.hash}, time.Now()); err != nil {
		t.Fatal(err)
	}
	w := postAssess(t, h.s.handleSecurityAssessStop, "/api/security/assessments/stop", map[string]any{"run": held}, true)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "not_started") {
		t.Fatalf("held run: %d %s", w.Code, w.Body)
	}
	if len(h.lm.closed) != 0 {
		t.Errorf("closed = %v", h.lm.closed)
	}
	h.s.opts.LaunchManager = nil
	w = postAssess(t, h.s.handleSecurityAssessStop, "/api/security/assessments/stop", map[string]any{"run": held}, true)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no launcher: %d", w.Code)
	}
}

// TestSecurityAssessDeleteDataRoute: deleting a run's stored evidence removes
// the side files and nothing else.
func TestSecurityAssessDeleteDataRoute(t *testing.T) {
	h := newRelaxHarness(t, "")
	id := secassesssvc.NewRunID()
	if code, body := h.launch(h.launchBody(id, nil)); code != http.StatusOK {
		t.Fatalf("launch: %d %v", code, body)
	}
	if err := h.runs.Side().Put(id, secassesssvc.SideModel, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	del := func(run string, confirm bool) *httptest.ResponseRecorder {
		return postAssess(t, h.s.handleSecurityAssessDeleteData, "/api/security/assessments/delete-data", map[string]any{"run": run}, confirm)
	}
	if w := del(id, false); w.Code != http.StatusForbidden || !h.runs.Side().Has(id) {
		t.Fatalf("no confirm token: %d (has %v)", w.Code, h.runs.Side().Has(id))
	}
	if w := del("00000000deadbeef", true); w.Code != http.StatusNotFound {
		t.Fatalf("unknown run: %d", w.Code)
	}
	w := del(id, true)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if h.runs.Side().Has(id) {
		t.Fatalf("the evidence is still there")
	}
	var out struct {
		Run securityAssessRunJS `json:"run"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Run.HasData || out.Run.ID != id {
		t.Fatalf("response = %s (%v)", w.Body, err)
	}
	if _, ok := h.runs.Get(id); !ok {
		t.Fatalf("the run itself was removed")
	}
	// Deleting again is not an error.
	if w := del(id, true); w.Code != http.StatusOK {
		t.Fatalf("second delete: %d", w.Code)
	}
}

// TestSecurityAssessListUnreadable: a run record that cannot be read is said
// so, not shown as "no runs", and nothing overwrites it.
func TestSecurityAssessListUnreadable(t *testing.T) {
	h := newRelaxHarness(t, "")
	path := secassesssvc.Path(h.s.opts.DBPath)
	if err := os.WriteFile(path, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var list securityAssessListJS
	if c := getAssessJSON(t, h.s.handleSecurityAssess, "/api/security/assessments", &list); c != http.StatusOK {
		t.Fatalf("list: %d", c)
	}
	if !list.RunsUnreadable || list.RunsError != "run_record_unreadable" || len(list.Runs) != 0 {
		t.Fatalf("list = unreadable %v %q runs %d", list.RunsUnreadable, list.RunsError, len(list.Runs))
	}
	// A launch is refused (the review tests pin the refusal), and the file is not
	// replaced by an empty history: the record is left as it was.
	id := secassesssvc.NewRunID()
	if code, body := h.launch(h.launchBody(id, nil)); code != http.StatusConflict || body["code"] != codeRunRecordUnreadable {
		t.Fatalf("launch over an unreadable record: %d %v", code, body)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "{ this is not json" {
		t.Fatalf("the record was rewritten: %q %v", b, err)
	}
}

// TestSecurityAssessRunThatEndedWithNothingReadsAsEnded: the first live run
// (2026-11-15) started a pen test whose terminal exited within seconds (the box
// refused it), and the card read "running, waiting for the agent to write its
// report" for hours beside "ended when the terminal closed". A run whose
// terminal has ended and that wrote nothing is "ended_empty", with how it ended
// still on the row; a run whose terminal is still there is "started"; and a
// result file written before the end keeps the state the file gives.
func TestSecurityAssessRunThatEndedWithNothingReadsAsEnded(t *testing.T) {
	h := newRelaxHarness(t, "")
	end := func(id, why string) {
		t.Helper()
		if _, found, err := h.runs.Mutate(id, func(r *secassesssvc.Run) error {
			r.EndedAt, r.EndWhy = time.Now().UTC(), why
			return nil
		}); err != nil || !found {
			t.Fatalf("end %s: found %v err %v", id, found, err)
		}
	}
	launch := func() string {
		t.Helper()
		id := secassesssvc.NewRunID()
		if code, body := h.launch(h.launchBody(id, nil)); code != http.StatusOK {
			t.Fatalf("launch: %d %v", code, body)
		}
		return id
	}
	for _, tc := range []struct {
		name    string
		files   map[string]string
		endWhy  string // "" leaves the run live
		want    string
		canStop bool
	}{
		{"live, nothing written", nil, "", string(secassess.StateStarted), true},
		{"ended with the terminal gone, nothing written", nil, secassess.EndGone, string(secassess.StateEndedEmpty), false},
		{"ended at the time box, nothing written", nil, secassess.EndTimeBox, string(secassess.StateEndedEmpty), false},
		{"ended by Stop, nothing written", nil, secassess.EndStopped, string(secassess.StateEndedEmpty), false},
		{"ended with a report", map[string]string{"report.md": "# r"}, secassess.EndGone, string(secassess.StateReportReady), false},
		{"ended with a model", map[string]string{"assessment.json": "{}"}, secassess.EndGone, string(secassess.StateModelReady), false},
		{"live with a report", map[string]string{"report.md": "# r"}, "", string(secassess.StateReportReady), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := launch()
			if len(tc.files) > 0 {
				dir := filepath.Join(h.root, ".observer", "assessments", id)
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				for name, body := range tc.files {
					if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			if tc.endWhy != "" {
				end(id, tc.endWhy)
			}
			v := h.runView(id)
			if v.State != tc.want || v.CanStop != tc.canStop || v.EndWhy != tc.endWhy {
				t.Fatalf("state %q can_stop %v end_why %q, want %q %v %q", v.State, v.CanStop, v.EndWhy, tc.want, tc.canStop, tc.endWhy)
			}
			if tc.endWhy != "" && v.EndedAt == nil {
				t.Fatal("an ended run reports no end time")
			}
		})
	}
}
