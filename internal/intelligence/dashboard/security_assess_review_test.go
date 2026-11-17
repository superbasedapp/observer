//go:build !sbo_omit_security

package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
)

// The run record (secassess-runs.json) is what gives a run its deadline, its
// Stop and its closing check, so a launch refuses to start one that could not
// be recorded and every route that needs the record says why it cannot answer.
// These tests pin that behaviour, one row per state and one row per route.

const reviewUnreadableBytes = "{ this is not json"

// reviewHeldRun is a run that can never be dropped for room (it waits on the
// organization), so a record of them is full.
func reviewHeldRun(h *relaxHarness, id string) secassesssvc.Run {
	return secassesssvc.Run{ID: id, Kind: string(secassess.PentestLocal), ProjectRootHash: h.hash, Phase: secassesssvc.PhaseHeld}
}

func reviewRecordPath(h *relaxHarness) string { return secassesssvc.Path(h.s.opts.DBPath) }

// A record state is a function that puts the record into it and returns the id
// of an ended run the state holds that a new run may drop ("" when none).
type reviewRecordState func(t *testing.T, h *relaxHarness) string

func reviewWriteRecord(t *testing.T, h *relaxHarness, data []byte) {
	t.Helper()
	if err := os.WriteFile(reviewRecordPath(h), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func reviewUnreadable(t *testing.T, h *relaxHarness) string {
	t.Helper()
	reviewWriteRecord(t, h, []byte(reviewUnreadableBytes))
	return ""
}

func reviewWrongSchema(t *testing.T, h *relaxHarness) string {
	t.Helper()
	reviewWriteRecord(t, h, []byte(`{"schema":99,"runs":[]}`))
	return ""
}

func reviewOverTheSizeCap(t *testing.T, h *relaxHarness) string {
	t.Helper()
	reviewWriteRecord(t, h, []byte(strings.Repeat(" ", 1<<20+1)))
	return ""
}

// reviewFillByCount records n runs that cannot be dropped for room.
func reviewFillByCount(t *testing.T, h *relaxHarness, n int) {
	t.Helper()
	for range n {
		if _, err := h.runs.Record(reviewHeldRun(h, secassesssvc.NewRunID()), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
}

func reviewFullByCount(t *testing.T, h *relaxHarness) string {
	t.Helper()
	reviewFillByCount(t, h, secassesssvc.MaxRuns)
	if err := h.runs.CanRecord(); !errors.Is(err, secassesssvc.ErrFull) {
		t.Fatalf("precondition: CanRecord = %v, want ErrFull", err)
	}
	return ""
}

// reviewFullBySize writes a record just under the 1 MiB cap whose runs all wait
// on the organization: it reads, and it has no room left for another run.
func reviewFullBySize(t *testing.T, h *relaxHarness) string {
	t.Helper()
	const runs = 8
	build := func(pad int) []byte {
		rs := make([]secassesssvc.Run, runs)
		for i := range rs {
			rs[i] = reviewHeldRun(h, secassesssvc.NewRunID())
			rs[i].CreatedAt = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
			rs[i].ProjectName = strings.Repeat("a", pad)
		}
		data, err := json.Marshal(struct {
			Schema int                `json:"schema"`
			Runs   []secassesssvc.Run `json:"runs"`
		}{secassesssvc.Schema, rs})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	pad := (1<<20 - 4096 - len(build(0))) / runs
	reviewWriteRecord(t, h, build(pad))
	if err := h.runs.Unreadable(); err != nil {
		t.Fatalf("precondition: the record does not read: %v", err)
	}
	if err := h.runs.CanRecord(); !errors.Is(err, secassesssvc.ErrFull) {
		t.Fatalf("precondition: CanRecord = %v, want ErrFull", err)
	}
	return ""
}

// reviewFullButDroppable is a record at its count limit whose oldest run has
// ended and owes nothing: a new run takes its place.
func reviewFullButDroppable(t *testing.T, h *relaxHarness) string {
	t.Helper()
	ended := secassesssvc.NewRunID()
	if _, err := h.runs.Record(secassesssvc.Run{
		ID: ended, Kind: string(secassess.ThreatModel), ProjectRootHash: h.hash, Phase: secassesssvc.PhaseStarted,
		Handle: "H-old", EndedAt: time.Now().Add(-time.Hour).UTC(), Audit: string(secassess.AuditOff),
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	reviewFillByCount(t, h, secassesssvc.MaxRuns-1)
	if err := h.runs.CanRecord(); err != nil {
		t.Fatalf("precondition: CanRecord = %v, want room", err)
	}
	return ended
}

// reviewBody reads a refusal's JSON body.
func reviewBody(t *testing.T, w *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var out map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("not a JSON refusal: %v (%s)", err, w.Body)
	}
	return out
}

func reviewRecordBytes(t *testing.T, h *relaxHarness) []byte {
	t.Helper()
	b, err := os.ReadFile(reviewRecordPath(h))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return b
}

// TestSecurityAssessLaunchAndTheRunRecord: a launch asks whether the run can be
// recorded before it prepares a folder, claims anything or starts a terminal.
func TestSecurityAssessLaunchAndTheRunRecord(t *testing.T) {
	cases := []struct {
		name   string
		state  reviewRecordState
		status int
		code   string
	}{
		{"a healthy record launches", nil, http.StatusOK, ""},
		{"a record that is not JSON", reviewUnreadable, http.StatusConflict, codeRunRecordUnreadable},
		{"a record of another schema", reviewWrongSchema, http.StatusConflict, codeRunRecordUnreadable},
		{"a record over its size cap", reviewOverTheSizeCap, http.StatusConflict, codeRunRecordUnreadable},
		{"a record full of runs in use, by count", reviewFullByCount, http.StatusConflict, codeRunRecordFull},
		{"a record full of runs in use, by size", reviewFullBySize, http.StatusConflict, codeRunRecordFull},
		{"a full record whose oldest run has ended makes room", reviewFullButDroppable, http.StatusOK, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Project scope, so a started run would create an approval row, and
			// reporting on, so it would write its launch audit row.
			h := newRelaxHarness(t, relaxOn+"relaxation_scope = \"project\"\nreport_to_org = true\n")
			ended := ""
			if tc.state != nil {
				ended = tc.state(t, h)
			}
			before := reviewRecordBytes(t, h)
			id := secassesssvc.NewRunID()
			code, body := h.launch(h.launchBody(id, map[string]any{"relaxations": []string{secassess.RuleScanner}}))
			runDir := filepath.Join(h.root, filepath.FromSlash(secassess.ResultPaths(id).Dir))
			_, dirErr := os.Stat(runDir)
			if code != tc.status || body["code"] != tc.code {
				t.Fatalf("launch: %d %v, want %d %q", code, body, tc.status, tc.code)
			}
			if tc.status == http.StatusOK {
				if dirErr != nil || h.lm.lastFreshSpec.Tool == "" || h.approvals() != 1 || !h.runs.Exists(id) {
					t.Fatalf("a healthy launch: dir %v tool %q approvals %d recorded %v", dirErr, h.lm.lastFreshSpec.Tool, h.approvals(), h.runs.Exists(id))
				}
				if ended != "" && h.runs.Exists(ended) {
					t.Errorf("the ended run was not dropped to make room")
				}
				return
			}
			if body["file"] != reviewRecordPath(h) || filepath.Base(body["file"]) != secassesssvc.Filename || body["error"] == "" {
				t.Errorf("the refusal does not name the file and the way out: %v", body)
			}
			// Nothing was prepared, claimed or started.
			if !errors.Is(dirErr, os.ErrNotExist) {
				t.Errorf("the run folder was created: %v", dirErr)
			}
			if h.lm.lastFreshSpec.Tool != "" || h.lm.lastFreshSpec.ProjectRoot != "" {
				t.Errorf("a terminal was started: %+v", h.lm.lastFreshSpec)
			}
			if h.approvals() != 0 {
				t.Errorf("an approval row was created")
			}
			if rows := h.auditRows(); len(rows) != 0 {
				t.Errorf("audit rows were written: %v", rows)
			}
			if after := reviewRecordBytes(t, h); string(after) != string(before) {
				t.Errorf("the run record was rewritten (%d bytes before, %d after)", len(before), len(after))
			}
		})
	}
}

// TestSecurityAssessHeldStartNeedsNoRoom: a held run is already in the record,
// so starting it asks only that the record reads, not that it has room.
func TestSecurityAssessHeldStartNeedsNoRoom(t *testing.T) {
	h := newRelaxHarness(t, "")
	id := secassesssvc.NewRunID()
	if _, err := h.runs.Record(reviewHeldRun(h, id), time.Now()); err != nil {
		t.Fatal(err)
	}
	reviewFillByCount(t, h, secassesssvc.MaxRuns-1)
	if err := h.runs.CanRecord(); !errors.Is(err, secassesssvc.ErrFull) {
		t.Fatalf("precondition: CanRecord = %v, want ErrFull", err)
	}
	if code, body := h.launch(h.launchBody(id, nil)); code != http.StatusOK {
		t.Fatalf("start of a held run in a full record: %d %v", code, body)
	}
	if run, _ := h.runs.Get(id); run.Phase != secassesssvc.PhaseStarted || run.Handle == "" {
		t.Fatalf("run = %+v", run)
	}
	// A new run, by contrast, is refused: the record is still full.
	if code, body := h.launch(h.launchBody(secassesssvc.NewRunID(), nil)); code != http.StatusConflict || body["code"] != codeRunRecordFull {
		t.Fatalf("a new run in a full record: %d %v", code, body)
	}
}

func reviewManagedHarness(t *testing.T) *relaxHarness {
	t.Helper()
	h := newRelaxHarness(t, relaxOn)
	h.managed(true)
	h.lockRule()
	return h
}

// TestSecurityAssessOrgRequestAndTheRunRecord: nothing is filed with the
// organization for a run that could not be recorded.
func TestSecurityAssessOrgRequestAndTheRunRecord(t *testing.T) {
	cases := []struct {
		name   string
		state  reviewRecordState
		status int
		code   string
		sent   int
	}{
		{"a healthy record files the request", nil, http.StatusCreated, "", 1},
		{"an unreadable record", reviewUnreadable, http.StatusConflict, codeRunRecordUnreadable, 0},
		{"a record full by count", reviewFullByCount, http.StatusConflict, codeRunRecordFull, 0},
		{"a record full by size", reviewFullBySize, http.StatusConflict, codeRunRecordFull, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := reviewManagedHarness(t)
			if tc.state != nil {
				tc.state(t, h)
			}
			before := reviewRecordBytes(t, h)
			id := secassesssvc.NewRunID()
			w := postAssess(t, h.s.handleSecurityAssessRequest, "/api/security/assessments/request", map[string]any{
				"assessment": "pentest_local", "project_root_hash": h.hash, "run_id": id, "target": "http://localhost:3000/",
				"relaxations": []string{secassess.RuleScanner},
			}, true)
			if w.Code != tc.status || len(h.reqs.sent) != tc.sent {
				t.Fatalf("request: %d (sent %d), want %d (sent %d): %s", w.Code, len(h.reqs.sent), tc.status, tc.sent, w.Body)
			}
			if tc.code == "" {
				return
			}
			if body := reviewBody(t, w); body["code"] != tc.code || body["file"] != reviewRecordPath(h) {
				t.Errorf("refusal = %v", body)
			}
			if h.runs.Exists(id) {
				t.Errorf("a run was recorded for a request that was not filed")
			}
			if after := reviewRecordBytes(t, h); string(after) != string(before) {
				t.Errorf("the run record was rewritten")
			}
		})
	}
}

// reviewRoute is one route that resolves a run through the run record.
type reviewRoute struct {
	name string
	call func(t *testing.T, h *relaxHarness, run string) *httptest.ResponseRecorder
}

func reviewGet(t *testing.T, h http.HandlerFunc, path, run string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, path+"?run="+run, nil))
	return w
}

func reviewPost(t *testing.T, h http.HandlerFunc, path, run string) *httptest.ResponseRecorder {
	t.Helper()
	return postAssess(t, h, path, map[string]any{"run": run}, true)
}

func reviewRoutes() []reviewRoute {
	return []reviewRoute{
		{"stop", func(t *testing.T, h *relaxHarness, run string) *httptest.ResponseRecorder {
			return reviewPost(t, h.s.handleSecurityAssessStop, "/api/security/assessments/stop", run)
		}},
		{"validate", func(t *testing.T, h *relaxHarness, run string) *httptest.ResponseRecorder {
			return reviewPost(t, h.s.handleSecurityAssessValidate, "/api/security/assessments/validate", run)
		}},
		{"model", func(t *testing.T, h *relaxHarness, run string) *httptest.ResponseRecorder {
			return reviewGet(t, h.s.handleSecurityAssessModel, "/api/security/assessments/model", run)
		}},
		{"report", func(t *testing.T, h *relaxHarness, run string) *httptest.ResponseRecorder {
			return reviewGet(t, h.s.handleSecurityAssessReport, "/api/security/assessments/report", run)
		}},
		{"import", func(t *testing.T, h *relaxHarness, run string) *httptest.ResponseRecorder {
			return reviewPost(t, h.s.handleSecurityAssessImport, "/api/security/assessments/import", run)
		}},
		{"delete-data", func(t *testing.T, h *relaxHarness, run string) *httptest.ResponseRecorder {
			return reviewPost(t, h.s.handleSecurityAssessDeleteData, "/api/security/assessments/delete-data", run)
		}},
		{"cancel", func(t *testing.T, h *relaxHarness, run string) *httptest.ResponseRecorder {
			return reviewPost(t, h.s.handleSecurityAssessCancel, "/api/security/assessments/cancel", run)
		}},
	}
}

// TestSecurityAssessRoutesAndTheRunRecord: with the record unreadable every
// route that looks a run up answers its own 409 (never "unknown run"), and
// leaves the record as it was; with a healthy record the same call on an
// unknown run is still the 404 it always was.
func TestSecurityAssessRoutesAndTheRunRecord(t *testing.T) {
	const run = "0123456789abcdef"
	for _, rt := range reviewRoutes() {
		t.Run(rt.name+" with an unreadable record", func(t *testing.T) {
			h := newRelaxHarness(t, "")
			reviewUnreadable(t, h)
			w := rt.call(t, h, run)
			if w.Code != http.StatusConflict {
				t.Fatalf("%d %s, want 409 %s", w.Code, w.Body, codeRunRecordUnreadable)
			}
			if body := reviewBody(t, w); body["code"] != codeRunRecordUnreadable || body["file"] != reviewRecordPath(h) {
				t.Errorf("refusal = %v", body)
			}
			if got := string(reviewRecordBytes(t, h)); got != reviewUnreadableBytes {
				t.Errorf("the record was rewritten: %q", got)
			}
		})
		t.Run(rt.name+" with a healthy record and an unknown run", func(t *testing.T) {
			h := newRelaxHarness(t, "")
			if w := rt.call(t, h, run); w.Code != http.StatusNotFound {
				t.Fatalf("%d %s, want 404", w.Code, w.Body)
			}
		})
	}
}

// TestSecurityAssessListAndTheRunRecord: the list says the history could not be
// read (and where it is) instead of showing an empty one; a full record is not
// unreadable.
func TestSecurityAssessListAndTheRunRecord(t *testing.T) {
	cases := []struct {
		name       string
		state      reviewRecordState
		unreadable bool
		runs       int
	}{
		{"an empty record", nil, false, 0},
		{"an unreadable record", reviewUnreadable, true, 0},
		{"a record over its size cap", reviewOverTheSizeCap, true, 0},
		{"a full record lists its newest runs", reviewFullByCount, false, securityAssessRunsShown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRelaxHarness(t, "")
			if tc.state != nil {
				tc.state(t, h)
			}
			w := httptest.NewRecorder()
			h.s.handleSecurityAssess(w, httptest.NewRequest(http.MethodGet, "/api/security/assessments", nil))
			if w.Code != http.StatusOK {
				t.Fatalf("list: %d %s", w.Code, w.Body)
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
				t.Fatal(err)
			}
			var list securityAssessListJS
			if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
				t.Fatal(err)
			}
			if len(list.Runs) != tc.runs || list.RunsUnreadable != tc.unreadable {
				t.Fatalf("runs %d unreadable %v, want %d %v", len(list.Runs), list.RunsUnreadable, tc.runs, tc.unreadable)
			}
			for _, key := range []string{"runs_unreadable", "runs_error", "runs_file"} {
				if _, present := raw[key]; present != tc.unreadable {
					t.Errorf("key %q present = %v, want %v", key, present, tc.unreadable)
				}
			}
			if tc.unreadable && (list.RunsError != codeRunRecordUnreadable || list.RunsFile != reviewRecordPath(h)) {
				t.Errorf("runs_error %q runs_file %q", list.RunsError, list.RunsFile)
			}
		})
	}
}

// TestSecurityAssessRecordRefusalWords: the words of each refusal name the file,
// the way out and what the way out costs.
func TestSecurityAssessRecordRefusalWords(t *testing.T) {
	cases := []struct {
		name  string
		state reviewRecordState
		code  string
		words []string
	}{
		{"unreadable", reviewUnreadable, codeRunRecordUnreadable, []string{
			"secassess-runs.json.bad", "rename the file", "close any other Observer", "Nothing in the file was changed",
			"stop being listed", "stored checks are cleared", "reports stay",
		}},
		{"full", reviewFullByCount, codeRunRecordFull, []string{"still in use", "Stop a running assessment"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRelaxHarness(t, "")
			tc.state(t, h)
			code, body := h.launch(h.launchBody(secassesssvc.NewRunID(), nil))
			if code != http.StatusConflict || body["code"] != tc.code {
				t.Fatalf("launch: %d %v", code, body)
			}
			for _, want := range tc.words {
				if !strings.Contains(body["error"], want) {
					t.Errorf("the refusal lacks %q: %s", want, body["error"])
				}
			}
			if filepath.Base(body["file"]) != "secassess-runs.json" {
				t.Errorf("file = %q", body["file"])
			}
		})
	}
}

// TestSecurityAssessRecordErrorMapping: one row per error the run record can
// answer a request with.
func TestSecurityAssessRecordErrorMapping(t *testing.T) {
	s, _ := newTestServer(t)
	cases := []struct {
		name   string
		err    error
		record bool
		code   string
	}{
		{"unreadable", secassesssvc.ErrUnreadable, true, codeRunRecordUnreadable},
		{"unreadable with its cause", fmt.Errorf("secassesssvc.Mutate: %w: %w", secassesssvc.ErrUnreadable, io.ErrUnexpectedEOF), true, codeRunRecordUnreadable},
		{"full", secassesssvc.ErrFull, true, codeRunRecordFull},
		{"full, wrapped", fmt.Errorf("secassesssvc.Record: %w", secassesssvc.ErrFull), true, codeRunRecordFull},
		{"busy", secassesssvc.ErrLockBusy, true, codeRunRecordBusy},
		{"busy with its cause", fmt.Errorf("%w: %w", secassesssvc.ErrLockBusy, os.ErrPermission), true, codeRunRecordBusy},
		{"another error", errors.New("disk on fire"), false, ""},
		{"no error", nil, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			if got := s.writeSecurityAssessRecordErr(w, tc.err); got != tc.record {
				t.Fatalf("handled = %v, want %v", got, tc.record)
			}
			if !tc.record {
				if w.Body.Len() != 0 {
					t.Errorf("an error that is not the record's wrote %s", w.Body)
				}
				return
			}
			if w.Code != http.StatusConflict {
				t.Errorf("status %d", w.Code)
			}
			if body := reviewBody(t, w); body["code"] != tc.code || body["file"] != secassesssvc.Path(s.opts.DBPath) || body["error"] == "" {
				t.Errorf("body = %v", body)
			}
			// The run lookups' mapper agrees, and sends anything else to a 500.
			w = httptest.NewRecorder()
			s.writeSecurityAssessRunErr(w, tc.err)
			want := http.StatusConflict
			if !tc.record && tc.err != nil {
				want = http.StatusInternalServerError
			}
			if tc.err != nil && w.Code != want {
				t.Errorf("run error status %d, want %d", w.Code, want)
			}
		})
	}
}
