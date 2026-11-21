//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func seedSecFinding(t *testing.T, st *store.Store, rootHash, key, rel string) string {
	t.Helper()
	id, _, err := st.UpsertSecFinding(context.Background(), secfinding.Normalize(secfinding.Finding{
		LocalKey: key, Rule: secfinding.Rule{ID: "S-721"}, Category: policy.FindingSecret,
		Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
		Project: secfinding.Project{RootHash: rootHash}, Location: secfinding.Location{RelPath: rel, StartLine: 3},
		Status: policy.FindingStatusOpen, Lineage: secfinding.Lineage{SessionID: "sA"},
	}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func getSecurityStatus(t *testing.T, s *Server) securityStatusResponse {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleSecurityStatus(w, httptest.NewRequest(http.MethodGet, "/api/security/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
	var resp securityStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestSecurityStatusNamesProjects is the regression for the page that
// listed projects as 12-hex root hash prefixes, which read as git commit
// ids: every row names its projects row (id, name, root), carries its open
// count and newest scan run, and a hash no project names is still listed
// (its findings are) as an unknown project, never as a bare id.
func TestSecurityStatusNamesProjects(t *testing.T) {
	s, root := newTestServer(t)
	ctx := context.Background()
	st := store.New(s.db())
	hash := secposture.ProjectRootHash(root)
	seedSecFinding(t, st, hash, "k1", "a.go")
	orphan := secposture.ProjectRootHash("/gone/project")
	seedSecFinding(t, st, orphan, "k2", "b.go")
	if err := st.InsertSecScanRun(ctx, store.SecScanRun{
		ProjectRootHash: hash, Driver: "native", Scope: policy.FindingScopeManual, Outcome: "findings", Findings: 1,
		StartedAt: time.Now().Add(-time.Minute), Duration: 2 * time.Second,
	}); err != nil {
		t.Fatal(err)
	}

	resp := getSecurityStatus(t, s)
	byHash := map[string]securityProjectRow{}
	for _, p := range resp.Projects {
		byHash[p.ProjectRootHash] = p
	}
	row, ok := byHash[hash]
	if !ok {
		t.Fatalf("the project is not listed: %+v", resp.Projects)
	}
	if row.ProjectID == 0 || row.RootPath != root || row.Name != filepath.Base(root) || !row.Active {
		t.Fatalf("row does not name its project: %+v", row)
	}
	if strings.HasPrefix(hash, row.Name) {
		t.Fatalf("row name is the root hash: %q", row.Name)
	}
	if row.Open != 1 || row.LastScanAt == "" || len(row.Runs) != 1 || row.Runs[0].Driver != "native" || row.Runs[0].Outcome != "findings" {
		t.Fatalf("row counts or runs: %+v", row)
	}
	o, ok := byHash[orphan]
	if !ok {
		t.Fatalf("a hash holding findings with no project row is not listed")
	}
	if o.ProjectID != 0 || o.Name != "" || o.Active || o.Reason != "project_not_found" || o.Open != 1 {
		t.Fatalf("orphan row: %+v", o)
	}
}

// TestSecurityFindingDetail: the drawer's route names the project and
// carries the sightings, the events and the attributed session; an unknown
// id is a 404.
func TestSecurityFindingDetail(t *testing.T) {
	s, root := newTestServer(t)
	st := store.New(s.db())
	id := seedSecFinding(t, st, secposture.ProjectRootHash(root), "k1", "a.go")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/security/findings/{id}", s.handleSecurityFinding)
	get := func(id string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/security/findings/"+id, nil))
		return w
	}
	if w := get("nope"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", w.Code)
	}
	w := get(id)
	if w.Code != http.StatusOK {
		t.Fatalf("detail: %d %s", w.Code, w.Body)
	}
	var d securityFindingDetail
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Finding.ID != id || d.Finding.SessionID != "sA" || d.Project == nil || d.Project.RootPath != root || d.Project.ID == 0 {
		t.Fatalf("detail: %+v", d)
	}
	if len(d.Sightings) != 1 || d.Sightings[0] != "a.go" || len(d.Events) == 0 {
		t.Fatalf("detail history: %+v", d)
	}
}

// fakeScanNow is a SecurityScanNow whose one step blocks until released.
// online, when set, is the seam's online check state; opts records the
// options each Scan call carried.
type fakeScanNow struct {
	mu      sync.Mutex
	roots   []string
	opts    []dashapi.SecurityScanOptions
	release chan struct{}
	online  *dashapi.SecurityScanOnline
}

func (f *fakeScanNow) seam() *dashapi.SecurityScanNow {
	seam := &dashapi.SecurityScanNow{
		Steps: func(context.Context) []dashapi.SecurityScanStep {
			return []dashapi.SecurityScanStep{
				{ID: "code", Label: "Code rules", Ready: true},
				{ID: "deps", Label: "Dependencies", Ready: false, Reason: "not selected"},
			}
		},
		Scan: func(ctx context.Context, root, step string, opts dashapi.SecurityScanOptions) dashapi.SecurityScanResult {
			f.mu.Lock()
			f.roots = append(f.roots, root+"|"+step)
			f.opts = append(f.opts, opts)
			f.mu.Unlock()
			select {
			case <-f.release:
			case <-ctx.Done():
				return dashapi.SecurityScanResult{Outcome: "failed", Reason: ctx.Err().Error()}
			}
			return dashapi.SecurityScanResult{Outcome: "findings", Findings: 2, New: 1}
		},
	}
	if f.online != nil {
		seam.Online = func(context.Context) dashapi.SecurityScanOnline {
			f.mu.Lock()
			defer f.mu.Unlock()
			return *f.online
		}
	}
	return seam
}

func getSecurityScan(t *testing.T, s *Server) securityScanView {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleSecurityScan(w, httptest.NewRequest(http.MethodGet, "/api/security/scan", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("scan view: %d %s", w.Code, w.Body)
	}
	var v securityScanView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func waitSecurityScan(t *testing.T, s *Server, state string) *securityScanJobJS {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if v := getSecurityScan(t, s); v.Job != nil && v.Job.State == state {
			return v.Job
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the job never reached %s", state)
	return nil
}

// TestSecurityScanNow: the GET lists the history step and the seam's rows;
// a POST needs the confirm token, names a known project, runs the ready
// steps only (the not-ready one is never called), refuses a second job
// while one runs, and reports each step's outcome when done. A cancel ends
// a running job as cancelled.
func TestSecurityScanNow(t *testing.T) {
	s, root := newTestServer(t)
	fake := &fakeScanNow{release: make(chan struct{})}
	s.opts.SecurityScanNow = fake.seam()
	hash := secposture.ProjectRootHash(root)

	v := getSecurityScan(t, s)
	if v.ConfirmToken == "" || len(v.Steps) != 3 || v.Steps[0].ID != securityScanHistoryStep || v.Job != nil {
		t.Fatalf("view: %+v", v)
	}
	body := `{"project":"` + hash + `"}`
	if w := securityPost(s.handleSecurityScan, "/api/security/scan", body, false); w.Code != http.StatusForbidden {
		t.Fatalf("without the confirm token: %d", w.Code)
	}
	if w := securityPost(s.handleSecurityScan, "/api/security/scan", `{"project":"nope"}`, true); w.Code != http.StatusNotFound {
		t.Fatalf("unknown project: %d", w.Code)
	}
	if w := securityPost(s.handleSecurityScan, "/api/security/scan", `{}`, true); w.Code != http.StatusBadRequest {
		t.Fatalf("no target: %d", w.Code)
	}
	if w := securityPost(s.handleSecurityScan, "/api/security/scan", body, true); w.Code != http.StatusAccepted {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	if w := securityPost(s.handleSecurityScan, "/api/security/scan", body, true); w.Code != http.StatusConflict {
		t.Fatalf("second job while one runs: %d", w.Code)
	}
	close(fake.release)
	job := waitSecurityScan(t, s, securityScanDone)
	if job.Total != 1 || job.Done != 1 || len(job.Projects) != 1 || job.Projects[0].ProjectID == 0 {
		t.Fatalf("job: %+v", job)
	}
	steps := job.Projects[0].Steps
	if len(steps) != 2 || steps[0].ID != securityScanHistoryStep || steps[0].Outcome != dashapi.SecurityScanSkipped ||
		steps[1].ID != "code" || steps[1].Outcome != "findings" || steps[1].New != 1 {
		t.Fatalf("steps: %+v", steps)
	}
	fake.mu.Lock()
	called := append([]string(nil), fake.roots...)
	fake.mu.Unlock()
	if len(called) != 1 || called[0] != root+"|code" {
		t.Fatalf("seam calls: %v", called)
	}

	// A cancelled job.
	fake.release = make(chan struct{})
	if w := securityPost(s.handleSecurityScan, "/api/security/scan", body, true); w.Code != http.StatusAccepted {
		t.Fatalf("restart: %d %s", w.Code, w.Body)
	}
	if w := securityPost(s.handleSecurityScan, "/api/security/scan", `{"cancel":true}`, true); w.Code != http.StatusOK {
		t.Fatalf("cancel: %d", w.Code)
	}
	if job := waitSecurityScan(t, s, securityScanCancelled); job.FinishedAt == "" {
		t.Fatalf("cancelled job: %+v", job)
	}
}
