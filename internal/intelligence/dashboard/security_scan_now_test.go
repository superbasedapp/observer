//go:build !sbo_omit_security

package dashboard

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// TestSecurityScanRequestValidation: exactly one of project, projects and
// all; an unknown scanner and a named scanner that is not ready are each
// refused with their own words; the bounds hold; an unknown project in a
// list refuses the request. Nothing starts.
func TestSecurityScanRequestValidation(t *testing.T) {
	s, root := newTestServer(t)
	fake := &fakeScanNow{release: make(chan struct{})}
	s.opts.SecurityScanNow = fake.seam()
	hash := secposture.ProjectRootHash(root)
	many := make([]string, securityScanMaxProjects+1)
	for i := range many {
		many[i] = hash
	}
	manyProjects, _ := json.Marshal(map[string]any{"projects": many})
	manySteps, _ := json.Marshal(map[string]any{"project": hash, "steps": strings.Split(strings.Repeat("code,", securityScanMaxSteps+1), ",")[:securityScanMaxSteps+1]})
	cases := []struct {
		name string
		body string
		code int
		says string
	}{
		{"no target", `{}`, http.StatusBadRequest, "name one project"},
		{"project and all", `{"project":"` + hash + `","all":true}`, http.StatusBadRequest, "name one project"},
		{"project and projects", `{"project":"` + hash + `","projects":["` + hash + `"]}`, http.StatusBadRequest, "name one project"},
		{"projects and all", `{"projects":["` + hash + `"],"all":true}`, http.StatusBadRequest, "name one project"},
		{"unknown scanner", `{"project":"` + hash + `","steps":["code","nope"]}`, http.StatusBadRequest, "unknown scanner: nope"},
		{"scanner not ready", `{"project":"` + hash + `","steps":["deps"]}`, http.StatusBadRequest, "Dependencies is not ready: not selected"},
		{"too many projects", string(manyProjects), http.StatusBadRequest, "too many projects"},
		{"too many scanners", string(manySteps), http.StatusBadRequest, "too many scanners"},
		{"an unknown project in the list", `{"projects":["` + hash + `","nope"]}`, http.StatusNotFound, "unknown project"},
	}
	for _, c := range cases {
		w := securityPost(s.handleSecurityScan, "/api/security/scan", c.body, true)
		if w.Code != c.code || !strings.Contains(w.Body.String(), c.says) {
			t.Errorf("%s: %d %q, want %d %q", c.name, w.Code, w.Body.String(), c.code, c.says)
		}
	}
	if v := getSecurityScan(t, s); v.Job != nil {
		t.Fatalf("a refused request started a job: %+v", v.Job)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.roots) != 0 {
		t.Fatalf("a refused request ran a scanner: %v", fake.roots)
	}
}

// TestSecurityScanChosenSteps: a job over a list of projects (repeats
// dropped) runs only the chosen scanners, names them in steps, reports the
// step it is on by id with its start time, and records each result's start
// and duration; a job choosing only the history step never calls the seam.
func TestSecurityScanChosenSteps(t *testing.T) {
	s, root := newTestServer(t)
	fake := &fakeScanNow{release: make(chan struct{})}
	s.opts.SecurityScanNow = fake.seam()
	hash := secposture.ProjectRootHash(root)

	if w := securityPost(s.handleSecurityScan, "/api/security/scan", `{"projects":["`+hash+`","`+hash+`"],"steps":["code"]}`, true); w.Code != http.StatusAccepted {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	var running *securityScanJobJS
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if v := getSecurityScan(t, s); v.Job != nil && v.Job.Current != nil {
			running = v.Job
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if running == nil {
		t.Fatal("the job never reported its current step")
	}
	if cur := running.Current; cur.StepID != "code" || cur.Step != "Code rules" || cur.StartedAt == "" || cur.ProjectRootHash != hash {
		t.Fatalf("current: %+v", cur)
	}
	if running.Scope != "project" || running.Total != 1 || len(running.Steps) != 1 || running.Steps[0] != "code" {
		t.Fatalf("running job: %+v", running)
	}
	close(fake.release)
	job := waitSecurityScan(t, s, securityScanDone)
	if job.Current != nil || len(job.Projects) != 1 {
		t.Fatalf("done job: %+v", job)
	}
	steps := job.Projects[0].Steps
	if len(steps) != 1 || steps[0].ID != "code" || steps[0].Outcome != "findings" || steps[0].StartedAt == "" || steps[0].DurationMS < 0 {
		t.Fatalf("only the chosen step ran, timed: %+v", steps)
	}
	if _, err := time.Parse(time.RFC3339, steps[0].StartedAt); err != nil {
		t.Fatalf("started_at: %v", err)
	}

	// Only the history step: the seam is never called.
	if w := securityPost(s.handleSecurityScan, "/api/security/scan", `{"project":"`+hash+`","steps":["`+securityScanHistoryStep+`"]}`, true); w.Code != http.StatusAccepted {
		t.Fatalf("history only: %d %s", w.Code, w.Body)
	}
	job = waitSecurityScan(t, s, securityScanDone)
	if len(job.Steps) != 1 || job.Steps[0] != securityScanHistoryStep || len(job.Projects[0].Steps) != 1 ||
		job.Projects[0].Steps[0].ID != securityScanHistoryStep || job.Projects[0].Steps[0].Outcome != dashapi.SecurityScanSkipped {
		t.Fatalf("history only job: %+v", job)
	}
	fake.mu.Lock()
	called := append([]string(nil), fake.roots...)
	fake.mu.Unlock()
	if len(called) != 1 || called[0] != root+"|code" {
		t.Fatalf("seam calls: %v", called)
	}
}

// TestSecurityScanChosenStepsTable is the step resolution's rows: none
// chosen is every ready step in list order; a chosen set runs in list
// order, each once; an unknown id and a step that is not ready (with and
// without a reason) are refused in words.
func TestSecurityScanChosenStepsTable(t *testing.T) {
	all := []dashapi.SecurityScanStep{
		{ID: "history", Label: "Secrets in recent commits", Ready: true},
		{ID: "code", Label: "Code rules", Ready: true},
		{ID: "deps", Label: "Dependencies", Ready: false, Reason: "not installed"},
		{ID: "iac.kics", Label: "KICS", Ready: false},
		{ID: "actionlint", Label: "Workflows", Ready: true},
	}
	cases := []struct {
		name    string
		chosen  []string
		want    string
		wantErr string
	}{
		{"none chosen is every ready step", nil, "history,code,actionlint", ""},
		{"list order, each once", []string{"actionlint", "history", "actionlint"}, "history,actionlint", ""},
		{"unknown", []string{"code", "trivy"}, "", "unknown scanner: trivy"},
		{"not ready", []string{"deps"}, "", "Dependencies is not ready: not installed"},
		{"not ready, no reason", []string{"iac.kics"}, "", "KICS is not ready: not ready"},
	}
	for _, c := range cases {
		got, err := securityScanChosenSteps(all, c.chosen)
		if c.wantErr != "" {
			if err == nil || err.Error() != c.wantErr {
				t.Errorf("%s: err %v, want %q", c.name, err, c.wantErr)
			}
			continue
		}
		var ids []string
		for _, st := range got {
			ids = append(ids, st.ID)
		}
		if err != nil || strings.Join(ids, ",") != c.want {
			t.Errorf("%s: %v %v, want %s", c.name, ids, err, c.want)
		}
	}
}
