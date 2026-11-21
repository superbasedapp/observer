//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// The dashboard's online dependency check (decision P-1 of
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md): POST
// /api/security/scan's online, behind the seam's online gate, handed to the
// steps as the job's options.

// onlineScanSeam is a SecurityScanNow with a ready dependency step, an
// online gate the test can open, and a Scan that records its options and
// reports the online word the cmd layer would.
type onlineScanSeam struct {
	mu     sync.Mutex
	online dashapi.SecurityScanOnline
	calls  []string
}

func (f *onlineScanSeam) seam() *dashapi.SecurityScanNow {
	return &dashapi.SecurityScanNow{
		Steps: func(context.Context) []dashapi.SecurityScanStep {
			return []dashapi.SecurityScanStep{
				{ID: "code", Label: "Code rules", Ready: true},
				{ID: "deps", Label: "Dependencies (OSV)", Ready: true},
			}
		},
		Scan: func(_ context.Context, _, step string, opts dashapi.SecurityScanOptions) dashapi.SecurityScanResult {
			f.mu.Lock()
			defer f.mu.Unlock()
			res := dashapi.SecurityScanResult{Outcome: "clean"}
			mark := "local"
			if opts.Online {
				mark = "online"
				if step == "deps" {
					res.Online = dashapi.SecurityScanOnlineChecked
				}
			}
			f.calls = append(f.calls, step+"|"+mark)
			return res
		},
		Online: func(context.Context) dashapi.SecurityScanOnline {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.online
		},
	}
}

func (f *onlineScanSeam) set(st dashapi.SecurityScanOnline) {
	f.mu.Lock()
	f.online = st
	f.mu.Unlock()
}

func (f *onlineScanSeam) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.calls
	f.calls = nil
	return out
}

// TestSecurityScanOnline: the GET shows the online check's state; a request
// for online checks while the gate is closed is refused with the gate's
// reason and starts nothing; the POST reads the gate fresh (the GET's cache
// does not hold back an accept just given); online without the step it
// applies to is refused; a job with online passes it to every step and the
// dependency step's result says it checked online; a job without it passes
// nothing.
func TestSecurityScanOnline(t *testing.T) {
	s, root := newTestServer(t)
	f := &onlineScanSeam{online: dashapi.SecurityScanOnline{Step: "deps", Reason: "online_checks_off"}}
	s.opts.SecurityScanNow = f.seam()
	hash := secposture.ProjectRootHash(root)

	v := getSecurityScan(t, s)
	if v.Online == nil || v.Online.Open || v.Online.Reason != "online_checks_off" || v.Online.Step != "deps" {
		t.Fatalf("view online: %+v", v.Online)
	}
	body := `{"project":"` + hash + `","steps":["deps"],"online":true}`
	if w := securityPost(s.handleSecurityScan, "/api/security/scan", body, true); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "online_checks_off") {
		t.Fatalf("closed gate: %d %s", w.Code, w.Body)
	}
	if v := getSecurityScan(t, s); v.Job != nil {
		t.Fatalf("a refused online request started a job: %+v", v.Job)
	}

	// The accept is given; the GET's cached state is still closed, the POST
	// reads it fresh.
	f.set(dashapi.SecurityScanOnline{Step: "deps", Open: true})
	if w := securityPost(s.handleSecurityScan, "/api/security/scan", `{"project":"`+hash+`","steps":["code"],"online":true}`, true); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "Dependencies (OSV)") {
		t.Fatalf("online without the dependency step: %d %s", w.Code, w.Body)
	}
	if w := securityPost(s.handleSecurityScan, "/api/security/scan", body, true); w.Code != http.StatusAccepted {
		t.Fatalf("online job: %d %s", w.Code, w.Body)
	}
	job := waitSecurityScan(t, s, securityScanDone)
	if !job.Online || len(job.Projects) != 1 || len(job.Projects[0].Steps) != 1 || job.Projects[0].Steps[0].Online != dashapi.SecurityScanOnlineChecked {
		t.Fatalf("online job: %+v", job)
	}
	if got := f.take(); len(got) != 1 || got[0] != "deps|online" {
		t.Fatalf("seam calls: %v", got)
	}

	// Without online: the steps are handed no online option.
	if w := securityPost(s.handleSecurityScan, "/api/security/scan", `{"project":"`+hash+`"}`, true); w.Code != http.StatusAccepted {
		t.Fatalf("local job: %d %s", w.Code, w.Body)
	}
	job = waitSecurityScan(t, s, securityScanDone)
	if job.Online || job.Projects[0].Steps[len(job.Projects[0].Steps)-1].Online != "" {
		t.Fatalf("local job: %+v", job)
	}
	for _, c := range f.take() {
		if strings.HasSuffix(c, "|online") {
			t.Fatalf("a job without online passed it: %s", c)
		}
	}
}

// TestSecurityScanOnlineNotOffered: with a seam that has no online check (a
// build without the dependency scanners) the GET carries no online block
// and a request for one is refused.
func TestSecurityScanOnlineNotOffered(t *testing.T) {
	s, root := newTestServer(t)
	fake := &fakeScanNow{release: make(chan struct{})}
	s.opts.SecurityScanNow = fake.seam()
	if v := getSecurityScan(t, s); v.Online != nil {
		t.Fatalf("online offered with no seam: %+v", v.Online)
	}
	body := `{"project":"` + secposture.ProjectRootHash(root) + `","steps":["code"],"online":true}`
	if w := securityPost(s.handleSecurityScan, "/api/security/scan", body, true); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "not available") {
		t.Fatalf("online with no seam: %d %s", w.Code, w.Body)
	}
}

// TestSecurityScanOnlineAllowed is the refusal's rows, top-down.
func TestSecurityScanOnlineAllowed(t *testing.T) {
	all := []dashapi.SecurityScanStep{{ID: "history", Label: "Secrets", Ready: true}, {ID: "deps", Label: "Dependencies (OSV)", Ready: true}}
	open := &dashapi.SecurityScanOnline{Step: "deps", Open: true}
	cases := []struct {
		name   string
		online *dashapi.SecurityScanOnline
		chosen []dashapi.SecurityScanStep
		want   string
	}{
		{"not in this build", nil, all, "not available in this build"},
		{"online checks off", &dashapi.SecurityScanOnline{Step: "deps", Reason: "online_checks_off"}, all, "online_checks_off"},
		{"disclosure not accepted", &dashapi.SecurityScanOnline{Step: "deps", Reason: "disclosure_not_shown"}, all, "disclosure_not_shown"},
		{"closed with no reason", &dashapi.SecurityScanOnline{Step: "deps"}, all, "closed"},
		{"the step not chosen", open, all[:1], "the Dependencies (OSV) scanner"},
		{"allowed", open, all, ""},
	}
	for _, c := range cases {
		err := securityScanOnlineAllowed(c.online, all, c.chosen)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}
