//go:build !sbo_omit_security

package dashboard

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// backendLM is a launch manager that reports which sandbox backend built the
// box (FreshLaunchDetailer.Backend), standing in for the daemon's adapter. It
// records the spec through the embedded fake and counts the detailed calls.
type backendLM struct {
	*fakeLaunchManager
	backend string
	detail  int
}

func (m *backendLM) CreateFreshDetailed(spec FreshLaunchSpec) (FreshLaunchResult, error) {
	m.detail++
	h, err := m.fakeLaunchManager.CreateFresh(spec)
	return FreshLaunchResult{Handle: h, Backend: m.backend}, err
}

// TestSecurityAssessRunRecordsTheBackendTheLauncherBuilt: a run records the
// sandbox backend that built its box, as the launcher resolved it. A threat model
// has no sandbox rule, so its verdict names no backend, and the Automatic choice
// of the New terminal step is resolved only by the launcher: before the launcher
// reported it the row said "in a sandbox" and not which (live defect 4).
func TestSecurityAssessRunRecordsTheBackendTheLauncherBuilt(t *testing.T) {
	good := assessProbe("proxy_only", "claude-code")
	cases := []struct {
		name string
		body map[string]any
		// manager: "plain" has no detailed call; otherwise the backend it reports.
		manager     string
		reported    string
		wantBackend string
		sandboxed   bool
		detailed    int
	}{
		{"a threat model in a box: the launcher's backend is recorded", map[string]any{"assessment": "threat_model", "sandbox": true}, "detailer", "bwrap", "bwrap", true, 1},
		{"another backend is recorded as it was reported", map[string]any{"assessment": "threat_model", "sandbox": true}, "detailer", "lima", "lima", true, 1},
		{"a launcher that names none leaves the row unnamed", map[string]any{"assessment": "threat_model", "sandbox": true}, "detailer", "", "", true, 1},
		{"a launcher that cannot report leaves the row unnamed, the box still runs", map[string]any{"assessment": "threat_model", "sandbox": true}, "plain", "", "", true, 0},
		{"a threat model on the host records no backend and asks no detail", map[string]any{"assessment": "threat_model"}, "detailer", "bwrap", "", false, 0},
		{"a pen test: the launcher's backend is recorded", map[string]any{"assessment": "pentest_local"}, "detailer", "bwrap", "bwrap", true, 1},
		{"a pen test whose launcher names none keeps the verdict's backend", map[string]any{"assessment": "pentest_local"}, "detailer", "", "bwrap", true, 1},
		{"a pen test on a launcher that cannot report keeps the verdict's backend", map[string]any{"assessment": "pentest_local"}, "plain", "", "bwrap", true, 0},
		{"what ran wins over what was asked for", map[string]any{"assessment": "pentest_local", "backend": "bwrap"}, "detailer", "lima", "lima", true, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, lm, root := assessTestServer(t, &good)
			var det *backendLM
			if tc.manager == "detailer" {
				det = &backendLM{fakeLaunchManager: lm, backend: tc.reported}
				s.opts.LaunchManager = det
			}
			id := secassesssvc.NewRunID()
			// A pen test is posted with its target and consent, a threat model without.
			body := map[string]any{"project_root_hash": secposture.ProjectRootHash(root), "run_id": id, "tool": "claude-code"}
			if tc.body["assessment"] == "pentest_local" {
				body = dialogBody("pentest_local", secposture.ProjectRootHash(root), id, nil)
			}
			for k, v := range tc.body {
				body[k] = v
			}
			w := postAssess(t, s.handleSecurityAssessLaunch, "/api/security/assessments/launch", body, true)
			if w.Code != http.StatusOK {
				t.Fatalf("launch: %d %s", w.Code, w.Body)
			}
			run, ok := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath)).Get(id)
			if !ok {
				t.Fatal("the run was not recorded")
			}
			if run.Sandboxed != tc.sandboxed || run.Backend != tc.wantBackend {
				t.Errorf("run: sandboxed %v backend %q, want %v %q", run.Sandboxed, run.Backend, tc.sandboxed, tc.wantBackend)
			}
			if det != nil && det.detail != tc.detailed {
				t.Errorf("the detailed call was used %d times, want %d", det.detail, tc.detailed)
			}
			// The row the list serves carries it, so the web names it.
			if view := securityAssessRunView(run, root); view.Backend != tc.wantBackend {
				t.Errorf("run view backend %q, want %q", view.Backend, tc.wantBackend)
			}
		})
	}
}

// TestGenericLaunchReportsNothingBeyondTheHandle: the plain terminal launch
// route is unchanged by the backend seam: a sandboxed launch asks the detailed
// call, and the wire response carries no backend member.
func TestGenericLaunchReportsNothingBeyondTheHandle(t *testing.T) {
	r := terminalLaunchResponse{Token: "T", Tool: "claude-code", backend: "bwrap"}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != `{"token":"T","tool":"claude-code","subcommand":"","has_project_root":false}` {
		t.Errorf("wire = %s", got)
	}
}
