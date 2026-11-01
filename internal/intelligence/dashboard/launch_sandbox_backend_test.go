package dashboard

import (
	"net/http"
	"strings"
	"testing"
)

// betaOnlyProbe is a probe on a host whose only available enabled row is a
// beta one: the overall verdict says beta_not_chosen (ruling P-062), the row
// itself is available, and a planned row is listed.
func betaOnlyProbe() SandboxAvailability {
	av := availableProbe()
	av.Available, av.Verdict, av.Backend = false, "beta_not_chosen", "oci-runc"
	av.Reason = "oci-runc is available but not chosen"
	av.Backends = []SandboxBackendAvail{
		{ID: "bwrap", Maturity: "shipped", Available: false, Verdict: "disabled_by_config", Reason: "not in backends"},
		{ID: "oci-runc", Maturity: "preview", Available: true, Beta: true, Verification: "doc"},
		{ID: "cloud-hypervisor", Maturity: "planned", Available: false, Verdict: "planned"},
	}
	return av
}

// TestTerminalLaunchBackendChoice (lane SBX-P3B, rulings P-062 and P-067):
// the New Terminal picker's per-launch backend reaches the launch only when
// one is chosen and only after the server re-validates it against its own
// probed rows. A chosen beta row runs; a launch naming nothing (absent or
// "auto") is refused on a host where only a beta row is available; an
// unknown, planned or unavailable choice never reaches CreateFresh.
func TestTerminalLaunchBackendChoice(t *testing.T) {
	cases := []struct {
		name     string
		body     terminalLaunchRequest
		want     int
		wantSpec string
		called   bool
	}{
		{"chosen beta row runs", terminalLaunchRequest{Tool: "claude-code", ProjectRoot: "/p", Sandbox: true, Backend: "oci-runc"}, http.StatusOK, "oci-runc", true},
		{"no backend keeps the overall refusal", terminalLaunchRequest{Tool: "claude-code", ProjectRoot: "/p", Sandbox: true}, http.StatusNotImplemented, "", false},
		{"auto is no backend", terminalLaunchRequest{Tool: "claude-code", ProjectRoot: "/p", Sandbox: true, Backend: "auto"}, http.StatusNotImplemented, "", false},
		{"unknown row", terminalLaunchRequest{Tool: "claude-code", ProjectRoot: "/p", Sandbox: true, Backend: "kata"}, http.StatusBadRequest, "", false},
		{"planned row", terminalLaunchRequest{Tool: "claude-code", ProjectRoot: "/p", Sandbox: true, Backend: "cloud-hypervisor"}, http.StatusBadRequest, "", false},
		{"unavailable row", terminalLaunchRequest{Tool: "claude-code", ProjectRoot: "/p", Sandbox: true, Backend: "bwrap"}, http.StatusForbidden, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lm := &countingLaunchManager{fakeLaunchManager: &fakeLaunchManager{}}
			s := newLaunchTestServerWithSandbox(t, lm, &fakeSandboxProber{avail: betaOnlyProbe()})
			rec := postTerminalLaunchSandbox(t, s.Handler(), tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
			if (lm.createFreshCalls > 0) != tc.called {
				t.Fatalf("CreateFresh called %d times, want called=%v", lm.createFreshCalls, tc.called)
			}
			if tc.called && lm.lastFreshSpec.Backend != tc.wantSpec {
				t.Fatalf("spec backend %q, want %q", lm.lastFreshSpec.Backend, tc.wantSpec)
			}
		})
	}
}

// TestTerminalLaunchBackendIgnoredWithoutSandbox: a backend on an
// unsandboxed launch is dropped, so the spec is what it always was.
func TestTerminalLaunchBackendIgnoredWithoutSandbox(t *testing.T) {
	lm := &fakeLaunchManager{}
	s := newLaunchTestServerWithSandbox(t, lm, &fakeSandboxProber{avail: availableProbe()})
	rec := postTerminalLaunchSandbox(t, s.Handler(), terminalLaunchRequest{Tool: "claude-code", Backend: "oci-runc"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d (body %s)", rec.Code, rec.Body.String())
	}
	if lm.lastFreshSpec.Sandbox || lm.lastFreshSpec.Backend != "" {
		t.Fatalf("spec %+v, want no sandbox and no backend", lm.lastFreshSpec)
	}
	if strings.Contains(rec.Body.String(), "backend") {
		t.Fatalf("unexpected body %s", rec.Body.String())
	}
}
