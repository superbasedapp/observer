package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestAppsPendingRules pins FR-M01: every AI Apps feature whose wiring runs
// only at daemon start is named after a hot enable, one case per
// appsPendingRules row, and nothing is pending on a daemon that started with
// AI Apps on.
func TestAppsPendingRules(t *testing.T) {
	saved := obsProxyRailInBuild
	t.Cleanup(func() { obsProxyRailInBuild = saved })

	base := func() config.Config {
		c := config.Default()
		c.Observability.Enabled = true
		c.Observability.ProxyTurnTraces = false
		return c
	}
	cases := []struct {
		name     string
		bootOn   bool
		railIn   bool
		edit     func(*config.Config)
		share    func() store.ShareOptions
		expected []string
	}{
		{name: "nothing configured", railIn: true, edit: func(*config.Config) {}},
		{name: "admission", railIn: true, edit: func(c *config.Config) { c.Observability.Admission.Enabled = true }, expected: []string{appsPendingAdmission}},
		{
			name: "egress with admission", railIn: true,
			edit: func(c *config.Config) {
				c.Observability.Admission.Enabled = true
				c.Observability.Egress.Enabled = true
			},
			expected: []string{appsPendingAdmission, appsPendingEgress},
		},
		{name: "egress without admission never runs", railIn: true, edit: func(c *config.Config) { c.Observability.Egress.Enabled = true }},
		{name: "proxy turn traces", railIn: true, edit: func(c *config.Config) { c.Observability.ProxyTurnTraces = true }, expected: []string{appsPendingProxyTurns}},
		{name: "proxy turn traces, no proxy rail in this build", railIn: false, edit: func(c *config.Config) { c.Observability.ProxyTurnTraces = true }},
		{name: "alerts", railIn: true, edit: func(c *config.Config) { c.Observability.Alerts.Enabled = true }, expected: []string{appsPendingAlerts}},
		{
			name: "organization share tiers", railIn: true,
			edit:     func(c *config.Config) { c.OrgClient.Enabled = true },
			share:    func() store.ShareOptions { return store.ShareOptions{ObsSummary: true} },
			expected: []string{appsPendingShareTiers},
		},
		{
			name: "enrolled with no obs tier", railIn: true,
			edit:  func(c *config.Config) { c.OrgClient.Enabled = true },
			share: func() store.ShareOptions { return store.ShareOptions{} },
		},
		{
			name: "every row, in table order", railIn: true,
			edit: func(c *config.Config) {
				c.Observability.Admission.Enabled = true
				c.Observability.Egress.Enabled = true
				c.Observability.ProxyTurnTraces = true
				c.Observability.Alerts.Enabled = true
				c.OrgClient.Enabled = true
			},
			share:    func() store.ShareOptions { return store.ShareOptions{ObsTraces: true} },
			expected: []string{appsPendingAdmission, appsPendingEgress, appsPendingProxyTurns, appsPendingAlerts, appsPendingShareTiers},
		},
		{
			name: "AI Apps on at start: nothing waits", bootOn: true, railIn: true,
			edit: func(c *config.Config) {
				c.Observability.Admission.Enabled = true
				c.Observability.ProxyTurnTraces = true
				c.Observability.Alerts.Enabled = true
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obsProxyRailInBuild = tc.railIn
			cfg := base()
			tc.edit(&cfg)
			a := newAppsRuntime(appsRuntimeOptions{BootOn: tc.bootOn, Share: tc.share})
			if got := a.pending(cfg); !slices.Equal(got, tc.expected) {
				t.Fatalf("pending = %v, want %v", got, tc.expected)
			}
		})
	}
	// Every row has a case naming it.
	for _, r := range appsPendingRules {
		found := false
		for _, tc := range cases {
			if slices.Contains(tc.expected, r.name) {
				found = true
			}
		}
		if !found {
			t.Errorf("rule %q has no case", r.name)
		}
	}
}

// TestAdmissionStatusPendingMark pins FR-M01's status rule: after a hot
// enable with admission waiting for the next start, the admission status
// says so; a non-200 or non-object answer passes through untouched, and
// other routes are left alone.
func TestAdmissionStatusPendingMark(t *testing.T) {
	status := func(code int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
		}
	}
	other := func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"x":1}`)) }
	cases := []struct {
		name    string
		handler http.HandlerFunc
		code    int
		pending bool
		raw     string
	}{
		{name: "200 object: marked", handler: status(http.StatusOK, `{"available":false,"enabled":false,"mode":"off"}`), code: http.StatusOK, pending: true},
		{name: "404 passes through", handler: status(http.StatusNotFound, "admission not enabled\n"), code: http.StatusNotFound, raw: "admission not enabled\n"},
		{name: "200 non-object passes through", handler: status(http.StatusOK, `[1,2]`), code: http.StatusOK, raw: `[1,2]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			routes := withAdmissionPendingStatus([]dashapi.ExtraRoute{
				{Pattern: obsAdmissionStatusPattern, Handler: tc.handler},
				{Pattern: "GET /api/obs/enabled", Handler: other},
			})
			rr := httptest.NewRecorder()
			routes[0].Handler(rr, httptest.NewRequest(http.MethodGet, "/api/obs/admission/status", nil))
			if rr.Code != tc.code {
				t.Fatalf("code %d, want %d", rr.Code, tc.code)
			}
			if rr.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("headers not kept: %v", rr.Header())
			}
			if tc.raw != "" {
				if rr.Body.String() != tc.raw {
					t.Fatalf("body %q, want %q", rr.Body.String(), tc.raw)
				}
				return
			}
			var m map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
				t.Fatal(err)
			}
			if m["pending_next_start"] != tc.pending || m["available"] != false || m["mode"] != "off" {
				t.Fatalf("status %v", m)
			}
			rr = httptest.NewRecorder()
			routes[1].Handler(rr, httptest.NewRequest(http.MethodGet, "/api/obs/enabled", nil))
			if rr.Body.String() != `{"x":1}` {
				t.Fatalf("another route was changed: %q", rr.Body.String())
			}
		})
	}
}
