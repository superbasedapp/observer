package diag

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// TestRouteHostNamesUnknownRouteFiles pins R-188 F6 in proxy.route_host: a
// route whose file the inspector cannot name (a relative relocation
// variable) is reported with the variable and raises an OK check to a
// warning; it is never reported as a present route.
func TestRouteHostNamesUnknownRouteFiles(t *testing.T) {
	cases := []struct {
		name       string
		in         Check
		routes     []proxyroute.RouteStatus
		wantStatus Status
		wantDetail string
	}{
		{
			"no unknown route leaves the check alone",
			Check{Status: StatusOK, Message: "m"},
			[]proxyroute.RouteStatus{{Tool: "codex", State: proxyroute.RouteOurs}},
			StatusOK, "",
		},
		{
			"relative CODEX_HOME warns naming the variable",
			Check{Status: StatusOK, Message: "m"},
			[]proxyroute.RouteStatus{{Tool: "codex", State: proxyroute.RouteUnknown, UnresolvedBy: "CODEX_HOME"}},
			StatusWarn, "codex: its route file is unknown because CODEX_HOME is set to a relative path",
		},
		{
			"a warning stays a warning",
			Check{Status: StatusWarn, Message: "m"},
			[]proxyroute.RouteStatus{{Tool: "claude-code", State: proxyroute.RouteUnknown, UnresolvedBy: "CLAUDE_CONFIG_DIR"}},
			StatusWarn, "CLAUDE_CONFIG_DIR is set to a relative path",
		},
		{
			"a row with no path on this OS",
			Check{Status: StatusOK, Message: "m"},
			[]proxyroute.RouteStatus{{Tool: "crush", State: proxyroute.RouteUnknown}},
			StatusWarn, "crush: its route file has no path on this OS",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := withUnknownRoutes(tc.in, tc.routes)
			if got.Status != tc.wantStatus {
				t.Errorf("status %s, want %s", got.Status, tc.wantStatus)
			}
			if tc.wantDetail == "" {
				if len(got.Details) != 0 || got.Message != tc.in.Message {
					t.Errorf("changed a check with no unknown route: %+v", got)
				}
				return
			}
			if !strings.Contains(strings.Join(got.Details, "\n"), tc.wantDetail) || !strings.Contains(got.Message, "route file unknown") {
				t.Errorf("got %+v, want a detail containing %q", got, tc.wantDetail)
			}
		})
	}
}
