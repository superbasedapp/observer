package cloudagents

import "testing"

// TestLifecycleOfDetail pins the status-detail refinement row by row: a
// detail a row names refines the status; any other detail, or none, leaves
// the status mapping alone.
func TestLifecycleOfDetail(t *testing.T) {
	devin := mustConn(t, ConnectorDevin)
	cursor := mustConn(t, ConnectorCursorCloud)
	cases := []struct {
		name           string
		c              Connector
		status, detail string
		want           Lifecycle
	}{
		{"devin running waiting_for_user is waiting (live)", devin, "running", "waiting_for_user", LifecycleWaiting},
		{"case and space tolerated", devin, " RUNNING ", "Waiting_For_User", LifecycleWaiting},
		{"devin running working stays running", devin, "running", "working", LifecycleRunning},
		{"devin running unknown detail stays running", devin, "running", "something_new", LifecycleRunning},
		{"devin running no detail", devin, "running", "", LifecycleRunning},
		{"detail never refines another status", devin, "finished", "waiting_for_user", LifecycleSucceeded},
		{"unknown status stays unknown", devin, "mystery", "waiting_for_user", LifecycleUnknown},
		{"a connector without rows ignores details", cursor, "running", "waiting_for_user", LifecycleRunning},
	}
	for _, tc := range cases {
		if got := tc.c.LifecycleOfDetail(tc.status, tc.detail); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

// TestStatusDetailRowsRefineKnownStatuses: every refinement row names a
// status its connector already maps, in lower case, and lands on a known
// lifecycle.
func TestStatusDetailRowsRefineKnownStatuses(t *testing.T) {
	for _, c := range Connectors {
		for _, r := range c.StatusDetails {
			if _, ok := c.Statuses[r.Status]; !ok || r.Detail == "" || r.Lifecycle == LifecycleUnknown || r.Lifecycle == "" {
				t.Errorf("%s: refinement row %+v", c.ID, r)
			}
		}
	}
}
