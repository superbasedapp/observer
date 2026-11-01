package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestPrintOrgStatusShowsUnshippableRows: `observer org status` prints the
// daemon's oversized snapshot row report, one line per family with names and
// sizes only.
func TestPrintOrgStatusShowsUnshippableRows(t *testing.T) {
	var out bytes.Buffer
	printOrgStatus(&out, orgStatusReport{
		State: orgclient.EnrolmentState{Enrolled: true, OrgID: "org-1"},
		Oversized: []store.OrgPushOversizedRow{{
			Family: "session_network", Rows: 2, LargestBytes: 2345678, BudgetBytes: 983040, LastSeen: "2026-10-27T16:00:00Z",
		}},
	})
	got := out.String()
	if !strings.Contains(got, "Unshippable rows: session_network: 2 row(s) larger than the 983040-byte snapshot budget (largest 2345678 bytes") ||
		!strings.Contains(got, "max_push_bytes") {
		t.Fatalf("org status output lacks the unshippable rows line:\n%s", got)
	}
}
