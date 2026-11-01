package sandboxvm

import (
	"strings"
	"testing"
)

// TestReadBackWhileRunning (the first live run, D9): a shortfall found once
// the run is under way says the run was ended, never that the agent was not
// started; before boot the reason is unchanged.
func TestReadBackWhileRunning(t *testing.T) {
	p := testPlan()
	if v := ReadBackWhileRunning(p, []byte("not json")); v.OK() || strings.Contains(v.Reason, "was not started") || !strings.HasSuffix(v.Reason, "; the run was ended") {
		t.Fatalf("%+v", v)
	}
	if v := ReadBack(p, []byte("not json"), false); !strings.HasSuffix(v.Reason, "; the agent was not started") {
		t.Fatalf("%+v", v)
	}
}
