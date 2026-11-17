package invariant

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/netlanes"
)

// netlanes_coverage_test.go ties the user-facing lane list `observer
// privacy` prints (internal/netlanes, Getting started v2) to the developer
// lane table in egress_lanes_test.go, so the two are one source:
//
//   - every live lane that can leave the machine (egressRemote) is named by
//     at least one user-facing row: a new remote lane cannot ship without a
//     plain-language row;
//   - every id a user-facing row names is a declared lane.
func TestNetLanesCoverEveryRemoteEgressLane(t *testing.T) {
	declared := map[string]egressKind{}
	for _, l := range egressLanes {
		declared[l.ID] = l.Kind
	}
	covered := map[string]bool{}
	for _, row := range netlanes.Lanes {
		for _, id := range row.EgressIDs {
			kind, ok := declared[id]
			if !ok {
				t.Errorf("netlanes row %q names %q, which is not a declared egress lane", row.ID, id)
				continue
			}
			if kind != egressRemote {
				t.Errorf("netlanes row %q names %q, a %s lane that never leaves the machine", row.ID, id, kind)
			}
			covered[id] = true
		}
	}
	for _, l := range egressLanes {
		if l.Kind == egressRemote && !covered[l.ID] {
			t.Errorf("remote egress lane %q (%s) has no row in internal/netlanes; add a plain-language row so `observer privacy` lists it", l.ID, l.Pkg)
		}
	}
}
