//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals && !sbo_omit_security

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// TestRelayChildCleanScanCoversTheHostMarker (lane sec-gate3 milestone 2e,
// the SEC-GATE2 audit note in plans decision log P-032): a relayed commit
// is evaluated by the relay child on the host, so the dirty counter its
// quick-scan request carries is the HOST marker of the run's project, not
// the box's (the observer directory is a tmpfs in the box). A clean answer
// therefore records the host counter as scanned and clears the host's
// dirty state for the next commit, as a host commit does; nothing in the
// box can hold it dirty. The counter is read from the host layout under
// the run's project root, whatever directory the payload names.
func TestRelayChildCleanScanCoversTheHostMarker(t *testing.T) {
	ws, other := twoRepos(t)
	n := newGatefixNode(t)
	hash := secposture.ProjectRootHash(ws)
	for range 3 {
		if err := secposture.RaiseDirty(n.layout, hash); err != nil {
			t.Fatal(err)
		}
	}
	daemonProcess(t, ws)
	pe := &policy.Event{Kind: policy.KindShellExec, ActionType: models.ActionRunCommand, Target: "git commit -m wip", Cwd: other, ProjectRoot: other}
	root := hookProjectRoot(pe)
	if root != ws {
		t.Fatalf("project %q, want the run's %q", root, ws)
	}
	plan := securityQuickScanPlanFor(pe, root, nil)
	plan.captureDirty(currentHookSecurity(n.cfgPath).layout, root)
	req := plan.first()
	if req == nil || req.ProjectRoot != ws || req.DirtySeen != 3 {
		t.Fatalf("quick-scan request %+v, want the run's project with the host counter 3", req)
	}
}
