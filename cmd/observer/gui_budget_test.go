package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestGUIManagedBudgetRefusesExhaustedCapBeforeResolutionOrSpawn pins the
// order: the managed admission check returns before binary resolution, and
// therefore before a detached spawn. No resolver is supplied, so reaching
// resolution at all would be visible.
func TestGUIManagedBudgetRefusesExhaustedCapBeforeResolutionOrSpawn(t *testing.T) {
	t.Parallel()
	configPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	exhaustManagedBudgetLaunchBudget(t, dbPath, "cursor")
	launcher := &guiLauncher{configPath: func() string { return configPath }}
	result, err := launcher.SpawnGUI(termsvc.GUISpawnRequest{ID: "cursor-ide"})
	if !errors.Is(err, errBudgetLaunchDenied) || result.PID != 0 {
		t.Fatalf("exhausted managed GUI admission result=%+v err=%v", result, err)
	}
}

// TestGUIManagedBudgetAdmitsSharedHostUnderCap is the other half, and the
// correction it pins: a GUI launch starts an IDE/desktop HOST, which the
// registry declares as a shared surface with no process boundary a cutoff
// could bind to. Refusing it at $0 reported a coverage gap the org posture
// already reports, while blocking work that is under the cap.
func TestGUIManagedBudgetAdmitsSharedHostUnderCap(t *testing.T) {
	t.Parallel()
	configPath, _ := writeManagedBudgetLaunchFixture(t, true, "enforce")
	class, ok := integration.GUILaunchSurfaceClass("cursor-ide")
	if !ok || class != integration.SurfaceSharedHost {
		t.Fatalf("test premise: cursor-ide surface class = %q ok=%v, want shared host", class, ok)
	}
	err := enforceBudgetControlledLaunch(context.Background(), configPath, "cursor-ide",
		budgetLaunchEvidence{Route: budgetLaunchRouteUnknown, SurfaceClass: class})
	if err != nil {
		t.Fatalf("under-cap shared-host GUI launch refused: %v", err)
	}
}

// TestGUIManagedBudgetKeepsUnknownLaunchFailClosed: an id the registry does
// not know declares no surface, so it inherits no exemption.
func TestGUIManagedBudgetKeepsUnknownLaunchFailClosed(t *testing.T) {
	t.Parallel()
	configPath, _ := writeManagedBudgetLaunchFixture(t, true, "enforce")
	if _, ok := integration.GUILaunchSurfaceClass("not-a-launch-row"); ok {
		t.Fatal("test premise: the id must be unknown to the GUI registry")
	}
	err := enforceBudgetControlledLaunch(context.Background(), configPath, "not-a-launch-row",
		budgetLaunchEvidence{Route: budgetLaunchRouteUnknown})
	if !errors.Is(err, errBudgetLaunchUncontrolled) ||
		!strings.Contains(err.Error(), "no verified Observer budget-admission route") {
		t.Fatalf("unknown GUI id admission error = %v, want fail-closed refusal", err)
	}
}
