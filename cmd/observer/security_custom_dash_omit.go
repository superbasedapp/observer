//go:build sbo_omit_security || sbo_omit_security_scan_custom

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// customScannersForDashboard has nothing to offer in a build without the
// security module or its security.scan.custom component.
func customScannersForDashboard(context.Context, componentstate.Snapshot, string, *store.Store) any {
	return nil
}

// startCustomScanSchedule starts nothing in a build without the
// security.scan.custom component.
func startCustomScanSchedule(context.Context, *gatedGroup, string, componentstate.Snapshot) {}
