//go:build !sbo_omit_security

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
)

// The floors' seam test helper, shared by the deps floor tests and the
// left-sec end-to-end test (R-008).

// unbindSecurityFloors leaves the floors' seam unbound for the test and
// restores it after.
func unbindSecurityFloors(t *testing.T) {
	t.Helper()
	secScanning.mu.Lock()
	savedActive, savedHeld, savedLoad := secScanning.active, secScanning.held, secScanning.load
	savedBase, savedOK, savedAt, savedOff := secScanning.base, secScanning.baseOK, secScanning.loadedAt, secScanning.moduleOff
	secScanning.active, secScanning.held, secScanning.load, secScanning.baseOK = nil, nil, nil, false
	secScanning.mu.Unlock()
	t.Cleanup(func() {
		secScanning.mu.Lock()
		secScanning.active, secScanning.held, secScanning.load = savedActive, savedHeld, savedLoad
		secScanning.base, secScanning.baseOK, secScanning.loadedAt, secScanning.moduleOff = savedBase, savedOK, savedAt, savedOff
		secScanning.mu.Unlock()
		securityscanning.SetNodeFactsProvider(nil)
	})
}
