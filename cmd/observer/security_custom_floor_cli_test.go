//go:build !sbo_omit_security && !sbo_omit_security_deps && !sbo_omit_security_scan_custom

package main

import (
	"context"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestCustomScannerServiceBindsTheFloorsInACLIProcess is SEC-E4 merge
// finding 1: the custom scanner service binds the floors' read seam in a
// process that is not the daemon, so `observer security scanners run` on a
// managed node reads allow.custom_manifests (the floor's own set, fail
// closed) instead of running any locally accepted manifest; and it never
// replaces a binding already in place (the daemon's).
func TestCustomScannerServiceBindsTheFloorsInACLIProcess(t *testing.T) {
	unbindSecurityFloors(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	db := filepath.Join(dir, "observer.db")
	writeFile(t, cfgPath, "[observer]\ndb_path = "+strconv.Quote(db)+"\n[components]\nadd = [\"security.scan.custom\"]\n")
	allowed := "sha256:" + strings.Repeat("a", 64)
	prev := securityScanningCachedHeld
	securityScanningCachedHeld = func(context.Context, config.Config, *store.Store) *securityScanningHeld {
		return heldFloor(t, `{"allow":{"custom_manifests":["`+allowed+`"]}}`)
	}
	t.Cleanup(func() { securityScanningCachedHeld = prev })
	ctx := context.Background()
	_, database, cleanup, err := loadConfigAndDB(ctx, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	snap := componentSnapshotFor(cfgPath)
	if !customScanSelected(snap) {
		t.Fatal("the custom scanner component is not selected by the test config")
	}
	svc, err := customScannerService(ctx, snap, cfgPath, store.New(database))
	if err != nil || svc == nil {
		t.Fatalf("service: %v %v", svc, err)
	}
	secScanning.mu.Lock()
	bound, held := secScanning.load != nil, secScanning.held
	secScanning.mu.Unlock()
	if !bound || held == nil {
		t.Fatalf("the custom scanner service left the floors unbound in a CLI process (bound=%v held=%v)", bound, held)
	}
	// On a managed node the custom policy reads the floor's own set.
	secScanning.mu.Lock()
	secScanning.load = func(context.Context) (securityScanningBase, error) {
		return securityScanningBase{Managed: true, Security: config.DefaultSecurityConfig()}, nil
	}
	secScanning.baseOK, secScanning.moduleOff = false, false
	secScanning.mu.Unlock()
	if got := securityCustomManifestsAllowed(config.DefaultSecurityConfig()); !slices.Equal(got, []string{allowed}) {
		t.Fatalf("allow.custom_manifests in a CLI process on a managed node = %v, want the floor's set", got)
	}
	// A binding already in place (the daemon's) is never replaced.
	daemonHeld := heldFloor(t, `{"allow":{"custom_manifests":["sha256:`+strings.Repeat("b", 64)+`"]}}`)
	secScanning.mu.Lock()
	secScanning.held = daemonHeld
	secScanning.mu.Unlock()
	if _, err := customScannerService(ctx, snap, cfgPath, store.New(database)); err != nil {
		t.Fatal(err)
	}
	secScanning.mu.Lock()
	kept := secScanning.held == daemonHeld
	secScanning.mu.Unlock()
	if !kept {
		t.Fatal("a second service build replaced the binding already in place")
	}
}
