//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// heldFloor compiles a security.scanning body into a held floor in effect.
func heldFloor(t *testing.T, body string) *securityScanningHeld {
	t.Helper()
	spec, _, err := securityscanning.CompileBody([]byte(body), 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	return &securityScanningHeld{Spec: spec, Version: 1, InEffect: true}
}

// TestCLIShowsTheFlooredOnlineSetting is P-051 (SECP-10's residual):
// `observer security deps status` and `observer doctor`, run outside the
// daemon, read the floors in force through the same depsInForce seam the
// daemon uses, so a published allow.online_checks = forbidden shows off.
func TestCLIShowsTheFlooredOnlineSetting(t *testing.T) {
	unbindSecurityFloors(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	db := filepath.Join(dir, "observer.db")
	switchConfig(t, cfgPath, db, true)
	// Online on locally, disclosure accepted.
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(db) + "\"\n[components]\nadd = [\"security.deps\"]\n[security.deps]\nonline = true\n"
	writeFile(t, cfgPath, body)
	cfg, database, cleanup, err := loadConfigAndDB(context.Background(), cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	_ = database
	if _, err := recordDepsDisclosure(filepath.Join(dir, "security"), "cli", time.Now()); err != nil {
		t.Fatal(err)
	}
	prev := securityScanningCachedHeld
	securityScanningCachedHeld = func(context.Context, config.Config, *store.Store) *securityScanningHeld {
		return heldFloor(t, `{"allow":{"online_checks":"forbidden"}}`)
	}
	t.Cleanup(func() { securityScanningCachedHeld = prev })

	c := securityDepsDoctorCheck(context.Background(), cfgPath)
	if !slices.Contains(c.Details, "online checks: off (offline lists only)") {
		t.Fatalf("doctor must show the floored setting: %+v", c.Details)
	}
	var b strings.Builder
	writeDepsStatus(context.Background(), &b, cfg, cfgPath, filepath.Join(dir, "security"), true)
	if !strings.Contains(b.String(), "online checks: off") {
		t.Fatalf("status must show the floored setting:\n%s", b.String())
	}
	if depsInForce(cfg.Security).Online {
		t.Fatal("depsInForce ignores the floor in a CLI process")
	}
}

// TestDepsFloorRows (lane SEC-E4, milestone 4): the deps keys are wired
// through securityFloorsApplied (raise-only on an individual node), the
// custom manifests floor is read fail closed on a managed node, and the
// keys with no node setting stay not_built with their reason.
func TestDepsFloorRows(t *testing.T) {
	withSecurityScanningNode(t, false, config.DefaultSecurityConfig(), "security.deps", "security.scan.custom")
	secScanning.mu.Lock()
	secScanning.held = heldFloor(t, `{"require":{"max_advisory_db_age_h":48,"install_unknown":"ask"},"allow":{"scanner_sources":["org_mirror"]}}`)
	secScanning.mu.Unlock()
	sc := config.DefaultSecurityConfig()
	got := securityFloorsApplied(sc)
	if got.Deps.MaxAdvisoryDBAgeH != 48 || depsAdvisoryFloor(sc) != 48*time.Hour {
		t.Errorf("max_advisory_db_age_h: %d", got.Deps.MaxAdvisoryDBAgeH)
	}
	if !slices.Equal(got.Deps.ScannerSources, []string{"org_mirror"}) || depsScannerSourceAllowed(sc, "vendor_release") || !depsScannerSourceAllowed(sc, "org_mirror") {
		t.Errorf("allow.scanner_sources: %v", got.Deps.ScannerSources)
	}
	// Raise only: a stricter local value stays.
	sc.Deps.MaxAdvisoryDBAgeH = 12
	if securityFloorsApplied(sc).Deps.MaxAdvisoryDBAgeH != 12 {
		t.Error("a floor loosened a stricter local value")
	}
	// No floor: every source allowed, the kind's own age floor.
	secScanning.mu.Lock()
	secScanning.held = nil
	secScanning.mu.Unlock()
	if !depsScannerSourceAllowed(config.DefaultSecurityConfig(), "vendor_release") || depsAdvisoryFloor(config.DefaultSecurityConfig()) != 0 {
		t.Error("no floor must change nothing")
	}
	// Built since lane LEFT-SEC: the unknown-package actions are node
	// settings ([security.deps] unknown_action, online_unknown_action) with
	// a floor row each, at the axis's weakest value by default.
	for _, k := range []string{securityscanning.AxisInstallUnknown, securityscanning.AxisInstallOnlineUnknown} {
		if _, ok := securityFloorNotBuilt[k]; ok {
			t.Errorf("%s still has a not_built reason", k)
		}
		if v, ok := securityLocalPosture(config.DefaultSecurityConfig())[k]; !ok || v.S != "flag" {
			t.Errorf("%s: local %+v (%v), want the default action as flag", k, v, ok)
		}
	}
	// allow.custom_manifests: nil on an individual node, the floor's own
	// set on a managed one (fail closed).
	secScanning.mu.Lock()
	secScanning.held = heldFloor(t, `{"allow":{"custom_manifests":["sha256:`+strings.Repeat("a", 64)+`"]}}`)
	secScanning.mu.Unlock()
	if securityCustomManifestsAllowed(config.DefaultSecurityConfig()) != nil {
		t.Error("an individual node takes no custom manifests floor")
	}
}
