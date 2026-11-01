package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestLocalGuardPostureReportsTheC_a1Edit replays the guard tamper re-test's
// C-a1 (2026-10-17, T-875) through the policy-state reader: a managed node
// whose governance pins guard.enabled=true / guard.mode=enforce, with
// `[guard] enabled=false, mode="observe"` in config.toml. The hook still
// enforces the pinned values; the report carries the local ones, so the
// organization's local_weakening evaluator names both keys.
func TestLocalGuardPostureReportsTheC_a1Edit(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + strings.ReplaceAll(filepath.Join(dir, "observer.db"), `\`, `\\`) + "\"\n\n" +
		"[guard]\nenabled = false\nmode = \"observe\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := guardposture.WriteNewKey(guardposture.KeyPath(cfgPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guardposture.Write(guardposture.PosturePath(cfgPath), guardposture.Posture{OrgLock: true, WrittenAt: time.Now()}, key); err != nil {
		t.Fatal(err)
	}
	pinned := `{"schema":1,"state":"applied","effective_hash":"h1","pinned":{"guard.enabled":true,"guard.mode":"enforce"}}`
	if err := os.WriteFile(filepath.Join(dir, config.GovernanceSidecarFilename), []byte(pinned), 0o600); err != nil {
		t.Fatal(err)
	}
	floor := guardposture.GuardFloor{Enabled: true, Mode: guardposture.ModeEnforce}
	lock := guardposture.OrgLock{Managed: true, Floor: floor, GovernanceKnown: true, Governance: pinned, WrittenAt: time.Now()}
	if _, err := guardposture.WriteOrgLock(guardposture.OrgLockPath(cfgPath), lock, key); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Guard.Enabled || cfg.Guard.Mode != "enforce" {
		t.Fatalf("enforced guard = %v/%q, want true/enforce", cfg.Guard.Enabled, cfg.Guard.Mode)
	}
	p := localGuardPostureFromDisk(func() string { return cfgPath })()
	if p == nil || p.Enabled || p.Mode != "observe" {
		t.Fatalf("reported posture = %+v, want enabled=false mode=observe", p)
	}
	pins := map[string]string{orgcontract.LocalGuardKeyEnabled: "true", orgcontract.LocalGuardKeyMode: "enforce"}
	want := []string{orgcontract.LocalGuardKeyEnabled, orgcontract.LocalGuardKeyMode}
	if got := orgcontract.LocalGuardWeakenings(p, pins); !reflect.DeepEqual(got, want) {
		t.Fatalf("weakenings = %v, want %v", got, want)
	}
}
