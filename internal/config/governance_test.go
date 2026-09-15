package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func govTempConfig(t *testing.T, dbDir, toml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dbDir, "observer.db")) + "\"\n" + toml
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func govWriteSidecar(t *testing.T, dbDir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dbDir, GovernanceSidecarFilename), []byte(body), 0o600); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}
}

func noEnv(string) string { return "" }

// TestGovernanceOverlayIsTheLastMergeStep: last-writer-wins is the only
// merge order in which a pinned value is the value the process actually
// uses, so the overlay must beat the TOML AND the env.
func TestGovernanceOverlayIsTheLastMergeStep(t *testing.T) {
	dbDir := t.TempDir()
	cfgPath := govTempConfig(t, dbDir, "[guard]\nenabled = false\nmode = \"off\"\n")
	govWriteSidecar(t, dbDir, `{"schema":1,"state":"applied","pinned":{"guard.enabled":true,"guard.mode":"enforce"}}`)

	env := func(k string) string {
		if k == "OBSERVER_GUARD_ENABLED" {
			return "false"
		}
		return ""
	}
	cfg, out, err := LoadGovernance(LoadOptions{GlobalPath: cfgPath, Env: env})
	if err != nil {
		t.Fatalf("LoadGovernance: %v", err)
	}
	if !cfg.Guard.Enabled || cfg.Guard.Mode != "enforce" {
		t.Fatalf("governance did not win the merge: enabled=%v mode=%q", cfg.Guard.Enabled, cfg.Guard.Mode)
	}
	if !out.Governed() || len(out.Applied) != 2 {
		t.Fatalf("outcome = %+v", out)
	}
}

// TestGovernancePinnedRoutingEnabledYieldsARouter is the W5 proof (plan
// docs/plans/org-observer-fundamentals-fix-plan-2026-09-13.md R4): a
// node.governance settings pin naming routing.enabled applies through the
// SAME generic overlay guard.mode already uses (no proxy.go code change
// needed) — the org can turn a managed node's router on, or off, entirely
// through the vocabulary change, not a new apply mechanism. The proxy's own
// gate (cmd/observer/proxy.go wireRouting: "if !cfg.Routing.Enabled ...
// return nil, nil") is exercised directly in
// cmd/observer/routing_live_test.go's TestWireRouting_RoutingEnabledGate,
// which starts from a Config built the same way (Routing.Enabled=true) and
// asserts a non-nil router comes back.
func TestGovernancePinnedRoutingEnabledYieldsARouter(t *testing.T) {
	dbDir := t.TempDir()
	cfgPath := govTempConfig(t, dbDir, "[routing]\nenabled = false\nmode = \"off\"\n")
	govWriteSidecar(t, dbDir, `{"schema":1,"state":"applied","pinned":{"routing.enabled":true}}`)

	cfg, out, err := LoadGovernance(LoadOptions{GlobalPath: cfgPath, Env: noEnv})
	if err != nil {
		t.Fatalf("LoadGovernance: %v", err)
	}
	if !cfg.Routing.Enabled {
		t.Fatal("governance-pinned routing.enabled=true did not apply — cfg.Routing.Enabled is still false")
	}
	if cfg.Routing.Mode != "off" {
		t.Fatalf("routing.mode changed to %q from an unrelated pin — it must only ever come from the local config or the signed org routing-policy body", cfg.Routing.Mode)
	}
	if !out.Governed() || len(out.Applied) != 1 || out.Applied[0] != "routing.enabled" {
		t.Fatalf("outcome = %+v", out)
	}

	// The org may also LOWER it back off — routing.enabled is DirFree, both
	// directions are legitimate fleet postures.
	dbDir2 := t.TempDir()
	cfgPath2 := govTempConfig(t, dbDir2, "[routing]\nenabled = true\nmode = \"advise\"\n")
	govWriteSidecar(t, dbDir2, `{"schema":1,"state":"applied","pinned":{"routing.enabled":false}}`)
	cfg2, _, err := LoadGovernance(LoadOptions{GlobalPath: cfgPath2, Env: noEnv})
	if err != nil {
		t.Fatalf("LoadGovernance: %v", err)
	}
	if cfg2.Routing.Enabled {
		t.Fatal("governance-pinned routing.enabled=false did not apply — cfg.Routing.Enabled is still true")
	}
}

// TestInertSidecarStillAppliesPins is the 2026-08-15 hook-smoke regression:
// govern.Resolve reports "inert" for any PARTIAL application (the
// always-present sections class drops whenever the grant lacks
// dashboard.visibility authority), so a pins-only deployment normally runs
// with state "inert" and a NON-EMPTY pinned map. The reader must apply
// those pins — dormancy is judged on the maps, never on the state string —
// or every hook and CLI ignores what the daemon materialized and reports
// as live.
func TestInertSidecarStillAppliesPins(t *testing.T) {
	dbDir := t.TempDir()
	cfgPath := govTempConfig(t, dbDir, "[guard]\nenabled = false\n")
	govWriteSidecar(t, dbDir, `{"schema":1,"state":"inert","pinned":{"guard.enabled":true}}`)

	cfg, out, err := LoadGovernance(LoadOptions{GlobalPath: cfgPath, Env: noEnv})
	if err != nil {
		t.Fatalf("LoadGovernance: %v", err)
	}
	if !cfg.Guard.Enabled {
		t.Fatal("an inert-state sidecar's pinned map was not applied — partial application must still pin")
	}
	if !out.Governed() || len(out.Applied) != 1 || out.Applied[0] != "guard.enabled" {
		t.Fatalf("outcome = %+v", out)
	}
}

// TestGovernanceSidecarAbsentIsByteIdentical is the solo claim stated over
// the FILE: creating, then deleting, the sidecar returns Load to its
// original result.
func TestGovernanceSidecarAbsentIsByteIdentical(t *testing.T) {
	dbDir := t.TempDir()
	cfgPath := govTempConfig(t, dbDir, "[guard]\nenabled = false\n[compression.conversation]\nenabled = false\n")

	before, err := Load(LoadOptions{GlobalPath: cfgPath, Env: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	govWriteSidecar(t, dbDir, `{"schema":1,"state":"applied","pinned":{"guard.enabled":true}}`)
	during, err := Load(LoadOptions{GlobalPath: cfgPath, Env: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if during.Guard.Enabled == before.Guard.Enabled {
		t.Fatal("the sidecar changed nothing — the test would prove nothing")
	}
	if err := os.Remove(filepath.Join(dbDir, GovernanceSidecarFilename)); err != nil {
		t.Fatalf("remove: %v", err)
	}
	after, err := Load(LoadOptions{GlobalPath: cfgPath, Env: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("removing the sidecar did not return Load to its original result")
	}
}

// TestNoGovernanceSidecarDisablesTheRead: the sentinel `observer config show
// --local` and the solo-parity invariant use.
func TestNoGovernanceSidecarDisablesTheRead(t *testing.T) {
	dbDir := t.TempDir()
	cfgPath := govTempConfig(t, dbDir, "[guard]\nenabled = false\n")
	govWriteSidecar(t, dbDir, `{"schema":1,"state":"applied","pinned":{"guard.enabled":true}}`)

	cfg, err := Load(LoadOptions{GlobalPath: cfgPath, Env: noEnv, GovernanceSidecar: NoGovernanceSidecar})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Guard.Enabled {
		t.Fatal("NoGovernanceSidecar still applied the overlay")
	}
}

// TestSidecarNeverMakesLoadFail is the review-B4 blocker, stated as the
// property rather than the instance: NO sidecar content of any shape can
// make config.Load return an error.
func TestSidecarNeverMakesLoadFail(t *testing.T) {
	bodies := []string{
		`{"schema":1,"state":"applied","pinned":{"guard.mode":"strict"}}`, // Validate rejects "strict"
		`{"schema":1,"state":"applied","pinned":{"guard.mode":42}}`,
		`{"schema":1,"state":"applied","pinned":{"nonsense.key":true}}`,
		`{"schema":1,"state":"applied","pinned":{"remote.enabled":true}}`, // restrictive-only violation
		`{"schema":1,`,
		`not json at all`,
		``,
		`{"schema":99,"state":"applied"}`,
		`{"schema":1,"state":"applied","grant_expires_at":"1999-01-01T00:00:00Z","pinned":{"guard.enabled":true}}`,
		`{"schema":1,"state":"no_grant"}`,
		`{"schema":1,"state":"applied","surprise":true}`,
	}
	for _, body := range bodies {
		dbDir := t.TempDir()
		cfgPath := govTempConfig(t, dbDir, "[guard]\nenabled = false\nmode = \"observe\"\n")
		govWriteSidecar(t, dbDir, body)
		cfg, out, err := LoadGovernance(LoadOptions{GlobalPath: cfgPath, Env: noEnv})
		if err != nil {
			t.Fatalf("sidecar %q made Load fail: %v", body, err)
		}
		if cfg.Guard.Mode != "observe" && cfg.Guard.Mode != "enforce" && cfg.Guard.Mode != "off" {
			t.Fatalf("sidecar %q produced an invalid guard mode %q", body, cfg.Guard.Mode)
		}
		_ = out
	}
}

// TestEnumGrammarCatchesValidateRejectsBeforeLoad is review B4's fix (b):
// guard.mode = "strict" type-checks as a string and would pass a Kind-only
// grammar, then be rejected by config.Validate. The Enum column stops the
// situation ARISING — the key is skipped, the rest of the overlay applies,
// and Load never sees an invalid config.
func TestEnumGrammarCatchesValidateRejectsBeforeLoad(t *testing.T) {
	dbDir := t.TempDir()
	cfgPath := govTempConfig(t, dbDir, "[guard]\nenabled = false\nmode = \"observe\"\n")
	govWriteSidecar(t, dbDir, `{"schema":1,"state":"applied","pinned":{"guard.enabled":true,"guard.mode":"strict"}}`)

	cfg, out, err := LoadGovernance(LoadOptions{GlobalPath: cfgPath, Env: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if out.Discarded {
		t.Fatal("the enum grammar did not fire first — the overlay reached Validate")
	}
	if _, skipped := out.Skipped["guard.mode"]; !skipped {
		t.Fatalf("guard.mode was not skipped: %+v", out.Skipped)
	}
	if !cfg.Guard.Enabled || cfg.Guard.Mode != "observe" {
		t.Fatalf("per-key skip did not leave the rest applied: enabled=%v mode=%q", cfg.Guard.Enabled, cfg.Guard.Mode)
	}
}

// TestValidateFailingOverlayIsDiscardedWhole is review B4's fix (a), the
// BACKSTOP for a posture that did not come through today's grammar — an
// older LKG, a hand-edited file, or a future key whose cross-field
// validation this table does not model.
//
// It is exercised by temporarily removing guard.mode's Enum from the mirror,
// which is exactly the shape of that drift. The rule under test is
// discard-ALL, not skip-the-bad-key: Validate is a whole-config predicate,
// so a partially-applied overlay would be a posture nobody authored.
func TestValidateFailingOverlayIsDiscardedWhole(t *testing.T) {
	relaxed := governancePinnableByKey["guard.mode"]
	relaxed.Enum = nil
	governancePinnableByKey["guard.mode"] = relaxed
	t.Cleanup(func() {
		governancePinnableByKey["guard.mode"] = governancePinnableKey{
			Key: "guard.mode", Kind: "string",
			Enum: []any{"off", "observe", "enforce"}, Direction: governanceDirFree,
		}
	})

	dbDir := t.TempDir()
	cfgPath := govTempConfig(t, dbDir, "[guard]\nenabled = false\nmode = \"observe\"\n")
	govWriteSidecar(t, dbDir, `{"schema":1,"state":"applied","pinned":{"guard.enabled":true,"guard.mode":"strict"}}`)

	cfg, out, err := LoadGovernance(LoadOptions{GlobalPath: cfgPath, Env: noEnv})
	if err != nil {
		t.Fatalf("Load failed because of governance: %v", err)
	}
	if !out.Discarded || out.DiscardErr == "" {
		t.Fatalf("the outcome does not record the discard: %+v", out)
	}
	if cfg.Guard.Enabled {
		t.Fatal("a key from a discarded overlay was still applied — discard must be whole-overlay")
	}
	if cfg.Guard.Mode != "observe" {
		t.Fatalf("guard mode = %q, want the ungoverned value", cfg.Guard.Mode)
	}
}

// TestUnknownAndBadKeysAreSkippedNotFatal: §1.3's per-key rows.
func TestUnknownAndBadKeysAreSkippedNotFatal(t *testing.T) {
	dbDir := t.TempDir()
	cfgPath := govTempConfig(t, dbDir, "[guard]\nenabled = false\n")
	govWriteSidecar(t, dbDir, `{"schema":1,"state":"applied","pinned":{
		"guard.enabled":true,
		"not.a.key":true,
		"cachetrack.enabled":"yes",
		"remote.enabled":true,
		"guard.mode":"sideways"}}`)

	cfg, out, err := LoadGovernance(LoadOptions{GlobalPath: cfgPath, Env: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Guard.Enabled {
		t.Fatal("the good key was not applied alongside the bad ones")
	}
	for _, key := range []string{"not.a.key", "cachetrack.enabled", "remote.enabled", "guard.mode"} {
		if _, skipped := out.Skipped[key]; !skipped {
			t.Errorf("%q was not recorded as skipped: %+v", key, out.Skipped)
		}
	}
	if len(out.Applied) != 1 || out.Applied[0] != "guard.enabled" {
		t.Fatalf("applied = %v", out.Applied)
	}
}

// TestExpiredGrantIgnoresSidecarThroughLoad is the offboarding guarantee at
// the Load layer, with an injected clock: the pin lifts the moment the grant
// expires, DAEMON OR NO DAEMON.
func TestExpiredGrantIgnoresSidecarThroughLoad(t *testing.T) {
	dbDir := t.TempDir()
	cfgPath := govTempConfig(t, dbDir, "[guard]\nenabled = false\n")
	expiry := time.Date(2026, 9, 14, 9, 0, 0, 0, time.UTC)
	govWriteSidecar(t, dbDir, `{"schema":1,"state":"applied","grant_expires_at":"`+
		expiry.Format(time.RFC3339)+`","pinned":{"guard.enabled":true}}`)

	live, err := Load(LoadOptions{GlobalPath: cfgPath, Env: noEnv, GovernanceNow: func() time.Time { return expiry.Add(-time.Hour) }})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !live.Guard.Enabled {
		t.Fatal("a live grant was not applied")
	}
	lapsed, err := Load(LoadOptions{GlobalPath: cfgPath, Env: noEnv, GovernanceNow: func() time.Time { return expiry.Add(time.Second) }})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if lapsed.Guard.Enabled {
		t.Fatal("an expired grant still pinned a key — offboarding depends on this even with a dead daemon")
	}
}

// TestResolveGovernanceSidecarPathIsBesideTheDB pins the placement rule.
func TestResolveGovernanceSidecarPathIsBesideTheDB(t *testing.T) {
	cfg := Default()
	cfg.Observer.DBPath = filepath.Join("/var", "lib", "sbo", "observer.db")
	want := filepath.Join("/var", "lib", "sbo", GovernanceSidecarFilename)
	if got := ResolveGovernanceSidecarPath(cfg, ""); got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	if got := ResolveGovernanceSidecarPath(cfg, NoGovernanceSidecar); got != "" {
		t.Fatalf("NoGovernanceSidecar resolved to %q", got)
	}
	if got := ResolveGovernanceSidecarPath(cfg, "/tmp/x.json"); got != "/tmp/x.json" {
		t.Fatalf("override ignored: %q", got)
	}
}

// TestGovernanceOverlayDoesNotMutateTheUngovernedConfig: the overlay is
// applied to a COPY, so the fallback path returns a config no pin touched.
func TestGovernanceOverlayDoesNotMutateTheUngovernedConfig(t *testing.T) {
	base := Default()
	base.Guard.Enabled = false
	governed := base
	out := GovernanceOutcome{}
	applyGovernancePins(&governed, map[string]any{"guard.enabled": true}, &out)
	if base.Guard.Enabled {
		t.Fatal("applying pins to the copy mutated the original")
	}
	if !governed.Guard.Enabled {
		t.Fatal("the pin did not land on the copy")
	}
	if !strings.Contains(strings.Join(out.Applied, ","), "guard.enabled") {
		t.Fatalf("applied = %v", out.Applied)
	}
}
