package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
)

// TestOwnGuardSwitchesSurviveGovernancePins pins T-875 (guard tamper re-test
// 2026-10-17 C-a1): on a managed node whose governance pins guard.enabled and
// guard.mode, a local `[guard] enabled=false, mode="observe"` is still
// enforced at the pinned values, while the reporting view
// (WithLocalSwitches) carries what the developer set, so the organization's
// local_weakening finding can name guard.enabled and guard.mode. A switch
// the developer never set keeps the governed value in the report, so an
// untouched node is not reported as weakened. One row per source of a local
// value.
func TestOwnGuardSwitchesSurviveGovernancePins(t *testing.T) {
	pinned := `{"schema":1,"state":"applied","effective_hash":"h1","pinned":{"guard.enabled":true,"guard.mode":"enforce"}}`
	cases := []struct {
		name        string
		guardTOML   string
		env         map[string]string
		wantEnabled bool
		wantMode    string
	}{
		{"the C-a1 edit in config.toml", "[guard]\nenabled = false\nmode = \"observe\"\n", nil, false, "observe"},
		{"only the mode set locally", "[guard]\nmode = \"off\"\n", nil, true, "off"},
		{"untouched node: the governed values, no false weakening", "", nil, true, "enforce"},
		{"set through the environment", "", map[string]string{"OBSERVER_GUARD_ENABLED": "false"}, false, "enforce"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFloorFixture(t, "")
			body := "[observer]\ndb_path = " + tomlQuote(filepath.Join(f.dir, "observer.db")) + "\n" +
				tc.guardTOML + "\n[guard.rules]\norg_bundle = " + tomlQuote(f.bundlePath) + "\n"
			if err := os.WriteFile(f.cfgPath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.sidecarPath, []byte(pinned), 0o600); err != nil {
				t.Fatal(err)
			}
			f.writeLock(t, guardposture.OrgLock{Managed: true, Floor: managedFloor, GovernanceKnown: true, Governance: pinned})
			env := func(k string) string { return tc.env[k] }
			cfg, err := Load(LoadOptions{GlobalPath: f.cfgPath, Env: env})
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.Guard.Enabled || cfg.Guard.Mode != "enforce" {
				t.Fatalf("enforced guard = %v/%q, want true/enforce", cfg.Guard.Enabled, cfg.Guard.Mode)
			}
			local := cfg.Guard.WithLocalSwitches()
			if local.Enabled != tc.wantEnabled || local.Mode != tc.wantMode {
				t.Fatalf("reported guard = %v/%q, want %v/%q", local.Enabled, local.Mode, tc.wantEnabled, tc.wantMode)
			}
		})
	}
}

// TestPinnedGuardSwitchesAreListedLocally pins T-881 (guard tamper re-test
// 2026-10-17 case 4): a local [guard] value a governance pin replaced is
// listed with the floor's overrides (OverrideLines, read by `observer guard
// status` and `observer doctor`), naming the local value, the organization's
// value and that a pin decided it. The lines come from the same rows and
// snapshot T-875 reports to the organization. A switch the developer never
// set, or set to the pinned value, is not listed.
func TestPinnedGuardSwitchesAreListedLocally(t *testing.T) {
	pinned := `{"schema":1,"state":"applied","effective_hash":"h1","pinned":{"guard.enabled":true,"guard.mode":"enforce"}}`
	cases := []struct {
		name      string
		guardTOML string
		env       map[string]string
		want      []string
	}{
		{
			"the C-a1 edit", "[guard]\nenabled = false\nmode = \"observe\"\n", nil,
			[]string{"guard.enabled: local false, organization pin true", "guard.mode: local observe, organization pin enforce"},
		},
		{"only the mode", "[guard]\nmode = \"off\"\n", nil, []string{"guard.mode: local off, organization pin enforce"}},
		{"through the environment", "", map[string]string{"OBSERVER_GUARD_ENABLED": "false"}, []string{"guard.enabled: local false, organization pin true"}},
		{"set to the pinned values", "[guard]\nenabled = true\nmode = \"enforce\"\n", nil, nil},
		{"untouched node", "", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFloorFixture(t, "")
			body := "[observer]\ndb_path = " + tomlQuote(filepath.Join(f.dir, "observer.db")) + "\n" +
				tc.guardTOML + "\n[guard.rules]\norg_bundle = " + tomlQuote(f.bundlePath) + "\n"
			if err := os.WriteFile(f.cfgPath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.sidecarPath, []byte(pinned), 0o600); err != nil {
				t.Fatal(err)
			}
			f.writeLock(t, guardposture.OrgLock{Managed: true, Floor: managedFloor, GovernanceKnown: true, Governance: pinned})
			env := func(k string) string { return tc.env[k] }
			cfg, err := Load(LoadOptions{GlobalPath: f.cfgPath, Env: env})
			if err != nil {
				t.Fatal(err)
			}
			got := cfg.Guard.Lock.Pinned
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("pinned = %q, want %q", got, tc.want)
			}
			lines := cfg.Guard.Lock.OverrideLines()
			if len(lines) != len(got)+len(cfg.Guard.Lock.Overridden) {
				t.Fatalf("override lines %q do not hold the pinned %q and the floored %q", lines, got, cfg.Guard.Lock.Overridden)
			}
			for i, l := range got {
				if lines[i] != l {
					t.Fatalf("override lines %q do not start with the pinned %q", lines, got)
				}
			}
		})
	}
}

// TestOwnGuardSwitchesNeedALock: with no org lock the report is the loaded
// config, exactly as before T-875 (an individual node with no daemon, or a
// daemon that predates the lock).
func TestOwnGuardSwitchesNeedALock(t *testing.T) {
	f := newFloorFixture(t, "")
	pinned := `{"schema":1,"state":"applied","effective_hash":"h1","pinned":{"guard.enabled":true,"guard.mode":"enforce"}}`
	if err := os.WriteFile(f.sidecarPath, []byte(pinned), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{guardposture.PosturePath(f.cfgPath), guardposture.KeyPath(f.cfgPath)} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := Load(LoadOptions{GlobalPath: f.cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Guard.Lock.Local != nil {
		t.Fatalf("no lock, yet a local snapshot was recorded: %+v", cfg.Guard.Lock.Local)
	}
	if local := cfg.Guard.WithLocalSwitches(); local.Enabled != cfg.Guard.Enabled || local.Mode != cfg.Guard.Mode {
		t.Fatalf("report %v/%q differs from the loaded %v/%q", local.Enabled, local.Mode, cfg.Guard.Enabled, cfg.Guard.Mode)
	}
}
