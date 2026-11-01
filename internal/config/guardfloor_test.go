package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
)

// floorFixture is a node directory: config.toml weakening the guard, the
// daemon's key and posture, and optionally an org lock and a governance
// sidecar.
type floorFixture struct {
	dir, cfgPath, sidecarPath, bundlePath string
	key                                   []byte
}

const weakenedGuardTOML = `
[guard]
enabled = false
mode = "off"

[guard.prompt]
enabled = false
hook_lane = false
enforce_independent = false
`

func newFloorFixture(t *testing.T, extraTOML string) floorFixture {
	t.Helper()
	dir := t.TempDir()
	f := floorFixture{
		dir:         dir,
		cfgPath:     filepath.Join(dir, "config.toml"),
		sidecarPath: filepath.Join(dir, GovernanceSidecarFilename),
		bundlePath:  filepath.Join(dir, "org-policy-bundle.json"),
	}
	body := "[observer]\ndb_path = " + tomlQuote(filepath.Join(dir, "observer.db")) + "\n" +
		weakenedGuardTOML + "\n[guard.rules]\norg_bundle = " + tomlQuote(f.bundlePath) + "\n" + extraTOML
	if err := os.WriteFile(f.cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := guardposture.WriteNewKey(guardposture.KeyPath(f.cfgPath))
	if err != nil {
		t.Fatal(err)
	}
	f.key = key
	if _, err := guardposture.Write(guardposture.PosturePath(f.cfgPath), guardposture.Posture{OrgLock: true, WrittenAt: time.Now()}, key); err != nil {
		t.Fatal(err)
	}
	return f
}

func tomlQuote(s string) string { return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"` }

func (f floorFixture) writeLock(t *testing.T, l guardposture.OrgLock) {
	t.Helper()
	l.WrittenAt = time.Now()
	if _, err := guardposture.WriteOrgLock(guardposture.OrgLockPath(f.cfgPath), l, f.key); err != nil {
		t.Fatal(err)
	}
}

var managedFloor = guardposture.GuardFloor{Enabled: true, Mode: guardposture.ModeEnforce, PromptEnabled: true, PromptEnforceIndependent: true}

// TestGuardFloorTable is the config half of D-672, one row per lock shape.
func TestGuardFloorTable(t *testing.T) {
	cases := []struct {
		name       string
		lock       *guardposture.OrgLock
		corrupt    bool
		bundle     bool
		wantGuard  bool
		wantMode   string
		wantPrompt bool
		wantState  string
		wantKeys   int
	}{
		{"managed lock floors every weakened switch", &guardposture.OrgLock{Managed: true, Floor: managedFloor}, false, false, true, "enforce", true, "valid", 5},
		{"individual lock keeps full local control", &guardposture.OrgLock{Managed: false, Floor: managedFloor}, false, false, false, "off", false, "valid", 0},
		{"tampered lock with an org bundle: conservative floor", nil, true, true, true, "observe", true, "tampered", 4},
		{"tampered lock, never enrolled: nothing to floor", nil, true, false, false, "off", false, "tampered", 0},
		{"lock deleted while the posture says one is written", nil, false, true, true, "observe", true, "tampered", 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFloorFixture(t, "")
			if tc.bundle {
				if err := os.WriteFile(f.bundlePath, []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			switch {
			case tc.lock != nil:
				f.writeLock(t, *tc.lock)
			case tc.corrupt:
				f.writeLock(t, guardposture.OrgLock{Managed: true, Floor: managedFloor})
				if err := os.WriteFile(guardposture.OrgLockPath(f.cfgPath), []byte(`{"schema":1,"managed":false}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := Load(LoadOptions{GlobalPath: f.cfgPath})
			if err != nil {
				t.Fatal(err)
			}
			g := cfg.Guard
			if g.Enabled != tc.wantGuard || g.Mode != tc.wantMode || g.Prompt.Enabled != tc.wantPrompt || g.Prompt.HookLane != tc.wantPrompt {
				t.Fatalf("guard = enabled %v mode %q prompt %v/%v, want %v %q %v", g.Enabled, g.Mode, g.Prompt.Enabled, g.Prompt.HookLane, tc.wantGuard, tc.wantMode, tc.wantPrompt)
			}
			if g.Lock.State != tc.wantState || len(g.Lock.Overridden) != tc.wantKeys {
				t.Fatalf("lock record = %+v, want state %q with %d overrides", g.Lock, tc.wantState, tc.wantKeys)
			}
			// The local view never applies an organization.
			local, err := Load(LoadOptions{GlobalPath: f.cfgPath, GovernanceSidecar: NoGovernanceSidecar})
			if err != nil {
				t.Fatal(err)
			}
			if local.Guard.Enabled || local.Guard.Lock.State != "" {
				t.Fatalf("--local view was floored: %+v", local.Guard.Lock)
			}
		})
	}
}

// TestNoLockIsByteIdentical: a node with no daemon key (solo, or a fresh
// install) loads exactly what it loaded before the lock existed.
func TestNoLockIsByteIdentical(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = "+tomlQuote(filepath.Join(dir, "o.db"))+"\n"+weakenedGuardTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Guard.Enabled || cfg.Guard.Lock.State != "" || cfg.Guard.Lock.Overridden != nil {
		t.Fatalf("no-lock node was changed: %+v", cfg.Guard)
	}
}

// TestGovernanceLastVerifiedCopy pins T-845 (audit row a1+b3): with a valid
// org lock the daemon's own copy of the governance sidecar is the posture, so
// stripping the pins from the file on disk changes nothing.
func TestGovernanceLastVerifiedCopy(t *testing.T) {
	f := newFloorFixture(t, "")
	pinned := `{"schema":1,"state":"applied","effective_hash":"h1","pinned":{"guard.enabled":true,"guard.mode":"enforce"}}`
	stripped := `{"schema":1,"state":"applied","effective_hash":"h1","pinned":{"tasks.enabled":true}}`
	if err := os.WriteFile(f.sidecarPath, []byte(stripped), 0o600); err != nil {
		t.Fatal(err)
	}
	// An individual node: no floor, so only the governance copy can keep
	// the guard on.
	f.writeLock(t, guardposture.OrgLock{GovernanceKnown: true, Governance: pinned})
	cfg, gout, err := LoadGovernance(LoadOptions{GlobalPath: f.cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Guard.Enabled || cfg.Guard.Mode != "enforce" {
		t.Fatalf("guard = %v/%q, want the verified pins (true/enforce)", cfg.Guard.Enabled, cfg.Guard.Mode)
	}
	if !gout.Verified || gout.Tampered == "" {
		t.Fatalf("outcome = verified %v tampered %q, want the stripped file named", gout.Verified, gout.Tampered)
	}

	// Without the lock the on-disk file applies exactly as before.
	if err := os.Remove(guardposture.OrgLockPath(f.cfgPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(guardposture.PosturePath(f.cfgPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(guardposture.KeyPath(f.cfgPath)); err != nil {
		t.Fatal(err)
	}
	cfg, gout, err = LoadGovernance(LoadOptions{GlobalPath: f.cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Guard.Enabled || gout.Verified || gout.Tampered != "" {
		t.Fatalf("legacy read changed: guard %v verified %v tampered %q", cfg.Guard.Enabled, gout.Verified, gout.Tampered)
	}
}

// TestWithLocalSwitchesShowsTheAttempt: the floored config enforces the
// organization's floor, while WithLocalSwitches (reporting only, the T-848
// policy-state seam) shows the switches exactly as the local config set
// them, so a weakening the floor overrode still reaches the organization.
func TestWithLocalSwitchesShowsTheAttempt(t *testing.T) {
	f := newFloorFixture(t, "")
	f.writeLock(t, guardposture.OrgLock{Managed: true, Floor: managedFloor})
	cfg, err := Load(LoadOptions{GlobalPath: f.cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Guard.Enabled || cfg.Guard.Mode != "enforce" {
		t.Fatalf("floored guard = %v %q, want the organization floor", cfg.Guard.Enabled, cfg.Guard.Mode)
	}
	local := cfg.Guard.WithLocalSwitches()
	if local.Enabled || local.Mode != "off" || local.Prompt.Enabled || local.Prompt.HookLane || local.Prompt.EnforceIndependent {
		t.Fatalf("local switches = %+v, want the weakened local values", local)
	}
	if !cfg.Guard.Enabled {
		t.Fatal("WithLocalSwitches mutated the enforced config")
	}
	// No lock: the reporting view is the config itself.
	var bare GuardConfig
	bare.Enabled, bare.Mode = true, "observe"
	if got := bare.WithLocalSwitches(); got.Enabled != true || got.Mode != "observe" {
		t.Fatalf("no-lock view changed: %+v", got)
	}
}
