package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// promptWeakenedTOML is the re-test's a2 tamper (T-864 gap 2): the prompt
// guard switched off and loosened, two detectors switched off, one of them
// (email) a detector the shipped defaults already switch off.
const promptWeakenedTOML = `
[guard]
enabled = true
mode = "observe"

[guard.prompt]
enabled = false
hook_lane = false
mode = "warn"

[guard.prompt.detectors]
us_ssn = "off"
github_pat = "off"
email = "off"
`

func writePromptWeakenedConfig(t *testing.T, f floorFixture) {
	t.Helper()
	body := "[observer]\ndb_path = " + tomlQuote(filepath.Join(f.dir, "observer.db")) + "\n" +
		promptWeakenedTOML + "\n[guard.rules]\norg_bundle = " + tomlQuote(f.bundlePath) + "\n"
	if err := os.WriteFile(f.cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestManagedFloorHoldsThePromptGuard pins T-864 gap 2: on a managed node the
// org floor (DeriveFloor for an org layer) keeps the prompt guard on, at the
// org's prompt floor, with every detector the shipped defaults do not switch
// off back at its default. The local values still reach the report
// (WithLocalSwitches), so the attempt is visible. An individual node keeps
// every local value.
func TestManagedFloorHoldsThePromptGuard(t *testing.T) {
	floor := guardposture.DeriveFloor(guardposture.FloorInputs{Managed: true, OrgLayer: true})
	for _, tc := range []struct {
		name    string
		managed bool
	}{
		{"managed node: held at the floor", true},
		{"individual node: local values stand", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFloorFixture(t, "")
			writePromptWeakenedConfig(t, f)
			f.writeLock(t, guardposture.OrgLock{Managed: tc.managed, Floor: floor})
			cfg, err := Load(LoadOptions{GlobalPath: f.cfgPath})
			if err != nil {
				t.Fatal(err)
			}
			p := cfg.Guard.Prompt
			if !tc.managed {
				if p.Enabled || p.HookLane || p.Mode != "warn" || p.Detectors["us_ssn"] != "off" {
					t.Fatalf("individual prompt config changed: %+v", p)
				}
				return
			}
			if !p.Enabled || !p.HookLane || p.Mode != orgcontract.LocalGuardPromptFloor {
				t.Fatalf("prompt = enabled %v hook_lane %v mode %q, want on/on/%s", p.Enabled, p.HookLane, p.Mode, orgcontract.LocalGuardPromptFloor)
			}
			want := map[string]string{"us_ssn": "ask-once", "github_pat": "block", "email": "off"}
			for id, m := range want {
				if p.Detectors[id] != m {
					t.Errorf("detector %s = %q, want %q", id, p.Detectors[id], m)
				}
			}
			local := cfg.Guard.WithLocalSwitches()
			if local.Prompt.Enabled || local.Prompt.Mode != "warn" || local.Prompt.Detectors["us_ssn"] != "off" {
				t.Fatalf("reported local prompt = %+v, want the weakened local values", local.Prompt)
			}
			// The seeded defaults map is shared state: the floor must have
			// replaced the map, not written into it.
			if d := Default().Guard.Prompt.Detectors; d["us_ssn"] != "ask-once" {
				t.Fatalf("defaults were mutated: %v", d)
			}
		})
	}
}

// TestDefaultDetectorsAreNotRaised: an untouched node keeps the shipped
// detector set exactly (email and the phone numbers stay off; T-864 gap 3's
// node half).
func TestDefaultDetectorsAreNotRaised(t *testing.T) {
	g := Default().Guard
	before := cloneDetectors(g.Prompt.Detectors)
	if raised := floorPromptDetectors(&g.Prompt); raised != nil {
		t.Fatalf("raised %v on the shipped defaults", raised)
	}
	if !reflect.DeepEqual(g.Prompt.Detectors, before) {
		t.Fatalf("detectors changed: %v", g.Prompt.Detectors)
	}
	if !reflect.DeepEqual(before, orgcontract.LocalGuardDefaultDetectorModes()) {
		t.Fatalf("config defaults %v do not come from orgcontract", before)
	}
}

// TestTamperedLockFallsBackToThePostureAnchor pins T-864 gap 1's "bundle and
// org lock both deleted" reading: the daemon's MAC'd posture decides.
func TestTamperedLockFallsBackToThePostureAnchor(t *testing.T) {
	for _, tc := range []struct {
		name         string
		posture      guardposture.Posture
		wantMode     string
		wantExpected bool
	}{
		{"managed, enforcing org layer: strictest floor", guardposture.Posture{OrgLock: true, Managed: true, TenancyRecorded: true, Source: guardposture.SourceOrg, Enforced: true}, "enforce", true},
		{"managed, observing org layer: conservative floor", guardposture.Posture{OrgLock: true, Managed: true, TenancyRecorded: true, Source: guardposture.SourceOrg}, "observe", true},
		{"individual node: local control", guardposture.Posture{OrgLock: true, TenancyRecorded: true, Source: guardposture.SourceOrg}, "off", false},
		{"older posture with no tenancy and no org file: nothing to floor", guardposture.Posture{OrgLock: true}, "off", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFloorFixture(t, "")
			tc.posture.WrittenAt = time.Now()
			if _, err := guardposture.Write(guardposture.PosturePath(f.cfgPath), tc.posture, f.key); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(LoadOptions{GlobalPath: f.cfgPath})
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Guard.Lock.State != "tampered" {
				t.Fatalf("lock state = %q, want tampered (deleted while the posture says one is written)", cfg.Guard.Lock.State)
			}
			if cfg.Guard.Mode != tc.wantMode || cfg.Guard.Lock.OrgExpected != tc.wantExpected {
				t.Fatalf("mode %q org expected %v, want %q %v", cfg.Guard.Mode, cfg.Guard.Lock.OrgExpected, tc.wantMode, tc.wantExpected)
			}
		})
	}
}

// TestPromptModeFloorMatchesTheOrgCheck: the floor guardposture raises a
// managed node's prompt mode to is the value the org accepts (guardposture is
// stdlib only and cannot import orgcontract itself).
func TestPromptModeFloorMatchesTheOrgCheck(t *testing.T) {
	if guardposture.PromptModeFloor != orgcontract.LocalGuardPromptFloor {
		t.Fatalf("guardposture.PromptModeFloor = %q, orgcontract.LocalGuardPromptFloor = %q", guardposture.PromptModeFloor, orgcontract.LocalGuardPromptFloor)
	}
}
