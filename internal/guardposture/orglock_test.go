package guardposture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestStaleOnlyByConfig pins T-864 gap 2's window: a posture that is stale
// only because config.toml changed after it was written, and otherwise
// fresh.
func TestStaleOnlyByConfig(t *testing.T) {
	now := time.Now()
	p := &Posture{WrittenAt: now.Add(-30 * time.Second)}
	for _, tc := range []struct {
		name string
		p    *Posture
		mod  time.Time
		want bool
	}{
		{"config edited after a fresh posture", p, now.Add(-time.Second), true},
		{"config unchanged", p, now.Add(-time.Minute), false},
		{"config time unknown", p, time.Time{}, false},
		{"posture past MaxAge", &Posture{WrittenAt: now.Add(-MaxAge - time.Minute)}, now, false},
		{"no posture", nil, now, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.StaleOnlyByConfig(now, tc.mod); got != tc.want {
				t.Fatalf("StaleOnlyByConfig = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOrgLockSignVerifyAndTamper(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if _, err := WriteNewKey(KeyPath(cfg)); err != nil {
		t.Fatal(err)
	}
	key, _ := ReadKey(KeyPath(cfg))
	lock := OrgLock{
		Managed: true, Floor: GuardFloor{Enabled: true, Mode: ModeEnforce}, KeyPinHash: "pin", Bundle: `{"v":1}`,
		GovernanceKnown: true, Governance: `{"schema":1}`, WrittenAt: time.Unix(500, 0),
	}
	if _, err := Write(PosturePath(cfg), Posture{OrgLock: true, WrittenAt: time.Unix(500, 0)}, key); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteOrgLock(OrgLockPath(cfg), lock, key); err != nil {
		t.Fatal(err)
	}
	ld := LoadOrgLock(cfg)
	if ld.State != OrgLockValid || !ld.Lock.Managed || ld.Lock.Floor.Mode != ModeEnforce || ld.Lock.Governance != `{"schema":1}` {
		t.Fatalf("valid lock = %+v", ld)
	}
	// A hand edit (strip the floor) no longer verifies.
	raw, _ := os.ReadFile(OrgLockPath(cfg))
	edited := []byte(strings.Replace(string(raw), `"mode": "enforce"`, `"mode": "observe"`, 1))
	if err := os.WriteFile(OrgLockPath(cfg), edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if ld := LoadOrgLock(cfg); ld.State != OrgLockTampered {
		t.Fatalf("edited lock = %v, want tampered", ld.State)
	}
}

// TestLoadOrgLockMissingTable walks orgLockExpectation row by row: a
// MISSING lock is tampered only when the anchor says a lock is written.
func TestLoadOrgLockMissingTable(t *testing.T) {
	cases := []struct {
		name    string
		key     bool
		posture *Posture
		want    OrgLockState
	}{
		{"no key: never published", false, nil, OrgLockAbsent},
		{"older daemon: verified posture without the flag", true, &Posture{}, OrgLockAbsent},
		{"lock-writing daemon: verified posture with the flag", true, &Posture{OrgLock: true}, OrgLockTampered},
		{"key present, posture deleted", true, nil, OrgLockTampered},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := filepath.Join(dir, "config.toml")
			var key []byte
			if tc.key {
				var err error
				if key, err = WriteNewKey(KeyPath(cfg)); err != nil {
					t.Fatal(err)
				}
			}
			if tc.posture != nil {
				p := *tc.posture
				p.WrittenAt = time.Now()
				if _, err := Write(PosturePath(cfg), p, key); err != nil {
					t.Fatal(err)
				}
			}
			if got := LoadOrgLock(cfg).State; got != tc.want {
				t.Fatalf("LoadOrgLock = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDeriveFloorTable walks the floor derivation: individual nodes and an
// org that pinned the guard off get nothing; a managed node's org layer and
// pins raise exactly their own part.
func TestDeriveFloorTable(t *testing.T) {
	cases := []struct {
		name string
		in   FloorInputs
		want GuardFloor
	}{
		{"individual node with everything", FloorInputs{OrgLayer: true, PromptFloor: true, PromptFloorStops: true, Pinned: map[string]any{"guard.mode": "enforce"}}, GuardFloor{}},
		{"managed, nothing held", FloorInputs{Managed: true}, GuardFloor{}},
		// T-864 gap 2: whatever keeps the guard on keeps the prompt guard on,
		// at the org's prompt floor.
		{"managed, org bundle", FloorInputs{Managed: true, OrgLayer: true}, GuardFloor{Enabled: true, Mode: ModeObserve, PromptEnabled: true, PromptMode: PromptModeFloor}},
		{"managed, pinned enforce", FloorInputs{Managed: true, Pinned: map[string]any{"guard.mode": "enforce"}}, GuardFloor{Enabled: true, Mode: ModeEnforce, PromptEnabled: true, PromptMode: PromptModeFloor}},
		{"managed, pinned enabled", FloorInputs{Managed: true, Pinned: map[string]any{"guard.enabled": true}}, GuardFloor{Enabled: true, Mode: ModeObserve, PromptEnabled: true, PromptMode: PromptModeFloor}},
		{"managed, org pinned the guard off", FloorInputs{Managed: true, OrgLayer: true, Pinned: map[string]any{"guard.enabled": false}}, GuardFloor{}},
		{"managed, org pinned mode off", FloorInputs{Managed: true, OrgLayer: true, Pinned: map[string]any{"guard.mode": "off"}}, GuardFloor{}},
		{"managed, prompt pin", FloorInputs{Managed: true, OrgLayer: true, PromptFloor: true}, GuardFloor{Enabled: true, Mode: ModeObserve, PromptEnabled: true, PromptMode: PromptModeFloor}},
		{"managed, stopping prompt pin", FloorInputs{Managed: true, OrgLayer: true, PromptFloor: true, PromptFloorStops: true}, GuardFloor{Enabled: true, Mode: ModeObserve, PromptEnabled: true, PromptEnforceIndependent: true, PromptMode: PromptModeFloor}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeriveFloor(tc.in); got != tc.want {
				t.Fatalf("DeriveFloor = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestGuardModeBelow(t *testing.T) {
	for _, tc := range []struct {
		local, floor string
		want         bool
	}{
		{"off", "observe", true},
		{"observe", "enforce", true},
		{"enforce", "observe", false},
		{"observe", "observe", false},
		{"off", "", false},
		{"", "observe", true},
	} {
		if got := GuardModeBelow(tc.local, tc.floor); got != tc.want {
			t.Errorf("GuardModeBelow(%q,%q) = %v, want %v", tc.local, tc.floor, got, tc.want)
		}
	}
}
