package guardposture

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testKey = bytes.Repeat([]byte{7}, keyBytes)

// TestLoadStates pins Sol A2-02's reader table: only a posture that
// verifies under its key is trusted; every other combination of present /
// missing / edited files is tampered, except "nothing at all" (no daemon
// ever published), which is absent.
func TestLoadStates(t *testing.T) {
	enforced := Posture{Enforced: true, Source: SourceOrg, Generation: "3", GateCaps: []string{"tool_gate"}, WrittenAt: time.Unix(5, 0)}
	forge := func(t *testing.T, dir string, p Posture) {
		t.Helper()
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, PostureFilename), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  State
	}{
		{"nothing", func(*testing.T, string) {}, StateAbsent},
		{"signed by the daemon", func(t *testing.T, dir string) {
			mustKey(t, dir, testKey)
			if _, err := Write(filepath.Join(dir, PostureFilename), enforced, testKey); err != nil {
				t.Fatal(err)
			}
		}, StateValid},
		{"forged lowering, no MAC", func(t *testing.T, dir string) {
			mustKey(t, dir, testKey)
			forge(t, dir, Posture{Schema: Schema, Enforced: false, Source: SourceLocal})
		}, StateTampered},
		{"forged with a copied MAC from another posture", func(t *testing.T, dir string) {
			mustKey(t, dir, testKey)
			signed := Sign(enforced, testKey)
			signed.Enforced = false
			signed.GateCaps = nil
			forge(t, dir, signed)
		}, StateTampered},
		{"signed under a different key", func(t *testing.T, dir string) {
			mustKey(t, dir, testKey)
			forge(t, dir, Sign(Posture{Source: SourceLocal}, bytes.Repeat([]byte{9}, keyBytes)))
		}, StateTampered},
		{"posture deleted, key kept", func(t *testing.T, dir string) { mustKey(t, dir, testKey) }, StateTampered},
		{"key deleted, posture kept", func(t *testing.T, dir string) {
			if _, err := Write(filepath.Join(dir, PostureFilename), enforced, testKey); err != nil {
				t.Fatal(err)
			}
		}, StateTampered},
		{"garbage posture", func(t *testing.T, dir string) {
			mustKey(t, dir, testKey)
			if err := os.WriteFile(filepath.Join(dir, PostureFilename), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, StateTampered},
		{"garbage key", func(t *testing.T, dir string) {
			if _, err := Write(filepath.Join(dir, PostureFilename), enforced, testKey); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, KeyFilename), []byte("nope"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, StateTampered},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			got := Load(filepath.Join(dir, PostureFilename), filepath.Join(dir, KeyFilename))
			if got.State != tc.want {
				t.Fatalf("state = %s (%s), want %s", got.State, got.Detail, tc.want)
			}
			if got.State == StateValid && (got.Posture == nil || !got.Posture.FailsClosed("tool_gate")) {
				t.Errorf("valid posture = %+v", got.Posture)
			}
			if got.State == StateTampered && got.Detail == "" {
				t.Error("a tampered load carries no detail")
			}
		})
	}
}

func mustKey(t *testing.T, dir string, key []byte) {
	t.Helper()
	if err := WriteKey(filepath.Join(dir, KeyFilename), key); err != nil {
		t.Fatal(err)
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), KeyFilename)
	k1, err := LoadOrCreateKey(path)
	if err != nil || len(k1) != keyBytes {
		t.Fatalf("create: %v len %d", err, len(k1))
	}
	k2, err := LoadOrCreateKey(path)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("reload changed the key: %v", err)
	}
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	k3, err := LoadOrCreateKey(path)
	if err != nil || bytes.Equal(k1, k3) || len(k3) != keyBytes {
		t.Fatalf("a malformed key was not replaced: %v", err)
	}
}

// TestSecurityFieldsAreMACed: the security pillar's module signal is
// covered by the MAC, and a posture that does not set it keeps the MAC an
// older binary computes.
func TestSecurityFieldsAreMACed(t *testing.T) {
	key := make([]byte, keyBytes)
	base := Posture{Source: SourceLocal, WrittenAt: time.Unix(1, 0)}
	signed := Sign(base, key)
	on := Sign(Posture{Source: SourceLocal, WrittenAt: time.Unix(1, 0), SecurityRecorded: true, SecurityActive: true}, key)
	if on.MAC == signed.MAC {
		t.Fatal("the security fields must change the MAC")
	}
	flipped := on
	flipped.SecurityActive = false
	if Verify(&flipped, key) {
		t.Fatal("clearing SecurityActive after signing must not verify")
	}
	if !Verify(&signed, key) {
		t.Fatal("a posture without the security fields still verifies")
	}
}

// TestSecurityPacksAreMACed (lane SEC-GATEFIX): the active pack set is
// covered by the MAC (dropping or adding a pack after signing does not
// verify), is normalized (sorted, deduplicated) before signing, and is
// dropped from a posture whose module is not active.
func TestSecurityPacksAreMACed(t *testing.T) {
	key := make([]byte, keyBytes)
	active := Posture{Source: SourceLocal, WrittenAt: time.Unix(1, 0), SecurityRecorded: true, SecurityActive: true}
	without := Sign(active, key)
	active.SecurityPacks = []string{"security.secrets", "security", "security.secrets", ""}
	with := Sign(active, key)
	if with.MAC == without.MAC {
		t.Fatal("the pack set must change the MAC")
	}
	if got := with.SecurityPacks; len(got) != 2 || got[0] != "security" || got[1] != "security.secrets" {
		t.Fatalf("packs not normalized: %v", got)
	}
	for _, mut := range []func(p *Posture){
		func(p *Posture) { p.SecurityPacks = []string{"security"} },
		func(p *Posture) {
			p.SecurityPacks = append(append([]string(nil), p.SecurityPacks...), "security.trust")
		},
		func(p *Posture) { p.SecurityPacks = nil },
	} {
		p := with
		mut(&p)
		if Verify(&p, key) {
			t.Fatalf("a changed pack set verifies: %v", p.SecurityPacks)
		}
	}
	if !Verify(&with, key) {
		t.Fatal("the signed pack set must verify")
	}
	off := Sign(Posture{Source: SourceLocal, WrittenAt: time.Unix(1, 0), SecurityRecorded: true, SecurityPacks: []string{"security"}}, key)
	if off.SecurityPacks != nil {
		t.Fatalf("an inactive module carries packs: %v", off.SecurityPacks)
	}
}

// TestTenancyFieldsAreMACed (task PT-01): Managed and TenancyRecorded are
// covered by the MAC; a flipped Managed bit on a current file is
// tampered; a file a pre-PT-01 binary signed still loads, with both
// fields cleared as unauthenticated, so flipping its Managed bit gains
// nothing; and a current file cannot be read in the legacy form.
func TestTenancyFieldsAreMACed(t *testing.T) {
	dir := t.TempDir()
	mustKey(t, dir, testKey)
	path := filepath.Join(dir, PostureFilename)
	load := func() Loaded { return Load(path, filepath.Join(dir, KeyFilename)) }
	put := func(p Posture) {
		t.Helper()
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	managed := Posture{Source: SourceOrg, Managed: true, TenancyRecorded: true, OrgLock: true, WrittenAt: time.Unix(9, 0)}
	cur := Sign(managed, testKey)
	if cur.MAC == Sign(Posture{Source: SourceOrg, OrgLock: true, WrittenAt: time.Unix(9, 0)}, testKey).MAC {
		t.Fatal("the tenancy fields must change the MAC")
	}
	put(cur)
	if ld := load(); ld.State != StateValid || ld.Legacy || !ld.Posture.Managed || !ld.Posture.TenancyRecorded {
		t.Fatalf("current managed posture: %+v", ld)
	}
	// Tamper: the Managed bit cleared on a current file (managed node read
	// as individual, guardfloor's loosening).
	tampered := cur
	tampered.Managed = false
	put(tampered)
	if ld := load(); ld.State != StateTampered {
		t.Fatalf("a flipped Managed bit must not verify: %+v", ld)
	}
	// A pre-PT-01 file: its MAC covers neither field.
	legacy := normalize(managed)
	legacy.MAC = macForm(legacy, testKey, false)
	put(legacy)
	ld := load()
	if ld.State != StateValid || !ld.Legacy || ld.Posture.Managed || ld.Posture.TenancyRecorded || !ld.Posture.OrgLock {
		t.Fatalf("legacy file: %+v", ld)
	}
	// Flipping the Managed bit on a legacy file gains nothing.
	legacyFlipped := legacy
	legacyFlipped.Managed = false
	put(legacyFlipped)
	if ld := load(); ld.State != StateValid || ld.Posture.Managed || ld.Posture.TenancyRecorded {
		t.Fatalf("legacy flipped: %+v", ld)
	}
	// A current file never verifies in the legacy form.
	c := cur
	if verifyLegacy(&c, testKey) {
		t.Fatal("a current file must not read in the legacy form")
	}
}

// TestKeyBeforeFirstPosture (live check macOS 2026-10-22, D4): a key an
// accept path made before any posture was published reads as not yet
// initialised (absent), for the posture and the org lock; the first
// posture write clears the marker, after which a removed posture is a
// tamper again; a forged marker does not verify.
func TestKeyBeforeFirstPosture(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "config.toml")
	keyPath, postPath := KeyPath(cp), PosturePath(cp)
	key, err := LoadOrCreateKeyBeforePosture(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if ld := Load(postPath, keyPath); ld.State != StateAbsent || !ld.Unpublished {
		t.Fatalf("a key made before the first posture reads %v (%s)", ld.State, ld.Detail)
	}
	if ld := LoadOrgLock(cp); ld.State != OrgLockAbsent {
		t.Fatalf("the org lock reads %v (%s)", ld.State, ld.Detail)
	}
	if again, err := LoadOrCreateKeyBeforePosture(keyPath); err != nil || !bytes.Equal(again, key) {
		t.Fatal("the second accept did not reuse the key")
	}
	if _, err := Write(postPath, Posture{OrgLock: true, WrittenAt: time.Now()}, key); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, UnpublishedFilename)); !os.IsNotExist(err) {
		t.Fatal("the first posture write left the marker")
	}
	if ld := Load(postPath, keyPath); ld.State != StateValid {
		t.Fatalf("after the first write: %v", ld.State)
	}
	// The real tamper: a posture removed after one existed.
	if err := os.Remove(postPath); err != nil {
		t.Fatal(err)
	}
	if ld := Load(postPath, keyPath); ld.State != StateTampered {
		t.Fatalf("a posture removed after one existed reads %v", ld.State)
	}
	if ld := LoadOrgLock(cp); ld.State != OrgLockTampered {
		t.Fatalf("the org lock after a removed posture reads %v", ld.State)
	}
	// A marker that does not verify under the key changes nothing.
	if err := os.WriteFile(filepath.Join(dir, UnpublishedFilename), []byte("00\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ld := Load(postPath, keyPath); ld.State != StateTampered {
		t.Fatalf("a forged marker reads %v", ld.State)
	}
	// The daemon's own key creation never marks.
	dir2 := t.TempDir()
	if _, err := LoadOrCreateKey(KeyPath(filepath.Join(dir2, "config.toml"))); err != nil {
		t.Fatal(err)
	}
	if ld := Load(PosturePath(filepath.Join(dir2, "config.toml")), KeyPath(filepath.Join(dir2, "config.toml"))); ld.State != StateTampered {
		t.Fatalf("a daemon key with no posture reads %v", ld.State)
	}
}

// TestPromptJudgeFieldsAreSigned pins the adm-2 posture fields: set, they are
// covered by the MAC (a flip no longer verifies); unset, the canonical form is
// byte-identical to the one earlier binaries sign.
func TestPromptJudgeFieldsAreSigned(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	base := Posture{Schema: 1, Source: SourceLocal, WrittenAt: time.Unix(1700000000, 0).UTC()}
	if string(canonical(base)) != string(canonical(Posture{Schema: 1, Source: SourceLocal, WrittenAt: base.WrittenAt})) {
		t.Fatal("canonical form is not stable")
	}
	if strings.Contains(string(canonical(base)), "prompt_judge") {
		t.Fatal("an unset prompt judge field must not change the canonical form")
	}
	cases := []struct {
		name string
		set  func(*Posture)
		flip func(*Posture)
	}{
		{"active", func(p *Posture) { p.PromptJudgeActive = true }, func(p *Posture) { p.PromptJudgeActive = false }},
		{"fail closed", func(p *Posture) { p.PromptJudgeActive, p.PromptJudgeFailClosed = true, true }, func(p *Posture) { p.PromptJudgeFailClosed = false }},
	}
	for _, tc := range cases {
		p := base
		tc.set(&p)
		signed := Sign(p, key)
		if !Verify(&signed, key) {
			t.Fatalf("%s: a signed posture must verify", tc.name)
		}
		tc.flip(&signed)
		if Verify(&signed, key) {
			t.Fatalf("%s: flipping the field must break the MAC", tc.name)
		}
	}
}
