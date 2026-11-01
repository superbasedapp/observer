package secposture

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestPostureFloorFact (lane SEC-P4 decision 9): the commit gate and
// launch trust floors ride the signed posture: the MAC covers them (an
// edit to either fails verification), a file without them signs byte for
// byte as before and reads no floor, values outside the vocabulary (or the
// axis's weakest) are not signed, and the commit gate floor reaches the
// policy.Security fact also from a file past its expiry (raise only).
func TestPostureFloorFact(t *testing.T) {
	l := LayoutFor(filepath.Join(t.TempDir(), "config.toml"))
	key, err := LoadOrCreateKey(l.KeyPath())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "proj")
	now := time.Now()
	base := File{
		ProjectRootHash: ProjectRootHash(root), Packs: []string{"security", "security.secrets"}, Sequence: 1,
		IssuedAt: now, ExpiresAt: now.Add(DefaultTTL), Trust: policy.TrustClean, QuickScanAvailable: true,
	}
	plain, err := Encode(Sign(base, key))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain, []byte("floor")) {
		t.Fatalf("a file without a floor names one: %s", plain)
	}
	floored := base
	floored.CommitGateFloor, floored.PrelaunchTrustFloor = policy.CommitGateFloorQuickScan, PrelaunchTrustRefuse
	signed := Sign(floored, key)
	if !Verify(&signed, key) {
		t.Fatal("a floored file does not verify")
	}
	for _, edit := range []func(f *File){
		func(f *File) { f.CommitGateFloor = "" },
		func(f *File) { f.PrelaunchTrustFloor = PrelaunchTrustAsk },
	} {
		c := signed
		edit(&c)
		if Verify(&c, key) {
			t.Fatal("the MAC does not cover a floor")
		}
	}
	odd := base
	odd.CommitGateFloor, odd.PrelaunchTrustFloor = "ask", "warn"
	if s := Sign(odd, key); s.CommitGateFloor != "" || s.PrelaunchTrustFloor != "" {
		t.Fatalf("the weakest values were signed: %+v", s)
	}
	odd.CommitGateFloor, odd.PrelaunchTrustFloor = "maybe", "sometimes"
	if s := Sign(odd, key); s.CommitGateFloor != "" || s.PrelaunchTrustFloor != "" {
		t.Fatalf("out-of-vocabulary values were signed: %+v", s)
	}

	// The fact, from a current file and from an expired one.
	for _, expired := range []bool{false, true} {
		f := floored
		f.Sequence = uint64(time.Now().UnixNano())
		if expired {
			f.IssuedAt, f.ExpiresAt = now.Add(-2*DefaultTTL), now.Add(-DefaultTTL)
		}
		if _, err := Write(l, f, key); err != nil {
			t.Fatal(err)
		}
		r := Load(l, root, ModuleActive, now, Versions{})
		sec := FactsUnder(r, []string{"security"})
		if sec.CommitGateFloor != policy.CommitGateFloorQuickScan {
			t.Fatalf("expired=%v: fact %q (state %+v), want the floor", expired, sec.CommitGateFloor, r.State)
		}
		if expired && sec.Posture != policy.SecurityPostureUnknown {
			t.Fatalf("an expired file reads %s, want unknown", sec.Posture)
		}
	}
	// An older posture (written before the field existed) reads no floor.
	f, err := Decode(plain)
	if err != nil || f.CommitGateFloor != "" || f.PrelaunchTrustFloor != "" {
		t.Fatalf("an older posture: %+v %v", f, err)
	}
}
