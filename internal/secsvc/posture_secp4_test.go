//go:build !sbo_omit_security

package secsvc

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// TestWriteAllSignsFloorsPerProject (lane SEC-P4 decision 9): the posture
// writer signs the floors in force at each project root (Options.Floors),
// so only the floored project's posture carries them; Compute reads them
// for a root too.
func TestWriteAllSignsFloorsPerProject(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	l := secposture.Layout{Dir: filepath.Join(t.TempDir(), "security")}
	s, err := New(context.Background(), Options{
		Layout: l, Store: &fakeStore{}, Now: func() time.Time { return now },
		Projects: func(context.Context, time.Time) ([]string, error) { return []string{"/a", "/b"}, nil },
		Packs:    func() []string { return []string{"security"} },
		Floors: func(root string) (string, string) {
			if root == "/a" {
				return policy.CommitGateFloorQuickScan, secposture.PrelaunchTrustAsk
			}
			return "", ""
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := secposture.Load(l, "/a", secposture.ModuleActive, now, secposture.Versions{})
	b := secposture.Load(l, "/b", secposture.ModuleActive, now, secposture.Versions{})
	if a.File == nil || a.File.CommitGateFloor != policy.CommitGateFloorQuickScan || a.File.PrelaunchTrustFloor != secposture.PrelaunchTrustAsk {
		t.Fatalf("/a posture %+v, want both floors", a.File)
	}
	if b.File == nil || b.File.CommitGateFloor != "" || b.File.PrelaunchTrustFloor != "" {
		t.Fatalf("/b posture %+v, want no floor", b.File)
	}
	if f := secposture.FactsUnder(a, nil); f.CommitGateFloor != policy.CommitGateFloorQuickScan {
		t.Fatalf("/a fact %+v", f)
	}
	if f, err := s.Compute(context.Background(), "/a", now); err != nil || f.CommitGateFloor != policy.CommitGateFloorQuickScan {
		t.Fatalf("Compute /a = %+v %v", f, err)
	}
}
