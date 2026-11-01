//go:build !sbo_omit_security

package secsvc

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestPostureScanningPerProject (lane LEFT-SEC milestone 1): the writer
// signs each project's [security.scanning] budget and staleness and
// computes its blocking list at the project's least severity; with no
// Scanning option (or a zero answer) the file is the built-in one.
func TestPostureScanningPerProject(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	st := &fakeStore{}
	l := secposture.Layout{Dir: filepath.Join(t.TempDir(), "security")}
	s, err := New(context.Background(), Options{
		Layout: l, Store: st, Now: func() time.Time { return now },
		Projects: func(context.Context, time.Time) ([]string, error) { return []string{"/a"}, nil },
		Packs:    func() []string { return []string{"security"} },
		Scanning: func(root string) ScanningFloors {
			if root == "/a" {
				return ScanningFloors{QuickScanBudgetS: 10, MaxScanStalenessMin: 60, MinBlocking: policy.FindingSeverityLow}
			}
			return ScanningFloors{}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f, err := s.Compute(context.Background(), "/a", now)
	if err != nil {
		t.Fatal(err)
	}
	if f.QuickScanBudgetS != 10 || f.MaxScanStalenessMin != 60 || len(st.q.Severities) != 4 || st.q.Severities[0] != policy.FindingSeverityLow {
		t.Fatalf("file %+v, severities %v", f, st.q.Severities)
	}
	plain, _ := newSvc(t, &fakeStore{}, now)
	g, err := plain.Compute(context.Background(), "/a", now)
	if err != nil || g.QuickScanBudgetS != 0 || g.MaxScanStalenessMin != 0 {
		t.Fatalf("no Scanning option: %+v %v", g, err)
	}
}

// TestReflogCappedKeys: a key is capped only when every holding commit is.
func TestReflogCappedKeys(t *testing.T) {
	rows := []store.SecHeldRow{
		{LocalKey: "a", CommitSHA: "1", ReflogCap: store.SecReflogCapAge},
		{LocalKey: "b", CommitSHA: "1", ReflogCap: store.SecReflogCapAge},
		{LocalKey: "b", CommitSHA: "2"},
		{LocalKey: "c", CommitSHA: "3", ReflogCap: store.SecReflogCapEntries},
	}
	got := ReflogCappedKeys([]string{"a", "b", "c", "d"}, rows)
	if len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("capped %v, want [a c]", got)
	}
}

// TestSourceTreeOf (lane LEFT-SEC milestone 2): a tree a copy run holds
// maps to the same place in its recorded source project; a live run, a run
// with no source, a copy inside its own source and a tree no run holds do
// not map.
func TestSourceTreeOf(t *testing.T) {
	runs := []CopyRun{
		{RunID: "live", Copy: false, WorkspaceDir: "/live", ProjectRoot: "/src0"},
		{RunID: "nosrc", Copy: true, WorkspaceDir: "/nosrc"},
		{RunID: "inside", Copy: true, WorkspaceDir: "/src2/.copies/w", ProjectRoot: "/src2"},
		{RunID: "a", Copy: true, WorkspaceDir: "/copies/a/work", CopyHostPath: "/host/a", ProjectRoot: "/src"},
	}
	for _, tc := range []struct {
		tree string
		want string
		ok   bool
	}{
		{"/copies/a/work", "/src", true},
		{"/copies/a/work/pkg", "/src/pkg", true},
		{"/host/a/x", "/src/x", true},
		{"/live", "", false},
		{"/nosrc", "", false},
		{"/src2/.copies/w", "", false},
		{"/elsewhere", "", false},
		{"", "", false},
	} {
		got, ok := SourceTreeOf(runs, tc.tree)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%q: %q %v, want %q %v", tc.tree, got, ok, tc.want, tc.ok)
		}
	}
}

// TestRotateBoxWalks: a tick resumes after the cursor, round robin, and
// with 65 refs and a cap of 64 the 65th is walked by the second tick.
func TestRotateBoxWalks(t *testing.T) {
	var walks []BoxRefWalk
	for i := 1; i <= 65; i++ {
		walks = append(walks, BoxRefWalk{Ref: "refs/observer/sandbox/R" + string(rune('0'+i/100)) + string(rune('0'+(i/10)%10)) + string(rune('0'+i%10))})
	}
	kept, deferred := CapBoxWalks(RotateBoxWalks(walks, ""), 64)
	if len(kept) != 64 || len(deferred) != 1 || deferred[0].Ref != walks[64].Ref {
		t.Fatalf("tick 1 kept %d deferred %v", len(kept), deferred)
	}
	cur := NextBoxCursor(kept, deferred)
	kept, _ = CapBoxWalks(RotateBoxWalks(walks, cur), 64)
	if kept[0].Ref != walks[64].Ref {
		t.Fatalf("tick 2 starts at %s, want %s", kept[0].Ref, walks[64].Ref)
	}
	if NextBoxCursor(walks[:3], nil) != "" || len(RotateBoxWalks(walks[:1], "x")) != 1 {
		t.Fatal("cursor edges")
	}
}
