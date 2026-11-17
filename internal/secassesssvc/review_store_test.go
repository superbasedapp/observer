package secassesssvc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Findings of the independent review of W0 to W2 (M1, M5, m1, m6, m7, m12).

func newStoreWithSide(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	return New(filepath.Join(dir, Filename)), dir
}

func ageDir(t *testing.T, s *Store, id string, at time.Time) {
	t.Helper()
	if err := os.Chtimes(filepath.Join(s.Side().dir, id), at, at); err != nil {
		t.Fatal(err)
	}
}

func TestPruneAndReconcileLeaveEverythingWhileTheRecordIsUnreadable(t *testing.T) {
	s, _ := newStoreWithSide(t)
	now := time.Now().UTC()
	id := hex16(1)
	if _, err := s.Record(Run{ID: id, Kind: "threat_model", Phase: PhaseStarted, EndedAt: now}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Side().Put(id, SideModel, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	ageDir(t, s, id, now.Add(-time.Hour))
	for name, body := range map[string]string{"not json": "not json", "other schema": `{"schema":99,"runs":[]}`} {
		if err := os.WriteFile(s.path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if n := s.PruneSide(0, now); n != 0 || !s.Side().Has(id) {
			t.Fatalf("%s: PruneSide removed %d directories of an unreadable record", name, n)
		}
		if n := Reconcile(context.Background(), s, Ports{Now: func() time.Time { return now }}); n != 0 || !s.Side().Has(id) {
			t.Fatalf("%s: Reconcile changed %d runs or pruned an unreadable record's evidence", name, n)
		}
		if err := s.CanRecord(); !errors.Is(err, ErrUnreadable) {
			t.Fatalf("%s: CanRecord = %v, want ErrUnreadable", name, err)
		}
		if _, err := s.AllErr(); !errors.Is(err, ErrUnreadable) {
			t.Fatalf("%s: AllErr = %v", name, err)
		}
	}
}

func TestPruneLeavesAYoungSideDirectory(t *testing.T) {
	s, _ := newStoreWithSide(t)
	now := time.Now().UTC()
	young, old := hex16(1), hex16(2)
	for _, id := range []string{young, old} {
		if err := s.Side().Put(id, SideTree, []byte("{}")); err != nil {
			t.Fatal(err)
		}
	}
	ageDir(t, s, old, now.Add(-time.Hour))
	// Neither is recorded: the launching run's "before" snapshot (young) stays, the stray old one goes.
	if n := s.PruneSide(0, now); n != 1 || !s.Side().Has(young) || s.Side().Has(old) {
		t.Fatalf("removed %d, young kept %v, old kept %v", n, s.Side().Has(young), s.Side().Has(old))
	}
	if n := s.PruneSide(0, now.Add(PruneGrace+time.Minute)); n != 1 || s.Side().Has(young) {
		t.Fatalf("a directory past its grace was not removed (%d)", n)
	}
}

func TestRecordCountTrimOnlyDropsWhatCanBeForgotten(t *testing.T) {
	s, _ := newStoreWithSide(t)
	now := time.Now().UTC()
	// A hundred runs, all still in use (started, with a terminal and no end).
	for i := 1; i <= MaxRuns; i++ {
		r := Run{ID: hex16(i), Kind: "pentest_local", Phase: PhaseStarted, Handle: "h", TimeBoxMinutes: 45}
		if _, err := s.Record(r, now); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if err := s.CanRecord(); !errors.Is(err, ErrFull) {
		t.Fatalf("CanRecord = %v, want ErrFull with a hundred runs in use", err)
	}
	if _, err := s.Record(Run{ID: hex16(500), Kind: "threat_model", Phase: PhaseStarted}, now); !errors.Is(err, ErrFull) {
		t.Fatalf("the hundred-and-first launch: %v, want ErrFull", err)
	}
	if len(s.All()) != MaxRuns || !s.Exists(hex16(1)) {
		t.Fatal("a run in use was evicted by the count trim")
	}
	// Once the oldest run has ended, it can go.
	if _, _, err := s.Mutate(hex16(1), func(r *Run) error { r.EndedAt = now; r.Audit = "no_change"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.CanRecord(); err != nil {
		t.Fatalf("CanRecord with a droppable run = %v", err)
	}
	if _, err := s.Record(Run{ID: hex16(500), Kind: "threat_model", Phase: PhaseStarted}, now); err != nil {
		t.Fatal(err)
	}
	if s.Exists(hex16(1)) || !s.Exists(hex16(500)) || len(s.All()) != MaxRuns {
		t.Fatal("the ended run was not the one dropped")
	}
}

func TestRecordLockTakesTurnsAndBreaksAStaleLock(t *testing.T) {
	s, _ := newStoreWithSide(t)
	lock := s.path + lockSuffix
	if err := os.WriteFile(lock, []byte("123"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * lockStale)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	// A lock whose owner died is taken over.
	if _, err := s.Record(Run{ID: hex16(1), Kind: "threat_model"}, time.Now()); err != nil {
		t.Fatalf("a stale lock blocked a write: %v", err)
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatal("the lock file was left behind")
	}
	// A live lock is waited for and then reported, never overwritten.
	if err := os.WriteFile(lock, []byte("123"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := s.Record(Run{ID: hex16(2), Kind: "threat_model"}, time.Now())
	if !errors.Is(err, ErrLockBusy) {
		t.Fatalf("a held lock: %v, want ErrLockBusy", err)
	}
	if time.Since(start) < lockWait/2 {
		t.Fatalf("the write did not wait for the lock (%v)", time.Since(start))
	}
	if s.Exists(hex16(2)) {
		t.Fatal("a write went ahead without the lock")
	}
}

func TestPrepareRunDirRemovesWhatItMadeIncludingEmptyParents(t *testing.T) {
	root := t.TempDir()
	cleanup, err := PrepareRunDir(root, hex16(7))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".observer", "assessments", hex16(7))); err != nil {
		t.Fatal(err)
	}
	cleanup()
	if _, err := os.Stat(filepath.Join(root, ".observer")); !os.IsNotExist(err) {
		t.Fatalf("an empty .observer folder was left in the project (%v)", err)
	}
	// A parent that held something else stays.
	if err := os.MkdirAll(filepath.Join(root, ".observer", "assessments"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".observer", "keep.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cleanup, err = PrepareRunDir(root, hex16(8))
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if _, err := os.Stat(filepath.Join(root, ".observer", "keep.txt")); err != nil {
		t.Fatalf("the cleanup took a parent that held a file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".observer", "assessments", hex16(8))); !os.IsNotExist(err) {
		t.Fatal("the run directory was left")
	}
}
