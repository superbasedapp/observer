package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/remoteauth"
)

func newRemoteSessionTestDB(t *testing.T) *RemoteSessionPersister {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "rs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return NewRemoteSessionPersister(database)
}

func TestRemoteSessionSaveLoadRoundTrip(t *testing.T) {
	ctx := context.Background()
	p := newRemoteSessionTestDB(t)
	now := time.Now().UTC().Truncate(time.Nanosecond)
	want := remoteauth.PersistedSession{IDHash: "abc123", Gen: 1, CreatedAt: now, LastSeen: now}
	if err := p.Save(ctx, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	gen, rows, err := p.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if gen != 1 {
		t.Fatalf("gen = %d, want 1 (migration seeds 1)", gen)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	got := rows[0]
	if got.IDHash != want.IDHash || got.Gen != want.Gen {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || !got.LastSeen.Equal(want.LastSeen) {
		t.Fatalf("timestamp round-trip mismatch: got %v/%v want %v/%v", got.CreatedAt, got.LastSeen, want.CreatedAt, want.LastSeen)
	}
}

func TestRemoteSessionTouchIsUpdateOnly(t *testing.T) {
	ctx := context.Background()
	p := newRemoteSessionTestDB(t)
	now := time.Now().UTC()
	// Touch a NON-existent id must NOT insert a row.
	if err := p.Touch(ctx, "ghost", 1, now); err != nil {
		t.Fatalf("Touch ghost: %v", err)
	}
	_, rows, _ := p.LoadAll(ctx)
	if len(rows) != 0 {
		t.Fatalf("Touch must never INSERT; found %d rows", len(rows))
	}
	// Touch with the WRONG generation must not update.
	_ = p.Save(ctx, remoteauth.PersistedSession{IDHash: "s1", Gen: 5, CreatedAt: now, LastSeen: now})
	later := now.Add(time.Hour)
	if err := p.Touch(ctx, "s1", 1, later); err != nil { // gen 1 != row gen 5
		t.Fatalf("Touch wrong-gen: %v", err)
	}
	_, rows, _ = p.LoadAll(ctx)
	if len(rows) != 1 || !rows[0].LastSeen.Equal(now) {
		t.Fatalf("gen-fenced Touch must not update a superseded row: %+v", rows)
	}
	// Touch with the RIGHT generation updates last_seen.
	if err := p.Touch(ctx, "s1", 5, later); err != nil {
		t.Fatalf("Touch right-gen: %v", err)
	}
	_, rows, _ = p.LoadAll(ctx)
	if !rows[0].LastSeen.Equal(later) {
		t.Fatalf("gen-matched Touch must update last_seen, got %v", rows[0].LastSeen)
	}
}

func TestRemoteSessionResetClearsAndAdvancesMonotonically(t *testing.T) {
	ctx := context.Background()
	p := newRemoteSessionTestDB(t)
	now := time.Now().UTC()
	_ = p.Save(ctx, remoteauth.PersistedSession{IDHash: "a", Gen: 1, CreatedAt: now, LastSeen: now})
	if err := p.Reset(ctx, 2); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	gen, rows, _ := p.LoadAll(ctx)
	if gen != 2 || len(rows) != 0 {
		t.Fatalf("Reset(2) must clear rows + set gen 2, got gen=%d rows=%d", gen, len(rows))
	}
	// A lower gen must NOT regress the durable generation.
	if err := p.Reset(ctx, 1); err != nil {
		t.Fatalf("Reset(1): %v", err)
	}
	gen, _, _ = p.LoadAll(ctx)
	if gen != 2 {
		t.Fatalf("Reset must be monotonic; gen regressed to %d", gen)
	}
}

func TestAdvanceRemoteSessionGeneration(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "adv.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	s := New(database)
	p := NewRemoteSessionPersister(database)
	now := time.Now().UTC()
	_ = p.Save(ctx, remoteauth.PersistedSession{IDHash: "x", Gen: 1, CreatedAt: now, LastSeen: now})

	newGen, err := s.AdvanceRemoteSessionGeneration(ctx)
	if err != nil {
		t.Fatalf("AdvanceRemoteSessionGeneration: %v", err)
	}
	if newGen != 2 {
		t.Fatalf("first advance = %d, want 2", newGen)
	}
	gen, rows, _ := p.LoadAll(ctx)
	if gen != 2 || len(rows) != 0 {
		t.Fatalf("advance must clear rows + bump gen, got gen=%d rows=%d", gen, len(rows))
	}
	newGen2, _ := s.AdvanceRemoteSessionGeneration(ctx)
	if newGen2 != 3 {
		t.Fatalf("second advance = %d, want 3 (monotonic +1)", newGen2)
	}
}
