package archivestore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/archive"
)

func openTemp(t *testing.T, dir string) *Store {
	t.Helper()
	fixed := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	s, err := Open(context.Background(), Options{
		Path: filepath.Join(dir, "archive.db"),
		Now:  func() time.Time { return fixed },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

// TestOpenIsIdempotentAcrossReopen pins that the migration runner records its
// version and re-running it on an existing file is a no-op — the daemon opens
// this file once per retention pass, so a runner that re-applied its lineage
// would corrupt or fail on every pass after the first.
func TestOpenIsIdempotentAcrossReopen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ctx := context.Background()

	s := openTemp(t, dir)
	if err := s.WriteFiles(ctx, []archive.FileRow{{ID: 1, Project: "/p", Path: "/p/a.go"}}); err != nil {
		t.Fatalf("WriteFiles: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2 := openTemp(t, dir)
	defer func() { _ = s2.Close() }()
	d, err := s2.CodeIntelProjectDigest(ctx, "/p", 0)
	if err != nil {
		t.Fatalf("digest after reopen: %v", err)
	}
	if d.Files.Rows != 1 {
		t.Fatalf("row did not survive reopen: %+v", d.Files)
	}
	var version string
	if err := s2.DB().QueryRowContext(ctx,
		`SELECT value FROM schema_meta WHERE key = 'version'`).Scan(&version); err != nil {
		t.Fatalf("schema_meta: %v", err)
	}
	// Bump alongside every new file in internal/archivestore/migrations.
	// 1 = archive_codeintel_* (Bucket A), 2 = archive_process_* (Bucket B).
	const wantVersion = "2"
	if version != wantVersion {
		t.Fatalf("schema version = %q, want %q", version, wantVersion)
	}
}

// TestWritesAreIdempotentUpserts pins the property the crash-then-retry path
// depends on: re-copying the same rows must not duplicate them. minhash is the
// interesting case — the HOT table has no unique constraint on (node_id, band),
// so this file's PRIMARY KEY is a deliberate strengthening rather than a mirror.
func TestWritesAreIdempotentUpserts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTemp(t, t.TempDir())
	defer func() { _ = s.Close() }()

	write := func() {
		t.Helper()
		if err := s.WriteFiles(ctx, []archive.FileRow{{ID: 1, Project: "/p", Path: "/p/a.go"}}); err != nil {
			t.Fatalf("WriteFiles: %v", err)
		}
		if err := s.WriteNodes(ctx, []archive.NodeRow{{ID: 5, Project: "/p", FileID: 1, Name: "F"}}); err != nil {
			t.Fatalf("WriteNodes: %v", err)
		}
		if err := s.WriteEmbeddings(ctx, []archive.EmbeddingRow{{NodeID: 5, Project: "/p", Dim: 2, Vec: []byte{1, 2}}}); err != nil {
			t.Fatalf("WriteEmbeddings: %v", err)
		}
		if err := s.WriteMinhash(ctx, []archive.MinhashRow{{NodeID: 5, Project: "/p", Band: 0, Hash: 42}}); err != nil {
			t.Fatalf("WriteMinhash: %v", err)
		}
	}
	write()
	first, err := s.CodeIntelProjectDigest(ctx, "/p", 0)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	write()
	second, err := s.CodeIntelProjectDigest(ctx, "/p", 0)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if err := archive.Verify(first, second); err != nil {
		t.Fatalf("a re-copy changed the archive contents — the writes are not idempotent: %v", err)
	}
}

// TestDeleteIsScopedToOneProject pins that the pre-clear (and, later, the
// cold-storage expiry) never reaches past the project it was asked about.
func TestDeleteIsScopedToOneProject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTemp(t, t.TempDir())
	defer func() { _ = s.Close() }()

	if err := s.WriteFiles(ctx, []archive.FileRow{
		{ID: 1, Project: "/a", Path: "/a/x.go"},
		{ID: 2, Project: "/b", Path: "/b/y.go"},
	}); err != nil {
		t.Fatalf("WriteFiles: %v", err)
	}
	if err := s.WriteNodes(ctx, []archive.NodeRow{
		{ID: 10, Project: "/a", FileID: 1},
		{ID: 20, Project: "/b", FileID: 2},
	}); err != nil {
		t.Fatalf("WriteNodes: %v", err)
	}
	if err := s.DeleteCodeIntelProject(ctx, "/a"); err != nil {
		t.Fatalf("DeleteCodeIntelProject: %v", err)
	}
	gone, err := s.CodeIntelProjectDigest(ctx, "/a", 0)
	if err != nil {
		t.Fatalf("digest /a: %v", err)
	}
	if !gone.Empty() {
		t.Fatalf("/a survived the delete: %+v", gone)
	}
	kept, err := s.CodeIntelProjectDigest(ctx, "/b", 0)
	if err != nil {
		t.Fatalf("digest /b: %v", err)
	}
	if kept.Files.Rows != 1 || kept.Nodes.Rows != 1 {
		t.Fatalf("/b was affected by deleting /a: %+v", kept)
	}
}

// TestOpenRequiresAPath pins the guard that stops an empty config value from
// silently creating a database in the process's working directory.
func TestOpenRequiresAPath(t *testing.T) {
	t.Parallel()
	if _, err := Open(context.Background(), Options{}); err == nil {
		t.Fatal("Open with no Path succeeded")
	}
}
