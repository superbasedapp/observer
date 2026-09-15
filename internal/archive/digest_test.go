package archive

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func sampleFile() FileRow {
	return FileRow{
		ID: 7, Project: "/p", Path: "/p/a.go", Lang: "go",
		ContentHash: "h1", Mtime: 100, IndexedAt: 200, Parser: "goast", Status: "indexed",
	}
}

// TestRowDigestIsFieldSensitive walks every column of every row type and
// asserts that changing it changes the digest. Without this, a copier that
// silently dropped a column (a scan that forgot a field, a schema that grew
// one) would still "verify" — the check would pass because both sides ignore
// the same column, which is exactly the shape of a verification that only
// looks like one.
func TestRowDigestIsFieldSensitive(t *testing.T) {
	t.Parallel()
	base := sampleFile()
	mutations := []struct {
		name string
		row  FileRow
	}{
		{"id", func() FileRow { r := base; r.ID = 8; return r }()},
		{"project", func() FileRow { r := base; r.Project = "/q"; return r }()},
		{"path", func() FileRow { r := base; r.Path = "/p/b.go"; return r }()},
		{"lang", func() FileRow { r := base; r.Lang = "py"; return r }()},
		{"content_hash", func() FileRow { r := base; r.ContentHash = "h2"; return r }()},
		{"mtime", func() FileRow { r := base; r.Mtime = 101; return r }()},
		{"indexed_at", func() FileRow { r := base; r.IndexedAt = 201; return r }()},
		{"parser", func() FileRow { r := base; r.Parser = "treesitter:go"; return r }()},
		{"status", func() FileRow { r := base; r.Status = "stale"; return r }()},
	}
	for _, m := range mutations {
		if m.row.Digest() == base.Digest() {
			t.Errorf("FileRow.%s change did not move the digest — the column is invisible to verification", m.name)
		}
	}

	node := NodeRow{
		ID: 1, Project: "/p", FileID: 7, Kind: "function", Name: "F",
		FQN: "pkg.F", Lang: "go", StartLine: 1, EndLine: 9, StartByte: 0, EndByte: 40,
		Signature: "func F()", SigHash: "s",
	}
	for _, m := range []struct {
		name string
		row  NodeRow
	}{
		{"file_id", func() NodeRow { r := node; r.FileID = 8; return r }()},
		{"name", func() NodeRow { r := node; r.Name = "G"; return r }()},
		{"end_line", func() NodeRow { r := node; r.EndLine = 10; return r }()},
		{"signature", func() NodeRow { r := node; r.Signature = "func F(x int)"; return r }()},
		{"sig_hash", func() NodeRow { r := node; r.SigHash = "t"; return r }()},
	} {
		if m.row.Digest() == node.Digest() {
			t.Errorf("NodeRow.%s change did not move the digest", m.name)
		}
	}

	edge := EdgeRow{
		ID: 1, Project: "/p", FileID: 7, SrcID: 1, DstID: 2,
		Kind: "CALLS", Confidence: 1.0, ResolverBackend: "name-matched",
	}
	if e2 := edge; func() bool { e2.Confidence = 0.5; return e2.Digest() == edge.Digest() }() {
		t.Error("EdgeRow.confidence change did not move the digest")
	}

	emb := EmbeddingRow{NodeID: 1, Project: "/p", Dim: 4, Vec: []byte{1, 2, 3, 4}}
	truncated := EmbeddingRow{NodeID: 1, Project: "/p", Dim: 4, Vec: []byte{1, 2, 3}}
	if emb.Digest() == truncated.Digest() {
		t.Error("a TRUNCATED embedding vector produced the same digest — a partially written BLOB would verify")
	}

	mh := MinhashRow{NodeID: 1, Project: "/p", Band: 2, Hash: 99}
	other := MinhashRow{NodeID: 1, Project: "/p", Band: 2, Hash: 100}
	if mh.Digest() == other.Digest() {
		t.Error("MinhashRow.hash change did not move the digest")
	}
}

// TestDigestIsLengthPrefixedNotDelimited pins the encoding choice in hash.go.
// With a delimiter-separated encoding, two genuinely different rows whose text
// fields straddle the delimiter hash identically — and the fields most likely
// to contain arbitrary bytes (a signature excerpt, a raw call site) are
// exactly the ones an operator's private code fills.
func TestDigestIsLengthPrefixedNotDelimited(t *testing.T) {
	t.Parallel()
	a := FileRow{Project: "ab", Path: "c"}
	b := FileRow{Project: "a", Path: "bc"}
	if a.Digest() == b.Digest() {
		t.Fatal("adjacent string fields are ambiguous across the boundary — the encoding is delimiter-based, not length-prefixed")
	}
}

// TestTableDigestDoesNotCancelDuplicates pins the ADDITION-not-XOR choice.
// Under XOR two identical rows annihilate, so a duplicate-key upsert bug that
// wrote a row twice would leave a digest identical to writing it zero times.
func TestTableDigestDoesNotCancelDuplicates(t *testing.T) {
	t.Parallel()
	var none, twice TableDigest
	twice.Add(0xABCD)
	twice.Add(0xABCD)
	if twice.Sum == none.Sum {
		t.Fatal("two identical rows cancelled out of the checksum — the accumulator is XOR-shaped")
	}
	if twice.Rows != 2 {
		t.Fatalf("Rows = %d, want 2", twice.Rows)
	}
}

// TestVerifyDetectsEveryTable makes sure no table was left out of the
// comparison loop: for each one, a single missing row must be caught.
func TestVerifyDetectsEveryTable(t *testing.T) {
	t.Parallel()
	full := func() ProjectDigest {
		var d ProjectDigest
		d.Files.Add(1)
		d.Nodes.Add(2)
		d.Edges.Add(3)
		d.Sites.Add(4)
		d.Embeddings.Add(5)
		d.Minhash.Add(6)
		return d
	}
	if err := Verify(full(), full()); err != nil {
		t.Fatalf("identical digests must verify: %v", err)
	}
	for _, tc := range []struct {
		name string
		drop func(*ProjectDigest)
	}{
		{"codeintel_files", func(d *ProjectDigest) { d.Files = TableDigest{} }},
		{"codeintel_nodes", func(d *ProjectDigest) { d.Nodes = TableDigest{} }},
		{"codeintel_edges", func(d *ProjectDigest) { d.Edges = TableDigest{} }},
		{"codeintel_sites", func(d *ProjectDigest) { d.Sites = TableDigest{} }},
		{"codeintel_embeddings", func(d *ProjectDigest) { d.Embeddings = TableDigest{} }},
		{"codeintel_minhash", func(d *ProjectDigest) { d.Minhash = TableDigest{} }},
	} {
		cold := full()
		tc.drop(&cold)
		err := Verify(full(), cold)
		if err == nil {
			t.Errorf("%s: a dropped table verified — the table is missing from Verify's loop", tc.name)
			continue
		}
		if !errors.Is(err, ErrDigestMismatch) {
			t.Errorf("%s: error %v does not wrap ErrDigestMismatch", tc.name, err)
		}
		if !strings.Contains(err.Error(), tc.name) {
			t.Errorf("%s: error %q does not name the offending table", tc.name, err)
		}
	}
}

// TestVerifyDetectsSameCountDifferentContent is the case a naive "count the
// rows" verification misses entirely: the right NUMBER of rows, the wrong
// rows. A corrupted or partially written copy is far more likely to look like
// this than to lose whole rows.
func TestVerifyDetectsSameCountDifferentContent(t *testing.T) {
	t.Parallel()
	var hot, cold ProjectDigest
	hot.Nodes.Add(FileRow{ID: 1, Path: "/a"}.Digest())
	cold.Nodes.Add(FileRow{ID: 1, Path: "/b"}.Digest())
	err := Verify(hot, cold)
	if err == nil {
		t.Fatal("same row count with different content verified — the checksum half of the digest is not load-bearing")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("error %q should identify the checksum as the mismatch", err)
	}
}

// TestTeeSinkDigestsWhatItForwards pins that the tee reports the digest of the
// rows it passed on — the hot-side fingerprint the mover compares against.
func TestTeeSinkDigestsWhatItForwards(t *testing.T) {
	t.Parallel()
	rec := &recordingSink{}
	tee := NewTeeSink(rec)
	ctx := context.Background()
	rows := []FileRow{sampleFile()}
	if err := tee.WriteFiles(ctx, rows); err != nil {
		t.Fatalf("WriteFiles: %v", err)
	}
	if len(rec.files) != 1 {
		t.Fatalf("tee forwarded %d file rows, want 1", len(rec.files))
	}
	got := tee.Digest()
	if got.Files.Rows != 1 || got.Files.Sum != rows[0].Digest() {
		t.Fatalf("tee digest = %+v, want the forwarded row's digest", got.Files)
	}
	if got.TotalRows() != 1 {
		t.Fatalf("TotalRows = %d, want 1", got.TotalRows())
	}
	if got.Empty() {
		t.Fatal("a digest with rows reported Empty")
	}
}

// TestTeeSinkPropagatesPrimaryError pins that a failed archive write is not
// masked by the digest bookkeeping succeeding.
func TestTeeSinkPropagatesPrimaryError(t *testing.T) {
	t.Parallel()
	boom := errors.New("cold write failed")
	tee := NewTeeSink(&recordingSink{fail: boom})
	if err := tee.WriteNodes(context.Background(), []NodeRow{{ID: 1}}); !errors.Is(err, boom) {
		t.Fatalf("WriteNodes error = %v, want the primary sink's error", err)
	}
}

type recordingSink struct {
	files []FileRow
	fail  error
}

func (s *recordingSink) WriteFiles(_ context.Context, rows []FileRow) error {
	if s.fail != nil {
		return s.fail
	}
	s.files = append(s.files, rows...)
	return nil
}
func (s *recordingSink) WriteNodes(context.Context, []NodeRow) error           { return s.fail }
func (s *recordingSink) WriteEdges(context.Context, []EdgeRow) error           { return s.fail }
func (s *recordingSink) WriteSites(context.Context, []SiteRow) error           { return s.fail }
func (s *recordingSink) WriteEmbeddings(context.Context, []EmbeddingRow) error { return s.fail }
func (s *recordingSink) WriteMinhash(context.Context, []MinhashRow) error      { return s.fail }
