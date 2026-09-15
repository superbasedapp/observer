package archive

import "context"

// DefaultBatchRows is the default number of rows one export callback carries.
// Small enough that a huge project never materializes wholesale in memory,
// large enough that the per-callback overhead is noise.
const DefaultBatchRows = 512

// FileRow mirrors one codeintel_files row. ID is the HOT rowid and is
// preserved verbatim through the archive so a rehydrate can restore the exact
// id every codeintel_nodes/edges/sites row references — a re-numbered restore
// would silently orphan the graph.
type FileRow struct {
	ID          int64
	Project     string
	Path        string
	Lang        string
	ContentHash string
	Mtime       int64
	IndexedAt   int64
	Parser      string
	Status      string
}

// Digest is the row's contribution to a [TableDigest].
func (r FileRow) Digest() uint64 {
	var w fieldWriter
	return w.i(r.ID).s(r.Project).s(r.Path).s(r.Lang).s(r.ContentHash).
		i(r.Mtime).i(r.IndexedAt).s(r.Parser).s(r.Status).sum()
}

// NodeRow mirrors one codeintel_nodes row (a symbol declaration: name, span,
// and the bounded signature excerpt — never a body).
type NodeRow struct {
	ID        int64
	Project   string
	FileID    int64
	Kind      string
	Name      string
	FQN       string
	Lang      string
	StartLine int64
	EndLine   int64
	StartByte int64
	EndByte   int64
	Signature string
	SigHash   string
}

// Digest is the row's contribution to a [TableDigest].
func (r NodeRow) Digest() uint64 {
	var w fieldWriter
	return w.i(r.ID).s(r.Project).i(r.FileID).s(r.Kind).s(r.Name).s(r.FQN).s(r.Lang).
		i(r.StartLine).i(r.EndLine).i(r.StartByte).i(r.EndByte).s(r.Signature).s(r.SigHash).sum()
}

// EdgeRow mirrors one codeintel_edges row (a CALLS/IMPORTS relationship).
type EdgeRow struct {
	ID              int64
	Project         string
	FileID          int64
	SrcID           int64
	DstID           int64
	Kind            string
	Confidence      float64
	ResolverBackend string
}

// Digest is the row's contribution to a [TableDigest].
func (r EdgeRow) Digest() uint64 {
	var w fieldWriter
	return w.i(r.ID).s(r.Project).i(r.FileID).i(r.SrcID).i(r.DstID).s(r.Kind).
		f(r.Confidence).s(r.ResolverBackend).sum()
}

// SiteRow mirrors one codeintel_sites row (the raw call/import site behind an
// edge, plus the migration-053 recv_type inference).
type SiteRow struct {
	ID              int64
	Project         string
	EdgeID          int64
	FileID          int64
	StartLine       int64
	StartByte       int64
	RawText         string
	TargetName      string
	ResolverBackend string
	Confidence      float64
	RecvType        string
}

// Digest is the row's contribution to a [TableDigest].
func (r SiteRow) Digest() uint64 {
	var w fieldWriter
	return w.i(r.ID).s(r.Project).i(r.EdgeID).i(r.FileID).i(r.StartLine).i(r.StartByte).
		s(r.RawText).s(r.TargetName).s(r.ResolverBackend).f(r.Confidence).s(r.RecvType).sum()
}

// EmbeddingRow mirrors one codeintel_embeddings row (a packed feature-hashed
// TF vector keyed by node id).
type EmbeddingRow struct {
	NodeID  int64
	Project string
	Dim     int64
	Vec     []byte
}

// Digest is the row's contribution to a [TableDigest]. The vector BLOB is
// hashed in full — a truncated copy must not verify.
func (r EmbeddingRow) Digest() uint64 {
	var w fieldWriter
	return w.i(r.NodeID).s(r.Project).i(r.Dim).b(r.Vec).sum()
}

// MinhashRow mirrors one codeintel_minhash row (one LSH band hash for a node).
type MinhashRow struct {
	NodeID  int64
	Project string
	Band    int64
	Hash    int64
}

// Digest is the row's contribution to a [TableDigest].
func (r MinhashRow) Digest() uint64 {
	var w fieldWriter
	return w.i(r.NodeID).s(r.Project).i(r.Band).i(r.Hash).sum()
}

// ProjectSink receives one archived project's rows in batches. It is the ONE
// seam the hot-side exporter writes through: internal/store streams hot rows
// into a sink, and internal/archivestore implements the sink over the archive
// file. Neither side sees the other's SQL or schema types.
//
// Batches arrive parent-first (files, then nodes, then everything that
// references them), so an implementation may rely on referential order even
// though the archive schema deliberately declares no foreign keys.
type ProjectSink interface {
	WriteFiles(ctx context.Context, rows []FileRow) error
	WriteNodes(ctx context.Context, rows []NodeRow) error
	WriteEdges(ctx context.Context, rows []EdgeRow) error
	WriteSites(ctx context.Context, rows []SiteRow) error
	WriteEmbeddings(ctx context.Context, rows []EmbeddingRow) error
	WriteMinhash(ctx context.Context, rows []MinhashRow) error
}

// digestSink is a ProjectSink that only accumulates a [ProjectDigest]. It lets
// the hot-side exporter be reused verbatim to compute the hot digest, so the
// two sides of the comparison are produced by the SAME row-reading code —
// a digest computed by a second, parallel query would verify that query, not
// the data.
type digestSink struct{ d ProjectDigest }

// NewDigestSink returns a [ProjectSink] that writes nothing and records a
// [ProjectDigest] of everything streamed through it, readable via Digest.
func NewDigestSink() interface {
	ProjectSink
	Digest() ProjectDigest
} {
	return &digestSink{}
}

func (s *digestSink) Digest() ProjectDigest { return s.d }

func (s *digestSink) WriteFiles(_ context.Context, rows []FileRow) error {
	for _, r := range rows {
		s.d.Files.Add(r.Digest())
	}
	return nil
}

func (s *digestSink) WriteNodes(_ context.Context, rows []NodeRow) error {
	for _, r := range rows {
		s.d.Nodes.Add(r.Digest())
	}
	return nil
}

func (s *digestSink) WriteEdges(_ context.Context, rows []EdgeRow) error {
	for _, r := range rows {
		s.d.Edges.Add(r.Digest())
	}
	return nil
}

func (s *digestSink) WriteSites(_ context.Context, rows []SiteRow) error {
	for _, r := range rows {
		s.d.Sites.Add(r.Digest())
	}
	return nil
}

func (s *digestSink) WriteEmbeddings(_ context.Context, rows []EmbeddingRow) error {
	for _, r := range rows {
		s.d.Embeddings.Add(r.Digest())
	}
	return nil
}

func (s *digestSink) WriteMinhash(_ context.Context, rows []MinhashRow) error {
	for _, r := range rows {
		s.d.Minhash.Add(r.Digest())
	}
	return nil
}

// teeSink fans one export into two sinks, so a single pass over the hot rows
// both writes the archive copy AND accumulates the hot digest. Reading the hot
// tables twice would leave a window in which a concurrent writer makes the two
// reads disagree for reasons that have nothing to do with copy fidelity.
//
// Every method DIGESTS FIRST, then forwards. A batch carries a slice, and the
// primary sink is free to touch it — a writer that normalized or reused a value
// in place would otherwise have its edit folded into the "hot" digest, which
// would then match the cold copy of that same edit and verify a corruption into
// existence. Fingerprinting before the batch is handed on pins the digest to
// what the exporter read out of the hot table.
type teeSink struct {
	primary ProjectSink
	digest  *digestSink
}

// NewTeeSink returns a [ProjectSink] that forwards every batch to primary and
// simultaneously accumulates a [ProjectDigest] of it. Digest reports the
// digest of everything forwarded so far.
func NewTeeSink(primary ProjectSink) interface {
	ProjectSink
	Digest() ProjectDigest
} {
	return &teeSink{primary: primary, digest: &digestSink{}}
}

func (s *teeSink) Digest() ProjectDigest { return s.digest.d }

func (s *teeSink) WriteFiles(ctx context.Context, rows []FileRow) error {
	if err := s.digest.WriteFiles(ctx, rows); err != nil {
		return err
	}
	return s.primary.WriteFiles(ctx, rows)
}

func (s *teeSink) WriteNodes(ctx context.Context, rows []NodeRow) error {
	if err := s.digest.WriteNodes(ctx, rows); err != nil {
		return err
	}
	return s.primary.WriteNodes(ctx, rows)
}

func (s *teeSink) WriteEdges(ctx context.Context, rows []EdgeRow) error {
	if err := s.digest.WriteEdges(ctx, rows); err != nil {
		return err
	}
	return s.primary.WriteEdges(ctx, rows)
}

func (s *teeSink) WriteSites(ctx context.Context, rows []SiteRow) error {
	if err := s.digest.WriteSites(ctx, rows); err != nil {
		return err
	}
	return s.primary.WriteSites(ctx, rows)
}

func (s *teeSink) WriteEmbeddings(ctx context.Context, rows []EmbeddingRow) error {
	if err := s.digest.WriteEmbeddings(ctx, rows); err != nil {
		return err
	}
	return s.primary.WriteEmbeddings(ctx, rows)
}

func (s *teeSink) WriteMinhash(ctx context.Context, rows []MinhashRow) error {
	if err := s.digest.WriteMinhash(ctx, rows); err != nil {
		return err
	}
	return s.primary.WriteMinhash(ctx, rows)
}
