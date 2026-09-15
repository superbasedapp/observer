package zed

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter parses Zed's native-agent threads.db store. See doc.go for
// the store layout, JSON shape, and off-limits files.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with the default scrubber and platform-default
// watch roots.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: defaultRoots()}
}

// NewWithOptions customizes the scrubber and/or watch roots for tests. A
// nil scrubber falls back to scrub.New(); no roots falls back to the
// platform defaults.
func NewWithOptions(s *scrub.Scrubber, roots ...string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = defaultRoots()
	}
	return &Adapter{scrubber: s, roots: roots}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolZed }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter: threads.db (and its -wal /
// -shm siblings — the live conversation usually lives almost entirely
// in the WAL) under a watch root.
func (a *Adapter) IsSessionFile(path string) bool {
	base := strings.ToLower(strings.ReplaceAll(pathBase(path), `\`, "/"))
	switch base {
	case dbName, dbName + "-wal", dbName + "-shm":
	default:
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// pathBase returns the final path segment without pulling in
// path/filepath's OS-specific separator handling (both `/` and `\`
// occur in test fixtures across platforms).
func pathBase(path string) string {
	p := strings.ReplaceAll(path, `\`, "/")
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// ParseSessionFile implements adapter.Adapter. threads.db is a
// watermark store (see doc.go): NewOffset is the latest UnixNano
// `updated_at` seen across every row, and every thread whose
// `updated_at` is at or after fromOffset is re-read and re-emitted
// WHOLE — deterministic SourceEventIDs make the re-emission of an
// already-seen row a store-level no-op.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	dbPath := mainDBPath(path)
	db, err := openDB(dbPath)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("zed.ParseSessionFile: open: %w", err)
	}
	defer db.Close()

	rows, latest, err := scanWatermarks(ctx, db)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("zed.ParseSessionFile: watermark: %w", err)
	}
	res := adapter.ParseResult{NewOffset: latest}
	if latest <= fromOffset {
		return res, nil
	}

	dec, err := zstd.NewReader(nil)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("zed.ParseSessionFile: new zstd reader: %w", err)
	}
	defer dec.Close()

	// minRetryNS tracks the earliest touched-thread watermark that failed
	// to decode (a mid-write read). Threads.db holds MANY sessions behind
	// one watermark, so one bad row must not block the cursor from
	// advancing past every OTHER thread's progress — but it also must not
	// advance PAST the failing thread's own timestamp, or it would never
	// be retried. Capping NewOffset at minRetryNS-1 (combined with the
	// watcher's documented MAX-semantics cursor write on RetrySuggested)
	// achieves both: unrelated threads' progress is kept, and the failing
	// thread's `updated_at >= cursor` test still matches next poll.
	minRetryNS := int64(-1)

	for _, tr := range rows {
		if tr.UpdatedAtNS < fromOffset {
			continue
		}
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if tr.DataType != "zstd" {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("zed: thread %s: unsupported data_type %q, skipped", tr.ID, tr.DataType))
			continue
		}
		blob, err := loadThreadData(ctx, db, tr.ID)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("zed: thread %s: load data: %v", tr.ID, err))
			if minRetryNS < 0 || tr.UpdatedAtNS < minRetryNS {
				minRetryNS = tr.UpdatedAtNS
			}
			res.RetrySuggested = true
			continue
		}
		plain, err := dec.DecodeAll(blob, nil)
		if err != nil {
			// A thread mid-write can be read with a truncated/corrupt
			// zstd frame; ask the watcher to retry rather than dropping
			// it (the deepseek precedent).
			res.Warnings = append(res.Warnings, fmt.Sprintf("zed: thread %s: zstd decode (retrying): %v", tr.ID, err))
			if minRetryNS < 0 || tr.UpdatedAtNS < minRetryNS {
				minRetryNS = tr.UpdatedAtNS
			}
			res.RetrySuggested = true
			continue
		}
		var data zedThreadData
		if err := json.Unmarshal(plain, &data); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("zed: thread %s: json decode: %v", tr.ID, err))
			continue
		}
		a.emitThread(&res, dbPath, tr, data)
	}
	if minRetryNS >= 0 && minRetryNS-1 < res.NewOffset {
		res.NewOffset = minRetryNS - 1
	}
	return res, nil
}
