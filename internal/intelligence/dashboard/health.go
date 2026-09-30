package dashboard

import (
	"context"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

// suspectedMisroutedMinBytes is the file-size threshold below which a
// cursor-at-EOF-with-zero-actions row is NOT flagged as suspected
// misrouted. Stub session files (created but never written to)
// legitimately have zero events; only files with enough content that
// some adapter SHOULD have emitted rows are worth surfacing. 1 KB is
// well below any real Codex rollout (a single token_count line is
// ~400 bytes) and well above the empty-stub case.
const suspectedMisroutedMinBytes int64 = 1024

// watcherHealthStatWorkers bounds the concurrent os.Stat fan-out in
// handleWatcherHealth. parse_cursors routinely holds thousands of
// rows, a third of which live on /mnt/c DrvFs where a single stat
// costs ~14 ms — serially that is a ~50 s request against a 60 s
// sidebar poll, i.e. near-saturation. The calls are independent and
// latency-bound, not CPU-bound, so a small fixed pool collapses the
// wall clock without thrashing the scheduler.
const watcherHealthStatWorkers = 32

// watcherHealthMaxFiles caps how many per-file rows the response
// carries. Every consumer of this endpoint reads either the rollup
// counts (the dashboard sidebar) or the single worst-lagging row (the
// VS Code watcher-lag notifier), and rows are sorted worst-first — so
// a cap preserves both answers exactly while keeping the payload from
// growing without bound (the uncapped response measured 974 KB).
// Counts are ALWAYS computed over every row, never over the cap.
const watcherHealthMaxFiles = 50

// CursorSemantics tells /api/health/watcher how to interpret one
// parse_cursors row. It is the dashboard-side mirror of
// adapter.FileCursorSemantics, resolved to plain capability flags at
// the wiring boundary (CLAUDE.md module rules #2 and #3) so this
// package never learns adapter types or tool names.
//
// The zero value is NOT a valid default — use byteOffsetSemantics,
// which reproduces the historical assumption that every tracked file
// is an append-only text log tailed by byte offset.
type CursorSemantics struct {
	// Kind is a stable machine-readable tag ("byte_offset",
	// "watermark", "encrypted", "no_actions") surfaced on the wire.
	Kind string
	// LagMeaningful reports whether `file_size - byte_offset` is a
	// real ingest lag. False when the saved cursor is a watermark (a
	// SQLite row id, a Unix-millis timestamp) rather than a byte
	// count — comparing those to a file size is a category error that
	// pins the row "behind" forever.
	LagMeaningful bool
	// ActionsExpected reports whether a non-trivial file of this shape
	// SHOULD have produced at least one action row. False for
	// watermark-scanned stores, undecodable (encrypted) stores, and
	// token/correlation-only files.
	ActionsExpected bool
	// Reason is a short operator-facing explanation of why a signal is
	// suppressed. Surfaced verbatim; may be empty.
	Reason string
}

// byteOffsetSemantics is the default applied when no adapter declares
// anything for a path (and when the wiring seam is absent entirely).
// It preserves the pre-capability behaviour byte for byte.
func byteOffsetSemantics() CursorSemantics {
	return CursorSemantics{Kind: "byte_offset", LagMeaningful: true, ActionsExpected: true}
}

// cursorSemanticsFor resolves the semantics of one parse_cursors path,
// falling back to byte-offset when the injection seam is unset (tests,
// embedders) or returns a zero-value Kind.
func (s *Server) cursorSemanticsFor(path string) CursorSemantics {
	if s.opts.CursorSemanticsFor == nil {
		return byteOffsetSemantics()
	}
	sem := s.opts.CursorSemanticsFor(path)
	if sem.Kind == "" {
		return byteOffsetSemantics()
	}
	return sem
}

// fileHealth is one parse_cursors row as it appears on the wire.
type fileHealth struct {
	Path        string `json:"path"`
	ByteOffset  int64  `json:"byte_offset"`
	FileSize    int64  `json:"file_size"`
	BehindBytes int64  `json:"behind_bytes"`
	LastParsed  string `json:"last_parsed"`
	// CursorKind classifies what ByteOffset actually means for this
	// file. Always present so the payload never implies byte
	// semantics it doesn't have.
	CursorKind         string `json:"cursor_kind"`
	BehindSeconds      int64  `json:"behind_seconds,omitempty"`
	Missing            bool   `json:"missing,omitempty"`
	OrphanUnmatched    bool   `json:"orphan_unmatched,omitempty"`
	SuspectedMisrouted bool   `json:"suspected_misrouted,omitempty"`
	MisrouteReason     string `json:"misroute_reason,omitempty"`
	// LagNotApplicable marks a row whose file has grown past the saved
	// cursor value, but where that comparison is meaningless because
	// the cursor is a watermark, not a byte offset. Surfaced (like
	// orphan_unmatched) but excluded from behind_count /
	// behind_total_bytes.
	LagNotApplicable bool `json:"lag_not_applicable,omitempty"`
	// ZeroActionsExpected marks a row that matches the misroute
	// fingerprint (cursor at EOF, non-trivial file, zero actions) but
	// where zero actions is the DESIGNED outcome — an encrypted store,
	// a token-only log, or a sidecar whose events land on a sibling
	// file. Surfaced, but excluded from suspected_misrouted_count.
	ZeroActionsExpected bool `json:"zero_actions_expected,omitempty"`
	// ExcludedReason explains a LagNotApplicable / ZeroActionsExpected
	// suppression in the adapter's own words.
	ExcludedReason string `json:"excluded_reason,omitempty"`
	ActionCount    int64  `json:"action_count,omitempty"`
}

// handleWatcherHealth serves /api/health/watcher — surfaces every
// session file the watcher knows about (one row in parse_cursors per
// file), the saved cursor, the current file size on disk, and how far
// behind the watcher is. Lets the dashboard render a "data is being
// dropped" banner when the watcher silently falls behind a session
// file (typical failure mode: fsnotify event drops on a busy session,
// or a daemon restart that lost in-flight state).
//
// The threshold for "behind" is non-zero — even a few bytes mean a
// JSONL line was appended to disk that the watcher hasn't ingested
// yet. The UI ranks the worst offenders by `behind_bytes` so the
// recovery prompt fires once the gap looks concerning (>10 KB, say —
// thresholding lives in the JS).
//
// v1.4.51 added the `suspected_misrouted` signal: parse_cursors rows
// whose cursor reached EOF on a non-trivial file BUT the actions
// table has zero rows for that source_file. That's the fingerprint
// the pre-v1.4.51 adapter-misrouting bug class produced — claude-code
// silently "parsed" Codex rollout-*.jsonl files (every JSON line
// unmarshalled cleanly so the cursor advanced to EOF) but none of
// the Codex-schema fields matched claude-code handlers, so zero
// actions landed. Surface these so the operator can run
// `observer scan --force --adapter <name>` to recover.
//
// BOTH of those signals assume the saved cursor is a byte offset into
// an append-only text file. For roughly half the adapter fleet it
// isn't: SQLite-backed adapters persist a watermark (a row id, a
// Unix-millis `updated_at`, a `MAX(time_updated)`) in the same
// column. Comparing a watermark to a file size mis-fires in BOTH
// directions — a small row-id watermark pins a multi-megabyte store
// "behind" forever (measured: 16.5 days), while a Unix-millis
// watermark dwarfs the file size and pins it "at EOF with zero
// actions", i.e. permanently misrouted. Adapters that decrypt-gate a
// store (Antigravity's OSCrypt `.pb`) or read a file for tokens only
// (Grok's `unified.jsonl`) produce the same unclosable fingerprint.
//
// So the row's semantics are resolved through Options.CursorSemanticsFor
// and the two signals are gated on capability flags — never on a tool
// name (CLAUDE.md module rule #3). Suppressed rows stay visible in
// `files` with `cursor_kind` + `excluded_reason`, exactly like
// `orphan_unmatched`: the recovery flow can't close them, so counting
// them would make the banner permanent.
func (s *Server) handleWatcherHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	var (
		out map[string]any
		err error
	)
	if s.opts.ReadCaches {
		out, err = s.watcherHealthCached(r.Context())
	} else {
		out, err = s.computeWatcherHealth(r.Context())
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, out)
}

// computeWatcherHealth builds the /api/health/watcher payload: one query
// over parse_cursors plus a bounded-parallel stat of every tracked file.
// The stat fan-out is the expensive half (thousands of files, a third of
// them on a DrvFs mount); see watcher_health_cache.go for how the
// production handler avoids paying it on the request path.
func (s *Server) computeWatcherHealth(ctx context.Context) (map[string]any, error) {
	// LEFT JOIN against actions so a single query returns both the
	// cursor state AND the per-file action count needed for the
	// suspected_misrouted heuristic. parse_cursors is small (one row
	// per known session file) so the JOIN is cheap.
	// s.opts.DB, not s.db(): watcher health describes the live
	// watcher's real cursors even while demo mode is active (P6.7).
	rows, err := s.opts.DB.QueryContext(ctx,
		`SELECT pc.source_file, pc.byte_offset, pc.last_parsed,
		        COALESCE(COUNT(a.id), 0) AS action_count
		   FROM parse_cursors pc
		   LEFT JOIN actions a ON a.source_file = pc.source_file
		  GROUP BY pc.source_file, pc.byte_offset, pc.last_parsed`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type cursorRow struct {
		path        string
		lastParsed  string
		offset      int64
		actionCount int64
	}
	cursors := []cursorRow{}
	for rows.Next() {
		var cr cursorRow
		if err := rows.Scan(&cr.path, &cr.offset, &cr.lastParsed, &cr.actionCount); err != nil {
			return nil, err
		}
		cursors = append(cursors, cr)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Bounded-parallel stat. Independent, latency-bound calls (a third
	// of them cross a DrvFs mount) — results are written into a
	// pre-sized slice by index, so ordering stays deterministic and
	// identical to the serial version.
	sizes := make([]int64, len(cursors))
	statErrs := make([]bool, len(cursors))
	statAll(len(cursors), func(i int) string { return cursors[i].path }, sizes, statErrs)

	out := make([]fileHealth, 0, len(cursors))
	var totalBehind int64
	orphanCount := 0
	suspectedMisroutedCount := 0
	lagNotApplicableCount := 0
	zeroActionsExpectedCount := 0
	now := time.Now().UTC()
	for i, cr := range cursors {
		sem := s.cursorSemanticsFor(cr.path)
		f := fileHealth{
			Path:        cr.path,
			ByteOffset:  cr.offset,
			LastParsed:  cr.lastParsed,
			CursorKind:  sem.Kind,
			ActionCount: cr.actionCount,
		}
		// orphan_unmatched: parse_cursors row exists but no currently
		// registered adapter's IsSessionFile claims this path. Almost
		// always means an older adapter version once tracked it and
		// has since tightened its filter (e.g. the v1.4.20 copilot
		// adapter narrowed from "any *.log under copilot-chat" to
		// "main.jsonl under debug-logs"). Surface the row but DON'T
		// count it as "behind" — the recovery flow can't process
		// these so the banner would never close.
		if s.opts.RecognizesSessionFile != nil && !s.opts.RecognizesSessionFile(cr.path) {
			f.OrphanUnmatched = true
			orphanCount++
			if !statErrs[i] {
				f.FileSize = sizes[i]
			} else {
				f.Missing = true
			}
			out = append(out, f)
			continue
		}
		if statErrs[i] {
			// File on disk gone (e.g. user deleted a session). Surface
			// it so the user can clean up parse_cursors, but don't
			// count it as "behind" — there's nothing to recover.
			f.Missing = true
			out = append(out, f)
			continue
		}
		f.FileSize = sizes[i]
		grown := f.FileSize > f.ByteOffset
		if grown && sem.LagMeaningful {
			f.BehindBytes = f.FileSize - f.ByteOffset
			totalBehind += f.BehindBytes
			if t, parseErr := time.Parse(time.RFC3339Nano, cr.lastParsed); parseErr == nil {
				f.BehindSeconds = int64(now.Sub(t).Seconds())
			}
		} else if grown {
			// The cursor is a watermark; "file_size - cursor" is not a
			// byte gap and can never close. Report it as excluded
			// rather than silently dropping the row.
			f.LagNotApplicable = true
			f.ExcludedReason = sem.Reason
			lagNotApplicableCount++
		}
		// suspected_misrouted: cursor at EOF on a non-trivial file but
		// zero actions emitted. The pre-v1.4.51 fingerprint — surface
		// for operator-driven recovery via
		// `observer scan --force --adapter <name>`. Only meaningful
		// where the adapter actually parses this file into actions.
		if f.BehindBytes == 0 && !f.LagNotApplicable &&
			f.FileSize >= suspectedMisroutedMinBytes && cr.actionCount == 0 {
			if sem.ActionsExpected {
				f.SuspectedMisrouted = true
				f.MisrouteReason = "cursor at EOF on non-trivial file but 0 actions emitted; likely a v1.4.51 adapter misroute — run `observer scan --force --adapter <name>` to recover"
				suspectedMisroutedCount++
			} else {
				f.ZeroActionsExpected = true
				if f.ExcludedReason == "" {
					f.ExcludedReason = sem.Reason
				}
				zeroActionsExpectedCount++
			}
		}
		if (f.LagNotApplicable || f.ZeroActionsExpected) && f.ExcludedReason == "" {
			f.ExcludedReason = "this file's parse cursor is not a byte offset into an append-only log"
		}
		out = append(out, f)
	}

	// Surface the worst offenders first so the UI's "click to recover"
	// banner can show the top-N that matter. Behind-bytes is the
	// primary sort key; ties broken by suspected-misrouted so the
	// pre-v1.4.51 fingerprint floats up among caught-up rows, then by
	// the structurally-excluded rows so a truncated payload still
	// carries examples of each suppression.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].BehindBytes != out[j].BehindBytes {
			return out[i].BehindBytes > out[j].BehindBytes
		}
		if out[i].SuspectedMisrouted != out[j].SuspectedMisrouted {
			return out[i].SuspectedMisrouted
		}
		return excludedRank(out[i]) > excludedRank(out[j])
	})
	behindCount := 0
	for _, f := range out {
		if f.BehindBytes > 0 && !f.OrphanUnmatched {
			behindCount++
		}
	}

	// Counts above are computed over EVERY row; only the per-file
	// array is capped.
	totalFiles := len(out)
	truncated := false
	if totalFiles > watcherHealthMaxFiles {
		out = out[:watcherHealthMaxFiles]
		truncated = true
	}

	return map[string]any{
		"files":                       out,
		"total_files":                 totalFiles,
		"files_truncated":             truncated,
		"files_limit":                 watcherHealthMaxFiles,
		"behind_count":                behindCount,
		"behind_total_bytes":          totalBehind,
		"orphan_count":                orphanCount,
		"suspected_misrouted_count":   suspectedMisroutedCount,
		"lag_not_applicable_count":    lagNotApplicableCount,
		"zero_actions_expected_count": zeroActionsExpectedCount,
		"checked_at":                  now.Format(time.RFC3339),
	}, nil
}

// excludedRank orders the structurally-excluded rows below genuine
// signals but above ordinary caught-up rows, so a truncated `files`
// array still shows the operator why a count was suppressed.
func excludedRank(f fileHealth) int {
	switch {
	case f.LagNotApplicable:
		return 2
	case f.ZeroActionsExpected:
		return 1
	default:
		return 0
	}
}

// statAll runs os.Stat over n paths in parallel, writing each result
// to sizes[i] / statErrs[i]. Slice-by-index writes keep the output
// order identical to a serial pass; the pool bounds concurrency so a
// large parse_cursors table can't spawn thousands of blocked threads.
func statAll(n int, pathOf func(int) string, sizes []int64, statErrs []bool) {
	if n == 0 {
		return
	}
	workers := watcherHealthStatWorkers
	if workers > n {
		workers = n
	}
	idx := make(chan int, n)
	for i := 0; i < n; i++ {
		idx <- i
	}
	close(idx)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range idx {
				st, err := os.Stat(pathOf(i))
				if err != nil {
					statErrs[i] = true
					continue
				}
				sizes[i] = st.Size()
			}
		}()
	}
	wg.Wait()
}
