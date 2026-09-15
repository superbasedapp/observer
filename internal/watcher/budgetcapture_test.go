package watcher

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/opencode"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

type budgetFakeMode uint8

const (
	budgetFakeClean budgetFakeMode = iota
	budgetFakeWarning
	budgetFakeRetry
	budgetFakeError
	budgetFakePanic
	budgetFakeEmpty
)

type budgetFakeAdapter struct {
	name        string
	root        string
	suffix      string
	mode        budgetFakeMode
	lastOffset  int64
	parseCalls  int
	mutate      func(string) error
	mutateEvery bool
}

func (a *budgetFakeAdapter) Name() string { return a.name }

func (a *budgetFakeAdapter) WatchPaths() []string { return []string{a.root} }

func (a *budgetFakeAdapter) IsSessionFile(path string) bool {
	suffix := a.suffix
	if suffix == "" {
		suffix = ".session"
	}
	return strings.HasSuffix(path, suffix) ||
		strings.HasSuffix(path, suffix+"-wal") ||
		strings.HasSuffix(path, suffix+"-shm")
}

func (a *budgetFakeAdapter) ParseSessionFile(_ context.Context, path string, offset int64) (adapter.ParseResult, error) {
	a.lastOffset = offset
	a.parseCalls++
	data, err := os.ReadFile(path)
	if err != nil {
		return adapter.ParseResult{}, err
	}
	if a.mutate != nil {
		mutate := a.mutate
		if !a.mutateEvery {
			a.mutate = nil
		}
		if err := mutate(path); err != nil {
			return adapter.ParseResult{}, err
		}
	}
	switch a.mode {
	case budgetFakeWarning:
		return adapter.ParseResult{NewOffset: int64(len(data)), Warnings: []string{"partial source"}}, nil
	case budgetFakeRetry:
		return adapter.ParseResult{NewOffset: int64(len(data)), RetrySuggested: true}, nil
	case budgetFakeError:
		return adapter.ParseResult{}, errors.New("fake parse failed")
	case budgetFakePanic:
		panic("fake parser panic")
	case budgetFakeEmpty:
		return adapter.ParseResult{}, nil
	default:
		return adapter.ParseResult{
			NewOffset: int64(len(data)),
			TokenEvents: []models.TokenEvent{{
				SourceFile: path, SourceEventID: "fake-token", SessionID: "fake-session",
				ProjectRoot: filepath.Dir(a.root), Timestamp: time.Now().UTC(), Tool: a.name,
				Model: "fake-model", InputTokens: 1, OutputTokens: 1, Source: "jsonl",
			}},
		}, nil
	}
}

type budgetFakeWatermarkAdapter struct{ *budgetFakeAdapter }

func (a *budgetFakeWatermarkAdapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !a.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	return adapter.FileCursorSemantics{
		Kind:   adapter.CursorWatermark,
		Detail: "test SQLite source uses a row watermark",
	}
}

type budgetDynamicRootAdapter struct {
	*budgetFakeAdapter
	paths func() []string
}

func (a *budgetDynamicRootAdapter) WatchPaths() []string { return a.paths() }

type budgetInvalidTokenAdapter struct {
	*budgetFakeAdapter
	field string
}

func (a *budgetInvalidTokenAdapter) ParseSessionFile(ctx context.Context, path string, offset int64) (adapter.ParseResult, error) {
	res, err := a.budgetFakeAdapter.ParseSessionFile(ctx, path, offset)
	if err != nil || len(res.TokenEvents) == 0 {
		return res, err
	}
	switch a.field {
	case "session":
		res.TokenEvents[0].SessionID = ""
	case "model":
		res.TokenEvents[0].Model = ""
	case "timestamp":
		res.TokenEvents[0].Timestamp = time.Time{}
	}
	return res, nil
}

type budgetBlockingAdapter struct {
	adapter.Adapter
	started     chan struct{}
	release     chan struct{}
	startOnce   sync.Once
	releaseOnce sync.Once
}

func (a *budgetBlockingAdapter) Name() string { return a.Adapter.Name() }

func (a *budgetBlockingAdapter) WatchPaths() []string { return a.Adapter.WatchPaths() }

func (a *budgetBlockingAdapter) IsSessionFile(path string) bool {
	return a.Adapter.IsSessionFile(path)
}

func (a *budgetBlockingAdapter) ParseSessionFile(ctx context.Context, path string, offset int64) (adapter.ParseResult, error) {
	a.startOnce.Do(func() { close(a.started) })
	select {
	case <-a.release:
	case <-ctx.Done():
		return adapter.ParseResult{}, ctx.Err()
	}
	return a.Adapter.ParseSessionFile(ctx, path, offset)
}

func (a *budgetBlockingAdapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	declared, ok := a.Adapter.(adapter.CursorSemantics)
	if !ok {
		return adapter.FileCursorSemantics{}
	}
	return declared.CursorSemanticsFor(path)
}

func (a *budgetBlockingAdapter) releaseParser() {
	a.releaseOnce.Do(func() { close(a.release) })
}

func newBudgetCaptureTestWatcher(t testing.TB, opts Options, a adapter.Adapter) (*Watcher, *store.Store) {
	return newBudgetCaptureTestWatcherWithAdapters(t, opts, a)
}

func newBudgetCaptureTestWatcherWithAdapters(t testing.TB, opts Options, adapters ...adapter.Adapter) (*Watcher, *store.Store) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "watcher.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s := store.New(database)
	r := adapter.NewRegistry()
	for _, a := range adapters {
		r.Register(a)
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return New(s, r, opts), s
}

func writeBudgetSource(t *testing.T, root, body string) string {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "capture.session")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReconcileBudgetCaptureReadyRequiresStrictSourceEvidence(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := writeBudgetSource(t, root, "source")
	a := &budgetFakeAdapter{name: "fake", root: root}
	w, s := newBudgetCaptureTestWatcher(t, Options{}, a)
	if err := s.SetCursor(context.Background(), path, 2); err != nil {
		t.Fatal(err)
	}

	got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
	if !got.Ready || got.Reason != BudgetCaptureReasonReady {
		t.Fatalf("status = %+v, want ready", got)
	}
	if got.FilesSeen != 1 || got.FilesProcessed != 1 {
		t.Fatalf("file counts = seen %d processed %d", got.FilesSeen, got.FilesProcessed)
	}
	// The strict pass resumes at the ordinary cursor. Everything before it is
	// already ingested, and re-reading a whole corpus from byte zero on every
	// two-second control cycle cannot finish inside the pass deadline
	// (accounting-readiness correction, 2026-09-14).
	if a.lastOffset != 2 {
		t.Fatalf("strict catchup parser offset = %d, want a resume at the ordinary cursor", a.lastOffset)
	}
	// It still must not ADVANCE that cursor: strict ingest is usage-only, so
	// moving it would skip action and content capture for those bytes.
	if off, err := s.GetCursor(context.Background(), path); err != nil || off != 2 {
		t.Fatalf("cursor = %d, err=%v; strict catchup must leave ordinary cursor unchanged", off, err)
	}

	// A second pass over an unchanged file costs one stat, not a parse.
	calls := a.parseCalls
	again := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
	if !again.Ready || again.Reason != BudgetCaptureReasonReady {
		t.Fatalf("second pass = %+v, want ready", again)
	}
	if again.FilesSeen != 1 || again.FilesProcessed != 1 {
		t.Fatalf("second pass counts = seen %d processed %d", again.FilesSeen, again.FilesProcessed)
	}
	if a.parseCalls != calls {
		t.Fatalf("unchanged source was reparsed: %d calls, want %d", a.parseCalls, calls)
	}

	// A grown file is parsed again, from where the strict pass stopped rather
	// than from the ordinary cursor it must not move.
	if err := os.WriteFile(path, []byte("source-grown"), 0o600); err != nil {
		t.Fatal(err)
	}
	if grown := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]; !grown.Ready {
		t.Fatalf("grown source = %+v, want ready", grown)
	}
	if a.parseCalls != calls+1 {
		t.Fatalf("grown source was not reparsed: %d calls, want %d", a.parseCalls, calls+1)
	}
	if a.lastOffset != int64(len("source")) {
		t.Fatalf("grown source resumed at %d, want the strict memo position %d", a.lastOffset, len("source"))
	}
	if off, err := s.GetCursor(context.Background(), path); err != nil || off != 2 {
		t.Fatalf("cursor = %d, err=%v; strict catchup must still leave the ordinary cursor alone", off, err)
	}
}

func TestReconcileBudgetCaptureDoesNotTreatEmptySourceAsHealthy(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeBudgetSource(t, root, "")
	a := &budgetFakeAdapter{name: "fake", root: root, mode: budgetFakeEmpty}
	w, _ := newBudgetCaptureTestWatcher(t, Options{}, a)

	got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
	if got.Ready || got.Reason != BudgetCaptureReasonNoEvidence {
		t.Fatalf("status = %+v, want unavailable for empty source evidence", got)
	}
}

func TestReconcileBudgetCaptureClassifiesStrictFailures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		mode budgetFakeMode
		want string
	}{
		{name: "warning", mode: budgetFakeWarning, want: BudgetCaptureReasonWarnings},
		{name: "retry", mode: budgetFakeRetry, want: BudgetCaptureReasonRetrySuggested},
		{name: "parse error", mode: budgetFakeError, want: BudgetCaptureReasonParseError},
		{name: "panic", mode: budgetFakePanic, want: BudgetCaptureReasonParserPanic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeBudgetSource(t, root, "source")
			a := &budgetFakeAdapter{name: "fake", root: root, mode: tc.mode}
			w, s := newBudgetCaptureTestWatcher(t, Options{}, a)
			got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
			if got.Ready || got.Reason != tc.want {
				t.Fatalf("status = %+v, want unavailable reason %q", got, tc.want)
			}
			if tc.mode == budgetFakeWarning || tc.mode == budgetFakeRetry {
				// The strict pass may ingest idempotent output, but warnings and
				// retry hints must not advance the ordinary cursor.
				if off, err := s.GetCursor(context.Background(), filepath.Join(root, "capture.session")); err != nil || off != 0 {
					t.Fatalf("cursor = %d, err=%v; warning/retry must not advance it", off, err)
				}
			}
		})
	}
}

func TestReconcileBudgetCaptureReportsRegistryAndRootStates(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeBudgetSource(t, root, "source")
	a := &budgetFakeAdapter{name: "fake", root: root}
	w, _ := newBudgetCaptureTestWatcher(t, Options{Allow: []string{"other"}}, a)

	got := w.ReconcileBudgetCapture(context.Background(), []string{"missing", "fake"})
	if got["missing"].Reason != BudgetCaptureReasonUnknownAdapter {
		t.Fatalf("unknown status = %+v", got["missing"])
	}
	if got["fake"].Reason != BudgetCaptureReasonAllowFiltered {
		t.Fatalf("filtered status = %+v", got["fake"])
	}

	w, _ = newBudgetCaptureTestWatcher(t, Options{}, &budgetFakeAdapter{name: "missing-root", root: filepath.Join(t.TempDir(), "gone")})
	if got := w.ReconcileBudgetCapture(context.Background(), []string{"missing-root"})["missing-root"]; got.Reason != BudgetCaptureReasonMissingRoot {
		t.Fatalf("missing root status = %+v", got)
	}
}

func TestReconcileBudgetCaptureReportsCanceledScan(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeBudgetSource(t, root, "source")
	a := &budgetFakeAdapter{name: "fake", root: root}
	w, _ := newBudgetCaptureTestWatcher(t, Options{}, a)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got := w.ReconcileBudgetCapture(ctx, []string{"fake"})["fake"]
	if got.Ready || got.Reason != BudgetCaptureReasonCanceled || !got.Incomplete {
		t.Fatalf("status = %+v, want canceled incomplete", got)
	}
}

func TestReconcileBudgetCaptureReportsOversizeAndUnsafeSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	outsideFile := writeBudgetSource(t, outside, "outside")
	link := filepath.Join(root, "capture.session")
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	a := &budgetFakeAdapter{name: "fake", root: root}
	w, _ := newBudgetCaptureTestWatcher(t, Options{MaxFileBytes: 1}, a)
	got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
	if got.Ready || got.Reason != BudgetCaptureReasonUnsafeSymlink {
		t.Fatalf("unsafe symlink status = %+v", got)
	}

	_ = os.Remove(link)
	writeBudgetSource(t, root, "too-large")
	got = w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
	if got.Ready || got.Reason != BudgetCaptureReasonOversizeFile {
		t.Fatalf("oversize status = %+v", got)
	}
}

// TestReconcileBudgetCaptureClassIsTheWorstIssueNotTheChosenOne pins the
// separation of Reason from Class. chooseBudgetIssue ranks the STRUCTURAL
// reasons last, so before Class existed a source that this node can never read
// (an oversize file) was classified by whatever routine issue a live tool
// produced alongside it - scan_incomplete every pass it wrote a file, warnings
// every pass its parser grumbled - and reported itself as merely delayed, or
// even known. The operator still reads the broad reason; the decision answers
// for every issue.
func TestReconcileBudgetCaptureClassIsTheWorstIssueNotTheChosenOne(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		mode       budgetFakeMode
		mutate     func(string) error
		wantReason string
	}{
		{
			name: "oversize beside a mid-pass source appearing",
			mutate: func(path string) error {
				nested := filepath.Join(filepath.Dir(path), "new", "capture.session")
				if err := os.MkdirAll(filepath.Dir(nested), 0o700); err != nil {
					return err
				}
				return os.WriteFile(nested, []byte("new source"), 0o600)
			},
			wantReason: BudgetCaptureReasonIncomplete,
		},
		{
			name:       "oversize beside a parser warning",
			mode:       budgetFakeWarning,
			wantReason: BudgetCaptureReasonWarnings,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			// "big.session" sorts before "capture.session", so the walk meets
			// the structural issue first and the routine one second - the
			// order that used to mask it.
			if err := os.WriteFile(filepath.Join(root, "big.session"), []byte(strings.Repeat("x", 128)), 0o600); err != nil {
				t.Fatal(err)
			}
			writeBudgetSource(t, root, "source")
			a := &budgetFakeAdapter{name: "fake", root: root, mode: tc.mode, mutate: tc.mutate}
			w, _ := newBudgetCaptureTestWatcher(t, Options{MaxFileBytes: 32}, a)

			got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
			if got.Reason != tc.wantReason {
				t.Fatalf("status = %+v, want the routine reason %q for the operator", got, tc.wantReason)
			}
			if got.AccountingClass() != BudgetAccountingUnavailable {
				t.Fatalf("status = %+v, want the oversize source to decide the class", got)
			}
			if got.AccountingReady() || got.AccountingDelayed() {
				t.Fatalf("status = %+v, want an unreadable source to fail closed", got)
			}
		})
	}
}

// TestReconcileBudgetCaptureReportsUnreadableRoot pins the split of
// source_unreadable out of scan_incomplete. A tree that MOVED under the pass
// is a race a later pass resolves; a tree this node cannot read is not, and
// classing the two together let a permanently unreadable store present itself
// as a delayed tail forever.
func TestReconcileBudgetCaptureReportsUnreadableRoot(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}
	root := t.TempDir()
	writeBudgetSource(t, root, "source")
	if err := os.Chmod(root, 0o000); err != nil {
		t.Skipf("chmod unavailable: %v", err)
	}
	// Restore before TempDir cleanup, which must be able to walk it.
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	w, _ := newBudgetCaptureTestWatcher(t, Options{}, &budgetFakeAdapter{name: "fake", root: root})

	got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
	if got.Ready || got.Reason != BudgetCaptureReasonUnreadable {
		t.Fatalf("status = %+v, want source_unreadable", got)
	}
	if got.AccountingClass() != BudgetAccountingUnavailable || got.AccountingReady() {
		t.Fatalf("status = %+v, want an unreadable root to fail closed", got)
	}
}

// TestReconcileNodeBudgetCaptureReconcilesActiveToolsOnly pins the
// accounting-readiness correction (2026-09-14): the strict pass covers the
// tools whose processes are being decided, never every rooted adapter on the
// machine. Before it, an idle adapter's source tree was re-parsed on every
// two-second cycle and its health gated every governed process.
func TestReconcileNodeBudgetCaptureReconcilesActiveToolsOnly(t *testing.T) {
	t.Parallel()
	activeRoot := t.TempDir()
	idleRoot := t.TempDir()
	writeBudgetSource(t, activeRoot, "active")
	writeBudgetSource(t, idleRoot, "idle")
	active := &budgetFakeAdapter{name: "active", root: activeRoot}
	idle := &budgetFakeAdapter{name: "idle", root: idleRoot, mode: budgetFakeError}
	w, _ := newBudgetCaptureTestWatcherWithAdapters(t, Options{}, active, idle)

	got := w.ReconcileNodeBudgetCapture(context.Background(), []string{"active"})
	if !got.Ready || got.Reason != BudgetCaptureReasonReady {
		t.Fatalf("aggregate = %+v, want the active source alone to decide", got)
	}
	if _, ok := got.Sources["idle"]; ok {
		t.Fatalf("idle rooted source reconciled: %+v", got.Sources)
	}
	if idle.parseCalls != 0 {
		t.Fatalf("idle adapter parsed %d files; the active set must bound the pass", idle.parseCalls)
	}
	if got := w.ReconcileNodeBudgetCapture(context.Background(), nil); got.Ready ||
		got.Reason != BudgetCaptureReasonNoRequiredSources {
		t.Fatalf("empty active set = %+v, want no_required_sources", got)
	}
}

// TestReconcileNodeBudgetCaptureActiveMissingRootIsAccountingReady pins the
// catch-22 fix: a tool that has never written a store has produced no spend,
// which is measured zero for that tool. The strict Ready flag stays false
// because no catchup happened; the ACCOUNTING classification is what a budget
// decision consults.
func TestReconcileNodeBudgetCaptureActiveMissingRootIsAccountingReady(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing")
	w, _ := newBudgetCaptureTestWatcherWithAdapters(t, Options{}, &budgetFakeAdapter{name: "fresh", root: missing})

	got := w.ReconcileNodeBudgetCapture(context.Background(), []string{"fresh"})
	source, ok := got.Sources["fresh"]
	if !ok || source.Reason != BudgetCaptureReasonMissingRoot {
		t.Fatalf("active missing-root source = %+v, present=%v", source, ok)
	}
	if source.Ready {
		t.Fatalf("missing root claimed a completed strict catchup: %+v", source)
	}
	if !source.AccountingReady() {
		t.Fatalf("missing root is unknown spend: %+v", source)
	}
	if !got.Ready || got.Reason != BudgetCaptureReasonReady {
		t.Fatalf("aggregate = %+v, want accounting-ready", got)
	}
}

func TestReconcileNodeBudgetCaptureIncludesRootedAllowFilteredSource(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeBudgetSource(t, root, "filtered")
	a := &budgetFakeAdapter{name: "filtered", root: root}
	w, _ := newBudgetCaptureTestWatcher(t, Options{Allow: []string{"other"}}, a)

	got := w.ReconcileNodeBudgetCapture(context.Background(), []string{"filtered"})
	if got.Ready || got.Reason != BudgetCaptureReasonAllowFiltered {
		t.Fatalf("aggregate = %+v, want allow-filtered source unavailable", got)
	}
	status, ok := got.Sources["filtered"]
	if !ok || status.Reason != BudgetCaptureReasonAllowFiltered {
		t.Fatalf("filtered source = %+v, present=%v", status, ok)
	}
}

// TestReconcileNodeBudgetCaptureKeepsDelayedSourceAccountable pins the
// 2026-09-15 ruling: a parser failure against a source the governed tool is
// actively writing is a LATE tail, not unknown spend. The strict Ready flag
// stays false, the per-tool source reports itself delayed, and neither the
// source nor the aggregate stops being accountable - the measured total in the
// store decides. Aggregate gating on a STRUCTURAL source is still pinned by
// TestReconcileNodeBudgetCaptureIncludesRootedAllowFilteredSource.
func TestReconcileNodeBudgetCaptureKeepsDelayedSourceAccountable(t *testing.T) {
	t.Parallel()
	readyRoot := t.TempDir()
	failingRoot := t.TempDir()
	writeBudgetSource(t, readyRoot, "ready")
	writeBudgetSource(t, failingRoot, "failing")
	ready := &budgetFakeAdapter{name: "ready", root: readyRoot}
	failing := &budgetFakeAdapter{name: "failing", root: failingRoot, mode: budgetFakeError}
	w, _ := newBudgetCaptureTestWatcherWithAdapters(t, Options{}, ready, failing)
	activeTools := []string{"ready", "failing"}

	got := w.ReconcileNodeBudgetCapture(context.Background(), activeTools)
	if !got.Ready || got.Reason != BudgetCaptureReasonReady {
		t.Fatalf("aggregate = %+v, want a delayed tail not to block accounting", got)
	}
	if !got.Sources["ready"].Ready || !got.Sources["ready"].AccountingReady() {
		t.Fatalf("ready source = %+v, want ready", got.Sources["ready"])
	}
	if got.Sources["failing"].Ready {
		t.Fatalf("failing source claimed a completed strict catchup: %+v", got.Sources["failing"])
	}
	// The aggregate is a summary. Per-tool accounting is what a decision uses,
	// and a tool whose newest tail is late must stay decidable on its measured
	// total (ruling 2026-09-15).
	if !got.Sources["failing"].AccountingReady() || !got.Sources["failing"].AccountingDelayed() ||
		got.Sources["failing"].Reason != BudgetCaptureReasonParseError {
		t.Fatalf("failing source = %+v, want delayed parse_error", got.Sources["failing"])
	}

	failing.mode = budgetFakeClean
	got = w.ReconcileNodeBudgetCapture(context.Background(), activeTools)
	if !got.Ready || got.Reason != BudgetCaptureReasonReady {
		t.Fatalf("aggregate after repair = %+v, want ready", got)
	}
	if got.Sources["failing"].AccountingDelayed() {
		t.Fatalf("repaired source is still delayed: %+v", got.Sources["failing"])
	}
}

// TestReconcileNodeBudgetCaptureUsesSortedUnavailableSource pins that the
// aggregate reports the FIRST sorted structurally-unavailable source. Both
// fixtures are structural since the 2026-09-15 ruling: a delayed tail no
// longer makes a source unavailable, so it can no longer name the aggregate.
func TestReconcileNodeBudgetCaptureUsesSortedUnavailableSource(t *testing.T) {
	t.Parallel()
	firstRoot := t.TempDir()
	writeBudgetSource(t, firstRoot, "first")
	// "aaa" is registered but excluded by the allow list; "zzz" is registered
	// nowhere. Two different structural reasons, so the sorted choice is
	// observable.
	first := &budgetFakeAdapter{name: "aaa", root: firstRoot}
	w, _ := newBudgetCaptureTestWatcherWithAdapters(t, Options{Allow: []string{"other"}}, first)

	got := w.ReconcileNodeBudgetCapture(context.Background(), []string{"zzz", "aaa"})
	if got.Ready || got.Reason != BudgetCaptureReasonAllowFiltered {
		t.Fatalf("aggregate = %+v, want first sorted unavailable source reason", got)
	}
	if got.Sources["zzz"].Reason != BudgetCaptureReasonUnknownAdapter {
		t.Fatalf("later sorted source = %+v, want unknown_adapter", got.Sources["zzz"])
	}
}

func TestReconcileNodeBudgetCaptureIgnoresInactiveSourceAppearingDuringPass(t *testing.T) {
	t.Parallel()
	firstRoot := t.TempDir()
	secondRoot := filepath.Join(t.TempDir(), "late")
	firstPath := writeBudgetSource(t, firstRoot, "first")
	first := &budgetFakeAdapter{name: "first", root: firstRoot}
	second := &budgetFakeAdapter{name: "second", root: secondRoot}
	first.mutate = func(path string) error {
		if path != firstPath {
			return nil
		}
		if err := os.MkdirAll(secondRoot, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(secondRoot, "capture.session"), []byte("second"), 0o600)
	}
	w, _ := newBudgetCaptureTestWatcherWithAdapters(t, Options{}, first, second)

	got := w.ReconcileNodeBudgetCapture(context.Background(), []string{"first"})
	if !got.Ready || got.Reason != BudgetCaptureReasonReady {
		t.Fatalf("aggregate = %+v; an inactive tool's store appearing mid-pass is not this pass's business", got)
	}
	if !got.Sources["first"].Ready {
		t.Fatalf("first source = %+v, want its own ready status", got.Sources["first"])
	}
	if late, ok := got.Sources["second"]; ok {
		t.Fatalf("inactive source reconciled: %+v", late)
	}
}

// TestReconcileNodeBudgetCaptureRetainsIncompleteWhenSourceDisappearsDuringPass
// pins that a source tree that moves under the strict pass is reported as
// incomplete and retained. Since the 2026-09-15 ruling that is a DELAYED tail,
// not unknown spend: a running tool rewrites its own store constantly, so the
// measured total stands and the decision is taken on it.
func TestReconcileNodeBudgetCaptureRetainsIncompleteWhenSourceDisappearsDuringPass(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := writeBudgetSource(t, root, "source")
	a := &budgetFakeAdapter{name: "vanishing", root: root}
	a.mutate = func(gotPath string) error {
		if gotPath != path {
			return nil
		}
		return os.RemoveAll(root)
	}
	w, _ := newBudgetCaptureTestWatcherWithAdapters(t, Options{}, a)

	got := w.ReconcileNodeBudgetCapture(context.Background(), []string{"vanishing"})
	if !got.Ready || got.Reason != BudgetCaptureReasonReady {
		t.Fatalf("aggregate = %+v, want a delayed tail not to block accounting", got)
	}
	status, ok := got.Sources["vanishing"]
	if !ok || !status.Incomplete || status.Reason != BudgetCaptureReasonIncomplete {
		t.Fatalf("vanishing source = %+v, present=%v; want retained incomplete status", status, ok)
	}
	if status.Ready || !status.AccountingDelayed() {
		t.Fatalf("vanishing source = %+v, want strictly unready but accounting-delayed", status)
	}
}

func TestReconcileBudgetCaptureRejectsChangedSourceFile(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mutate func(string) error
	}{
		{
			name: "replaced",
			mutate: func(path string) error {
				tmp := path + ".replacement"
				if err := os.WriteFile(tmp, []byte("replacement"), 0o600); err != nil {
					return err
				}
				return os.Rename(tmp, path)
			},
		},
		{
			name:   "truncated",
			mutate: func(path string) error { return os.Truncate(path, 0) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeBudgetSource(t, root, "source that changes")
			a := &budgetFakeAdapter{name: "fake", root: root, mutate: tc.mutate}
			w, _ := newBudgetCaptureTestWatcher(t, Options{}, a)

			got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
			if got.Ready || got.Reason != BudgetCaptureReasonIncomplete || !got.Incomplete {
				t.Fatalf("status = %+v, want changed source to be incomplete", got)
			}
		})
	}
}

func TestReconcileBudgetCaptureRechecksEarlierFilesAfterAdapterPass(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	first := writeBudgetSource(t, root, "first source")
	second := filepath.Join(root, "later.session")
	if err := os.WriteFile(second, []byte("later source"), 0o600); err != nil {
		t.Fatal(err)
	}
	mutated := false
	a := &budgetFakeAdapter{
		name:        "fake",
		root:        root,
		mutateEvery: true,
		mutate: func(path string) error {
			if path != second || mutated {
				return nil
			}
			mutated = true
			return os.WriteFile(first, []byte("first source appended later"), 0o600)
		},
	}
	w, _ := newBudgetCaptureTestWatcher(t, Options{}, a)

	got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
	if got.Ready || got.Reason != BudgetCaptureReasonIncomplete || !got.Incomplete {
		t.Fatalf("status = %+v, want earlier change after parse to be incomplete", got)
	}
}

func TestReconcileBudgetCaptureRejectsFilesAddedDuringWalk(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeBudgetSource(t, root, "source")
	a := &budgetFakeAdapter{name: "fake", root: root}
	a.mutate = func(path string) error {
		nested := filepath.Join(filepath.Dir(path), "new", "capture.session")
		if err := os.MkdirAll(filepath.Dir(nested), 0o700); err != nil {
			return err
		}
		return os.WriteFile(nested, []byte("new source"), 0o600)
	}
	w, _ := newBudgetCaptureTestWatcher(t, Options{}, a)

	got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
	if got.Ready || got.Reason != BudgetCaptureReasonIncomplete || !got.Incomplete {
		t.Fatalf("status = %+v, want added source to be incomplete", got)
	}
}

func TestReconcileBudgetCaptureRejectsNestedDirectorySymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := t.TempDir()
	writeBudgetSource(t, target, "hidden source")
	link := filepath.Join(root, "nested")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	w, _ := newBudgetCaptureTestWatcher(t, Options{}, &budgetFakeAdapter{name: "fake", root: root})

	got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
	// A directory symlink is never descended, so the store behind it stays
	// unread on every future pass too: structural, not a mid-pass race.
	if got.Ready || got.Reason != BudgetCaptureReasonUnreadable || !got.Incomplete {
		t.Fatalf("status = %+v, want unavailable unreadable status", got)
	}
	if got.AccountingClass() != BudgetAccountingUnavailable || got.AccountingReady() {
		t.Fatalf("status = %+v, want a skipped subtree to fail closed", got)
	}
	if !strings.Contains(got.Detail, "directory symlink") {
		t.Fatalf("detail = %q, want directory-symlink explanation", got.Detail)
	}
}

func TestReconcileBudgetCaptureRechecksRootsAddedDuringPass(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	lateRoot := filepath.Join(t.TempDir(), "appeared")
	writeBudgetSource(t, root, "source")
	appeared := false
	base := &budgetFakeAdapter{name: "fake", root: root}
	base.mutate = func(string) error {
		if appeared {
			return nil
		}
		if err := os.MkdirAll(lateRoot, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(lateRoot, "capture.session"), []byte("late source"), 0o600); err != nil {
			return err
		}
		appeared = true
		return nil
	}
	a := &budgetDynamicRootAdapter{
		budgetFakeAdapter: base,
		paths: func() []string {
			if appeared {
				return []string{root, lateRoot}
			}
			return []string{root}
		},
	}
	w, _ := newBudgetCaptureTestWatcher(t, Options{}, a)

	got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
	if got.Ready || got.Reason != BudgetCaptureReasonIncomplete || !got.Incomplete {
		t.Fatalf("status = %+v, want newly rooted source to block readiness", got)
	}
	if !strings.Contains(got.Detail, lateRoot) {
		t.Fatalf("detail = %q, want late root %q", got.Detail, lateRoot)
	}
	if !containsString(got.Roots, lateRoot) {
		t.Fatalf("roots = %v, want final candidate root %q", got.Roots, lateRoot)
	}
}

func TestReconcileBudgetCaptureRejectsStaticCandidateRootCreatedDuringPass(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	lateRoot := filepath.Join(t.TempDir(), "appeared")
	firstPath := writeBudgetSource(t, root, "source")
	base := &budgetFakeAdapter{name: "fake", root: root}
	base.mutate = func(path string) error {
		if path != firstPath {
			return nil
		}
		if err := os.MkdirAll(lateRoot, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(lateRoot, "capture.session"), []byte("late source"), 0o600)
	}
	a := &budgetDynamicRootAdapter{
		budgetFakeAdapter: base,
		paths:             func() []string { return []string{root, lateRoot} },
	}
	w, _ := newBudgetCaptureTestWatcher(t, Options{}, a)

	got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
	if got.Ready || got.Reason != BudgetCaptureReasonIncomplete || !got.Incomplete {
		t.Fatalf("status = %+v, want absent static candidate root to block readiness", got)
	}
	if !strings.Contains(got.Detail, "appeared during scan") || !strings.Contains(got.Detail, lateRoot) {
		t.Fatalf("detail = %q, want late candidate-root explanation", got.Detail)
	}
}

func TestReconcileBudgetCaptureSnapshotsSQLiteSidecars(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dbPath := filepath.Join(root, "capture.db")
	if err := os.WriteFile(dbPath, []byte("main"), 0o600); err != nil {
		t.Fatal(err)
	}
	walPath := dbPath + "-wal"
	if err := os.WriteFile(walPath, []byte("wal-before"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &budgetFakeWatermarkAdapter{budgetFakeAdapter: &budgetFakeAdapter{
		name:   "fake",
		root:   root,
		suffix: ".db",
	}}
	a.mutate = func(string) error {
		return os.WriteFile(walPath, []byte("wal-after-with-more-pages"), 0o600)
	}
	w, _ := newBudgetCaptureTestWatcher(t, Options{}, a)

	got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
	if got.Ready || got.Reason != BudgetCaptureReasonIncomplete || !got.Incomplete {
		t.Fatalf("status = %+v, want SQLite mutation to block readiness", got)
	}
	if !strings.Contains(got.Detail, "SQLite companion") {
		t.Fatalf("detail = %q, want SQLite companion explanation", got.Detail)
	}
}

func TestReconcileBudgetCaptureRejectsRewrittenWatermarkJSON(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "sessions.json")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &budgetFakeWatermarkAdapter{budgetFakeAdapter: &budgetFakeAdapter{name: "fake", root: root, suffix: ".json"}}
	a.mutate = func(path string) error { return os.WriteFile(path, []byte("rewritten with new records"), 0o600) }
	w, _ := newBudgetCaptureTestWatcher(t, Options{}, a)
	got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
	if got.Ready || !got.Incomplete {
		t.Fatalf("rewritten watermark source accepted: %+v", got)
	}
}

func TestReconcileBudgetCaptureDeduplicatesSQLiteSidecars(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dbPath := filepath.Join(root, "capture.db")
	if err := os.WriteFile(dbPath, []byte("main"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath+"-wal", []byte("wal"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &budgetFakeWatermarkAdapter{budgetFakeAdapter: &budgetFakeAdapter{
		name:   "fake",
		root:   root,
		suffix: ".db",
	}}
	w, _ := newBudgetCaptureTestWatcher(t, Options{}, a)

	got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
	if !got.Ready || got.FilesSeen != 1 || got.FilesProcessed != 1 {
		t.Fatalf("status = %+v, want one canonical SQLite source", got)
	}
	if a.parseCalls != 1 {
		t.Fatalf("parse calls = %d, want one parse for main plus sidecar", a.parseCalls)
	}
}

func TestReconcileBudgetCaptureOpenCodeSQLiteStableAcrossWALReads(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "opencode.db")
	setupBudgetOpenCodeDB(t, dbPath)
	holder := openBudgetSQLiteWALWriter(t, dbPath)
	defer holder.Close()
	if _, err := holder.Exec(`UPDATE session SET time_updated = 4000 WHERE id = 'ses_1'`); err != nil {
		t.Fatalf("seed WAL row: %v", err)
	}
	if _, err := os.Stat(dbPath + "-wal"); err != nil {
		t.Fatalf("WAL sidecar: %v", err)
	}

	a := opencode.NewWithOptions(nil, []string{root})
	w, _ := newBudgetCaptureTestWatcher(t, Options{}, a)
	for i := 0; i < 3; i++ {
		got := w.ReconcileBudgetCapture(context.Background(), []string{a.Name()})[a.Name()]
		if !got.Ready || got.Reason != BudgetCaptureReasonReady {
			t.Fatalf("reconciliation %d = %+v, want stable ready status", i+1, got)
		}
	}
	if _, err := os.Stat(dbPath + "-shm"); err != nil {
		t.Fatalf("SQLite parser did not leave its shared-memory sidecar: %v", err)
	}
}

func TestReconcileBudgetCaptureOpenCodeSQLiteRejectsWALMutation(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "opencode.db")
	setupBudgetOpenCodeDB(t, dbPath)
	holder := openBudgetSQLiteWALWriter(t, dbPath)
	defer holder.Close()
	if _, err := holder.Exec(`UPDATE session SET time_updated = 4000 WHERE id = 'ses_1'`); err != nil {
		t.Fatalf("seed WAL row: %v", err)
	}
	mutator, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open WAL mutator: %v", err)
	}
	defer mutator.Close()
	mutator.SetMaxOpenConns(1)
	if _, err := mutator.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		t.Fatalf("enable mutator WAL: %v", err)
	}

	inner := opencode.NewWithOptions(nil, []string{root})
	blocking := &budgetBlockingAdapter{
		Adapter: inner,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	t.Cleanup(blocking.releaseParser)
	w, _ := newBudgetCaptureTestWatcher(t, Options{}, blocking)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resultCh := make(chan BudgetCaptureStatus, 1)
	go func() {
		resultCh <- w.ReconcileBudgetCapture(ctx, []string{inner.Name()})[inner.Name()]
	}()
	select {
	case <-blocking.started:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for OpenCode parser pause")
	}

	if _, err := mutator.Exec(`UPDATE message SET time_updated = 5000 WHERE id = 'msg_done'`); err != nil {
		blocking.releaseParser()
		t.Fatalf("commit WAL row mutation: %v", err)
	}
	blocking.releaseParser()

	var got BudgetCaptureStatus
	select {
	case got = <-resultCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OpenCode reconciliation")
	}
	if got.Ready || got.Reason != BudgetCaptureReasonIncomplete || !got.Incomplete {
		t.Fatalf("status = %+v, want WAL mutation to make source incomplete", got)
	}
	if !strings.Contains(got.Detail, "SQLite companion") {
		t.Fatalf("detail = %q, want SQLite WAL mutation explanation", got.Detail)
	}
}

func setupBudgetOpenCodeDB(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	stmts := []string{
		`CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`INSERT INTO session(id, directory, time_updated) VALUES ('ses_1', '/tmp/oc', 3000)`,
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_done', 'ses_1', 2900, 3000,
			 '{"role":"assistant","agent":"build","modelID":"big-pickle","providerID":"opencode","path":{"cwd":"/tmp/oc"},"time":{"created":2900,"completed":3000},"finish":"stop","tokens":{"input":1234,"output":567,"reasoning":89,"cache":{"read":12345,"write":678}},"cost":0.0532}')`,
	}
	for _, stmt := range stmts {
		if _, err := database.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

func openBudgetSQLiteWALWriter(t *testing.T, path string) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open WAL writer: %v", err)
	}
	database.SetMaxOpenConns(1)
	if _, err := database.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		database.Close()
		t.Fatalf("enable WAL: %v", err)
	}
	if _, err := database.Exec(`PRAGMA wal_autocheckpoint = 0`); err != nil {
		database.Close()
		t.Fatalf("disable WAL autocheckpoint: %v", err)
	}
	return database
}

func TestReconcileBudgetCaptureRejectsUsageWithMissingAccountingDimensions(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"session", "model", "timestamp"} {
		t.Run(field, func(t *testing.T) {
			root := t.TempDir()
			writeBudgetSource(t, root, "source")
			a := &budgetInvalidTokenAdapter{
				budgetFakeAdapter: &budgetFakeAdapter{name: "fake", root: root},
				field:             field,
			}
			w, _ := newBudgetCaptureTestWatcher(t, Options{}, a)

			got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
			if got.Ready || got.Reason != BudgetCaptureReasonParseError {
				t.Fatalf("status = %+v, want strict validation failure", got)
			}
			if !strings.Contains(got.Detail, "nonzero usage") || !strings.Contains(got.Detail, field) {
				t.Fatalf("detail = %q, want missing %s dimension", got.Detail, field)
			}
		})
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
