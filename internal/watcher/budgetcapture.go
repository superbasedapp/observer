package watcher

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// BudgetCaptureStatus reports whether a tool's local capture source completed
// a strict catchup. Ready describes source availability only. It does not
// assert that spend is complete, that a monetary limit can be enforced, or
// that a future request can be admitted before its vendor call.
type BudgetCaptureStatus struct {
	// Ready is true only when at least one source file was fully scanned and
	// every source file in the detected roots completed without a strict
	// catchup failure.
	Ready bool `json:"ready"`
	// Reason is a stable machine-readable reason when Ready is false. It is
	// "ready" when Ready is true. It names ONE issue chosen for the operator;
	// it is deliberately not the accounting authority, because a pass can
	// produce several issues at once and the most readable one is rarely the
	// most severe.
	Reason string `json:"reason,omitempty"`
	// Class is the accounting classification of the WHOLE pass: the most
	// severe class over every issue it produced, not the class of the one
	// issue Reason names. A structural issue (an oversize file, a session-file
	// symlink that escapes the watch roots) ranks LAST in the reason
	// precedence, so before this field existed it was routinely masked by the
	// scan_incomplete or warnings a live tool produces on every pass, and a
	// permanently unreadable source reported itself as merely delayed.
	//
	// It is empty on a zero-value status and on a status built by a writer
	// that predates the field; AccountingClass then falls back to classifying
	// Reason through the readiness table.
	Class BudgetAccountingClass `json:"accounting_class,omitempty"`
	// Detail is bounded operator-facing context for the reason. It may include
	// a source path or parser error and must not be used as an admission rule.
	Detail string `json:"detail,omitempty"`
	// Adapter is the registry adapter used for this status.
	Adapter string `json:"adapter,omitempty"`
	// Roots contains the candidate roots observed during reconciliation. A root
	// that appears after the walk begins is retained here and makes the status
	// unavailable until a later pass covers it.
	Roots []string `json:"roots,omitempty"`
	// FilesSeen is the number of canonical source files encountered during the
	// strict walk. SQLite trigger sidecars are counted with their primary file.
	FilesSeen int `json:"files_seen,omitempty"`
	// FilesProcessed is the number of recognized files whose parser and store
	// ingestion completed without returning an error. A file with warnings can
	// be counted here while the overall status remains unavailable.
	FilesProcessed int `json:"files_processed,omitempty"`
	// Warnings contains parser warnings observed during strict catchup.
	Warnings []string `json:"warnings,omitempty"`
	// Incomplete is true when cancellation, a walk error, or a root change
	// prevented the strict pass from covering its intended source tree.
	Incomplete bool `json:"incomplete,omitempty"`
}

const (
	// BudgetCaptureReasonReady is the successful status reason.
	BudgetCaptureReasonReady = "ready"
	// BudgetCaptureReasonMissingRoot means none of the adapter's candidate
	// roots existed when reconciliation started.
	BudgetCaptureReasonMissingRoot = "missing_root"
	// BudgetCaptureReasonUnknownAdapter means the requested tool is absent from
	// the adapter registry.
	BudgetCaptureReasonUnknownAdapter = "unknown_adapter"
	// BudgetCaptureReasonAllowFiltered means the adapter exists but the
	// watcher's allow list excludes it.
	BudgetCaptureReasonAllowFiltered = "allow_filtered_adapter"
	// BudgetCaptureReasonParseError means a parser or store operation failed.
	BudgetCaptureReasonParseError = "parse_error"
	// BudgetCaptureReasonParserPanic means the adapter panicked while parsing.
	BudgetCaptureReasonParserPanic = "parser_panic"
	// BudgetCaptureReasonWarnings means parsing produced one or more warnings.
	BudgetCaptureReasonWarnings = "warnings"
	// BudgetCaptureReasonRetrySuggested means the adapter asked to be retried.
	BudgetCaptureReasonRetrySuggested = "retry_suggested"
	// BudgetCaptureReasonOversizeFile means a file exceeded the configured
	// strict size gate.
	BudgetCaptureReasonOversizeFile = "oversize_file"
	// BudgetCaptureReasonUnsafeSymlink means a session-file symlink escaped its
	// adapter watch roots.
	BudgetCaptureReasonUnsafeSymlink = "unsafe_symlink"
	// BudgetCaptureReasonCanceled means the reconciliation context was canceled.
	BudgetCaptureReasonCanceled = "scan_canceled"
	// BudgetCaptureReasonIncomplete means the source walk did not complete
	// because the tree MOVED under it: a file or directory was deleted,
	// renamed, replaced, or grew mid-pass. That is the ordinary signature of a
	// tool writing its own store (muse removes its session directory on a
	// clean exit), so it is a race, never evidence that the source cannot be
	// read.
	BudgetCaptureReasonIncomplete = "scan_incomplete"
	// BudgetCaptureReasonUnreadable means a root, directory, or source file
	// exists but this node cannot read it: a non-ENOENT stat or walk error
	// (permissions, an I/O error, an unreadable mount), a source that is not a
	// regular file, or a directory symlink the walk cannot descend. Unlike
	// scan_incomplete it does not resolve by waiting, so it is structural.
	BudgetCaptureReasonUnreadable = "source_unreadable"
	// BudgetCaptureReasonNoFiles means roots existed but no recognized source
	// files were found. An empty source is not evidence of zero spend.
	BudgetCaptureReasonNoFiles = "no_source_files"
	// BudgetCaptureReasonNoEvidence means recognized files parsed cleanly but
	// exposed neither parser progress nor an ingested source record. Empty SQL
	// results do not establish source health or zero spend.
	BudgetCaptureReasonNoEvidence = "no_source_evidence"
	// BudgetCaptureReasonStoreUnavailable means the watcher has no usable store.
	BudgetCaptureReasonStoreUnavailable = "store_unavailable"
	// BudgetCaptureReasonNoRequiredSources means no active tool and no
	// currently rooted adapter supplied a source to reconcile.
	BudgetCaptureReasonNoRequiredSources = "no_required_sources"
	// BudgetCaptureReasonMissingStatus means the caller asked about a tool that
	// this reconciliation pass never produced a status for. It is never written
	// by a pass; it is the honest classification of a zero-value status.
	BudgetCaptureReasonMissingStatus = "no_capture_status"
)

// BudgetAccountingClass is the three-way accounting classification of a
// capture reason. It replaced a boolean "ready" column on 2026-09-15, because
// that column conflated two very different failures: a source that CANNOT be
// read on this node, and a strict tail catch-up that merely did not finish
// this pass while the tool was writing its own session files.
type BudgetAccountingClass string

const (
	// BudgetAccountingKnown means this tool's spend is measured. The strict
	// pass either covered the source tree or established that the tool has
	// honestly captured nothing on this machine.
	BudgetAccountingKnown BudgetAccountingClass = "known"
	// BudgetAccountingDelayed means the strict tail catch-up did not complete
	// this pass, but the source is intact. The measured total already in the
	// store stands and the decision is taken on it.
	BudgetAccountingDelayed BudgetAccountingClass = "delayed"
	// BudgetAccountingUnavailable means this tool's spend cannot be captured on
	// this node at all. It is the structural class, and the only one that fails
	// closed.
	BudgetAccountingUnavailable BudgetAccountingClass = "unavailable"
)

// budgetCaptureReadinessRow classifies one capture reason for an accounting
// decision. Exactly one row exists per BudgetCaptureReason* constant, so the
// classification is a table walked by reason rather than a conditional ladder
// that grows a branch per new failure mode (CLAUDE.md #5).
type budgetCaptureReadinessRow struct {
	// reason is the BudgetCaptureReason* constant this row classifies.
	reason string
	// class is the accounting class this reason carries.
	//
	// BudgetAccountingKnown covers the reasons that mean this tool's own spend
	// is measured for the pass, including the benign "nothing captured yet"
	// shapes: a tool with no store, no recognized source file, or no usage
	// event on this machine has produced no billable work, which is measured
	// zero spend for that tool, not unknown spend. Treating those as
	// unavailable created a catch-22 in which a freshly launched tool was
	// stopped before it could write the very source that would have made it
	// ready.
	//
	// BudgetAccountingDelayed covers the transient tail failures. The strict
	// pass is a tail ACCELERATOR, never the source of truth for the total: the
	// ordinary watcher path plus every earlier strict pass have already landed
	// the measured spend in the store. Failing to read the newest tail can only
	// UNDER-count by seconds of spend, which can only delay a stop, never cause
	// a false one.
	//
	// BudgetAccountingUnavailable covers the structural reasons, where nothing
	// on this node can read the tool's spend. Only that class fails closed.
	class BudgetAccountingClass
	// note is bounded operator-facing context for why the row classifies this
	// way. It is not an admission rule.
	note string
}

// budgetCaptureReadinessTable is the closed classification of every capture
// reason. A new BudgetCaptureReason* constant must gain a row here;
// TestBudgetCaptureReadinessClassifiesEveryReason fails otherwise, and an
// unclassified reason is treated as unavailable at runtime (fail closed).
//
// The delayed rows are the 2026-09-15 correction. A tool that is actively
// RUNNING is actively WRITING the very files the strict pass reads, so the
// pass routinely returned retry_suggested (an adapter deferring a half-written
// tool call), scan_incomplete (the file grew during the parse - of course it
// did), or parse_error (a mid-write SQLite/JSONL read, or SQLITE_BUSY against
// the ordinary watcher writing the same rows). Classified as unavailable,
// every one of those TERMed the running process: real guard_events on the
// managed devbox killed Muse and antigravity-cli mid-run at $0.26 of a $2/day
// cap on 2026-09-14. A delayed tail is not unknown spend, so it never stops a
// process; only a structurally unavailable source does.
var budgetCaptureReadinessTable = []budgetCaptureReadinessRow{
	{BudgetCaptureReasonReady, BudgetAccountingKnown, "strict catchup covered the source tree"},
	{BudgetCaptureReasonMissingRoot, BudgetAccountingKnown, "the tool has no store on this machine; it has produced no spend"},
	{BudgetCaptureReasonNoFiles, BudgetAccountingKnown, "the store exists but holds no recognized session file yet"},
	{BudgetCaptureReasonNoEvidence, BudgetAccountingKnown, "recognized files parsed cleanly and carried no usage event"},
	{BudgetCaptureReasonWarnings, BudgetAccountingKnown, "the source parsed and the adapter reported a non-fatal warning"},
	{BudgetCaptureReasonParseError, BudgetAccountingDelayed, "a parser or store operation failed on the live tail; the measured total stands and the tail lands on a later pass"},
	{BudgetCaptureReasonParserPanic, BudgetAccountingDelayed, "the adapter panicked on the live tail; the measured total stands and the tail lands on a later pass"},
	{BudgetCaptureReasonRetrySuggested, BudgetAccountingDelayed, "the adapter deferred a half-written tail; the measured total stands and the tail lands on a later pass"},
	{BudgetCaptureReasonCanceled, BudgetAccountingDelayed, "the strict pass ran out of time; the measured total stands and the tail lands on a later pass"},
	{BudgetCaptureReasonIncomplete, BudgetAccountingDelayed, "the source grew or moved while it was being read; the measured total stands and the tail lands on a later pass"},
	{BudgetCaptureReasonUnreadable, BudgetAccountingUnavailable, "a root, directory or source file exists but cannot be read on this node"},
	{BudgetCaptureReasonOversizeFile, BudgetAccountingUnavailable, "a source file exceeded the strict size gate and is never read"},
	{BudgetCaptureReasonUnsafeSymlink, BudgetAccountingUnavailable, "a session-file symlink escaped the adapter watch roots and is never read"},
	{BudgetCaptureReasonUnknownAdapter, BudgetAccountingUnavailable, "no adapter is registered to read this tool's spend"},
	{BudgetCaptureReasonAllowFiltered, BudgetAccountingUnavailable, "the watcher allow list excludes this adapter, so it captures nothing"},
	{BudgetCaptureReasonStoreUnavailable, BudgetAccountingUnavailable, "the watcher has no store to record captured spend in"},
	{BudgetCaptureReasonNoRequiredSources, BudgetAccountingUnavailable, "no source was reconciled in this pass"},
	{BudgetCaptureReasonMissingStatus, BudgetAccountingUnavailable, "this pass produced no status for the requested tool"},
}

func budgetCaptureReadinessFor(reason string) (budgetCaptureReadinessRow, bool) {
	for _, row := range budgetCaptureReadinessTable {
		if row.reason == reason {
			return row, true
		}
	}
	return budgetCaptureReadinessRow{reason: reason}, false
}

// budgetAccountingClassFor classifies one reason through the readiness table.
// An unclassified reason is unavailable, so a reason nobody has decided about
// still fails closed.
func budgetAccountingClassFor(reason string) BudgetAccountingClass {
	row, ok := budgetCaptureReadinessFor(reason)
	if !ok || row.class == "" {
		return BudgetAccountingUnavailable
	}
	return row.class
}

// budgetAccountingSeverity orders the classes so a pass can be classified by
// its WORST issue. Unavailable outranks delayed outranks known.
func budgetAccountingSeverity(class BudgetAccountingClass) int {
	switch class {
	case BudgetAccountingKnown:
		return 0
	case BudgetAccountingDelayed:
		return 1
	default:
		return 2
	}
}

// budgetAccountingWorse returns the more severe of two classes. It is how a
// pass with several issues is classified: the reason an operator reads names
// one issue, but the accounting decision must answer for all of them.
func budgetAccountingWorse(left, right BudgetAccountingClass) BudgetAccountingClass {
	if budgetAccountingSeverity(right) > budgetAccountingSeverity(left) {
		return right
	}
	return left
}

// AccountingClass reports this source's accounting class: known (spend is
// measured), delayed (the strict tail catch-up did not finish this pass, but
// the measured total stands), or unavailable (nothing on this node can read
// this tool's spend).
//
// The pass's own Class wins when it is set, because it answers for EVERY issue
// the pass produced; Reason names only the one issue chosen for the operator,
// and the structural reasons rank last in that choice. Reason is classified
// through the readiness table only when Class is empty - a zero-value status,
// or one built before the field existed. Either way an unclassified reason is
// unavailable, so a reason nobody has classified still fails closed.
func (s BudgetCaptureStatus) AccountingClass() BudgetAccountingClass {
	switch s.Class {
	case BudgetAccountingKnown, BudgetAccountingDelayed, BudgetAccountingUnavailable:
		return s.Class
	case "":
		return budgetAccountingClassFor(s.Reason)
	default:
		// A class value this build does not know is not a licence to run.
		return BudgetAccountingUnavailable
	}
}

// AccountingReady reports whether this source's status permits a budget
// decision for its own tool. It is deliberately weaker than Ready: Ready
// asserts a completed strict catchup, while AccountingReady accepts every
// class except the structurally unavailable one - the benign "this tool has
// captured nothing yet" reasons, which are measured zero spend for that tool,
// and the delayed reasons, where the store's measured total stands while the
// newest tail lands on a later pass.
//
// Accepting the delayed class is the 2026-09-15 correction: a running tool is
// writing the files the strict pass reads, so retry_suggested / scan_incomplete
// / parse_error are the NORMAL result of governing a live process. Treating
// them as unavailable TERMed real sessions mid-run at a fraction of their cap.
func (s BudgetCaptureStatus) AccountingReady() bool {
	return s.AccountingClass() != BudgetAccountingUnavailable
}

// AccountingDelayed reports whether the strict tail catch-up did not complete
// for this source while the source itself stayed intact. It is honesty context
// for an operator: the decision was taken on the measured total in the store,
// and the newest tail lands on a later pass. It never denies.
func (s BudgetCaptureStatus) AccountingDelayed() bool {
	return s.AccountingClass() == BudgetAccountingDelayed
}

// AccountingReason is the stable machine-readable reason behind
// AccountingReady. A zero-value status (no pass covered this tool) reports
// BudgetCaptureReasonMissingStatus rather than an empty string.
func (s BudgetCaptureStatus) AccountingReason() string {
	if s.Reason == "" {
		return BudgetCaptureReasonMissingStatus
	}
	return s.Reason
}

// NodeBudgetCaptureStatus is the node-wide strict source result. Sources
// retains the per-tool statuses so a false aggregate can explain which
// adapter is unavailable. Ready is source availability after strict catchup;
// it does not provide a complete monetary total or pre-request enforcement.
type NodeBudgetCaptureStatus struct {
	// Ready is true only when every required source is strictly ready and at
	// least one required source exists.
	Ready bool `json:"ready"`
	// Reason is "ready", no_required_sources, scan_incomplete when the required
	// source set changed during the pass, or the first unavailable source reason
	// selected from Sources.
	Reason string `json:"reason,omitempty"`
	// Sources is the retained per-tool reconciliation result.
	Sources map[string]BudgetCaptureStatus `json:"sources,omitempty"`
}

// budgetCaptureFileOutcome is the strict-aware result of one processFile
// attempt. The ordinary watcher deliberately ignores most of these fields.
type budgetCaptureFileOutcome struct {
	// startOffset is the position the strict parse resumed from. It is the
	// input to the strict memo written after a successful batch ingest.
	startOffset      int64
	parsed           bool
	sourceEvidence   bool
	strictResult     *adapter.ParseResult
	beforeSnapshot   *budgetFileSnapshot
	warnings         []string
	retrySuggested   bool
	parserPanic      bool
	unsafeSymlink    bool
	oversize         bool
	incomplete       bool
	incompleteDetail string
	parseError       error
	storeError       error
}

// budgetCaptureSeenEntry memoizes one (adapter, source file) strict result
// for the lifetime of this daemon. It exists because the strict pass runs on
// every node-control cycle: without it, every cycle re-opened and re-parsed
// the whole corpus, which no real machine can finish inside the pass deadline
// (accounting-readiness correction, 2026-09-14).
//
// The memo is NEVER persisted and never replaces the ordinary cursor. The
// ordinary cursor stays where the ordinary watcher left it, because strict
// ingest is usage-only: advancing it would skip action and content capture for
// the bytes the strict pass consumed. After a restart the strict pass resumes
// from the ordinary cursor, which the ordinary watcher keeps current.
type budgetCaptureSeenEntry struct {
	// snapshot is the file (and SQLite family) metadata at the last strict
	// pass. An identical snapshot means the source cannot have new usage, so
	// the file costs one stat instead of a parse.
	snapshot budgetFileSnapshot
	// offset is the position the last successful strict parse reached.
	offset int64
	// parsed records that the last pass completed parser and store work.
	parsed bool
	// evidence is sticky: once a source has produced a usage event, a later
	// pass that legitimately parses nothing new must not report the source as
	// evidence-free.
	evidence bool
}

// budgetCaptureSeenMax bounds the memo. It is a performance cache, so a reset
// costs one re-parse per file, never correctness.
const budgetCaptureSeenMax = 8192

func budgetCaptureSeenKey(a adapter.Adapter, path string) string {
	return a.Name() + "\x00" + path
}

// budgetCaptureMemo returns the memoized entry for an UNCHANGED file. A
// changed, replaced, or unstattable file reports false and must be parsed.
func (w *Watcher) budgetCaptureMemo(a adapter.Adapter, path string) (budgetCaptureSeenEntry, bool) {
	w.budgetCaptureMu.Lock()
	entry, ok := w.budgetCaptureSeen[budgetCaptureSeenKey(a, path)]
	w.budgetCaptureMu.Unlock()
	if !ok {
		return budgetCaptureSeenEntry{}, false
	}
	current, err := strictBudgetFileSnapshot(a, path)
	if err != nil {
		return budgetCaptureSeenEntry{}, false
	}
	if strictBudgetFileChange(entry.snapshot, current) != "" {
		return budgetCaptureSeenEntry{}, false
	}
	entry.snapshot = current
	return entry, true
}

// budgetCaptureOffset returns the strict resume position for a file whose
// identity still matches the memo. Identity is re-checked here because a
// replaced file reuses its path and must never resume at a stale offset.
func (w *Watcher) budgetCaptureOffset(a adapter.Adapter, path string) (int64, bool) {
	w.budgetCaptureMu.Lock()
	entry, ok := w.budgetCaptureSeen[budgetCaptureSeenKey(a, path)]
	w.budgetCaptureMu.Unlock()
	if !ok || entry.offset <= 0 {
		return 0, false
	}
	info, err := os.Stat(path)
	if err != nil || !os.SameFile(entry.snapshot.info, info) {
		return 0, false
	}
	return entry.offset, true
}

// rememberBudgetCapture records a successful strict pass. Evidence is ORed so
// it stays sticky across passes that parse no new events.
func (w *Watcher) rememberBudgetCapture(a adapter.Adapter, path string, entry budgetCaptureSeenEntry) bool {
	key := budgetCaptureSeenKey(a, path)
	w.budgetCaptureMu.Lock()
	defer w.budgetCaptureMu.Unlock()
	if w.budgetCaptureSeen == nil {
		w.budgetCaptureSeen = make(map[string]budgetCaptureSeenEntry)
	}
	if previous, ok := w.budgetCaptureSeen[key]; ok {
		entry.evidence = entry.evidence || previous.evidence
		if previous.offset > entry.offset {
			entry.offset = previous.offset
		}
	} else if len(w.budgetCaptureSeen) >= budgetCaptureSeenMax {
		w.budgetCaptureSeen = make(map[string]budgetCaptureSeenEntry)
	}
	w.budgetCaptureSeen[key] = entry
	return entry.evidence
}

// forgetBudgetCapture drops a memo after any unsuccessful outcome so the next
// pass reparses instead of inheriting an unverified position.
func (w *Watcher) forgetBudgetCapture(a adapter.Adapter, path string) {
	w.budgetCaptureMu.Lock()
	defer w.budgetCaptureMu.Unlock()
	delete(w.budgetCaptureSeen, budgetCaptureSeenKey(a, path))
}

type budgetCaptureIssue struct {
	reason string
	detail string
}

type budgetCaptureReport struct {
	filesSeen      int
	filesProcessed int
	evidence       bool
	warnings       []string
	incomplete     bool
	issues         []budgetCaptureIssue
	directories    map[string]budgetDirectorySnapshot
	files          map[string]budgetFileSnapshot
	sources        map[string]struct{}
	pending        []budgetCapturePending
	pendingEvents  int
	pendingBytes   int64
}

type budgetCapturePending struct {
	path    string
	outcome budgetCaptureFileOutcome
}

const (
	budgetCaptureBatchFiles  = 32
	budgetCaptureBatchEvents = 4096
	budgetCaptureBatchBytes  = 8 << 20
)

type budgetRootSnapshot struct {
	path string
	info os.FileInfo
}

type budgetDirectorySnapshot struct {
	path string
	info os.FileInfo
}

type budgetFileSnapshot struct {
	info        os.FileInfo
	semantics   adapter.FileCursorSemantics
	sqliteFiles []budgetSQLiteFileSnapshot
}

type budgetSQLiteFileSnapshot struct {
	path   string
	exists bool
	info   os.FileInfo
}

func (r *budgetCaptureReport) addIssue(reason, detail string) {
	r.issues = append(r.issues, budgetCaptureIssue{reason: reason, detail: budgetCaptureDetail(detail)})
}

func budgetCaptureDetail(detail string) string {
	const maxDetailBytes = 2048
	if len(detail) <= maxDetailBytes {
		return detail
	}
	return detail[:maxDetailBytes-3] + "..."
}

// ReconcileBudgetCapture performs a bounded, uncached full catchup for each
// requested adapter and reports source availability. A nil tools slice means
// all registered adapters; a non-nil empty slice means no tools were
// requested. The pass intentionally reparses unchanged files from offset zero
// for now; an unchanged-file cache can be added later without changing this
// status contract.
func (w *Watcher) ReconcileBudgetCapture(ctx context.Context, tools []string) map[string]BudgetCaptureStatus {
	statuses := make(map[string]BudgetCaptureStatus)
	if w == nil || w.registry == nil {
		for _, name := range uniqueBudgetTools(tools) {
			statuses[name] = BudgetCaptureStatus{
				Reason: BudgetCaptureReasonUnknownAdapter,
				Class:  budgetAccountingClassFor(BudgetCaptureReasonUnknownAdapter),
				Detail: "adapter registry is unavailable",
			}
		}
		return statuses
	}
	if w.store == nil {
		names := uniqueBudgetTools(tools)
		if tools == nil && w.registry != nil {
			for _, a := range w.registry.All() {
				if a != nil {
					names = append(names, a.Name())
				}
			}
			names = uniqueBudgetTools(names)
		}
		for _, name := range names {
			statuses[name] = BudgetCaptureStatus{
				Adapter: name,
				Reason:  BudgetCaptureReasonStoreUnavailable,
				Class:   budgetAccountingClassFor(BudgetCaptureReasonStoreUnavailable),
				Detail:  "watcher store is unavailable",
			}
		}
		return statuses
	}

	names := uniqueBudgetTools(tools)
	if tools == nil {
		for _, a := range w.registry.All() {
			if a != nil {
				names = append(names, a.Name())
			}
		}
		names = uniqueBudgetTools(names)
	}

	all := w.registry.All()
	byName := make(map[string]adapter.Adapter, len(all))
	for _, a := range all {
		if a != nil {
			byName[a.Name()] = a
		}
	}
	// Detected is deliberately consulted once here instead of treating a
	// successful empty query or a main-file timestamp as source health.
	detected := make(map[string]adapter.Adapter)
	for _, a := range w.registry.Detected(w.allow) {
		if a != nil {
			detected[a.Name()] = a
		}
	}

	for _, name := range names {
		a := byName[name]
		if a == nil {
			statuses[name] = BudgetCaptureStatus{
				Adapter: name,
				Reason:  BudgetCaptureReasonUnknownAdapter,
				Class:   budgetAccountingClassFor(BudgetCaptureReasonUnknownAdapter),
				Detail:  "no adapter is registered under this name",
			}
			continue
		}
		if ctx != nil && ctx.Err() != nil {
			statuses[name] = BudgetCaptureStatus{
				Adapter:    name,
				Reason:     BudgetCaptureReasonCanceled,
				Class:      budgetAccountingClassFor(BudgetCaptureReasonCanceled),
				Detail:     ctx.Err().Error(),
				Incomplete: true,
			}
			continue
		}
		if !budgetAdapterAllowed(w.allow, name) {
			statuses[name] = BudgetCaptureStatus{
				Adapter: name,
				Reason:  BudgetCaptureReasonAllowFiltered,
				Class:   budgetAccountingClassFor(BudgetCaptureReasonAllowFiltered),
				Detail:  "the watcher allow list excludes this adapter",
			}
			continue
		}
		roots := w.strictBudgetRoots(a)
		existing, statIssues := budgetExistingRoots(roots)
		if len(statIssues) > 0 {
			// The reason names ONE issue for the operator; the class answers
			// for all of them, so an unreadable root is not masked by a root
			// that merely moved.
			issue := chooseBudgetIssue(statIssues)
			statuses[name] = BudgetCaptureStatus{
				Adapter:    name,
				Roots:      append([]string(nil), roots...),
				Reason:     issue.reason,
				Class:      budgetIssuesClass(statIssues),
				Detail:     budgetCaptureDetail(issue.detail),
				Incomplete: true,
			}
			continue
		}
		if len(existing) == 0 {
			statuses[name] = BudgetCaptureStatus{
				Adapter: name,
				Roots:   append([]string(nil), roots...),
				Reason:  BudgetCaptureReasonMissingRoot,
				Class:   budgetAccountingClassFor(BudgetCaptureReasonMissingRoot),
				Detail:  "no adapter watch root exists",
			}
			continue
		}
		if detected[name] == nil {
			// A root existed when we statted it but disappeared from the
			// registry's detected snapshot. Treat that race as incomplete,
			// rather than claiming the source is missing or healthy.
			statuses[name] = BudgetCaptureStatus{
				Adapter:    name,
				Roots:      append([]string(nil), roots...),
				Reason:     BudgetCaptureReasonIncomplete,
				Class:      budgetAccountingClassFor(BudgetCaptureReasonIncomplete),
				Detail:     "adapter detection changed during reconciliation",
				Incomplete: true,
			}
			continue
		}
		statuses[name] = w.reconcileBudgetAdapter(ctx, a, roots, existing)
	}
	return statuses
}

// ReconcileNodeBudgetCapture performs strict catchup for the ACTIVE source
// set: the tools of the governed processes the caller is about to decide for.
// An active tool is always required, even when its roots are missing or the
// adapter is unknown, and its status is retained in Sources.
//
// Adapters that are NOT active are deliberately excluded (accounting-readiness
// correction, 2026-09-14). Their spend still reaches the store through the
// ordinary watcher; re-parsing every registered adapter's whole source tree on
// every two-second cycle made one unrelated adapter's failure - or merely a
// slow tree - stop every governed process on the machine, and burned the
// pass's time budget on trees no decision depended on.
//
// The required source set is checked again after the pass; it is the caller's
// active-tool list, so a change can only mean the caller's own input moved
// under it, which invalidates the aggregate until a later pass. This pass is
// intentionally uncached; unchanged-file validation caching remains a future
// optimization.
func (w *Watcher) ReconcileNodeBudgetCapture(ctx context.Context, activeTools []string) NodeBudgetCaptureStatus {
	required := w.nodeBudgetRequiredTools(activeTools)
	statuses := w.ReconcileBudgetCapture(ctx, required)
	finalRequired := w.nodeBudgetRequiredTools(activeTools)
	changed := budgetToolSetDifference(required, finalRequired)
	if len(changed) > 0 {
		// Keep the statuses produced by the pass so operators can still see
		// which sources were covered. A source that appeared only after the
		// pass gets an explicit incomplete status; a source that disappeared
		// retains its existing status (which normally records the root race).
		for _, name := range changed {
			if _, ok := statuses[name]; ok {
				continue
			}
			statuses[name] = BudgetCaptureStatus{
				Adapter:    name,
				Reason:     BudgetCaptureReasonIncomplete,
				Class:      budgetAccountingClassFor(BudgetCaptureReasonIncomplete),
				Detail:     "required source set changed during node reconciliation",
				Incomplete: true,
			}
		}
		return NodeBudgetCaptureStatus{
			Reason:  BudgetCaptureReasonIncomplete,
			Sources: statuses,
		}
	}
	aggregate := NodeBudgetCaptureStatus{Sources: statuses}
	if len(statuses) == 0 {
		aggregate.Reason = BudgetCaptureReasonNoRequiredSources
		return aggregate
	}
	names := make([]string, 0, len(statuses))
	for name := range statuses {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		status := statuses[name]
		// The aggregate summarizes the active set for reporting. A per-workload
		// decision must consult that workload's OWN source (Sources[tool]); one
		// tool's broken source never speaks for another tool's spend. A delayed
		// source counts as ready here, exactly as it does for a decision: the
		// aggregate is a report, and the measured total stands.
		if !status.AccountingReady() {
			aggregate.Reason = status.AccountingReason()
			return aggregate
		}
	}
	aggregate.Ready = true
	aggregate.Reason = BudgetCaptureReasonReady
	return aggregate
}

func budgetToolSetDifference(left, right []string) []string {
	leftSet := make(map[string]struct{}, len(left))
	rightSet := make(map[string]struct{}, len(right))
	for _, name := range left {
		leftSet[name] = struct{}{}
	}
	for _, name := range right {
		rightSet[name] = struct{}{}
	}
	changed := make(map[string]struct{})
	for name := range leftSet {
		if _, ok := rightSet[name]; !ok {
			changed[name] = struct{}{}
		}
	}
	for name := range rightSet {
		if _, ok := leftSet[name]; !ok {
			changed[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(changed))
	for name := range changed {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// nodeBudgetRequiredTools is the strict-catchup scope: the caller's active
// tools and nothing else. It used to append every registered adapter that had
// a rooted store, which made an idle adapter's source health a precondition
// for governing an unrelated tool's process.
func (w *Watcher) nodeBudgetRequiredTools(activeTools []string) []string {
	return uniqueBudgetTools(activeTools)
}

// strictBudgetRoots deliberately bypasses Watcher's steady-state root cache.
// A symlink or junction can retarget while its WatchPaths spelling stays the
// same; strict reconciliation must re-evaluate identity before and after its
// pass instead of inheriting a cached deduplication result.
func (w *Watcher) strictBudgetRoots(a adapter.Adapter) []string {
	raw := a.WatchPaths()
	fold := w.dedupRoots
	if fold == nil {
		fold = adapter.DedupRootsByIdentity
	}
	return fold(raw)
}

func uniqueBudgetTools(tools []string) []string {
	seen := make(map[string]struct{}, len(tools))
	out := make([]string, 0, len(tools))
	for _, name := range tools {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func budgetAdapterAllowed(allow []string, name string) bool {
	if allow == nil {
		return true
	}
	for _, candidate := range allow {
		if candidate == name {
			return true
		}
	}
	return false
}

func budgetExistingRoots(roots []string) ([]budgetRootSnapshot, []budgetCaptureIssue) {
	existing := make([]budgetRootSnapshot, 0, len(roots))
	var issues []budgetCaptureIssue
	for _, root := range roots {
		if root == "" {
			continue
		}
		info, err := os.Stat(root)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Adapter roots are candidates; absent candidates are
				// expected when a tool has more than one install layout.
				continue
			}
			// The root exists (it is not ENOENT) but cannot be statted:
			// permissions, an I/O error, an unreadable mount. Waiting does not
			// fix that, so it is structural rather than a mid-pass race.
			issues = append(issues, budgetCaptureIssue{
				reason: BudgetCaptureReasonUnreadable,
				detail: fmt.Sprintf("stat watch root %s: %v", root, err),
			})
			continue
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			continue
		}
		existing = append(existing, budgetRootSnapshot{path: root, info: info})
	}
	return existing, issues
}

func (w *Watcher) reconcileBudgetAdapter(ctx context.Context, a adapter.Adapter, roots []string, existing []budgetRootSnapshot) BudgetCaptureStatus {
	name := a.Name()
	status := BudgetCaptureStatus{
		Adapter: name,
		Roots:   append([]string(nil), roots...),
	}
	if len(existing) == 0 {
		status.Reason = BudgetCaptureReasonMissingRoot
		status.Class = budgetAccountingClassFor(BudgetCaptureReasonMissingRoot)
		status.Detail = "no adapter watch root exists"
		return status
	}

	report := budgetCaptureReport{
		directories: make(map[string]budgetDirectorySnapshot),
		files:       make(map[string]budgetFileSnapshot),
		sources:     make(map[string]struct{}),
	}
	for _, root := range existing {
		if ctx != nil && ctx.Err() != nil {
			report.incomplete = true
			report.addIssue(BudgetCaptureReasonCanceled, ctx.Err().Error())
			break
		}
		w.walkBudgetRoot(ctx, a, root.path, &report)
	}
	w.flushBudgetCaptureBatch(ctx, a, &report)
	w.checkBudgetDirectories(&report)
	w.checkBudgetFiles(&report)
	finalRoots := w.recheckBudgetRoots(a, roots, existing, &report)
	if ctx != nil && ctx.Err() != nil {
		report.incomplete = true
		report.addIssue(BudgetCaptureReasonCanceled, ctx.Err().Error())
	}
	status.FilesSeen = report.filesSeen
	status.FilesProcessed = report.filesProcessed
	status.Roots = append([]string(nil), finalRoots...)
	status.Warnings = append([]string(nil), report.warnings...)
	status.Incomplete = report.incomplete
	if len(report.issues) == 0 && report.filesSeen > 0 && !report.incomplete {
		if !report.evidence {
			status.Reason = BudgetCaptureReasonNoEvidence
			status.Class = budgetAccountingClassFor(BudgetCaptureReasonNoEvidence)
			status.Detail = "strict parsing produced no token usage events"
			return status
		}
		status.Ready = true
		status.Reason = BudgetCaptureReasonReady
		status.Class = budgetAccountingClassFor(BudgetCaptureReasonReady)
		return status
	}
	if len(report.issues) == 0 {
		status.Reason = BudgetCaptureReasonNoFiles
		status.Class = budgetAccountingClassFor(BudgetCaptureReasonNoFiles)
		status.Detail = "watch roots existed but no recognized source file was found"
		return status
	}
	// Reason names ONE issue, chosen for readability; Class answers for ALL of
	// them. They are computed separately on purpose: the structural reasons
	// rank LAST in chooseBudgetIssue, so an oversize file or an escaping
	// symlink was silently masked by the scan_incomplete or warnings a live
	// tool produces on every single pass, and a permanently unreadable source
	// reported itself as merely delayed.
	issue := chooseBudgetIssue(report.issues)
	status.Reason = issue.reason
	status.Class = budgetIssuesClass(report.issues)
	status.Detail = budgetCaptureDetail(issue.detail)
	return status
}

// budgetIssuesClass is the accounting class of a whole pass: the most severe
// class over every issue it produced. An empty issue list is known, which only
// arises for callers that have already handled the no-issue outcomes.
func budgetIssuesClass(issues []budgetCaptureIssue) BudgetAccountingClass {
	class := BudgetAccountingKnown
	for _, issue := range issues {
		class = budgetAccountingWorse(class, budgetAccountingClassFor(issue.reason))
	}
	return class
}

// recheckBudgetRoots repeats candidate-root discovery after the strict walk.
// A root can appear after the initial stat (for example, when a tool creates
// its store while the pass is running); treating only the initial existing set
// as authoritative would incorrectly report a complete source tree.
func (w *Watcher) recheckBudgetRoots(a adapter.Adapter, initialRoots []string, initialExisting []budgetRootSnapshot, report *budgetCaptureReport) []string {
	finalRoots := w.strictBudgetRoots(a)
	initialCandidates := budgetRootSet(initialRoots)
	finalCandidates := budgetRootSet(finalRoots)
	for root := range finalCandidates {
		if _, ok := initialCandidates[root]; !ok {
			report.incomplete = true
			report.addIssue(BudgetCaptureReasonIncomplete, fmt.Sprintf("watch root %s appeared in candidate set during scan", root))
		}
	}
	for root := range initialCandidates {
		if _, ok := finalCandidates[root]; !ok {
			report.incomplete = true
			report.addIssue(BudgetCaptureReasonIncomplete, fmt.Sprintf("watch root candidate %s changed during scan", root))
		}
	}

	finalExisting, statIssues := budgetExistingRoots(finalRoots)
	for _, issue := range statIssues {
		report.incomplete = true
		report.addIssue(issue.reason, issue.detail)
	}
	initialExistingSet := make(map[string]struct{}, len(initialExisting))
	for _, root := range initialExisting {
		initialExistingSet[root.path] = struct{}{}
	}
	for _, root := range finalExisting {
		if _, candidateWasInitial := initialCandidates[root.path]; !candidateWasInitial {
			// The candidate-set issue above explains a root that was added by
			// WatchPaths during the pass. Avoid a duplicate issue here.
			continue
		}
		if _, existedInitially := initialExistingSet[root.path]; !existedInitially {
			report.incomplete = true
			report.addIssue(BudgetCaptureReasonIncomplete, fmt.Sprintf("watch root %s appeared during scan", root.path))
		}
	}
	for _, root := range initialExisting {
		info, err := os.Stat(root.path)
		if err != nil {
			report.incomplete = true
			report.addIssue(BudgetCaptureReasonIncomplete, fmt.Sprintf("watch root %s changed during scan: %v", root.path, err))
			continue
		}
		if !os.SameFile(root.info, info) {
			report.incomplete = true
			report.addIssue(BudgetCaptureReasonIncomplete, fmt.Sprintf("watch root %s changed identity during scan", root.path))
		}
	}
	return finalRoots
}

func budgetRootSet(roots []string) map[string]struct{} {
	set := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		if root != "" {
			set[root] = struct{}{}
		}
	}
	return set
}

func (w *Watcher) walkBudgetRoot(ctx context.Context, a adapter.Adapter, root string, report *budgetCaptureReport) {
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if ctx != nil && ctx.Err() != nil {
			report.incomplete = true
			report.addIssue(BudgetCaptureReasonCanceled, ctx.Err().Error())
			return ctx.Err()
		}
		if walkErr != nil {
			report.incomplete = true
			// A vanished entry is a race (a tool removing its own session
			// directory on a clean exit); anything else - a permission or I/O
			// error - is a subtree this node cannot read at all.
			report.addIssue(budgetWalkFailureReason(walkErr), fmt.Sprintf("walk %s: %v", path, walkErr))
			return nil
		}
		if entry == nil {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			// WalkDir deliberately does not follow directory symlinks. A
			// symlinked subtree can therefore contain an entire unscanned
			// source store without producing a walk error; fail closed rather
			// than claiming the visible tree was complete.
			info, err := os.Stat(path)
			if err != nil {
				report.incomplete = true
				report.addIssue(BudgetCaptureReasonIncomplete, fmt.Sprintf("stat symlink %s: %v", path, err))
				return nil
			}
			if info.IsDir() {
				// WalkDir never descends it, so an entire source store can sit
				// behind this link unread on every future pass too. That does
				// not resolve by waiting.
				report.incomplete = true
				report.addIssue(BudgetCaptureReasonUnreadable, fmt.Sprintf("walk skipped directory symlink %s", path))
				return nil
			}
		}
		if entry.IsDir() {
			report.recordDirectory(path)
			return nil
		}
		if !a.IsSessionFile(path) {
			return nil
		}
		sourceKey := budgetCaptureSourceKey(a, path)
		if report.sources == nil {
			report.sources = make(map[string]struct{})
		}
		if _, seen := report.sources[sourceKey]; seen {
			return nil
		}
		info, err := os.Stat(path)
		if err != nil {
			report.incomplete = true
			report.addIssue(BudgetCaptureReasonIncomplete, fmt.Sprintf("stat source %s: %v", path, err))
			return nil
		}
		if !info.Mode().IsRegular() {
			// A device, socket or FIFO in the session-file position is never
			// going to become a readable transcript.
			report.incomplete = true
			report.addIssue(BudgetCaptureReasonUnreadable, fmt.Sprintf("source %s is not a regular file", path))
			return nil
		}
		report.filesSeen++
		if w.reuseBudgetCaptureMemo(a, path, sourceKey, report) {
			return nil
		}
		out, err := w.processFileStrict(ctx, a, path)
		if out.beforeSnapshot != nil {
			if report.files == nil {
				report.files = make(map[string]budgetFileSnapshot)
			}
			report.files[path] = *out.beforeSnapshot
		}
		if err != nil {
			if ctx != nil && ctx.Err() != nil {
				report.incomplete = true
				report.addIssue(BudgetCaptureReasonCanceled, ctx.Err().Error())
				return ctx.Err()
			}
			report.addIssue(BudgetCaptureReasonParseError, fmt.Sprintf("%s: %v", path, err))
			return nil
		}
		if out.strictResult == nil {
			applyBudgetCaptureOutcome(report, path, out)
			return nil
		}
		if err := validateBudgetTokenEvents(path, out.strictResult.TokenEvents); err != nil {
			out.parseError = err
			out.strictResult = nil
			applyBudgetCaptureOutcome(report, path, out)
			return nil
		}
		report.sources[sourceKey] = struct{}{}
		report.pending = append(report.pending, budgetCapturePending{path: path, outcome: out})
		report.pendingEvents += len(out.strictResult.ToolEvents) + len(out.strictResult.TokenEvents)
		report.pendingBytes += info.Size()
		if len(report.pending) >= budgetCaptureBatchFiles || report.pendingEvents >= budgetCaptureBatchEvents || report.pendingBytes >= budgetCaptureBatchBytes {
			w.flushBudgetCaptureBatch(ctx, a, report)
		}
		return nil
	})
	if walkErr != nil {
		if ctx != nil && errors.Is(walkErr, ctx.Err()) {
			report.incomplete = true
			if ctx.Err() != nil {
				report.addIssue(BudgetCaptureReasonCanceled, ctx.Err().Error())
			}
			return
		}
		report.incomplete = true
		report.addIssue(budgetWalkFailureReason(walkErr), fmt.Sprintf("walk %s: %v", root, walkErr))
	}
}

// budgetWalkFailureReason separates a tree that MOVED from a tree this node
// cannot read. A vanished path is the ordinary signature of a tool managing
// its own store and must stay a delayed race; a permission or I/O error does
// not resolve by waiting, so it is structural.
func budgetWalkFailureReason(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return BudgetCaptureReasonIncomplete
	}
	return BudgetCaptureReasonUnreadable
}

// reuseBudgetCaptureMemo short-circuits a source that is byte-for-byte what the
// last strict pass already reconciled: it cannot hold new usage, so it costs
// one stat and no parse. The memoized snapshot still enters the report's file
// set, so the end-of-pass recheck reports a file that changes mid-pass as
// incomplete exactly as a parsed file would.
func (w *Watcher) reuseBudgetCaptureMemo(a adapter.Adapter, path, sourceKey string, report *budgetCaptureReport) bool {
	memo, ok := w.budgetCaptureMemo(a, path)
	if !ok {
		return false
	}
	if memo.parsed {
		report.filesProcessed++
	}
	if memo.evidence {
		report.evidence = true
	}
	if report.files == nil {
		report.files = make(map[string]budgetFileSnapshot)
	}
	report.files[path] = memo.snapshot
	report.sources[sourceKey] = struct{}{}
	return true
}

func (r *budgetCaptureReport) recordDirectory(path string) {
	info, err := os.Stat(path)
	if err != nil {
		r.incomplete = true
		r.addIssue(BudgetCaptureReasonIncomplete, fmt.Sprintf("stat directory %s: %v", path, err))
		return
	}
	if !info.IsDir() {
		r.incomplete = true
		r.addIssue(BudgetCaptureReasonIncomplete, fmt.Sprintf("walk directory %s changed to a non-directory", path))
		return
	}
	if r.directories == nil {
		r.directories = make(map[string]budgetDirectorySnapshot)
	}
	r.directories[path] = budgetDirectorySnapshot{path: path, info: info}
}

func (w *Watcher) flushBudgetCaptureBatch(ctx context.Context, a adapter.Adapter, report *budgetCaptureReport) {
	if len(report.pending) == 0 {
		return
	}
	pending := report.pending
	report.pending = nil
	report.pendingEvents = 0
	report.pendingBytes = 0

	var events []models.ToolEvent
	var tokens []models.TokenEvent
	var lineages []models.SessionLineage
	for i := range pending {
		res := pending[i].outcome.strictResult
		events = append(events, res.ToolEvents...)
		tokens = append(tokens, res.TokenEvents...)
		lineages = append(lineages, res.SessionLineages...)
	}
	result, err := w.store.IngestBudgetUsage(ctx, events, tokens, lineages)
	if err != nil {
		for i := range pending {
			w.forgetBudgetCapture(a, pending[i].path)
			pending[i].outcome.storeError = err
			applyBudgetCaptureOutcome(report, pending[i].path, pending[i].outcome)
		}
		return
	}
	if dropped := len(tokens) - result.TokensInserted; dropped > 0 {
		// The ingest owner drops a zero-usage event that names no session.
		// That hides no spend, so it is a warning rather than an unavailable
		// source; the count stays visible to an operator.
		report.warnings = append(report.warnings,
			fmt.Sprintf("%d zero-usage token events were not attachable to a session", dropped))
		report.addIssue(BudgetCaptureReasonWarnings,
			fmt.Sprintf("%d zero-usage token events were not attachable to a session", dropped))
	}
	for i := range pending {
		pending[i].outcome.parsed = true
		pending[i].outcome.sourceEvidence = len(pending[i].outcome.strictResult.TokenEvents) > 0
		// A clean pass memoizes its position and file metadata so the next
		// cycle can skip an unchanged source. A pass that produced any issue
		// (warning, retry hint, incomplete walk) deliberately does not: the
		// next cycle must re-examine it.
		if pending[i].outcome.clean() && pending[i].outcome.beforeSnapshot != nil {
			pending[i].outcome.sourceEvidence = w.rememberBudgetCapture(a, pending[i].path, budgetCaptureSeenEntry{
				snapshot: *pending[i].outcome.beforeSnapshot,
				offset:   pending[i].outcome.strictResult.NewOffset,
				parsed:   true,
				evidence: pending[i].outcome.sourceEvidence,
			})
		} else {
			w.forgetBudgetCapture(a, pending[i].path)
		}
		applyBudgetCaptureOutcome(report, pending[i].path, pending[i].outcome)
	}
}

// clean reports an outcome with no issue of any kind. Only a clean outcome may
// be memoized; anything else must be re-examined on the next pass.
func (o budgetCaptureFileOutcome) clean() bool {
	return o.strictResult != nil && o.parseError == nil && o.storeError == nil &&
		!o.parserPanic && !o.unsafeSymlink && !o.oversize && !o.incomplete &&
		!o.retrySuggested && len(o.warnings) == 0
}

// validateBudgetTokenEvents rejects usage rows whose accounting dimensions are
// absent. The ordinary ingest path intentionally tolerates partial token rows,
// but strict budget readiness cannot accept a nonzero event that will be
// inserted under a zero timestamp or without a session/model identity and then
// disappear from a requested accounting window.
func validateBudgetTokenEvents(path string, tokens []models.TokenEvent) error {
	for i, token := range tokens {
		if !budgetTokenHasUsage(token) {
			continue
		}
		switch {
		case token.SessionID == "":
			return fmt.Errorf("%s token event %d has nonzero usage but no session id; accounting is incomplete", path, i)
		case token.Model == "":
			return fmt.Errorf("%s token event %d has nonzero usage but no model; accounting is incomplete", path, i)
		case token.Timestamp.IsZero():
			return fmt.Errorf("%s token event %d has nonzero usage but no timestamp; accounting is incomplete", path, i)
		}
	}
	return nil
}

func budgetTokenHasUsage(token models.TokenEvent) bool {
	return token.InputTokens != 0 ||
		token.OutputTokens != 0 ||
		token.CacheReadTokens != 0 ||
		token.CacheCreationTokens != 0 ||
		token.CacheCreation1hTokens != 0 ||
		token.ReasoningTokens != 0 ||
		token.WebSearchRequests != 0 ||
		token.EstimatedCostUSD != 0
}

func applyBudgetCaptureOutcome(report *budgetCaptureReport, path string, out budgetCaptureFileOutcome) {
	if out.parsed {
		report.filesProcessed++
	}
	if out.sourceEvidence {
		report.evidence = true
	}
	if out.parserPanic {
		report.addIssue(BudgetCaptureReasonParserPanic, path)
	}
	if out.unsafeSymlink {
		report.addIssue(BudgetCaptureReasonUnsafeSymlink, path)
	}
	if out.oversize {
		report.addIssue(BudgetCaptureReasonOversizeFile, path)
	}
	if out.incomplete {
		report.incomplete = true
		report.addIssue(BudgetCaptureReasonIncomplete, out.incompleteDetail)
	}
	if out.parseError != nil || out.storeError != nil {
		err := out.parseError
		if err == nil {
			err = out.storeError
		}
		report.addIssue(BudgetCaptureReasonParseError, fmt.Sprintf("%s: %v", path, err))
	}
	if len(out.warnings) > 0 {
		report.warnings = append(report.warnings, out.warnings...)
		report.addIssue(BudgetCaptureReasonWarnings, fmt.Sprintf("%s: %s", path, strings.Join(out.warnings, "; ")))
	}
	if out.retrySuggested {
		report.addIssue(BudgetCaptureReasonRetrySuggested, path)
	}
}

func (w *Watcher) checkBudgetDirectories(report *budgetCaptureReport) {
	if len(report.directories) == 0 {
		return
	}
	paths := make([]string, 0, len(report.directories))
	for path := range report.directories {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		snapshot := report.directories[path]
		info, err := os.Stat(path)
		if err != nil {
			report.incomplete = true
			report.addIssue(BudgetCaptureReasonIncomplete, fmt.Sprintf("stat directory %s after scan: %v", path, err))
			continue
		}
		if !info.IsDir() {
			report.incomplete = true
			report.addIssue(BudgetCaptureReasonIncomplete, fmt.Sprintf("directory %s changed to a non-directory", path))
			continue
		}
		if !os.SameFile(snapshot.info, info) {
			report.incomplete = true
			report.addIssue(BudgetCaptureReasonIncomplete, fmt.Sprintf("directory %s changed identity during scan", path))
			continue
		}
		if !snapshot.info.ModTime().Equal(info.ModTime()) {
			report.incomplete = true
			report.addIssue(BudgetCaptureReasonIncomplete, fmt.Sprintf("directory %s changed during scan", path))
		}
	}
}

func (w *Watcher) checkBudgetFiles(report *budgetCaptureReport) {
	if len(report.files) == 0 {
		return
	}
	paths := make([]string, 0, len(report.files))
	for path := range report.files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		before := report.files[path]
		after, err := strictBudgetFileSnapshotFromInfo(path, before.semantics)
		if err != nil {
			report.incomplete = true
			report.addIssue(BudgetCaptureReasonIncomplete, fmt.Sprintf("stat source %s after adapter scan: %v", path, err))
			continue
		}
		if detail := strictBudgetFileChange(before, after); detail != "" {
			report.incomplete = true
			report.addIssue(BudgetCaptureReasonIncomplete, fmt.Sprintf("%s: %s", path, detail))
		}
	}
}

func strictBudgetFileSnapshot(a adapter.Adapter, path string) (budgetFileSnapshot, error) {
	info, err := os.Stat(path)
	if err != nil {
		return budgetFileSnapshot{}, fmt.Errorf("stat source %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return budgetFileSnapshot{}, fmt.Errorf("source %s is not a regular file", path)
	}
	semantics := adapter.FileCursorSemantics{}
	if declared, ok := a.(adapter.CursorSemantics); ok {
		semantics = declared.CursorSemanticsFor(path)
	}
	return strictBudgetFileSnapshotWithInfo(path, info, semantics)
}

func strictBudgetFileSnapshotFromInfo(path string, semantics adapter.FileCursorSemantics) (budgetFileSnapshot, error) {
	info, err := os.Stat(path)
	if err != nil {
		return budgetFileSnapshot{}, fmt.Errorf("stat source %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return budgetFileSnapshot{}, fmt.Errorf("source %s is not a regular file", path)
	}
	return strictBudgetFileSnapshotWithInfo(path, info, semantics)
}

func strictBudgetFileSnapshotWithInfo(path string, info os.FileInfo, semantics adapter.FileCursorSemantics) (budgetFileSnapshot, error) {
	snapshot := budgetFileSnapshot{info: info, semantics: semantics}
	if semantics.Kind != adapter.CursorWatermark {
		return snapshot, nil
	}
	for _, sibling := range budgetSQLiteFamily(path) {
		siblingInfo, err := os.Stat(sibling)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				snapshot.sqliteFiles = append(snapshot.sqliteFiles, budgetSQLiteFileSnapshot{path: sibling})
				continue
			}
			return budgetFileSnapshot{}, fmt.Errorf("stat SQLite source %s: %w", sibling, err)
		}
		if !siblingInfo.Mode().IsRegular() {
			return budgetFileSnapshot{}, fmt.Errorf("SQLite source %s is not a regular file", sibling)
		}
		snapshot.sqliteFiles = append(snapshot.sqliteFiles, budgetSQLiteFileSnapshot{
			path:   sibling,
			exists: true,
			info:   siblingInfo,
		})
	}
	return snapshot, nil
}

// budgetSQLiteFamily returns the primary file and the SQLite sidecars for a
// recognized database spelling. Non-SQLite watermark files such as rewritten
// JSON indexes return no family and use ordinary file stability checks.
func budgetSQLiteFamily(path string) []string {
	base := path
	lower := strings.ToLower(base)
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if strings.HasSuffix(lower, suffix) {
			base = base[:len(base)-len(suffix)]
			lower = lower[:len(lower)-len(suffix)]
			break
		}
	}
	if !strings.HasSuffix(lower, ".db") &&
		!strings.HasSuffix(lower, ".sqlite") &&
		!strings.HasSuffix(lower, ".sqlite3") &&
		!strings.HasSuffix(lower, ".vscdb") {
		return nil
	}
	return []string{base, base + "-wal", base + "-shm", base + "-journal"}
}

func budgetCaptureSourceKey(a adapter.Adapter, path string) string {
	semantics := adapter.FileCursorSemantics{}
	if declared, ok := a.(adapter.CursorSemantics); ok {
		semantics = declared.CursorSemanticsFor(path)
	}
	if semantics.Kind == adapter.CursorWatermark {
		if family := budgetSQLiteFamily(path); len(family) > 0 {
			return family[0]
		}
	}
	return path
}

func strictBudgetFileChange(before, after budgetFileSnapshot) string {
	if !os.SameFile(before.info, after.info) {
		return "source file identity changed during scan"
	}
	// SQLite stores require main/WAL/journal checks. Other watermark sources
	// (for example a rewritten JSON index) still require a stable file. The
	// cursor is never compared to file size here; only before/after metadata is.
	if before.semantics.Kind == adapter.CursorWatermark && len(before.sqliteFiles) > 0 {
		return strictBudgetSQLiteChange(before.sqliteFiles, after.sqliteFiles)
	}
	if before.info.Size() != after.info.Size() {
		return fmt.Sprintf("source file size changed during scan (%d to %d bytes)", before.info.Size(), after.info.Size())
	}
	if !before.info.ModTime().Equal(after.info.ModTime()) {
		return "source file modification time changed during scan"
	}
	return ""
}

func strictBudgetSQLiteChange(before, after []budgetSQLiteFileSnapshot) string {
	if len(before) == 0 && len(after) == 0 {
		return ""
	}
	if len(before) != len(after) {
		return "SQLite source family changed during scan"
	}
	for i := range before {
		oldFile, newFile := before[i], after[i]
		if oldFile.path != newFile.path {
			return "SQLite source family changed during scan"
		}
		// SQLite's shared-memory index is a derived reader coordination file.
		// Opening a WAL database can create or rewrite it without changing the
		// database contents. The main database, WAL, and rollback journal remain
		// authoritative for this conservative mutation check.
		if budgetSQLiteDerivedSidecar(oldFile.path) {
			continue
		}
		if oldFile.exists != newFile.exists {
			return fmt.Sprintf("SQLite companion %s appeared or disappeared during scan", oldFile.path)
		}
		if !oldFile.exists {
			continue
		}
		if !os.SameFile(oldFile.info, newFile.info) {
			return fmt.Sprintf("SQLite companion %s identity changed during scan", oldFile.path)
		}
		if oldFile.info.Size() != newFile.info.Size() {
			return fmt.Sprintf("SQLite companion %s size changed during scan (%d to %d bytes)", oldFile.path, oldFile.info.Size(), newFile.info.Size())
		}
		if !oldFile.info.ModTime().Equal(newFile.info.ModTime()) {
			return fmt.Sprintf("SQLite companion %s modification time changed during scan", oldFile.path)
		}
	}
	return ""
}

func budgetSQLiteDerivedSidecar(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), "-shm")
}

// chooseBudgetIssue picks the ONE issue an operator reads. It is a
// readability ranking - the broadest cause first - and it is deliberately NOT
// the accounting authority: the structural reasons sit at the bottom of this
// order, so classifying a pass by the issue it returns would let a routine
// mid-pass race hide an unreadable or oversize source. budgetIssuesClass
// answers for every issue instead.
func chooseBudgetIssue(issues []budgetCaptureIssue) budgetCaptureIssue {
	priority := map[string]int{
		BudgetCaptureReasonCanceled:       0,
		BudgetCaptureReasonIncomplete:     1,
		BudgetCaptureReasonMissingRoot:    2,
		BudgetCaptureReasonParserPanic:    3,
		BudgetCaptureReasonParseError:     4,
		BudgetCaptureReasonWarnings:       5,
		BudgetCaptureReasonRetrySuggested: 6,
		BudgetCaptureReasonOversizeFile:   7,
		BudgetCaptureReasonUnsafeSymlink:  8,
		BudgetCaptureReasonUnreadable:     9,
	}
	best := issues[0]
	for _, issue := range issues[1:] {
		if priority[issue.reason] < priority[best.reason] {
			best = issue
		}
	}
	return best
}
