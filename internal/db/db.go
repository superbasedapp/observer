package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/migrations"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"

	sqlite "modernc.org/sqlite" // sqlite driver registration + typed errors.
)

// Options configures the SQLite database.
type Options struct {
	// Path is the filesystem location of the SQLite database. Use ":memory:"
	// for an in-memory instance (intended for tests).
	Path string

	// BusyTimeout is the SQLite busy_timeout pragma value. Defaults to 30s.
	//
	// 30s headroom matches the migration-runner's own busy_timeout (set
	// on its pinned connection at runMigrations:148) and absorbs WAL
	// write contention when a second writer process — typically
	// `observer backfill --all` while `observer start` is also running
	// — competes for the write lock. The previous 5s default produced
	// SQLITE_BUSY on multi-thousand-row backfill batches against a busy
	// watcher.
	BusyTimeout time.Duration

	// IntegrityCheck opts IN to the `PRAGMA quick_check` probe (and the
	// one-time schema-034 path-hash backfill) at the end of Open. It is
	// OFF by default, and that default is deliberate: quick_check reads
	// and checksums EVERY PAGE of the file, so its cost scales with the
	// database, not with the work the caller came to do. On the reference
	// 14.7 GB install it costs >120s — measured, not estimated.
	//
	// The polarity was inverted on 2026-07-28 after the same defect
	// recurred FOUR times under the old opt-out spelling
	// (`SkipIntegrityCheck`): the MCP server (2026-07-06), the daemon
	// (2026-07-16), `observer run` (2026-07-23, re-measured 0.16s vs
	// >120s), and finally every read-only reporting command via
	// cmd/observer's loadConfigAndDB — 85 call sites that each paid a
	// full-database checksum to print a table. An opt-out flag has to be
	// remembered at every new call site and is silent when forgotten; an
	// opt-in flag fails safe. Memory note
	// `feedback_hook_db_open_no_timeout` captured the original contention.
	//
	// Do NOT set this to make a caller "safe". The probe is a diagnostic,
	// not a guard — nothing downstream consumes its result, so a caller
	// that enables it only pays for it. The long-running daemon runs the
	// probe + backfill EXACTLY ONCE, off its readiness path, via
	// [RunStartupMaintenance] on a background goroutine after the listener
	// is already serving; `observer doctor` runs its own quick_check as
	// the reported `db.integrity` check (internal/diag/doctor.go). Both
	// are better homes for it than Open. The one caller that legitimately
	// sets it is `observer db import`, which validates an UNTRUSTED
	// foreign database file before merging it into the live one.
	IntegrityCheck bool

	// MaxOpenConns bounds the pool (see [database/sql.DB.SetMaxOpenConns]).
	// Zero (unset) applies the built-in default of 16 — generous enough for
	// proxy + watcher + dashboard + hook subprocesses to run concurrently
	// without opening an unbounded number of physical connections, each of
	// which is a candidate temp-file holder under the pragmas below. Go's
	// SetMaxOpenConns(0) means unlimited, which is exactly what this field
	// exists to avoid, so there is no "explicitly unlimited" sentinel here
	// — a caller that truly wants that can call SetMaxOpenConns(0) on the
	// returned *sql.DB itself.
	MaxOpenConns int

	// ConnMaxIdleTime bounds how long an idle pooled connection is kept
	// before being closed (see [database/sql.DB.SetConnMaxIdleTime]). Zero
	// (unset) applies a 5-minute default, reaping idle connections so a
	// bursty caller doesn't pin a pool's worth of physical connections
	// (and their per-connection temp-file state) open indefinitely.
	ConnMaxIdleTime time.Duration

	// HardHeapLimitBytes sets `PRAGMA hard_heap_limit` on the DSN so it
	// applies to EVERY pooled connection (see applyPragmas's comment for
	// why the DSN, not a post-open ExecContext, is the only place this can
	// be applied correctly). SQLite's heap limit is process-global —
	// verified empirically (2026-08-26, modernc.org/sqlite v1.48.2): once
	// any connection in the process sets it, a later connection that opens
	// WITHOUT the pragma still reads the same limit back. Every connection
	// re-setting the same value on open is therefore idempotent, not
	// additive. This is the in-memory backstop: it bounds SQLite's
	// page-cache / in-memory sort growth so a pathological query fails fast
	// with SQLITE_NOMEM instead of exhausting host RAM. (With the default
	// TempStore == "file", temp b-trees and VACUUM scratch go to disk and
	// are NOT bounded by this — that is deliberate; see TempStore.) Zero
	// (unset)
	// applies a 1 GiB default. A NEGATIVE value explicitly disables the
	// pragma (omitted from the DSN entirely) — the standing zero-means-
	// unset / negative-means-disabled convention used elsewhere in this
	// codebase (see internal/processobs/lateseed.go). `hard_heap_limit`
	// confirmed accepted as a `_pragma=` DSN term by modernc.org/sqlite
	// v1.48.2 (2026-08-26 verification for the disk/compute remediation
	// plan; see docs/plans/observer-disk-compute-remediation-plan-
	// 2026-08-26.md Phase 1, T1.6).
	HardHeapLimitBytes int64

	// TempStore selects `PRAGMA temp_store` on the DSN: "file" (SQLite
	// value 1 — spill temp b-trees/VACUUM scratch to disk), "memory"
	// (SQLite value 2 — hold temp in RAM, bounded by HardHeapLimitBytes),
	// or "default" (omit the pragma; whatever the build ships with). Empty
	// (unset) applies "file".
	//
	// FILE is the default deliberately (docs/plans/observer-disk-compute-
	// remediation-plan-2026-08-26.md Phase 1, revised 2026-08-26): once the
	// automatic looping VACUUM (P0-A) is removed and the recurring
	// unindexed sorts (P1-C) are de-spilled, disk-backed temp no longer
	// runs away — while MEMORY would silently break the one legitimate
	// heavy path left, the operator's `observer prune --vacuum`, which on a
	// multi-GB DB builds a whole-file temp copy that MEMORY would try to
	// hold in RAM and fail SQLITE_NOMEM against HardHeapLimitBytes (or OOM
	// the host without it). FILE keeps that VACUUM working and can never
	// OOM; HardHeapLimitBytes still bounds in-memory page-cache/sort
	// growth, and any residual disk spill is bounded + surfaced by the
	// temp watchdog (cmd/observer/tempwatch.go). The per-connection
	// CONSISTENCY of this pragma across the pool — via the DSN, not a
	// post-open ExecContext — is the actual P0-B fix; FILE-vs-MEMORY is the
	// value, and FILE is the safe one.
	TempStore string
}

// SQLite's own `PRAGMA temp_store` / `PRAGMA synchronous` integer values,
// used when rendering DSN `_pragma=` terms.
const (
	sqliteTempStoreFile     = 1
	sqliteTempStoreMemory   = 2
	sqliteSynchronousNormal = 1 // NORMAL; matches internal/edge/wal/store.go.
)

// defaultMaxOpenConns, defaultConnMaxIdleTime, and defaultHardHeapLimitBytes
// are the Options zero-value fallbacks applied inside Open — see the
// matching Options field doc comments for the rationale.
const (
	defaultMaxOpenConns       = 16
	defaultConnMaxIdleTime    = 5 * time.Minute
	defaultHardHeapLimitBytes = int64(1) << 30 // 1 GiB
)

// dsnTempStoreAndHeapTerms renders the `&_pragma=temp_store(N)` and
// `&_pragma=hard_heap_limit(N)` DSN terms for the given resolved
// (defaults-applied) TempStore mode and heap-limit byte count. tempStore ==
// "default" and hardHeapLimitBytes <= 0 each omit their own term — see
// Options.TempStore / Options.HardHeapLimitBytes for what each mode means.
func dsnTempStoreAndHeapTerms(tempStore string, hardHeapLimitBytes int64) string {
	var b strings.Builder
	switch tempStore {
	case "memory":
		fmt.Fprintf(&b, "&_pragma=temp_store(%d)", sqliteTempStoreMemory)
	case "default":
		// Omit the pragma entirely — inherit the driver/SQLite default.
	default: // "file" (also the fallback for an unrecognized value) — the
		// safe, never-OOM choice: a large operator VACUUM or a pathological
		// unindexed sort spills to disk (bounded, surfaced by the temp
		// watchdog) rather than failing SQLITE_NOMEM against hard_heap_limit
		// or exhausting host RAM.
		fmt.Fprintf(&b, "&_pragma=temp_store(%d)", sqliteTempStoreFile)
	}
	if hardHeapLimitBytes > 0 {
		fmt.Fprintf(&b, "&_pragma=hard_heap_limit(%d)", hardHeapLimitBytes)
	}
	return b.String()
}

// Open opens (or creates) the SQLite database at opts.Path, enables WAL mode,
// and applies any pending migrations. The returned *sql.DB is safe for
// concurrent use.
//
// Open does NOT verify the database. The `PRAGMA quick_check` probe is opt-in
// via Options.IntegrityCheck and costs a full-file checksum — see that field
// for why the default is off and where the probe actually lives.
//
// Under `go test`, Open REFUSES a path inside the operator's real ~/.observer
// directory and returns [ErrRealDBInTest] before creating a file or running a
// migration. See [AllowRealDBInTestEnv] for the deliberate escape hatch and
// testguard.go for the incident that motivated it. Production behaviour is
// unchanged.
//
// Concurrency note: every transaction acquires the SQLite write lock
// upfront via _txlock=immediate. The default BEGIN DEFERRED behavior
// would take a read lock at BeginTx and try to upgrade to a write lock
// at the first write — when two writers race that upgrade, one gets
// SQLITE_BUSY immediately (busy_timeout doesn't kick in on
// upgrade-deadlocks). BEGIN IMMEDIATE serializes writers through the
// file lock so busy_timeout's exponential backoff handles contention
// properly. All five BeginTx callers in this codebase
// (store.InsertActions, store.InsertTokenEvents, store.UpsertGuidanceScan,
// retention.deleteActionsOlder, indexing.EmbedBatch) are write-only, so
// the IMMEDIATE upgrade is always correct — no read-only tx is being
// unnecessarily serialized.
func Open(ctx context.Context, opts Options) (*sql.DB, error) {
	if opts.Path == "" {
		return nil, errors.New("db.Open: Path is required")
	}
	// Live-DB test isolation gate (incident "task #17", 2026-07-30). Inert in
	// production — see GuardLiveDB. This must stay ABOVE sql.Open: the whole
	// point is that no file is created and no migration runs.
	if err := GuardLiveDB(opts.Path); err != nil {
		return nil, err
	}
	busy := opts.BusyTimeout
	if busy <= 0 {
		busy = 30 * time.Second
	}
	maxOpenConns := opts.MaxOpenConns
	if maxOpenConns == 0 {
		maxOpenConns = defaultMaxOpenConns
	}
	connMaxIdleTime := opts.ConnMaxIdleTime
	if connMaxIdleTime == 0 {
		connMaxIdleTime = defaultConnMaxIdleTime
	}
	// Zero means "unset, apply the default"; negative means "explicitly
	// disabled" — see the Options.HardHeapLimitBytes doc comment.
	hardHeapLimitBytes := opts.HardHeapLimitBytes
	if hardHeapLimitBytes == 0 {
		hardHeapLimitBytes = defaultHardHeapLimitBytes
	} else if hardHeapLimitBytes < 0 {
		hardHeapLimitBytes = 0
	}
	tempStore := opts.TempStore
	if tempStore == "" {
		tempStore = "file"
	}

	// Pin the memory/durability pragmas on the DSN so modernc.org/sqlite
	// applies them to EVERY pooled connection the *sql.DB ever opens —
	// applyPragmas below runs its ExecContext calls against whatever ONE
	// connection the pool happens to hand it, which silently left every
	// OTHER connection on SQLite's compile-time defaults (TEMP_STORE=1,
	// file-backed). That gap is the root cause of the P0-B disk-exhaustion
	// incident: `temp_store=MEMORY` applied to one connection meant every
	// other connection's sort/hash/VACUUM temp spilled, unmonitored, to
	// /var/tmp. See docs/plans/observer-disk-compute-remediation-plan-
	// 2026-08-26.md Phase 1 and internal/edge/wal/store.go, which fixed
	// this class for journal_mode/synchronous but not temp_store, and not
	// here. hard_heap_limit is included for the same per-connection
	// reason, even though the underlying SQLite limit is process-global
	// (re-setting the same value on each connection is idempotent) — it
	// bounds in-memory page-cache / sort growth so a pathological query
	// fails fast with SQLITE_NOMEM instead of exhausting host RAM. temp
	// b-trees and VACUUM scratch default to disk (temp_store=file — see
	// Options.TempStore for why FILE, not MEMORY), so a large operator
	// VACUUM still succeeds; the temp watchdog surfaces any runaway spill.
	dsn := opts.Path
	if opts.Path != ":memory:" {
		dsn = fmt.Sprintf("file:%s?_pragma=busy_timeout(%d)&_pragma=foreign_keys(1)&_pragma=synchronous(%d)%s&_txlock=immediate",
			sqlitedsn.Escape(opts.Path), busy.Milliseconds(), sqliteSynchronousNormal,
			dsnTempStoreAndHeapTerms(tempStore, hardHeapLimitBytes))
	}

	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("db.Open: sql.Open: %w", err)
	}
	database.SetMaxOpenConns(maxOpenConns)
	database.SetConnMaxIdleTime(connMaxIdleTime)
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("db.Open: ping: %w", err)
	}

	if err := applyPragmas(ctx, database, opts.Path); err != nil {
		_ = database.Close()
		return nil, err
	}
	if err := runMigrations(ctx, database); err != nil {
		_ = database.Close()
		return nil, err
	}
	// Migration 034 (v1.8.0) added denormalized SHA256 hash columns for
	// org-push privacy. The schema change is a NOT NULL DEFAULT '' column
	// add so existing rows pass the constraint immediately, but the org
	// push seam reads the hash columns — leaving them empty would ship
	// degenerate empty hashes. Backfill them here in Go (modernc/sqlite
	// has no built-in sha256 SQL function). Idempotent: only updates rows
	// where the hash column is empty AND the source value is non-empty.
	//
	// Gated by IntegrityCheck (Ticket A, 2026-07-12; polarity inverted
	// 2026-07-28): the backfill issues an UNINDEXED `WHERE
	// source_file_hash = ''` scan of the `actions` / `token_usage` tables —
	// on a multi-GB `actions` table under WAL contention that full-scan
	// dominated the hook-path `db.Open` latency (~100s stalls), even though
	// it finds 0 rows on any already-backfilled DB. It short-circuits on a
	// schema_meta done-marker after the first successful pass, so the one
	// process that does run it — the daemon, via [RunStartupMaintenance] —
	// pays the scan at most once per DB. See docs/plans/claude-code-hook-
	// stall-ticket-and-db-prune-plan-2026-07-12.md.
	if opts.IntegrityCheck {
		if err := backfillPathHashes(ctx, database); err != nil {
			_ = database.Close()
			return nil, err
		}
		if err := integrityCheck(ctx, database); err != nil {
			_ = database.Close()
			return nil, err
		}
	}
	return database, nil
}

func applyPragmas(ctx context.Context, db *sql.DB, path string) error {
	if path != ":memory:" {
		// WAL mode is incompatible with in-memory databases.
		//
		// The conversion out of rollback-journal mode (first-ever open of
		// a fresh DB) needs an EXCLUSIVE lock. Among N simultaneous first
		// openers — `observer start` bringing up proxy + watcher +
		// dashboard against a new DB, or a bridged hook racing the
		// daemon's first start — two connections can each hold a SHARED
		// lock while both requesting the upgrade, and SQLite reports
		// SQLITE_BUSY immediately WITHOUT invoking the busy handler (the
		// same upgrade-deadlock class BEGIN IMMEDIATE solves for
		// transactions; see Open's doc comment). Retry with backoff: the
		// winner converts in milliseconds, and every later attempt sees
		// journal_mode already WAL, which no longer needs the lock.
		if err := execRetryBusy(ctx, db, "PRAGMA journal_mode = WAL", 5*time.Second); err != nil {
			return err
		}
	}
	// synchronous and temp_store used to be set HERE, post-open — which
	// only reaches the one pooled connection database/sql happened to
	// hand ExecContext, leaving every OTHER connection on SQLite's
	// defaults (this was the P0-B disk-exhaustion root cause; see Open's
	// dsn construction above). They are now DSN `_pragma=` terms so every
	// connection the pool ever opens carries them — do not re-add them
	// here. foreign_keys is likewise already a DSN term for the
	// file-backed path; it stays here too as a harmless idempotent
	// belt-and-suspenders that also covers ":memory:", whose DSN carries
	// no pragma terms at all.
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("db.Open: PRAGMA foreign_keys = ON: %w", err)
	}
	return nil
}

// execRetryBusy executes stmt, retrying on SQLITE_BUSY until window
// elapses. Only lock contention is retried — every other error (and a
// still-busy statement past the deadline) is returned wrapped.
func execRetryBusy(ctx context.Context, db *sql.DB, stmt string, window time.Duration) error {
	deadline := time.Now().Add(window)
	for {
		_, err := db.ExecContext(ctx, stmt)
		if err == nil {
			return nil
		}
		if !isBusy(err) || ctx.Err() != nil || time.Now().After(deadline) {
			return fmt.Errorf("db.Open: %s: %w", stmt, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// isBusy reports whether err is SQLITE_BUSY (primary code 5, including
// extended busy codes such as SQLITE_BUSY_RECOVERY, whose low byte is 5).
func isBusy(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code()&0xff == 5
	}
	return false
}

// IsTransientWriteError reports whether err is a SQLite failure that the SAME
// statement is expected to survive on a later attempt with no change to the
// data — lock contention, and nothing else.
//
// It is the exported, structured answer to "should this write be retried
// rather than dropped", and it exists so callers outside this package do not
// re-derive it by matching on message text (which has been reworded across
// driver versions). Two primary codes qualify, and deliberately no others:
//
//	SQLITE_BUSY   (5) — another CONNECTION holds the write lock; also covers
//	                    the extended busy codes (SQLITE_BUSY_SNAPSHOT,
//	                    SQLITE_BUSY_RECOVERY, …) whose low byte is 5.
//	SQLITE_LOCKED (6) — a conflicting lock within the SAME connection/cache.
//
// Everything else — constraint violations, schema drift, read-only handles,
// I/O errors, a full disk — is left to the caller. Some of those are
// genuinely permanent and some are merely ambiguous, and this function
// refuses to flatten that distinction into a bare false.
func IsTransientWriteError(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 0xff {
		case 5, 6:
			return true
		}
	}
	return false
}

// integrityCheckTimeout bounds a single `PRAGMA quick_check` run (T2.2,
// 2026-08-26 disk/compute remediation plan, P1-D). quick_check has no
// built-in deadline of its own — it just keeps checksumming pages — so a
// pathological file (or one on a stalled/degraded filesystem) could hang
// the background maintenance goroutine indefinitely. 10 minutes is well
// above the >120s measured cost on the 14.7 GB reference install; a probe
// that is genuinely still running past this is more useful reported as a
// timeout (logged, non-fatal) than left to hang silently.
const integrityCheckTimeout = 10 * time.Minute

// RunStartupMaintenance runs the post-open, one-time-per-DB work the daemon
// otherwise pays for inside [Open]: the schema-034 path-hash backfill
// (idempotent — short-circuits on a schema_meta done-marker after the first
// pass) followed by the `PRAGMA quick_check` integrity probe.
//
// It exists so the long-running daemon can move this work OFF its readiness
// path. On a multi-GB DB quick_check reads and checksums every page (tens of
// seconds of CPU), so running it inside every daemon db.Open — proxy,
// watcher, and dashboard each open the same file synchronously before the
// listener binds — delayed `observer start` becoming ready by minutes. The
// daemon opens without the probe (the default) and calls this once
// from a single background goroutine after it is already serving. A
// corruption result is returned as an error for the caller to log loudly.
//
// Idempotent and safe to call from exactly one goroutine per process; do not
// fan it out (the underlying quick_check has no benefit run twice).
//
// T2.2 (2026-08-26 disk/compute remediation plan, P1-D): on a very large
// DB even a single quick_check pass is expensive enough that the daemon
// should skip it automatically and rely on the on-demand `observer doctor`
// path instead. Callers that need to size-gate the probe (rather than
// unconditionally running it, as this function does) should call
// [RunStartupBackfillOnly] for the cheap always-run half and reach for
// their own db.RunStartupMaintenance-equivalent when under the threshold
// — see cmd/observer/diag.go::runStartupDBMaintenance for the wiring.
func RunStartupMaintenance(ctx context.Context, database *sql.DB) error {
	if err := backfillPathHashes(ctx, database); err != nil {
		return fmt.Errorf("db.RunStartupMaintenance: backfill path hashes: %w", err)
	}
	if err := integrityCheck(ctx, database); err != nil {
		return fmt.Errorf("db.RunStartupMaintenance: %w", err)
	}
	return nil
}

// RunStartupBackfillOnly runs just the schema-034 path-hash backfill half
// of [RunStartupMaintenance] — the cheap, idempotent pass (short-circuits
// on its schema_meta done-marker after the first successful run) — without
// the expensive `PRAGMA quick_check`. It exists for a caller that has
// decided to skip the integrity probe (T2.2's size gate: a DB over
// [observer.db].integrity_check_max_gb) but still wants the backfill kept
// current every startup.
func RunStartupBackfillOnly(ctx context.Context, database *sql.DB) error {
	if err := backfillPathHashes(ctx, database); err != nil {
		return fmt.Errorf("db.RunStartupBackfillOnly: backfill path hashes: %w", err)
	}
	return nil
}

// Integrity verdict statuses. A CLOSED vocabulary, because the three outcomes
// are genuinely different and a surface must not flatten them: a probe that
// could not RUN is not the same as one that ran and found damage, and calling a
// timeout "corrupt" would send an operator to restore a healthy database.
const (
	// IntegrityOK is a completed `PRAGMA quick_check` that reported "ok".
	IntegrityOK = "ok"
	// IntegrityCorrupt is a completed probe that reported damage.
	IntegrityCorrupt = "corrupt"
	// IntegrityError is a probe that did not complete — a timeout, a locked
	// or unreadable file. Says nothing about the data either way.
	IntegrityError = "error"
)

// integrityVerdictKey is the schema_meta key holding the JSON-encoded verdict
// of the most recent `PRAGMA quick_check`. schema_meta is the existing
// node-local key-value store (migration 001), so persisting here adds NO table
// and NO migration — see RES-3 in docs/audits/codebase-audit-2026-09-16.md.
const integrityVerdictKey = "integrity_verdict"

// IntegrityVerdict is the persisted outcome of the daemon's background
// `PRAGMA quick_check` (RES-3, codebase audit 2026-09-16).
//
// Before this the probe's only output was one ERROR log line. A daemon runs
// unattended, its log is usually unread, and nothing on `observer status` or
// the dashboard said a word — so a corrupt database silently degraded capture
// until somebody happened to run `observer doctor`. Recording the verdict where
// the health surfaces already read turns "you had to know to look" into "it is
// on the screen you were already looking at".
//
// Spec §17's quarantine-and-recreate is deliberately still NOT implemented: the
// safer behavior on a corruption report is to keep the file intact for the
// operator (and for `observer doctor`) rather than to move it aside
// automatically. This makes that choice legible instead of silent.
type IntegrityVerdict struct {
	// CheckedAt is when the probe finished (UTC).
	CheckedAt time.Time `json:"checked_at"`
	// Status is one of IntegrityOK / IntegrityCorrupt / IntegrityError.
	Status string `json:"status"`
	// Message is the pragma's own text, or the error's, for a non-ok status.
	// Empty when Status is IntegrityOK.
	Message string `json:"message,omitempty"`
}

// OK reports whether the verdict is a clean completed probe.
func (v IntegrityVerdict) OK() bool { return v.Status == IntegrityOK }

// LastIntegrityVerdict returns the most recently recorded verdict, and whether
// one has been recorded at all. A missing verdict (ok=false) means the probe
// has not run on this database yet — a fresh install, or one where the startup
// probe is size-gated off by [observer.db].integrity_check_max_gb. That is NOT
// a failure and callers must not render it as one.
//
// A malformed stored value is reported as an error rather than silently
// treated as absent: the difference between "never checked" and "the record is
// unreadable" matters to the operator reading it.
func LastIntegrityVerdict(ctx context.Context, db *sql.DB) (IntegrityVerdict, bool, error) {
	var raw string
	err := db.QueryRowContext(ctx,
		`SELECT value FROM schema_meta WHERE key = ?`, integrityVerdictKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return IntegrityVerdict{}, false, nil
	}
	if err != nil {
		return IntegrityVerdict{}, false, fmt.Errorf("db.LastIntegrityVerdict: %w", err)
	}
	var v IntegrityVerdict
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return IntegrityVerdict{}, false, fmt.Errorf("db.LastIntegrityVerdict: decode: %w", err)
	}
	return v, true, nil
}

// recordIntegrityVerdict upserts the verdict into schema_meta.
//
// BEST EFFORT BY CONTRACT: the write is attempted on the very database the
// probe may have just called corrupt, so it can legitimately fail. The caller
// ignores that error and returns the PROBE's result — a failed bookkeeping
// write must never mask, or manufacture, an integrity result.
func recordIntegrityVerdict(ctx context.Context, db *sql.DB, v IntegrityVerdict) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("db.recordIntegrityVerdict: encode: %w", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO schema_meta(key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		integrityVerdictKey, string(body)); err != nil {
		return fmt.Errorf("db.recordIntegrityVerdict: %w", err)
	}
	return nil
}

func integrityCheck(ctx context.Context, db *sql.DB) error {
	probeCtx, cancel := context.WithTimeout(ctx, integrityCheckTimeout)
	defer cancel()
	// The verdict write uses the PARENT context, not probeCtx: a probe that
	// exhausted its own deadline has a cancelled probeCtx, and recording
	// "error" is exactly what we want to do in that case.
	record := func(status, msg string) {
		_ = recordIntegrityVerdict(ctx, db, IntegrityVerdict{
			CheckedAt: time.Now().UTC(), Status: status, Message: msg,
		})
	}
	var result string
	if err := db.QueryRowContext(probeCtx, "PRAGMA quick_check").Scan(&result); err != nil {
		record(IntegrityError, err.Error())
		return fmt.Errorf("db.Open: quick_check: %w", err)
	}
	if result != "ok" {
		record(IntegrityCorrupt, result)
		return fmt.Errorf("db.Open: integrity check failed: %s", result)
	}
	record(IntegrityOK, "")
	return nil
}

// runMigrations applies any .sql files under the embedded migrations FS
// that have not already been applied, recording progress in schema_meta.
//
// Concurrency contract: the entire pending-migration batch runs inside
// a single BEGIN IMMEDIATE transaction on a dedicated connection. SQLite
// serializes BEGIN IMMEDIATE across processes via file locks, and PRAGMA
// busy_timeout makes a contending caller wait rather than fail
// immediately. This makes parallel daemon startups (watch + dashboard +
// proxy as three separate processes opening the same DB file) race-free:
// whoever wins the lock first applies pending migrations and commits;
// later contenders re-read schema_meta INSIDE their own lock, see the
// updated applied version, and skip everything. Pre-fix, racing daemons
// would each read applied=N, each try to apply migration N+1, and
// non-idempotent statements (ALTER TABLE ADD COLUMN) would error with
// "duplicate column name" on whichever lost the race.
//
// Tradeoff vs the previous per-migration tx approach: if migration K
// succeeds but K+1 fails in the same batch, K is rolled back too. That's
// preferable to partial application — the next run re-attempts both,
// not just K+1, so a botched migration script can't leave the schema
// in a half-state.
func runMigrations(ctx context.Context, db *sql.DB) error {
	// Live-DB test isolation gate, handle form (incident "task #17"). Open is
	// not the only route here: a caller can build a raw database/sql handle
	// and call this runner directly (migrations_test.go does exactly that), so
	// the DAMAGE site guards itself independently of the path seam. Inert in
	// production — see GuardLiveDBHandle.
	if err := GuardLiveDBHandle(ctx, db); err != nil {
		return err
	}
	entries, err := readMigrationEntries()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	maxVersion := entries[len(entries)-1].version

	// Fast path: a lock-free read of the applied version (a plain SELECT;
	// in WAL mode it never blocks on a writer). When the schema is already
	// current there is provably nothing to apply, so we skip the BEGIN
	// IMMEDIATE write lock below entirely. This is the overwhelmingly
	// common case for short-lived CLI/hook db.Open calls (observer index,
	// the hook subprocesses, doctor, guard, …): without it, every such
	// open contends for the write lock the running daemon holds and burns
	// up to busy_timeout (30s) on SQLITE_BUSY backoff just to confirm
	// there is no migration to run. A missing schema_meta (fresh DB) or
	// any read error makes currentVersion return a non-nil error, and a
	// stale lower read returns applied < maxVersion — both fall through to
	// the authoritative locked path, so the concurrent-first-migration
	// race the lock guards against is unaffected. We only ever skip the
	// lock when there is nothing to do.
	if applied, err := currentVersion(ctx, db); err == nil && applied >= maxVersion {
		return nil
	}

	// schema_meta must exist before we read it. CREATE TABLE IF NOT
	// EXISTS is idempotent so this is safe to run from multiple
	// processes concurrently and doesn't need the migration lock.
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_meta (
		key TEXT PRIMARY KEY, value TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("db.runMigrations: bootstrap schema_meta: %w", err)
	}

	// Pin a single connection so BEGIN IMMEDIATE / SQL / COMMIT all run
	// against the same SQLite session — database/sql.DB.BeginTx may
	// return a tx on any connection in the pool by default.
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("db.runMigrations: acquire connection: %w", err)
	}
	defer conn.Close()

	// 30s is generous; well-formed migrations apply in milliseconds
	// even on multi-GB DBs. The wait is for OTHER daemons holding the
	// lock during their own migration pass.
	if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout = 30000"); err != nil {
		return fmt.Errorf("db.runMigrations: set busy_timeout: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("db.runMigrations: acquire migration lock: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			// Best-effort rollback if the function returns an error
			// before COMMIT. Errors here are intentionally swallowed —
			// we're already on the error path; surfacing a rollback
			// failure would mask the real cause.
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	// Re-read applied INSIDE the lock so we observe any commits that
	// landed while we were waiting on BEGIN IMMEDIATE.
	var applied int
	var s sql.NullString
	row := conn.QueryRowContext(ctx, `SELECT value FROM schema_meta WHERE key = 'version'`)
	switch err := row.Scan(&s); {
	case errors.Is(err, sql.ErrNoRows):
		applied = 0
	case err != nil:
		return fmt.Errorf("db.runMigrations: read applied version: %w", err)
	default:
		if s.Valid {
			applied, err = strconv.Atoi(s.String)
			if err != nil {
				return fmt.Errorf("db.runMigrations: parse applied version %q: %w", s.String, err)
			}
		}
	}

	for _, e := range entries {
		if e.version <= applied {
			continue
		}
		body, readErr := fs.ReadFile(migrations.Files, e.filename)
		if readErr != nil {
			return fmt.Errorf("db.runMigrations: read %s: %w", e.filename, readErr)
		}
		if _, err := conn.ExecContext(ctx, string(body)); err != nil {
			return fmt.Errorf("db.runMigrations: exec %s: %w", e.filename, err)
		}
		if _, err := conn.ExecContext(
			ctx,
			`INSERT INTO schema_meta(key, value) VALUES ('version', ?)
			 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
			strconv.Itoa(e.version),
		); err != nil {
			return fmt.Errorf("db.runMigrations: record version %d: %w", e.version, err)
		}
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("db.runMigrations: commit: %w", err)
	}
	committed = true
	return nil
}

type migrationEntry struct {
	version  int
	filename string
}

func readMigrationEntries() ([]migrationEntry, error) {
	dirEntries, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		return nil, fmt.Errorf("db.readMigrationEntries: %w", err)
	}
	var entries []migrationEntry
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if filepath.Ext(name) != ".sql" {
			continue
		}
		prefix := strings.SplitN(name, "_", 2)[0]
		v, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("db.readMigrationEntries: unparseable migration %q: %w", name, err)
		}
		entries = append(entries, migrationEntry{version: v, filename: name})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].version < entries[j].version })
	return entries, nil
}

func currentVersion(ctx context.Context, db *sql.DB) (int, error) {
	var raw string
	err := db.QueryRowContext(ctx, "SELECT value FROM schema_meta WHERE key = 'version'").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("db.currentVersion: %w", err)
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("db.currentVersion: parse %q: %w", raw, err)
	}
	return v, nil
}

// Version reports the highest applied migration version. Returns 0 on a
// fresh database.
func Version(ctx context.Context, db *sql.DB) (int, error) {
	return currentVersion(ctx, db)
}

// backfillPathHashes populates the sha256-hex hash columns introduced by
// migration 034 (v1.8.0 org-push privacy fix). The migration adds the
// columns with NOT NULL DEFAULT ” so existing rows pass the constraint,
// but the org-push seam at internal/store/orgpush.go reads the hash
// columns and would otherwise ship empty strings for legacy rows.
//
// Idempotent: the WHERE clause skips already-populated rows, so this is
// cheap on every-startup re-run. Batched at 5000 rows per UPDATE to keep
// the in-Go SHA loop bounded and avoid pathological memory spikes on
// hosts with months of corpus.
//
// Scoping rationale: each table has a unique (table, source-column,
// hash-column) tuple; we walk all four. The SHA256 input is the raw
// source string (UTF-8 bytes); empty source → empty hash (left as the
// DEFAULT).
func backfillPathHashes(ctx context.Context, db *sql.DB) error {
	// Done-marker short-circuit (Ticket A): once a full pass has run, every
	// row with a non-empty source has a hash and new inserts populate it at
	// write time (store.InsertActions), so re-scanning on every daemon open
	// only burns IO. A cheap indexed schema_meta point-read replaces the
	// unindexed full-table scan. schema_meta is guaranteed to exist here
	// (runMigrations created/bootstrapped it before Open reaches this).
	if pathHashBackfillDone(ctx, db) {
		return nil
	}
	if backfillProbeHook != nil {
		// Test-only observation point: fires exactly when a real scan is
		// about to run (i.e. the marker did NOT short-circuit).
		backfillProbeHook()
	}
	jobs := []struct {
		name        string
		idCol       string
		sourceCol   string
		hashCol     string
		table       string
		extraFilter string // optional WHERE addition (e.g. NULL handling)
	}{
		{"projects.root_path_hash", "id", "root_path", "root_path_hash", "projects", ""},
		{"projects.git_remote_hash", "id", "git_remote", "git_remote_hash", "projects", "AND git_remote IS NOT NULL AND git_remote != ''"},
		{"actions.source_file_hash", "id", "source_file", "source_file_hash", "actions", "AND source_file IS NOT NULL AND source_file != ''"},
		{"token_usage.source_file_hash", "rowid", "source_file", "source_file_hash", "token_usage", "AND source_file IS NOT NULL AND source_file != ''"},
	}
	const batchSize = 5000
	for _, j := range jobs {
		for {
			// All format args are in-package literals from the `jobs`
			// allowlist above, not user input — gosec G201 is a false
			// positive for table/column substitution.
			query := fmt.Sprintf( //nolint:gosec // G201: table/column names from in-package allowlist
				`SELECT %s, %s FROM %s WHERE %s = '' %s LIMIT %d`,
				j.idCol, j.sourceCol, j.table, j.hashCol, j.extraFilter, batchSize,
			)
			rows, err := db.QueryContext(ctx, query)
			if err != nil {
				return fmt.Errorf("db.backfillPathHashes: %s scan: %w", j.name, err)
			}
			type pair struct {
				id   int64
				hash string
			}
			var batch []pair
			for rows.Next() {
				var id int64
				var src string
				if err := rows.Scan(&id, &src); err != nil {
					_ = rows.Close()
					return fmt.Errorf("db.backfillPathHashes: %s row scan: %w", j.name, err)
				}
				if src == "" {
					continue
				}
				sum := sha256.Sum256([]byte(src))
				batch = append(batch, pair{id: id, hash: hex.EncodeToString(sum[:])})
			}
			if err := rows.Close(); err != nil {
				return fmt.Errorf("db.backfillPathHashes: %s rows.Close: %w", j.name, err)
			}
			if len(batch) == 0 {
				break
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return fmt.Errorf("db.backfillPathHashes: %s begin: %w", j.name, err)
			}
			updateSQL := fmt.Sprintf( //nolint:gosec // G201: table/column names from in-package allowlist
				`UPDATE %s SET %s = ? WHERE %s = ?`, j.table, j.hashCol, j.idCol,
			)
			stmt, err := tx.PrepareContext(ctx, updateSQL)
			if err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("db.backfillPathHashes: %s prepare: %w", j.name, err)
			}
			for _, p := range batch {
				if _, err := stmt.ExecContext(ctx, p.hash, p.id); err != nil {
					_ = stmt.Close()
					_ = tx.Rollback()
					return fmt.Errorf("db.backfillPathHashes: %s update: %w", j.name, err)
				}
			}
			_ = stmt.Close()
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("db.backfillPathHashes: %s commit: %w", j.name, err)
			}
			if len(batch) < batchSize {
				break
			}
		}
	}
	// The loop above ran every job to exhaustion, so all rows with a
	// non-empty source now carry a hash. Record the done-marker so future
	// opens (including the daemon's own) short-circuit the scan.
	return markPathHashBackfillDone(ctx, db)
}

// pathHashBackfillDoneKey is the schema_meta key whose presence records
// that backfillPathHashes has completed a full pass on this DB.
const pathHashBackfillDoneKey = "path_hash_backfill_done"

// backfillProbeHook, when non-nil, is invoked exactly once per
// backfillPathHashes call that actually performs a table scan (i.e. was
// not short-circuited by the done-marker). Tests set it to count scans;
// production leaves it nil.
var backfillProbeHook func()

// pathHashBackfillDone reports whether the backfill done-marker is set. A
// read error (e.g. schema_meta not yet created on some exotic path) is
// treated as "not done" so the backfill still runs — fail toward doing the
// work, never toward skipping it.
func pathHashBackfillDone(ctx context.Context, db *sql.DB) bool {
	var v string
	err := db.QueryRowContext(ctx,
		`SELECT value FROM schema_meta WHERE key = ?`, pathHashBackfillDoneKey).Scan(&v)
	return err == nil && v == "1"
}

// markPathHashBackfillDone records the done-marker in schema_meta.
// Idempotent via upsert.
func markPathHashBackfillDone(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx,
		`INSERT INTO schema_meta(key, value) VALUES (?, '1')
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		pathHashBackfillDoneKey); err != nil {
		return fmt.Errorf("db.markPathHashBackfillDone: %w", err)
	}
	return nil
}
