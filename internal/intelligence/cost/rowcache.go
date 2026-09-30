package cost

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"time"
)

// Raw-row load cache (optimization review 2026-09-27,
// docs/audits/optimization-review-2026-09-27.md finding N4).
//
// WHY. Nearly every dashboard read of spend — /api/cost, /api/models,
// /api/timeseries/cost, /api/sessions/calendar, /api/projects, and five of
// the Analysis page's panels (headline, trend, movers x2, cost-by-hour,
// cost-by-dow-hour, cache-savings, top-sessions) — goes through
// Engine.loadRows, which re-reads EVERY api_turns and token_usage row in the
// window (~210k rows for 30 days on the reference node, 1.5-2.5 s of
// row-fetch + scan CPU in the pure-Go driver) and only then groups them. A
// single page load fires several of those at once on the same window, each
// paying the full read, all competing for the same 4 cores. This cache lets
// those loads share ONE read.
//
// WHAT IS CACHED is the loader's raw, pre-dedup row slice for one query shape
// (source kind + every filter except the window's lower bound). A request for
// a window that is a SUFFIX of a cached one is answered by filtering the
// cached rows with the same TEXT comparison the SQL uses (timestamp >= since,
// BINARY collation), preserving their order, so the rows handed to the
// dedup/rollup pipeline are exactly the rows (and order) the SQL would have
// returned. The dedup/reconcile/price steps then run unchanged on a private
// copy — cached slices are never handed out.
//
// FRESHNESS. An entry is reused only while ALL of:
//   - the data fingerprint is unchanged: MAX(rowid) and COUNT(*) of
//     api_turns, token_usage and sessions, plus MAX(rowid) of projects. Any
//     insert or delete (ingest, retention prune, archive) invalidates at once;
//   - it is younger than rowCacheTTL. This bounds the one change a
//     fingerprint cannot see: an in-place UPDATE (a token_usage MAX-upgrade
//     of a streaming turn, a session reassignment, a backfill). Such a change
//     is visible at most rowCacheTTL late on a cached read.
//
// OPT-IN. Only a context marked with WithRowCache uses the cache; the
// dashboard's production handler chain marks GET requests. Every other
// caller (budget guards, routing, CLI, org push, tests) reads the database
// exactly as before.
//
// MEMORY. Entries over rowCacheMaxRows are not stored, session-id-scoped
// loads (the Sessions page's per-page rows, already small) are never cached,
// and expired entries are released by a sweep scheduled when they are stored.

// rowCacheTTL bounds how long an unchanged-fingerprint entry is reused.
const rowCacheTTL = 10 * time.Second

// rowCacheMaxRows is the largest single loader result the cache will hold
// (~100 MB of rawRow at the measured ~330 B/row). A larger window is simply
// read uncached, exactly as before.
const rowCacheMaxRows = 300_000

type rowCacheCtxKey struct{}

// WithRowCache marks ctx so that Engine reads made under it may be served
// from the engine's short-lived raw-row cache (see rowcache.go's header for
// the freshness contract). The dashboard marks its GET requests; nothing else
// should need to.
func WithRowCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, rowCacheCtxKey{}, true)
}

func rowCacheAllowed(ctx context.Context) bool {
	v, _ := ctx.Value(rowCacheCtxKey{}).(bool)
	return v
}

// rowFingerprint is the cheap "did the rows change" probe. Every field is an
// index-only read (MAX(rowid) is a single seek; COUNT(*) walks the smallest
// index — ~6 ms for token_usage on the reference node).
type rowFingerprint struct {
	apiMax, apiCount     int64
	tuMax, tuCount       int64
	sessMax, sessCount   int64
	projMax, projPresent int64
	// verdictRev is spend_verdict_state.rev (agent migration 143): it bumps
	// on every stored-verdict write, so a re-derive that changes which rows
	// count - with no row added or removed - still invalidates the cache. -1
	// on a schema without the table.
	verdictRev int64
}

const rowFingerprintSQL = `SELECT
	(SELECT COALESCE(MAX(rowid), 0) FROM api_turns),
	(SELECT COUNT(*) FROM api_turns),
	(SELECT COALESCE(MAX(rowid), 0) FROM token_usage),
	(SELECT COUNT(*) FROM token_usage),
	(SELECT COALESCE(MAX(rowid), 0) FROM sessions),
	(SELECT COUNT(*) FROM sessions),
	(SELECT COALESCE(MAX(rowid), 0) FROM projects),
	1`

// verdictRevSQL reads the stored-verdict revision (see rowFingerprint).
const verdictRevSQL = `SELECT COALESCE(MAX(rev), 0) FROM spend_verdict_state`

func loadRowFingerprint(ctx context.Context, db *sql.DB) (rowFingerprint, bool) {
	var fp rowFingerprint
	if err := db.QueryRowContext(ctx, rowFingerprintSQL).Scan(
		&fp.apiMax, &fp.apiCount, &fp.tuMax, &fp.tuCount,
		&fp.sessMax, &fp.sessCount, &fp.projMax, &fp.projPresent,
	); err != nil {
		return rowFingerprint{}, false
	}
	if err := db.QueryRowContext(ctx, verdictRevSQL).Scan(&fp.verdictRev); err != nil {
		fp.verdictRev = -1 // an unmigrated schema: no verdicts to track
	}
	return fp, true
}

// rowCacheKey is one loader query shape: everything that goes into the SQL
// except the window's lower bound. allTime separates "no lower bound" loads
// (planned as a plain table scan, i.e. rowid order) from bounded ones
// (planned through the timestamp index, i.e. timestamp order), so a filtered
// suffix is only ever taken from an entry with the same row order.
type rowCacheKey struct {
	db          *sql.DB
	kind        string
	allTime     bool
	until       string
	projectID   int64
	projectRoot string
	tool        string
}

type rowCacheSlot struct {
	// mu is held across a miss's database read, so concurrent loads of the
	// same shape share one read (per-key singleflight).
	mu    sync.Mutex
	valid bool
	since string
	rows  []rawRow
	fp    rowFingerprint
	at    time.Time
}

// rowCache is the Engine's raw-row cache. The zero value is ready to use.
type rowCache struct {
	mu    sync.Mutex
	slots map[rowCacheKey]*rowCacheSlot
	// now is the clock; nil means time.Now (tests replace it).
	now func() time.Time
	// afterFunc schedules the expiry sweep; nil means time.AfterFunc.
	afterFunc func(time.Duration, func()) *time.Timer
}

func (c *rowCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *rowCache) slot(k rowCacheKey) *rowCacheSlot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.slots == nil {
		c.slots = map[rowCacheKey]*rowCacheSlot{}
	}
	s, ok := c.slots[k]
	if !ok {
		s = &rowCacheSlot{}
		c.slots[k] = s
	}
	return s
}

// sweep drops expired entries (and their row memory). A slot whose lock is
// held is mid-load and skipped; it will be swept by the sweep its own store
// schedules.
func (c *rowCache) sweep() {
	now := c.clock()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, s := range c.slots {
		if !s.mu.TryLock() {
			continue
		}
		if !s.valid || now.Sub(s.at) >= rowCacheTTL || now.Before(s.at) {
			delete(c.slots, k)
		}
		s.mu.Unlock()
	}
}

// load returns the loader's rows for since, from the cache when a fresh entry
// covers the window and from load() otherwise. The returned slice is always a
// private copy the caller may mutate.
func (c *rowCache) load(k rowCacheKey, since time.Time, fp rowFingerprint, load func() ([]rawRow, error)) ([]rawRow, error) {
	sinceStr := ""
	if !since.IsZero() {
		sinceStr = since.UTC().Format(time.RFC3339Nano)
	}
	s := c.slot(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := c.clock()
	if s.valid && s.fp == fp && !now.Before(s.at) && now.Sub(s.at) < rowCacheTTL && s.since <= sinceStr {
		return filterRowsSince(s.rows, sinceStr), nil
	}
	rows, err := load()
	if err != nil {
		s.valid, s.rows = false, nil
		return nil, err
	}
	if len(rows) > rowCacheMaxRows {
		s.valid, s.rows = false, nil
		return rows, nil
	}
	s.valid, s.since, s.rows, s.fp, s.at = true, sinceStr, rows, fp, now
	after := c.afterFunc
	if after == nil {
		after = time.AfterFunc
	}
	after(rowCacheTTL+time.Second, c.sweep)
	return filterRowsSince(rows, sinceStr), nil
}

// filterRowsSince copies the rows whose timestamp is >= sinceStr, in order.
// The comparison is Go's byte-wise string order, which is exactly SQLite's
// BINARY collation on the TEXT timestamp column the SQL filter compares.
func filterRowsSince(rows []rawRow, sinceStr string) []rawRow {
	n := len(rows)
	if sinceStr != "" {
		n = 0
		for i := range rows {
			if strings.Compare(rows[i].ts, sinceStr) >= 0 {
				n++
			}
		}
	}
	out := make([]rawRow, 0, n)
	for i := range rows {
		if sinceStr != "" && strings.Compare(rows[i].ts, sinceStr) < 0 {
			continue
		}
		out = append(out, rows[i])
	}
	return out
}

// rowCacheKeyFor builds the cache key for one loader kind, or reports that
// this load shape is not cached.
func rowCacheKeyFor(db *sql.DB, kind string, opts Options, since time.Time) (rowCacheKey, bool) {
	if len(opts.SessionIDs) > 0 {
		return rowCacheKey{}, false
	}
	k := rowCacheKey{
		db:          db,
		kind:        kind,
		allTime:     since.IsZero(),
		projectID:   opts.ProjectID,
		projectRoot: opts.ProjectRoot,
		tool:        opts.Tool,
	}
	if !opts.Until.IsZero() {
		k.until = opts.Until.UTC().Format(time.RFC3339Nano)
	}
	return k, true
}
