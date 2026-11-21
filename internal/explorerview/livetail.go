package explorerview

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// livetail.go is the live tail dialect (W5-4): a poll (or, on the machine,
// a server-sent event stream) of the traces that arrived after a cursor and
// match the explorer's filters. Both sides bound the page, the poll rate and
// the scan, and tell the page how many rows it should keep.

// Live tail bounds.
const (
	TailDefaultPage = 25
	TailMaxPage     = 50
	// TailMinInterval is the shortest gap between two polls by one viewer;
	// a faster poll is refused 429 with Retry-After.
	TailMinInterval = 2 * time.Second
	// TailPollInterval is the interval the page is told to poll at.
	TailPollInterval = 3 * time.Second
	// TailFirstLookback is how far back an empty cursor starts: a tail shows
	// what arrives from now on, plus the last minute so it is not blank.
	TailFirstLookback = time.Minute
	// TailMaxScan bounds the candidate rows one poll reads (the org reads by
	// whole seconds of arrival and orders inside them in Go).
	TailMaxScan = 500
	// TailClientBuffer is how many rows the page keeps; older rows drop off.
	TailClientBuffer = 200
	// TailLimiterKeys bounds the limiter's memory (viewers tracked at once).
	TailLimiterKeys = 4096
)

// ClampPage returns the page size for a requested limit (0 = default).
func ClampPage(n int) int {
	switch {
	case n <= 0:
		return TailDefaultPage
	case n > TailMaxPage:
		return TailMaxPage
	default:
		return n
	}
}

// ErrInvalidCursor is returned for a cursor this package did not mint;
// handlers map it to 400.
var ErrInvalidCursor = errors.New("explorerview: invalid live tail cursor")

// TimeCursor is the org's tail position: the arrival stamp of the last row
// returned and its trace id (the tie-break inside one stamp).
type TimeCursor struct {
	At time.Time
	ID string
}

const cursorSep = "\x1f"

// Encode mints the opaque cursor.
func (c TimeCursor) Encode() string {
	return base64.RawURLEncoding.EncodeToString([]byte("t" + c.At.UTC().Format(time.RFC3339Nano) + cursorSep + c.ID))
}

// DecodeTimeCursor reads a cursor minted by Encode. The empty cursor starts
// the tail at now - TailFirstLookback.
func DecodeTimeCursor(s string, now time.Time) (TimeCursor, error) {
	if s == "" {
		return TimeCursor{At: now.Add(-TailFirstLookback).UTC()}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) < 2 || raw[0] != 't' {
		return TimeCursor{}, ErrInvalidCursor
	}
	at, id, ok := strings.Cut(string(raw[1:]), cursorSep)
	if !ok {
		return TimeCursor{}, ErrInvalidCursor
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return TimeCursor{}, ErrInvalidCursor
	}
	return TimeCursor{At: t.UTC(), ID: id}, nil
}

// SecondFloor is the SQL lower bound for arrival stamps at or after c: the
// fixed-width "YYYY-MM-DDTHH:MM:SS" prefix of c's second. Every RFC 3339
// UTC stamp in that second or later compares >= it as text, whatever its
// fractional digits, so one indexable text comparison serves SQLite and
// PostgreSQL; the order inside the second is settled by Select.
func (c TimeCursor) SecondFloor() string {
	return c.At.UTC().Format("2006-01-02T15:04:05")
}

// ArrivalKey is the cursor's position as a fixed-width text key
// ("YYYY-MM-DDTHH:MM:SS.nnnnnnnnn"), the Go twin of ArrivalKeySQL. Stored
// stamps vary in fractional digits ("…05Z", "…05.5Z"), so their text order
// is not their time order inside a second; the key is (review finding
// R-C11), and comparing it with (key, trace_id) lets the SQL itself step
// past every row at or before the cursor, however many share one second.
func (c TimeCursor) ArrivalKey() string {
	return c.At.UTC().Format("2006-01-02T15:04:05") + fmt.Sprintf(".%09d", c.At.UTC().Nanosecond())
}

// ArrivalKeySQL is the SQL expression (SQLite and PostgreSQL) of a stored
// RFC 3339 UTC stamp column's ArrivalKey: the second, then the fraction
// right-padded to nine digits. It assumes the "Z" suffix every org ingest
// path writes.
func ArrivalKeySQL(col string) string {
	return "(substr(" + col + ", 1, 19) || '.' || substr(CASE WHEN substr(" + col + ", 20, 1) = '.' THEN substr(" + col + ", 21, length(" + col +
		") - 21) ELSE '' END || '000000000', 1, 9))"
}

// ArrivalSecond is the "YYYY-MM-DDTHH:MM:SS" second of a stored stamp (the
// whole stamp when it is shorter).
func ArrivalSecond(stamp string) string {
	if len(stamp) < 19 {
		return stamp
	}
	return stamp[:19]
}

// NextSecondFloor is the text bound just past second sec: every stamp of sec
// compares below it, every later stamp at or above it. ok is false for a
// second that does not parse.
func NextSecondFloor(sec string) (string, bool) {
	t, err := time.Parse("2006-01-02T15:04:05", sec)
	if err != nil {
		return "", false
	}
	return t.Add(time.Second).Format("2006-01-02T15:04:05"), true
}

// CompleteSeconds reads a scan that hit its bound, in stored-text order
// (grouped by second, unordered inside one): it returns how many leading
// candidates lie in seconds before the last candidate's second. Those
// seconds were read whole, so their rows can be ordered exactly; the last
// second may be cut. 0 means the whole scan is one second, which the caller
// reads again in ArrivalKeySQL order.
func CompleteSeconds(cands []Candidate) int {
	if len(cands) == 0 {
		return 0
	}
	last := ArrivalSecond(cands[len(cands)-1].At)
	n := 0
	for n < len(cands) && ArrivalSecond(cands[n].At) < last {
		n++
	}
	return n
}

// Candidate is one row a poll read: its arrival stamp as stored and its id.
type Candidate struct {
	At string
	ID string
}

// Selection is the outcome of Select.
type Selection struct {
	// Keep are the indexes (into the candidates) to return, oldest first.
	Keep []int
	// Next is the cursor after the last kept row (the input cursor when
	// nothing new arrived).
	Next TimeCursor
	// More reports that more matching rows are waiting (the page or the scan
	// bound was reached): the page should poll again at once.
	More bool
	// Unparsed counts candidates whose stamp did not parse; they are skipped
	// and counted, never silently dropped.
	Unparsed int
}

// Select orders the candidates by (arrival, id), keeps those strictly after
// cur, and returns at most limit of them. scanFull says the read hit its
// TailMaxScan bound.
func Select(cands []Candidate, cur TimeCursor, limit int, scanFull bool) Selection {
	type row struct {
		i  int
		at time.Time
		id string
	}
	rows := make([]row, 0, len(cands))
	sel := Selection{Next: cur, More: scanFull}
	for i, c := range cands {
		t, err := time.Parse(time.RFC3339Nano, c.At)
		if err != nil {
			sel.Unparsed++
			continue
		}
		t = t.UTC()
		if t.Before(cur.At) || (t.Equal(cur.At) && c.ID <= cur.ID) {
			continue
		}
		rows = append(rows, row{i, t, c.ID})
	}
	sort.Slice(rows, func(a, b int) bool {
		if !rows[a].at.Equal(rows[b].at) {
			return rows[a].at.Before(rows[b].at)
		}
		return rows[a].id < rows[b].id
	})
	if len(rows) > limit {
		rows = rows[:limit]
		sel.More = true
	}
	for _, r := range rows {
		sel.Keep = append(sel.Keep, r.i)
		sel.Next = TimeCursor{At: r.at, ID: r.id}
	}
	return sel
}

// EncodeSeqCursor mints the machine's tail cursor over a monotonic row
// sequence (the obs store's rowid).
func EncodeSeqCursor(seq int64) string {
	return "s" + strconv.FormatInt(seq, 10)
}

// DecodeSeqCursor reads an EncodeSeqCursor cursor; ok=false for the empty
// cursor (the caller starts from its own "now" position).
func DecodeSeqCursor(s string) (seq int64, ok bool, err error) {
	if s == "" {
		return 0, false, nil
	}
	if len(s) < 2 || s[0] != 's' {
		return 0, false, ErrInvalidCursor
	}
	n, perr := strconv.ParseInt(s[1:], 10, 64)
	if perr != nil || n < 0 {
		return 0, false, ErrInvalidCursor
	}
	return n, true, nil
}

// MaxTailClientLen bounds the page-chosen tail client id.
const MaxTailClientLen = 64

// TailLimiterKey is the Limiter key of one machine-dashboard viewer: the
// client address and, when the page sends one, its per-tab client id. Every
// tab of the machine dashboard (and the dev proxy) reaches the daemon from
// 127.0.0.1, so the address alone made two tabs throttle each other (review
// finding R-C39). An id that is too long or not [A-Za-z0-9_-] is ignored.
func TailLimiterKey(host, client string) string {
	if client == "" || len(client) > MaxTailClientLen {
		return host
	}
	for i := 0; i < len(client); i++ {
		c := client[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return host
		}
	}
	return host + "|" + client
}

// Limiter bounds how often one viewer polls the tail: at most one poll per
// interval per key, tracking at most maxKeys keys (the stalest are evicted).
// Safe for concurrent use; holds no I/O.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	maxKeys  int
	last     map[string]time.Time
}

// NewLimiter builds a limiter. interval <= 0 is TailMinInterval, maxKeys <= 0
// is TailLimiterKeys.
func NewLimiter(interval time.Duration, maxKeys int) *Limiter {
	if interval <= 0 {
		interval = TailMinInterval
	}
	if maxKeys <= 0 {
		maxKeys = TailLimiterKeys
	}
	return &Limiter{interval: interval, maxKeys: maxKeys, last: map[string]time.Time{}}
}

// Allow records a poll by key at now. ok=false means it came sooner than the
// interval; retryAfter is how long to wait.
func (l *Limiter) Allow(key string, now time.Time) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if prev, seen := l.last[key]; seen {
		if gap := now.Sub(prev); gap < l.interval {
			return false, l.interval - gap
		}
	}
	if _, seen := l.last[key]; !seen && len(l.last) >= l.maxKeys {
		l.evict(now)
	}
	l.last[key] = now
	return true, 0
}

// evict drops every key idle for longer than the interval, and if none is,
// the single stalest key.
func (l *Limiter) evict(now time.Time) {
	stalest, stalestAt := "", now
	for k, t := range l.last {
		if now.Sub(t) >= l.interval {
			delete(l.last, k)
			continue
		}
		if t.Before(stalestAt) {
			stalest, stalestAt = k, t
		}
	}
	if len(l.last) >= l.maxKeys && stalest != "" {
		delete(l.last, stalest)
	}
}
