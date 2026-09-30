package timebucket

import (
	"strconv"
	"strings"
	"time"
)

// SQL-side grouping: EXACT UTC slots, re-floored in Go.
//
// SQL never computes a viewer-zone bucket. It groups rows into UTC SLOTS (a
// UTC day, hour, quarter hour, 5 minutes, minute or second) and Go floors
// each slot's start into its bucket with the exact zone (Spec.Floor). A
// slot is chosen so it lies WHOLLY inside one bucket for every zone period
// the window touches, which makes the result exact across DST changes and
// off-hour offsets (IST +5:30, Nepal +5:45, Lord Howe's 30-minute DST
// shift) with no per-row zone arithmetic in SQL. (The previous design
// shifted every row by the zone's offset at `until`, which put rows on the
// wrong local day across a DST change.)
//
// Two renderings of the same slot table:
//   - SQLiteExpr is the slot index unixepoch(col) / width: one date parse
//     per row whatever the width, and unixepoch normalizes any stored zone
//     suffix or the "YYYY-MM-DD HH:MM:SS" form (the node's tables). The
//     label is the integer slot index. (SQLite's integer division truncates,
//     so a pre-1970 timestamp lands one slot late; no real row is that old.)
//   - TextExpr uses plain substr() over canonical UTC RFC3339 text
//     ("...Z"), identical on SQLite and PostgreSQL (the org's tables). It
//     never casts, so a malformed or short timestamp yields a label that
//     does not parse (the row is excluded) instead of a PostgreSQL
//     "invalid input syntax for type integer" error.
//
// The column expressions are code constants (never request text), so the
// returned fragments are safe to splice into a statement.

// slotRow is one UTC slot width.
type slotRow struct {
	seconds int64
	// layout parses the slot label (in UTC).
	layout string
	text   func(col string) string
}

// quarterSQL / fiveSQL floor a two-digit minute text to its 15- / 5-minute
// slot with string comparisons only (no CAST: portable, never errors).
func quarterSQL(mm string) string {
	return "CASE WHEN " + mm + " < '15' THEN '00' WHEN " + mm + " < '30' THEN '15' WHEN " + mm + " < '45' THEN '30' ELSE '45' END"
}

func fiveSQL(minuteUnits string) string {
	return "CASE WHEN " + minuteUnits + " < '5' THEN '0' ELSE '5' END"
}

// slotTable is THE slot table, coarsest first; Spec.Slot walks it top-down
// and takes the first row that fits (CLAUDE.md #5).
var slotTable = []slotRow{
	{
		seconds: 86400, layout: "2006-01-02",
		text: func(c string) string { return "substr(" + c + ",1,10)" },
	},
	{
		seconds: 3600, layout: "2006-01-02T15",
		text: func(c string) string { return "substr(" + c + ",1,13)" },
	},
	{
		seconds: 900, layout: "2006-01-02T15:04",
		text: func(c string) string {
			return "(substr(" + c + ",1,14) || " + quarterSQL("substr("+c+",15,2)") + ")"
		},
	},
	{
		seconds: 300, layout: "2006-01-02T15:04",
		text: func(c string) string {
			return "(substr(" + c + ",1,15) || " + fiveSQL("substr("+c+",16,1)") + ")"
		},
	},
	{
		seconds: 60, layout: "2006-01-02T15:04",
		text: func(c string) string { return "substr(" + c + ",1,16)" },
	},
	{
		seconds: 1, layout: "2006-01-02T15:04:05",
		text: func(c string) string { return "substr(" + c + ",1,19)" },
	},
}

// Slot is a resolved SQL grouping plan for one Spec: the UTC slot width and
// the spec whose buckets the slots are re-floored into.
type Slot struct {
	// Seconds is the UTC slot width.
	Seconds int64
	row     slotRow
	spec    Spec
	// dayOnly marks a slot with no spec (UTCDaySlot): labels pass through
	// as UTC days.
	dayOnly bool
}

// maxZonePeriods bounds the zone-period walk (a real zone has well under a
// few hundred transitions since 1970).
const maxZonePeriods = 4096

// zoneFacts returns every UTC offset (seconds) the zone uses over
// [since, until) and every offset-change instant inside it. An unbounded
// window (zero since) is walked from the Unix epoch.
func zoneFacts(loc *time.Location, since, until time.Time) (offs, changes []int64) {
	if loc == nil {
		loc = time.UTC
	}
	if since.IsZero() {
		since = time.Unix(0, 0)
	}
	t := since.In(loc)
	for i := 0; i < maxZonePeriods; i++ {
		_, off := t.Zone()
		offs = append(offs, int64(off))
		_, end := t.ZoneBounds()
		if end.IsZero() || !end.After(t) || !end.Before(until) {
			break
		}
		changes = append(changes, end.Unix())
		t = end.In(loc)
	}
	return offs, changes
}

func divides(w int64, xs []int64) bool {
	for _, x := range xs {
		if x%w != 0 {
			return false
		}
	}
	return true
}

// Slot picks the coarsest UTC slot that lies wholly inside one bucket of s
// across the whole window: its width divides the bucket width, every UTC
// offset the zone uses in the window, and every offset-change instant in it
// (a change starts a sub-day bucket of its own, see Floor). A UTC day or
// week gets UTC-day slots; IST hours get quarter hours; New York hours get
// hours. The finest row (one second) always fits a zone whose offsets are
// whole seconds.
func (s Spec) Slot() Slot {
	offs, changes := zoneFacts(s.Loc, s.Since, s.Until)
	step := int64(s.Gran.Step() / time.Second)
	for _, r := range slotTable {
		if step <= 0 || r.seconds > step || step%r.seconds != 0 {
			continue
		}
		if divides(r.seconds, offs) && divides(r.seconds, changes) {
			return Slot{Seconds: r.seconds, row: r, spec: s}
		}
	}
	last := slotTable[len(slotTable)-1]
	return Slot{Seconds: last.seconds, row: last, spec: s}
}

// UTCDaySlot is the UTC-day slot with no spec: Bucket passes a parseable day
// label through as that UTC midnight. It is the legacy (pre-granularity)
// `substr(ts,1,10)` grouping.
func UTCDaySlot() Slot {
	return Slot{Seconds: slotTable[0].seconds, row: slotTable[0], dayOnly: true}
}

// Daily reports whether the slot is a whole UTC day.
func (sl Slot) Daily() bool { return sl.Seconds == 86400 }

// SQLiteExpr renders the slot label of col as the integer slot index
// unixepoch(col) / Seconds (any timestamp form SQLite's date functions
// accept; zone suffixes are normalized to UTC). NULL for a timestamp SQLite
// cannot read.
func (sl Slot) SQLiteExpr(col string) string {
	return "(unixepoch(" + col + ") / " + strconv.FormatInt(sl.Seconds, 10) + ")"
}

// TextExpr renders the slot label of col over canonical UTC RFC3339 text
// with substr() only: identical on SQLite and PostgreSQL and never an
// error, so a malformed timestamp becomes an unparseable label.
func (sl Slot) TextExpr(col string) string { return sl.row.text(col) }

// Start parses a TextExpr label back to the slot's UTC start. ok is false
// for a NULL / malformed label (the row is excluded).
func (sl Slot) Start(label string) (time.Time, bool) {
	t, err := time.Parse(sl.row.layout, strings.TrimSpace(label))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// Bucket parses a TextExpr label and returns the start of the bucket
// holding it, floored with the exact zone. ok is false for a label that does
// not parse.
func (sl Slot) Bucket(label string) (time.Time, bool) {
	t, ok := sl.Start(label)
	if !ok {
		return time.Time{}, false
	}
	if sl.dayOnly {
		return t, true
	}
	return sl.spec.Floor(t), true
}

// IndexBucket returns the bucket holding the SQLiteExpr slot index k (valid
// false = a NULL label, i.e. a timestamp SQLite could not read: ok false).
func (sl Slot) IndexBucket(k int64, valid bool) (time.Time, bool) {
	if !valid {
		return time.Time{}, false
	}
	t := time.Unix(k*sl.Seconds, 0).UTC()
	if sl.dayOnly {
		return t, true
	}
	return sl.spec.Floor(t), true
}
