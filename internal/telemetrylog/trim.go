package telemetrylog

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Trimmer is an OPTIONAL capability a Log implements when it can remove the
// records every durable consumer has already acknowledged (T-823, the
// "no silent loss" retention model).
//
// The durable log is a buffer in front of PostgreSQL and the SoR, never the
// store. A record therefore leaves the log for exactly one reason: every
// durable consumer on the log has acked it. Age never removes a record, and a
// full log refuses new records (ErrFull, answered 503 + Retry-After) instead of
// evicting unacked ones. TrimApplied is the one place records are removed.
//
// required names the durables this deployment depends on (the apply worker,
// the SoR writer when a durable store is configured, ...). When any of them is
// absent from the log, TrimApplied removes NOTHING and reports the missing
// names in TrimResult.HeldBy, so a durable that has not been created yet (or
// was deleted by an operator) can never have its records trimmed out from
// under it. Every durable that IS present holds the floor too, whether or not
// it is required, so an optional consumer is never overtaken either.
//
// A caller branches on the capability (a type assertion), never on the engine
// name (CLAUDE.md rule 3). An engine that cannot trim does not implement it.
type Trimmer interface {
	TrimApplied(ctx context.Context, required []string) (TrimResult, error)
}

// TrimResult reports one TrimApplied pass.
type TrimResult struct {
	// Floor is the highest stream sequence every durable has acked; records at
	// or below it were eligible. 0 when nothing was eligible.
	Floor uint64
	// Removed is the number of records the pass removed (best effort: an
	// engine that cannot count exactly reports its estimate, never more than
	// it removed).
	Removed uint64
	// HeldBy names the required durables that were missing, in sorted order.
	// Non-empty means the pass removed nothing on purpose.
	HeldBy []string
	// Ahead names the durables whose position is beyond the stream's last
	// sequence (F01: the stream was recreated or reset under them), in sorted
	// order. Non-empty is a FAULT: the pass removed nothing, and those
	// consumers will never be delivered the records the stream now holds
	// until an operator resets them (docs/teams-operations.md "Durable log:
	// consumer ahead of the stream").
	Ahead []ConsumerAhead
	// LimitingConsumer is the durable whose ack floor set Floor (empty when
	// no trim was possible), so an operator can see who holds the log.
	LimitingConsumer string
	// CeilingUnknown is true when the stream ceiling could not be re-read and
	// a durable sits above the first read: the pass removed nothing, and no
	// fault is reported (R-A05). The next pass decides.
	CeilingUnknown bool
}

// ConsumerFloor is the per-durable input to AckedFloor: the slice of
// ConsumerStats the floor depends on.
type ConsumerFloor struct {
	Name       string
	AckFloor   uint64
	Pending    uint64
	AckPending uint64
	// Delivered is the highest stream sequence delivered (0 = unknown).
	Delivered uint64
}

// ConsumerAhead is one durable whose position is beyond the stream: the
// position it reports and the stream ceiling it was compared with.
type ConsumerAhead struct {
	Name     string `json:"name"`
	Position uint64 `json:"position"`
	Ceiling  uint64 `json:"ceiling"`
}

// FloorVerdict is the full result of the trim floor rules (TrimFloor).
type FloorVerdict struct {
	// Floor is the highest sequence every durable has acked; 0 means trim
	// nothing (held, ahead, or nothing consumed).
	Floor uint64
	// Limiting is the durable whose ack floor set Floor.
	Limiting string
	// Held names the required durables that are missing, sorted.
	Held []string
	// Ahead names the durables beyond the stream, sorted by name. Non-empty
	// is a fault: never trim, alert, fail readiness.
	Ahead []ConsumerAhead
	// CeilingUnknown is true when the stats carried no usable ceiling
	// (StreamStats.CeilingUnknown) and a durable sits above the first read of
	// the last sequence: floor 0 (hold), Ahead empty (not a fault).
	CeilingUnknown bool
}

// AheadOfStream returns every durable whose ack floor or delivered position
// is beyond ceiling, sorted by name. ceiling must be the stream's last
// sequence read AFTER the consumer states (StreamCeiling), so a record
// published, delivered and acked between the two reads is never mistaken for
// a fault: stream sequences only grow, so a position above a later read of
// the last sequence means the stream was recreated or reset under the
// consumer (F01). Such a consumer reports nothing pending (it is "past" every
// record the stream holds) and is never delivered them.
func AheadOfStream(ceiling uint64, consumers []ConsumerFloor) []ConsumerAhead {
	var out []ConsumerAhead
	for _, c := range consumers {
		pos := max(c.AckFloor, c.Delivered)
		if pos > ceiling {
			out = append(out, ConsumerAhead{Name: c.Name, Position: pos, Ceiling: ceiling})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// AheadOf is AheadOfStream over one stats read, and nothing when the read
// carries no usable ceiling (StreamStats.CeilingUnknown, R-A05): an unknown
// ceiling is never reported as a fault. Every ahead reader (the probe, the
// backlog evaluator, readiness) goes through it.
func AheadOf(stats StreamStats) []ConsumerAhead {
	if stats.CeilingUnknown {
		return nil
	}
	return AheadOfStream(StreamCeiling(stats), FloorsOf(stats))
}

// StreamCeiling is the highest last sequence a stats read observed: the
// re-read taken after the consumer states when the engine made one, else the
// first read.
func StreamCeiling(stats StreamStats) uint64 {
	return max(stats.LastSequence, stats.CeilingSequence)
}

// DescribeAhead is the one operator-facing sentence for an ahead fault, used
// by the trim loop's ERROR line, the probe's Fault and the backlog banner.
func DescribeAhead(ahead []ConsumerAhead) string {
	if len(ahead) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ahead))
	for _, a := range ahead {
		parts = append(parts, fmt.Sprintf("%s at %d > stream last %d", a.Name, a.Position, a.Ceiling))
	}
	return "durable consumer ahead of the stream (" + strings.Join(parts, "; ") +
		"): the stream was recreated or reset under it, so new records are never delivered to it; trim is held and nothing is removed until the consumer is reset (docs/teams-operations.md, \"Durable log: consumer ahead of the stream\")"
}

// TrimFloor applies the trim floor rules to one stats read. It is pure and
// table-tested; every Trimmer calls it with an engine snapshot taken by
// reading the stream state, then the consumer states, then (optionally) the
// stream state again (StreamStats.CeilingSequence).
//
// Rules, in order:
//
//  1. A required durable missing from consumers holds the trim: floor 0,
//     held names returned.
//  2. A durable whose ack floor or delivered position is beyond the stream
//     ceiling (AheadOfStream) is a FAULT: floor 0, ahead returned. It is never
//     clamped to the stream's last sequence: doing so (the pre-F01 rule)
//     declared every record of a recreated stream consumed and purged it
//     unapplied. When the ceiling is unknown (StreamStats.CeilingUnknown) a
//     durable above the first read holds the trim instead (floor 0,
//     CeilingUnknown, no fault).
//  3. No durables at all: floor 0 (nobody has consumed anything).
//  4. A durable with nothing pending and nothing awaiting ack has consumed
//     every record up to lastSeq: its floor is lastSeq.
//  5. Otherwise its floor is its AckFloor, capped at lastSeq (an ack of a
//     record published after the first read, within the ceiling, is real but
//     must not let the purge reach past what was read).
//  6. The log's floor is the MINIMUM over every durable present.
func TrimFloor(stats StreamStats, consumers []ConsumerFloor, required []string) FloorVerdict {
	if stats.CeilingUnknown {
		v := trimFloor(stats.LastSequence, stats.LastSequence, consumers, required)
		if len(v.Ahead) > 0 {
			// Above the first read, but no second read to compare with: it may
			// be a record published, delivered and acked in between. Hold, do
			// not fault.
			v.Ahead, v.Floor, v.Limiting, v.CeilingUnknown = nil, 0, "", true
		}
		return v
	}
	return trimFloor(stats.LastSequence, StreamCeiling(stats), consumers, required)
}

// AckedFloor is TrimFloor for a caller holding only the first read of the
// last sequence: the ceiling is lastSeq itself, so any consumer position
// above it holds the trim (conservative: a race costs one interval, never a
// record). Kept for callers that pre-date TrimFloor.
func AckedFloor(lastSeq uint64, consumers []ConsumerFloor, required []string) (floor uint64, limiting string, held []string) {
	v := trimFloor(lastSeq, lastSeq, consumers, required)
	return v.Floor, v.Limiting, v.Held
}

func trimFloor(lastSeq, ceiling uint64, consumers []ConsumerFloor, required []string) FloorVerdict {
	var v FloorVerdict
	present := make(map[string]bool, len(consumers))
	for _, c := range consumers {
		present[c.Name] = true
	}
	for _, name := range required {
		if name != "" && !present[name] {
			v.Held = append(v.Held, name)
		}
	}
	sort.Strings(v.Held)
	v.Ahead = AheadOfStream(max(lastSeq, ceiling), consumers)
	if len(v.Held) > 0 || len(v.Ahead) > 0 || len(consumers) == 0 {
		return v
	}
	first := true
	for _, c := range consumers {
		f := c.AckFloor
		if c.Pending == 0 && c.AckPending == 0 {
			f = lastSeq
		}
		f = min(f, lastSeq)
		if first || f < v.Floor || (f == v.Floor && c.Name < v.Limiting) {
			v.Floor, v.Limiting, first = f, c.Name, false
		}
	}
	return v
}

// FloorsOf projects StreamStats.Consumers onto AckedFloor's input.
func FloorsOf(stats StreamStats) []ConsumerFloor {
	out := make([]ConsumerFloor, 0, len(stats.Consumers))
	for _, c := range stats.Consumers {
		out = append(out, ConsumerFloor{Name: c.Name, AckFloor: c.AckFloor, Pending: c.Pending, AckPending: c.AckPending, Delivered: c.Delivered})
	}
	return out
}
