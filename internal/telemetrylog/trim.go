package telemetrylog

import (
	"context"
	"sort"
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
	// LimitingConsumer is the durable whose ack floor set Floor (empty when
	// no trim was possible), so an operator can see who holds the log.
	LimitingConsumer string
}

// ConsumerFloor is the per-durable input to AckedFloor: the slice of
// ConsumerStats the floor depends on.
type ConsumerFloor struct {
	Name       string
	AckFloor   uint64
	Pending    uint64
	AckPending uint64
}

// AckedFloor computes the highest stream sequence at or below which EVERY
// durable consumer has acked every record it is interested in. It is pure and
// table-tested; the adapters call it with an engine snapshot.
//
// lastSeq must be the stream's last sequence read BEFORE the consumer states
// (so a record published after the read can never be counted as consumed).
//
// Rules, in order:
//
//  1. A required durable missing from consumers holds the trim: floor 0,
//     held names returned.
//  2. No durables at all: floor 0 (nobody has consumed anything).
//  3. A durable with nothing pending and nothing awaiting ack has consumed
//     every record up to lastSeq: its floor is lastSeq.
//  4. Otherwise its floor is its AckFloor.
//  5. The log's floor is the MINIMUM over every durable present.
func AckedFloor(lastSeq uint64, consumers []ConsumerFloor, required []string) (floor uint64, limiting string, held []string) {
	present := make(map[string]bool, len(consumers))
	for _, c := range consumers {
		present[c.Name] = true
	}
	for _, name := range required {
		if name != "" && !present[name] {
			held = append(held, name)
		}
	}
	if len(held) > 0 {
		sort.Strings(held)
		return 0, "", held
	}
	if len(consumers) == 0 {
		return 0, "", nil
	}
	first := true
	for _, c := range consumers {
		f := c.AckFloor
		if c.Pending == 0 && c.AckPending == 0 {
			f = lastSeq
		}
		if f > lastSeq {
			f = lastSeq
		}
		if first || f < floor || (f == floor && c.Name < limiting) {
			floor, limiting, first = f, c.Name, false
		}
	}
	return floor, limiting, nil
}

// FloorsOf projects StreamStats.Consumers onto AckedFloor's input.
func FloorsOf(stats StreamStats) []ConsumerFloor {
	out := make([]ConsumerFloor, 0, len(stats.Consumers))
	for _, c := range stats.Consumers {
		out = append(out, ConsumerFloor{Name: c.Name, AckFloor: c.AckFloor, Pending: c.Pending, AckPending: c.AckPending})
	}
	return out
}
