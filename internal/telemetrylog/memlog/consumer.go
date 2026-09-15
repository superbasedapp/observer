package memlog

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

// deliveryState is one consumer's per-record delivery bookkeeping. A record with
// no deliveryState has never been delivered to the consumer (attempts 0).
type deliveryState struct {
	// attempts is the 1-based delivery count so far.
	attempts int
	// acked / termed are terminal: the record is never delivered again.
	acked, termed bool
	// inflight is true between a Fetch and its Ack/Nak/Term (or AckWait expiry).
	inflight bool
	// redeliverAt is the earliest time the record may be fetched again: while
	// inflight it is the AckWait deadline; after a Nak it is the backoff time.
	// The zero time means immediately eligible (fresh or Nak(0) already elapsed).
	redeliverAt time.Time
}

// consumerState is a durable pull consumer's cursor and delivery state. It lives
// in the Log (keyed by name) so Close + re-Subscribe reattach to the same state.
type consumerState struct {
	name          string
	filters       []string
	maxDeliver    int
	ackWait       time.Duration
	states        map[uint64]*deliveryState
	maxAckPending int
}

// matches reports whether subject passes any of the consumer's filters (an empty
// filter set matches every subject).
func (cs *consumerState) matches(subject string) bool {
	if len(cs.filters) == 0 {
		return true
	}
	for _, f := range cs.filters {
		if subjectMatches(f, subject) {
			return true
		}
	}
	return false
}

// eligible reports whether msg may be delivered to the consumer at now.
func (cs *consumerState) eligible(msg *storedMsg, now time.Time) bool {
	if !cs.matches(msg.rec.Subject) {
		return false
	}
	st := cs.states[msg.seq]
	if st == nil {
		return true // never delivered
	}
	if st.acked || st.termed {
		return false
	}
	if st.attempts >= cs.maxDeliver {
		return false // parked: delivery budget exhausted
	}
	return !now.Before(st.redeliverAt)
}

// statsLocked builds this consumer's backlog view over the current records.
func (cs *consumerState) statsLocked(records []*storedMsg, now time.Time) telemetrylog.ConsumerStats {
	out := telemetrylog.ConsumerStats{Name: cs.name}
	for _, msg := range records {
		if !cs.matches(msg.rec.Subject) {
			continue
		}
		st := cs.states[msg.seq]
		if st == nil {
			out.Pending++ // matched but never delivered
			continue
		}
		if st.acked || st.termed {
			continue // done
		}
		if st.inflight && now.Before(st.redeliverAt) {
			out.AckPending++ // delivered, awaiting ack within AckWait
		} else {
			out.Pending++ // redeliverable (AckWait expired or Nak elapsed)
		}
		if st.attempts > 1 {
			out.Redelivered++
		}
	}
	return out
}

// consumer is a pull-handle view onto a durable consumerState. Close releases the
// handle without deleting the durable state.
type consumer struct {
	log    *Log
	state  *consumerState
	closed bool
}

// Fetch blocks up to wait for at least one eligible record and returns at most
// max, marking each delivered (in-flight, attempt incremented). An empty slice
// with a nil error means nothing was available within wait.
func (c *consumer) Fetch(ctx context.Context, max int, wait time.Duration) ([]telemetrylog.Delivered, error) {
	if max <= 0 {
		return nil, nil
	}
	deadline := time.Now().Add(wait)
	for {
		got, err := c.collect(max)
		if err != nil {
			return nil, err
		}
		if len(got) > 0 {
			return got, nil
		}
		if !time.Now().Before(deadline) {
			return nil, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("memlog.Fetch: %w", ctx.Err())
		case <-time.After(pollInterval):
		}
	}
}

// collect does one non-blocking pass, delivering up to max eligible records.
func (c *consumer) collect(max int) ([]telemetrylog.Delivered, error) {
	c.log.mu.Lock()
	defer c.log.mu.Unlock()
	if c.log.closed {
		return nil, fmt.Errorf("memlog.Fetch: %w", telemetrylog.ErrClosed)
	}
	if c.closed {
		return nil, fmt.Errorf("memlog.Fetch: %w", telemetrylog.ErrClosed)
	}
	now := c.log.now()
	// A NAK releases this attempt, not the durable's credit. All unresolved
	// occurrences retain credit until Ack/Term, including a delayed retry.
	pending := 0
	for _, st := range c.state.states {
		if st.attempts > 0 && !st.acked && !st.termed {
			pending++
		}
	}
	var out []telemetrylog.Delivered
	for _, msg := range c.log.records { // records are in ascending sequence order
		if len(out) >= max {
			break
		}
		if !c.state.eligible(msg, now) {
			continue
		}
		st := c.state.states[msg.seq]
		if st == nil {
			if c.state.maxAckPending > 0 && pending >= c.state.maxAckPending {
				continue
			}
			st = &deliveryState{}
			c.state.states[msg.seq] = st
			pending++
		}
		st.attempts++
		st.inflight = true
		st.redeliverAt = now.Add(c.state.ackWait)
		out = append(out, &delivered{
			log:     c.log,
			state:   c.state,
			rec:     cloneRecord(msg.rec),
			seq:     msg.seq,
			attempt: st.attempts,
		})
	}
	return out, nil
}

// Close releases the handle. The durable cursor and delivery state survive so a
// later Subscribe with the same Name reattaches to them.
func (c *consumer) Close() error {
	c.log.mu.Lock()
	defer c.log.mu.Unlock()
	c.closed = true
	return nil
}

// delivered is one fetched record with its acknowledgement handle.
type delivered struct {
	log     *Log
	state   *consumerState
	rec     telemetrylog.Record
	seq     uint64
	attempt int
}

// Record returns the record as published.
func (d *delivered) Record() telemetrylog.Record { return d.rec }

// Sequence returns the engine's stream sequence for this record.
func (d *delivered) Sequence() uint64 { return d.seq }

// OrderPosition reports this stored occurrence within its immutable log lifetime.
func (d *delivered) OrderPosition() (telemetrylog.OrderPosition, bool) {
	position := telemetrylog.OrderPosition{Generation: d.log.generation, Sequence: d.seq}
	return position, position.Generation != "" && position.Sequence != 0
}

// Attempt returns the 1-based delivery count of this record to this consumer.
func (d *delivered) Attempt() int { return d.attempt }

// Ack marks the record consumed; it is never redelivered.
func (d *delivered) Ack(ctx context.Context) error {
	return d.update(ctx, "Ack", func(st *deliveryState) {
		st.acked = true
		st.inflight = false
	})
}

// Nak asks for redelivery after delay (0 = the 1s default backoff).
func (d *delivered) Nak(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		delay = defaultNakDelay
	}
	return d.update(ctx, "Nak", func(st *deliveryState) {
		st.inflight = false
		st.redeliverAt = d.log.now().Add(delay)
	})
}

// Term stops redelivery permanently (the poison-record path).
func (d *delivered) Term(ctx context.Context, reason string) error {
	_ = reason // the caller records reason in quarantine before calling Term
	return d.update(ctx, "Term", func(st *deliveryState) {
		st.termed = true
		st.inflight = false
	})
}

// update applies fn to this delivery's state under the log lock.
func (d *delivered) update(ctx context.Context, op string, fn func(*deliveryState)) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("memlog.%s: %w", op, err)
	}
	d.log.mu.Lock()
	defer d.log.mu.Unlock()
	if d.log.closed {
		return fmt.Errorf("memlog.%s: %w", op, telemetrylog.ErrClosed)
	}
	st := d.state.states[d.seq]
	if st == nil {
		st = &deliveryState{}
		d.state.states[d.seq] = st
	}
	fn(st)
	return nil
}

// subjectMatches implements the NATS subject-filter wildcard rules: "*" matches
// exactly one token, ">" matches one or more trailing tokens, and every other
// token matches literally.
func subjectMatches(filter, subject string) bool {
	if filter == "" {
		return true
	}
	f := strings.Split(filter, ".")
	s := strings.Split(subject, ".")
	for i, tok := range f {
		if tok == ">" {
			return len(s) >= i+1 // one or more trailing tokens
		}
		if i >= len(s) {
			return false
		}
		if tok == "*" {
			continue
		}
		if tok != s[i] {
			return false
		}
	}
	return len(s) == len(f)
}
