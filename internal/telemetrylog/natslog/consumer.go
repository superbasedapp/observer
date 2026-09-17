package natslog

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

// natsConsumer is a durable pull consumer. Close releases the local handle
// without deleting the durable cursor, so a re-Subscribe by the same Name
// reattaches and unacked records are redelivered.
type natsConsumer struct {
	cons            jetstream.Consumer
	name            string
	streamName      string
	streamCreated   time.Time
	consumerCreated time.Time
	orderGeneration string
	maxAckPending   int

	mu     sync.Mutex
	closed bool
}

// Fetch blocks up to wait for at least one record and returns at most max.
// wait <= 0 uses a non-blocking single request. An empty slice with a nil
// error means nothing was available within wait.
func (c *natsConsumer) Fetch(ctx context.Context, max int, wait time.Duration) ([]telemetrylog.Delivered, error) {
	if c.isClosed() {
		return nil, fmt.Errorf("natslog.Fetch: %w", telemetrylog.ErrClosed)
	}
	// A same-name durable recreated under this live handle must not inherit
	// the previous stream's ordering provenance. Also fail closed if another
	// subscriber relaxed the global credit promised by this handle.
	info, err := c.cons.Info(ctx)
	if err != nil {
		// A DELETED durable is a reattach case, not a transport fault: the
		// connection is healthy and every future Fetch on this handle fails the
		// same way, so it must carry the sentinel or the runner backs off forever
		// (the incident's failure mode, one step earlier in the same path).
		if isConsumerGone(err) {
			return nil, fmt.Errorf("natslog.Fetch: durable %q no longer exists: %w",
				c.name, telemetrylog.ErrReattachRequired)
		}
		if isStreamGone(err) {
			// The STREAM took the durable with it — the shape a broker whose
			// store does not survive a restart actually takes (the estate's
			// sidecar runs on emptyDir, R=1). It is reported as the same typed
			// reattach demand, deliberately: the re-Subscribe that answers it
			// is refused with ErrReconnectRequired, which is what escalates to
			// the Log's Reconnector capability. Leaving it untyped is what left
			// every consumer backing off forever on a plain fetch error while
			// the backlog grew.
			return nil, fmt.Errorf("natslog.Fetch: stream %q no longer exists (durable %q went with it): %w",
				c.streamName, c.name, telemetrylog.ErrReattachRequired)
		}
		return nil, fmt.Errorf("natslog.Fetch: durable identity: %w", mapTransportErr(err))
	}
	if why := c.identityDrift(info); why != "" {
		// Typed, not prose: the caller must Close this handle and Subscribe by
		// the same durable Name. errors.Is is the only supported branch; why is
		// diagnostic only (the incident's single collapsed message could not say
		// WHICH of the three conditions had tripped).
		return nil, fmt.Errorf("natslog.Fetch: durable identity or global credit changed (%s): %w",
			why, telemetrylog.ErrReattachRequired)
	}
	if max <= 0 {
		max = 1
	}
	// Two pulls, not one: a single Fetch(max, FetchMaxWait(wait)) waits for the
	// WHOLE batch, and when fewer than max records exist the engine keeps the
	// request open for the full wait. During that window AckWait can expire on
	// the records already handed out, and the engine redelivers them INTO THE
	// SAME BATCH (observed: 3 published, 6 fetched with AckWait < wait). So the
	// first pull blocks for at most ONE record and the second drains, without
	// waiting, whatever else is immediately available.
	var out []telemetrylog.Delivered
	if wait > 0 {
		first, err := c.pull(1, jetstream.FetchMaxWait(wait))
		if err != nil {
			return nil, err
		}
		out = append(out, first...)
		if len(out) == 0 || max == 1 {
			return out, nil
		}
	}
	rest, err := c.pullNoWait(max - len(out))
	if err != nil {
		if len(out) > 0 {
			return out, nil // the blocking pull already succeeded; keep it
		}
		return nil, err
	}
	return append(out, rest...), nil
}

// identityDrift reports, for the operator's log line, WHICH fact about the live
// durable no longer matches what this handle attached to — empty when the handle
// is still valid. A same-name durable that was re-created (a broker restart
// racing JetStream's store recovery) shows up as a changed created stamp.
func (c *natsConsumer) identityDrift(info *jetstream.ConsumerInfo) string {
	switch {
	case info == nil:
		return "no consumer info"
	case info.Stream != c.streamName:
		return fmt.Sprintf("stream %q != %q", info.Stream, c.streamName)
	case !info.Created.Equal(c.consumerCreated):
		return fmt.Sprintf("durable re-created at %s (attached to %s)",
			info.Created.UTC().Format(time.RFC3339Nano), c.consumerCreated.UTC().Format(time.RFC3339Nano))
	case c.maxAckPending > 0 && info.Config.MaxAckPending != c.maxAckPending:
		return fmt.Sprintf("max_ack_pending %d != %d", info.Config.MaxAckPending, c.maxAckPending)
	}
	return ""
}

// pull issues one blocking pull request for up to n records.
func (c *natsConsumer) pull(n int, opts ...jetstream.FetchOpt) ([]telemetrylog.Delivered, error) {
	batch, err := c.cons.Fetch(n, opts...)
	if err != nil {
		return nil, fmt.Errorf("natslog.Fetch: %w", mapTransportErr(err))
	}
	return c.drainBatch(batch)
}

// pullNoWait issues one non-blocking pull request for up to n records.
func (c *natsConsumer) pullNoWait(n int) ([]telemetrylog.Delivered, error) {
	if n <= 0 {
		return nil, nil
	}
	batch, err := c.cons.FetchNoWait(n)
	if err != nil {
		return nil, fmt.Errorf("natslog.Fetch: %w", mapTransportErr(err))
	}
	return c.drainBatch(batch)
}

// drainBatch materializes a message batch; a batch error with no records is
// surfaced, a batch error after some records is not (they are delivered).
func (c *natsConsumer) drainBatch(batch jetstream.MessageBatch) ([]telemetrylog.Delivered, error) {
	var out []telemetrylog.Delivered
	for msg := range batch.Messages() {
		out = append(out, newDelivered(msg, c.streamName, c.streamCreated, c.orderGeneration))
	}
	if err := batch.Error(); err != nil && len(out) == 0 {
		return nil, fmt.Errorf("natslog.Fetch: %w", mapTransportErr(err))
	}
	return out, nil
}

// Close retires this handle. The durable cursor is untouched, so a Subscribe by
// the same ConsumerSpec.Name reattaches and every unacked record redelivers.
//
// There is deliberately NO broker-side teardown here, and that is an honest
// nothing rather than an omission: with the pull API this adapter uses, every
// Fetch issues its own short-lived pull request that drainBatch consumes to
// completion, so between Fetches the handle owns no subscription, no goroutine
// and no server-side interest — unlike kafkalog's consumer, which owns a
// franz-go client + consumer-group membership and must release both. What Close
// DOES own is the local invariant: after it returns, Fetch on this handle is
// telemetrylog.ErrClosed rather than a silent read through a handle its owner
// has already replaced (the Runner's reattach closes the stale handle straight
// after the swap). Idempotent.
func (c *natsConsumer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

// isClosed reports whether Close has run.
func (c *natsConsumer) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// natsDelivered wraps one fetched jetstream.Msg as a telemetrylog.Delivered.
type natsDelivered struct {
	msg      jetstream.Msg
	rec      telemetrylog.Record
	seq      uint64
	attempt  int
	position telemetrylog.OrderPosition
}

// newDelivered rebuilds the Record from the message subject + headers and reads
// the stream sequence and 1-based delivery count from the message metadata.
func newDelivered(msg jetstream.Msg, streamName string, streamCreated time.Time, generation string) *natsDelivered {
	d := &natsDelivered{msg: msg, rec: recordFromMsg(msg), attempt: 1}
	if md, err := msg.Metadata(); err == nil && md != nil {
		d.seq = md.Sequence.Stream
		if md.NumDelivered > 0 {
			d.attempt = int(md.NumDelivered)
		}
		if generation != "" && md.Stream == streamName && md.Sequence.Stream > 0 && !md.Timestamp.Before(streamCreated) {
			d.position = telemetrylog.OrderPosition{Generation: generation, Sequence: md.Sequence.Stream}
		}
	}
	return d
}

// Record returns the rebuilt record (equal to the published Record).
func (d *natsDelivered) Record() telemetrylog.Record { return d.rec }

// Sequence returns the engine's stream sequence for this record.
func (d *natsDelivered) Sequence() uint64 { return d.seq }

// OrderPosition reports broker metadata only when the stream has the durable
// upgraded-adapter ordering marker. Unmarked historical streams are untrusted.
func (d *natsDelivered) OrderPosition() (telemetrylog.OrderPosition, bool) {
	return d.position, d.position.Generation != "" && d.position.Sequence != 0
}

// Attempt returns the 1-based delivery count of this record to this consumer.
func (d *natsDelivered) Attempt() int { return d.attempt }

// Ack marks the record consumed. ctx is accepted for the interface; the
// underlying JetStream ack is a fire-and-forget publish.
func (d *natsDelivered) Ack(ctx context.Context) error {
	if err := d.msg.Ack(); err != nil {
		return fmt.Errorf("natslog.Ack: %w", mapTransportErr(err))
	}
	return nil
}

// Nak asks for redelivery after delay (0 uses the engine's default backoff).
func (d *natsDelivered) Nak(ctx context.Context, delay time.Duration) error {
	var err error
	if delay <= 0 {
		err = d.msg.Nak()
	} else {
		err = d.msg.NakWithDelay(delay)
	}
	if err != nil {
		return fmt.Errorf("natslog.Nak: %w", mapTransportErr(err))
	}
	return nil
}

// Term stops redelivery permanently (the poison-record path).
func (d *natsDelivered) Term(ctx context.Context, reason string) error {
	var err error
	if reason == "" {
		err = d.msg.Term()
	} else {
		err = d.msg.TermWithReason(reason)
	}
	if err != nil {
		return fmt.Errorf("natslog.Term: %w", mapTransportErr(err))
	}
	return nil
}

// recordFromMsg reconstructs a telemetrylog.Record from a delivered message.
func recordFromMsg(msg jetstream.Msg) telemetrylog.Record {
	h := msg.Headers()
	rec := telemetrylog.Record{
		Subject: msg.Subject(),
		Payload: msg.Data(),
		Org:     h.Get(headerOrg),
		DedupID: h.Get(headerMsgID),
	}
	// An operator requeue has a new broker delivery identity but MUST retain
	// its original archive/quarantine identity for first-writer-wins semantics.
	if original := h.Get(headerOriginalDedupID); original != "" {
		rec.DedupID = original
	}
	if pv := h.Get(headerPayloadVer); pv != "" {
		if n, err := strconv.Atoi(pv); err == nil {
			rec.PayloadVer = n
		}
	}
	var attrs map[string]string
	for k, vs := range h {
		if !strings.HasPrefix(k, headerAttrPrefix) || len(vs) == 0 {
			continue
		}
		if attrs == nil {
			attrs = make(map[string]string)
		}
		attrs[strings.TrimPrefix(k, headerAttrPrefix)] = vs[0]
	}
	rec.Attrs = attrs
	return rec
}
