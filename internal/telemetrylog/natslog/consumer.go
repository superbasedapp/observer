package natslog

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

// natsConsumer is a durable pull consumer. Close releases the local handle
// without deleting the durable cursor, so a re-Subscribe by the same Name
// reattaches and unacked records are redelivered.
type natsConsumer struct {
	cons            jetstream.Consumer
	streamName      string
	streamCreated   time.Time
	consumerCreated time.Time
	orderGeneration string
	maxAckPending   int
}

// Fetch blocks up to wait for at least one record and returns at most max.
// wait <= 0 uses a non-blocking single request. An empty slice with a nil
// error means nothing was available within wait.
func (c *natsConsumer) Fetch(ctx context.Context, max int, wait time.Duration) ([]telemetrylog.Delivered, error) {
	// A same-name durable recreated under this live handle must not inherit
	// the previous stream's ordering provenance. Also fail closed if another
	// subscriber relaxed the global credit promised by this handle.
	info, err := c.cons.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("natslog.Fetch: durable identity: %w", mapTransportErr(err))
	}
	if info.Stream != c.streamName || !info.Created.Equal(c.consumerCreated) || (c.maxAckPending > 0 && info.Config.MaxAckPending != c.maxAckPending) {
		return nil, fmt.Errorf("natslog.Fetch: durable identity or global credit changed; reattach required")
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

// Close releases the pull handle. The durable cursor is untouched.
func (c *natsConsumer) Close() error { return nil }

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
