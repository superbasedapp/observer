package kafkalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

type consumer struct {
	log                *Log
	client             *kgo.Client
	spec               telemetrylog.ConsumerSpec
	fingerprint, group string
	ready              chan struct{}
	initialized        chan struct{}
	initOnce           sync.Once
	fetchMu            sync.Mutex
	mu                 sync.Mutex
	closed, owner      bool
	epoch              uint64
	member             string
	generation         int32
	restoreErr         error
	state              cursorState
	raw                map[int64]*kgo.Record
}

// Subscribe attaches to a durable Kafka group with the requested subject and
// retry policy. Changing the policy of an existing durable cursor is refused.
func (l *Log) Subscribe(ctx context.Context, spec telemetrylog.ConsumerSpec) (telemetrylog.Consumer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if spec.MaxAckPending != 0 {
		return nil, fmt.Errorf("kafkalog.Subscribe: strict durable-wide MaxAckPending is unsupported; ordered consumers require a supporting log adapter")
	}
	normalized, fingerprint, err := normalizeSpec(spec, l.opts)
	if err != nil {
		return nil, err
	}
	clientOpts, err := l.opts.clientOptions()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(l.opts.Topic + "\x00" + spec.Name))
	c := &consumer{log: l, spec: normalized, fingerprint: fingerprint, group: l.opts.GroupPrefix + "." + hex.EncodeToString(sum[:16]), ready: make(chan struct{}), initialized: make(chan struct{}), raw: make(map[int64]*kgo.Record)}
	clientOpts = append(clientOpts,
		kgo.ConsumerGroup(c.group), kgo.ConsumeTopics(l.opts.Topic), kgo.DisableAutoCommit(),
		kgo.Balancers(kgo.RangeBalancer()), kgo.BlockRebalanceOnPoll(),
		kgo.ConsumeResetOffset(kgo.NoResetOffset()), kgo.FetchMaxPartitionBytes(l.opts.MaxMsgBytes+(64<<10)),
		kgo.AdjustFetchOffsetsFn(c.restore), kgo.OnPartitionsAssigned(c.assigned), kgo.OnPartitionsRevoked(c.revoked), kgo.OnPartitionsLost(c.revoked),
	)
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, telemetrylog.ErrClosed
	}
	c.client, err = kgo.NewClient(clientOpts...)
	if err != nil {
		l.mu.Unlock()
		return nil, fmt.Errorf("kafkalog.Subscribe: invalid consumer configuration")
	}
	close(c.ready)
	l.consumers[c] = struct{}{}
	l.mu.Unlock()
	// Attaching means the group has joined and restored its durable state, not
	// merely that a local client object exists. The first Fetch then owns its
	// full wait budget even when Kafka must initialize its offsets topic.
	attachCtx, cancel := context.WithTimeout(ctx, l.opts.ConnectTimeout)
	defer cancel()
	select {
	case <-attachCtx.Done():
		_ = c.Close()
		return nil, transportError("Subscribe", attachCtx.Err())
	case <-c.initialized:
	}
	c.mu.Lock()
	closed, restoreErr := c.closed, c.restoreErr
	c.mu.Unlock()
	if closed {
		return nil, telemetrylog.ErrClosed
	}
	if restoreErr != nil {
		_ = c.Close()
		return nil, restoreErr
	}
	return c, nil
}

func (c *consumer) assigned(_ context.Context, _ *kgo.Client, partitions map[string][]int32) {
	count := 0
	for _, values := range partitions {
		count += len(values)
	}
	if count == 0 {
		c.initOnce.Do(func() { close(c.initialized) })
	}
}

func (c *consumer) revoked(_ context.Context, _ *kgo.Client, _ map[string][]int32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.owner = false
	c.epoch++
	c.raw = make(map[int64]*kgo.Record)
}

func (c *consumer) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed, c.owner = true, false
	c.epoch++
	c.mu.Unlock()
	c.initOnce.Do(func() { close(c.initialized) })
	c.client.AllowRebalance()
	c.client.Close()
	c.log.mu.Lock()
	delete(c.log.consumers, c)
	c.log.mu.Unlock()
	return nil
}

func (c *consumer) Fetch(ctx context.Context, max int, wait time.Duration) ([]telemetrylog.Delivered, error) {
	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()
	if max <= 0 {
		return nil, nil
	}
	if max > maxOutstanding {
		max = maxOutstanding
	}
	deadline := time.Now().Add(wait)
	polled := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		got, canPoll, err := c.collect(ctx, max)
		if err != nil || len(got) > 0 {
			return got, err
		}
		if polled && (wait <= 0 || !time.Now().Before(deadline)) {
			return nil, nil
		}
		step := 50 * time.Millisecond
		if remaining := time.Until(deadline); remaining < step {
			step = remaining
		}
		if step < 0 {
			step = 0
		}
		if !canPoll {
			if step <= 0 {
				return nil, nil
			}
			timer := time.NewTimer(step)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
			polled = true
			continue
		}
		pollCtx, cancel := context.WithTimeout(ctx, step)
		fetches := c.client.PollRecords(pollCtx, maxOutstanding)
		cancel()
		polled = true
		c.mu.Lock()
		for _, fetchErr := range fetches.Errors() {
			if errors.Is(fetchErr.Err, context.DeadlineExceeded) || errors.Is(fetchErr.Err, context.Canceled) {
				continue
			}
			c.mu.Unlock()
			c.client.AllowRebalance()
			return nil, transportError("Fetch", fetchErr.Err)
		}
		if c.owner && !c.closed {
			for _, record := range fetches.Records() {
				if record.Topic != c.log.opts.Topic || record.Partition != 0 {
					c.mu.Unlock()
					c.client.AllowRebalance()
					return nil, fmt.Errorf("kafkalog: unexpected partition")
				}
				c.raw[record.Offset] = record
			}
		}
		c.mu.Unlock()
		// Every subsequent transition carries the assignment's generation fence;
		// old application deliveries cannot Ack into a new owner's generation.
		c.client.AllowRebalance()
	}
}

func (c *consumer) collect(ctx context.Context, max int) ([]telemetrylog.Delivered, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, false, telemetrylog.ErrClosed
	}
	if c.restoreErr != nil {
		return nil, false, fmt.Errorf("kafkalog: durable consumer restore: %w", c.restoreErr)
	}
	if !c.owner {
		return nil, true, nil
	}
	candidate := c.state.copy()
	offsets := make([]int64, 0, len(c.raw))
	for offset := range c.raw {
		offsets = append(offsets, offset)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	var out []telemetrylog.Delivered
	var discard []int64
	changed := false
	now := time.Now()
	for _, offset := range offsets {
		entry, pending := candidate.Pending[offset]
		if offset < candidate.Next && !pending {
			discard = append(discard, offset)
			continue
		}
		record, err := decodeRecord(c.raw[offset])
		if err != nil {
			return nil, false, err
		}
		if offset >= candidate.Next {
			if subjectMatches(c.spec.FilterSubjects, record.Subject) {
				if len(candidate.Pending) >= maxOutstanding {
					break
				}
				pending = true
			} else {
				discard = append(discard, offset)
			}
			candidate.Next, changed = offset+1, true
		}
		if !pending || entry.Attempt >= c.spec.MaxDeliver || now.UnixMilli() < entry.ReadyAt {
			continue
		}
		entry.Attempt++
		entry.ReadyAt = now.Add(c.spec.AckWait).UnixMilli() + 1
		candidate.Pending[offset], changed = entry, true
		out = append(out, &delivered{consumer: c, rec: record, offset: offset, attempt: entry.Attempt, epoch: c.epoch})
		if len(out) >= max {
			break
		}
	}
	if changed {
		if err := c.commit(ctx, candidate); err != nil {
			return nil, false, err
		}
		c.state = candidate
	}
	for _, offset := range discard {
		delete(c.raw, offset)
	}
	canPoll := len(c.raw) < 2*maxOutstanding && len(c.state.Pending) < maxOutstanding
	if !canPoll {
		// On restart, refetch every durable unfinished record before waiting for
		// its retry deadline, even if all outstanding slots were already filled.
		for offset := range c.state.Pending {
			if c.raw[offset] == nil {
				canPoll = true
				break
			}
		}
	}
	return out, canPoll, nil
}

type delivered struct {
	consumer *consumer
	rec      telemetrylog.Record
	offset   int64
	attempt  int
	epoch    uint64
	done     bool
}

func (d *delivered) Record() telemetrylog.Record {
	copy := d.rec
	copy.Payload = append([]byte(nil), d.rec.Payload...)
	if d.rec.Attrs != nil {
		copy.Attrs = make(map[string]string, len(d.rec.Attrs))
		for key, value := range d.rec.Attrs {
			copy.Attrs[key] = value
		}
	}
	return copy
}
func (d *delivered) Sequence() uint64                         { return uint64(d.offset) + 1 }
func (d *delivered) Attempt() int                             { return d.attempt }
func (d *delivered) Ack(ctx context.Context) error            { return d.finish(ctx, false, 0) }
func (d *delivered) Term(ctx context.Context, _ string) error { return d.finish(ctx, false, 0) }
func (d *delivered) Nak(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		delay = time.Second
	}
	return d.finish(ctx, true, delay)
}

func (d *delivered) finish(ctx context.Context, nak bool, delay time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c := d.consumer
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return telemetrylog.ErrClosed
	}
	if !c.owner || c.epoch != d.epoch {
		return fmt.Errorf("kafkalog: stale delivery assignment: %w", telemetrylog.ErrUnavailable)
	}
	if d.done {
		return nil
	}
	entry, pending := c.state.Pending[d.offset]
	if !pending || entry.Attempt != d.attempt {
		return fmt.Errorf("kafkalog: stale delivery attempt: %w", telemetrylog.ErrUnavailable)
	}
	candidate := c.state.copy()
	if nak {
		entry.ReadyAt = time.Now().Add(delay).UnixMilli() + 1
		candidate.Pending[d.offset] = entry
	} else {
		delete(candidate.Pending, d.offset)
	}
	if err := c.commit(ctx, candidate); err != nil {
		return err
	}
	c.state, d.done = candidate, true
	if !nak {
		delete(c.raw, d.offset)
	}
	return nil
}
