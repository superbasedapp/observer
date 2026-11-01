package natslog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

// publishN publishes n distinct push records and returns their sequences.
func publishN(t *testing.T, l *Log, prefix string, n int) []uint64 {
	t.Helper()
	seqs := make([]uint64, 0, n)
	for i := 0; i < n; i++ {
		res, err := l.Publish(context.Background(), rec("o", "sbo.push.o", fmt.Sprintf("%s-%d", prefix, i), "payload", nil))
		if err != nil {
			t.Fatalf("Publish %d: %v", i, err)
		}
		seqs = append(seqs, res.Sequence)
	}
	return seqs
}

// consumeAndAck fetches up to n records on c and acks them.
func consumeAndAck(t *testing.T, c telemetrylog.Consumer, n int) []uint64 {
	t.Helper()
	var acked []uint64
	for len(acked) < n {
		got, err := c.Fetch(context.Background(), n-len(acked), time.Second)
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		if len(got) == 0 {
			break
		}
		for _, d := range got {
			if err := d.Ack(context.Background()); err != nil {
				t.Fatalf("Ack: %v", err)
			}
			acked = append(acked, d.Sequence())
		}
	}
	return acked
}

// waitAckFloor polls until the durable's ack floor reaches seq (acks are
// asynchronous on the broker side).
func waitAckFloor(t *testing.T, l *Log, name string, seq uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st, err := l.Stats(context.Background())
		if err == nil {
			for _, c := range st.Consumers {
				if c.Name == name && (c.AckFloor >= seq || (c.Pending == 0 && c.AckPending == 0)) {
					return
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("durable %q never reached ack floor %d", name, seq)
}

// TestStreamHasNoAgeLimitAndUpgradeKeepsGeneration pins the T-823 cut-over: a
// stream an older release provisioned with a MaxAge is updated in place to no
// age limit on the next provisioning, and its creation stamp and ordering
// generation (what OrderPosition and archive recovery key on) are unchanged.
func TestStreamHasNoAgeLimitAndUpgradeKeepsGeneration(t *testing.T) {
	l := newTestLog(t, Options{})
	ctx := context.Background()
	stream, created, generation := l.identity()
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Config.MaxAge != 0 {
		t.Fatalf("fresh stream MaxAge = %v, want 0 (no age eviction)", info.Config.MaxAge)
	}
	if generation == "" {
		t.Fatal("fresh stream has no ordering generation")
	}

	// Simulate the pre-T-823 release: the same stream carrying a 72 h MaxAge.
	old := info.Config
	old.MaxAge = 72 * time.Hour
	if _, err := l.js.UpdateStream(ctx, old); err != nil {
		t.Fatalf("simulate old MaxAge: %v", err)
	}
	if err := l.Reconnect(ctx); err != nil {
		t.Fatalf("Reconnect (re-provision): %v", err)
	}
	stream2, created2, generation2 := l.identity()
	info2, err := stream2.Info(ctx)
	if err != nil {
		t.Fatalf("Info after re-provision: %v", err)
	}
	if info2.Config.MaxAge != 0 {
		t.Errorf("re-provisioned MaxAge = %v, want 0", info2.Config.MaxAge)
	}
	if info2.Config.Retention != jetstream.LimitsPolicy {
		t.Errorf("retention changed to %v; the cut-over must not touch it", info2.Config.Retention)
	}
	if !created2.Equal(created) || generation2 != generation {
		t.Errorf("identity changed: created %v -> %v, generation %q -> %q", created, created2, generation, generation2)
	}
}

// TestTrimAppliedRemovesOnlyWhatEveryDurableAcked is the no-silent-loss pin:
// with two durables (the apply worker and the SoR writer), a record leaves
// the log only once BOTH acked it, and the lagging one still receives every
// record it has not acked.
func TestTrimAppliedRemovesOnlyWhatEveryDurableAcked(t *testing.T) {
	l := newTestLog(t, Options{})
	ctx := context.Background()
	apply, err := l.Subscribe(ctx, telemetrylog.ConsumerSpec{Name: "applyworker", FilterSubjects: []string{"sbo.push.>"}})
	if err != nil {
		t.Fatalf("Subscribe apply: %v", err)
	}
	sor, err := l.Subscribe(ctx, telemetrylog.ConsumerSpec{Name: "sorwriter"})
	if err != nil {
		t.Fatalf("Subscribe sor: %v", err)
	}
	seqs := publishN(t, l, "r", 5)
	required := []string{"applyworker", "sorwriter"}

	consumeAndAck(t, apply, 5)
	consumeAndAck(t, sor, 2)
	waitAckFloor(t, l, "applyworker", seqs[4])
	waitAckFloor(t, l, "sorwriter", seqs[1])

	res, err := l.TrimApplied(ctx, required)
	if err != nil {
		t.Fatalf("TrimApplied: %v", err)
	}
	if res.Floor != seqs[1] || res.LimitingConsumer != "sorwriter" || len(res.HeldBy) != 0 {
		t.Fatalf("TrimApplied = %+v, want floor %d limited by sorwriter", res, seqs[1])
	}
	if res.Removed != 2 {
		t.Errorf("Removed = %d, want 2", res.Removed)
	}
	st, err := l.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Messages != 3 || st.FirstSequence != seqs[2] {
		t.Fatalf("after trim: %d messages from seq %d, want 3 from %d", st.Messages, st.FirstSequence, seqs[2])
	}

	// The lagging durable still gets the three records it never acked.
	rest := consumeAndAck(t, sor, 3)
	if len(rest) != 3 || rest[0] != seqs[2] {
		t.Fatalf("lagging durable received %v, want the 3 records from seq %d", rest, seqs[2])
	}
	waitAckFloor(t, l, "sorwriter", seqs[4])
	if _, err := l.TrimApplied(ctx, required); err != nil {
		t.Fatalf("second TrimApplied: %v", err)
	}
	if st, _ := l.Stats(ctx); st.Messages != 0 {
		t.Errorf("after both durables acked everything: %d messages, want 0", st.Messages)
	}
	// Sequences never reset: the next record continues the numbering.
	if next := publishN(t, l, "after", 1); next[0] != seqs[4]+1 {
		t.Errorf("next sequence = %d, want %d (a trim must not reset sequences)", next[0], seqs[4]+1)
	}
}

// TestTrimAppliedHeldWhileRequiredDurableMissing pins that a durable that does
// not exist yet (or was deleted) can never have records trimmed out from under
// it.
func TestTrimAppliedHeldWhileRequiredDurableMissing(t *testing.T) {
	l := newTestLog(t, Options{})
	ctx := context.Background()
	apply, err := l.Subscribe(ctx, telemetrylog.ConsumerSpec{Name: "applyworker"})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	seqs := publishN(t, l, "h", 3)
	consumeAndAck(t, apply, 3)
	waitAckFloor(t, l, "applyworker", seqs[2])

	res, err := l.TrimApplied(ctx, []string{"applyworker", "sorwriter"})
	if err != nil {
		t.Fatalf("TrimApplied: %v", err)
	}
	if len(res.HeldBy) != 1 || res.HeldBy[0] != "sorwriter" || res.Removed != 0 {
		t.Fatalf("TrimApplied = %+v, want held by sorwriter and nothing removed", res)
	}
	if st, _ := l.Stats(ctx); st.Messages != 3 {
		t.Fatalf("held trim removed records: %d left, want 3", st.Messages)
	}
	// The late durable then sees every record.
	sor, err := l.Subscribe(ctx, telemetrylog.ConsumerSpec{Name: "sorwriter"})
	if err != nil {
		t.Fatalf("Subscribe late: %v", err)
	}
	if got := consumeAndAck(t, sor, 3); len(got) != 3 || got[0] != seqs[0] {
		t.Fatalf("late durable received %v, want all 3 from seq %d", got, seqs[0])
	}
}

// TestFullStreamRefusesInsteadOfEvicting pins the disk safety valve: at the
// byte cap a publish fails ErrFull (the collector's 503 + Retry-After) and the
// unapplied records already stored are untouched; once the consumers catch up
// and the trim runs, publishes succeed again.
func TestFullStreamRefusesInsteadOfEvicting(t *testing.T) {
	l := newTestLog(t, Options{MaxBytes: 8 << 10, MaxMsgBytes: 1 << 10})
	ctx := context.Background()
	apply, err := l.Subscribe(ctx, telemetrylog.ConsumerSpec{Name: "applyworker"})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	body := strings.Repeat("x", 512)
	var stored []uint64
	var fullErr error
	for i := 0; i < 200 && fullErr == nil; i++ {
		res, err := l.Publish(ctx, rec("o", "sbo.push.o", fmt.Sprintf("f-%d", i), body, nil))
		switch {
		case err == nil:
			stored = append(stored, res.Sequence)
		case errors.Is(err, telemetrylog.ErrFull):
			fullErr = err
		default:
			t.Fatalf("Publish %d: %v", i, err)
		}
	}
	if fullErr == nil || len(stored) == 0 {
		t.Fatalf("never reached the byte cap (stored %d)", len(stored))
	}
	st, err := l.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.FirstSequence != stored[0] || st.Messages != uint64(len(stored)) {
		t.Fatalf("full stream evicted: first %d, %d messages; want first %d, %d", st.FirstSequence, st.Messages, stored[0], len(stored))
	}
	if st.MaxBytes != 8<<10 {
		t.Errorf("Stats.MaxBytes = %d, want %d", st.MaxBytes, 8<<10)
	}

	consumeAndAck(t, apply, len(stored))
	waitAckFloor(t, l, "applyworker", stored[len(stored)-1])
	if _, err := l.TrimApplied(ctx, []string{"applyworker"}); err != nil {
		t.Fatalf("TrimApplied: %v", err)
	}
	if _, err := l.Publish(ctx, rec("o", "sbo.push.o", "after-trim", body, nil)); err != nil {
		t.Fatalf("publish after trim: %v", err)
	}
}

// TestStatsReportAckFloorAndOldestPending pins the T-813 freshness inputs: the
// ack floor and the publish time of the oldest unacked record, per durable,
// honouring the durable's subject filter.
func TestStatsReportAckFloorAndOldestPending(t *testing.T) {
	l := newTestLog(t, Options{})
	ctx := context.Background()
	c, err := l.Subscribe(ctx, telemetrylog.ConsumerSpec{Name: "applyworker", FilterSubjects: []string{"sbo.push.>"}})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	// An OTLP record first: the push durable's filter must skip it.
	if _, err := l.Publish(ctx, rec("o", "sbo.otlp.o.traces", "otlp-0", "t", nil)); err != nil {
		t.Fatalf("Publish otlp: %v", err)
	}
	before := time.Now().Add(-time.Second)
	seqs := publishN(t, l, "p", 3)
	consumeAndAck(t, c, 1)
	waitAckFloor(t, l, "applyworker", seqs[0])

	st, err := l.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	var cs telemetrylog.ConsumerStats
	for _, x := range st.Consumers {
		if x.Name == "applyworker" {
			cs = x
		}
	}
	if cs.AckFloor != seqs[0] {
		t.Errorf("AckFloor = %d, want %d", cs.AckFloor, seqs[0])
	}
	if cs.OldestPendingAt.IsZero() || cs.OldestPendingAt.Before(before) || cs.OldestPendingAt.After(time.Now().Add(time.Second)) {
		t.Errorf("OldestPendingAt = %v, want the publish time of seq %d", cs.OldestPendingAt, seqs[1])
	}

	consumeAndAck(t, c, 2)
	waitAckFloor(t, l, "applyworker", seqs[2])
	st, _ = l.Stats(ctx)
	for _, x := range st.Consumers {
		if x.Name == "applyworker" && !x.OldestPendingAt.IsZero() {
			t.Errorf("caught-up durable still reports an oldest pending record: %v", x.OldestPendingAt)
		}
	}
}
