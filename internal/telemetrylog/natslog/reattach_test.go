package natslog

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

// TestStaleDurableFetchIsReattachRequiredAndSubscribeByNameRecovers is incident
// ORG-NATS-REATTACH-1 against a live embedded JetStream server. Two ways the
// durable behind a live handle can change identity — it is re-created, or its
// global credit is changed by another subscriber — must both surface the TYPED
// telemetrylog.ErrReattachRequired (callers branch with errors.Is, never on the
// message text), and a re-Subscribe by the SAME durable name must fetch again.
func TestStaleDurableFetchIsReattachRequiredAndSubscribeByNameRecovers(t *testing.T) {
	t.Run("durable recreated under the handle", func(t *testing.T) {
		log := newTestLog(t, Options{AckWait: time.Minute})
		if _, err := log.Publish(t.Context(), rec("org", telemetrylog.PushSubject("org"), "first", "first", nil)); err != nil {
			t.Fatal(err)
		}
		spec := telemetrylog.ConsumerSpec{Name: "reattacher", MaxAckPending: 1, AckWait: time.Minute}
		stale, err := log.Subscribe(t.Context(), spec)
		if err != nil {
			t.Fatal(err)
		}
		got, err := stale.Fetch(t.Context(), 8, 2*time.Second)
		if err != nil || len(got) != 1 {
			t.Fatalf("first fetch: n=%d err=%v", len(got), err)
		}
		// The record is deliberately NOT acked: a durable reattach by name must
		// redeliver it.

		// The broker drops and re-creates the same-name durable (what a restart
		// racing JetStream's store recovery does to a consumer).
		if err := log.js.DeleteConsumer(t.Context(), log.opts.Stream, spec.Name); err != nil {
			t.Fatal(err)
		}
		fresh, err := log.Subscribe(t.Context(), spec)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := stale.Fetch(t.Context(), 8, 0); !errors.Is(err, telemetrylog.ErrReattachRequired) {
			t.Fatalf("stale handle err=%v, want telemetrylog.ErrReattachRequired", err)
		}
		if err := stale.Close(); err != nil {
			t.Fatal(err)
		}
		again, err := fresh.Fetch(t.Context(), 8, 2*time.Second)
		if err != nil || len(again) != 1 || again[0].Sequence() != 1 {
			t.Fatalf("reattached fetch: n=%d err=%v", len(again), err)
		}
		if string(again[0].Record().Payload) != "first" {
			t.Fatalf("reattached record=%q", again[0].Record().Payload)
		}
	})

	t.Run("durable deleted under the handle", func(t *testing.T) {
		log := newTestLog(t, Options{AckWait: time.Minute})
		if _, err := log.Publish(t.Context(), rec("org", telemetrylog.PushSubject("org"), "first", "first", nil)); err != nil {
			t.Fatal(err)
		}
		spec := telemetrylog.ConsumerSpec{Name: "deleted", MaxAckPending: 1, AckWait: time.Minute}
		stale, err := log.Subscribe(t.Context(), spec)
		if err != nil {
			t.Fatal(err)
		}
		got, err := stale.Fetch(t.Context(), 8, 2*time.Second)
		if err != nil || len(got) != 1 {
			t.Fatalf("first fetch: n=%d err=%v", len(got), err)
		}
		if err := got[0].Ack(t.Context()); err != nil {
			t.Fatal(err)
		}
		// The durable is gone entirely: c.cons.Info now fails with the
		// JetStream 404 (err_code 10014) rather than returning a drifted
		// identity. That must still be the sentinel — a deleted durable is
		// exactly as unrecoverable on this handle as a re-created one.
		if err := log.js.DeleteConsumer(t.Context(), log.opts.Stream, spec.Name); err != nil {
			t.Fatal(err)
		}
		if _, err := stale.Fetch(t.Context(), 8, 0); !errors.Is(err, telemetrylog.ErrReattachRequired) {
			t.Fatalf("stale handle err=%v, want telemetrylog.ErrReattachRequired", err)
		}
		if err := stale.Close(); err != nil {
			t.Fatal(err)
		}
		// Re-Subscribe by name recovers — but note the honest cost: the deleted
		// durable took its cursor with it, so under DeliverAllPolicy the fresh
		// consumer replays the stream from sequence 1, including the record that
		// was already acked. Re-application is idempotent by ingest receipt.
		fresh, err := log.Subscribe(t.Context(), spec)
		if err != nil {
			t.Fatal(err)
		}
		again, err := fresh.Fetch(t.Context(), 8, 2*time.Second)
		if err != nil || len(again) != 1 || again[0].Sequence() != 1 {
			t.Fatalf("reattached fetch: n=%d err=%v", len(again), err)
		}
	})

	t.Run("global credit changed under the handle", func(t *testing.T) {
		// A short AckWait so the un-acked record redelivers on the fresh handle
		// within the test's fetch window.
		log := newTestLog(t, Options{AckWait: 300 * time.Millisecond})
		if _, err := log.Publish(t.Context(), rec("org", telemetrylog.PushSubject("org"), "only", "only", nil)); err != nil {
			t.Fatal(err)
		}
		spec := telemetrylog.ConsumerSpec{Name: "credit", MaxAckPending: 1, AckWait: 300 * time.Millisecond}
		stale, err := log.Subscribe(t.Context(), spec)
		if err != nil {
			t.Fatal(err)
		}
		got, err := stale.Fetch(t.Context(), 8, 2*time.Second)
		if err != nil || len(got) != 1 {
			t.Fatalf("first fetch: n=%d err=%v", len(got), err)
		}

		// Another subscriber relaxes the durable-wide credit this handle promised.
		info, err := log.js.Consumer(t.Context(), log.opts.Stream, spec.Name)
		if err != nil {
			t.Fatal(err)
		}
		cfg := info.CachedInfo().Config
		cfg.MaxAckPending = 5
		if _, err := log.js.CreateOrUpdateConsumer(t.Context(), log.opts.Stream, cfg); err != nil {
			t.Fatal(err)
		}

		if _, err := stale.Fetch(t.Context(), 8, 0); !errors.Is(err, telemetrylog.ErrReattachRequired) {
			t.Fatalf("stale handle err=%v, want telemetrylog.ErrReattachRequired", err)
		}
		if err := stale.Close(); err != nil {
			t.Fatal(err)
		}

		// Reattach by the SAME durable name with the SAME spec: the cursor is
		// preserved, so the un-acked record redelivers with a higher attempt.
		fresh, err := log.Subscribe(t.Context(), spec)
		if err != nil {
			t.Fatal(err)
		}
		again, err := fresh.Fetch(t.Context(), 8, 5*time.Second)
		if err != nil || len(again) != 1 {
			t.Fatalf("reattached fetch: n=%d err=%v", len(again), err)
		}
		if again[0].Sequence() != 1 || again[0].Attempt() < 2 {
			t.Fatalf("unacked record did not redeliver: seq=%d attempt=%d", again[0].Sequence(), again[0].Attempt())
		}
		if err := again[0].Ack(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
}

// countingJS wraps a live jetstream.JetStream and counts the consumer-API calls
// the adapter makes, so a test can assert on WHICH call Subscribe chose. The
// probe can also be told to report "not found" once, which is the recovery
// window the incident's root cause raced: the durable is really there, but the
// broker has not finished loading its consumer store yet.
type countingJS struct {
	jetstream.JetStream

	mu           sync.Mutex
	probes       int
	creates      int
	updates      int
	createUpdate int
	hideProbe    bool
}

func (j *countingJS) Consumer(ctx context.Context, stream, name string) (jetstream.Consumer, error) {
	j.mu.Lock()
	j.probes++
	hide := j.hideProbe
	j.hideProbe = false
	j.mu.Unlock()
	if hide {
		return nil, jetstream.ErrConsumerNotFound
	}
	return j.JetStream.Consumer(ctx, stream, name)
}

func (j *countingJS) CreateConsumer(ctx context.Context, stream string, cfg jetstream.ConsumerConfig) (jetstream.Consumer, error) {
	j.mu.Lock()
	j.creates++
	j.mu.Unlock()
	return j.JetStream.CreateConsumer(ctx, stream, cfg)
}

func (j *countingJS) UpdateConsumer(ctx context.Context, stream string, cfg jetstream.ConsumerConfig) (jetstream.Consumer, error) {
	j.mu.Lock()
	j.updates++
	j.mu.Unlock()
	return j.JetStream.UpdateConsumer(ctx, stream, cfg)
}

func (j *countingJS) CreateOrUpdateConsumer(ctx context.Context, stream string, cfg jetstream.ConsumerConfig) (jetstream.Consumer, error) {
	j.mu.Lock()
	j.createUpdate++
	j.mu.Unlock()
	return j.JetStream.CreateOrUpdateConsumer(ctx, stream, cfg)
}

func (j *countingJS) counts() (probes, creates, updates, createUpdate int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.probes, j.creates, j.updates, j.createUpdate
}

// countConsumerCalls installs the counting wrapper on log's JetStream context.
func countConsumerCalls(l *Log) *countingJS {
	c := &countingJS{JetStream: l.js}
	l.js = c
	return c
}

// consumerCreated reads the live durable's immutable creation stamp.
func consumerCreated(t *testing.T, l *Log, name string) time.Time {
	t.Helper()
	c, err := l.js.Consumer(t.Context(), l.opts.Stream, name)
	if err != nil {
		t.Fatalf("read durable %q: %v", name, err)
	}
	return c.CachedInfo().Created
}

// TestSubscribeProbesTheDurableBeforeCreating is residual 1 of incident
// ORG-NATS-REATTACH-1: the create-if-absent Subscribe wrote to the durable on
// EVERY subscribe (CreateOrUpdateConsumer), which is the write that races
// JetStream's store recovery and leaves a live handle pinned to an identity the
// recovered durable no longer matches. Subscribe must instead PROBE first,
// attach to a durable that already satisfies the spec without writing anything,
// reconcile one that does not (keeping its cursor), and attach to the WINNER
// when a create loses the race to a durable that appeared after the probe.
func TestSubscribeProbesTheDurableBeforeCreating(t *testing.T) {
	t.Run("existing matching durable is attached, never rewritten", func(t *testing.T) {
		log := newTestLog(t, Options{AckWait: time.Minute})
		spec := telemetrylog.ConsumerSpec{Name: "probed", MaxAckPending: 1, AckWait: time.Minute}
		if _, err := log.Subscribe(t.Context(), spec); err != nil {
			t.Fatal(err)
		}
		created := consumerCreated(t, log, spec.Name)

		calls := countConsumerCalls(log)
		second, err := log.Subscribe(t.Context(), spec)
		if err != nil {
			t.Fatal(err)
		}
		probes, creates, updates, createUpdate := calls.counts()
		if creates != 0 || updates != 0 || createUpdate != 0 {
			t.Fatalf("a matching durable was written to: creates=%d updates=%d createOrUpdate=%d (want 0/0/0)",
				creates, updates, createUpdate)
		}
		if probes != 1 {
			t.Fatalf("probes=%d, want exactly 1 (probe-then-attach)", probes)
		}
		if got := consumerCreated(t, log, spec.Name); !got.Equal(created) {
			t.Fatalf("durable identity moved: %s != %s", got, created)
		}
		if c, ok := second.(*natsConsumer); !ok || !c.consumerCreated.Equal(created) {
			t.Fatalf("handle pinned a different identity: %+v", second)
		}
	})

	t.Run("a spec with no credit request is still attached, not rewritten", func(t *testing.T) {
		// MaxAckPending unset means "the engine's default", which the server
		// resolves to its own non-zero value. Treating that as drift would call
		// every healthy durable drifted and put a write back on every Subscribe
		// — exactly the recovery-window write this residual removed.
		log := newTestLog(t, Options{AckWait: time.Minute})
		spec := telemetrylog.ConsumerSpec{Name: "defaulted", FilterSubjects: []string{telemetrylog.PushFilter}}
		if _, err := log.Subscribe(t.Context(), spec); err != nil {
			t.Fatal(err)
		}
		calls := countConsumerCalls(log)
		if _, err := log.Subscribe(t.Context(), spec); err != nil {
			t.Fatal(err)
		}
		_, creates, updates, createUpdate := calls.counts()
		if creates != 0 || updates != 0 || createUpdate != 0 {
			t.Fatalf("a credit-less spec rewrote its durable: creates=%d updates=%d createOrUpdate=%d",
				creates, updates, createUpdate)
		}
	})

	t.Run("create that loses the race attaches to the winner", func(t *testing.T) {
		log := newTestLog(t, Options{AckWait: time.Minute})
		if _, err := log.Publish(t.Context(), rec("org", telemetrylog.PushSubject("org"), "one", "one", nil)); err != nil {
			t.Fatal(err)
		}
		spec := telemetrylog.ConsumerSpec{Name: "racer", MaxAckPending: 1, AckWait: time.Minute}
		if _, err := log.Subscribe(t.Context(), spec); err != nil {
			t.Fatal(err)
		}
		created := consumerCreated(t, log, spec.Name)

		// The recovery window: the durable IS there, but this probe cannot see
		// it yet. The create therefore runs and must LOSE to the existing
		// durable — and the loser must attach to the winner rather than cache an
		// identity of its own.
		calls := countConsumerCalls(log)
		calls.hideProbe = true
		handle, err := log.Subscribe(t.Context(), spec)
		if err != nil {
			t.Fatalf("Subscribe after a lost create race: %v", err)
		}
		_, creates, _, _ := calls.counts()
		if creates != 1 {
			t.Fatalf("creates=%d, want 1 (the probe missed, so a create was attempted)", creates)
		}
		c, ok := handle.(*natsConsumer)
		if !ok || !c.consumerCreated.Equal(created) {
			t.Fatalf("handle did not attach to the winning durable: %+v want created=%s", handle, created)
		}
		got, err := handle.Fetch(t.Context(), 8, 2*time.Second)
		if err != nil || len(got) != 1 {
			t.Fatalf("fetch on the attached handle: n=%d err=%v", len(got), err)
		}
	})

	t.Run("drifted durable is reconciled and keeps its cursor", func(t *testing.T) {
		log := newTestLog(t, Options{AckWait: time.Minute})
		for _, body := range []string{"first", "second"} {
			if _, err := log.Publish(t.Context(), rec("org", telemetrylog.PushSubject("org"), body, body, nil)); err != nil {
				t.Fatal(err)
			}
		}
		spec := telemetrylog.ConsumerSpec{Name: "drifted", MaxAckPending: 1, AckWait: time.Minute}
		first, err := log.Subscribe(t.Context(), spec)
		if err != nil {
			t.Fatal(err)
		}
		got, err := first.Fetch(t.Context(), 1, 2*time.Second)
		if err != nil || len(got) != 1 {
			t.Fatalf("first fetch: n=%d err=%v", len(got), err)
		}
		if err := got[0].Ack(t.Context()); err != nil { // cursor now past sequence 1
			t.Fatal(err)
		}
		created := consumerCreated(t, log, spec.Name)

		// Another party relaxes the durable-wide credit this spec promises.
		live, err := log.js.Consumer(t.Context(), log.opts.Stream, spec.Name)
		if err != nil {
			t.Fatal(err)
		}
		cfg := live.CachedInfo().Config
		cfg.MaxAckPending = 7
		if _, err := log.js.UpdateConsumer(t.Context(), log.opts.Stream, cfg); err != nil {
			t.Fatal(err)
		}

		calls := countConsumerCalls(log)
		fresh, err := log.Subscribe(t.Context(), spec)
		if err != nil {
			t.Fatal(err)
		}
		_, creates, updates, _ := calls.counts()
		if updates != 1 || creates != 0 {
			t.Fatalf("drift was not reconciled by an update: creates=%d updates=%d", creates, updates)
		}
		if got := consumerCreated(t, log, spec.Name); !got.Equal(created) {
			t.Fatalf("reconcile re-created the durable: %s != %s", got, created)
		}
		// The cursor survived the reconcile: the next record is sequence 2, not
		// a replay from 1.
		next, err := fresh.Fetch(t.Context(), 8, 2*time.Second)
		if err != nil || len(next) != 1 || next[0].Sequence() != 2 {
			t.Fatalf("reconciled handle replayed the stream: n=%d seq=%v err=%v", len(next), next, err)
		}
	})

	t.Run("broker restart with a preserved store attaches the recovered durable", func(t *testing.T) {
		// The incident's own trigger, end to end: the broker restarts, its
		// JetStream store survives, and the process re-subscribes.
		dir := t.TempDir()
		opts := EmbeddedTestOptions(Options{AckWait: time.Minute, ConnectTimeout: 5 * time.Second})
		before, err := Embedded(t.Context(), dir, opts)
		if err != nil {
			t.Fatalf("Embedded: %v", err)
		}
		for _, body := range []string{"first", "second"} {
			if _, err := before.Publish(t.Context(), rec("org", telemetrylog.PushSubject("org"), body, body, nil)); err != nil {
				t.Fatal(err)
			}
		}
		spec := telemetrylog.ConsumerSpec{Name: "survivor", MaxAckPending: 1, AckWait: time.Minute}
		c, err := before.Subscribe(t.Context(), spec)
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.Fetch(t.Context(), 1, 2*time.Second)
		if err != nil || len(got) != 1 {
			t.Fatalf("pre-restart fetch: n=%d err=%v", len(got), err)
		}
		if err := got[0].Ack(t.Context()); err != nil {
			t.Fatal(err)
		}
		created := consumerCreated(t, before, spec.Name)
		if err := before.Close(); err != nil {
			t.Fatal(err)
		}

		after, err := Embedded(t.Context(), dir, opts)
		if err != nil {
			t.Fatalf("restart: %v", err)
		}
		t.Cleanup(func() { _ = after.Close() })
		calls := countConsumerCalls(after)
		fresh, err := after.Subscribe(t.Context(), spec)
		if err != nil {
			t.Fatalf("subscribe after restart: %v", err)
		}
		_, creates, updates, createUpdate := calls.counts()
		if creates != 0 || updates != 0 || createUpdate != 0 {
			t.Fatalf("the recovered durable was written to: creates=%d updates=%d createOrUpdate=%d",
				creates, updates, createUpdate)
		}
		if got := consumerCreated(t, after, spec.Name); !got.Equal(created) {
			t.Fatalf("recovered durable was re-created: %s != %s", got, created)
		}
		// Attached, not re-created: the cursor is intact, so the next delivery
		// is sequence 2 and NOT a replay of the already-acked record.
		next, err := fresh.Fetch(t.Context(), 8, 5*time.Second)
		if err != nil || len(next) != 1 || next[0].Sequence() != 2 {
			t.Fatalf("recovered consumer replayed: n=%d err=%v", len(next), err)
		}
	})
}

// TestClosedConsumerRefusesFetch pins residual 2's natslog half: the pull handle
// owns no broker-side resource to release (every Fetch issues its own pull
// request), but Close must still retire the handle locally so a read through a
// handle its owner already replaced is a typed refusal, not a silent success.
func TestClosedConsumerRefusesFetch(t *testing.T) {
	log := newTestLog(t, Options{AckWait: time.Minute})
	if _, err := log.Publish(t.Context(), rec("org", telemetrylog.PushSubject("org"), "one", "one", nil)); err != nil {
		t.Fatal(err)
	}
	c, err := log.Subscribe(t.Context(), telemetrylog.ConsumerSpec{Name: "closer", MaxAckPending: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close is not idempotent: %v", err)
	}
	if _, err := c.Fetch(t.Context(), 1, 0); !errors.Is(err, telemetrylog.ErrClosed) {
		t.Fatalf("Fetch after Close = %v, want telemetrylog.ErrClosed", err)
	}
	// The durable itself is untouched: a fresh Subscribe still delivers.
	fresh, err := log.Subscribe(t.Context(), telemetrylog.ConsumerSpec{Name: "closer", MaxAckPending: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := fresh.Fetch(t.Context(), 1, 2*time.Second); err != nil || len(got) != 1 {
		t.Fatalf("durable cursor was harmed by Close: n=%d err=%v", len(got), err)
	}
}

// TestReconnectReestablishesARecreatedStream is residual 4: a re-created stream
// leaves every Subscribe on a running process fenced off (the fail-closed
// generation rule), while a fresh boot against the same broker works. The
// refusal must be TYPED so a caller can branch on the capability, and
// Reconnect must re-establish exactly what that fresh boot establishes.
func TestReconnectReestablishesARecreatedStream(t *testing.T) {
	log := newTestLog(t, Options{})
	spec := telemetrylog.ConsumerSpec{Name: "reader", MaxAckPending: 1}
	if _, err := log.Subscribe(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	oldGeneration := log.orderGeneration

	if err := log.js.DeleteStream(t.Context(), log.opts.Stream); err != nil {
		t.Fatal(err)
	}
	// A fresh boot re-creates the stream; this process is still pinned to the
	// old one and must refuse, typed.
	recreated, err := Connect(t.Context(), log.opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recreated.Close() })

	_, err = log.Subscribe(t.Context(), spec)
	if !errors.Is(err, telemetrylog.ErrReconnectRequired) {
		t.Fatalf("Subscribe on a re-created stream = %v, want telemetrylog.ErrReconnectRequired", err)
	}
	var capability telemetrylog.Reconnector = log // compile-time capability check
	if err := capability.Reconnect(t.Context()); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	if log.orderGeneration == "" || log.orderGeneration == oldGeneration {
		t.Fatalf("Reconnect did not adopt the new generation: %q (was %q)", log.orderGeneration, oldGeneration)
	}
	fresh, err := log.Subscribe(t.Context(), spec)
	if err != nil {
		t.Fatalf("Subscribe after Reconnect: %v", err)
	}
	if _, err := log.Publish(t.Context(), rec("org", telemetrylog.PushSubject("org"), "post", "post", nil)); err != nil {
		t.Fatalf("Publish after Reconnect: %v", err)
	}
	got, err := fresh.Fetch(t.Context(), 8, 5*time.Second)
	if err != nil || len(got) != 1 {
		t.Fatalf("fetch after Reconnect: n=%d err=%v", len(got), err)
	}
	position, certified := got[0].(telemetrylog.OrderedDelivery).OrderPosition()
	if !certified || position.Generation != log.orderGeneration {
		t.Fatalf("delivery did not carry the NEW generation: %+v certified=%v", position, certified)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := log.Reconnect(t.Context()); !errors.Is(err, telemetrylog.ErrClosed) {
		t.Fatalf("Reconnect after Close = %v, want telemetrylog.ErrClosed", err)
	}
}

// TestSubscribeOnAVanishedStreamIsReconnectRequired is the deployed estate's
// actual shape of residual 4: the NATS sidecar runs on emptyDir with R=1, so a
// sidecar restart does not re-create the stream under a running process — it
// takes the stream AWAY. The identity read then fails with
// jetstream.ErrStreamNotFound rather than returning a DIFFERENT identity, and
// unless that is mapped onto the typed ErrReconnectRequired the Runner's
// reattach never reaches the Reconnect branch and every consumer backs off
// forever. Nothing re-creates the stream here: Reconnect must be what does.
func TestSubscribeOnAVanishedStreamIsReconnectRequired(t *testing.T) {
	log := newTestLog(t, Options{})
	spec := telemetrylog.ConsumerSpec{Name: "vanisher", MaxAckPending: 1}
	if _, err := log.Subscribe(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	oldGeneration := log.orderGeneration

	if err := log.js.DeleteStream(t.Context(), log.opts.Stream); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Subscribe(t.Context(), spec); !errors.Is(err, telemetrylog.ErrReconnectRequired) {
		t.Fatalf("Subscribe on a VANISHED stream = %v, want telemetrylog.ErrReconnectRequired", err)
	}
	// The recovery is the same one a re-created stream takes: Reconnect
	// re-establishes what a fresh boot would, including a NEW generation.
	if err := log.Reconnect(t.Context()); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	if log.orderGeneration == "" || log.orderGeneration == oldGeneration {
		t.Fatalf("Reconnect did not adopt a new generation: %q (was %q)", log.orderGeneration, oldGeneration)
	}
	fresh, err := log.Subscribe(t.Context(), spec)
	if err != nil {
		t.Fatalf("Subscribe after Reconnect: %v", err)
	}
	if _, err := log.Publish(t.Context(), rec("org", telemetrylog.PushSubject("org"), "post", "post", nil)); err != nil {
		t.Fatalf("Publish after Reconnect: %v", err)
	}
	got, err := fresh.Fetch(t.Context(), 8, 5*time.Second)
	if err != nil || len(got) != 1 {
		t.Fatalf("fetch after Reconnect: n=%d err=%v", len(got), err)
	}
	position, certified := got[0].(telemetrylog.OrderedDelivery).OrderPosition()
	if !certified || position.Generation != log.orderGeneration {
		t.Fatalf("delivery did not carry the NEW generation: %+v certified=%v", position, certified)
	}
}

// TestSubscribeRefusesADurableWithAnUnrepairableDeliveryPolicy pins the silent
// half of the attach-as-is change: a legacy durable created with DeliverLast /
// DeliverNew pins a start position that UpdateConsumer cannot repair. Attaching
// to it looks healthy — Fetch returns empty batches forever while the backlog
// behind that start position is never delivered, and an empty successful Fetch
// even keeps the dead-handle clock clear. It must fail CLOSED and NAME the
// field, and it must not rewrite the operator's durable on the way out.
func TestSubscribeRefusesADurableWithAnUnrepairableDeliveryPolicy(t *testing.T) {
	log := newTestLog(t, Options{})
	spec := telemetrylog.ConsumerSpec{Name: "legacy", MaxAckPending: 1, AckWait: log.opts.AckWait, MaxDeliver: log.opts.MaxDeliver}
	legacy := jetstream.ConsumerConfig{
		Name:          spec.Name,
		Durable:       spec.Name,
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxDeliver:    spec.MaxDeliver,
		AckWait:       spec.AckWait,
		DeliverPolicy: jetstream.DeliverLastPolicy,
		ReplayPolicy:  jetstream.ReplayInstantPolicy,
		MaxAckPending: spec.MaxAckPending,
	}
	before, err := log.js.CreateConsumer(t.Context(), log.opts.Stream, legacy)
	if err != nil {
		t.Fatal(err)
	}
	created := before.CachedInfo().Created

	_, err = log.Subscribe(t.Context(), spec)
	if !errors.Is(err, ErrDurableIncompatible) {
		t.Fatalf("Subscribe onto a DeliverLast durable = %v, want ErrDurableIncompatible", err)
	}
	if !strings.Contains(err.Error(), "deliver_policy") {
		t.Fatalf("refusal does not name the field: %v", err)
	}
	after, err := log.js.Consumer(t.Context(), log.opts.Stream, spec.Name)
	if err != nil {
		t.Fatal(err)
	}
	info, err := after.Info(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if info.Config.DeliverPolicy != jetstream.DeliverLastPolicy || !info.Created.Equal(created) {
		t.Fatalf("the refused durable was rewritten: policy=%v created=%s (was %s)",
			info.Config.DeliverPolicy, info.Created, created)
	}
}

// TestConsumerDriftIgnoresFilterSubjectOrder is NATS-3: the server may return a
// multi-subject filter in its own order. Judging that drifted would rewrite a
// perfectly healthy durable on EVERY reattach (a consumer-API write per
// attempt), which is exactly the churn attach-as-is exists to stop.
func TestConsumerDriftIgnoresFilterSubjectOrder(t *testing.T) {
	want := jetstream.ConsumerConfig{
		AckPolicy:      jetstream.AckExplicitPolicy,
		MaxDeliver:     10,
		AckWait:        time.Minute,
		FilterSubjects: []string{"sbo.push.>", "sbo.otlp.>"},
	}
	reordered := &jetstream.ConsumerInfo{Config: jetstream.ConsumerConfig{
		AckPolicy:      want.AckPolicy,
		MaxDeliver:     want.MaxDeliver,
		AckWait:        want.AckWait,
		FilterSubjects: []string{"sbo.otlp.>", "sbo.push.>"},
	}}
	if drift := consumerConfigDrift(reordered, want); drift != "" {
		t.Fatalf("a re-ordered filter list was judged drifted: %s", drift)
	}
	missing := &jetstream.ConsumerInfo{Config: jetstream.ConsumerConfig{
		AckPolicy:      want.AckPolicy,
		MaxDeliver:     want.MaxDeliver,
		AckWait:        want.AckWait,
		FilterSubjects: []string{"sbo.otlp.>", "sbo.other.>"},
	}}
	if drift := consumerConfigDrift(missing, want); drift == "" {
		t.Fatal("a genuinely different filter set was judged equal")
	}
}
