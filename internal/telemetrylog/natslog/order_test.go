package natslog

import (
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

func TestMaxAckPendingRetainsCreditAcrossNakAndReplicas(t *testing.T) {
	log := newTestLog(t, Options{AckWait: time.Minute})
	for _, body := range []string{"first", "second"} {
		if _, err := log.Publish(t.Context(), rec("org", telemetrylog.PushSubject("org"), body, body, nil)); err != nil {
			t.Fatal(err)
		}
	}
	spec := telemetrylog.ConsumerSpec{Name: "ordered", MaxAckPending: 1, AckWait: time.Minute}
	first, err := log.Subscribe(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := log.Subscribe(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	info, err := log.js.Consumer(t.Context(), log.opts.Stream, spec.Name)
	if err != nil || info.CachedInfo().Config.MaxAckPending != 1 {
		t.Fatalf("durable global credit not one: err=%v", err)
	}
	got, err := first.Fetch(t.Context(), 64, time.Second)
	if err != nil || len(got) != 1 || got[0].Sequence() != 1 {
		t.Fatalf("first=%v err=%v", got, err)
	}
	if blocked, err := second.Fetch(t.Context(), 64, 0); err != nil || len(blocked) != 0 {
		t.Fatalf("inflight credit escaped: n=%d err=%v", len(blocked), err)
	}
	if err := got[0].Nak(t.Context(), 300*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if blocked, err := second.Fetch(t.Context(), 64, 50*time.Millisecond); err != nil || len(blocked) != 0 {
		t.Fatalf("NAK released durable credit: n=%d err=%v", len(blocked), err)
	}
	retry, err := second.Fetch(t.Context(), 64, time.Second)
	if err != nil || len(retry) != 1 || retry[0].Sequence() != 1 || retry[0].Attempt() != 2 {
		t.Fatalf("retry=%v err=%v", retry, err)
	}
	before, trusted := got[0].(telemetrylog.OrderedDelivery).OrderPosition()
	after, retryTrusted := retry[0].(telemetrylog.OrderedDelivery).OrderPosition()
	if !trusted || !retryTrusted || before != after {
		t.Fatalf("retry provenance changed: before=%+v after=%+v", before, after)
	}
	if err := retry[0].Ack(t.Context()); err != nil {
		t.Fatal(err)
	}
	// A JetStream Ack is fire-and-forget, and under MaxAckPending=1 the next
	// record is only released once the server has PROCESSED that ack. The
	// assertion is "the credit comes back", not "within one second", so the
	// window is generous: a one-second window loses this race whenever the box
	// is busy (two test packages in parallel on a 2-core runner) and turns a
	// correct adapter into a red build.
	next, err := first.Fetch(t.Context(), 64, 10*time.Second)
	if err != nil || len(next) != 1 || next[0].Sequence() != 2 {
		t.Fatalf("next=%v err=%v", next, err)
	}
}

func TestOrderingMetadataSurvivesRestartWithoutCertifyingLegacyStreams(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		name := "legacy-unmarked"
		if trusted {
			name = "new-marked"
		}
		t.Run(name, func(t *testing.T) {
			original := newTestLog(t, Options{})
			info, err := original.stream.Info(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			cfg := info.Config
			cfg.Metadata["operator.extension"] = "preserve-me"
			if !trusted {
				delete(cfg.Metadata, orderingMetadataKey)
			}
			if _, err := original.js.UpdateStream(t.Context(), cfg); err != nil {
				t.Fatal(err)
			}
			if _, err := original.Publish(t.Context(), rec("org", telemetrylog.PushSubject("org"), "existing", "existing", nil)); err != nil {
				t.Fatal(err)
			}
			reopened, err := Connect(t.Context(), original.opts)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			current, err := reopened.stream.Info(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if current.Config.Metadata["operator.extension"] != "preserve-me" {
				t.Fatal("restart discarded operator metadata")
			}
			if got := current.Config.Metadata[orderingMetadataKey] == orderingMetadataVersion; got != trusted {
				t.Fatalf("ordering marker changed: trusted=%v want=%v", got, trusted)
			}
			consumer, err := reopened.Subscribe(t.Context(), telemetrylog.ConsumerSpec{Name: "reader", MaxAckPending: 1})
			if err != nil {
				t.Fatal(err)
			}
			got, err := consumer.Fetch(t.Context(), 1, time.Second)
			if err != nil || len(got) != 1 {
				t.Fatalf("fetch=%v err=%v", got, err)
			}
			position, certified := got[0].(telemetrylog.OrderedDelivery).OrderPosition()
			if certified != trusted {
				t.Fatalf("certified=%v want=%v position=%+v", certified, trusted, position)
			}
			if trusted && (position.Generation != original.orderGeneration || position.Sequence != 1) {
				t.Fatalf("restart changed occurrence=%+v", position)
			}
		})
	}
}

func TestOrderGenerationChangesOnStreamRecreationAndFencesOldConsumer(t *testing.T) {
	original := newTestLog(t, Options{})
	spec := telemetrylog.ConsumerSpec{Name: "reader", MaxAckPending: 1}
	oldConsumer, err := original.Subscribe(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := original.js.DeleteStream(t.Context(), original.opts.Stream); err != nil {
		t.Fatal(err)
	}
	recreated, err := Connect(t.Context(), original.opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recreated.Close() })
	if recreated.orderGeneration == "" || recreated.orderGeneration == original.orderGeneration {
		t.Fatal("stream recreation reused ordering generation")
	}
	if _, err := recreated.Subscribe(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	if _, err := oldConsumer.Fetch(t.Context(), 1, 0); err == nil {
		t.Fatal("old handle followed same-name recreated durable")
	}
	if _, err := original.Subscribe(t.Context(), spec); err == nil {
		t.Fatal("old log attached to recreated stream with stale generation")
	}
}

type orderMetadataMessage struct {
	jetstream.Msg
	metadata *jetstream.MsgMetadata
	err      error
}

func (m orderMetadataMessage) Metadata() (*jetstream.MsgMetadata, error) { return m.metadata, m.err }
func (m orderMetadataMessage) Headers() nats.Header                      { return nats.Header{} }
func (m orderMetadataMessage) Subject() string                           { return telemetrylog.PushSubject("org") }

func (m orderMetadataMessage) Data() []byte { return []byte("payload") }

func TestOrderPositionRejectsUntrustedMetadata(t *testing.T) {
	created := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, stream, generation string
		sequence                 uint64
		stamp                    time.Time
		err                      error
		want                     bool
	}{
		{"current", "SBO_TELEMETRY", "trusted", 1, created, nil, true},
		{"unmarked", "SBO_TELEMETRY", "", 1, created, nil, false},
		{"foreign-stream", "OTHER", "trusted", 1, created, nil, false},
		{"zero-sequence", "SBO_TELEMETRY", "trusted", 0, created, nil, false},
		{"before-creation", "SBO_TELEMETRY", "trusted", 1, created.Add(-time.Second), nil, false},
		{"malformed", "SBO_TELEMETRY", "trusted", 1, created, errors.New("bad metadata"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			message := orderMetadataMessage{metadata: &jetstream.MsgMetadata{Stream: tc.stream, Sequence: jetstream.SequencePair{Stream: tc.sequence}, Timestamp: tc.stamp}, err: tc.err}
			_, trusted := newDelivered(message, "SBO_TELEMETRY", created, tc.generation).OrderPosition()
			if trusted != tc.want {
				t.Fatalf("trusted=%v want=%v", trusted, tc.want)
			}
		})
	}
}
