package kafkalog

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
	"github.com/marmutapp/superbased-observer/internal/telemetrylog/logtest"
)

func liveOptions(t *testing.T, partitions int32) Options {
	t.Helper()
	brokers := os.Getenv("OBSERVER_KAFKA_TEST_BROKERS")
	if brokers == "" {
		t.Skip("set OBSERVER_KAFKA_TEST_BROKERS or run test-kafka.sh for real Kafka")
	}
	opts := Options{Brokers: strings.Split(brokers, ","), Topic: fmt.Sprintf("sbo-test-%d", time.Now().UnixNano()), RequiredReplicas: 1, MinInSyncReplicas: 1, AckWait: 500 * time.Millisecond}
	admin, err := kgo.NewClient(kgo.SeedBrokers(opts.Brokers...))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	req := kmsg.NewPtrCreateTopicsRequest()
	cleanup, minISR, unclean := "delete", "1", "false"
	req.Topics = []kmsg.CreateTopicsRequestTopic{{Topic: opts.Topic, NumPartitions: partitions, ReplicationFactor: 1, Configs: []kmsg.CreateTopicsRequestTopicConfig{{Name: "cleanup.policy", Value: &cleanup}, {Name: "min.insync.replicas", Value: &minISR}, {Name: "unclean.leader.election.enable", Value: &unclean}}}}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	resp, err := req.RequestWith(ctx, admin)
	if err != nil || len(resp.Topics) != 1 || resp.Topics[0].ErrorCode != 0 {
		t.Fatalf("create test topic: %v / %+v", err, resp)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req := kmsg.NewPtrDeleteTopicsRequest()
		req.TopicNames = []string{opts.Topic}
		req.Topics = []kmsg.DeleteTopicsRequestTopic{{Topic: &opts.Topic}}
		_, _ = req.RequestWith(ctx, admin)
	})
	return opts
}

func liveConnect(t *testing.T, opts Options) *Log {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		log, err := Connect(t.Context(), opts)
		if err == nil {
			t.Cleanup(func() { _ = log.Close() })
			return log
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestLiveConformance(t *testing.T) {
	logtest.RunConformanceWithCapabilities(t, func(t *testing.T, cfg logtest.Config) telemetrylog.Log {
		opts := liveOptions(t, 1)
		opts.MaxMsgBytes, opts.MaxDeliver, opts.AckWait = int32(cfg.MaxMsgBytes), cfg.MaxDeliver, cfg.AckWait
		return liveConnect(t, opts)
	}, telemetrylog.Capabilities{})
}

func mustConsumer(t *testing.T, log *Log, name string, ackWait time.Duration) telemetrylog.Consumer {
	t.Helper()
	consumer, err := log.Subscribe(t.Context(), telemetrylog.ConsumerSpec{Name: name, FilterSubjects: []string{telemetrylog.PushFilter}, MaxDeliver: 3, AckWait: ackWait})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = consumer.Close() })
	return consumer
}

func mustFetch(t *testing.T, consumer telemetrylog.Consumer, max int, wait time.Duration) []telemetrylog.Delivered {
	t.Helper()
	records, err := consumer.Fetch(t.Context(), max, wait)
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func mustProduce(t *testing.T, log *Log, body string, otlp bool) uint64 {
	t.Helper()
	result, err := log.Publish(t.Context(), testRecord(body, otlp))
	if err != nil {
		t.Fatal(err)
	}
	return result.Sequence
}

func TestLiveWholeAdapterRestartPreservesAckGapFilterNakAndTerm(t *testing.T) {
	opts := liveOptions(t, 1)
	first := liveConnect(t, opts)
	sequence := mustProduce(t, first, "gap", false)
	mustProduce(t, first, "filtered", true)
	mustProduce(t, first, "later-acked", false)
	mustProduce(t, first, "later-termed", false)
	consumer := mustConsumer(t, first, "restart", time.Second)
	batch := mustFetch(t, consumer, 10, 3*time.Second)
	if len(batch) != 3 {
		t.Fatalf("initial batch = %d", len(batch))
	}
	if err := batch[1].Ack(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := batch[2].Term(t.Context(), "quarantined-first"); err != nil {
		t.Fatal(err)
	}
	if err := batch[0].Nak(t.Context(), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second := liveConnect(t, opts)
	again := mustConsumer(t, second, "restart", time.Second)
	if got := mustFetch(t, again, 10, 100*time.Millisecond); len(got) != 0 {
		t.Fatal("Nak delay was lost on restart")
	}
	got := mustFetch(t, again, 10, 4*time.Second)
	if len(got) != 1 || got[0].Sequence() != sequence || got[0].Attempt() != 2 {
		t.Fatalf("restart redelivery = %+v", got)
	}
	if err := got[0].Ack(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	third := liveConnect(t, opts)
	if got := mustFetch(t, mustConsumer(t, third, "restart", time.Second), 10, time.Second); len(got) != 0 {
		t.Fatal("acked/filtered/termed offsets replayed after restart")
	}
}

func TestLiveWholeAdapterRestartPreservesAckWaitAttempt(t *testing.T) {
	opts := liveOptions(t, 1)
	first := liveConnect(t, opts)
	sequence := mustProduce(t, first, "unacknowledged", false)
	batch := mustFetch(t, mustConsumer(t, first, "ackwait", 200*time.Millisecond), 1, 3*time.Second)
	if len(batch) != 1 || batch[0].Attempt() != 1 {
		t.Fatal("first attempt missing")
	}
	_ = first.Close()
	second := liveConnect(t, opts)
	batch = mustFetch(t, mustConsumer(t, second, "ackwait", 200*time.Millisecond), 1, 3*time.Second)
	if len(batch) != 1 || batch[0].Sequence() != sequence || batch[0].Attempt() != 2 {
		t.Fatal("durable attempt lost across whole adapter recreation")
	}
}

func TestLiveRefusesMultiplePartitionsAndUnavailableBroker(t *testing.T) {
	opts := liveOptions(t, 2)
	if log, err := Connect(t.Context(), opts); err == nil {
		_ = log.Close()
		t.Fatal("ambiguous multi-partition sequence accepted")
	}
	opts = Options{Brokers: []string{"127.0.0.1:1"}, ConnectTimeout: 100 * time.Millisecond}
	if _, err := Connect(t.Context(), opts); !errors.Is(err, telemetrylog.ErrUnavailable) {
		t.Fatalf("unavailable broker = %v", err)
	}
}

func TestLiveFilteredOnlyOffsetsPersistAndPolicyChangeRefused(t *testing.T) {
	opts := liveOptions(t, 1)
	first := liveConnect(t, opts)
	mustProduce(t, first, "filtered-only-1", true)
	mustProduce(t, first, "filtered-only-2", true)
	c := mustConsumer(t, first, "filters", time.Second)
	if got := mustFetch(t, c, 10, 200*time.Millisecond); len(got) != 0 {
		t.Fatal("filter mismatch delivered")
	}
	private := c.(*consumer)
	offset, metadata, err := private.committed(t.Context())
	if err != nil || offset != 2 {
		t.Fatalf("filtered cursor not durable: offset=%d err=%v", offset, err)
	}
	state, err := decodeState(metadata, private.fingerprint, offset)
	if err != nil || state.Next != 2 || len(state.Pending) != 0 {
		t.Fatalf("filtered durable state invalid: %v", err)
	}
	_ = first.Close()
	second := liveConnect(t, opts)
	changed, err := second.Subscribe(t.Context(), telemetrylog.ConsumerSpec{Name: "filters", FilterSubjects: []string{telemetrylog.OTLPFilter}, MaxDeliver: 3, AckWait: time.Second})
	if err == nil {
		_ = changed.Close()
		t.Fatal("changed filter silently inherited an already-skipped durable cursor")
	}
}

func TestLiveRetentionCannotSilentlyResetAnUnackedGap(t *testing.T) {
	opts := liveOptions(t, 1)
	first := liveConnect(t, opts)
	mustProduce(t, first, "must-not-skip", false)
	batch := mustFetch(t, mustConsumer(t, first, "retention", time.Second), 1, time.Second)
	if len(batch) != 1 {
		t.Fatal("initial delivery missing")
	}
	_ = first.Close()
	admin, err := kgo.NewClient(kgo.SeedBrokers(opts.Brokers...))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	request := kmsg.NewPtrDeleteRecordsRequest()
	request.Topics = []kmsg.DeleteRecordsRequestTopic{{Topic: opts.Topic, Partitions: []kmsg.DeleteRecordsRequestTopicPartition{{Partition: 0, Offset: 1}}}}
	response, err := request.RequestWith(t.Context(), admin)
	if err != nil || len(response.Topics) != 1 || response.Topics[0].Partitions[0].ErrorCode != 0 {
		t.Fatalf("advance retention: %v", err)
	}
	second := liveConnect(t, opts)
	c := mustConsumer(t, second, "retention", time.Second)
	if _, err := c.Fetch(t.Context(), 1, time.Second); err == nil {
		t.Fatal("missing unfinished record silently reset past retention")
	}
}

func TestLiveBoundedOutstandingAndConcurrentAcknowledgments(t *testing.T) {
	opts := liveOptions(t, 1)
	log := liveConnect(t, opts)
	for i := 0; i < maxOutstanding+6; i++ {
		mustProduce(t, log, fmt.Sprintf("bounded-%d", i), false)
	}
	c := mustConsumer(t, log, "bounded", 30*time.Second)
	batch := mustFetch(t, c, 100, time.Second)
	if len(batch) != maxOutstanding {
		t.Fatalf("batch size = %d, want bounded64", len(batch))
	}
	if got := mustFetch(t, c, 100, 100*time.Millisecond); len(got) != 0 {
		t.Fatal("outstanding limit exceeded")
	}
	var group sync.WaitGroup
	errorsFound := make(chan error, len(batch))
	for _, delivery := range batch {
		group.Add(1)
		go func(d telemetrylog.Delivered) { defer group.Done(); errorsFound <- d.Ack(t.Context()) }(delivery)
	}
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	remainder := mustFetch(t, c, 100, time.Second)
	if len(remainder) != 6 {
		t.Fatalf("remaining batch = %d", len(remainder))
	}
	for _, d := range remainder {
		if err := d.Ack(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	_ = log.Close()
	reopened := liveConnect(t, opts)
	if got := mustFetch(t, mustConsumer(t, reopened, "bounded", 30*time.Second), 100, 200*time.Millisecond); len(got) != 0 {
		t.Fatal("concurrent acknowledgments lost durable progress")
	}
}

func TestLiveConsumerGroupFailoverPreservesUnackedAttempt(t *testing.T) {
	opts := liveOptions(t, 1)
	first := liveConnect(t, opts)
	sequence := mustProduce(t, first, "group-failover", false)
	one := mustConsumer(t, first, "failover", 300*time.Millisecond)
	batch := mustFetch(t, one, 1, time.Second)
	if len(batch) != 1 {
		t.Fatal("first group owner did not receive record")
	}
	second := liveConnect(t, opts)
	two := mustConsumer(t, second, "failover", 300*time.Millisecond)
	_ = first.Close()
	if err := batch[0].Ack(t.Context()); !errors.Is(err, telemetrylog.ErrClosed) {
		t.Fatalf("closed owner's Ack = %v", err)
	}
	redelivered := mustFetch(t, two, 1, 4*time.Second)
	if len(redelivered) != 1 || redelivered[0].Sequence() != sequence || redelivered[0].Attempt() != 2 {
		t.Fatal("group failover lost durable attempt or record")
	}
	if err := redelivered[0].Ack(t.Context()); err != nil {
		t.Fatal(err)
	}
}
