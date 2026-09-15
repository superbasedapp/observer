package logtest

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

// Config is the pinned tuning a Factory receives. The suite chooses small values
// so the capacity, size and quarantine arms need only a handful of operations and
// the timing arms resolve in well under a second of real time.
type Config struct {
	// MaxMessages caps stored records (0 = unbounded).
	MaxMessages int
	// MaxMsgBytes caps one record's payload (0 = unbounded).
	MaxMsgBytes int
	// DuplicateWindow is the de-dup window.
	DuplicateWindow time.Duration
	// MaxDeliver is the per-record delivery budget for the suite's consumers.
	MaxDeliver int
	// AckWait is the redelivery deadline for the suite's consumers.
	AckWait time.Duration
}

// Factory builds a fresh Log from cfg. The suite calls it once per sub-test and
// closes the result via t.Cleanup.
type Factory func(t *testing.T, cfg Config) telemetrylog.Log

// The org every record in the suite belongs to.
const org = "acme"

// Pinned small durations / caps (see doc.go). Real time; no injected clock.
const (
	ackWait     = 500 * time.Millisecond
	dupWindow   = 2 * time.Second
	maxDeliver  = 3
	maxMsgBytes = 1024
	capMessages = 3
)

// baseConfig is the generous default; capacity/size arms override the one field
// they exercise so no unrelated arm trips a cap.
func baseConfig() Config {
	return Config{
		MaxMessages:     0,
		MaxMsgBytes:     0,
		DuplicateWindow: dupWindow,
		MaxDeliver:      maxDeliver,
		AckWait:         ackWait,
	}
}

// RunConformance drives the shared contract against the Log the factory builds.
func RunConformance(t *testing.T, factory Factory) {
	RunConformanceWithCapabilities(t, factory, telemetrylog.Capabilities{ContentDedup: true, DiscardNew: true, ExactStats: true})
}

// RunConformanceWithCapabilities runs mandatory durability/delivery rules and
// the declared optional broker guarantees. Unsupported exact counters must
// return the named sentinel, not invented zero counts. Existing adapters use
// RunConformance and retain every original assertion.
func RunConformanceWithCapabilities(t *testing.T, factory Factory, caps telemetrylog.Capabilities) {
	t.Helper()
	cases := []struct {
		name string
		fn   func(t *testing.T, factory Factory)
	}{
		{"PublishReturnsSequence", testPublishReturnsSequence},
		{"DuplicateInsideWindowIsAcceptedNoop", testDuplicateNoop},
		{"DistinctPayloadIsNewRecord", testDistinctPayload},
		{"ErrFullWhenAtCapacity", testErrFull},
		{"ErrTooLarge", testErrTooLarge},
		{"InvalidRecordRejected", testInvalidRecord},
		{"OrderedDeliveryPerSubject", testOrderedDelivery},
		{"DurableConsumerReattachesByName", testDurableReattach},
		{"AckStopsRedelivery", testAckStops},
		{"NakRedeliversAfterDelay", testNakRedelivers},
		{"AckWaitExpiryRedelivers", testAckWaitExpiry},
		{"TermStopsRedelivery", testTermStops},
		{"MaxDeliverParksRecord", testMaxDeliverParks},
		{"FilterSubjectsWildcards", testFilterWildcards},
		{"AttrsRoundTrip", testAttrsRoundTrip},
		{"StatsReflectBacklog", testStatsBacklog},
		{"ProbeHealthy", testProbeHealthy},
	}
	for _, c := range cases {
		if c.name == "DuplicateInsideWindowIsAcceptedNoop" && !caps.ContentDedup {
			continue
		}
		if c.name == "ErrFullWhenAtCapacity" && !caps.DiscardNew {
			continue
		}
		if c.name == "StatsReflectBacklog" && !caps.ExactStats {
			continue
		}
		t.Run(c.name, func(t *testing.T) { c.fn(t, factory) })
	}
	t.Run("DeclaredCapabilities", func(t *testing.T) {
		log := newLog(t, factory, baseConfig())
		if got := telemetrylog.CapabilitiesOf(log); got != caps {
			t.Fatalf("capabilities=%+v, want %+v", got, caps)
		}
		if !caps.ExactStats {
			if _, err := log.Stats(t.Context()); !errors.Is(err, telemetrylog.ErrStatsUnavailable) {
				t.Fatalf("Stats=%v, want explicit unavailable", err)
			}
			if report := log.Probe(t.Context()); !report.Healthy || !report.StatsUnavailable {
				t.Fatalf("unsupported counters must not imply broker failure or zero depth: %+v", report)
			}
		}
	})
}

// --- helpers -------------------------------------------------------------

func newLog(t *testing.T, factory Factory, cfg Config) telemetrylog.Log {
	t.Helper()
	log := factory(t, cfg)
	t.Cleanup(func() { _ = log.Close() })
	return log
}

func pushRecord(payload string) telemetrylog.Record {
	subj := telemetrylog.PushSubject(org)
	p := []byte(payload)
	return telemetrylog.Record{
		Org:        org,
		Subject:    subj,
		DedupID:    telemetrylog.DedupID(org, subj, p),
		PayloadVer: telemetrylog.PushPayloadVer,
		Payload:    p,
	}
}

func otlpRecord(signal, payload string) telemetrylog.Record {
	subj := telemetrylog.OTLPSubject(org, signal)
	p := []byte(payload)
	return telemetrylog.Record{
		Org:     org,
		Subject: subj,
		DedupID: telemetrylog.DedupID(org, subj, p),
		Payload: p,
	}
}

func mustPublish(t *testing.T, log telemetrylog.Log, rec telemetrylog.Record) telemetrylog.PubResult {
	t.Helper()
	res, err := log.Publish(context.Background(), rec)
	if err != nil {
		t.Fatalf("Publish(%q) = %v, want nil", rec.Payload, err)
	}
	return res
}

func mustSubscribe(t *testing.T, log telemetrylog.Log, name string, filters ...string) telemetrylog.Consumer {
	t.Helper()
	c, err := log.Subscribe(context.Background(), telemetrylog.ConsumerSpec{
		Name:           name,
		FilterSubjects: filters,
		MaxDeliver:     maxDeliver,
		AckWait:        ackWait,
	})
	if err != nil {
		t.Fatalf("Subscribe(%q) = %v", name, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// fetch is a thin wrapper that fails the test on a fetch error.
func fetch(t *testing.T, c telemetrylog.Consumer, max int, wait time.Duration) []telemetrylog.Delivered {
	t.Helper()
	got, err := c.Fetch(context.Background(), max, wait)
	if err != nil {
		t.Fatalf("Fetch = %v", err)
	}
	return got
}

// fetchOne blocks up to wait for exactly one record and fails if none arrives.
func fetchOne(t *testing.T, c telemetrylog.Consumer, wait time.Duration) telemetrylog.Delivered {
	t.Helper()
	got := fetch(t, c, 1, wait)
	if len(got) != 1 {
		t.Fatalf("Fetch returned %d records, want 1", len(got))
	}
	return got[0]
}

func statsMessages(t *testing.T, log telemetrylog.Log) uint64 {
	t.Helper()
	st, err := log.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats = %v", err)
	}
	return st.Messages
}

func consumerStats(t *testing.T, log telemetrylog.Log, name string) telemetrylog.ConsumerStats {
	t.Helper()
	st, err := log.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats = %v", err)
	}
	for _, cs := range st.Consumers {
		if cs.Name == name {
			return cs
		}
	}
	t.Fatalf("consumer %q not in Stats", name)
	return telemetrylog.ConsumerStats{}
}

// --- sub-tests -----------------------------------------------------------

func testPublishReturnsSequence(t *testing.T, factory Factory) {
	log := newLog(t, factory, baseConfig())
	r1 := mustPublish(t, log, pushRecord("a"))
	if r1.Sequence == 0 || r1.Duplicate {
		t.Fatalf("first publish = %+v, want non-zero sequence, not duplicate", r1)
	}
	r2 := mustPublish(t, log, pushRecord("b"))
	if r2.Sequence <= r1.Sequence {
		t.Fatalf("second sequence %d not > first %d", r2.Sequence, r1.Sequence)
	}
}

func testDuplicateNoop(t *testing.T, factory Factory) {
	log := newLog(t, factory, baseConfig())
	first := mustPublish(t, log, pushRecord("dup"))
	if first.Duplicate {
		t.Fatal("first publish reported Duplicate")
	}
	second := mustPublish(t, log, pushRecord("dup")) // same bytes, same DedupID, within window
	if !second.Duplicate {
		t.Fatalf("second publish = %+v, want Duplicate=true", second)
	}
	if m := statsMessages(t, log); m != 1 {
		t.Fatalf("Messages = %d after a duplicate, want 1", m)
	}
}

func testDistinctPayload(t *testing.T, factory Factory) {
	log := newLog(t, factory, baseConfig())
	mustPublish(t, log, pushRecord("a"))
	res := mustPublish(t, log, pushRecord("b"))
	if res.Duplicate {
		t.Fatal("distinct payload reported Duplicate")
	}
	if telemetrylog.CapabilitiesOf(log).ExactStats {
		if m := statsMessages(t, log); m != 2 {
			t.Fatalf("Messages = %d, want 2", m)
		}
	}
}

func testErrFull(t *testing.T, factory Factory) {
	cfg := baseConfig()
	cfg.MaxMessages = capMessages
	log := newLog(t, factory, cfg)

	for _, p := range []string{"a", "b", "c"} {
		mustPublish(t, log, pushRecord(p))
	}
	// A NET-NEW record over the cap is shed.
	if _, err := log.Publish(context.Background(), pushRecord("d")); !errors.Is(err, telemetrylog.ErrFull) {
		t.Fatalf("net-new over cap: err = %v, want ErrFull", err)
	}
	// A duplicate AT capacity is still an accepted no-op.
	res, err := log.Publish(context.Background(), pushRecord("a"))
	if err != nil || !res.Duplicate {
		t.Fatalf("duplicate at capacity: res = %+v, err = %v, want Duplicate=true nil", res, err)
	}
	if m := statsMessages(t, log); m != capMessages {
		t.Fatalf("Messages = %d, want %d (d was shed)", m, capMessages)
	}
}

func testErrTooLarge(t *testing.T, factory Factory) {
	cfg := baseConfig()
	cfg.MaxMsgBytes = maxMsgBytes
	log := newLog(t, factory, cfg)

	big := make([]byte, maxMsgBytes+1)
	for i := range big {
		big[i] = 'x'
	}
	rec := pushRecord(string(big))
	if _, err := log.Publish(context.Background(), rec); !errors.Is(err, telemetrylog.ErrTooLarge) {
		t.Fatalf("oversize publish: err = %v, want ErrTooLarge", err)
	}
	// A payload within the cap is accepted.
	mustPublish(t, log, pushRecord("small"))
}

func testInvalidRecord(t *testing.T, factory Factory) {
	log := newLog(t, factory, baseConfig())
	bad := telemetrylog.Record{
		Org:     "", // empty org
		Subject: telemetrylog.PushSubject(org),
		DedupID: "deadbeef",
		Payload: []byte("p"),
	}
	if _, err := log.Publish(context.Background(), bad); !errors.Is(err, telemetrylog.ErrInvalidRecord) {
		t.Fatalf("invalid record: err = %v, want ErrInvalidRecord", err)
	}
}

func testOrderedDelivery(t *testing.T, factory Factory) {
	log := newLog(t, factory, baseConfig())
	for _, p := range []string{"a", "b", "c"} {
		mustPublish(t, log, pushRecord(p))
	}
	c := mustSubscribe(t, log, "ordered", telemetrylog.PushFilter)
	got := fetch(t, c, 10, time.Second)
	if len(got) != 3 {
		t.Fatalf("fetched %d, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].Sequence() <= got[i-1].Sequence() {
			t.Fatalf("delivery not in ascending sequence order: %d then %d", got[i-1].Sequence(), got[i].Sequence())
		}
	}
	for _, d := range got {
		if err := d.Ack(context.Background()); err != nil {
			t.Fatalf("Ack = %v", err)
		}
	}
}

func testDurableReattach(t *testing.T, factory Factory) {
	log := newLog(t, factory, baseConfig())
	mustPublish(t, log, pushRecord("survive"))

	c1 := mustSubscribe(t, log, "worker", telemetrylog.PushFilter)
	d := fetchOne(t, c1, time.Second)
	if d.Attempt() != 1 {
		t.Fatalf("first delivery Attempt = %d, want 1", d.Attempt())
	}
	// Worker dies between Fetch and Ack.
	if err := c1.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	// A new worker reattaches by the same Name; the unacked record redelivers
	// after AckWait.
	c2 := mustSubscribe(t, log, "worker", telemetrylog.PushFilter)
	again := fetchOne(t, c2, ackWait+2*time.Second)
	if again.Attempt() < 2 {
		t.Fatalf("redelivered Attempt = %d, want >= 2", again.Attempt())
	}
	if err := again.Ack(context.Background()); err != nil {
		t.Fatalf("Ack = %v", err)
	}
}

func testAckStops(t *testing.T, factory Factory) {
	log := newLog(t, factory, baseConfig())
	mustPublish(t, log, pushRecord("a"))
	c := mustSubscribe(t, log, "acker", telemetrylog.PushFilter)
	d := fetchOne(t, c, time.Second)
	if err := d.Ack(context.Background()); err != nil {
		t.Fatalf("Ack = %v", err)
	}
	// Past the AckWait window, an acked record must never redeliver.
	if got := fetch(t, c, 10, ackWait+300*time.Millisecond); len(got) != 0 {
		t.Fatalf("acked record redelivered: %d records", len(got))
	}
}

func testNakRedelivers(t *testing.T, factory Factory) {
	log := newLog(t, factory, baseConfig())
	mustPublish(t, log, pushRecord("a"))
	c := mustSubscribe(t, log, "naker", telemetrylog.PushFilter)
	d := fetchOne(t, c, time.Second)
	if err := d.Nak(context.Background(), 300*time.Millisecond); err != nil {
		t.Fatalf("Nak = %v", err)
	}
	// Before the delay elapses, nothing is redelivered.
	if got := fetch(t, c, 10, 100*time.Millisecond); len(got) != 0 {
		t.Fatalf("record redelivered before Nak delay: %d records", len(got))
	}
	// After the delay, it comes back as a fresh attempt.
	again := fetchOne(t, c, 2*time.Second)
	if again.Attempt() < 2 {
		t.Fatalf("Nak redelivery Attempt = %d, want >= 2", again.Attempt())
	}
	_ = again.Ack(context.Background())
}

func testAckWaitExpiry(t *testing.T, factory Factory) {
	log := newLog(t, factory, baseConfig())
	mustPublish(t, log, pushRecord("a"))
	c := mustSubscribe(t, log, "expiry", telemetrylog.PushFilter)
	first := fetchOne(t, c, time.Second) // no Ack, no Nak
	if first.Attempt() != 1 {
		t.Fatalf("first Attempt = %d, want 1", first.Attempt())
	}
	// The AckWait deadline alone must trigger redelivery.
	again := fetchOne(t, c, ackWait+time.Second)
	if again.Attempt() < 2 {
		t.Fatalf("AckWait redelivery Attempt = %d, want >= 2", again.Attempt())
	}
	_ = again.Ack(context.Background())
}

func testTermStops(t *testing.T, factory Factory) {
	log := newLog(t, factory, baseConfig())
	mustPublish(t, log, pushRecord("a"))
	c := mustSubscribe(t, log, "termer", telemetrylog.PushFilter)
	d := fetchOne(t, c, time.Second)
	if err := d.Term(context.Background(), "poison"); err != nil {
		t.Fatalf("Term = %v", err)
	}
	if got := fetch(t, c, 10, ackWait+300*time.Millisecond); len(got) != 0 {
		t.Fatalf("terminated record redelivered: %d records", len(got))
	}
}

func testMaxDeliverParks(t *testing.T, factory Factory) {
	log := newLog(t, factory, baseConfig()) // MaxDeliver = 3
	mustPublish(t, log, pushRecord("a"))
	c := mustSubscribe(t, log, "parker", telemetrylog.PushFilter)

	for attempt := 1; attempt <= maxDeliver; attempt++ {
		d := fetchOne(t, c, time.Second)
		if d.Attempt() != attempt {
			t.Fatalf("delivery %d reported Attempt %d", attempt, d.Attempt())
		}
		if err := d.Nak(context.Background(), 20*time.Millisecond); err != nil {
			t.Fatalf("Nak = %v", err)
		}
	}
	// After MaxDeliver unacked deliveries the record is parked, not redelivered.
	if got := fetch(t, c, 10, 500*time.Millisecond); len(got) != 0 {
		t.Fatalf("record redelivered past MaxDeliver: %d records (Attempt %d)", len(got), got[0].Attempt())
	}
}

func testFilterWildcards(t *testing.T, factory Factory) {
	log := newLog(t, factory, baseConfig())
	mustPublish(t, log, pushRecord("push-body"))
	mustPublish(t, log, otlpRecord(telemetrylog.SignalTraces, "t"))
	mustPublish(t, log, otlpRecord(telemetrylog.SignalLogs, "l"))
	mustPublish(t, log, otlpRecord(telemetrylog.SignalMetrics, "m"))

	pushC := mustSubscribe(t, log, "pushonly", telemetrylog.PushFilter)
	gotPush := fetch(t, pushC, 10, time.Second)
	if len(gotPush) != 1 {
		t.Fatalf("push filter fetched %d, want 1", len(gotPush))
	}
	if kind, _ := telemetrylog.KindOf(gotPush[0].Record().Subject); kind != telemetrylog.KindPush {
		t.Fatalf("push filter delivered a %q record", kind)
	}

	otlpC := mustSubscribe(t, log, "otlpall", telemetrylog.OTLPFilter)
	gotOTLP := fetch(t, otlpC, 10, time.Second)
	if len(gotOTLP) != 3 {
		t.Fatalf("otlp filter fetched %d, want 3", len(gotOTLP))
	}
	for _, d := range gotOTLP {
		if kind, _ := telemetrylog.KindOf(d.Record().Subject); kind != telemetrylog.KindOTLP {
			t.Fatalf("otlp filter delivered a %q record", kind)
		}
	}
}

func testAttrsRoundTrip(t *testing.T, factory Factory) {
	log := newLog(t, factory, baseConfig())
	rec := pushRecord("a")
	rec.Attrs = map[string]string{
		telemetrylog.AttrUserID:   "u1",
		telemetrylog.AttrPushedAt: "2026-09-08T00:00:00Z",
	}
	mustPublish(t, log, rec)

	c := mustSubscribe(t, log, "attrs", telemetrylog.PushFilter)
	d := fetchOne(t, c, time.Second)
	if !reflect.DeepEqual(d.Record().Attrs, rec.Attrs) {
		t.Fatalf("Attrs round-trip: got %v, want %v", d.Record().Attrs, rec.Attrs)
	}
	_ = d.Ack(context.Background())
}

func testStatsBacklog(t *testing.T, factory Factory) {
	cfg := baseConfig()
	cfg.AckWait = 30 * time.Second // keep AckPending stable across the assertions
	log := newLog(t, factory, cfg)

	mustPublish(t, log, pushRecord("a"))
	mustPublish(t, log, pushRecord("b"))
	c, err := log.Subscribe(context.Background(), telemetrylog.ConsumerSpec{
		Name:           "backlog",
		FilterSubjects: []string{telemetrylog.PushFilter},
		MaxDeliver:     maxDeliver,
		AckWait:        30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Subscribe = %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if cs := consumerStats(t, log, "backlog"); cs.Pending != 2 || cs.AckPending != 0 {
		t.Fatalf("before fetch: Pending=%d AckPending=%d, want 2,0", cs.Pending, cs.AckPending)
	}
	got := fetch(t, c, 10, time.Second)
	if len(got) != 2 {
		t.Fatalf("fetched %d, want 2", len(got))
	}
	if cs := consumerStats(t, log, "backlog"); cs.AckPending != 2 || cs.Pending != 0 {
		t.Fatalf("after fetch: Pending=%d AckPending=%d, want 0,2", cs.Pending, cs.AckPending)
	}
	for _, d := range got {
		_ = d.Ack(context.Background())
	}
	if cs := consumerStats(t, log, "backlog"); cs.AckPending != 0 || cs.Pending != 0 {
		t.Fatalf("after ack: Pending=%d AckPending=%d, want 0,0", cs.Pending, cs.AckPending)
	}
	if m := statsMessages(t, log); m != 2 {
		t.Fatalf("Messages = %d, want 2 (acks do not delete records)", m)
	}
}

func testProbeHealthy(t *testing.T, factory Factory) {
	log := newLog(t, factory, baseConfig())
	rep := log.Probe(context.Background())
	if !rep.Configured || !rep.Healthy {
		t.Fatalf("Probe = %+v, want Configured && Healthy", rep)
	}
	if rep.Engine == "" {
		t.Fatalf("Probe.Engine is empty")
	}
	if rep.Replicas < 1 {
		t.Fatalf("Probe.Replicas = %d, want >= 1", rep.Replicas)
	}
}
