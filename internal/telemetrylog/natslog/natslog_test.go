package natslog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

// testAckWait / testDupWindow keep the whole file fast (well under 60s wall).
const (
	testAckWait   = 500 * time.Millisecond
	testDupWindow = 2 * time.Second
)

// newTestLog starts an embedded JetStream server in a temp dir on a random
// loopback port and returns a ready Log, closed at test cleanup. The caller may
// override any Options field; the small AckWait / DuplicateWindow defaults keep
// the timing tests quick.
const (
	// testStreamMaxBytes is the stream storage reservation EVERY embedded test
	// broker makes. It is deliberately tiny and explicit instead of
	// DefaultMaxBytes (10 GiB): a stream reservation the host cannot back is
	// refused by the broker at create time (JetStream 10047), so the production
	// default made every natslog test fail at once on a small CI runner while
	// passing on a roomy dev box. A test that PROVES the capacity check
	// (TestConnectStreamStorageCapacity, TestPreflightCapacityErrAgainstFakeJetStream)
	// sets its own explicit limits and never goes through here.
	testStreamMaxBytes int64 = 64 << 20
	// testBrokerMaxStore caps the embedded server's whole JetStream pool, so a
	// test broker's footprint is bounded by what the test asked for rather than
	// by the machine's free disk. Comfortably above testStreamMaxBytes: the
	// pool must hold the reservation, not merely equal it.
	testBrokerMaxStore int64 = 256 << 20
)

// EmbeddedTestOptions fills o with the shared embedded-test-broker footprint
// (see testStreamMaxBytes / testBrokerMaxStore) plus the package's standard test
// timings, leaving every field the caller set alone. It is exported so the
// external conformance test package builds its broker from the SAME numbers —
// one owner for "how big is a test broker".
func EmbeddedTestOptions(o Options) Options {
	if o.MaxBytes == 0 {
		o.MaxBytes = testStreamMaxBytes
	}
	if o.EmbeddedMaxStore == 0 {
		o.EmbeddedMaxStore = testBrokerMaxStore
	}
	if o.AckWait == 0 {
		o.AckWait = testAckWait
	}
	if o.DuplicateWindow == 0 {
		o.DuplicateWindow = testDupWindow
	}
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = 3 * time.Second
	}
	return o
}

// TestEmbeddedTestBrokerFootprintIsExplicit pins the CI failure this closes: a
// test broker must reserve the small explicit footprint, never the 10 GiB
// production default, because a reservation the host cannot back is refused by
// the broker at create time — which on a small runner failed every natslog test
// at once while passing on a roomy dev box. Both halves are asserted: the shared
// fixture reserves testStreamMaxBytes, and the production default against a
// bounded pool really is refused (so the fixture is load-bearing, not decorative).
func TestEmbeddedTestBrokerFootprintIsExplicit(t *testing.T) {
	l := newTestLog(t, Options{})
	info, err := l.stream.Info(context.Background())
	if err != nil {
		t.Fatalf("stream info: %v", err)
	}
	if info.Config.MaxBytes != testStreamMaxBytes {
		t.Fatalf("test stream MaxBytes = %d, want the explicit test footprint %d",
			info.Config.MaxBytes, testStreamMaxBytes)
	}
	if info.Config.MaxBytes >= DefaultMaxBytes {
		t.Fatalf("the test broker is using the production storage default (%d)", DefaultMaxBytes)
	}

	oversized, err := Embedded(context.Background(), t.TempDir(), Options{
		MaxBytes:         DefaultMaxBytes,
		EmbeddedMaxStore: testBrokerMaxStore,
		ConnectTimeout:   3 * time.Second,
	})
	if oversized != nil {
		t.Cleanup(func() { _ = oversized.Close() })
	}
	if err == nil {
		t.Fatal("a 10 GiB reservation against a bounded pool was accepted; the fixture would not be protecting anything")
	}
	if !strings.Contains(err.Error(), "cannot provision stream") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

func newTestLog(t *testing.T, o Options) *Log {
	t.Helper()
	o = EmbeddedTestOptions(o)
	l, err := Embedded(context.Background(), t.TempDir(), o)
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func rec(org, subject, dedup string, payload string, attrs map[string]string) telemetrylog.Record {
	return telemetrylog.Record{
		Org:        org,
		Subject:    subject,
		DedupID:    dedup,
		PayloadVer: telemetrylog.PushPayloadVer,
		Payload:    []byte(payload),
		Attrs:      attrs,
	}
}

// TestEmbeddedStartupUnderBudget records the embedded server's startup time so
// the report can quote it and a regression that makes boot slow is visible.
func TestEmbeddedStartupUnderBudget(t *testing.T) {
	start := time.Now()
	_ = newTestLog(t, Options{})
	elapsed := time.Since(start)
	t.Logf("embedded server ready + stream provisioned in %s", elapsed)
	if elapsed > 10*time.Second {
		t.Errorf("embedded startup took %s, want < 10s", elapsed)
	}
}

// TestPublishFetchAckRoundTrip covers the happy path: a record published lands,
// fetches back byte-for-byte with its attrs and payload version, carries a
// 1-based Attempt and a non-zero Sequence, and acks cleanly. Stats then report
// the depth.
func TestPublishFetchAckRoundTrip(t *testing.T) {
	l := newTestLog(t, Options{})
	ctx := context.Background()

	attrs := map[string]string{
		telemetrylog.AttrUserID:   "u-42",
		telemetrylog.AttrPushedAt: "2026-09-08T00:00:00Z",
		telemetrylog.AttrSignal:   "traces",
	}
	r := rec("orgA", "sbo.push.orgA", "dedup-1", "hello-payload", attrs)
	res, err := l.Publish(ctx, r)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if res.Duplicate {
		t.Error("first publish reported Duplicate")
	}
	if res.Sequence == 0 {
		t.Error("first publish Sequence = 0, want the stream sequence")
	}

	cons, err := l.Subscribe(ctx, telemetrylog.ConsumerSpec{Name: "rt", FilterSubjects: []string{"sbo.push.*"}})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	got, err := cons.Fetch(ctx, 1, time.Second)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Fetch returned %d records, want 1", len(got))
	}
	d := got[0]
	if d.Attempt() != 1 {
		t.Errorf("Attempt = %d, want 1", d.Attempt())
	}
	if d.Sequence() != res.Sequence {
		t.Errorf("Delivered Sequence = %d, want %d", d.Sequence(), res.Sequence)
	}
	gr := d.Record()
	if gr.Org != r.Org || gr.Subject != r.Subject || gr.DedupID != r.DedupID {
		t.Errorf("record identity mismatch: got %+v", gr)
	}
	if gr.PayloadVer != r.PayloadVer {
		t.Errorf("PayloadVer = %d, want %d", gr.PayloadVer, r.PayloadVer)
	}
	if string(gr.Payload) != "hello-payload" {
		t.Errorf("Payload = %q, want %q", gr.Payload, "hello-payload")
	}
	for k, v := range attrs {
		if gr.Attrs[k] != v {
			t.Errorf("attr %q = %q, want %q (round-trip through headers)", k, gr.Attrs[k], v)
		}
	}
	if err := d.Ack(ctx); err != nil {
		t.Fatalf("Ack: %v", err)
	}

	stats, err := l.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Messages != 1 {
		t.Errorf("Stats.Messages = %d, want 1", stats.Messages)
	}
	if stats.LastSequence != res.Sequence {
		t.Errorf("Stats.LastSequence = %d, want %d", stats.LastSequence, res.Sequence)
	}
	var found bool
	for _, cs := range stats.Consumers {
		if cs.Name == "rt" {
			found = true
			if cs.AckPending != 0 || cs.Pending != 0 {
				t.Errorf("after Ack, consumer backlog = %+v, want zero", cs)
			}
		}
	}
	if !found {
		t.Error("Stats.Consumers missing the durable consumer 'rt'")
	}
}

// TestPublishDuplicate pins the dedup-window contract: a re-publish of the same
// DedupID inside the window returns Duplicate=true and stores nothing new.
func TestPublishDuplicate(t *testing.T) {
	l := newTestLog(t, Options{})
	ctx := context.Background()
	r := rec("orgA", "sbo.push.orgA", "dedup-same", "body", nil)

	if _, err := l.Publish(ctx, r); err != nil {
		t.Fatalf("first Publish: %v", err)
	}
	res, err := l.Publish(ctx, r)
	if err != nil {
		t.Fatalf("duplicate Publish: %v", err)
	}
	if !res.Duplicate {
		t.Error("duplicate publish did not report Duplicate=true")
	}
	stats, err := l.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Messages != 1 {
		t.Errorf("Stats.Messages = %d after a duplicate, want 1 (nothing stored)", stats.Messages)
	}
}

// TestPublishErrorMapping is table-driven over the per-record failure modes.
func TestPublishErrorMapping(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		opts    Options
		records []telemetrylog.Record
		wantErr error
	}{
		{
			name:    "too large",
			opts:    Options{MaxMsgBytes: 1024},
			records: []telemetrylog.Record{rec("o", "sbo.push.o", "big", string(make([]byte, 4096)), nil)},
			wantErr: telemetrylog.ErrTooLarge,
		},
		{
			name: "full",
			opts: Options{MaxMessages: 2},
			records: []telemetrylog.Record{
				rec("o", "sbo.push.o", "d1", "a", nil),
				rec("o", "sbo.push.o", "d2", "b", nil),
				rec("o", "sbo.push.o", "d3", "c", nil),
			},
			wantErr: telemetrylog.ErrFull,
		},
		{
			name:    "invalid record",
			opts:    Options{},
			records: []telemetrylog.Record{rec("", "sbo.push.o", "d", "x", nil)},
			wantErr: telemetrylog.ErrInvalidRecord,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := newTestLog(t, tc.opts)
			var lastErr error
			for _, r := range tc.records {
				_, lastErr = l.Publish(ctx, r)
			}
			if !errors.Is(lastErr, tc.wantErr) {
				t.Fatalf("last Publish err = %v, want errors.Is %v", lastErr, tc.wantErr)
			}
		})
	}
}

// TestDurableReattach proves a consumer re-Subscribe'd by the same Name after
// Close gets its unacked record redelivered (the no-loss-on-worker-crash
// contract), with Attempt advancing to 2.
func TestDurableReattach(t *testing.T) {
	l := newTestLog(t, Options{})
	ctx := context.Background()
	if _, err := l.Publish(ctx, rec("o", "sbo.push.o", "d1", "payload", nil)); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	c1, err := l.Subscribe(ctx, telemetrylog.ConsumerSpec{Name: "worker"})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	got, err := c1.Fetch(ctx, 1, time.Second)
	if err != nil || len(got) != 1 {
		t.Fatalf("first Fetch: err=%v n=%d", err, len(got))
	}
	if got[0].Attempt() != 1 {
		t.Errorf("first delivery Attempt = %d, want 1", got[0].Attempt())
	}
	// Simulate a crash between Fetch and Ack: drop the handle without acking.
	if err := c1.Close(); err != nil {
		t.Fatalf("consumer Close: %v", err)
	}

	c2, err := l.Subscribe(ctx, telemetrylog.ConsumerSpec{Name: "worker"})
	if err != nil {
		t.Fatalf("re-Subscribe: %v", err)
	}
	// The AckWait timer must expire before redelivery; Fetch blocks for it.
	got2, err := c2.Fetch(ctx, 1, 2*time.Second)
	if err != nil || len(got2) != 1 {
		t.Fatalf("redelivery Fetch: err=%v n=%d", err, len(got2))
	}
	if got2[0].Attempt() != 2 {
		t.Errorf("redelivery Attempt = %d, want 2", got2[0].Attempt())
	}
	if string(got2[0].Record().Payload) != "payload" {
		t.Errorf("redelivered payload = %q, want %q", got2[0].Record().Payload, "payload")
	}
	if err := got2[0].Ack(ctx); err != nil {
		t.Fatalf("Ack: %v", err)
	}
}

// TestNakWithDelay proves Nak(delay) holds redelivery until the delay elapses.
func TestNakWithDelay(t *testing.T) {
	l := newTestLog(t, Options{AckWait: 5 * time.Second}) // long, so only the Nak drives timing
	ctx := context.Background()
	if _, err := l.Publish(ctx, rec("o", "sbo.push.o", "d1", "x", nil)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	cons, err := l.Subscribe(ctx, telemetrylog.ConsumerSpec{Name: "nakker"})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	got, err := cons.Fetch(ctx, 1, time.Second)
	if err != nil || len(got) != 1 {
		t.Fatalf("Fetch: err=%v n=%d", err, len(got))
	}
	if err := got[0].Nak(ctx, 800*time.Millisecond); err != nil {
		t.Fatalf("Nak: %v", err)
	}
	// Too soon: nothing redeliverable yet.
	early, err := cons.Fetch(ctx, 1, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("early Fetch: %v", err)
	}
	if len(early) != 0 {
		t.Errorf("record redelivered before the Nak delay elapsed (n=%d)", len(early))
	}
	// After the delay it comes back.
	late, err := cons.Fetch(ctx, 1, time.Second)
	if err != nil {
		t.Fatalf("late Fetch: %v", err)
	}
	if len(late) != 1 {
		t.Fatalf("record not redelivered after the Nak delay (n=%d)", len(late))
	}
	_ = late[0].Ack(ctx)
}

// TestMaxDeliverParking proves a record delivered MaxDeliver times without an
// Ack is not delivered again (the poison-record ceiling).
func TestMaxDeliverParking(t *testing.T) {
	l := newTestLog(t, Options{})
	ctx := context.Background()
	if _, err := l.Publish(ctx, rec("o", "sbo.push.o", "poison", "x", nil)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	cons, err := l.Subscribe(ctx, telemetrylog.ConsumerSpec{Name: "poisoned", MaxDeliver: 2})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		got, err := cons.Fetch(ctx, 1, time.Second)
		if err != nil || len(got) != 1 {
			t.Fatalf("delivery %d: err=%v n=%d", attempt, err, len(got))
		}
		if got[0].Attempt() != attempt {
			t.Errorf("delivery %d Attempt = %d, want %d", attempt, got[0].Attempt(), attempt)
		}
		if err := got[0].Nak(ctx, 0); err != nil {
			t.Fatalf("Nak: %v", err)
		}
	}
	// Budget exhausted: no further delivery.
	extra, err := cons.Fetch(ctx, 1, 700*time.Millisecond)
	if err != nil {
		t.Fatalf("post-parking Fetch: %v", err)
	}
	if len(extra) != 0 {
		t.Errorf("record delivered past MaxDeliver (n=%d)", len(extra))
	}
}

// TestWildcardFilters proves FilterSubjects with "sbo.push.*" and "sbo.otlp.>"
// route disjoint families to disjoint consumers.
func TestWildcardFilters(t *testing.T) {
	l := newTestLog(t, Options{})
	ctx := context.Background()
	if _, err := l.Publish(ctx, rec("o", "sbo.push.o", "p1", "push", nil)); err != nil {
		t.Fatalf("push Publish: %v", err)
	}
	if _, err := l.Publish(ctx, rec("o", "sbo.otlp.o.traces", "t1", "otlp", nil)); err != nil {
		t.Fatalf("otlp Publish: %v", err)
	}

	pushCons, err := l.Subscribe(ctx, telemetrylog.ConsumerSpec{Name: "pushonly", FilterSubjects: []string{"sbo.push.*"}})
	if err != nil {
		t.Fatalf("Subscribe push: %v", err)
	}
	otlpCons, err := l.Subscribe(ctx, telemetrylog.ConsumerSpec{Name: "otlponly", FilterSubjects: []string{"sbo.otlp.>"}})
	if err != nil {
		t.Fatalf("Subscribe otlp: %v", err)
	}

	assertOne := func(name string, c telemetrylog.Consumer, wantSubject string) {
		got, err := c.Fetch(ctx, 1, time.Second)
		if err != nil {
			t.Fatalf("%s Fetch: %v", name, err)
		}
		if len(got) != 1 {
			t.Fatalf("%s Fetch returned %d, want 1", name, len(got))
		}
		if got[0].Record().Subject != wantSubject {
			t.Errorf("%s got subject %q, want %q", name, got[0].Record().Subject, wantSubject)
		}
		_ = got[0].Ack(ctx)
	}
	assertOne("pushonly", pushCons, "sbo.push.o")
	assertOne("otlponly", otlpCons, "sbo.otlp.o.traces")
}

// TestProbeHealthy checks the doctor round trip reports a healthy R=1 stream.
func TestProbeHealthy(t *testing.T) {
	l := newTestLog(t, Options{})
	rep := l.Probe(context.Background())
	if rep.Engine != "nats" {
		t.Errorf("Report.Engine = %q, want nats", rep.Engine)
	}
	if !rep.Configured || !rep.Healthy {
		t.Errorf("Report = %+v, want Configured && Healthy", rep)
	}
	if rep.Replicas != 1 {
		t.Errorf("Report.Replicas = %d, want 1 (embedded)", rep.Replicas)
	}
}

// TestCloseThenErrClosed pins that every entry point returns ErrClosed after
// Close, and that Close is idempotent.
func TestCloseThenErrClosed(t *testing.T) {
	l := newTestLog(t, Options{})
	ctx := context.Background()
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close (idempotent): %v", err)
	}
	if _, err := l.Publish(ctx, rec("o", "sbo.push.o", "d", "x", nil)); !errors.Is(err, telemetrylog.ErrClosed) {
		t.Errorf("Publish after Close = %v, want ErrClosed", err)
	}
	if _, err := l.Subscribe(ctx, telemetrylog.ConsumerSpec{Name: "x"}); !errors.Is(err, telemetrylog.ErrClosed) {
		t.Errorf("Subscribe after Close = %v, want ErrClosed", err)
	}
	if _, err := l.Stats(ctx); !errors.Is(err, telemetrylog.ErrClosed) {
		t.Errorf("Stats after Close = %v, want ErrClosed", err)
	}
	rep := l.Probe(ctx)
	if rep.Healthy {
		t.Error("Probe after Close reported Healthy")
	}
}

// TestConnectUnreachable proves Connect to a closed port fails as ErrUnavailable
// within roughly ConnectTimeout, never a hang.
func TestConnectUnreachable(t *testing.T) {
	start := time.Now()
	_, err := Connect(context.Background(), Options{
		URL:            "nats://127.0.0.1:1",
		ConnectTimeout: time.Second,
	})
	elapsed := time.Since(start)
	if !errors.Is(err, telemetrylog.ErrUnavailable) {
		t.Fatalf("Connect to closed port = %v, want ErrUnavailable", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("Connect took %s, want to fail fast within the connect timeout", elapsed)
	}
}

// TestConnectStreamStorageCapacity pins that the requested reservation must
// fit the broker's capacity, with the rejected request retaining its API
// error. This server has no explicit per-account JetStream limits configured
// (only the server-wide JetStreamMaxStore pool), so its single global account
// reports an unbounded AccountInfo().Limits.MaxStore (nats-server's
// dynamicJSAccountLimits, -1 = "dynamic"/unlimited, is what every account
// gets absent an explicit `accounts { ... jetstream: {...} }` config block) —
// preflightCapacityErr's proactive check therefore falls through as designed
// (fail-open on an unbounded/unset limit) and this test still exercises
// exactly the pre-existing REACTIVE path (streamProvisionErr, the 10047
// catch). Direct unit coverage of the new PROACTIVE path — where the broker
// DOES advertise a bounded account limit — is
// TestPreflightCapacityErrAgainstFakeJetStream below.
func TestConnectStreamStorageCapacity(t *testing.T) {
	const brokerMaxStore = 16 << 20
	cases := []struct {
		name     string
		maxBytes int64
		wantErr  bool
	}{
		{name: "above broker capacity", maxBytes: 2 * brokerMaxStore, wantErr: true},
		{name: "below broker capacity", maxBytes: brokerMaxStore / 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := natsserver.NewServer(&natsserver.Options{
				Host:               "127.0.0.1",
				Port:               natsserver.RANDOM_PORT,
				JetStream:          true,
				StoreDir:           t.TempDir(),
				JetStreamMaxStore:  brokerMaxStore,
				JetStreamMaxMemory: 8 << 20,
				NoSigs:             true,
				NoLog:              true,
			})
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			t.Cleanup(func() {
				srv.Shutdown()
				srv.WaitForShutdown()
			})
			srv.Start()
			if !srv.ReadyForConnections(3 * time.Second) {
				t.Fatal("NATS server did not become ready")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			l, err := Connect(ctx, Options{
				URL:            srv.ClientURL(),
				MaxBytes:       tc.maxBytes,
				MaxMsgBytes:    1024,
				ConnectTimeout: time.Second,
				PublishTimeout: 3 * time.Second,
			})
			if l != nil {
				t.Cleanup(func() { _ = l.Close() })
			}
			if tc.wantErr {
				if err == nil || l != nil {
					t.Fatalf("Connect = %v, %v; want no log and a capacity error", l, err)
				}
				var ae *jetstream.APIError
				if !errors.As(err, &ae) || ae.ErrorCode != codeStorageResources {
					t.Fatalf("Connect error lost storage API cause: %v", err)
				}
				for _, hint := range []string{
					fmt.Sprintf("MaxBytes=%d bytes", tc.maxBytes),
					"configure MaxBytes",
					"increase broker storage capacity",
					ae.Description,
				} {
					if !strings.Contains(err.Error(), hint) {
						t.Errorf("capacity error %q missing %q", err, hint)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Connect within broker capacity: %v", err)
			}
			info, err := l.stream.Info(ctx)
			if err != nil {
				t.Fatalf("stream Info: %v", err)
			}
			if info.Config.MaxBytes != tc.maxBytes {
				t.Errorf("stream MaxBytes = %d, want requested %d", info.Config.MaxBytes, tc.maxBytes)
			}
		})
	}
}

// TestStreamProvisionErrWrapsAPIError is a direct, live-broker-free unit test
// of the REACTIVE half of the capacity fix: when the broker itself refuses
// CreateStream/UpdateStream with the storage-resources API error (10047), the
// wrapped error must retain the underlying *jetstream.APIError (so
// errors.As still finds it) and name the requested MaxBytes. This remains the
// backstop for a broker preflightCapacityErr's AccountInfo-based check cannot
// fully replace: an AccountInfo call that fails, an older broker without the
// endpoint, or an account whose reported limit is unbounded/unset while its
// real disk is smaller all fall through to this path.
func TestStreamProvisionErrWrapsAPIError(t *testing.T) {
	apiErrCause := &jetstream.APIError{Code: 500, ErrorCode: codeStorageResources, Description: "insufficient storage resources available"}
	err := streamProvisionErr(apiErrCause, 1<<30)
	if err == nil {
		t.Fatal("streamProvisionErr(storage-resources API error) = nil, want an error")
	}
	var ae *jetstream.APIError
	if !errors.As(err, &ae) || ae.ErrorCode != codeStorageResources {
		t.Fatalf("streamProvisionErr lost the storage API cause: %v", err)
	}
	for _, hint := range []string{"MaxBytes=1073741824 bytes", "configure MaxBytes", "increase broker storage capacity", apiErrCause.Description} {
		if !strings.Contains(err.Error(), hint) {
			t.Errorf("capacity error %q missing %q", err, hint)
		}
	}
	// A non-storage API error (or any other error) is returned unchanged —
	// streamProvisionErr must not manufacture a capacity hint for it.
	other := &jetstream.APIError{Code: 400, ErrorCode: codeMessageExceedsMax, Description: "message size exceeds maximum allowed"}
	if got := streamProvisionErr(other, 1<<30); !errors.Is(got, other) {
		t.Errorf("streamProvisionErr(non-storage error) = %v, want unchanged %v", got, other)
	}
}

// fakeJetStream is a minimal jetstream.JetStream double for exercising
// preflightCapacityErr without a live broker. It embeds the (nil) interface
// so every method other than AccountInfo compiles but panics if ever called —
// preflightCapacityErr calls only AccountInfo, so nothing else is reachable.
type fakeJetStream struct {
	jetstream.JetStream
	info *jetstream.AccountInfo
	err  error
}

func (f *fakeJetStream) AccountInfo(context.Context) (*jetstream.AccountInfo, error) {
	return f.info, f.err
}

// TestPreflightCapacityErrAgainstFakeJetStream is the direct unit test of the
// PROACTIVE half of the capacity fix (preflightCapacityErr): it must refuse a
// requested MaxBytes that exceeds the broker's own advertised JetStream
// account storage limit BEFORE ensureStream is ever reached, and must
// fail-open (return nil, never a new hard dependency on AccountInfo) whenever
// the requested cap is unlimited, the broker call errors, or the broker
// itself reports an unbounded/unset limit — the exact shape
// TestConnectStreamStorageCapacity's single-global-account server produces,
// which is why that test still only exercises the reactive backstop.
func TestPreflightCapacityErrAgainstFakeJetStream(t *testing.T) {
	const requested = 32 << 20 // 32 MiB
	const brokerMax = 16 << 20 // 16 MiB
	cases := []struct {
		name     string
		maxBytes int64
		js       *fakeJetStream
		wantErr  bool
	}{
		{
			name:     "over the broker's advertised limit",
			maxBytes: requested,
			js:       &fakeJetStream{info: &jetstream.AccountInfo{Tier: jetstream.Tier{Limits: jetstream.AccountLimits{MaxStore: brokerMax}}}},
			wantErr:  true,
		},
		{
			name:     "within the broker's advertised limit",
			maxBytes: brokerMax / 2,
			js:       &fakeJetStream{info: &jetstream.AccountInfo{Tier: jetstream.Tier{Limits: jetstream.AccountLimits{MaxStore: brokerMax}}}},
		},
		{
			name:     "exactly at the broker's advertised limit",
			maxBytes: brokerMax,
			js:       &fakeJetStream{info: &jetstream.AccountInfo{Tier: jetstream.Tier{Limits: jetstream.AccountLimits{MaxStore: brokerMax}}}},
		},
		{
			name:     "unlimited requested (MaxBytes <= 0) never checked, even over a bounded broker",
			maxBytes: -1,
			js:       &fakeJetStream{info: &jetstream.AccountInfo{Tier: jetstream.Tier{Limits: jetstream.AccountLimits{MaxStore: brokerMax}}}},
		},
		{
			name:     "broker reports unbounded (-1, the single-global-account default) fails open",
			maxBytes: requested,
			js:       &fakeJetStream{info: &jetstream.AccountInfo{Tier: jetstream.Tier{Limits: jetstream.AccountLimits{MaxStore: -1}}}},
		},
		{
			name:     "AccountInfo call fails fails open",
			maxBytes: requested,
			js:       &fakeJetStream{err: errors.New("account info unavailable")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := preflightCapacityErr(context.Background(), tc.js, tc.maxBytes)
			if tc.wantErr {
				if err == nil {
					t.Fatal("preflightCapacityErr = nil, want an error")
				}
				for _, hint := range []string{
					fmt.Sprintf("MaxBytes=%d bytes", tc.maxBytes),
					"the broker advertises",
					fmt.Sprintf("%d bytes", int64(brokerMax)),
					"configure MaxBytes",
					"increase broker storage capacity",
				} {
					if !strings.Contains(err.Error(), hint) {
						t.Errorf("capacity error %q missing %q", err, hint)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("preflightCapacityErr = %v, want nil", err)
			}
		})
	}
}

// TestWithDefaults pins the pinned defaults and the duplicate-window clamp.
func TestWithDefaults(t *testing.T) {
	o := Options{}.withDefaults()
	if o.Stream != DefaultStream {
		t.Errorf("Stream = %q, want %q", o.Stream, DefaultStream)
	}
	if o.Replicas != 1 {
		t.Errorf("Replicas = %d, want 1", o.Replicas)
	}
	if o.MaxAge != DefaultMaxAge || o.MaxBytes != DefaultMaxBytes || o.MaxMsgBytes != DefaultMaxMsgBytes {
		t.Errorf("caps = %v/%d/%d, want %v/%d/%d", o.MaxAge, o.MaxBytes, o.MaxMsgBytes, DefaultMaxAge, DefaultMaxBytes, DefaultMaxMsgBytes)
	}
	if o.MaxMessages != unlimited {
		t.Errorf("MaxMessages = %d, want unlimited (%d)", o.MaxMessages, unlimited)
	}
	if o.DuplicateWindow != DefaultDuplicateWindow {
		t.Errorf("DuplicateWindow = %v, want %v", o.DuplicateWindow, DefaultDuplicateWindow)
	}
	if o.MaxDeliver != DefaultMaxDeliver || o.AckWait != DefaultAckWait {
		t.Errorf("consumer defaults = %d/%v", o.MaxDeliver, o.AckWait)
	}
	// The duplicate window may never exceed MaxAge.
	clamped := Options{MaxAge: time.Minute, DuplicateWindow: time.Hour}.withDefaults()
	if clamped.DuplicateWindow != time.Minute {
		t.Errorf("clamped DuplicateWindow = %v, want %v (MaxAge)", clamped.DuplicateWindow, time.Minute)
	}
}

// TestValidateEmbeddedAuth is the P3-3 address/credential classifier, one row
// per rule: a loopback (or empty) listen is always allowed; a non-loopback
// listen is allowed ONLY when a credential the embedded server actually
// ENFORCES (Token, or User+Password) is configured, else refused.
//
// A creds_file / nkey_seed_file is a valid NATS credential shape in general
// (the external "nats" engine honours it), but Embedded never wires either
// into the in-process server's auth — so on a non-loopback listen it must be
// refused exactly like "no credentials at all" (the security fix for the P2
// fail-open gate: those two shapes used to satisfy this check without the
// server ever enforcing them). Table covers each credential shape crossed
// with loopback vs non-loopback.
func TestValidateEmbeddedAuth(t *testing.T) {
	const loopback = "127.0.0.1:4222"
	const nonLoopback = "0.0.0.0:4222"
	cases := []struct {
		name    string
		listen  string
		opts    Options
		wantErr bool
	}{
		{name: "empty listen (random loopback)", listen: "", wantErr: false},
		{name: "explicit loopback ip", listen: "127.0.0.1:4222", wantErr: false},
		{name: "loopback /8", listen: "127.0.0.5:4222", wantErr: false},
		{name: "localhost by name", listen: "localhost:4222", wantErr: false},
		{name: "ipv6 loopback", listen: "[::1]:4222", wantErr: false},
		{name: "bare port resolves to loopback", listen: ":4222", wantErr: false},
		{name: "unparseable listen", listen: "not-a-host-port", wantErr: true},

		// none: loopback always allowed, non-loopback always refused.
		{name: "loopback, no creds → allowed", listen: loopback, opts: Options{}, wantErr: false},
		{name: "non-loopback, no creds → refused", listen: nonLoopback, opts: Options{}, wantErr: true},
		{name: "lan address, no creds → refused", listen: "192.168.1.10:4222", wantErr: true},

		// token: enforced by the embedded server, allowed on both.
		{name: "loopback + token → allowed", listen: loopback, opts: Options{Token: "s3cret"}, wantErr: false},
		{name: "non-loopback + token → allowed", listen: nonLoopback, opts: Options{Token: "s3cret"}, wantErr: false},

		// user+password: enforced, allowed on both.
		{name: "loopback + user+password → allowed", listen: loopback, opts: Options{User: "u", Password: "p"}, wantErr: false},
		{name: "non-loopback + user+password → allowed", listen: nonLoopback, opts: Options{User: "u", Password: "p"}, wantErr: false},
		{name: "non-loopback + user without password → refused", listen: nonLoopback, opts: Options{User: "u"}, wantErr: true},

		// creds file only: NOT enforced by Embedded → refused on non-loopback.
		{name: "loopback + creds file → allowed", listen: loopback, opts: Options{CredsFile: "/tmp/x.creds"}, wantErr: false},
		{name: "non-loopback + creds file only → refused", listen: nonLoopback, opts: Options{CredsFile: "/tmp/x.creds"}, wantErr: true},

		// nkey seed only: NOT enforced by Embedded → refused on non-loopback.
		{name: "loopback + nkey seed → allowed", listen: loopback, opts: Options{NKeySeedFile: "/tmp/x.nk"}, wantErr: false},
		{name: "non-loopback + nkey seed only → refused", listen: nonLoopback, opts: Options{NKeySeedFile: "/tmp/x.nk"}, wantErr: true},

		// creds/nkey file PLUS an enforced credential → allowed (the enforced
		// credential is what matters, not the presence of the unenforced one).
		{name: "non-loopback + creds file + token → allowed", listen: nonLoopback, opts: Options{CredsFile: "/tmp/x.creds", Token: "s3cret"}, wantErr: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEmbeddedAuth(tc.listen, tc.opts)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateEmbeddedAuth(%q, %+v) = nil, want error", tc.listen, tc.opts)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateEmbeddedAuth(%q, %+v) = %v, want nil", tc.listen, tc.opts, err)
			}
			if tc.wantErr && err != nil && (tc.opts.CredsFile != "" || tc.opts.NKeySeedFile != "") && tc.opts.Token == "" && tc.opts.Password == "" {
				if !strings.Contains(err.Error(), "creds_file/nkey_seed_file") {
					t.Fatalf("error for creds/nkey-only shape should name the reason, got: %v", err)
				}
			}
		})
	}
}

// TestEmbeddedStartsWithToken proves the embedded server actually enforces a
// configured token: it starts WITH the token wired into its auth and the
// in-process client round-trips a record (which only succeeds if the client
// presented the same token).
func TestEmbeddedStartsWithToken(t *testing.T) {
	l := newTestLog(t, Options{Token: "s3cret-token"})
	r := rec("org-1", telemetrylog.PushSubject("org-1"), "d1", `{"x":1}`, nil)
	if _, err := l.Publish(context.Background(), r); err != nil {
		t.Fatalf("publish over token-authenticated embedded server: %v", err)
	}
}
