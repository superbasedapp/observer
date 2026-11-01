package natslog

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

// outageWait bounds every wait in this file. Each one polls a condition, so a
// healthy run finishes in a few seconds; the bound only decides how long a
// broken build takes to fail.
const outageWait = 60 * time.Second

// externalBroker is an EXTERNAL nats-server (the estate's shape: the org dials
// it, it is not in-process) on a fixed loopback port and store directory, so a
// test can stop it and start it again at the same address with the same data.
type externalBroker struct {
	t    *testing.T
	port int
	dir  string
	srv  *natsserver.Server
}

func newExternalBroker(t *testing.T) *externalBroker {
	t.Helper()
	b := &externalBroker{t: t, port: freePort(t), dir: testStoreDir(t)}
	b.start()
	t.Cleanup(b.stop)
	return b
}

func (b *externalBroker) start() {
	b.t.Helper()
	srv, err := natsserver.NewServer(&natsserver.Options{
		ServerName:        "outage-broker",
		Host:              "127.0.0.1",
		Port:              b.port,
		JetStream:         true,
		StoreDir:          b.dir,
		JetStreamMaxStore: testBrokerMaxStore,
		NoSigs:            true,
		NoLog:             true,
	})
	if err != nil {
		b.t.Fatalf("new broker: %v", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		srv.Shutdown()
		b.t.Fatal("broker not ready")
	}
	b.srv = srv
}

func (b *externalBroker) stop() {
	if b.srv == nil {
		return
	}
	b.srv.Shutdown()
	b.srv.WaitForShutdown()
	b.srv = nil
}

func (b *externalBroker) url() string { return "nats://127.0.0.1:" + strconv.Itoa(b.port) }

// freePort returns a loopback port nothing listens on right now.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// waitUntil polls cond until it holds or outageWait passes.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(outageWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", outageWait, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// connectOutageLog dials b with a fast reconnect cadence, so the old 60-attempt
// budget is exhausted in about a second instead of minutes.
func connectOutageLog(t *testing.T, b *externalBroker) *Log {
	t.Helper()
	l, err := Connect(context.Background(), EmbeddedTestOptions(Options{
		URL:            b.url(),
		ReconnectWait:  10 * time.Millisecond,
		PublishTimeout: time.Second,
		AckWait:        time.Minute,
	}))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// TestBrokerOutageLongerThanTheOldReconnectBudgetRecoversByItself is T-883: the
// broker was unreachable for hours, the client's default budget of
// nats.DefaultMaxReconnect attempts ran out, the library closed the connection
// for good, and the org stayed log-unavailable until a restart. The broker is
// kept down here until the client has failed MORE than that many attempts, then
// restored: the same Log must come back by itself, with the stream identity and
// the durable consumer intact.
func TestBrokerOutageLongerThanTheOldReconnectBudgetRecoversByItself(t *testing.T) {
	ctx := t.Context()
	b := newExternalBroker(t)
	l := connectOutageLog(t, b)
	_, createdBefore, generationBefore := l.identity()

	if _, err := l.Publish(ctx, rec("org", telemetrylog.PushSubject("org"), "before", "before", nil)); err != nil {
		t.Fatal(err)
	}
	spec := telemetrylog.ConsumerSpec{Name: "applyworker", MaxAckPending: 1, AckWait: time.Minute}
	cons, err := l.Subscribe(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cons.Fetch(ctx, 8, 2*time.Second)
	if err != nil || len(got) != 1 {
		t.Fatalf("fetch before the outage: n=%d err=%v", len(got), err)
	}
	if err := got[0].Ack(ctx); err != nil {
		t.Fatal(err)
	}
	// The ack is fire-and-forget: let the broker record it before it goes
	// away, or the un-acked record holds the durable's single credit after
	// the restart (an artefact of the test, not of the recovery).
	waitUntil(t, "the broker to record the ack", func() bool {
		c, err := l.js.Consumer(ctx, l.opts.Stream, spec.Name)
		return err == nil && c.CachedInfo().NumAckPending == 0 && c.CachedInfo().AckFloor.Stream == 1
	})

	start := time.Now()
	b.stop()
	waitUntil(t, "more failed reconnects than the old budget", func() bool {
		return l.ConnectionState().FailedReconnects > uint64(nats.DefaultMaxReconnect)
	})
	t.Logf("outage held for %s, %d failed reconnects (old budget %d)",
		time.Since(start).Round(time.Millisecond), l.ConnectionState().FailedReconnects, nats.DefaultMaxReconnect)

	// The old client was CLOSED for good at this point. Now it is still trying.
	if nc, _ := l.client(); nc.IsClosed() {
		t.Fatal("the connection was closed after the old reconnect budget; it must keep reconnecting")
	}
	rep := l.Probe(ctx)
	if rep.Healthy {
		t.Fatal("probe healthy while the broker is down")
	}
	if !strings.Contains(rep.Detail, "reconnecting automatically") {
		t.Fatalf("probe detail %q does not say recovery is automatic", rep.Detail)
	}
	// A refused publish must not be sent later behind the caller's back: the
	// node was told 503 and retries it itself.
	if _, err := l.Publish(ctx, rec("org", telemetrylog.PushSubject("org"), "down", "down", nil)); !errors.Is(err, telemetrylog.ErrUnavailable) {
		t.Fatalf("publish during the outage: err=%v, want ErrUnavailable", err)
	}

	b.start()
	waitUntil(t, "the probe to report healthy again", func() bool { return l.Probe(ctx).Healthy })
	t.Logf("healthy again %s after the outage began, on the same connection", time.Since(start).Round(time.Millisecond))
	if st := l.ConnectionState(); !st.Connected || st.Rebuilds != 0 || st.FailedReconnects != 0 {
		t.Fatalf("connection state after recovery = %+v, want connected on the SAME connection", st)
	}

	res, err := l.Publish(ctx, rec("org", telemetrylog.PushSubject("org"), "after", "after", nil))
	if err != nil {
		t.Fatalf("publish after recovery: %v", err)
	}
	if res.Sequence != 2 {
		t.Fatalf("publish after recovery landed at sequence %d, want 2 (the refused publish must not have been buffered and sent)", res.Sequence)
	}
	// The consumer handle taken BEFORE the outage keeps working: nothing it
	// depends on was rebuilt, and the stream identity it is fenced to is the same.
	again, err := cons.Fetch(ctx, 8, 2*time.Second)
	if err != nil || len(again) != 1 || string(again[0].Record().Payload) != "after" {
		t.Fatalf("fetch after recovery: n=%d err=%v", len(again), err)
	}
	pos, ok := again[0].(telemetrylog.OrderedDelivery).OrderPosition()
	if !ok || pos.Generation != generationBefore {
		t.Fatalf("order position after recovery = %+v (ok=%v), want generation %q", pos, ok, generationBefore)
	}
	if _, createdAfter, generationAfter := l.identity(); !createdAfter.Equal(createdBefore) || generationAfter != generationBefore {
		t.Fatal("the stream identity changed across a plain outage")
	}
}

// TestClosedConnectionIsRebuiltAndHandlesReattach covers the second layer: if
// the library closes the connection anyway (an unrecognised server -ERR still
// does), the Log dials a new one by itself. A handle bound to the closed
// connection reports ErrReattachRequired, the re-Subscribe by durable name
// works on the new connection, and the stream identity fence is unchanged.
func TestClosedConnectionIsRebuiltAndHandlesReattach(t *testing.T) {
	ctx := t.Context()
	b := newExternalBroker(t)
	l := connectOutageLog(t, b)
	_, _, generationBefore := l.identity()

	spec := telemetrylog.ConsumerSpec{Name: "sorwriter", MaxAckPending: 1, AckWait: time.Minute}
	stale, err := l.Subscribe(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := l.client()
	old.Close() // what the library does after a fatal server error

	waitUntil(t, "the connection to be rebuilt", func() bool {
		st := l.ConnectionState()
		return st.Connected && st.Rebuilds == 1
	})
	if nc, _ := l.client(); nc == old {
		t.Fatal("the rebuilt Log still holds the closed connection")
	}
	if !l.Probe(ctx).Healthy {
		t.Fatal("probe unhealthy after the rebuild")
	}
	if _, err := l.Publish(ctx, rec("org", telemetrylog.PushSubject("org"), "rebuilt", "rebuilt", nil)); err != nil {
		t.Fatalf("publish after the rebuild: %v", err)
	}
	if _, err := stale.Fetch(ctx, 8, 0); !errors.Is(err, telemetrylog.ErrReattachRequired) {
		t.Fatalf("fetch on a handle of the closed connection: err=%v, want ErrReattachRequired", err)
	}
	fresh, err := l.Subscribe(ctx, spec)
	if err != nil {
		t.Fatalf("re-subscribe after the rebuild: %v", err)
	}
	got, err := fresh.Fetch(ctx, 8, 2*time.Second)
	if err != nil || len(got) != 1 {
		t.Fatalf("fetch after the rebuild: n=%d err=%v", len(got), err)
	}
	if pos, ok := got[0].(telemetrylog.OrderedDelivery).OrderPosition(); !ok || pos.Generation != generationBefore {
		t.Fatalf("order position after the rebuild = %+v (ok=%v), want generation %q", pos, ok, generationBefore)
	}
}

// TestCloseStopsReconnectingToAVanishedBroker pins the shutdown half: with
// indefinite reconnects, a Log closed while its broker is gone must not leave a
// reconnect loop or a rebuild loop running behind it.
func TestCloseStopsReconnectingToAVanishedBroker(t *testing.T) {
	b := newExternalBroker(t)
	l := connectOutageLog(t, b)
	b.stop()
	waitUntil(t, "the client to notice the outage", func() bool { return !l.ConnectionState().Connected })
	done := make(chan struct{})
	go func() { _ = l.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(outageWait):
		t.Fatal("Close did not return while the broker was down")
	}
	if nc, _ := l.client(); !nc.IsClosed() {
		t.Fatal("the connection is still open (reconnecting) after Close")
	}
}
