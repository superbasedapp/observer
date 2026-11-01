//go:build linux

package sandboxrelayd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// The hostile guest suite's multi-connection cases (sandbox plan section
// 13.12, A5; plans decision log P-026, lane sbx-p2b). JSP-3's 29 scenarios
// attack one connection's frames; these attack the relay as a set of
// connections through the real topology (box client, host helper, link,
// daemon): replaying one connection's bytes on another, flooding past the
// connection cap, holding a run's slots, and starving another run.

// multiRelay is the topology with fast limits and a controllable executor.
type multiRelay struct {
	obs, sock, link string
	runs            []RunRecord
	daemon          *Daemon
	fw              *Forwarder
	ran             atomic.Int64
	release         chan struct{}
}

func fastConn() sandboxrelay.ConnLimits {
	l := sandboxrelay.DefaultConnLimits
	l.IdleTimeout = 300 * time.Millisecond
	l.FrameDeadline = 300 * time.Millisecond
	l.MessageDeadline = time.Second
	return l
}

// startMultiRelay serves two runs on the daemon and a forwarder for the
// first. block makes every execution wait on release.
func startMultiRelay(t *testing.T, fwConns, perRun int, block bool, tune ...func(d *Daemon, f *Forwarder)) *multiRelay {
	t.Helper()
	m := &multiRelay{obs: shortDir(t), sock: shortDir(t), release: make(chan struct{})}
	_ = os.Chmod(m.sock, 0o700)
	for _, id := range []string{"run-a", "run-b"} {
		rec, err := NewRunRecord(RunRecord{RunID: id, Tool: "claude-code", WorkspaceDir: "/w", Roots: []string{"/w"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteRun(m.obs, rec); err != nil {
			t.Fatal(err)
		}
		m.runs = append(m.runs, rec)
	}
	if err := WriteBoxRecord(m.sock, m.runs[0]); err != nil {
		t.Fatal(err)
	}
	m.link = filepath.Join(m.obs, "link.sock")
	dln, err := net.Listen("unix", m.link)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		select {
		case <-m.release:
		default:
			close(m.release)
		}
	})
	m.daemon = &Daemon{
		ObserverDir: m.obs, Rules: testRules, Peer: PeerSameUser, PerRun: perRun, Conn: fastConn(),
		Exec: func(ctx context.Context, _ RunRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
			m.ran.Add(1)
			if block {
				select {
				case <-m.release:
				case <-ctx.Done():
				}
			}
			return sandboxrelay.HookResponse{Stdout: req.Stdin}, nil
		},
	}
	bln, err := net.Listen("unix", filepath.Join(m.sock, RelaySocketName))
	if err != nil {
		t.Fatal(err)
	}
	m.fw = &Forwarder{Run: m.runs[0], Rules: testRules, Peer: PeerSameUser, MaxConns: fwConns, Conn: fastConn(), DialDaemon: m.dialLink}
	for _, f := range tune {
		f(m.daemon, m.fw)
	}
	go func() { _ = m.daemon.Serve(ctx, dln) }()
	go func() { _ = m.fw.Serve(ctx, bln) }()
	return m
}

func (m *multiRelay) dialLink(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", m.link)
}

func (m *multiRelay) box(t *testing.T) BoxRecord {
	t.Helper()
	br, ok, err := ReadBoxRecord(filepath.Join(m.sock, BoxRecordName))
	if !ok || err != nil {
		t.Fatalf("box record: %v %v", ok, err)
	}
	return br
}

func hookReq(payload string) sandboxrelay.HookRequest {
	return sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: []string{"claude-code", "PostToolUse"}, Stdin: []byte(payload)}
}

// recorder keeps every byte written through it.
type recorder struct {
	net.Conn
	mu  sync.Mutex
	out bytes.Buffer
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.out.Write(p)
	r.mu.Unlock()
	return r.Conn.Write(p)
}

// TestMultiConnReplayAcrossConnections: the bytes of one valid box
// connection (hello and authenticated frames) replayed on a second
// connection fail its MAC, because every connection's keys are bound to
// the server's fresh nonce; the executor runs once.
func TestMultiConnReplayAcrossConnections(t *testing.T) {
	m := startMultiRelay(t, 8, 4, false)
	br := m.box(t)
	raw, err := net.Dial("unix", filepath.Join(m.sock, RelaySocketName))
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{Conn: raw}
	s, err := sandboxrelay.Dial(rec, params(sandboxrelay.PurposeBox, fastConn()), br.RunID, br.BoxSecret)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := sandboxrelay.EncodeHookRequest(hookReq("once"))
	if err := s.Send(sandboxrelay.StreamHook, msg); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Recv(sandboxrelay.StreamHook, sandboxrelay.MaxMessage); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()
	if m.ran.Load() != 1 {
		t.Fatalf("ran %d", m.ran.Load())
	}
	replay, err := net.Dial("unix", filepath.Join(m.sock, RelaySocketName))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replay.Close() }()
	pre := make([]byte, 40)
	if _, err := io.ReadFull(replay, pre); err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	captured := append([]byte(nil), rec.out.Bytes()...)
	rec.mu.Unlock()
	_, _ = replay.Write(captured)
	_ = replay.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, _ := io.ReadAll(replay)
	if m.ran.Load() != 1 {
		t.Fatalf("the replayed connection ran the executor (%d runs)", m.ran.Load())
	}
	if bytes.Contains(got, []byte("once")) {
		t.Fatal("the replayed connection was answered")
	}
}

// TestMultiConnFloodPastTheCap: connections past the helper's cap are
// closed at once, idle ones are closed by the idle bound and free their
// slots, and a real request then succeeds; no goroutine is left behind.
func TestMultiConnFloodPastTheCap(t *testing.T) {
	m := startMultiRelay(t, 4, 4, false)
	base := runtime.NumGoroutine()
	var conns []net.Conn
	for range 40 {
		c, err := net.Dial("unix", filepath.Join(m.sock, RelaySocketName))
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	closedAtOnce := 0
	for _, c := range conns {
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if errors.Is(err, io.EOF) || (n == 0 && err != nil && !isTimeout(err)) {
			closedAtOnce++
		}
	}
	if closedAtOnce < 30 {
		t.Fatalf("only %d of 36 connections past the cap were closed at once", closedAtOnce)
	}
	time.Sleep(fastConn().FrameDeadline + 300*time.Millisecond) // the held handshakes time out
	for _, c := range conns {
		_ = c.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := BoxRoundTrip(ctx, m.sock, m.box(t), hookReq("after the flood"), fastConn())
	if err != nil || string(resp.Stdout) != "after the flood" {
		t.Fatalf("a request after the flood: %q %v", resp.Stdout, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > base+4 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > base+4 {
		t.Fatalf("%d goroutines left behind after the flood (base %d)", n, base)
	}
}

// TestMultiConnRunSlotsAndIsolation: one run holding every one of its
// slots (executions that do not return) gets its next requests refused
// instead of queued, while another run is still served at once.
func TestMultiConnRunSlotsAndIsolation(t *testing.T) {
	m := startMultiRelay(t, 16, 2, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	msg, _ := sandboxrelay.EncodeHookRequest(hookReq("held"))
	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := LinkRoundTrip(ctx, m.dialLink, m.runs[0], msg, fastConn())
			errs <- err
		}()
	}
	deadline := time.Now().Add(3 * time.Second)
	for m.ran.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if n := m.ran.Load(); n != 2 {
		t.Fatalf("%d executions started for a run with 2 slots", n)
	}
	st, _ := m.daemon.Run("run-a")
	deadline = time.Now().Add(3 * time.Second)
	for st.Refused.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if st.Refused.Load() != 3 {
		t.Fatalf("refused %d requests past the run's slots, want 3", st.Refused.Load())
	}
	// Another run is not starved by run-a's held slots. Its execution
	// blocks too, so the proof is that it STARTED.
	go func() { _, _ = LinkRoundTrip(ctx, m.dialLink, m.runs[1], msg, fastConn()) }()
	deadline = time.Now().Add(2 * time.Second)
	for m.ran.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if m.ran.Load() != 3 {
		t.Fatal("run-b was starved by run-a's held slots")
	}
	close(m.release)
	wg.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		if err == nil {
			ok++
		}
	}
	if ok != 2 {
		t.Fatalf("%d of run-a's requests answered, want the 2 that held slots", ok)
	}
}

// TestMultiConnDripHoldsNoSlot: many connections that each drip a frame
// slower than its deadline are all closed within the bound, so a guest
// cannot keep the helper's slots by trickling bytes.
func TestMultiConnDripHoldsNoSlot(t *testing.T) {
	m := startMultiRelay(t, 4, 4, false)
	br := m.box(t)
	start := time.Now()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("unix", filepath.Join(m.sock, RelaySocketName))
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			s, err := sandboxrelay.Dial(c, params(sandboxrelay.PurposeBox, fastConn()), br.RunID, br.BoxSecret)
			if err != nil {
				return
			}
			_ = s // hold the session, then drip a frame header byte by byte
			for i := 0; i < 64; i++ {
				if _, err := c.Write([]byte{0}); err != nil {
					return
				}
				time.Sleep(40 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the drip connections were held for %s", took)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if resp, err := BoxRoundTrip(ctx, m.sock, br, hookReq("after the drip"), fastConn()); err != nil || string(resp.Stdout) != "after the drip" {
		t.Fatalf("a request after the drip: %v", err)
	}
	if m.ran.Load() != 1 {
		t.Fatalf("a drip reached the executor (%d runs)", m.ran.Load())
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// TestHeartbeatThroughTheHelper (lane sbx-p2b): while the daemon works
// longer than a waiting client's idle bound, the daemon heartbeats the
// helper and the helper heartbeats the box, so the box gets its answer;
// with heartbeats off the box gives up at its idle bound.
func TestHeartbeatThroughTheHelper(t *testing.T) {
	for _, beat := range []time.Duration{40 * time.Millisecond, -1} {
		m := startMultiRelay(t, 8, 4, false, func(d *Daemon, f *Forwarder) {
			d.Heartbeat, f.Heartbeat = beat, beat
			d.Exec = func(_ context.Context, _ RunRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
				time.Sleep(600 * time.Millisecond)
				return sandboxrelay.HookResponse{Stdout: req.Stdin}, nil
			}
		})
		box := fastConn()
		box.IdleTimeout = 200 * time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := BoxRoundTrip(ctx, m.sock, m.box(t), hookReq("slow"), box)
		cancel()
		if beat > 0 && (err != nil || string(resp.Stdout) != "slow") {
			t.Fatalf("with heartbeats: %q %v", resp.Stdout, err)
		}
		if beat < 0 && err == nil {
			t.Fatal("without heartbeats the box's idle bound did not fire")
		}
	}
}

// slowWriter delays every write after the first `fast` ones.
type slowWriter struct {
	net.Conn
	fast  int
	delay time.Duration
	n     int
}

func (w *slowWriter) Write(p []byte) (int, error) {
	if w.n >= w.fast {
		time.Sleep(w.delay)
	}
	w.n++
	return w.Conn.Write(p)
}

// TestSlowBodyHoldsNoSlot (P-032): a valid head followed by a body dripped
// frame by frame (each frame inside its own deadline, so the box channel
// keeps it) holds neither one of the run's slots nor a daemon connection
// for longer than the link's body deadline.
func TestSlowBodyHoldsNoSlot(t *testing.T) {
	m := startMultiRelay(t, 4, 1, false, func(d *Daemon, f *Forwarder) {
		d.BodyDeadline = 300 * time.Millisecond
		d.MaxConns = 2
		f.Conn.IdleTimeout = 2 * time.Second
		f.Conn.MessageDeadline = 10 * time.Second
	})
	br := m.box(t)
	start := time.Now()
	dripDone := make(chan error, 1)
	go func() {
		c, err := net.Dial("unix", filepath.Join(m.sock, RelaySocketName))
		if err != nil {
			dripDone <- err
			return
		}
		defer func() { _ = c.Close() }()
		p := params(sandboxrelay.PurposeBox, fastConn())
		p.Limits.MaxPayload = 256
		s, err := sandboxrelay.Dial(&slowWriter{Conn: c, fast: 2, delay: 100 * time.Millisecond}, p, br.RunID, br.BoxSecret)
		if err != nil {
			dripDone <- err
			return
		}
		msg, _ := sandboxrelay.EncodeHookRequest(hookReq(string(bytes.Repeat([]byte("x"), 8<<10))))
		if err := s.Send(sandboxrelay.StreamHook, msg); err != nil {
			dripDone <- err
			return
		}
		_, err = s.Recv(sandboxrelay.StreamHook, sandboxrelay.MaxMessage)
		dripDone <- err
	}()
	// While the body drips, the run's single slot is free.
	time.Sleep(150 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if resp, err := BoxRoundTrip(ctx, m.sock, br, hookReq("beside the drip"), fastConn()); err != nil || string(resp.Stdout) != "beside the drip" {
		t.Fatalf("a request beside the drip: %v", err)
	}
	select {
	case err := <-dripDone:
		if err == nil {
			t.Fatal("the dripped request was answered")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the drip was still held after three seconds")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the dripped body held the relay for %s", took)
	}
	if m.ran.Load() != 1 {
		t.Fatalf("the dripped body reached the executor (%d runs)", m.ran.Load())
	}
	if st, _ := m.daemon.Run("run-a"); len(st.sem) != 0 {
		t.Fatalf("%d run slots still held", len(st.sem))
	}
}
