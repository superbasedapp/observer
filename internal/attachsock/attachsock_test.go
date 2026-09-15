package attachsock

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- fakes -----------------------------------------------------------------

// fakeSession is an in-memory Session with no real PTY. Output is fed via an
// io.Pipe; Write/Resize/Detach are recorded. It records whether it was killed —
// it never is (the interface exposes no Kill), which is the point of test (d).
type fakeSession struct {
	handle string
	runID  string

	pr *io.PipeReader
	pw *io.PipeWriter

	mu       sync.Mutex
	writes   [][]byte
	resizes  []Winsize
	exitCode int
	exited   bool
	hideExit bool  // when true, ExitCode never reports "known" (A4 unknown-exit test)
	writeErr error // when set, Write returns it (A5 writer-revoked test)
	detached bool
	killed   bool // never set — asserted false

	writeCh  chan []byte
	resizeCh chan Winsize
	detachCh chan struct{}

	// corrCh, when non-nil, makes the session a CorrelationSource: the server's
	// relay drains it into frameCorrelated frames. Detach closes it (once) so
	// the relay goroutine exits. nil (the default) means the session does not
	// source correlations — but the type still satisfies CorrelationSource, so
	// the server's relay is gated on the CLIENT's AutoResumeCapable, not on the
	// interface assertion (mirrors production).
	corrCh    chan CorrelatedSession
	corrClose sync.Once

	// reclaimFn, when non-nil, makes the session a working Reclaimer (Feature 1):
	// ReclaimWriter runs it and returns its result. nil means reclaim is
	// unavailable (ReclaimWriter returns an error), so the server falls back to
	// the revoked notice — every existing test keeps its pre-Feature-1 behavior.
	reclaimFn    func() error
	reclaimCalls int
}

func newFakeSession(handle, runID string) *fakeSession {
	pr, pw := io.Pipe()
	return &fakeSession{
		handle:   handle,
		runID:    runID,
		pr:       pr,
		pw:       pw,
		writeCh:  make(chan []byte, 16),
		resizeCh: make(chan Winsize, 16),
		detachCh: make(chan struct{}, 1),
	}
}

// withCorrelation makes the session a live CorrelationSource with a buffered
// announce channel.
func (f *fakeSession) withCorrelation() *fakeSession {
	f.corrCh = make(chan CorrelatedSession, 8)
	return f
}

// CorrelatedSessions satisfies the optional CorrelationSource capability.
func (f *fakeSession) CorrelatedSessions() <-chan CorrelatedSession { return f.corrCh }

// announceCorrelation pushes a correlated-session id toward the client (through
// the server relay). No-op when the session was not built withCorrelation.
func (f *fakeSession) announceCorrelation(c CorrelatedSession) {
	if f.corrCh != nil {
		f.corrCh <- c
	}
}

func (f *fakeSession) Handle() string    { return f.handle }
func (f *fakeSession) RunID() string     { return f.runID }
func (f *fakeSession) Output() io.Reader { return f.pr }

func (f *fakeSession) Write(p []byte) (int, error) {
	f.mu.Lock()
	werr := f.writeErr
	f.mu.Unlock()
	if werr != nil {
		return 0, werr
	}
	cp := append([]byte(nil), p...)
	f.mu.Lock()
	f.writes = append(f.writes, cp)
	f.mu.Unlock()
	f.writeCh <- cp
	return len(p), nil
}

// setWriteErr makes subsequent Writes return err (a lease-revocation sentinel).
func (f *fakeSession) setWriteErr(err error) {
	f.mu.Lock()
	f.writeErr = err
	f.mu.Unlock()
}

// ReclaimWriter satisfies the optional Reclaimer capability (Feature 1). With no
// reclaimFn configured it reports reclaim unavailable, so the server keeps the
// fence-and-notify path.
func (f *fakeSession) ReclaimWriter() error {
	f.mu.Lock()
	fn := f.reclaimFn
	f.reclaimCalls++
	f.mu.Unlock()
	if fn == nil {
		return errors.New("reclaim unavailable")
	}
	return fn()
}

// enableReclaim wires a working reclaim that clears the write fence (as a real
// AcquireWriterLocal swap would), so the re-delivered chunk lands.
func (f *fakeSession) enableReclaim() {
	f.mu.Lock()
	f.reclaimFn = func() error { f.setWriteErr(nil); return nil }
	f.mu.Unlock()
}

// reclaimAttempts reports how many times the server called ReclaimWriter.
func (f *fakeSession) reclaimAttempts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reclaimCalls
}

// wroteAny reports whether any keystroke was forwarded to Write.
func (f *fakeSession) wroteAny() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes) > 0
}

func (f *fakeSession) Resize(rows, cols uint16) error {
	ws := Winsize{Rows: rows, Cols: cols}
	f.mu.Lock()
	f.resizes = append(f.resizes, ws)
	f.mu.Unlock()
	f.resizeCh <- ws
	return nil
}

func (f *fakeSession) ExitCode() (int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hideExit {
		return 0, false // the daemon can't determine the code (A4)
	}
	return f.exitCode, f.exited
}

func (f *fakeSession) Detach() {
	f.mu.Lock()
	first := !f.detached
	f.detached = true
	f.mu.Unlock()
	// Close the correlation channel (once) so the server's relay goroutine
	// exits, the way a real run's end does.
	if f.corrCh != nil {
		f.corrClose.Do(func() { close(f.corrCh) })
	}
	// Unblock the server's output pump the way a real unsubscribe would.
	_ = f.pr.CloseWithError(errors.New("detached"))
	if first {
		select {
		case f.detachCh <- struct{}{}:
		default:
		}
	}
}

// feed pushes PTY output bytes toward the client (blocks until the pump reads).
func (f *fakeSession) feed(b []byte) { _, _ = f.pw.Write(b) }

// endOutput marks the child exited and closes the output stream (→ io.EOF).
func (f *fakeSession) endOutput(code int) {
	f.mu.Lock()
	f.exitCode = code
	f.exited = true
	f.mu.Unlock()
	_ = f.pw.Close()
}

func (f *fakeSession) wasDetached() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.detached }
func (f *fakeSession) wasKilled() bool   { f.mu.Lock(); defer f.mu.Unlock(); return f.killed }

// fakeHost hands out a preconfigured session and records the spawn request.
type fakeHost struct {
	sess    *fakeSession
	err     error
	mu      sync.Mutex
	lastReq SpawnRequest
	gotReq  chan SpawnRequest
}

func newFakeHost(sess *fakeSession) *fakeHost {
	return &fakeHost{sess: sess, gotReq: make(chan SpawnRequest, 1)}
}

func (h *fakeHost) LaunchAttachable(_ context.Context, req SpawnRequest) (Session, error) {
	h.mu.Lock()
	h.lastReq = req
	h.mu.Unlock()
	select {
	case h.gotReq <- req:
	default:
	}
	if h.err != nil {
		return nil, h.err
	}
	return h.sess, nil
}

// pipeStdin adapts an *io.PipeReader to the ClientReader contract (A3-1) for
// tests. It does not support read deadlines (SetReadDeadline errors), so
// Attach's unblock falls through to Close — which, for an io.Pipe, unblocks a
// parked Read just as a real fd's past deadline would.
type pipeStdin struct{ *io.PipeReader }

func (pipeStdin) SetReadDeadline(time.Time) error { return errors.New("pipe: no read deadline") }

// --- helpers ---------------------------------------------------------------

// syncBuffer is a mutex-guarded buffer safe for concurrent read/write.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// startServer runs a single serveConn over the server end of a net.Pipe and
// returns the client end.
func startServer(t *testing.T, host Host) net.Conn {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	s := &server{host: host, logger: nil, conns: make(map[*frameConn]net.Conn)}
	// slog.Default() is used when logger is nil inside Serve; serveConn does not
	// touch the logger, so a nil is fine here.
	go s.serveConn(context.Background(), serverConn)
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })
	return clientConn
}

// --- tests -----------------------------------------------------------------

// (a) spawn round-trip delivers the handle/run id and the server sees the req.
func TestSpawnRoundTrip(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("HANDLE-1", "RUN-1")
	host := newFakeHost(sess)
	cc := startServer(t, host)
	fc := newFrameConn(cc)

	if err := fc.sendControl(spawnMsg{
		Op: opSpawn, V: ProtocolVersion, Tool: "claude-code", Subcommand: "claude",
		Dir: "/work", Rows: 40, Cols: 120, Env: []string{"K=V"},
	}); err != nil {
		t.Fatalf("send spawn: %v", err)
	}
	t2, payload, err := fc.readFrame()
	if err != nil {
		t.Fatalf("read spawned: %v", err)
	}
	if t2 != frameControl {
		t.Fatalf("frame type = %d, want control", t2)
	}
	var sm spawnedMsg
	if err := unmarshalControl(payload, &sm); err != nil {
		t.Fatalf("decode spawned: %v", err)
	}
	if sm.Op != opSpawned || sm.Handle != "HANDLE-1" || sm.RunID != "RUN-1" {
		t.Fatalf("spawned = %+v", sm)
	}
	select {
	case req := <-host.gotReq:
		if req.Tool != "claude-code" || req.Subcommand != "claude" || req.Dir != "/work" ||
			req.Rows != 40 || req.Cols != 120 || len(req.Env) != 1 || req.Env[0] != "K=V" {
			t.Fatalf("spawn request = %+v", req)
		}
	default:
		t.Fatal("host never saw the spawn request")
	}
}

// TestServerSkipsUnknownControlOp is the M7 forward-compat mirror: the server
// must SKIP (fully consume + continue) an UNKNOWN control op from a newer client
// rather than replying CodeProtocol and closing — the same tolerance it already
// gives unknown FRAME types. Proof: after an unknown op, a subsequent VALID
// resize still reaches the session (the readLoop kept running). Malformed frames
// stay fatal (covered by TestOversizedFrameProtocolError / the peekOp path).
func TestServerSkipsUnknownControlOp(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	host := newFakeHost(sess)
	cc := startServer(t, host)
	fc := newFrameConn(cc)

	// Spawn handshake.
	if err := fc.sendControl(spawnMsg{Op: opSpawn, V: ProtocolVersion, Tool: "t", Subcommand: "s"}); err != nil {
		t.Fatalf("send spawn: %v", err)
	}
	if _, _, err := fc.readFrame(); err != nil { // spawnedMsg
		t.Fatalf("read spawned: %v", err)
	}

	// An UNKNOWN control op from a (hypothetical) newer client: the server must
	// skip it silently, NOT send a protocol error and close.
	if err := fc.sendControl(struct {
		Op    string `json:"op"`
		Extra string `json:"extra"`
	}{Op: "future_only_op", Extra: "ignored"}); err != nil {
		t.Fatalf("send unknown op: %v", err)
	}

	// A subsequent VALID resize must still be processed — proof the readLoop kept
	// running after the unknown op (had the server closed, this would time out).
	if err := fc.sendControl(resizeMsg{Op: opResize, Rows: 33, Cols: 99}); err != nil {
		t.Fatalf("send resize after unknown op: %v", err)
	}
	select {
	case ws := <-sess.resizeCh:
		if ws.Rows != 33 || ws.Cols != 99 {
			t.Fatalf("resize = %+v, want 33x99", ws)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resize after an unknown control op never reached the session — the server closed on the unknown op (M7 regression)")
	}
}

// (b)+(c)+(e) full duplex through Attach: stdin reaches Write, output reaches
// Stdout in order, resize reaches Resize, child exit yields Exited status.
func TestAttachDuplexResizeAndExit(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	host := newFakeHost(sess)
	cc := startServer(t, host)

	stdinR, stdinW := io.Pipe()
	out := &syncBuffer{}
	resize := make(chan Winsize, 1)
	resultCh := make(chan struct {
		st  ExitStatus
		err error
	}, 1)

	go func() {
		st, err := Attach(context.Background(), cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{
			Stdin: pipeStdin{stdinR}, Stdout: out, Resize: resize, InitialRows: 24, InitialCols: 80,
		})
		resultCh <- struct {
			st  ExitStatus
			err error
		}{st, err}
	}()

	// Wait for the handshake to complete (host saw the spawn).
	select {
	case <-host.gotReq:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}

	// stdin → Write.
	if _, err := stdinW.Write([]byte("hello")); err != nil {
		t.Fatalf("stdin write: %v", err)
	}
	select {
	case got := <-sess.writeCh:
		if string(got) != "hello" {
			t.Fatalf("session Write = %q, want hello", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stdin never reached session Write")
	}

	// resize → Resize.
	resize <- Winsize{Rows: 50, Cols: 200}
	select {
	case ws := <-sess.resizeCh:
		if ws.Rows != 50 || ws.Cols != 200 {
			t.Fatalf("resize = %+v", ws)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resize never reached session Resize")
	}

	// output → Stdout, in order.
	sess.feed([]byte("abc"))
	sess.feed([]byte("def"))
	waitFor(t, "stdout to receive abcdef", func() bool { return out.String() == "abcdef" })

	// child exit → Exited status.
	sess.endOutput(7)
	select {
	case r := <-resultCh:
		if r.err != nil {
			t.Fatalf("Attach err = %v", r.err)
		}
		if !r.st.Exited || r.st.Code != 7 {
			t.Fatalf("exit status = %+v", r.st)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Attach did not return after child exit")
	}
	_ = stdinW.Close()
}

// (d) client conn drop ⇒ Detach called, never a kill.
func TestClientDropDetachesNotKill(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	host := newFakeHost(sess)
	cc := startServer(t, host)
	fc := newFrameConn(cc)

	if err := fc.sendControl(spawnMsg{Op: opSpawn, V: ProtocolVersion, Tool: "t", Subcommand: "s"}); err != nil {
		t.Fatalf("send spawn: %v", err)
	}
	if _, _, err := fc.readFrame(); err != nil { // spawned
		t.Fatalf("read spawned: %v", err)
	}
	// Drop the client.
	_ = cc.Close()

	select {
	case <-sess.detachCh:
	case <-time.After(2 * time.Second):
		t.Fatal("server never detached after client drop")
	}
	if !sess.wasDetached() {
		t.Fatal("expected Detach")
	}
	if sess.wasKilled() {
		t.Fatal("client drop must never kill the child")
	}
}

// (f) daemon-side close without an exit or explicit daemon_shutdown ⇒
// ErrConnLost (ambiguous: daemon exit vs connection failure — A2-2).
func TestDaemonCloseWithoutExit(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	host := newFakeHost(sess)
	clientConn, serverConn := net.Pipe()
	s := &server{host: host, conns: make(map[*frameConn]net.Conn)}
	go s.serveConn(context.Background(), serverConn)
	t.Cleanup(func() { _ = clientConn.Close() })

	resultCh := make(chan error, 1)
	go func() {
		_, err := Attach(context.Background(), clientConn, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{})
		resultCh <- err
	}()

	// Let the handshake complete, then close the daemon side WITHOUT an exit.
	select {
	case <-host.gotReq:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}
	_ = serverConn.Close()

	select {
	case err := <-resultCh:
		if !errors.Is(err, ErrConnLost) {
			t.Fatalf("err = %v, want ErrConnLost", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Attach did not return after daemon close")
	}
}

// error-frame handling: a daemon_shutdown error maps to ErrDaemonExited, a
// spawn_failed error maps to *ServerError.
func TestAttachErrorFrames(t *testing.T) {
	t.Parallel()

	t.Run("spawn_failed", func(t *testing.T) {
		t.Parallel()
		sess := newFakeSession("H", "R")
		host := newFakeHost(sess)
		host.err = errors.New("boom")
		clientConn, serverConn := net.Pipe()
		s := &server{host: host, conns: make(map[*frameConn]net.Conn)}
		go s.serveConn(context.Background(), serverConn)
		t.Cleanup(func() { _ = clientConn.Close() })

		_, err := Attach(context.Background(), clientConn, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{})
		var se *ServerError
		if !errors.As(err, &se) || se.Code != CodeSpawnFailed {
			t.Fatalf("err = %v, want *ServerError spawn_failed", err)
		}
	})

	t.Run("daemon_shutdown", func(t *testing.T) {
		t.Parallel()
		// Hand-run the server side so we can send a shutdown error after spawned.
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })
		go func() {
			sfc := newFrameConn(serverConn)
			if _, _, err := sfc.readFrame(); err != nil { // spawn
				return
			}
			_ = sfc.sendControl(spawnedMsg{Op: opSpawned, Handle: "H", RunID: "R"})
			_ = sfc.sendError(CodeDaemonShutdown, "shutting down")
		}()
		_, err := Attach(context.Background(), clientConn, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{})
		if !errors.Is(err, ErrDaemonExited) {
			t.Fatalf("err = %v, want ErrDaemonExited", err)
		}
	})
}

// ctx cancel detaches cleanly (no error, not exited).
func TestAttachCtxCancelDetaches(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	host := newFakeHost(sess)
	cc := startServer(t, host)

	ctx, cancel := context.WithCancel(context.Background())
	resultCh := make(chan struct {
		st  ExitStatus
		err error
	}, 1)
	go func() {
		st, err := Attach(ctx, cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{})
		resultCh <- struct {
			st  ExitStatus
			err error
		}{st, err}
	}()
	select {
	case <-host.gotReq:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}
	cancel()
	select {
	case r := <-resultCh:
		if r.err != nil || r.st.Exited {
			t.Fatalf("ctx-cancel detach should be clean: st=%+v err=%v", r.st, r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Attach did not return after ctx cancel")
	}
	waitFor(t, "server detach after ctx cancel", sess.wasDetached)
}

// (g) an oversized frame at handshake ⇒ protocol error frame, conn closed.
func TestOversizedFrameProtocolError(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	host := newFakeHost(sess)
	cc := startServer(t, host)

	// Raw header: length just over the 64 KiB max, type=control.
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], controlFrameMax+1)
	hdr[4] = frameControl
	if _, err := cc.Write(hdr[:]); err != nil {
		t.Fatalf("write raw header: %v", err)
	}
	fc := newFrameConn(cc)
	_, payload, err := fc.readFrame()
	if err != nil {
		t.Fatalf("read error frame: %v", err)
	}
	var em errorMsg
	if err := unmarshalControl(payload, &em); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if em.Op != opError || em.Code != CodeProtocol {
		t.Fatalf("error frame = %+v, want protocol", em)
	}
}

// a malformed handshake (wrong op) ⇒ protocol error frame.
func TestMalformedHandshakeWrongOp(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	host := newFakeHost(sess)
	cc := startServer(t, host)
	fc := newFrameConn(cc)

	if err := fc.sendControl(resizeMsg{Op: opResize, Rows: 1, Cols: 1}); err != nil {
		t.Fatalf("send: %v", err)
	}
	_, payload, err := fc.readFrame()
	if err != nil {
		t.Fatalf("read error frame: %v", err)
	}
	var em errorMsg
	if err := unmarshalControl(payload, &em); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if em.Code != CodeProtocol {
		t.Fatalf("error = %+v, want protocol", em)
	}
}

// bad protocol version ⇒ protocol error frame.
func TestSpawnBadVersion(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	host := newFakeHost(sess)
	cc := startServer(t, host)
	fc := newFrameConn(cc)

	if err := fc.sendControl(spawnMsg{Op: opSpawn, V: 99, Tool: "t", Subcommand: "s"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	_, payload, err := fc.readFrame()
	if err != nil {
		t.Fatalf("read error frame: %v", err)
	}
	var em errorMsg
	_ = unmarshalControl(payload, &em)
	if em.Code != CodeProtocol {
		t.Fatalf("error = %+v, want protocol", em)
	}
}

// (h) ListenSocket refuses to unlink a regular file; on a clean path it creates
// a 0600 socket.
func TestListenSocketPerms(t *testing.T) {
	t.Parallel()
	skipUnlessUnixSocketTransport(t)
	dir := t.TempDir()

	// Refuse a non-socket file.
	regular := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatalf("write regular: %v", err)
	}
	if _, err := ListenSocket(regular); err == nil {
		t.Fatal("expected ListenSocket to refuse a regular file")
	}
	if _, err := os.Stat(regular); err != nil {
		t.Fatalf("regular file should be untouched: %v", err)
	}

	// Clean path → a 0700 parent dir + a 0600 socket (A1). The socket lives in
	// its own dedicated directory so the parent-dir permission enforces
	// owner-only connect().
	sockPath := filepath.Join(dir, "attach", "attach.sock")
	ln, err := ListenSocket(sockPath)
	if err != nil {
		t.Fatalf("ListenSocket: %v", err)
	}
	defer ln.Close()
	fi, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected a socket, got mode %v", fi.Mode())
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket perm = %o, want 600", perm)
	}
	// A1: the parent dir must be 0700 (owner rwx only).
	dfi, err := os.Stat(filepath.Dir(sockPath))
	if err != nil {
		t.Fatalf("stat parent dir: %v", err)
	}
	if perm := dfi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("attach dir perm = %o, want 700", perm)
	}
}

// A1: a pre-existing looser parent dir is tightened to 0700.
func TestListenSocketTightensLooseDir(t *testing.T) {
	t.Parallel()
	skipUnlessUnixSocketTransport(t)
	dir := t.TempDir()
	attachDir := filepath.Join(dir, "attach")
	if err := os.MkdirAll(attachDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	ln, err := ListenSocket(filepath.Join(attachDir, "attach.sock"))
	if err != nil {
		t.Fatalf("ListenSocket: %v", err)
	}
	defer ln.Close()
	dfi, _ := os.Stat(attachDir)
	if perm := dfi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("attach dir perm = %o, want 700 (should have been tightened)", perm)
	}
}

// A9: ListenSocket refuses to steal a path a LIVE daemon is already serving,
// and DOES rebind a stale socket left by a crashed daemon.
func TestListenSocketRefusesLiveDaemon(t *testing.T) {
	t.Parallel()
	skipUnlessUnixSocketTransport(t)
	sockPath := filepath.Join(t.TempDir(), "attach", "attach.sock")
	ln1, err := ListenSocket(sockPath)
	if err != nil {
		t.Fatalf("first ListenSocket: %v", err)
	}
	// Accept in the background so the probe-dial succeeds (a live server).
	go func() {
		for {
			c, aerr := ln1.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// A second bind must refuse — the path is served by a live daemon.
	if _, err := ListenSocket(sockPath); !errors.Is(err, ErrSocketLiveDaemon) {
		t.Fatalf("second ListenSocket err = %v, want ErrSocketLiveDaemon", err)
	}

	// Close the live listener → the socket file is now stale → a rebind
	// succeeds (the probe-dial fails).
	_ = ln1.Close()
	ln2, err := ListenSocket(sockPath)
	if err != nil {
		t.Fatalf("rebind over stale socket: %v", err)
	}
	_ = ln2.Close()
}

// A4: when the daemon cannot determine the child's exit code, the client
// reports an honest unknown (Exited=true, Known=false, Code=-1) — never a
// fabricated 0.
func TestUnknownExitReportedHonestly(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	sess.hideExit = true // ExitCode never becomes known
	host := newFakeHost(sess)
	cc := startServer(t, host)

	resultCh := make(chan ExitStatus, 1)
	go func() {
		st, _ := Attach(context.Background(), cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{})
		resultCh <- st
	}()
	select {
	case <-host.gotReq:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}
	sess.endOutput(0) // child exits but ExitCode stays unknown

	select {
	case st := <-resultCh:
		if !st.Exited || st.Known || st.Code != -1 {
			t.Fatalf("status = %+v, want {Code:-1 Exited:true Known:false}", st)
		}
	case <-time.After(exitPollTimeout + 2*time.Second):
		t.Fatal("Attach did not return")
	}
}

// A5: a writer-revoked write yields a NON-FATAL notice; the client surfaces it
// once and keeps streaming until a real exit.
func TestWriterRevokedNonFatal(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	sess.setWriteErr(ErrWriterRevoked)
	host := newFakeHost(sess)
	cc := startServer(t, host)

	stdinR, stdinW := io.Pipe()
	var noticeCount int
	var noticeCode string
	var nmu sync.Mutex
	resultCh := make(chan ExitStatus, 1)
	go func() {
		st, _ := Attach(context.Background(), cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{
			Stdin: pipeStdin{stdinR},
			Notice: func(code, _ string) {
				nmu.Lock()
				noticeCount++
				noticeCode = code
				nmu.Unlock()
			},
		})
		resultCh <- st
	}()
	select {
	case <-host.gotReq:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}

	// Two keystrokes → two revoked writes → the client dedupes to ONE notice.
	_, _ = stdinW.Write([]byte("a"))
	_, _ = stdinW.Write([]byte("b"))
	waitFor(t, "a writer-revoked notice", func() bool {
		nmu.Lock()
		defer nmu.Unlock()
		return noticeCount >= 1
	})

	// Output still streams after the revocation.
	sess.feed([]byte("live"))
	// Then a clean exit ends the session.
	sess.endOutput(0)
	select {
	case st := <-resultCh:
		if !st.Exited {
			t.Fatalf("status = %+v, want Exited", st)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Attach did not return after exit")
	}
	nmu.Lock()
	defer nmu.Unlock()
	if noticeCount != 1 || noticeCode != CodeWriterRevoked {
		t.Fatalf("notices = %d code=%q, want exactly 1 writer_revoked", noticeCount, noticeCode)
	}
	_ = stdinW.Close()
}

// Feature 1: a fenced stdin chunk whose first byte is a real key (not ESC)
// RECLAIMS the writer — the daemon re-acquires the local lease, re-delivers the
// chunk, and notifies the client with writer_reclaimed.
func TestWriterReclaimOnNonESCInput(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	sess.setWriteErr(ErrWriterRevoked)
	sess.enableReclaim()
	host := newFakeHost(sess)
	cc := startServer(t, host)

	stdinR, stdinW := io.Pipe()
	var noticeCount int
	var noticeCode string
	var nmu sync.Mutex
	resultCh := make(chan ExitStatus, 1)
	go func() {
		st, _ := Attach(context.Background(), cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{
			Stdin: pipeStdin{stdinR},
			Notice: func(code, _ string) {
				nmu.Lock()
				noticeCount++
				noticeCode = code
				nmu.Unlock()
			},
		})
		resultCh <- st
	}()
	select {
	case <-host.gotReq:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}

	_, _ = stdinW.Write([]byte("a")) // a real key → reclaim
	waitFor(t, "a writer-reclaimed notice", func() bool {
		nmu.Lock()
		defer nmu.Unlock()
		return noticeCount >= 1
	})
	waitFor(t, "the reclaimed keystroke to land", sess.wroteAny)

	sess.endOutput(0)
	select {
	case <-resultCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Attach did not return after exit")
	}
	nmu.Lock()
	defer nmu.Unlock()
	if noticeCode != CodeWriterReclaimed {
		t.Fatalf("notice code = %q, want %q", noticeCode, CodeWriterReclaimed)
	}
	if sess.reclaimAttempts() == 0 {
		t.Fatal("ReclaimWriter was never called on a non-ESC fenced write")
	}
	_ = stdinW.Close()
}

// Feature 1: an ESC-initiated fenced chunk — e.g. a TUI's cursor-position reply
// ESC[6n the terminal EMULATOR auto-answers on stdin — must NEVER reclaim, or
// the dashboard's control would be stolen with nobody typing. It stays fenced
// and yields the plain revoked notice.
func TestWriterReclaimSkippedForESCChunk(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	sess.setWriteErr(ErrWriterRevoked)
	sess.enableReclaim() // reclaim WOULD work; the ESC lead must veto it
	host := newFakeHost(sess)
	cc := startServer(t, host)

	stdinR, stdinW := io.Pipe()
	var noticeCount int
	var noticeCode string
	var nmu sync.Mutex
	resultCh := make(chan ExitStatus, 1)
	go func() {
		st, _ := Attach(context.Background(), cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{
			Stdin: pipeStdin{stdinR},
			Notice: func(code, _ string) {
				nmu.Lock()
				noticeCount++
				noticeCode = code
				nmu.Unlock()
			},
		})
		resultCh <- st
	}()
	select {
	case <-host.gotReq:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}

	_, _ = stdinW.Write([]byte{escByte, '[', '6', 'n'}) // ESC[6n — machine bytes
	waitFor(t, "a writer-revoked notice", func() bool {
		nmu.Lock()
		defer nmu.Unlock()
		return noticeCount >= 1
	})

	sess.endOutput(0)
	select {
	case <-resultCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Attach did not return after exit")
	}
	nmu.Lock()
	defer nmu.Unlock()
	if noticeCode != CodeWriterRevoked {
		t.Fatalf("notice code = %q, want %q (ESC must not reclaim)", noticeCode, CodeWriterRevoked)
	}
	if sess.reclaimAttempts() != 0 {
		t.Fatalf("ReclaimWriter called %d times for an ESC chunk, want 0", sess.reclaimAttempts())
	}
	if sess.wroteAny() {
		t.Fatal("an ESC-led fenced chunk reached the PTY")
	}
	_ = stdinW.Close()
}

// Feature 1: with reclaim disabled (the Session's ReclaimWriter reports
// unavailable, e.g. [terminal.attach].reclaim_on_input=false), a non-ESC fenced
// write keeps the pre-Feature-1 fence-and-notify behavior — the plain revoked
// notice, no keystroke delivered.
func TestWriterReclaimDisabledFallsBackToRevoked(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	sess.setWriteErr(ErrWriterRevoked) // reclaim NOT enabled
	host := newFakeHost(sess)
	cc := startServer(t, host)

	stdinR, stdinW := io.Pipe()
	var noticeCount int
	var noticeCode string
	var nmu sync.Mutex
	resultCh := make(chan ExitStatus, 1)
	go func() {
		st, _ := Attach(context.Background(), cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{
			Stdin: pipeStdin{stdinR},
			Notice: func(code, _ string) {
				nmu.Lock()
				noticeCount++
				noticeCode = code
				nmu.Unlock()
			},
		})
		resultCh <- st
	}()
	select {
	case <-host.gotReq:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}

	_, _ = stdinW.Write([]byte("a")) // non-ESC, but reclaim is disabled
	waitFor(t, "a writer-revoked notice", func() bool {
		nmu.Lock()
		defer nmu.Unlock()
		return noticeCount >= 1
	})

	sess.endOutput(0)
	select {
	case <-resultCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Attach did not return after exit")
	}
	nmu.Lock()
	defer nmu.Unlock()
	if noticeCode != CodeWriterRevoked {
		t.Fatalf("notice code = %q, want %q (reclaim disabled ⇒ old behavior)", noticeCode, CodeWriterRevoked)
	}
	if sess.wroteAny() {
		t.Fatal("a fenced chunk reached the PTY though reclaim is disabled")
	}
	_ = stdinW.Close()
}

// Feature 1: the client's revoked/reclaimed notices are a TRANSITION toggle — a
// revoke→reclaim→revoke cycle prints each change, while a repeat of the same
// transition is deduped.
func TestWriterRevokeReclaimRevokeTransitionsEachNotify(t *testing.T) {
	t.Parallel()
	cc := scriptServer(t, func(sfc *frameConn) {
		_ = sfc.sendError(CodeWriterRevoked, "revoked-1")
		_ = sfc.sendError(CodeWriterRevoked, "revoked-1-dup") // same transition: deduped
		_ = sfc.sendError(CodeWriterReclaimed, "reclaimed")
		_ = sfc.sendError(CodeWriterRevoked, "revoked-2")
		_ = sfc.sendControl(exitMsg{Op: opExit, Code: 0, Known: true})
	})
	var mu sync.Mutex
	var codes []string
	st, err := Attach(context.Background(), cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{
		Notice: func(code, _ string) { mu.Lock(); codes = append(codes, code); mu.Unlock() },
	})
	if err != nil || !st.Exited {
		t.Fatalf("st=%+v err=%v, want clean exit", st, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(codes) != 3 || codes[0] != CodeWriterRevoked || codes[1] != CodeWriterReclaimed || codes[2] != CodeWriterRevoked {
		t.Fatalf("notice codes = %v, want [%s %s %s] (each transition prints; a dup is deduped)",
			codes, CodeWriterRevoked, CodeWriterReclaimed, CodeWriterRevoked)
	}
}

// A3: no stdin read is forwarded to the session after Attach returns — a
// keystroke typed once the session has ended is not stolen from the shell.
func TestNoStdinForwardedAfterExit(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	host := newFakeHost(sess)
	cc := startServer(t, host)

	stdinR, stdinW := io.Pipe()
	resultCh := make(chan ExitStatus, 1)
	go func() {
		st, _ := Attach(context.Background(), cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{Stdin: pipeStdin{stdinR}})
		resultCh <- st
	}()
	select {
	case <-host.gotReq:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}

	// Child exits; Attach must return with the stdin pump stopped.
	sess.endOutput(0)
	select {
	case <-resultCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Attach did not return after exit")
	}

	// A keystroke AFTER Attach returned must NOT reach the session.
	_, _ = stdinW.Write([]byte("late"))
	time.Sleep(50 * time.Millisecond)
	if sess.wroteAny() {
		t.Fatal("a stdin byte was forwarded to the session AFTER the session ended")
	}
	_ = stdinW.Close()
}

// A3-2/B3-4: resolveAttachResult precedence — observed exit > clean ctx-cancel
// detach > lost connection/server error > input stall. inputStalled must never
// override a real exit or a cancellation.
func TestResolveAttachResultPrecedence(t *testing.T) {
	t.Parallel()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	live := context.Background()

	exit := ExitStatus{Code: 7, Exited: true, Known: true}

	cases := []struct {
		name            string
		ctx             context.Context
		status          ExitStatus
		aerr            error
		inputStalled    bool
		connLostOnWrite bool
		wantStatus      ExitStatus
		wantErr         error
	}{
		{"exit beats stall", live, exit, nil, true, false, exit, nil},
		{"exit beats cancel", canceled, exit, nil, false, false, exit, nil},
		{"cancel beats stall", canceled, ExitStatus{}, nil, true, false, ExitStatus{}, nil},
		{"cancel beats connloss", canceled, ExitStatus{}, ErrConnLost, false, false, ExitStatus{}, nil},
		{"connloss beats stall", live, ExitStatus{}, ErrConnLost, true, false, ExitStatus{}, ErrConnLost},
		{"stall when nothing else", live, ExitStatus{}, nil, true, false, ExitStatus{}, ErrInputStalled},
		{"clean detach", live, ExitStatus{}, nil, false, false, ExitStatus{}, nil},
		// F2b: a connection lost DURING a stdin write (daemon crash mid-write)
		// must surface as ErrConnLost, not be masked as a mere stall — even
		// though the stdin pump marked detached so the read loop reported a
		// clean detach (aerr==nil).
		{"connloss-on-write beats stall", live, ExitStatus{}, nil, true, true, ExitStatus{}, ErrConnLost},
		{"connloss-on-write without stall", live, ExitStatus{}, nil, false, true, ExitStatus{}, ErrConnLost},
		{"exit beats connloss-on-write", live, exit, nil, false, true, exit, nil},
		{"cancel beats connloss-on-write", canceled, ExitStatus{}, nil, false, true, ExitStatus{}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotStatus, gotErr := resolveAttachResult(tc.ctx, tc.status, tc.aerr, tc.inputStalled, tc.connLostOnWrite)
			if gotStatus != tc.wantStatus {
				t.Errorf("status = %+v, want %+v", gotStatus, tc.wantStatus)
			}
			if !errors.Is(gotErr, tc.wantErr) {
				t.Errorf("err = %v, want %v", gotErr, tc.wantErr)
			}
		})
	}
}

// fakeTimeoutErr satisfies net.Error with Timeout()==true, modeling a blown
// write deadline (a stall, not a lost connection).
type fakeTimeoutErr struct{}

func (fakeTimeoutErr) Error() string   { return "i/o timeout" }
func (fakeTimeoutErr) Timeout() bool   { return true }
func (fakeTimeoutErr) Temporary() bool { return true }

// F2b: writeIndicatesConnLost treats a blown write deadline as a stall and any
// other write error as a lost connection.
func TestWriteIndicatesConnLost(t *testing.T) {
	t.Parallel()
	if writeIndicatesConnLost(nil) {
		t.Error("nil write error is not a lost connection")
	}
	if writeIndicatesConnLost(fakeTimeoutErr{}) {
		t.Error("a write-deadline timeout is a stall, not a lost connection")
	}
	if writeIndicatesConnLost(fmt.Errorf("wrapped: %w", fakeTimeoutErr{})) {
		t.Error("a wrapped write-deadline timeout is a stall, not a lost connection")
	}
	if !writeIndicatesConnLost(errors.New("broken pipe")) {
		t.Error("a non-timeout write error is a lost connection")
	}
}

// Dial to a missing socket is distinguishable as ErrDaemonUnreachable.
func TestDialUnreachable(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "nope.sock")
	if _, err := Dial(missing); !errors.Is(err, ErrDaemonUnreachable) {
		t.Fatalf("err = %v, want ErrDaemonUnreachable", err)
	}
}

// Serve over a real unix socket end-to-end: spawn, exchange, exit.
func TestServeOverUnixSocket(t *testing.T) {
	t.Parallel()
	skipUnlessUnixSocketTransport(t)
	sockPath := filepath.Join(t.TempDir(), "attach.sock")
	ln, err := ListenSocket(sockPath)
	if err != nil {
		t.Fatalf("ListenSocket: %v", err)
	}
	sess := newFakeSession("H", "R")
	host := newFakeHost(sess)
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- Serve(ctx, ln, host, nil) }()

	conn, err := Dial(sockPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	out := &syncBuffer{}
	resultCh := make(chan ExitStatus, 1)
	go func() {
		st, _ := Attach(context.Background(), conn, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{Stdout: out})
		resultCh <- st
	}()
	select {
	case <-host.gotReq:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete over unix socket")
	}
	sess.feed([]byte("ok"))
	waitFor(t, "stdout ok", func() bool { return out.String() == "ok" })
	sess.endOutput(0)
	select {
	case st := <-resultCh:
		if !st.Exited {
			t.Fatalf("status = %+v", st)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Attach did not return")
	}

	// Clean shutdown returns nil.
	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil on ctx cancel", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after ctx cancel")
	}
}

// Layer 1 (a): a capable client (ClientIO.Correlated set → AutoResumeCapable
// advertised) receives the daemon's frameCorrelated announce with the REAL
// session id + provenance.
func TestCorrelatedFrameDeliveredToCapableClient(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R").withCorrelation()
	host := newFakeHost(sess)
	cc := startServer(t, host)

	type corr struct {
		id, source string
		conf       float64
	}
	corrCh := make(chan corr, 4)
	resultCh := make(chan ExitStatus, 1)
	go func() {
		st, _ := Attach(context.Background(), cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{
			Correlated: func(id, source string, confidence float64) {
				corrCh <- corr{id, source, confidence}
			},
		})
		resultCh <- st
	}()
	// The server must have seen AutoResumeCapable=true in the spawn frame.
	select {
	case req := <-host.gotReq:
		if !req.AutoResumeCapable {
			t.Fatalf("spawn req AutoResumeCapable = false, want true (Correlated set)")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}

	// Correlation lands: the id must reach the client's callback.
	sess.announceCorrelation(CorrelatedSession{SessionID: "sess-42", Source: "oob", Confidence: 0.95})
	select {
	case got := <-corrCh:
		if got.id != "sess-42" || got.source != "oob" || got.conf != 0.95 {
			t.Fatalf("correlated = %+v, want {sess-42 oob 0.95}", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("frameCorrelated never reached the capable client")
	}

	sess.endOutput(0)
	select {
	case st := <-resultCh:
		if !st.Exited {
			t.Fatalf("status = %+v, want Exited", st)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Attach did not return after exit")
	}
}

// Layer 1 backward-compat: an OLD client (no ClientIO.Correlated → not
// AutoResumeCapable) never receives frameCorrelated, so it never trips the
// unknown-frame path and completes normally. Proves the daemon gates emission on
// the client's advertised capability.
func TestCorrelatedFrameSuppressedForIncapableClient(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R").withCorrelation()
	host := newFakeHost(sess)
	cc := startServer(t, host)

	out := &syncBuffer{}
	resultCh := make(chan struct {
		st  ExitStatus
		err error
	}, 1)
	go func() {
		st, err := Attach(context.Background(), cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{Stdout: out})
		resultCh <- struct {
			st  ExitStatus
			err error
		}{st, err}
	}()
	select {
	case req := <-host.gotReq:
		if req.AutoResumeCapable {
			t.Fatalf("spawn req AutoResumeCapable = true, want false (no Correlated)")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}

	// Even though the session would announce a correlation, the server never
	// started a relay (client not capable), so nothing is sent. Output + exit
	// still flow normally.
	sess.announceCorrelation(CorrelatedSession{SessionID: "sess-x", Source: "oob"})
	sess.feed([]byte("hi"))
	waitFor(t, "stdout hi", func() bool { return out.String() == "hi" })
	sess.endOutput(0)
	select {
	case r := <-resultCh:
		if r.err != nil || !r.st.Exited {
			t.Fatalf("incapable client: st=%+v err=%v, want clean exit", r.st, r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Attach did not return")
	}
}

// scriptServer hand-runs the server end of a net.Pipe: it reads the spawn frame,
// replies spawned, then invokes script(sfc) to send arbitrary frames.
func scriptServer(t *testing.T, script func(sfc *frameConn)) net.Conn {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })
	go func() {
		sfc := newFrameConn(serverConn)
		if _, _, err := sfc.readFrame(); err != nil { // spawn
			return
		}
		_ = sfc.sendControl(spawnedMsg{Op: opSpawned, Handle: "H", RunID: "R"})
		script(sfc)
	}()
	return clientConn
}

// Layer 1 forward-compat: an UNKNOWN frame type from a newer daemon is
// size-bounded and SKIPPED by the client reader (the length prefix keeps the
// stream synced), so real output after it still arrives and the session exits
// cleanly — the reader never poisons on an unrecognized type.
func TestUnknownFrameTypeSkippedByClient(t *testing.T) {
	t.Parallel()
	cc := scriptServer(t, func(sfc *frameConn) {
		_ = sfc.writeFrame(99, []byte(`{"future":"payload"}`)) // unknown type
		_ = sfc.writeData(frameOutput, []byte("ok"))
		_ = sfc.sendControl(exitMsg{Op: opExit, Code: 0, Known: true})
	})
	out := &syncBuffer{}
	st, err := Attach(context.Background(), cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{Stdout: out})
	if err != nil {
		t.Fatalf("Attach err = %v, want nil (unknown frame type must be skipped)", err)
	}
	if !st.Exited || st.Code != 0 {
		t.Fatalf("status = %+v, want clean exit 0", st)
	}
	if out.String() != "ok" {
		t.Fatalf("stdout = %q, want ok (output after an unknown frame must still arrive)", out.String())
	}
}

// Layer 1 forward-compat: an UNKNOWN control op from a newer daemon is skipped,
// not fatal.
func TestUnknownControlOpSkippedByClient(t *testing.T) {
	t.Parallel()
	cc := scriptServer(t, func(sfc *frameConn) {
		_ = sfc.sendControl(map[string]any{"op": "future_op", "x": 1}) // unknown op
		_ = sfc.writeData(frameOutput, []byte("ok"))
		_ = sfc.sendControl(exitMsg{Op: opExit, Code: 0, Known: true})
	})
	out := &syncBuffer{}
	st, err := Attach(context.Background(), cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{Stdout: out})
	if err != nil {
		t.Fatalf("Attach err = %v, want nil (unknown control op must be skipped)", err)
	}
	if !st.Exited || out.String() != "ok" {
		t.Fatalf("status=%+v out=%q, want clean exit + ok", st, out.String())
	}
}

// A newer client against an OLD daemon (one that never sends frameCorrelated)
// simply never fires Correlated — no auto-resume target, degrade to the hint.
func TestNoCorrelatedFrameLeavesCallbackUnfired(t *testing.T) {
	t.Parallel()
	cc := scriptServer(t, func(sfc *frameConn) {
		_ = sfc.writeData(frameOutput, []byte("hi"))
		_ = sfc.sendControl(exitMsg{Op: opExit, Code: 0, Known: true})
	})
	var fired int32
	st, err := Attach(context.Background(), cc, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{
		Correlated: func(string, string, float64) { atomic.AddInt32(&fired, 1) },
	})
	if err != nil || !st.Exited {
		t.Fatalf("st=%+v err=%v, want clean exit", st, err)
	}
	if atomic.LoadInt32(&fired) != 0 {
		t.Fatalf("Correlated fired %d times, want 0 (old daemon sent no frame)", fired)
	}
}

// Resume spawn metadata (ResumeSession + AutoResume) reaches the Host so its
// double-spawn guard + orphan validation can act on it.
func TestResumeSpawnFieldsReachHost(t *testing.T) {
	t.Parallel()
	sess := newFakeSession("H", "R")
	host := newFakeHost(sess)
	cc := startServer(t, host)
	fc := newFrameConn(cc)
	if err := fc.sendControl(spawnMsg{
		Op: opSpawn, V: ProtocolVersion, Tool: "t", Subcommand: "s",
		ResumeSession: "sess-9", AutoResume: true, AutoResumeCapable: true,
	}); err != nil {
		t.Fatalf("send spawn: %v", err)
	}
	if _, _, err := fc.readFrame(); err != nil { // spawned
		t.Fatalf("read spawned: %v", err)
	}
	select {
	case req := <-host.gotReq:
		if req.ResumeSession != "sess-9" || !req.AutoResume || !req.AutoResumeCapable {
			t.Fatalf("host req = %+v, want ResumeSession=sess-9 AutoResume+AutoResumeCapable=true", req)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("host never saw the spawn")
	}
}

// A resume-guard refusal (double-spawn / not-resumable) maps to a distinct
// wire code the client can key off, surfaced as a *ServerError.
func TestResumeRefusalMapsToServerError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		hostErr  error
		wantCode string
	}{
		{"conflict", ErrResumeConflict, CodeResumeConflict},
		{"not-resumable", ErrResumeNotResumable, CodeResumeNotResumable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sess := newFakeSession("H", "R")
			host := newFakeHost(sess)
			host.err = tc.hostErr
			clientConn, serverConn := net.Pipe()
			s := &server{host: host, conns: make(map[*frameConn]net.Conn)}
			go s.serveConn(context.Background(), serverConn)
			t.Cleanup(func() { _ = clientConn.Close() })

			_, err := Attach(context.Background(), clientConn, SpawnRequest{
				Tool: "t", Subcommand: "s", ResumeSession: "sess-9", AutoResume: true,
			}, ClientIO{})
			var se *ServerError
			if !errors.As(err, &se) || se.Code != tc.wantCode {
				t.Fatalf("err = %v, want *ServerError code %q", err, tc.wantCode)
			}
		})
	}
}
