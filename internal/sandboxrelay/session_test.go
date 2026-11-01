package sandboxrelay

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func testParams(p Purpose) Params {
	return Params{Purpose: p, Limits: DefaultLimits, Conn: DefaultConnLimits, Rand: rand.Reader}
}

// pair runs Accept on one end of a pipe and Dial on the other.
func pair(t *testing.T, serverRun string, clientRun string, clientSecret []byte, p Params) (*Session, *Session, error, error) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	type res struct {
		s   *Session
		err error
	}
	sc := make(chan res, 1)
	go func() {
		s, err := Accept(a, p, func(id string) ([]byte, error) {
			if id != serverRun {
				return nil, errors.New("unknown run")
			}
			return testSecret, nil
		})
		if err != nil {
			_ = a.Close()
		}
		sc <- res{s, err}
	}()
	cs, cerr := Dial(b, p, clientRun, clientSecret)
	if cerr != nil {
		_ = b.Close()
	}
	r := <-sc
	return r.s, cs, r.err, cerr
}

// TestSessionHookRoundTrip: a hook request larger than one frame crosses
// the hook stream behind its length prefix and the response comes back.
func TestSessionHookRoundTrip(t *testing.T) {
	srv, cli, serr, cerr := pair(t, "run-1", "run-1", testSecret, testParams(PurposeBox))
	if serr != nil || cerr != nil {
		t.Fatalf("handshake: %v %v", serr, cerr)
	}
	stdin := bytes.Repeat([]byte("x"), 256<<10) // four frames' worth (JSP-2's largest Write)
	req := HookRequest{Args: []string{"claude-code", "PreToolUse"}, Env: map[string]string{"OBSERVER_SANDBOX": "1"}, Cwd: "/work", Stdin: stdin}
	msg, err := EncodeHookRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cli.Send(StreamHook, msg) }()
	got, err := srv.Recv(StreamHook, MaxMessage)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	rules := RequestRules{EnvAllowed: func(n string) bool { return n == "OBSERVER_SANDBOX" }}
	dec, err := DecodeHookRequest(got, rules)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Stdin, stdin) || dec.Args[1] != "PreToolUse" || dec.Cwd != "/work" {
		t.Fatalf("decoded %+v", dec.Args)
	}
	resp, _ := EncodeHookResponse(HookResponse{Exit: 2, Stdout: []byte(`{"decision":"block"}`), Stderr: []byte("denied")})
	go func() { done <- srv.Send(StreamHook, resp) }()
	back, err := cli.Recv(StreamHook, MaxMessage)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	r, err := DecodeHookResponse(back)
	if err != nil || r.Exit != 2 || string(r.Stdout) != `{"decision":"block"}` || string(r.Stderr) != "denied" {
		t.Fatalf("response %+v %v", r, err)
	}
}

// TestSessionRefusesAnotherRun is the mutation proof of the acceptance "a
// relay frame claiming another run id is refused": a client that claims
// run-2 to a server that only knows run-1 is refused at the handshake, and
// a client that claims run-1 with run-2's secret fails the first MAC.
func TestSessionRefusesAnotherRun(t *testing.T) {
	_, _, serr, _ := pair(t, "run-1", "run-2", testSecret, testParams(PurposeBox))
	if !errors.Is(serr, ErrHandshake) {
		t.Fatalf("a claim of another run: server %v", serr)
	}
	_, _, _, cerr := pair(t, "run-1", "run-1", []byte("ffffffffffffffffffffffffffffffff"), testParams(PurposeBox))
	if !errors.Is(cerr, ErrMAC) {
		t.Fatalf("the wrong secret: client %v, want a MAC failure on the server's first frame", cerr)
	}
}

// TestSessionPurposeBound: a box key never authenticates on the link.
func TestSessionPurposeBound(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	go func() {
		_, _ = Accept(a, testParams(PurposeLink), func(string) ([]byte, error) { return testSecret, nil })
		_ = a.Close()
	}()
	if _, err := Dial(b, testParams(PurposeBox), "run-1", testSecret); !errors.Is(err, ErrHandshake) {
		t.Fatalf("a box client on the link: %v", err)
	}
}

// TestMessageCaps: a message over the per-message cap is refused before it
// is sent and, when a peer declares one anyway, before it is buffered; a
// message longer than its prefix is refused.
func TestMessageCaps(t *testing.T) {
	if err := AppendMessageFrames(make([]byte, MaxMessage+1), DefaultLimits.MaxPayload, func([]byte) error { return nil }); !errors.Is(err, ErrMessage) {
		t.Fatalf("an oversized send: %v", err)
	}
	a := NewAssembler(1024)
	if _, err := a.Add([]byte{0, 0, 8, 0}); !errors.Is(err, ErrMessage) {
		t.Fatalf("a declared 2 KiB over a 1 KiB cap: %v", err)
	}
	a = NewAssembler(1024)
	if _, err := a.Add([]byte{0, 0, 0, 2, 'a'}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add([]byte("bc")); !errors.Is(err, ErrMessage) {
		t.Fatalf("more bytes than declared: %v", err)
	}
	a = NewAssembler(0)
	if m, err := a.Add([]byte{0, 0, 0, 0}); err != nil || m == nil || len(m) != 0 {
		t.Fatalf("an empty message: %v %v", m, err)
	}
}

// TestMessageDeadline: a peer that trickles one message as valid frames
// slower than the message deadline is closed at it, even though every
// single frame arrives within its own deadline.
func TestMessageDeadline(t *testing.T) {
	p := testParams(PurposeBox)
	p.Conn.MessageDeadline = 300 * time.Millisecond
	p.Limits.MaxPayload = 16
	srv, cli, serr, cerr := pair(t, "run-1", "run-1", testSecret, p)
	if serr != nil || cerr != nil {
		t.Fatalf("handshake: %v %v", serr, cerr)
	}
	msg := bytes.Repeat([]byte("y"), 200)
	go func() {
		_ = AppendMessageFrames(msg, p.Limits.MaxPayload, func(chunk []byte) error {
			time.Sleep(50 * time.Millisecond)
			return cli.w.Write(TypeData, StreamHook, chunk)
		})
	}()
	start := time.Now()
	_, err := srv.Recv(StreamHook, MaxMessage)
	var ne net.Error
	if err == nil || !(errors.Is(err, ErrDeadline) || errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("a trickled message: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("closed after %v", d)
	}
}

// TestHookSchema: one case per validation rule.
func TestHookSchema(t *testing.T) {
	rules := RequestRules{EnvAllowed: func(n string) bool { return n == "OBSERVER_SANDBOX" }}
	ok := HookRequest{Args: []string{"claude-code", "PreToolUse"}}
	for _, tc := range []struct {
		name string
		mut  func(r *HookRequest)
		want bool
	}{
		{"valid", func(*HookRequest) {}, true},
		{"no args", func(r *HookRequest) { r.Args = nil }, false},
		{"a flag (the host decides its own config)", func(r *HookRequest) { r.Args = append(r.Args, "--config") }, false},
		{"tool with upper case", func(r *HookRequest) { r.Args[0] = "Claude" }, false},
		{"arg with a slash", func(r *HookRequest) { r.Args[1] = "../x" }, false},
		{"too many args", func(r *HookRequest) { r.Args = make([]string, maxArgs+1); r.Args[0] = "a" }, false},
		{"undeclarable env", func(r *HookRequest) { r.Env = map[string]string{"OBSERVER_HOOK_SHAPE_LOG": "/etc/x"} }, false},
		{"declarable env", func(r *HookRequest) { r.Env = map[string]string{"OBSERVER_SANDBOX": "1"} }, true},
		{"relative cwd", func(r *HookRequest) { r.Cwd = "work" }, false},
		{"launch gate kind", func(r *HookRequest) { r.Kind = KindLaunchGate }, true},
		{"unknown kind", func(r *HookRequest) { r.Kind = "exec" }, false},
		{"unclean cwd", func(r *HookRequest) { r.Cwd = "/a/../b" }, false},
	} {
		r := ok
		r.Args = append([]string(nil), ok.Args...)
		tc.mut(&r)
		msg, err := EncodeHookRequest(r)
		if err != nil {
			t.Fatalf("%s: encode %v", tc.name, err)
		}
		_, err = DecodeHookRequest(msg, rules)
		if (err == nil) != tc.want {
			t.Errorf("%s: err %v", tc.name, err)
		}
	}
	// Unknown header fields and mismatched sections are refused.
	bad := append([]byte{0, 0, 0, 0}, []byte(`{"v":1,"args":["a"],"stdin_len":0,"run_id":"x"}`)...)
	bad[3] = byte(len(bad) - 4)
	if _, err := DecodeHookRequest(bad, rules); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("an unknown header field (a run id in the body): %v", err)
	}
	msg, _ := EncodeHookRequest(HookRequest{Args: []string{"a"}, Stdin: []byte("abc")})
	if _, err := DecodeHookRequest(msg[:len(msg)-1], rules); err == nil {
		t.Fatal("a short stdin section was accepted")
	}
}

// TestMissedBeatsCounting (P-032, milestone 2c): a waiting side counts the
// heartbeats that did not come over a gap (none for a gap of about one
// interval, the intervals past the first otherwise, every interval of a
// wait that ended without a frame); a side not expecting beats counts none.
func TestMissedBeatsCounting(t *testing.T) {
	every := 100 * time.Millisecond
	for _, tc := range []struct {
		gap    time.Duration
		failed bool
		expect time.Duration
		want   int
	}{
		{90 * time.Millisecond, false, every, 0},
		{140 * time.Millisecond, false, every, 0},
		{350 * time.Millisecond, false, every, 2},
		{300 * time.Millisecond, true, every, 3},
		{50 * time.Millisecond, true, every, 0},
		{time.Second, false, 0, 0},
	} {
		s := &Session{p: Params{ExpectBeat: tc.expect}}
		s.noteGap(tc.gap, tc.failed)
		if got := s.MissedBeats(); got != tc.want {
			t.Errorf("gap %s failed %v expect %s: missed %d, want %d", tc.gap, tc.failed, tc.expect, got, tc.want)
		}
	}
	// End to end: a server silent for five intervals while the client
	// waits for its answer.
	p := testParams(PurposeLink)
	server, client, serr, cerr := pair(t, "run-1", "run-1", testSecret, p)
	if serr != nil || cerr != nil {
		t.Fatal(serr, cerr)
	}
	client.p.ExpectBeat = 20 * time.Millisecond
	go func() {
		time.Sleep(110 * time.Millisecond)
		_ = server.Send(StreamHook, []byte("late"))
	}()
	if msg, err := client.Recv(StreamHook, MaxMessage); err != nil || string(msg) != "late" {
		t.Fatalf("recv %q %v", msg, err)
	}
	if n := client.MissedBeats(); n < 3 {
		t.Fatalf("missed %d beats over five silent intervals", n)
	}
}
