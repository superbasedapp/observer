package relaymux

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

var testSecret = bytes.Repeat([]byte{7}, 32)

// stack wraps one end of a pipe the way the cmd layer wraps a vendor
// stream: base64 lines under the deadline adapter.
func stack(c net.Conn) *DeadlineConn {
	return NewDeadlineConn(NewLineReader(c), NewLineWriter(c), c.Close)
}

// echoDial answers every dial with an echo server.
func echoDial(context.Context, string) (io.ReadWriteCloser, error) {
	a, b := net.Pipe()
	go func() {
		_, _ = io.Copy(b, b)
		_ = b.Close()
	}()
	return a, nil
}

func startPair(t *testing.T, kinds map[string]bool, pty io.ReadWriteCloser) (*Host, *Guest) {
	t.Helper()
	hc, gc := net.Pipe()
	type res struct {
		h   *Host
		err error
	}
	ch := make(chan res, 1)
	go func() {
		h, err := ServeHost(context.Background(), stack(hc), HostOptions{
			Options: Options{RunID: "run-1", Secret: testSecret}, Rand: rand.Reader,
			Kinds: kinds, Dial: echoDial, PTY: pty, Record: []byte(`{"v":1}`),
		})
		ch <- res{h, err}
	}()
	g, err := DialGuest(context.Background(), stack(gc), Options{RunID: "run-1", Secret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { r.h.Close(); g.Close() })
	return r.h, g
}

func TestMuxRoundTripPastTheWindow(t *testing.T) {
	h, g := startPair(t, map[string]bool{KindRelay: true, KindProxy: true}, nil)
	defer func() {
		if t.Failed() {
			t.Logf("host err %v guest err %v", h.Err(), g.Err())
		}
	}()
	if string(g.Hello().Record) != `{"v":1}` || len(g.Hello().Kinds) != 2 {
		t.Fatalf("hello %+v", g.Hello())
	}
	c, err := g.Connect(context.Background(), KindProxy)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("0123456789abcdef"), 4*Window/16)
	go func() { _, _ = c.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo differs")
	}
	// Several streams at once.
	for i := 0; i < 5; i++ {
		c2, err := g.Connect(context.Background(), KindRelay)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c2.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 4)
		if _, err := io.ReadFull(c2, b); err != nil || string(b) != "ping" {
			t.Fatalf("stream %d: %q %v", i, b, err)
		}
		_ = c2.Close()
	}
}

func TestMuxRefusesAKindTheTierDoesNotAllow(t *testing.T) {
	_, g := startPair(t, map[string]bool{KindRelay: true}, nil)
	if _, err := g.Connect(context.Background(), KindProxy); !errors.Is(err, ErrRefused) {
		t.Fatalf("proxy on the none tier: %v", err)
	}
	if _, err := g.Connect(context.Background(), KindRelay); err != nil {
		t.Fatalf("relay: %v", err)
	}
}

func TestMuxPTYAndResize(t *testing.T) {
	term, termPeer := net.Pipe()
	h, g := startPair(t, map[string]bool{KindRelay: true}, termPeer)
	box := g.PTY()
	if box == nil {
		t.Fatal("no PTY stream")
	}
	go func() { _, _ = box.Write([]byte("box says hi")) }()
	b := make([]byte, 11)
	if _, err := io.ReadFull(term, b); err != nil || string(b) != "box says hi" {
		t.Fatalf("output %q %v", b, err)
	}
	go func() { _, _ = term.Write([]byte("ls\r")) }()
	in := make([]byte, 3)
	if _, err := io.ReadFull(box, in); err != nil || string(in) != "ls\r" {
		t.Fatalf("input %q %v", in, err)
	}
	if err := h.Resize(40, 120); err != nil {
		t.Fatal(err)
	}
	select {
	case sz := <-g.Resizes():
		if sz.Rows != 40 || sz.Cols != 120 {
			t.Fatalf("size %+v", sz)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no resize")
	}
}

// rawGuest performs the guest handshake by hand and returns a sealer for
// crafting frames, so the hostile cases reach the host's frame checks.
type rawGuest struct {
	c      net.Conn
	lw     *LineWriter
	sealer *sandboxrelay.Sealer
	host   chan error
}

func newRawGuest(t *testing.T, secret []byte) *rawGuest {
	t.Helper()
	return newRawGuestDial(t, secret, echoDial)
}

// stuckDial answers with a socket nobody reads.
func stuckDial(context.Context, string) (io.ReadWriteCloser, error) {
	a, _ := net.Pipe()
	return a, nil
}

func newRawGuestDial(t *testing.T, secret []byte, dial func(context.Context, string) (io.ReadWriteCloser, error)) *rawGuest {
	t.Helper()
	hc, gc := net.Pipe()
	host := make(chan error, 1)
	go func() {
		h, err := ServeHost(context.Background(), stack(hc), HostOptions{
			Options: Options{RunID: "run-1", Secret: testSecret}, Rand: rand.Reader,
			Kinds: map[string]bool{KindRelay: true}, Dial: dial,
		})
		if err != nil {
			host <- err
			return
		}
		<-h.Done()
		host <- h.Err()
	}()
	lr, lw := NewLineReader(gc), NewLineWriter(gc)
	pre := make([]byte, 8+sandboxrelay.NonceSize)
	if _, err := io.ReadFull(lr, pre); err != nil {
		t.Fatal(err)
	}
	hello := append(append(append([]byte(nil), muxMagic...), 1, 5), "run-1"...)
	if _, err := lw.Write(hello); err != nil {
		t.Fatal(err)
	}
	k, err := sandboxrelay.DeriveKeys(secret, sandboxrelay.PurposeBox, "run-1", pre[8:], 0)
	if err != nil {
		t.Fatal(err)
	}
	// Drain what the host sends so its writes never block.
	go func() { _, _ = io.Copy(io.Discard, lr) }()
	return &rawGuest{c: gc, lw: lw, sealer: sandboxrelay.NewSealer(k.GuestToHost, 0), host: host}
}

func (g *rawGuest) send(t *testing.T, typ byte, stream uint32, payload []byte) []byte {
	t.Helper()
	f := g.sealer.Seal(nil, typ, stream, payload)
	if _, err := g.lw.Write(f); err != nil {
		t.Logf("write: %v", err)
	}
	return f
}

func (g *rawGuest) hostErr(t *testing.T) error {
	t.Helper()
	select {
	case err := <-g.host:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the host did not close the channel")
		return nil
	}
}

// TestMuxHostileGuest is acceptance case A5 over the new transport: each
// hostile frame closes the channel; none crashes the host side or reaches a
// socket.
func TestMuxHostileGuest(t *testing.T) {
	cases := []struct {
		name string
		do   func(t *testing.T, g *rawGuest)
		want error
	}{
		{"wrongly keyed", nil, sandboxrelay.ErrMAC},
		{"replayed", func(t *testing.T, g *rawGuest) {
			f := g.send(t, sandboxrelay.TypePing, 0, nil)
			_, _ = g.lw.Write(f)
		}, sandboxrelay.ErrSeq},
		{"unrequested stream", func(t *testing.T, g *rawGuest) {
			g.send(t, sandboxrelay.TypeData, 99, []byte("x"))
		}, sandboxrelay.ErrStream},
		{"guest opens a stream", func(t *testing.T, g *rawGuest) {
			g.send(t, sandboxrelay.TypeOpen, 40, nil)
		}, sandboxrelay.ErrDirection},
		{"bad control", func(t *testing.T, g *rawGuest) {
			msg := []byte(`{"op":"hello","extra":1}`)
			_ = sandboxrelay.AppendMessageFrames(msg, limits.MaxPayload, func(c []byte) error {
				g.send(t, sandboxrelay.TypeData, StreamControl, c)
				return nil
			})
		}, ErrProtocol},
		{"oversized line", func(t *testing.T, g *rawGuest) {
			_, _ = g.c.Write(append(bytes.Repeat([]byte("A"), maxLine+10), '\n'))
		}, ErrLineTooLong},
		{"not base64", func(t *testing.T, g *rawGuest) {
			_, _ = g.c.Write([]byte("!!!!\n"))
		}, ErrBadLine},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			secret := testSecret
			if c.do == nil {
				secret = bytes.Repeat([]byte{9}, 32)
			}
			g := newRawGuest(t, secret)
			defer g.c.Close()
			if c.do == nil {
				g.send(t, sandboxrelay.TypePing, 0, nil)
			} else {
				c.do(t, g)
			}
			if err := g.hostErr(t); !errors.Is(err, c.want) {
				t.Fatalf("host ended with %v, want %v", err, c.want)
			}
		})
	}
}

func TestMuxWindowOverrunCloses(t *testing.T) {
	g := newRawGuestDial(t, testSecret, stuckDial)
	defer g.c.Close()
	// Ask for a stream through the control stream, then wait for the host's
	// answer by sending past the window on the stream id the host will use.
	msg := []byte(`{"op":"connect","id":1,"kind":"relay"}`)
	_ = sandboxrelay.AppendMessageFrames(msg, limits.MaxPayload, func(c []byte) error {
		g.send(t, sandboxrelay.TypeData, StreamControl, c)
		return nil
	})
	time.Sleep(200 * time.Millisecond)
	chunk := bytes.Repeat([]byte("x"), int(limits.MaxPayload))
	for sent := 0; sent <= Window; sent += len(chunk) {
		g.send(t, sandboxrelay.TypeData, firstDynamic, chunk)
	}
	if err := g.hostErr(t); !errors.Is(err, ErrProtocol) {
		t.Fatalf("host ended with %v, want a window violation", err)
	}
}

func TestDeadlineConn(t *testing.T) {
	a, b := net.Pipe()
	c := NewDeadlineConn(a, a, a.Close)
	_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, ErrTimeout) {
		t.Fatalf("read: %v", err)
	}
	go func() { _, _ = b.Write([]byte("hello")) }()
	_ = c.SetReadDeadline(time.Time{})
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("read %q %v", buf, err)
	}
	_ = c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := c.Write([]byte("nobody reads")); !errors.Is(err, ErrTimeout) {
		t.Fatalf("write: %v", err)
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, ErrBroken) {
		t.Fatalf("write after a timeout: %v", err)
	}
	_ = c.Close()
	_ = b.Close()
}

func TestLineCodec(t *testing.T) {
	var buf bytes.Buffer
	w := NewLineWriter(&buf)
	data := bytes.Repeat([]byte{0, 1, 2, 255, '\n'}, MaxLineChunk/2)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if strings.Count(buf.String(), "\n") < 2 {
		t.Error("a large write was not split into lines")
	}
	got, err := io.ReadAll(NewLineReader(&buf))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("round trip %v", err)
	}
}

// TestMuxReadyAck (live run 2026-10-23, finding F2): the home side learns
// that the guest acted on the hello (wrote the box record, listens on its
// sockets) only from the guest's own ready, never from the hello alone.
func TestMuxReadyAck(t *testing.T) {
	h, g := startPair(t, map[string]bool{KindRelay: true}, nil)
	select {
	case <-h.Ready():
		t.Fatal("ready before the guest said so")
	case <-time.After(100 * time.Millisecond):
	}
	if err := g.Ready(); err != nil {
		t.Fatal(err)
	}
	if err := g.Ready(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("the guest's ready never reached the home side")
	}
	if h.Err() != nil {
		t.Errorf("a repeated ready ended the session: %v", h.Err())
	}
}

// TestMuxHelloCarriesEnvAndGateway (the Apple container row's tunnel): the
// launch environment rides in the authenticated hello and the gateway is a
// kind the home side may offer and the guest may ask for.
func TestMuxHelloCarriesEnvAndGateway(t *testing.T) {
	hc, gc := net.Pipe()
	ch := make(chan *Host, 1)
	go func() {
		h, err := ServeHost(context.Background(), stack(hc), HostOptions{
			Options: Options{RunID: "run-1", Secret: testSecret}, Rand: rand.Reader,
			Kinds: map[string]bool{KindRelay: true, KindGateway: true}, Dial: echoDial,
			Env: []string{"HOME=/Users/dev", "ANTHROPIC_API_KEY=k"},
		})
		if err != nil {
			t.Error(err)
		}
		ch <- h
	}()
	g, err := DialGuest(context.Background(), stack(gc), Options{RunID: "run-1", Secret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	h := <-ch
	t.Cleanup(func() { h.Close(); g.Close() })
	hello := g.Hello()
	if strings.Join(hello.Env, ",") != "HOME=/Users/dev,ANTHROPIC_API_KEY=k" || strings.Join(hello.Kinds, ",") != "relay,gateway" {
		t.Fatalf("hello %+v", hello)
	}
	c, err := g.Connect(context.Background(), KindGateway)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "ping" {
		t.Fatalf("gateway stream %q %v", b, err)
	}
	if _, err := g.Connect(context.Background(), KindProxy); !errors.Is(err, ErrRefused) {
		t.Fatalf("an unoffered proxy: %v", err)
	}
}
