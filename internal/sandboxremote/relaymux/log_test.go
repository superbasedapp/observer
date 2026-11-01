package relaymux

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// logPair starts a pair whose home side logs to the returned collector, with
// dial answering every relay connect with an error.
func logPair(t *testing.T, withLog bool) (*Guest, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var lines []string
	hc, gc := net.Pipe()
	opts := HostOptions{
		Options: Options{RunID: "run-1", Secret: testSecret}, Rand: rand.Reader,
		Kinds: map[string]bool{KindRelay: true},
		Dial: func(context.Context, string) (io.ReadWriteCloser, error) {
			return nil, errors.New("dial unix relay.sock: connect: no such file")
		},
	}
	if withLog {
		opts.Log = func(l string) { mu.Lock(); lines = append(lines, l); mu.Unlock() }
	}
	ch := make(chan *Host, 1)
	go func() {
		h, err := ServeHost(context.Background(), stack(hc), opts)
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
	return g, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), lines...) }
}

// TestMuxRelayLog (lane SBX-UPD, finding H1): with a home log the hello
// offers it, a refused kind and a failed home dial are each logged with
// why, and the guest's own lines arrive (control characters cleaned, the
// length bounded); without one the guest's Log sends nothing.
func TestMuxRelayLog(t *testing.T) {
	g, lines := logPair(t, true)
	if !g.Hello().Log {
		t.Fatal("the hello did not offer the log")
	}
	if _, err := g.Connect(context.Background(), KindProxy); !errors.Is(err, ErrRefused) {
		t.Fatalf("proxy: %v", err)
	}
	if _, err := g.Connect(context.Background(), KindRelay); !errors.Is(err, ErrRefused) {
		t.Fatalf("relay with a failing dial: %v", err)
	}
	g.Log("closed a relay connection\x1b[31m: " + strings.Repeat("x", 2*MaxLogLine))
	deadline := time.Now().Add(2 * time.Second)
	for len(lines()) < 4 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	all := strings.Join(lines(), "\n")
	for _, want := range []string{"refused a proxy connection", "no such file", "refused a relay connection", "guest: closed a relay connection"} {
		if !strings.Contains(all, want) {
			t.Fatalf("log lacks %q:\n%s", want, all)
		}
	}
	for _, l := range lines() {
		if strings.ContainsRune(l, 0x1b) || len(l) > MaxLogLine+len("guest: ") {
			t.Fatalf("an unclean or unbounded line: %q", l)
		}
	}

	g2, _ := logPair(t, false)
	if g2.Hello().Log {
		t.Fatal("a home side without a log offered one")
	}
	g2.Log("nothing") // must not fail the session
	if _, err := g2.Connect(context.Background(), KindRelay); !errors.Is(err, ErrRefused) {
		t.Fatalf("the session failed after a Log with no home log: %v", err)
	}
}
