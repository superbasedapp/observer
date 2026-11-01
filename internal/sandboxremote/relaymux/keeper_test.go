package relaymux

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// keeperPair starts a pair whose home side takes a keeper key (keep) and
// hands the guest attachKey.
func keeperPair(t *testing.T, keep bool, attachKey []byte) (*Guest, <-chan []byte) {
	t.Helper()
	got := make(chan []byte, 1)
	hc, gc := net.Pipe()
	opts := HostOptions{
		Options: Options{RunID: "run-1", Secret: testSecret}, Rand: rand.Reader,
		Kinds: map[string]bool{}, AttachKey: attachKey,
		Dial: func(context.Context, string) (io.ReadWriteCloser, error) { return nil, errors.New("none") },
	}
	if keep {
		opts.KeeperKey = func(k []byte) { got <- k }
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
	return g, got
}

// TestMuxKeeperKey (SBX-UPD audit finding 2): a home side that keeps a
// keeper key offers it in the hello and receives the key the guest sends,
// inside the authenticated channel; one that keeps none offers nothing and
// SendKeeperKey refuses; a short key is refused; the attach key a home side
// hands a guest arrives in its hello.
func TestMuxKeeperKey(t *testing.T) {
	g, got := keeperPair(t, true, nil)
	if !g.Hello().Keep || len(g.Hello().AttachKey) != 0 {
		t.Fatalf("hello = %+v", g.Hello())
	}
	key := bytes.Repeat([]byte{7}, 32)
	if err := g.SendKeeperKey(key); err != nil {
		t.Fatal(err)
	}
	select {
	case k := <-got:
		if !bytes.Equal(k, key) {
			t.Fatalf("home side kept %x", k)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the keeper key never arrived")
	}
	if err := g.SendKeeperKey(key[:8]); err == nil {
		t.Fatal("a short keeper key was sent")
	}

	g2, _ := keeperPair(t, false, bytes.Repeat([]byte{5}, 32))
	if g2.Hello().Keep {
		t.Fatal("a home side keeping no key offered the channel")
	}
	if err := g2.SendKeeperKey(key); !errors.Is(err, errNoKeeperChannel) {
		t.Fatalf("SendKeeperKey with no channel = %v", err)
	}
	if !bytes.Equal(g2.Hello().AttachKey, bytes.Repeat([]byte{5}, 32)) {
		t.Fatalf("attach key = %x", g2.Hello().AttachKey)
	}
}
