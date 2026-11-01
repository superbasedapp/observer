package sandboxrelay

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// TestRekeyInUse (lane sbx-p2b): the host re-keys a connection once an
// epoch has carried RekeyAfter bytes from the guest; both directions keep
// verifying across the change, the guest follows the announcement, and the
// host never announces again before the guest caught up.
func TestRekeyInUse(t *testing.T) {
	p := testParams(PurposeBox)
	p.RekeyAfter = 64 << 10
	srv, cli, serr, cerr := pair(t, "run-1", "run-1", testSecret, p)
	if serr != nil || cerr != nil {
		t.Fatalf("handshake: %v %v", serr, cerr)
	}
	big := bytes.Repeat([]byte("r"), 1<<20) // sixteen frames
	done := make(chan error, 1)
	go func() { done <- cli.Send(StreamHook, big) }()
	got, err := srv.Recv(StreamHook, MaxMessage)
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("recv across a re-key: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if srv.Epoch() != 1 {
		t.Fatalf("host epoch %d after 1 MiB at a 64 KiB bound, want 1 (no second announcement before the guest caught up)", srv.Epoch())
	}
	go func() { done <- srv.Send(StreamHook, big) }()
	back, err := cli.Recv(StreamHook, MaxMessage)
	if err != nil || !bytes.Equal(back, big) {
		t.Fatalf("the answer under the new epoch: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if cli.Epoch() != 1 {
		t.Fatalf("guest epoch %d, want it to follow to 1", cli.Epoch())
	}
	// The guest's next message is sealed under epoch 1, and the host moves
	// on to epoch 2 once it has seen it.
	go func() { done <- cli.Send(StreamHook, big) }()
	if got, err := srv.Recv(StreamHook, MaxMessage); err != nil || !bytes.Equal(got, big) {
		t.Fatalf("a second message: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if srv.Epoch() != 2 {
		t.Fatalf("host epoch %d, want 2", srv.Epoch())
	}
	if err := cli.Rekey(); !errors.Is(err, ErrRekey) {
		t.Fatalf("a guest re-keyed: %v", err)
	}
}

// TestRekeyAnnouncementOutOfOrder: a host frame announcing any epoch but
// the next one closes the guest's side (hostile or broken host).
func TestRekeyAnnouncementOutOfOrder(t *testing.T) {
	for _, skip := range []uint32{0, 2, 7} {
		srv, cli, serr, cerr := pair(t, "run-1", "run-1", testSecret, testParams(PurposeBox))
		if serr != nil || cerr != nil {
			t.Fatalf("handshake: %v %v", serr, cerr)
		}
		var ann [4]byte
		binary.BigEndian.PutUint32(ann[:], cli.Epoch()+skip)
		k, err := DeriveKeys(testSecret, PurposeBox, "run-1", srv.nonce, 0)
		if err != nil {
			t.Fatal(err)
		}
		// Sealed under the host's real key (sequence 2: Open was 1).
		frame := SealRaw(nil, hmac.New(sha256.New, k.HostToGuest), TypeRekey, 0, 2, 0, ann[:])
		go func() { _, _ = srv.w.c.Write(frame) }()
		if _, err := cli.Recv(StreamHook, MaxMessage); !errors.Is(err, ErrRekey) {
			t.Fatalf("an announcement of epoch +%d: %v", skip, err)
		}
	}
}

// TestHeartbeatKeepsAWaitingClient: a client whose idle bound is shorter
// than the server's work stays connected while the server heartbeats, and
// times out when it does not.
func TestHeartbeatKeepsAWaitingClient(t *testing.T) {
	for _, beat := range []bool{true, false} {
		p := testParams(PurposeBox)
		p.Conn.IdleTimeout = 150 * time.Millisecond
		srv, cli, serr, cerr := pair(t, "run-1", "run-1", testSecret, p)
		if serr != nil || cerr != nil {
			t.Fatalf("handshake: %v %v", serr, cerr)
		}
		go func() {
			stop := func() {}
			if beat {
				stop = srv.Heartbeat(40 * time.Millisecond)
			}
			time.Sleep(450 * time.Millisecond) // the work, three idle bounds long
			stop()
			_ = srv.Send(StreamHook, []byte("done"))
		}()
		got, err := cli.Recv(StreamHook, MaxMessage)
		if beat && (err != nil || string(got) != "done") {
			t.Fatalf("with heartbeats: %q %v", got, err)
		}
		if !beat && err == nil {
			t.Fatal("without heartbeats the idle bound did not fire")
		}
	}
}
