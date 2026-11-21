package openshellorg

import (
	"context"
	"sync"
	"testing"
	"time"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
)

// recSender records the frames a process sends.
type recSender struct {
	mu     sync.Mutex
	frames []*pb.ExecSandboxInput
	closed bool
}

func (r *recSender) Send(m *pb.ExecSandboxInput) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frames = append(r.frames, m)
	return nil
}

func (r *recSender) CloseSend() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func (r *recSender) heartbeats() (n int, other int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.frames {
		if s, ok := f.GetPayload().(*pb.ExecSandboxInput_Stdin); ok && len(s.Stdin) == 0 {
			n++
		} else {
			other++
		}
	}
	return n, other
}

// TestHeartbeatKeepsAnIdleStdinSideAlive (FX4 item 1, F-P6-3): an
// interactive stream that sends nothing gets a zero-byte stdin frame at
// least once per period; a stream that writes stdin often gets none; the
// heartbeat stops at the half-close and at the stream's end.
func TestHeartbeatKeepsAnIdleStdinSideAlive(t *testing.T) {
	const every = 40 * time.Millisecond
	t.Run("idle", func(t *testing.T) {
		rs := &recSender{}
		p := newProcess(func() {}, nil, nil)
		p.send, p.lastSend = rs, time.Now()
		go p.heartbeat(context.Background(), every)
		time.Sleep(10 * every)
		n, _ := rs.heartbeats()
		if n < 5 {
			t.Fatalf("%d heartbeats in ten periods, want at least one a period", n)
		}
		_ = p.CloseWrite()
		time.Sleep(3 * every)
		after, _ := rs.heartbeats()
		if after > n+1 {
			t.Fatalf("heartbeats went on after the half-close: %d then %d", n, after)
		}
		close(p.done)
	})
	t.Run("busy", func(t *testing.T) {
		rs := &recSender{}
		p := newProcess(func() {}, nil, nil)
		p.send, p.lastSend = rs, time.Now()
		go p.heartbeat(context.Background(), every)
		for range 20 {
			if _, err := p.Write([]byte("k")); err != nil {
				t.Fatal(err)
			}
			time.Sleep(every / 4)
		}
		close(p.done)
		if n, other := rs.heartbeats(); n != 0 || other != 20 {
			t.Fatalf("a busy stream got %d heartbeats (%d frames)", n, other)
		}
	})
	t.Run("off", func(t *testing.T) {
		c := &Client{opts: Options{Heartbeat: -1}}
		if c.heartbeat() > 0 {
			t.Fatal("a negative Heartbeat still beats")
		}
		if (&Client{}).heartbeat() != 20*time.Second {
			t.Fatal("the default period is not osorg.StreamHeartbeat")
		}
	})
	// FX4-A5: a Kill without a Close (the pump blocked on a stream that
	// never ends, the stdin side never closed) still stops the heartbeat:
	// it selects on the stream's context, which the Kill cancels.
	t.Run("kill without close", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		rs := &recSender{}
		p := newProcess(cancel, nil, nil)
		p.send, p.lastSend = rs, time.Now()
		exited := make(chan struct{})
		go func() {
			p.heartbeat(ctx, every)
			close(exited)
		}()
		time.Sleep(2 * every)
		if err := p.Kill(context.Background()); err != nil {
			t.Fatal(err)
		}
		select {
		case <-exited:
		case <-time.After(20 * every):
			t.Fatal("the heartbeat goroutine outlived a Kill without a Close")
		}
		close(p.done)
	})
}

// TestEmptyStdoutIsSkipped: an empty stdout chunk never blocks the pump.
func TestEmptyStdoutIsSkipped(t *testing.T) {
	p := newProcess(func() {}, nil, nil)
	evs := []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{}}},
		{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 0}}},
	}
	i := 0
	done := make(chan struct{})
	go func() {
		p.pump(func() (*pb.ExecSandboxEvent, error) { e := evs[i]; i++; return e, nil })
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("an empty stdout chunk blocked the pump")
	}
}
