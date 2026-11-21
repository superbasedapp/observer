package openshellorg

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
)

// TestBoxOutputAfterTheHalfCloseNeverHoldsThePump (lane FX6, FX6-R1): a box
// that writes after the node's half-close, to a stdout nobody reads, held
// the pump in its pipe write: the exit was never read and the pump leaked.
// Close and Kill now close the reader, the pump drops the late output, and
// it reaches the exit (kept) and ends; no pump goroutine is left.
func TestBoxOutputAfterTheHalfCloseNeverHoldsThePump(t *testing.T) {
	for _, end := range []string{"close", "kill"} {
		t.Run(end, func(t *testing.T) {
			events := make(chan *pb.ExecSandboxEvent, 4)
			cut := make(chan struct{})
			recv := func() (*pb.ExecSandboxEvent, error) {
				select {
				case ev := <-events:
					return ev, nil
				case <-cut:
					return nil, context.Canceled
				}
			}
			p := newProcess(func() {}, nil, nil)
			p.send = &recSender{}
			go p.pump(recv)
			if err := p.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			// The box writes after the half-close, more than once, then exits.
			events <- &pb.ExecSandboxEvent{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("late,")}}}
			events <- &pb.ExecSandboxEvent{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("later")}}}
			events <- &pb.ExecSandboxEvent{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 7}}}
			time.Sleep(50 * time.Millisecond) // the pump is in its pipe write
			if end == "close" {
				_ = p.Close()
			} else {
				_ = p.Kill(context.Background())
			}
			select {
			case <-p.done:
			case <-time.After(2 * time.Second):
				close(cut)
				t.Fatal("the pump is still held by box output nobody reads")
			}
			if code, err := p.Wait(context.Background()); err != nil || code != 7 {
				t.Fatalf("exit %d %v, want the box's 7", code, err)
			}
			if _, err := p.Read(make([]byte, 8)); err == nil || errors.Is(err, io.EOF) {
				t.Fatalf("a read after the end: %v, want the closed reader", err)
			}
		})
	}
}
