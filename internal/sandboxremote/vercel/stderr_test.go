package vercel

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// lockedBuffer is a goroutine-safe stderr sink.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestExecStderrSink (lane SBX-UPD, finding H1): with ExecSpec.Stderr set
// the command's stderr reaches it, once even when the log stream drops and
// replays from the start; without it stderr is discarded as before.
func TestExecStderrSink(t *testing.T) {
	f := newFakeVercel(t)
	f.dropLogsAt = 1
	c := f.client(t)
	ctx := context.Background()
	info, _ := c.Create(ctx, sandboxremote.BoxSpec{RunID: "r", TimeoutSeconds: 60})
	var errOut lockedBuffer
	p, err := c.Exec(ctx, info.ID, sandboxremote.ExecSpec{Argv: []string{"cat"}, Stdin: true, Stderr: &errOut})
	if err != nil {
		t.Fatal(err)
	}
	pr := p.(*process)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		for {
			if _, err := p.Read(buf); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 3; i++ {
		_, _ = p.Write([]byte("x\n"))
	}
	if err := pr.pump.close(); err != nil {
		t.Fatal(err)
	}
	<-done
	_ = p.Close()
	if got := errOut.String(); got != "noise" {
		t.Fatalf("stderr = %q, want %q exactly once", got, "noise")
	}
}
