package e2b

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// TestExecStderrSink (lane SBX-UPD, finding H1): a non-PTY process's
// stderr reaches ExecSpec.Stderr and never its stdout; without a sink it is
// discarded as before.
func TestExecStderrSink(t *testing.T) {
	f := newFakeE2B(t)
	c := f.client(t)
	ctx := context.Background()
	info, err := c.Create(ctx, sandboxremote.BoxSpec{RunID: "r", TimeoutSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	for _, withSink := range []bool{true, false} {
		var errOut bytes.Buffer
		spec := sandboxremote.ExecSpec{Argv: []string{"warn"}}
		if withSink {
			spec.Stderr = &errOut
		}
		p, err := c.Exec(ctx, info.ID, spec)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(p)
		_, _ = p.Wait(ctx)
		_ = p.Close()
		if len(out) != 0 {
			t.Fatalf("stdout carried %q", out)
		}
		if withSink && errOut.String() != "relay: refused\n" {
			t.Fatalf("stderr = %q", errOut.String())
		}
	}
}
