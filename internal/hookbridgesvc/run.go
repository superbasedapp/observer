package hookbridgesvc

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookbridge"
)

// MaxOutputBytes caps each captured stream (16 MiB). A hook reply is a few
// kilobytes; output past the cap cannot be replayed whole, which the
// decision table turns into the fail-closed block.
const MaxOutputBytes = 16 << 20

// Result is one bridged run: how it ended and what the hook wrote.
type Result struct {
	Run    hookbridge.Run
	Stdout []byte
	Stderr []byte
}

// Run starts exe (wsl.exe, hookbridge.WSLExe) with argv (hookbridge's
// Entry.Argv), stdin passed straight through, and waits for it. A start
// failure is Started=false; any exit is Started=true with the code
// (ExitCode -1 when the process ended without one). ctx carries the
// bridge's deadline (hookbridge.Deadline): when it fires the process is
// killed and the result is TimedOut, whatever code the kill left.
func Run(ctx context.Context, exe string, argv []string, stdin io.Reader) Result {
	cmd := exec.CommandContext(ctx, exe, argv...) //nolint:gosec // G204: the System32 wsl.exe with a closed-spelling argv (hookbridge.Entry.Validate)
	cmd.Stdin = stdin
	// A killed wsl.exe can leave a grandchild holding the pipes; stop
	// waiting for them shortly after the kill.
	cmd.WaitDelay = time.Second
	out, errb := &cappedBuffer{max: MaxOutputBytes}, &cappedBuffer{max: MaxOutputBytes}
	cmd.Stdout, cmd.Stderr = out, errb
	var res Result
	if err := cmd.Start(); err != nil {
		return res
	}
	res.Run.Started = true
	err := cmd.Wait()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		res.Run.ExitCode = 0
	case errors.As(err, &exitErr):
		res.Run.ExitCode = exitErr.ExitCode()
	default:
		res.Run.ExitCode = -1
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		res.Run.TimedOut = true
	}
	res.Run.OutputOverflow = out.overflow || errb.overflow
	res.Stdout, res.Stderr = out.buf, errb.buf
	return res
}

// cappedBuffer keeps the first max bytes written and notes an overflow.
type cappedBuffer struct {
	buf      []byte
	max      int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.max - len(b.buf); room < len(p) {
		b.overflow = true
		if room > 0 {
			b.buf = append(b.buf, p[:room]...)
		}
		return len(p), nil
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}
