//go:build windows && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"

	"github.com/marmutapp/superbased-observer/internal/conpty"
	"github.com/marmutapp/superbased-observer/internal/termsession"
)

// sandboxCLIConsoleFactsHere reads the facts of this launcher process.
func sandboxCLIConsoleFactsHere(driverHosts bool) sandboxCLIConsoleFacts {
	var mode uint32
	return sandboxCLIConsoleFacts{
		DriverHosts:   driverHosts,
		DaemonChild:   os.Getenv(envDaemonChild) != "",
		StdoutConsole: windows.GetConsoleMode(windows.Handle(os.Stdout.Fd()), &mode) == nil,
		PseudoConsole: conpty.Available(),
	}
}

// hostConsoleResizePoll is how often the real console's size is read.
const hostConsoleResizePoll = 250 * time.Millisecond

// hostConsoleQuiet is how long the copy waits without output, after the
// child has exited, before it closes the pseudo console; hostConsoleDrain
// bounds that wait.
const (
	hostConsoleQuiet = 300 * time.Millisecond
	hostConsoleDrain = 5 * time.Second
)

// consoleSize is the visible size of the console behind out (80 x 24 when
// it cannot be read).
func consoleSize(out windows.Handle) (cols, rows uint16) {
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(out, &info); err != nil {
		return 80, 24
	}
	return uint16(info.Window.Right-info.Window.Left) + 1, uint16(info.Window.Bottom-info.Window.Top) + 1 //nolint:gosec // G115: a console size
}

// runSandboxCLIOnHostConsole runs argv (env, dir) on a pseudo console of
// this launcher's own, made by the dashboard's spawner, with the real
// console's output in VT mode and its input raw: the pseudo console's
// output is copied to the console, keystrokes (Ctrl+C included, which the
// pseudo console raises in the child) are copied back, and a resize of the
// console is forwarded. A signal on sigs (the console window closed, a
// stop) ends the child's tree. With stripOSC52 the copy removes OSC 52
// clipboard sequences (ruling P-175: the box must not write the user's
// clipboard through Windows Terminal). It returns the child's exit code.
func runSandboxCLIOnHostConsole(argv, env []string, dir string, sigs <-chan os.Signal, stripOSC52 bool) (int, error) {
	out := windows.Handle(os.Stdout.Fd())
	in := windows.Handle(os.Stdin.Fd())
	cols, rows := consoleSize(out)
	pty, err := termsession.NewOSSpawner().Spawn(termsession.Spec{
		Kind: termsession.SpecSetup, SetupArgv: argv, Env: env, Dir: dir, Cols: cols, Rows: rows,
	})
	if err != nil {
		return 0, fmt.Errorf("the launch's pseudo console: %w", err)
	}
	var restore []func()
	defer func() {
		for i := len(restore) - 1; i >= 0; i-- {
			restore[i]()
		}
	}()
	var om uint32
	if windows.GetConsoleMode(out, &om) == nil {
		// The pseudo console speaks VT and ends its own lines.
		if windows.SetConsoleMode(out, om|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.DISABLE_NEWLINE_AUTO_RETURN) == nil {
			restore = append(restore, func() { _ = windows.SetConsoleMode(out, om) })
		}
	}
	var im uint32
	if windows.GetConsoleMode(in, &im) == nil {
		raw := (im | windows.ENABLE_VIRTUAL_TERMINAL_INPUT) &^ (windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT | windows.ENABLE_PROCESSED_INPUT)
		if windows.SetConsoleMode(in, raw) == nil {
			restore = append(restore, func() { _ = windows.SetConsoleMode(in, im) })
		}
		go func() { _, _ = io.Copy(pty, os.Stdin) }()
	}
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		_ = copyConsoleOutput(os.Stdout, pty, stripOSC52, func() { last.Store(time.Now().UnixNano()) })
	}()
	stop := make(chan struct{})
	var stopOnce sync.Once
	defer stopOnce.Do(func() { close(stop) })
	go func() {
		t := time.NewTicker(hostConsoleResizePoll)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-sigs:
				_ = pty.Kill()
			case <-t.C:
				if nc, nr := consoleSize(out); nc != cols || nr != rows {
					cols, rows = nc, nr
					_ = pty.Resize(rows, cols)
				}
			}
		}
	}()
	code, werr := pty.Wait()
	// The child's last output reaches the console before any closing line:
	// copy until the pseudo console has been quiet a moment, then close it.
	deadline := time.Now().Add(hostConsoleDrain)
	for time.Now().Before(deadline) && time.Since(time.Unix(0, last.Load())) < hostConsoleQuiet {
		select {
		case <-outDone:
			deadline = time.Now()
		case <-time.After(50 * time.Millisecond):
		}
	}
	_ = pty.Close()
	select {
	case <-outDone:
	case <-time.After(hostConsoleDrain):
	}
	if werr != nil {
		return 0, werr
	}
	return code, nil
}
