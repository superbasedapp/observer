//go:build windows && !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// mxcConsoleFactsHere reads the route facts of this helper process.
func mxcConsoleFactsHere() mxcConsoleFacts {
	return mxcConsoleFacts{
		DaemonChild:   os.Getenv(envDaemonChild) != "",
		Hosted:        os.Getenv(sandboxConsoleHostedEnv) == "1",
		StdoutConsole: mxcIsConsole(os.Stdout),
	}
}

// mxcIsConsole reports whether f is a console handle.
func mxcIsConsole(f *os.File) bool {
	if f == nil {
		return false
	}
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}

// mxcStartHandles are the standard handles wxc-exec gets: the helper's own,
// on every route. On a pseudo console (the daemon's or the launcher's) they
// are that console's handles, which wxc-exec inherits and passes to the box,
// so the box's output reaches the terminal (RERUN2 D1); a file or a pipe
// (the kit's receipts) goes as it is.
func mxcStartHandles() (stdin, stdout, stderr *os.File) {
	return os.Stdin, os.Stdout, os.Stderr
}
