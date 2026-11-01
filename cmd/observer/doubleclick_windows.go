//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/inconshreveable/mousetrap"

	"github.com/marmutapp/superbased-observer/internal/setup"
)

// doubleClickDispatch replaces cobra's "This is a command line tool" notice
// (shown for five seconds before the window closes) with something useful
// when observer.exe is started from Explorer with no arguments: start the
// daemon in the background if it is not running and open the dashboard.
// It reports ok=false for every other invocation, so the CLI is untouched.
func doubleClickDispatch(args []string) (int, bool) {
	if len(args) != 1 || !mousetrap.StartedByExplorer() {
		return 0, false
	}
	out := os.Stdout
	fmt.Fprintf(out, "SuperBased Observer %s\n\n", version)
	err := runSetupLaunch(setupLaunchOptions{open: true, wait: 60 * time.Second, out: out, sys: defaultSetupOS()})
	code := 0
	if err != nil {
		fmt.Fprintf(out, "\n%v\n", err)
		code = 1
	}
	fmt.Fprintf(out, "\nSuperBased keeps running in the background after this window closes.\n"+
		"To add it to your Path, start it at sign-in and get a Start menu entry, use the\n"+
		"Windows installer from %s. Everything else is in a terminal: observer --help\n", setup.DownloadURL)
	fmt.Fprint(out, "\nPress Enter to close this window (it closes by itself in 30 seconds).")
	done := make(chan struct{})
	go func() {
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}
	return code, true
}
