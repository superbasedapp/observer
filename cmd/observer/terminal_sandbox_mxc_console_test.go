//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
)

// TestMXCConsoleRoute (RERUN2 D1): one case per row of the console route
// table. A CLI launch on a console window runs on the launcher's own
// pseudo console (before, the box got a console with no window and the
// screen stayed blank); a dashboard terminal keeps the daemon's; a
// redirected stdout keeps its handles; a console nobody hosted is named.
func TestMXCConsoleRoute(t *testing.T) {
	for _, c := range []struct {
		name string
		f    mxcConsoleFacts
		want mxcConsoleRoute
	}{
		{"a dashboard terminal", mxcConsoleFacts{DaemonChild: true, StdoutConsole: true}, mxcConsoleDaemonPTY},
		{"a script", mxcConsoleFacts{StdoutConsole: false, Hosted: true}, mxcConsoleRedirected},
		{"a CLI launch on a console window", mxcConsoleFacts{StdoutConsole: true, Hosted: true}, mxcConsoleHostPTY},
		{"a console nobody hosted", mxcConsoleFacts{StdoutConsole: true}, mxcConsoleClassic},
	} {
		if got := mxcConsoleRouteFor(c.f); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if !sandboxDriverRegs[sandboxbackend.BackendMXCProcess].cliConsoleHost {
		t.Fatal("the mxc-process driver must ask for the launcher's pseudo console on a CLI launch")
	}
	env := map[string]string{mxcConsoleEnv: string(mxcConsoleHostPTY)}
	if got := boxConsoleNote(func(k string) string { return env[k] }, "hidden"); got != "; console: host pseudo console, console window hidden" {
		t.Fatalf("boxConsoleNote = %q", got)
	}
	if got := boxConsoleNote(func(string) string { return "" }, "none"); got != "; console: not named by the helper, console window none" {
		t.Fatalf("boxConsoleNote without a route = %q", got)
	}
}
