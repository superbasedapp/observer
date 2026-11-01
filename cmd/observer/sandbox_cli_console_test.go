//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "testing"

// TestSandboxCLIHostConsole (RERUN2 D1): one case per row. Only a driver
// that asks for it, on a console window, outside a daemon terminal, with a
// pseudo console available, runs its helper on the launcher's own pseudo
// console.
func TestSandboxCLIHostConsole(t *testing.T) {
	all := sandboxCLIConsoleFacts{DriverHosts: true, StdoutConsole: true, PseudoConsole: true}
	for _, c := range []struct {
		name string
		f    func(sandboxCLIConsoleFacts) sandboxCLIConsoleFacts
		want bool
	}{
		{"a driver that does not ask", func(f sandboxCLIConsoleFacts) sandboxCLIConsoleFacts { f.DriverHosts = false; return f }, false},
		{"a dashboard terminal", func(f sandboxCLIConsoleFacts) sandboxCLIConsoleFacts { f.DaemonChild = true; return f }, false},
		{"a script (stdout a file or a pipe)", func(f sandboxCLIConsoleFacts) sandboxCLIConsoleFacts { f.StdoutConsole = false; return f }, false},
		{"no pseudo console on this OS", func(f sandboxCLIConsoleFacts) sandboxCLIConsoleFacts { f.PseudoConsole = false; return f }, false},
		{"a CLI launch on a console window", func(f sandboxCLIConsoleFacts) sandboxCLIConsoleFacts { return f }, true},
	} {
		if got := sandboxCLIHostConsole(c.f(all)); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
