//go:build !unix

package agentconfigsvc

import "testing"

// makeFIFO skips: Windows has no named pipe at a filesystem path (its pipes
// live under \\.\pipe\), so a settings path can never be a FIFO there.
func makeFIFO(t *testing.T, _ string) {
	t.Helper()
	t.Skip("no FIFO at a filesystem path on this OS: Windows named pipes live under \\\\.\\pipe\\")
}
