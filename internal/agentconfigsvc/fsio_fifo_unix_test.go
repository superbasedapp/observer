//go:build unix

package agentconfigsvc

import (
	"syscall"
	"testing"
)

// makeFIFO creates a named pipe at path.
func makeFIFO(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
}
