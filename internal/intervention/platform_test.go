package intervention

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
)

// TestProcessControlSupportedOn pins one row per OS the node ships on.
func TestProcessControlSupportedOn(t *testing.T) {
	for goos, want := range map[string]bool{
		"linux": true, "windows": false, "darwin": false, "freebsd": false, "": false,
	} {
		if got := ProcessControlSupportedOn(goos); got != want {
			t.Errorf("ProcessControlSupportedOn(%q) = %v, want %v", goos, got, want)
		}
	}
}

// TestProcessControlTableMatchesThisBuild proves the table and the build-tag
// split agree on the host the test runs on: an unsupported OS is exactly one
// whose Inspect reports ErrUnsupported.
func TestProcessControlTableMatchesThisBuild(t *testing.T) {
	_, err := Inspect(context.Background(), os.Getpid())
	if unsupported := errors.Is(err, ErrUnsupported); unsupported == ProcessControlSupportedOn(runtime.GOOS) {
		t.Fatalf("on %s: Inspect err = %v, but the table says supported=%v", runtime.GOOS, err, ProcessControlSupportedOn(runtime.GOOS))
	}
}
