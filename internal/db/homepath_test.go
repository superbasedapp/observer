package db

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestOpenRefusesAnUnexpandedHome (R-183): a database path that still
// starts with "~" is refused by name and no folder named "~" is created in
// the working directory, on every OS and for both separators.
func TestOpenRefusesAnUnexpandedHome(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, p := range []string{"~/.observer/observer.db", `~\.observer\observer.db`, "~"} {
		if _, err := Open(context.Background(), Options{Path: p}); !errors.Is(err, ErrUnexpandedHome) {
			t.Fatalf("Open(%q): %v, want ErrUnexpandedHome", p, err)
		}
	}
	if _, err := os.Stat("~"); !os.IsNotExist(err) {
		t.Fatalf("a folder named ~ exists in the working directory: %v", err)
	}
	// An ordinary name that merely starts with "~" is not a home spelling.
	for _, p := range []string{"~foo/x.db", filepath.Join("dir", "~", "x.db")} {
		if unexpandedHomePath(p) {
			t.Fatalf("%q read as an unexpanded home", p)
		}
	}
}
