//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package templatecache

import (
	"os"
	"sync/atomic"
	"testing"
)

// TestSharedDirectoryOthersMayWriteIsRefused: a template directory others
// may write could carry a planted template, so it is never trusted.
func TestSharedDirectoryOthersMayWriteIsRefused(t *testing.T) {
	dir := withDir(t)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := privateDir(dir); err == nil {
		t.Fatal("a world-writable template directory was accepted")
	}
	spec := SQLite("org", lineage(map[string]string{"001_a.sql": "x"}))
	var calls atomic.Int32
	for i := 0; i < 2; i++ {
		if _, err := Image(spec, fakeDB(&calls, 'a')); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("builds = %d, want 2 private builds", calls.Load())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("files written into the refused directory: %d", len(entries))
	}
}
