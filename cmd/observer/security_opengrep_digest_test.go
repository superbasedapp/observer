//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCodeDigestCacheRehashesOnlyWhenAKeyChanges: lane SEC-G2 audit
// finding 2. A repeated read reuses the digest; a change of size, of
// modification time or of file identity (a rename over the path) hashes
// again.
func TestCodeDigestCacheRehashesOnlyWhenAKeyChanges(t *testing.T) {
	c := &codeDigestCache{m: map[string]codeDigestEntry{}}
	dir := t.TempDir()
	path := filepath.Join(dir, "opengrep")
	if err := os.WriteFile(path, []byte("engine-v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	calls := 0
	h := codeCachedHash(c, func(p string) (string, error) {
		calls++
		s, _, err := hashRegularFile(p, 1<<20)
		return s, err
	})
	read := func(step string, want int) {
		t.Helper()
		if _, err := h(path); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		if calls != want {
			t.Fatalf("%s: %d hashes, want %d", step, calls, want)
		}
	}
	read("first read", 1)
	read("the loop, the card and the Scanners card again", 1)
	read("and again", 1)

	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	read("mtime changed", 2)
	read("unchanged since", 2)

	if err := os.WriteFile(path, []byte("engine-v1-longer"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	read("size changed", 3)

	// Same size and mtime, a new file renamed over the path: a new identity.
	next := filepath.Join(dir, "next")
	if err := os.WriteFile(next, []byte("engine-v2-longer"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(next, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
	read("file identity changed", 4)
	read("unchanged since", 4)
	sum, err := h(path)
	want, _, _ := hashRegularFile(path, 1<<20)
	if err != nil || sum != want {
		t.Fatalf("cached digest %q, want %q (%v)", sum, want, err)
	}

	// A file that cannot be keyed is never cached.
	if _, err := h(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing file hashed")
	}
}

// TestCodeInspectorReadsThroughTheDigestCache: the inspector's runner (the
// loop's presence check, the card and the Scanners GET) hashes through the
// cache.
func TestCodeInspectorReadsThroughTheDigestCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opengrep")
	if err := os.WriteFile(path, []byte("engine"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := codeInspectRunner()
	if _, err := r.Hash(path); err != nil {
		t.Fatal(err)
	}
	codeDigests.mu.Lock()
	_, cached := codeDigests.m[path]
	codeDigests.mu.Unlock()
	if !cached {
		t.Fatal("the inspector's hash did not go through the cache")
	}
}
