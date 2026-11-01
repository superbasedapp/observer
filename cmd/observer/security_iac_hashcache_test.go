//go:build !sbo_omit_security

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestIaCProbeHashCacheByPathSizeMtime (audit finding F5): an unchanged
// binary is hashed once however often the loop probes it; a new size or
// modification time hashes again; a stat failure falls back to hashing.
func TestIaCProbeHashCacheByPathSizeMtime(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "trivy")
	if err := os.WriteFile(bin, []byte("v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	hashes := 0
	raw := func(string) (string, error) { hashes++; return "sum", nil }
	c := &iacHashCache{}
	h := c.hash(raw, os.Stat)
	for i := 0; i < 5; i++ {
		if s, err := h(bin); err != nil || s != "sum" {
			t.Fatal(s, err)
		}
	}
	if hashes != 1 {
		t.Fatalf("an unchanged binary was hashed %d times", hashes)
	}
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(bin, later, later); err != nil {
		t.Fatal(err)
	}
	_, _ = h(bin)
	if hashes != 2 {
		t.Fatalf("a new modification time did not rehash: %d", hashes)
	}
	if err := os.WriteFile(bin, []byte("v2-longer"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(bin, later, later); err != nil {
		t.Fatal(err)
	}
	_, _ = h(bin)
	if hashes != 3 {
		t.Fatalf("a new size did not rehash: %d", hashes)
	}
	failing := c.hash(raw, func(string) (os.FileInfo, error) { return nil, errors.New("no stat") })
	_, _ = failing(bin)
	_, _ = failing(bin)
	if hashes != 5 {
		t.Fatalf("a binary that cannot be stat'ed was served from the cache: %d", hashes)
	}
}
