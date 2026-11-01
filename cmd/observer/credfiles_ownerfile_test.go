package main

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
)

// mustOwnerOnlyFile fails unless path is readable by this user only (0600
// on POSIX; on Windows a protected DACL granting this user and SYSTEM only).
func mustOwnerOnlyFile(t *testing.T, path string) {
	t.Helper()
	ok, err := fsatomic.IsOwnerOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("%s is not owner-only", filepath.Base(path))
	}
}

// TestBrowserTokenFileIsOwnerOnly (R-160): the browser ingest token (and
// the OTLP token, through the same resolveLocalTokenFile) is created
// owner-only, never with the profile directory's inherited ACL on Windows.
func TestBrowserTokenFileIsOwnerOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "browser-ingest-token")
	if tok, err := resolveLocalTokenFile(p); err != nil || tok == "" {
		t.Fatalf("resolveLocalTokenFile: %q, %v", tok, err)
	}
	mustOwnerOnlyFile(t, p)
}
