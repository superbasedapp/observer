package depscan

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDumpCanaryFiles writes the canary project to SBO_DUMP_CANARY (a live
// check helper; skipped otherwise).
func TestDumpCanaryFiles(t *testing.T) {
	dir := os.Getenv("SBO_DUMP_CANARY")
	if dir == "" {
		t.Skip("SBO_DUMP_CANARY not set")
	}
	for name, body := range CanaryFiles() {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
