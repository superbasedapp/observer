package invariant

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOTLPServiceVersionIsNotAToolVersionSource pins the T-784 ruling
// (D-629) that OTLP resource `service.version` is NOT wired generically
// into sessions.tool_version: gemini-cli reports the Node.js runtime
// version there, not its own build, so a generic mapping would stamp a
// runtime version as the tool's. No node-side OTLP ingest package may
// emit a SessionToolVersion or call the tool-version store seam. A
// per-vendor mapping that is grounded to carry the tool's own build would
// be added deliberately, with this test amended to name that file.
func TestOTLPServiceVersionIsNotAToolVersionSource(t *testing.T) {
	roots := []string{
		"../../internal/ingest/otlp",
		"../../internal/otlpvendor",
		"../../internal/obs",
	}
	forbidden := []string{"SessionToolVersion", "SetSessionToolVersion"}
	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, f := range forbidden {
				if strings.Contains(string(body), f) {
					t.Errorf("%s references %s: OTLP service.version must not feed sessions.tool_version (gemini-cli reports the Node runtime there)", path, f)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}
