//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// TestSandboxImportChecksTheImageSize (R-038): the content importer parses
// a staged sandbox.image descriptor under the node's rules, so a declared
// size_bytes past the cap is refused before anything is installed, while a
// declared size within it and an undeclared one import.
func TestSandboxImportChecksTheImageSize(t *testing.T) {
	_, _, d := installTestImage(t)
	stage := func(t *testing.T, size any) []sandboxImportStaged {
		t.Helper()
		b, err := d.Encode()
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if size == nil {
			delete(m, "size_bytes")
		} else {
			m["size_bytes"] = size
		}
		b, _ = json.Marshal(m)
		p := filepath.Join(t.TempDir(), sandboximage.DescriptorName)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return []sandboxImportStaged{{kind: content.SandboxImage, files: map[string]string{sandboximage.DescriptorName: p}}}
	}
	if err := sandboxImportImageGate(stage(t, int64(85_100_000))); err != nil {
		t.Fatalf("a declared size within the cap was refused: %v", err)
	}
	if err := sandboxImportImageGate(stage(t, nil)); err != nil {
		t.Fatalf("an undeclared size was refused: %v", err)
	}
	err := sandboxImportImageGate(stage(t, int64(sandboximage.MaxSizeBytes)+1))
	if err == nil || !strings.Contains(err.Error(), sandboximage.VerdictArtifactUnverified) || !strings.Contains(err.Error(), "size") {
		t.Fatalf("a size past the cap imported: %v", err)
	}
	if err := sandboxImportImageGate(stage(t, -1)); err == nil {
		t.Fatal("a negative size imported")
	}
}
