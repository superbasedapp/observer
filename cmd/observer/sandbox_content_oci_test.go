//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// TestSandboxContentStoreIsTheOCIStore: the fetch fills the store the
// container driver reads.
func TestSandboxContentStoreIsTheOCIStore(t *testing.T) {
	if sandboxContentDir != sandboxImageContentDir {
		t.Fatalf("the fetch writes %q, the driver reads %q", sandboxContentDir, sandboxImageContentDir)
	}
	if sandboxContentStore("/x").Root != ociImageStore("/x").Root {
		t.Fatal("the two stores differ")
	}
}

// TestOCIResolveAsksForTheDefaultImageOnlyWhenNeeded: the hook asks for a
// fetch only when no image is configured.
func TestOCIResolveAsksForTheDefaultImageOnlyWhenNeeded(t *testing.T) {
	var asked []content.Kind
	prev := sandboxContentEnsureFn
	sandboxContentEnsureFn = func(k content.Kind, _ string) { asked = append(asked, k) }
	t.Cleanup(func() { sandboxContentEnsureFn = prev })
	dir := t.TempDir()
	_ = ociResolveImageFn(config.TerminalSandboxOCIConfig{Image: "docker.io/library/debian@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}, dir)
	if len(asked) != 0 {
		t.Fatalf("a configured image asked for the default: %v", asked)
	}
	_ = ociResolveImageFn(config.TerminalSandboxOCIConfig{}, dir)
	if len(asked) != 1 || asked[0] != content.SandboxImage {
		t.Fatalf("asked: %v", asked)
	}
}
