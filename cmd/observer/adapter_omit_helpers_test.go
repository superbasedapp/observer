package main

import (
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// adapterCompiledOut reports whether this test binary was built with tool's
// adapter left out (an sbo_omit_adapter_* tag; lane MP-L1D, T-598).
func adapterCompiledOut(tool string) bool {
	id := components.AdapterID(strings.TrimSuffix(tool, "-windows"))
	for _, o := range components.Omitted() {
		if o == id {
			return true
		}
	}
	return false
}

// requireAdapter skips a test that exercises tool's adapter (its hook
// receiver, parser or backfill pass) in a build that compiled it out. The
// omit-tag CI job (scripts/omit-tag-check.sh) runs this package's tests
// under the edition tag sets, which compile adapters out, and vets them
// under every single adapter tag (since 2026-11-01 a single tag gets vet
// only); there the adapter's own behaviour is absent by design, and what
// the build does instead is pinned by the omit tests.
func requireAdapter(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if adapterCompiledOut(tool) {
			t.Skipf("adapter.%s is compiled out of this build", tool)
		}
	}
}

// requireFullAdapterSet skips a golden that pins the full product's adapter
// set when any adapter is compiled out.
func requireFullAdapterSet(t *testing.T) {
	t.Helper()
	for _, o := range components.Omitted() {
		if strings.HasPrefix(o, "adapter.") {
			t.Skipf("this golden pins the full adapter set; %s is compiled out of this build", o)
		}
	}
}

// cursorReceiverForTest is the cursor hook receiver for a (sub)test that
// drives it, skipping that test in a build without adapter.cursor.
func cursorReceiverForTest(t *testing.T) func(context.Context, string, string) {
	t.Helper()
	requireAdapter(t, "cursor")
	return hookReceivers["cursor"]
}
