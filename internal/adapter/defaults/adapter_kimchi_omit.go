//go:build sbo_omit_adapter_kimchi

package defaults

import "github.com/marmutapp/superbased-observer/internal/components"

// This build leaves internal/adapter/kimchi out: the binary reports
// adapter.kimchi compiled out (L1), so every gate resolves it as not in this build.
func init() {
	components.MarkOmitted("adapter.kimchi")
}
