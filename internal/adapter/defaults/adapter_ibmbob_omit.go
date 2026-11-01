//go:build sbo_omit_adapter_ibm_bob

package defaults

import "github.com/marmutapp/superbased-observer/internal/components"

// This build leaves internal/adapter/ibmbob out: the binary reports
// adapter.ibm-bob compiled out (L1), so every gate resolves it as not in this build.
func init() {
	components.MarkOmitted("adapter.ibm-bob")
}
