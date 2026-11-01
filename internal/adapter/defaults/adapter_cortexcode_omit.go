//go:build sbo_omit_adapter_cortex_code

package defaults

import "github.com/marmutapp/superbased-observer/internal/components"

// This build leaves internal/adapter/cortexcode out: the binary reports
// adapter.cortex-code compiled out (L1), so every gate resolves it as not in this build.
func init() {
	components.MarkOmitted("adapter.cortex-code")
}
