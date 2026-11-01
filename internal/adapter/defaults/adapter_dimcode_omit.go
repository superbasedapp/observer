//go:build sbo_omit_adapter_dimcode

package defaults

import "github.com/marmutapp/superbased-observer/internal/components"

// This build leaves internal/adapter/dimcode out: the binary reports
// adapter.dimcode compiled out (L1), so every gate resolves it as not in this build.
func init() {
	components.MarkOmitted("adapter.dimcode")
}
