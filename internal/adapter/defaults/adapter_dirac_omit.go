//go:build sbo_omit_adapter_dirac

package defaults

import "github.com/marmutapp/superbased-observer/internal/components"

// This build leaves internal/adapter/dirac out: the binary reports
// adapter.dirac compiled out (L1), so every gate resolves it as not in this build.
func init() {
	components.MarkOmitted("adapter.dirac")
}
