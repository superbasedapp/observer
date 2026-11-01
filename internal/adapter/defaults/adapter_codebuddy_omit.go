//go:build sbo_omit_adapter_codebuddy

package defaults

import "github.com/marmutapp/superbased-observer/internal/components"

// This build leaves internal/adapter/codebuddy out: the binary reports
// adapter.codebuddy compiled out (L1), so every gate resolves it as not in this build.
func init() {
	components.MarkOmitted("adapter.codebuddy")
}
