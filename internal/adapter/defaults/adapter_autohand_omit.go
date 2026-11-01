//go:build sbo_omit_adapter_autohand

package defaults

import "github.com/marmutapp/superbased-observer/internal/components"

// This build leaves internal/adapter/autohand out: the binary reports
// adapter.autohand compiled out (L1), so every gate resolves it as not in this build.
func init() {
	components.MarkOmitted("adapter.autohand")
}
