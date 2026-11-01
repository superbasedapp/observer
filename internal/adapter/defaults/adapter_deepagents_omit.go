//go:build sbo_omit_adapter_deepagents_code

package defaults

import "github.com/marmutapp/superbased-observer/internal/components"

// This build leaves internal/adapter/deepagents out: the binary reports
// adapter.deepagents-code compiled out (L1), so every gate resolves it as not in this build.
func init() {
	components.MarkOmitted("adapter.deepagents-code")
}
