//go:build sbo_omit_adapter_custom_agent

package defaults

import "github.com/marmutapp/superbased-observer/internal/components"

// This build leaves internal/adapter/customagent out: the binary reports
// adapter.custom-agent compiled out (L1), so every gate resolves it as not in this build.
func init() {
	components.MarkOmitted("adapter.custom-agent")
}
