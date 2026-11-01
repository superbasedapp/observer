//go:build sbo_omit_adapter_stakpak

package defaults

import "github.com/marmutapp/superbased-observer/internal/components"

// This build leaves internal/adapter/stakpak out: the binary reports
// adapter.stakpak compiled out (L1), so every gate resolves it as not in this build.
func init() {
	components.MarkOmitted("adapter.stakpak")
}
