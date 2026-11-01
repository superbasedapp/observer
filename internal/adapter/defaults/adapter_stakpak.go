//go:build !sbo_omit_adapter_stakpak

package defaults

import (
	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/stakpak"
)

// adapter.stakpak (package internal/adapter/stakpak). A build with any tag in the
// constraint above leaves the package out of the binary, and
// adapter_stakpak_omit.go reports the component compiled out (L1).
func init() {
	register(54, func() adapter.Adapter { return stakpak.New() })
}
