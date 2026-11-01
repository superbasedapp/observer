//go:build !sbo_omit_adapter_dirac

package defaults

import (
	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/dirac"
)

// adapter.dirac (package internal/adapter/dirac). A build with any tag in the
// constraint above leaves the package out of the binary, and
// adapter_dirac_omit.go reports the component compiled out (L1).
func init() {
	register(52, func() adapter.Adapter { return dirac.New() })
}
