//go:build !sbo_omit_adapter_codebuddy

package defaults

import (
	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/codebuddy"
)

// adapter.codebuddy (package internal/adapter/codebuddy). A build with any tag in the
// constraint above leaves the package out of the binary, and
// adapter_codebuddy_omit.go reports the component compiled out (L1).
func init() {
	register(49, func() adapter.Adapter { return codebuddy.New() })
}
