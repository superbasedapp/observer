//go:build !sbo_omit_adapter_cortex_code

package defaults

import (
	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/cortexcode"
)

// adapter.cortex-code (package internal/adapter/cortexcode). A build with any tag in the
// constraint above leaves the package out of the binary, and
// adapter_cortexcode_omit.go reports the component compiled out (L1).
func init() {
	register(48, func() adapter.Adapter { return cortexcode.New() })
}
