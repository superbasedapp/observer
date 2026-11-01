//go:build !sbo_omit_adapter_dimcode

package defaults

import (
	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/dimcode"
)

// adapter.dimcode (package internal/adapter/dimcode). A build with any tag in the
// constraint above leaves the package out of the binary, and
// adapter_dimcode_omit.go reports the component compiled out (L1).
func init() {
	register(51, func() adapter.Adapter { return dimcode.New() })
}
