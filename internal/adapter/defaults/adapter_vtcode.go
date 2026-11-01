//go:build !sbo_omit_adapter_vtcode

package defaults

import (
	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/vtcode"
)

// adapter.vtcode (package internal/adapter/vtcode). A build with any tag in the
// constraint above leaves the package out of the binary, and
// adapter_vtcode_omit.go reports the component compiled out (L1).
func init() {
	register(55, func() adapter.Adapter { return vtcode.New() })
}
