//go:build !sbo_omit_adapter_ibm_bob

package defaults

import (
	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/ibmbob"
)

// adapter.ibm-bob (package internal/adapter/ibmbob). A build with any tag in the
// constraint above leaves the package out of the binary, and
// adapter_ibmbob_omit.go reports the component compiled out (L1).
func init() {
	register(47, func() adapter.Adapter { return ibmbob.New() })
}
