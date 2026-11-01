//go:build !sbo_omit_adapter_kimchi

package defaults

import (
	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/kimchi"
)

// adapter.kimchi (package internal/adapter/kimchi). A build with any tag in the
// constraint above leaves the package out of the binary, and
// adapter_kimchi_omit.go reports the component compiled out (L1).
func init() {
	register(53, func() adapter.Adapter { return kimchi.New() })
}
