//go:build !sbo_omit_adapter_autohand

package defaults

import (
	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/autohand"
)

// adapter.autohand (package internal/adapter/autohand). A build with any tag in the
// constraint above leaves the package out of the binary, and
// adapter_autohand_omit.go reports the component compiled out (L1).
func init() {
	register(46, func() adapter.Adapter { return autohand.New() })
}
