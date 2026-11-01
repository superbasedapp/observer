//go:build !sbo_omit_adapter_deepagents_code

package defaults

import (
	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/deepagents"
)

// adapter.deepagents-code (package internal/adapter/deepagents). A build with any tag in the
// constraint above leaves the package out of the binary, and
// adapter_deepagents_omit.go reports the component compiled out (L1).
func init() {
	register(50, func() adapter.Adapter { return deepagents.New() })
}
