//go:build !sbo_omit_adapter_custom_agent

package defaults

import (
	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/customagent"
)

// adapter.custom-agent (package internal/adapter/customagent). A build with
// any tag in the constraint above leaves the package out of the binary, and
// adapter_customagent_omit.go reports the component compiled out (L1).
func init() {
	register(56, func() adapter.Adapter { return customagent.New() })
}
