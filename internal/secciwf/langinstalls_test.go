package secciwf

import (
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secshellrisk"
)

// The binary registers the security.deps component's install parser
// (cmd/observer security_shellrisk.go); the tests do the same.
func init() { secshellrisk.LangInstalls = secfeed.UnpinnedInstallEcosystem }
