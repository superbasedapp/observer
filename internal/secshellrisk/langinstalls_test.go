package secshellrisk

import "github.com/marmutapp/superbased-observer/internal/secfeed"

// The binary registers the security.deps component's install parser
// (cmd/observer security_shellrisk.go); the tests do the same.
func init() { LangInstalls = secfeed.UnpinnedInstallEcosystem }
