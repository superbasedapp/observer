//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secshellrisk"
)

// The language-install rules (S-754 in a Dockerfile, S-781 in a workflow)
// read installs through the security.deps component's parser; a build
// without that component leaves secshellrisk.LangInstalls nil and reports
// neither rule.
func init() { secshellrisk.LangInstalls = secfeed.UnpinnedInstallEcosystem }
