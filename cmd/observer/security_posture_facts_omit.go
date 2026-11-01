//go:build !sbo_omit_security && sbo_omit_security_deps

package main

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
)

// securityPostureDaemonFacts reports neither daemon fact in a build without
// the dependency checks: the row's Reported list leaves them out, so the
// org reads them as not reported, never as zero.
func securityPostureDaemonFacts(*orgcontract.SecurityPostureRow, securityscanning.NodeFacts, string, time.Time) {
}
