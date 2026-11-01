//go:build !sbo_omit_security && !sbo_omit_security_scan_custom

package main

import (
	"github.com/marmutapp/superbased-observer/internal/seccustom"
	"github.com/marmutapp/superbased-observer/internal/seccustomsvc"
)

// security_feedback_custom.go adds the custom scanners' own row to the
// feedback rule table (feedbackRuleTables, audit finding F5, lane
// sec-polish): built only with the security.scan.custom module. It names
// only Observer's own changed-scanner finding; a custom driver's results
// carry the driver as their pack ("custom:<id>"), which has no row, so the
// user's engine never names a rule in a feedback line.

func init() {
	feedbackRuleTables[seccustom.ComponentID] = func(id string) bool { return id == seccustomsvc.TrustRuleID }
}
