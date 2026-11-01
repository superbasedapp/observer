//go:build !sbo_omit_security

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// securityOrgShareDash is dashapi.Options.SecurityOrgShare (security plan
// 7.12, lane SEC-E3): the share level this node pushes at (the same table
// the org wire uses, security_orgpush.go), whether an org security floor is
// in force, and whether the node is managed. localLevel is
// [org_client.share].security.
func securityOrgShareDash(localLevel string) dashapi.SecurityOrgShareFunc {
	return func(context.Context) (dashapi.SecurityOrgShare, bool) {
		base, ok := secScanning.baseNow()
		if !ok {
			return dashapi.SecurityOrgShare{}, false
		}
		facts := secScanning.facts()
		if facts.ModuleOff {
			// The security module is not active: no security row is
			// pushed and no floor applies, so nothing is shared.
			return dashapi.SecurityOrgShare{Level: "off", Managed: base.Managed}, true
		}
		share := securityShareFor(base.Managed, securityManagedCurrent().Policy, localLevel)
		return dashapi.SecurityOrgShare{Level: share.Level, FloorsInForce: facts.Held != nil, Managed: base.Managed}, true
	}
}
