//go:build sbo_omit_security

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policystate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_scanning_wire_omit.go: a build without the security module has no
// security.scanning compiler (family_securityscanning.go is omitted too), so
// every body of the family is refused at decode with ErrFamilyNotLinked and
// nothing here ever holds a floor.

func bindSecurityScanning(string, componentstate.Snapshot) {}

// projectFamilyStatusFrom reports nothing: no family section is read here.
func projectFamilyStatusFrom(*guard.Guard, func() time.Time) func() ([]orgcontract.ProjectFamilySectionState, bool) {
	return nil
}

func securityScanningPublish(orgclient.PolicyResourceResult, *slog.Logger) {}

func securityScanningClear() {}

// securityCommitGateFloorHeld: no floor is ever held without the module.
func securityCommitGateFloorHeld() bool { return false }

// newSecurityScanningPointReader reports the node-security point as off
// (none/no_policy), with the latest fetch outcome (a NACK names why).
func newSecurityScanningPointReader(lastFetch func() orgclient.PolicyResourceFetchOutcome, now func() time.Time) policystate.PointReader {
	return func(context.Context) (policystate.PointFacts, error) {
		o := orgclient.PolicyResourceFetchOutcome{}
		if lastFetch != nil {
			o = lastFetch()
		}
		reject := wirePolicyResourceRejectReason(o.RejectCode)
		return policystate.PointFacts{
			LastSeen: now(), EnforceMode: "off",
			LatestFetchRejected: reject != "", RejectCode: reject, RejectedVersion: o.Version, Unreachable: o.Unreachable,
		}, nil
	}
}

func securityOrgStatusLines(context.Context, string, config.Config, *store.Store) []string {
	return []string{"Code security: not in this build (no org floors, no managed pull)"}
}
