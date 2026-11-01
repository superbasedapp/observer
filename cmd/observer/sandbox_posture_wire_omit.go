//go:build sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

// sandbox_posture_wire_omit.go: a build without the sandbox module registers
// no pin posture evaluator (the [terminal.sandbox] pins keep their per-key
// directions only; nothing in this build can launch a sandbox), links no
// terminals.isolation compiler (every body of it NACKs not linked), so its
// install hooks are no-ops and its policy-state row is the honest "off".

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policystate"
)

func isolationFloorsPublish(orgclient.PolicyResourceResult) {}

func isolationFloorsClear() {}

func isolationFloorsAllowUnsandboxed() (bool, string) { return true, "" }

// sandboxCannotRunHere: this build has no sandbox module, so no terminal can
// be sandboxed here (a seam for tests, as in the module build).
var sandboxCannotRunHere = func() string { return "the Sandboxes and VMs module is not in this build" }

func newIsolationFloorsPointReader(lastFetch func() orgclient.PolicyResourceFetchOutcome, now func() time.Time) policystate.PointReader {
	return func(context.Context) (policystate.PointFacts, error) {
		f := policystate.PointFacts{EnforceMode: "off", LastSeen: now()}
		if lastFetch != nil {
			o := lastFetch()
			reject := wirePolicyResourceRejectReason(o.RejectCode)
			f.LatestFetchRejected = reject != ""
			f.RejectCode = reject
			f.RejectedVersion = o.Version
			f.Unreachable = o.Unreachable
		}
		return f, nil
	}
}
