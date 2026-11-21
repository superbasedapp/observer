package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/dblease"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// storeExecutionStamper adapts the one writer of sessions.execution_location
// / sessions.vendor_session_ref (Store.SetSessionExecution, agent migration
// 240, lane CA-A1) to the Rail S planner's cloudsession.ExecutionStamper
// interface (lane CA-A3). It is the only place the two shapes meet (CA-B4).
type storeExecutionStamper struct{ st *store.Store }

// SetSessionExecution stamps one session. A vendor reference the wire
// grammar (orgcontract.ValidVendorSessionRef) refuses is dropped and the
// location is still stamped: cloudsession's marker check is looser than the
// store's, and an odd variable value must neither fail the flush nor lose
// the location.
func (s storeExecutionStamper) SetSessionExecution(ctx context.Context, sessionID, location, vendorRef string) (bool, error) {
	if vendorRef != "" && !orgcontract.ValidVendorSessionRef(vendorRef) {
		vendorRef = ""
	}
	return s.st.SetSessionExecution(ctx, models.SessionExecution{
		SessionID:         sessionID,
		ExecutionLocation: location,
		VendorSessionRef:  vendorRef,
	})
}

// executionStamperFor returns the Rail S flush's stamper over st, nil for a
// nil store (the flush then reports "pending" and stamps nothing).
func executionStamperFor(st *store.Store) cloudsession.ExecutionStamper {
	if st == nil {
		return nil
	}
	return storeExecutionStamper{st: st}
}

// hookCloudExecution resolves the cloud-execution stamp a hook process can
// prove from its own environment (cloud-agents lane CA-B4): the agent's
// cloud-marker table (cloudsession.Detect, the same rows the Rail S flush
// walks, so there is one marker table per agent, not a second copy here)
// says where the session ran, and the agent's declared reference variable
// (CLAUDE_CODE_REMOTE_SESSION_ID for claude-code, the `cse_...` id) is its
// cross-rail reference. Grounded live 2026-10-31 (lane CA-A2): the variables
// are inherited by every hook process, and CLAUDE_CODE_SESSION_ID equals the
// hook stdin session_id the row is keyed on.
//
// Returns nil off the cloud (no marker matched, which is every developer
// machine), for an unknown agent id, and for an empty session id, so the
// caller can hand the result straight to store.IngestOptions.
// SessionExecutions. A reference the wire grammar refuses is dropped and the
// location still stamped.
func hookCloudExecution(agentID, sessionID string, env cloudsession.LookupEnv) []models.SessionExecution {
	if sessionID == "" || env == nil {
		return nil
	}
	agent, err := cloudsession.AgentByID(agentID)
	if err != nil {
		return nil
	}
	det := cloudsession.Detect(agent, env)
	if !det.InCloud || !models.KnownExecutionLocation(string(det.Location)) {
		return nil
	}
	ref := det.VendorRef
	if ref != "" && !orgcontract.ValidVendorSessionRef(ref) {
		ref = ""
	}
	return []models.SessionExecution{{
		SessionID:         sessionID,
		ExecutionLocation: string(det.Location),
		VendorSessionRef:  ref,
	}}
}

// hookEnvLookup reads the hook's environment through the hook context seam
// (hookctx: the hook process's own environment on the host path, the
// frame's declared fields on the daemon relay path), as a
// cloudsession.LookupEnv. An empty value counts as unset.
func hookEnvLookup(ctx context.Context) cloudsession.LookupEnv {
	hc := hookContext(ctx)
	return func(name string) (string, bool) {
		v := hc.Getenv(name)
		return v, v != ""
	}
}

// cloudSessionLock takes the one-flush-at-a-time lease in stateDir. A lease
// error is fail-open (the flush proceeds), the dblease convention.
func cloudSessionLock(stateDir string) (release func(), acquired bool, err error) {
	return dblease.TryAcquire(stateDir, "cloud-session-flush")
}
