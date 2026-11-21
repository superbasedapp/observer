package cloudsession

import (
	"context"
	"fmt"
)

// ExecutionStamper records where a session ran (CA-D1) and the vendor's
// cross-rail reference (CA-D2) on the session row.
//
// TODO(CA-A1): lane CA-A1 adds sessions.execution_location /
// sessions.vendor_session_ref (agent migration 240) and the one writer
// Store.SetSessionExecution (first-wins-unless-empty, the SetSessionSurface
// shape). When it merges, make *store.Store satisfy this interface (or adapt
// it in cmd/observer/cloudsession_stamp.go) and the flush stamps every
// session it ships. Until then the command reports "stamp: pending CA-A1".
type ExecutionStamper interface {
	SetSessionExecution(ctx context.Context, sessionID, location, vendorRef string) (bool, error)
}

// Stamp is one session's execution stamp.
type Stamp struct {
	SessionID string
	Location  ExecutionLocation
	VendorRef string
}

// PlanStamps returns the stamps for the sessions a flush ships. Every session
// in the sandbox's database ran in the sandbox, so all of them take the
// detection's location; the vendor reference is the sandbox's one cloud
// session id (several agent session ids, e.g. after /clear, map onto it).
// Nothing is stamped outside the cloud.
func PlanStamps(det Detection, sessionIDs []string) []Stamp {
	if !det.InCloud || det.Location == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []Stamp
	for _, id := range sessionIDs {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, Stamp{SessionID: id, Location: det.Location, VendorRef: det.VendorRef})
	}
	return out
}

// ApplyStamps writes stamps through s. A nil stamper (CA-A1 not merged)
// applies nothing and is not an error. It returns how many rows changed.
func ApplyStamps(ctx context.Context, s ExecutionStamper, stamps []Stamp) (int, error) {
	if s == nil {
		return 0, nil
	}
	changed := 0
	for _, st := range stamps {
		ok, err := s.SetSessionExecution(ctx, st.SessionID, string(st.Location), st.VendorRef)
		if err != nil {
			return changed, fmt.Errorf("cloudsession.ApplyStamps: %s: %w", st.SessionID, err)
		}
		if ok {
			changed++
		}
	}
	return changed, nil
}
