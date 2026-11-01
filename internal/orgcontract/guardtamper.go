package orgcontract

import (
	"fmt"
	"time"
)

// GuardTamperWindow is how long a repaired guard-file tamper stays on the
// node's policy-state report (and so keeps the fleet finding open) after the
// daemon repaired it (T-864, re-test gap 4).
const GuardTamperWindow = 24 * time.Hour

// Guard tamper kinds: the closed vocabulary of GuardTamperReport.LastKind.
// They are the degraded_from values the node's daemon stamps on the high
// guard_error event it records when it repairs an org-held guard file, so
// the node-local event and the org report name a tamper the same way.
const (
	// GuardTamperOrgBundle: the cached org policy bundle was edited, replaced
	// or deleted outside the daemon.
	GuardTamperOrgBundle = "org_bundle_tamper"
	// GuardTamperGovernance: the governance sidecar (or its exceptions file)
	// was edited or removed outside the daemon.
	GuardTamperGovernance = "governance_tamper"
	// GuardTamperOrgLock: the daemon's MAC'd org lock was edited or removed.
	GuardTamperOrgLock = "org_lock_tamper"
	// GuardTamperPosture: the daemon's MAC'd guard posture (or its key) was
	// edited or removed.
	GuardTamperPosture = "posture_tamper"
)

// guardTamperLabels names each kind for a finding reason (no path, no
// value: the kind is the whole observation).
var guardTamperLabels = map[string]string{
	GuardTamperOrgBundle:  "org guard policy bundle",
	GuardTamperGovernance: "org governance settings file",
	GuardTamperOrgLock:    "org guard lock",
	GuardTamperPosture:    "guard posture",
}

// GuardTamperKinds returns the closed vocabulary in a stable order.
func GuardTamperKinds() []string {
	return []string{GuardTamperOrgBundle, GuardTamperGovernance, GuardTamperOrgLock, GuardTamperPosture}
}

// GuardTamperKindKnown reports whether k is in the closed vocabulary.
func GuardTamperKindKnown(k string) bool { _, ok := guardTamperLabels[k]; return ok }

// GuardTamperReport is what a node reports about the org-held guard files its
// daemon repaired recently (PolicyStateRow.GuardTamper, gen4). A count, a
// timestamp and a closed kind only: no path, no file content, no detail
// string a developer could have influenced.
type GuardTamperReport struct {
	// Repairs is how many tamper events the daemon recorded and repaired in
	// the last GuardTamperWindow (bounded server-side).
	Repairs int `json:"repairs"`
	// LastAt is the newest repair, RFC3339 UTC. Each new value is a new
	// event: the server re-opens the finding on it.
	LastAt string `json:"last_at"`
	// LastKind is the newest repair's kind (GuardTamper*).
	LastKind string `json:"last_kind"`
}

// Valid reports whether r is well formed: a known kind, a parseable time and
// a count in range. A nil report is valid (nothing to report).
func (r *GuardTamperReport) Valid() bool {
	if r == nil {
		return true
	}
	if r.Repairs < 1 || r.Repairs > 100000 || !GuardTamperKindKnown(r.LastKind) {
		return false
	}
	_, err := time.Parse(time.RFC3339, r.LastAt)
	return err == nil
}

// Event renders the newest repair as one line: the kind's label and the raw
// repair time. The org fleet finding does NOT use it (a machine timestamp in
// a sentence a person reads): it names the file with Label and carries the
// time as a structured field (fleethealth.Finding.ObservedAt).
func (r *GuardTamperReport) Event() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%s changed outside the daemon and repaired at %s", r.Label(), r.LastAt)
}

// Label names the newest repair's file for a sentence a person reads (no
// path, no value, no time): the closed kind's label, or "org-held guard
// file" for a kind this build does not know. "" for a nil report.
func (r *GuardTamperReport) Label() string {
	if r == nil {
		return ""
	}
	if label := guardTamperLabels[r.LastKind]; label != "" {
		return label
	}
	return "org-held guard file"
}

// Live reports whether the newest repair is still inside GuardTamperWindow
// at now.
func (r *GuardTamperReport) Live(now time.Time) bool {
	if r == nil {
		return false
	}
	t, err := time.Parse(time.RFC3339, r.LastAt)
	if err != nil {
		return false
	}
	return now.Sub(t) <= GuardTamperWindow
}
