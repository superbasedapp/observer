package orgcontract

import (
	"slices"
	"strings"
)

// SandboxPostureRow is one row of the sandbox posture aggregate (sandbox
// plan v2 section 8.4, phase P1a): COUNTS of the node's terminal runs per
// UTC day by the closed isolation and capture enums. It is the shape that
// lets an org see capture compliance on an individual node that has not
// opted into full content: the per-run evidence rides only on
// TerminalRunRow under shipsRawContent(), and this aggregate ships under the
// terminal_detail tier.
//
// Every field is a closed enum from internal/sandboxvocab or a count. It
// never carries a run id, a session id, a hostname, a path, a project, a
// tool or a tool version (pinned by tests/invariant/privacy_test.go). Empty
// enums mean "not recorded" (a run from before the columns existed).
// Optional both directions: an old agent omits it, an old server ignores
// the unknown key.
type SandboxPostureRow struct {
	// OrgID / UserEmail are the agent-stamped attribution.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD) the runs launched.
	Day string `json:"day"`
	// The bucket: the class actually built, the computed capture level, where
	// capture was recorded, the host's verification of the backend, what
	// Observer did with the agent's own sandbox and where the model
	// credential sat.
	IsolationClass     string `json:"isolation_class"`
	CaptureLevel       string `json:"capture_level"`
	CaptureOrigin      string `json:"capture_origin"`
	Verification       string `json:"verification"`
	NativeSandboxState string `json:"native_sandbox_state"`
	KeyCustody         string `json:"key_custody"`
	// Runs is how many terminal runs fell into the bucket.
	Runs int64 `json:"runs"`
}

// SandboxCapabilityRow is the node's sandbox capability: which floors this
// node can meet right now (sandbox plan v2 section 8.4). Enums and booleans
// only, envelope-level like BudgetPosture (one push comes from one node).
// It ships with the posture aggregate under terminal_detail, and only while
// the Sandboxes and VMs module is active on the node; a node where the
// module is inactive sends nothing. An install with no [components] block
// resolves the module active, so it does send this row; the row is
// therefore enums and booleans only (pinned by tests/invariant/privacy_test.go,
// clamped at org ingest), never anything about a run.
type SandboxCapabilityRow struct {
	// OrgID / UserEmail are the agent-stamped attribution; the server
	// overwrites both with the authenticated pusher's.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Backends are the registry ids of the backends available on this host
	// now (closed ids, for example "bwrap").
	Backends []string `json:"backends,omitempty"`
	// MaxClass is the strongest isolation class an available backend builds
	// ("" when none is available).
	MaxClass string `json:"max_class,omitempty"`
	// FullCapture is true when an available backend computes full capture
	// on the configured network tier.
	FullCapture bool `json:"full_capture,omitempty"`
	// Beta is true when every available backend is beta on this host (not
	// live-verified, or a version outside its tested range).
	Beta bool `json:"beta,omitempty"`
	// ManagedRefused are the sandbox managed pull's body keys this node did
	// not apply, each with its closed reason (SBX-P2E, P1c audit: the
	// per-node path refusals the developer page shows). A key is a body key
	// (SandboxManagedKeys), a reason a SandboxNodeRefusalReasons entry;
	// never a path or a value. Empty when no managed body is in force or
	// every key applied. An old server ignores it; ingest clamps it.
	ManagedRefused []SandboxManagedRefusedKeyRow `json:"managed_refused,omitempty"`
}

// SandboxManagedRefusedKeyRow is one body key a node refused, by name.
type SandboxManagedRefusedKeyRow struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

// SandboxManagedKeys are the managed body's keys, by their wire name (the
// [terminal.sandbox] key without its prefix), the closed set a refusal row
// may name.
var SandboxManagedKeys = []string{
	"enabled", "backends", "default_on", "egress", "egress_allow_cidrs", "allow_tool_config_writes",
	"allow_remote_clone", "remote_allowed_hosts", "workspace_retention_days", "mask_paths",
	"prep_timeout_seconds", "extra_ro_binds", "extra_rw_binds",
	// The org-published E2B endpoint (lane SBX-UPD).
	"hosted.e2b.endpoint",
	// The container sandboxes' install-script floor (lane LEFT-SBX, P-136).
	"oci.install_scripts",
	// The org's sign-in seeding forbid (lane BOXSIGNIN), lowering only.
	"sign_in_seed_tools",
}

// SandboxNodeRefusalReasons are the closed reasons a node refuses a body key
// for when it composes the body (cmd/observer/sandbox_managed.go keeps its
// constants equal to these; a test pins it).
var SandboxNodeRefusalReasons = []string{
	"pinned_by_org", "not_absolute", "bad_character", "dot_dot_segment", "leading_dash",
	"whole_root_rw", "exposes_observer_dir", "cidr_not_allowable", string(SandboxRefusedSensitivePath),
	"would_disable_pinned_enabled",
}

// maxSandboxManagedRefused bounds the refusal list (one per key at most).
const maxSandboxManagedRefused = 16

// ClampSandboxManagedRefused keeps the rows whose key and reason are in
// their closed sets, once per key, in order: what the org stores never
// carries anything else, whatever a node sends.
func ClampSandboxManagedRefused(rows []SandboxManagedRefusedKeyRow) []SandboxManagedRefusedKeyRow {
	var out []SandboxManagedRefusedKeyRow
	seen := map[string]bool{}
	for _, r := range rows {
		if len(out) == maxSandboxManagedRefused {
			break
		}
		if seen[r.Key] || !slices.Contains(SandboxManagedKeys, r.Key) || !slices.Contains(SandboxNodeRefusalReasons, r.Reason) {
			continue
		}
		seen[r.Key] = true
		out = append(out, r)
	}
	return out
}

// EncodeSandboxManagedRefused renders clamped rows as the server column's
// "key:reason,..." text ("" for none).
func EncodeSandboxManagedRefused(rows []SandboxManagedRefusedKeyRow) string {
	var parts []string
	for _, r := range ClampSandboxManagedRefused(rows) {
		parts = append(parts, r.Key+":"+r.Reason)
	}
	return strings.Join(parts, ",")
}

// DecodeSandboxManagedRefused reads the server column back, dropping any
// entry outside the closed sets.
func DecodeSandboxManagedRefused(col string) []SandboxManagedRefusedKeyRow {
	if col == "" {
		return nil
	}
	var rows []SandboxManagedRefusedKeyRow
	for e := range strings.SplitSeq(col, ",") {
		k, r, ok := strings.Cut(e, ":")
		if ok {
			rows = append(rows, SandboxManagedRefusedKeyRow{Key: k, Reason: r})
		}
	}
	return ClampSandboxManagedRefused(rows)
}
