package models

import "strings"

// Execution-location vocabulary (cloud-agents arc, decision CA-D1): the
// normalized answer to "where did this session's agent run?". It is a
// dimension of its own, NOT a new Surface kind: Surface stays "where the
// human interacts" (cli, ide, desktop, sdk, web), and one Claude Code cloud
// session can be driven from the web, the desktop app or the CLI, so folding
// "cloud" into Surface would lose that.
//
// The set is closed (KnownExecutionLocation). A capture path resolves its
// vendor's own marker (a `bc-` id, CLAUDE_CODE_REMOTE, a self-hosted worker
// label, ...) into one of these at its boundary through a table, so nothing
// downstream switches on a tool name to infer where a session ran. An empty
// value is the honest "unknown" (sessions.execution_location NULL), never a
// defaulted ExecutionLocal.
const (
	// ExecutionLocal is a session whose agent ran on the developer's own
	// machine (the node itself, or a machine the node captures directly).
	ExecutionLocal = "local"
	// ExecutionVendorCloud is a session whose agent ran in compute the
	// vendor operates (Claude Code on the web, Codex Cloud, the Copilot
	// cloud agent, Cursor Cloud Agents, Devin, OpenHands Cloud, ...).
	ExecutionVendorCloud = "vendor_cloud"
	// ExecutionCustomerWorker is a session whose agent ran on compute the
	// customer operates on the vendor's behalf (Claude Code self-hosted
	// environments, Copilot self-hosted runners, Devin Outposts, Warp
	// self-hosted workers).
	ExecutionCustomerWorker = "customer_worker"
)

// executionLocations is the closed vocabulary KnownExecutionLocation walks.
// One row per kind; adding a kind is a row here plus a constant above.
var executionLocations = []string{
	ExecutionLocal,
	ExecutionVendorCloud,
	ExecutionCustomerWorker,
}

// KnownExecutionLocation reports whether loc is one of the Execution*
// constants. The empty string is NOT known: "unknown" is a NULL column, not
// a vocabulary entry. The node store refuses an out-of-vocabulary write with
// it and the org ingest lands an out-of-vocabulary pushed value as NULL.
func KnownExecutionLocation(loc string) bool { return inVocab(loc, executionLocations) }

// ExecutionLocations returns the closed vocabulary in its declared order
// (a copy, so a caller cannot mutate the table). For pickers and tests.
func ExecutionLocations() []string { return copyVocab(executionLocations) }

// SessionExecution is the per-session cloud-execution attribution: where
// the session ran (CA-D1) and the vendor's second native reference used to
// join the same session across capture rails (CA-D2).
//
// Written through the single store seam Store.SetSessionExecution with
// FIRST-WINS-UNLESS-EMPTY semantics per column (the SetSessionSurface
// shape): the first grounded stamp sticks, a later stamp can only FILL a
// still-empty column, and an empty field never clears a stored one. Both
// columns ship on the org-push wire as metadata (orgcontract.SessionRow
// ExecutionLocation / VendorSessionRef).
type SessionExecution struct {
	// SessionID is the session the attribution belongs to (sessions.id).
	SessionID string
	// ExecutionLocation is one of the Execution* constants, or "" when this
	// stamp carries no location.
	ExecutionLocation string
	// VendorSessionRef is the vendor's second native session reference
	// (`cse_...`, the `ccr.session.id` value, a GitHub `agent_session_id`),
	// used for cross-rail joins. It is an opaque vendor-minted id, never
	// content and never developer-typed text; orgcontract.ValidVendorSessionRef
	// is its grammar. "" when this stamp carries no reference. The vendor's
	// PRIMARY native id is sessions.id itself (CA-D2), not this field.
	VendorSessionRef string
}

// CloudProjectRootPrefix is the prefix of a SYNTHETIC project root for a
// remote-only session (CA-D3): a session that ran in the vendor's cloud and
// left no local checkout resolves its project by normalized git remote,
// first to an existing local project with that remote, else to the root
// "cloud:<normalized-remote>" (the "[cursor]" placeholder precedent). The org
// project resolver's remote rule then folds it onto the developer's local
// project.
const CloudProjectRootPrefix = "cloud:"

// SyntheticCloudProjectRoot returns the synthetic project root for a
// normalized git remote ("github.com/org/repo" -> "cloud:github.com/org/repo").
// The caller normalizes first (internal/git.NormalizeRemote).
func SyntheticCloudProjectRoot(normalizedRemote string) string {
	return CloudProjectRootPrefix + normalizedRemote
}

// IsSyntheticCloudProjectRoot reports whether root is a synthetic cloud
// project root (SyntheticCloudProjectRoot's output).
func IsSyntheticCloudProjectRoot(root string) bool {
	return len(root) > len(CloudProjectRootPrefix) && strings.HasPrefix(root, CloudProjectRootPrefix)
}
