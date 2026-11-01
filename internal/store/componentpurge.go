package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// componentpurge.go is the store seam of the component purge (modular
// packaging plan 3.2.1 and 6.3, lane MP-GATE): typed, hand-reviewed purge
// plans per component, persisted as immutable, expiring candidate sets
// (agent migration 158), executed one-shot in one short transaction that
// re-checks every candidate row and runs under db.WithRetentionDeletes so
// no org deletion tombstone is ever emitted (the purge is always
// local_only: rows already pushed follow the org's retention).
//
// A component without a reviewed plan here has its data kept and the purge
// refused with ErrNoPurgePlan: the catalog's DataOwnership is a declaration,
// never a delete generator.

// PurgeKind is a purge plan kind.
type PurgeKind string

// The two plan kinds.
const (
	PurgeInteractive PurgeKind = "interactive"
	PurgeScheduled   PurgeKind = "scheduled"
)

// PurgeState is a purge plan state.
type PurgeState string

// The closed PurgeState vocabulary (migration 158's CHECK).
const (
	PurgePreviewed    PurgeState = "previewed"
	PurgeGracePending PurgeState = "grace_pending"
	PurgeEligible     PurgeState = "eligible"
	PurgeConsumed     PurgeState = "consumed"
	PurgeExpired      PurgeState = "expired"
	PurgeCancelled    PurgeState = "cancelled"
)

// PurgeEvent drives a plan transition.
type PurgeEvent string

// The closed PurgeEvent vocabulary.
const (
	PurgeEventExecute      PurgeEvent = "execute"
	PurgeEventExpire       PurgeEvent = "expire"
	PurgeEventCancel       PurgeEvent = "cancel"
	PurgeEventGraceElapsed PurgeEvent = "grace_elapsed"
)

// purgeTransition is one row of the plan state machine.
type purgeTransition struct {
	kind  PurgeKind
	from  PurgeState
	event PurgeEvent
	to    PurgeState
}

// purgeTransitions is THE purge plan state machine (plan 3.2.1, fourth-pass
// M7), one table-driven transition set, one test row each.
var purgeTransitions = []purgeTransition{
	{PurgeInteractive, PurgePreviewed, PurgeEventExecute, PurgeConsumed},
	{PurgeInteractive, PurgePreviewed, PurgeEventExpire, PurgeExpired},
	{PurgeInteractive, PurgePreviewed, PurgeEventCancel, PurgeCancelled},
	{PurgeScheduled, PurgeGracePending, PurgeEventGraceElapsed, PurgeEligible},
	{PurgeScheduled, PurgeGracePending, PurgeEventCancel, PurgeCancelled},
	{PurgeScheduled, PurgeGracePending, PurgeEventExpire, PurgeExpired},
	{PurgeScheduled, PurgeEligible, PurgeEventExecute, PurgeConsumed},
	{PurgeScheduled, PurgeEligible, PurgeEventCancel, PurgeCancelled},
	{PurgeScheduled, PurgeEligible, PurgeEventExpire, PurgeExpired},
}

// NextPurgeState returns the state a plan of kind in state from moves to on
// event, and false when the transition is not allowed (every terminal
// state is final).
func NextPurgeState(kind PurgeKind, from PurgeState, event PurgeEvent) (PurgeState, bool) {
	for _, t := range purgeTransitions {
		if t.kind == kind && t.from == from && t.event == event {
			return t.to, true
		}
	}
	return "", false
}

// Purge plan lifetimes (plan 3.2.1).
const (
	// InteractivePurgeTTL is how long an interactive preview stays
	// executable.
	InteractivePurgeTTL = 15 * time.Minute
	// ScheduledPurgeGrace is the default grace period of a scheduled plan
	// (plan 6.3: a 7-day grace, visible on the node).
	ScheduledPurgeGrace = 7 * 24 * time.Hour
	// scheduledPurgeWindow is how long a scheduled plan stays executable
	// after its grace period ends.
	scheduledPurgeWindow = 24 * time.Hour
)

// Purge errors.
var (
	// ErrNoPurgePlan means the component has no reviewed purge plan: its
	// data is kept.
	ErrNoPurgePlan = errors.New("store: no reviewed purge plan for this component; its data is kept")
	// ErrPurgePlanNotFound means no plan has the id.
	ErrPurgePlanNotFound = errors.New("store: purge plan not found")
	// ErrPurgePlanNotExecutable means the plan is expired, consumed,
	// cancelled or still in its grace period.
	ErrPurgePlanNotExecutable = errors.New("store: purge plan is not executable")
)

// ComponentPurgeSpec asks for a new plan.
type ComponentPurgeSpec struct {
	Kind      PurgeKind
	Component string
	// CatalogVersion is components.CatalogVersion at preview time.
	CatalogVersion int
	// PolicyVersion is the signed node.components policy version a scheduled
	// plan was created under ("" for interactive).
	PolicyVersion string
	// Grace overrides ScheduledPurgeGrace for a scheduled plan (> 0).
	Grace time.Duration
	// Now overrides the clock (tests). Zero = time.Now.
	Now time.Time
}

// ComponentPurgePlan is one persisted plan.
type ComponentPurgePlan struct {
	ID             string         `json:"id"`
	Kind           PurgeKind      `json:"kind"`
	Component      string         `json:"component"`
	CatalogVersion int            `json:"catalog_version"`
	PolicyVersion  string         `json:"policy_version,omitempty"`
	State          PurgeState     `json:"state"`
	CreatedAt      time.Time      `json:"created_at"`
	GraceUntil     *time.Time     `json:"grace_until,omitempty"`
	ExpiresAt      time.Time      `json:"expires_at"`
	ConsumedAt     *time.Time     `json:"consumed_at,omitempty"`
	Counts         map[string]int `json:"counts"`
	Result         *PurgeResult   `json:"result,omitempty"`
}

// PurgeResult reports an executed plan.
type PurgeResult struct {
	// Deleted counts rows deleted per table.
	Deleted map[string]int `json:"deleted"`
	// Skipped counts candidate rows that no longer matched the selector (or
	// were gone) per table.
	Skipped map[string]int `json:"skipped"`
	// Nulled counts rows kept with their session link set to NULL per
	// table (the purgeNullLink decisions), or with the purged session's id
	// removed from a JSON id list (the purgeRemoveFromList decisions).
	Nulled map[string]int `json:"nulled,omitempty"`
	// KeptSessions counts candidate sessions kept because another source's
	// rows still reference them (the keep_if_other_source rule).
	KeptSessions int `json:"kept_sessions"`
}

// PurgeRecheck is the executor's revalidation of a scheduled plan inside
// its transaction: the currently effective signed policy still authorises
// the purge for this component and the component is still inert. A nil
// error allows the purge. Interactive plans pass nil (the caller already
// refused an active component).
type PurgeRecheck func(ctx context.Context, plan ComponentPurgePlan) error

// purgeCandidate is one candidate query of a typed plan: the table, its
// primary-key column, and the selector.
type purgeCandidate struct {
	table string
	pk    string
	// where is the selector over the table, with ? placeholders.
	where string
}

// purgeDef is one typed, hand-reviewed purge plan.
type purgeDef struct {
	candidates []purgeCandidate
	args       []any
	execute    func(ctx context.Context, tx *sql.Tx, cands map[string][]string, args []any, res *PurgeResult) error
	// estimate adds the preview's per-table estimate of the derived rows
	// that go with the candidates (nil = none).
	estimate func(ctx context.Context, tx *sql.Tx, args []any, counts map[string]int) error
}

// purgeDefFor returns the reviewed plan of a component. Every adapter row
// shares one plan shape, parameterised by its registry tool id: the rows
// it captured are selected by tool, never by a free SQL fragment.
func purgeDefFor(component string) (purgeDef, bool) {
	if tool, ok := strings.CutPrefix(component, "adapter."); ok && tool != "" {
		return adapterPurgeDef(tool), true
	}
	return purgeDef{}, false
}

// HasPurgePlan reports whether a component has a reviewed purge plan.
func HasPurgePlan(component string) bool {
	_, ok := purgeDefFor(component)
	return ok
}

// adapterPurgeDef is the reviewed plan for one adapter's captured rows:
// actions (with the dependency protocol of retention.deleteActionsOlder and
// migration 079), token_usage and compaction_events with tool = ?, then the
// adapter's sessions that no other source still references, each with the
// derived rows purgeSessionDecisions assigns to it (ledger MODPKG-10).
func adapterPurgeDef(tool string) purgeDef {
	return purgeDef{
		candidates: []purgeCandidate{
			{table: "actions", pk: "id", where: "tool = ?"},
			{table: "token_usage", pk: "id", where: "tool = ?"},
			{table: "compaction_events", pk: "id", where: "tool = ?"},
			{table: "sessions", pk: "id", where: "tool = ?"},
		},
		args:     []any{tool},
		execute:  executeAdapterPurge,
		estimate: estimateAdapterDerived,
	}
}

// purgeDecisionKind is what an adapter purge does with the rows of one
// session-keyed column (ledger MODPKG-10).
type purgeDecisionKind string

// The closed purgeDecisionKind vocabulary.
const (
	// purgeKeepSession: the rows are another source's capture of the same
	// session (or this adapter's rows, deleted by their own tool selector
	// first). Any surviving row keeps the session, so nothing loses the
	// session it points at.
	purgeKeepSession purgeDecisionKind = "keep_session"
	// purgeDeleteWithSession: the rows are derived from the session or
	// only mean something with it; they are deleted in the same savepoint
	// as the session row. In a session the purge keeps, rows whose
	// toolColumn names the purged tool are still deleted.
	purgeDeleteWithSession purgeDecisionKind = "delete_with_session"
	// purgeNullLink: the rows are their own record (spend, provider state,
	// another subsystem's capture); they stay, with the session link set
	// to NULL.
	purgeNullLink purgeDecisionKind = "null_link"
	// purgeKeepDangling: the rows are an audit or hash-chained record, an
	// operator-authored result or a deletion handle; the purge never
	// rewrites them and their readers tolerate a session that is gone.
	purgeKeepDangling purgeDecisionKind = "keep_dangling"
	// purgeOwnerReconciles: another single owner reconciles the rows when
	// the session or its rows go (CLAUDE.md rule 4: the purge never writes
	// them).
	purgeOwnerReconciles purgeDecisionKind = "owner_reconciles"
	// purgeRemoveFromList: the rows are their own record but carry session
	// ids inside a JSON array column (a list, not a key); the purged
	// session's id is removed from every list that holds it and the row
	// stays.
	purgeRemoveFromList purgeDecisionKind = "remove_from_list"
)

// purgeSessionDecision is the reviewed decision for one session-keyed
// column.
type purgeSessionDecision struct {
	table, column string
	kind          purgeDecisionKind
	// otherSource (purgeKeepSession) selects the rows that are NOT this
	// adapter's own, with the tool as its only ? argument ("" = every row
	// is another source's).
	otherSource string
	// toolColumn (purgeDeleteWithSession) names the column that tags a row
	// with the tool that wrote it ("" = untagged).
	toolColumn string
	// keptCascade (purgeDeleteWithSession with a toolColumn) runs before
	// the tool-tagged delete in a kept session, with (session, session,
	// tool) as arguments, for rows that hang off the deleted ones by a
	// key; keptCascadeTable names the table it deletes from and
	// keptCascadeCount is the preview's count of those rows, with %s the
	// kept-session set and the tool as its last argument.
	keptCascade      string
	keptCascadeTable string
	keptCascadeCount string
	reason           string
}

// purgeSessionDecisions is THE reviewed per-column decision table of the
// adapter purge (ledger MODPKG-10, T-678). Every column of the node schema
// whose name contains session_id or thread_id has exactly one row here:
// TestPurgeSessionDecisionsCoverTheSchema fails on a new one, so a new
// session-keyed table cannot ship without a recorded purge decision. A JSON
// list of session ids under another name (remove_from_list) is listed too,
// and that test pins each such column by name. The order is the statement
// order inside a session's savepoint.
var purgeSessionDecisions = []purgeSessionDecision{
	// Capture rows: this adapter's are deleted by the tool selector before
	// the session step; what is left is another source's.
	{table: "actions", column: "session_id", kind: purgeKeepSession, otherSource: "tool <> ?", reason: "this adapter's actions are candidates; another tool's actions keep the session"},
	{table: "token_usage", column: "session_id", kind: purgeKeepSession, otherSource: "tool <> ?", reason: "this adapter's token rows are candidates; another tool's keep the session"},
	{table: "compaction_events", column: "session_id", kind: purgeKeepSession, otherSource: "tool <> ?", reason: "this adapter's compaction events are candidates; another tool's keep the session"},
	{table: "failure_context", column: "session_id", kind: purgeKeepSession, otherSource: "action_id IN (SELECT id FROM actions WHERE tool <> ?)", reason: "deleted with its action (dependency protocol); one on another tool's action keeps the session"},
	{table: "api_turns", column: "session_id", kind: purgeKeepSession, reason: "proxy capture is another source: the session it points at is kept"},
	{table: "otel_content", column: "session_id", kind: purgeKeepSession, reason: "OTel content capture is another source: the session it points at is kept"},
	// Derived from the session's capture: they go with the session.
	{table: "task_transitions", column: "session_id", kind: purgeDeleteWithSession, reason: "derived from the session's todo snapshots"},
	{
		table: "task_items", column: "session_id", kind: purgeDeleteWithSession, toolColumn: "tool",
		keptCascade:      `DELETE FROM task_transitions WHERE session_id = ? AND key IN (SELECT key FROM task_items WHERE session_id = ? AND tool = ?)`,
		keptCascadeTable: "task_transitions",
		keptCascadeCount: `SELECT COUNT(*) FROM task_transitions tt WHERE tt.session_id IN (%s) AND tt.key IN (SELECT ti.key FROM task_items ti WHERE ti.session_id = tt.session_id AND ti.tool = ?)`,
		reason:           "derived todo items, including the todo content text",
	},
	{table: "file_changes", column: "session_id", kind: purgeDeleteWithSession, reason: "lines-of-code rows derived from the session's edits"},
	{table: "tool_account_observations", column: "session_id", kind: purgeDeleteWithSession, toolColumn: "tool", reason: "account identity observed in this adapter's capture"},
	{table: "session_skill_snapshots", column: "session_id", kind: purgeDeleteWithSession, toolColumn: "tool", reason: "skills observed in this adapter's capture"},
	{table: "claudecode_effort", column: "session_id", kind: purgeDeleteWithSession, reason: "effort level captured for the session's tool calls"},
	{table: "hook_activity", column: "session_id", kind: purgeDeleteWithSession, toolColumn: "tool", reason: "hook liveness counts of this adapter's hooks for the session; the unattributed bucket has no session and is never purged with one"},
	{table: "cache_events", column: "session_id", kind: purgeDeleteWithSession, reason: "cache observations derived from the session's turns"},
	{table: "cache_segments", column: "session_id", kind: purgeDeleteWithSession, reason: "cache segments derived from the session's turns"},
	{table: "cache_entries", column: "session_id", kind: purgeDeleteWithSession, reason: "cache state derived from the session's turns"},
	{table: "router_decisions", column: "session_id", kind: purgeDeleteWithSession, reason: "routing decisions; a session with proxy turns is kept by api_turns, so these go only with a session that has none"},
	{table: "retrieval_signals", column: "session_id", kind: purgeDeleteWithSession, reason: "retrieval scoring signals derived from the session"},
	{table: "handoffs", column: "source_session_id", kind: purgeDeleteWithSession, reason: "a handoff is derived from its source session"},
	{table: "session_annotations", column: "session_id", kind: purgeDeleteWithSession, reason: "the operator's note, rating and title of a session that no longer exists"},
	{table: "session_tags", column: "session_id", kind: purgeDeleteWithSession, reason: "tags of a session that no longer exists"},
	{table: "session_pid_bridge", column: "session_id", kind: purgeDeleteWithSession, reason: "transient process to session map"},
	{table: "terminal_run_session", column: "session_id", kind: purgeDeleteWithSession, reason: "launch to session correlation; the launch record itself stays"},
	{table: "guard_prompt_presend", column: "session_id", kind: purgeDeleteWithSession, reason: "transient prompt dedup state"},
	{table: "guard_prompt_reconsider", column: "session_id", kind: purgeDeleteWithSession, reason: "transient prompt warning state"},
	{table: "cloud_enrich_skips", column: "session_id", kind: purgeDeleteWithSession, reason: "local enrichment retry state"},
	{table: "cloud_outbox", column: "session_id", kind: purgeDeleteWithSession, reason: "a queued upload of a purged session must never send"},
	{table: "cloud_results", column: "session_id", kind: purgeDeleteWithSession, reason: "enrichment results carry content derived from the session"},
	{table: "org_intel_outbox", column: "session_id", kind: purgeDeleteWithSession, reason: "a queued org intelligence upload of a purged session must never send"},
	{table: "org_intel_cache", column: "session_id", kind: purgeDeleteWithSession, reason: "org intelligence results carry content derived from the session"},
	// Their own record: kept, unlinked.
	{table: "process_runs", column: "session_id", kind: purgeNullLink, reason: "process observability is its own capture"},
	{table: "process_events", column: "session_id", kind: purgeNullLink, reason: "process observability is its own capture"},
	{table: "summary_calls", column: "session_id", kind: purgeNullLink, reason: "Observer's own LLM spend stays counted"},
	{table: "limit_snapshots", column: "session_id", kind: purgeNullLink, reason: "account-level provider rate-limit state"},
	{table: "sec_findings", column: "session_id", kind: purgeNullLink, reason: "a security finding is a fact about the project's code, not capture; the purged session's lineage link is dropped"},
	{table: "plan_snapshots", column: "session_id", kind: purgeNullLink, reason: "Plans & limits status line readings are account-level plan state; the session link only scopes them"},
	{table: "handoffs", column: "target_session_id", kind: purgeNullLink, reason: "a handoff from a kept session into a purged one keeps its source record"},
	// Their own record, with session ids inside a JSON list: kept, the
	// purged id removed from the list.
	{table: "commit_landings", column: "contributors_json", kind: purgeRemoveFromList, reason: "a commit's delivery outcome is git history, not capture; the purged session's opaque id leaves its contributor list"},
	// Never rewritten.
	{table: "guard_events", column: "session_id", kind: purgeKeepDangling, reason: "hash-chained guard audit"},
	{table: "guard_approvals", column: "session_id", kind: purgeKeepDangling, reason: "security grant record (expires on its own)"},
	{table: "mcp_audit", column: "session_id", kind: purgeKeepDangling, reason: "MCP audit record"},
	{table: "mcp_relay_record", column: "coding_session_id", kind: purgeKeepDangling, reason: "hash-chained Agent Access relay record"},
	{table: "remote_audit", column: "session_id", kind: purgeKeepDangling, reason: "remote access audit record; its session_id is a remote device session, not a coding session"},
	{table: "terminal_run", column: "source_session_id", kind: purgeKeepDangling, reason: "dashboard launch record"},
	{table: "org_message_threads_local", column: "thread_id", kind: purgeKeepDangling, reason: "an org message thread id, not a coding session; owned by the messaging store (orgmessages.go)"},
	{table: "org_messages_inbox", column: "thread_id", kind: purgeKeepDangling, reason: "an org message thread id, not a coding session; owned by the messaging store (orgmessages.go)"},
	{table: "org_message_outbox", column: "thread_id", kind: purgeKeepDangling, reason: "an org message thread id, not a coding session; owned by the messaging store (orgmessages.go)"},
	{table: "org_message_outbox", column: "result_thread_id", kind: purgeKeepDangling, reason: "the org message thread id the server returned, not a coding session; owned by the messaging store (orgmessages.go)"},
	{table: "benchmark_session_members", column: "session_id", kind: purgeKeepDangling, reason: "operator-authored benchmark result; its reader LEFT JOINs, so a purged member reads as absent"},
	{table: "arena_candidates", column: "session_ids", kind: purgeKeepDangling, reason: "operator-authored arena result (a JSON id list, display only)"},
	{table: "cloud_session_map", column: "local_session_id", kind: purgeKeepDangling, reason: "content-free pseudonym; the handle a hosted deletion request needs"},
	{table: "sessions", column: "parent_thread_id", kind: purgeKeepDangling, reason: "opaque vendor lineage pointer, already tolerated dangling"},
	// Another owner reconciles.
	{table: "spend_verdict_dirty", column: "session_id", kind: purgeOwnerReconciles, reason: "spendverdict.Refresh is the one writer; the token_usage delete trigger queues the session"},
	{table: "spend_verdict_token", column: "session_id", kind: purgeOwnerReconciles, reason: "replaced by spendverdict.Refresh for the queued session"},
	{table: "spend_verdict_proxy", column: "session_id", kind: purgeOwnerReconciles, reason: "replaced by spendverdict.Refresh for the queued session"},
	{table: "org_push_manifests", column: "session_id", kind: purgeOwnerReconciles, reason: "orgpushtomb acknowledges a manifest whose session is gone without shipping it"},
}

// purgeDependent is a table whose rows hang off a candidate row by a key
// column.
type purgeDependent struct{ table, column string }

// purgeActionDependents are rows keyed to a candidate action that go with
// it wherever its session ends up (the dependency protocol, before the
// action delete); purgeTokenDependents is the same for token_usage.
var (
	purgeActionDependents = []purgeDependent{{"file_changes", "action_id"}, {"task_transitions", "action_id"}}
	purgeTokenDependents  = []purgeDependent{{"cache_events", "token_usage_id"}, {"cache_segments", "token_usage_id"}}
)

// purgeOtherSourceSQL is the keep_if_other_source predicate over one
// session expression. It returns the predicate and a binder that, given the
// session value (nil when sessionExpr binds nothing), returns its
// arguments in placeholder order.
func purgeOtherSourceSQL(sessionExpr string) (string, func(session, tool any) []any) {
	var parts []string
	for _, d := range purgeSessionDecisions {
		if d.kind != purgeKeepSession {
			continue
		}
		q := `EXISTS (SELECT 1 FROM ` + d.table + ` WHERE ` + d.column + ` = ` + sessionExpr
		if d.otherSource != "" {
			q += ` AND ` + d.otherSource
		}
		parts = append(parts, q+`)`)
	}
	bind := func(session, tool any) []any {
		var a []any
		for _, d := range purgeSessionDecisions {
			if d.kind != purgeKeepSession {
				continue
			}
			if session != nil {
				a = append(a, session)
			}
			if d.otherSource != "" {
				a = append(a, tool)
			}
		}
		return a
	}
	return `(` + strings.Join(parts, ` OR `) + `)`, bind
}

// estimateAdapterDerived fills the preview's estimate of the derived rows
// that go with the plan: every delete_with_session row of a candidate
// session no other source references, the tool-tagged rows of the ones it
// keeps, and the dependents of the candidate actions and token rows outside
// the deleted sessions. Executing reports the exact numbers.
func estimateAdapterDerived(ctx context.Context, tx *sql.Tx, args []any, counts map[string]int) error {
	tool := args[0]
	other, bind := purgeOtherSourceSQL("s.id")
	gone := `SELECT s.id FROM sessions s WHERE s.tool = ? AND NOT ` + other
	kept := `SELECT s.id FROM sessions s WHERE s.tool = ? AND ` + other
	setArgs := func(extra ...any) []any {
		a := append([]any{tool}, bind(nil, tool)...)
		return append(a, extra...)
	}
	count := func(q string, a ...any) (int, error) {
		var n int
		err := tx.QueryRowContext(ctx, q, a...).Scan(&n)
		return n, err
	}
	for _, d := range purgeSessionDecisions {
		if d.kind != purgeDeleteWithSession {
			continue
		}
		//nolint:gosec // G202: table, column and the predicates come from the reviewed decision table.
		n, err := count(`SELECT COUNT(*) FROM `+d.table+` WHERE `+d.column+` IN (`+gone+`)`, setArgs()...)
		if err != nil {
			return fmt.Errorf("store.purge: estimate %s: %w", d.table, err)
		}
		if d.toolColumn != "" {
			//nolint:gosec // G202: as above.
			m, err := count(`SELECT COUNT(*) FROM `+d.table+` WHERE `+d.column+` IN (`+kept+`) AND `+d.toolColumn+` = ?`, setArgs(tool)...)
			if err != nil {
				return fmt.Errorf("store.purge: estimate %s: %w", d.table, err)
			}
			n += m
		}
		counts[d.table] += n
		if d.keptCascadeCount != "" {
			//nolint:gosec // G201: the format string is a reviewed decision table literal; %s is the kept-session subquery.
			m, err := count(fmt.Sprintf(d.keptCascadeCount, kept), setArgs(tool)...)
			if err != nil {
				return fmt.Errorf("store.purge: estimate %s: %w", d.keptCascadeTable, err)
			}
			counts[d.keptCascadeTable] += m
		}
	}
	for _, dep := range []struct {
		parent string
		rows   []purgeDependent
	}{{"actions", purgeActionDependents}, {"token_usage", purgeTokenDependents}} {
		for _, r := range dep.rows {
			//nolint:gosec // G202: package literals; values are bound.
			n, err := count(`SELECT COUNT(*) FROM `+r.table+` WHERE `+r.column+` IN (SELECT id FROM `+dep.parent+` WHERE tool = ?)
				AND COALESCE(session_id, '') NOT IN (`+gone+`)`, append([]any{tool}, setArgs()...)...)
			if err != nil {
				return fmt.Errorf("store.purge: estimate %s: %w", r.table, err)
			}
			counts[r.table] += n
		}
	}
	return nil
}

// purgeChunk bounds IN lists.
const purgeChunk = 400

func executeAdapterPurge(ctx context.Context, tx *sql.Tx, cands map[string][]string, args []any, res *PurgeResult) error {
	tool := args[0]
	if res.Nulled == nil {
		res.Nulled = map[string]int{}
	}
	exec := func(table string, counter map[string]int, q string, a ...any) error {
		r, err := tx.ExecContext(ctx, q, a...)
		if err != nil {
			return fmt.Errorf("store.purge: %s: %w", table, err)
		}
		if n, _ := r.RowsAffected(); n > 0 {
			counter[table] += int(n)
		}
		return nil
	}
	// 1. actions: re-check, then the dependency protocol, then the delete.
	ids, err := purgeRecheckRows(ctx, tx, "actions", "id", "tool = ?", cands["actions"], tool)
	if err != nil {
		return err
	}
	res.Skipped["actions"] += len(cands["actions"]) - len(ids)
	for _, part := range purgeChunks(ids) {
		in, inArgs := purgeInList(part)
		for _, dep := range purgeActionDependents {
			//nolint:gosec // G202: package literals; in is only bound placeholders.
			if err := exec(dep.table, res.Deleted, `DELETE FROM `+dep.table+` WHERE `+dep.column+` IN (`+in+`)`, inArgs...); err != nil {
				return err
			}
		}
		steps := []struct{ name, sql string }{
			// FTS5 excerpts: search never joins actions, so a skipped
			// excerpt would be a searchable ghost (migration 079).
			{"action_excerpts", `DELETE FROM action_excerpts WHERE rowid IN (SELECT id FROM action_excerpts_content WHERE c0 IN (` + in + `))`},
			{"failure_context", `DELETE FROM failure_context WHERE action_id IN (` + in + `)`},
			{"file_state", `UPDATE file_state SET last_action_id = NULL WHERE last_action_id IN (` + in + `)`},
			{"retrieval_signals", `UPDATE retrieval_signals SET action_id = NULL WHERE action_id IN (` + in + `)`},
			{"guard_events", `UPDATE guard_events SET action_id = NULL WHERE action_id IN (` + in + `)`},
			{"process_runs", `UPDATE process_runs SET action_id = NULL WHERE action_id IN (` + in + `)`},
			{"process_events", `UPDATE process_events SET action_id = NULL WHERE action_id IN (` + in + `)`},
		}
		for _, st := range steps {
			if _, err := tx.ExecContext(ctx, st.sql, inArgs...); err != nil {
				return fmt.Errorf("store.purge: %s: %w", st.name, err)
			}
		}
		//nolint:gosec // G202: in is only bound placeholders (purgeInList).
		r, err := tx.ExecContext(ctx, `DELETE FROM actions WHERE id IN (`+in+`)`, inArgs...)
		if err != nil {
			return fmt.Errorf("store.purge: delete actions: %w", err)
		}
		n, _ := r.RowsAffected()
		res.Deleted["actions"] += int(n)
	}
	// 2. token_usage and compaction_events: re-check, delete (a token row
	// first takes its cache dependents).
	for _, tbl := range []string{"token_usage", "compaction_events"} {
		ids, err := purgeRecheckRows(ctx, tx, tbl, "id", "tool = ?", cands[tbl], tool)
		if err != nil {
			return err
		}
		res.Skipped[tbl] += len(cands[tbl]) - len(ids)
		for _, part := range purgeChunks(ids) {
			in, inArgs := purgeInList(part)
			if tbl == "token_usage" {
				for _, dep := range purgeTokenDependents {
					//nolint:gosec // G202: package literals; in is only bound placeholders.
					if err := exec(dep.table, res.Deleted, `DELETE FROM `+dep.table+` WHERE `+dep.column+` IN (`+in+`)`, inArgs...); err != nil {
						return err
					}
				}
			}
			//nolint:gosec // G202: tbl is a package literal; in is only bound placeholders.
			r, err := tx.ExecContext(ctx, `DELETE FROM `+tbl+` WHERE id IN (`+in+`)`, inArgs...)
			if err != nil {
				return fmt.Errorf("store.purge: delete %s: %w", tbl, err)
			}
			n, _ := r.RowsAffected()
			res.Deleted[tbl] += int(n)
		}
	}
	// 3. sessions (purgeAdapterSessions).
	if err := purgeAdapterSessions(ctx, tx, cands["sessions"], tool, res, exec); err != nil {
		return err
	}
	// Every node-side deleter of sessions clamps the org push cursor in its
	// own delete transaction (T-373, ledger MODPKG-8): sessions has an
	// implicit rowid, so purging the newest sessions lets SQLite hand the
	// next one a rowid at or below the cursor, and that session would never
	// ship to the org.
	if res.Deleted["sessions"] > 0 {
		if err := ClampSessionPushCursor(ctx, tx); err != nil {
			return fmt.Errorf("store.purge: %w", err)
		}
	}
	return nil
}

// purgeExec runs one statement and adds its affected rows to counter[table].
type purgeExec func(table string, counter map[string]int, q string, a ...any) error

// purgeAdapterSessions is step 3 of the adapter purge: re-check the
// candidate sessions; keep one another source's rows still reference
// (keep_if_other_source over every purgeKeepSession row) and delete only its
// rows tagged with this tool; otherwise apply purgeSessionDecisions and
// delete it, under a savepoint so an unforeseen reference keeps that one
// session (and its derived rows) instead of failing the purge.
func purgeAdapterSessions(ctx context.Context, tx *sql.Tx, cands []string, tool any, res *PurgeResult, exec purgeExec) error {
	sids, err := purgeRecheckRows(ctx, tx, "sessions", "id", "tool = ?", cands, tool)
	if err != nil {
		return err
	}
	res.Skipped["sessions"] += len(cands) - len(sids)
	other, bind := purgeOtherSourceSQL("?")
	for _, sid := range sids {
		var keep bool
		//nolint:gosec // G202: the predicate is built from the reviewed decision table.
		if err := tx.QueryRowContext(ctx, `SELECT `+other, bind(sid, tool)...).Scan(&keep); err != nil {
			return fmt.Errorf("store.purge: session refs: %w", err)
		}
		if keep {
			res.KeptSessions++
			if err := purgeKeptSessionToolRows(ctx, tx, sid, tool, res); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, `SAVEPOINT purge_session`); err != nil {
			return fmt.Errorf("store.purge: savepoint: %w", err)
		}
		deleted, nulled := map[string]int{}, map[string]int{}
		var stepErr error
		for _, d := range purgeSessionDecisions {
			switch d.kind {
			case purgeDeleteWithSession:
				//nolint:gosec // G202: table and column come from the reviewed decision table.
				stepErr = exec(d.table, deleted, `DELETE FROM `+d.table+` WHERE `+d.column+` = ?`, sid)
			case purgeNullLink:
				//nolint:gosec // G202: as above.
				stepErr = exec(d.table, nulled, `UPDATE `+d.table+` SET `+d.column+` = NULL WHERE `+d.column+` = ?`, sid)
			case purgeRemoveFromList:
				//nolint:gosec // G202: as above.
				stepErr = exec(d.table, nulled, `UPDATE `+d.table+` SET `+d.column+` =
					(SELECT COALESCE(json_group_array(j.value), '[]') FROM json_each(`+d.table+`.`+d.column+`) j WHERE j.value <> ?)
					WHERE EXISTS (SELECT 1 FROM json_each(`+d.table+`.`+d.column+`) j WHERE j.value = ?)`, sid, sid)
			}
			if stepErr != nil {
				break
			}
		}
		if stepErr == nil {
			_, stepErr = tx.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, sid)
		}
		if stepErr != nil {
			if _, err := tx.ExecContext(ctx, `ROLLBACK TO purge_session`); err != nil {
				return fmt.Errorf("store.purge: rollback to savepoint: %w", err)
			}
			res.KeptSessions++
		} else {
			res.Deleted["sessions"]++
			for k, v := range deleted {
				res.Deleted[k] += v
			}
			for k, v := range nulled {
				res.Nulled[k] += v
			}
		}
		if _, err := tx.ExecContext(ctx, `RELEASE purge_session`); err != nil {
			return fmt.Errorf("store.purge: release savepoint: %w", err)
		}
	}
	return nil
}

// purgeKeptSessionToolRows deletes, in a candidate session the purge keeps,
// the derived rows tagged with the purged tool (the purgeSessionDecisions
// rows with a toolColumn), each after its keptCascade.
func purgeKeptSessionToolRows(ctx context.Context, tx *sql.Tx, sid string, tool any, res *PurgeResult) error {
	for _, d := range purgeSessionDecisions {
		if d.kind != purgeDeleteWithSession || d.toolColumn == "" {
			continue
		}
		if d.keptCascade != "" {
			r, err := tx.ExecContext(ctx, d.keptCascade, sid, sid, tool)
			if err != nil {
				return fmt.Errorf("store.purge: %s: %w", d.keptCascadeTable, err)
			}
			if n, _ := r.RowsAffected(); n > 0 {
				res.Deleted[d.keptCascadeTable] += int(n)
			}
		}
		//nolint:gosec // G202: table and columns come from the reviewed decision table.
		r, err := tx.ExecContext(ctx, `DELETE FROM `+d.table+` WHERE `+d.column+` = ? AND `+d.toolColumn+` = ?`, sid, tool)
		if err != nil {
			return fmt.Errorf("store.purge: %s: %w", d.table, err)
		}
		if n, _ := r.RowsAffected(); n > 0 {
			res.Deleted[d.table] += int(n)
		}
	}
	return nil
}

// recheckRows returns the candidate keys that still exist and still match
// the selector.
func purgeRecheckRows(ctx context.Context, tx *sql.Tx, table, pk, where string, keys []string, selArgs ...any) ([]string, error) {
	var out []string
	for _, part := range purgeChunks(keys) {
		in, inArgs := purgeInList(part)
		//nolint:gosec // G202: pk, table and where come from the reviewed purgeDefs table; in is only bound placeholders.
		q := `SELECT ` + pk + ` FROM ` + table + ` WHERE ` + pk + ` IN (` + in + `) AND ` + where
		rows, err := tx.QueryContext(ctx, q, append(inArgs, selArgs...)...)
		if err != nil {
			return nil, fmt.Errorf("store.purge: recheck %s: %w", table, err)
		}
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				rows.Close()
				return nil, fmt.Errorf("store.purge: recheck %s: %w", table, err)
			}
			out = append(out, v)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// CreateComponentPurgePlan builds the candidate set of a component's
// reviewed plan and persists it, in one short transaction. The returned
// plan's Counts are the candidate row counts per candidate table plus, for
// the derived tables, the estimate of the rows that go with them (the
// executed result reports the exact numbers).
func (s *Store) CreateComponentPurgePlan(ctx context.Context, spec ComponentPurgeSpec) (ComponentPurgePlan, error) {
	def, ok := purgeDefFor(spec.Component)
	if !ok {
		return ComponentPurgePlan{}, ErrNoPurgePlan
	}
	now := spec.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	plan := ComponentPurgePlan{
		Kind: spec.Kind, Component: spec.Component, CatalogVersion: spec.CatalogVersion,
		PolicyVersion: spec.PolicyVersion, CreatedAt: now, Counts: map[string]int{},
	}
	switch spec.Kind {
	case PurgeInteractive:
		plan.State = PurgePreviewed
		plan.ExpiresAt = now.Add(InteractivePurgeTTL)
	case PurgeScheduled:
		grace := spec.Grace
		if grace <= 0 {
			grace = ScheduledPurgeGrace
		}
		g := now.Add(grace)
		plan.State = PurgeGracePending
		plan.GraceUntil = &g
		plan.ExpiresAt = g.Add(scheduledPurgeWindow)
	default:
		return ComponentPurgePlan{}, fmt.Errorf("store.CreateComponentPurgePlan: unknown kind %q", spec.Kind)
	}
	id, err := randomPlanID()
	if err != nil {
		return ComponentPurgePlan{}, err
	}
	plan.ID = id

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ComponentPurgePlan{}, fmt.Errorf("store.CreateComponentPurgePlan: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO component_purge_plans
		(id, kind, component, catalog_version, policy_version, state, created_at, grace_until, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		plan.ID, string(plan.Kind), plan.Component, plan.CatalogVersion, plan.PolicyVersion, string(plan.State),
		purgeTime(plan.CreatedAt), purgeTimePtr(plan.GraceUntil), purgeTime(plan.ExpiresAt)); err != nil {
		return ComponentPurgePlan{}, fmt.Errorf("store.CreateComponentPurgePlan: insert plan: %w", err)
	}
	ins, err := tx.PrepareContext(ctx, `INSERT INTO component_purge_candidates (plan_id, tbl, pk) VALUES (?, ?, ?)`)
	if err != nil {
		return ComponentPurgePlan{}, fmt.Errorf("store.CreateComponentPurgePlan: prepare: %w", err)
	}
	defer ins.Close()
	for _, c := range def.candidates {
		//nolint:gosec // G202: pk, table and where come from the reviewed purgeDefs table; values are bound.
		rows, err := tx.QueryContext(ctx, `SELECT CAST(`+c.pk+` AS TEXT) FROM `+c.table+` WHERE `+c.where, def.args...)
		if err != nil {
			return ComponentPurgePlan{}, fmt.Errorf("store.CreateComponentPurgePlan: select %s: %w", c.table, err)
		}
		var keys []string
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				rows.Close()
				return ComponentPurgePlan{}, fmt.Errorf("store.CreateComponentPurgePlan: scan %s: %w", c.table, err)
			}
			keys = append(keys, k)
		}
		if err := rows.Close(); err != nil {
			return ComponentPurgePlan{}, err
		}
		for _, k := range keys {
			if _, err := ins.ExecContext(ctx, plan.ID, c.table, k); err != nil {
				return ComponentPurgePlan{}, fmt.Errorf("store.CreateComponentPurgePlan: candidate: %w", err)
			}
		}
		plan.Counts[c.table] = len(keys)
	}
	if def.estimate != nil {
		if err := def.estimate(ctx, tx, def.args, plan.Counts); err != nil {
			return ComponentPurgePlan{}, fmt.Errorf("store.CreateComponentPurgePlan: %w", err)
		}
	}
	counts, _ := json.Marshal(plan.Counts)
	if _, err := tx.ExecContext(ctx, `UPDATE component_purge_plans SET counts_json = ? WHERE id = ?`, string(counts), plan.ID); err != nil {
		return ComponentPurgePlan{}, fmt.Errorf("store.CreateComponentPurgePlan: counts: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ComponentPurgePlan{}, fmt.Errorf("store.CreateComponentPurgePlan: commit: %w", err)
	}
	return plan, nil
}

// ComponentPurgePlanByID loads one plan.
func (s *Store) ComponentPurgePlanByID(ctx context.Context, id string) (ComponentPurgePlan, error) {
	return loadPurgePlan(ctx, s.db.QueryRowContext, id)
}

// ExecuteComponentPurgePlan consumes a plan: inside ONE transaction it
// revalidates the plan (unexpired, not consumed or cancelled, a scheduled
// plan past its grace and still authorised by recheck), deletes only the
// persisted candidate rows that still match the selector, records the
// result and marks the plan consumed. It runs under
// db.WithRetentionDeletes, so no org tombstone is emitted.
func (s *Store) ExecuteComponentPurgePlan(ctx context.Context, id string, recheck PurgeRecheck, now time.Time) (PurgeResult, error) {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PurgeResult{}, fmt.Errorf("store.ExecuteComponentPurgePlan: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	plan, err := loadPurgePlan(ctx, tx.QueryRowContext, id)
	if err != nil {
		return PurgeResult{}, err
	}
	state := plan.State
	if plan.Kind == PurgeScheduled && state == PurgeGracePending && plan.GraceUntil != nil && !now.Before(*plan.GraceUntil) {
		state, _ = NextPurgeState(plan.Kind, state, PurgeEventGraceElapsed)
	}
	if !now.Before(plan.ExpiresAt) {
		if next, ok := NextPurgeState(plan.Kind, state, PurgeEventExpire); ok {
			_, _ = tx.ExecContext(ctx, `UPDATE component_purge_plans SET state = ? WHERE id = ?`, string(next), plan.ID)
			_, _ = tx.ExecContext(ctx, `DELETE FROM component_purge_candidates WHERE plan_id = ?`, plan.ID)
			_ = tx.Commit()
		}
		return PurgeResult{}, fmt.Errorf("%w: expired at %s", ErrPurgePlanNotExecutable, plan.ExpiresAt.Format(time.RFC3339))
	}
	next, ok := NextPurgeState(plan.Kind, state, PurgeEventExecute)
	if !ok {
		return PurgeResult{}, fmt.Errorf("%w: state %s", ErrPurgePlanNotExecutable, state)
	}
	if plan.Kind == PurgeScheduled {
		if recheck == nil {
			return PurgeResult{}, fmt.Errorf("%w: a scheduled plan needs its policy revalidation", ErrPurgePlanNotExecutable)
		}
		if err := recheck(ctx, plan); err != nil {
			return PurgeResult{}, fmt.Errorf("%w: %w", ErrPurgePlanNotExecutable, err)
		}
	} else if recheck != nil {
		if err := recheck(ctx, plan); err != nil {
			return PurgeResult{}, fmt.Errorf("%w: %w", ErrPurgePlanNotExecutable, err)
		}
	}
	def, ok := purgeDefFor(plan.Component)
	if !ok {
		return PurgeResult{}, ErrNoPurgePlan
	}
	cands, err := loadPurgeCandidates(ctx, tx, plan.ID)
	if err != nil {
		return PurgeResult{}, err
	}
	res := PurgeResult{Deleted: map[string]int{}, Skipped: map[string]int{}}
	if err := db.WithRetentionDeletes(ctx, tx, func() error {
		return def.execute(ctx, tx, cands, def.args, &res)
	}); err != nil {
		return PurgeResult{}, err
	}
	out, _ := json.Marshal(res)
	r, err := tx.ExecContext(ctx, `UPDATE component_purge_plans SET state = ?, consumed_at = ?, result_json = ?
		WHERE id = ? AND consumed_at IS NULL AND state = ?`,
		string(next), purgeTime(now), string(out), plan.ID, string(plan.State))
	if err != nil {
		return PurgeResult{}, fmt.Errorf("store.ExecuteComponentPurgePlan: consume: %w", err)
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return PurgeResult{}, fmt.Errorf("%w: consumed concurrently", ErrPurgePlanNotExecutable)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM component_purge_candidates WHERE plan_id = ?`, plan.ID); err != nil {
		return PurgeResult{}, fmt.Errorf("store.ExecuteComponentPurgePlan: clear candidates: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return PurgeResult{}, fmt.Errorf("store.ExecuteComponentPurgePlan: commit: %w", err)
	}
	return res, nil
}

// CancelComponentPurgePlan cancels a plan that has not run (the scheduled
// path: the policy changed or the component became active again).
func (s *Store) CancelComponentPurgePlan(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.CancelComponentPurgePlan: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	plan, err := loadPurgePlan(ctx, tx.QueryRowContext, id)
	if err != nil {
		return err
	}
	next, ok := NextPurgeState(plan.Kind, plan.State, PurgeEventCancel)
	if !ok {
		return fmt.Errorf("%w: state %s", ErrPurgePlanNotExecutable, plan.State)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE component_purge_plans SET state = ? WHERE id = ? AND state = ?`, string(next), id, string(plan.State)); err != nil {
		return fmt.Errorf("store.CancelComponentPurgePlan: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM component_purge_candidates WHERE plan_id = ?`, id); err != nil {
		return fmt.Errorf("store.CancelComponentPurgePlan: clear candidates: %w", err)
	}
	return tx.Commit()
}

// AdvanceComponentPurgePlans applies the time-driven transitions (grace
// elapsed, expiry) to every open plan and drops the candidate rows of plans
// that reached a terminal state. It returns how many plans changed.
func (s *Store) AdvanceComponentPurgePlans(ctx context.Context, now time.Time) (int, error) {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM component_purge_plans WHERE state IN ('previewed', 'grace_pending', 'eligible')`)
	if err != nil {
		return 0, fmt.Errorf("store.AdvanceComponentPurgePlans: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	changed := 0
	for _, id := range ids {
		plan, err := loadPurgePlan(ctx, s.db.QueryRowContext, id)
		if err != nil {
			continue
		}
		state := plan.State
		if plan.GraceUntil != nil && !now.Before(*plan.GraceUntil) {
			if next, ok := NextPurgeState(plan.Kind, state, PurgeEventGraceElapsed); ok {
				state = next
			}
		}
		if !now.Before(plan.ExpiresAt) {
			if next, ok := NextPurgeState(plan.Kind, state, PurgeEventExpire); ok {
				state = next
			}
		}
		if state == plan.State {
			continue
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE component_purge_plans SET state = ? WHERE id = ? AND state = ?`, string(state), id, string(plan.State)); err != nil {
			return changed, fmt.Errorf("store.AdvanceComponentPurgePlans: %w", err)
		}
		if state == PurgeExpired {
			_, _ = s.db.ExecContext(ctx, `DELETE FROM component_purge_candidates WHERE plan_id = ?`, id)
		}
		changed++
	}
	return changed, nil
}

// ListScheduledComponentPurgePlans returns every scheduled plan (any state),
// oldest first: the scheduled purge runner (componentsvc.RunScheduledPurges,
// T-682) reads them to decide what to create, cancel or execute.
func (s *Store) ListScheduledComponentPurgePlans(ctx context.Context) ([]ComponentPurgePlan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM component_purge_plans WHERE kind = ? ORDER BY created_at, id`, string(PurgeScheduled))
	if err != nil {
		return nil, fmt.Errorf("store.ListScheduledComponentPurgePlans: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store.ListScheduledComponentPurgePlans: scan: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("store.ListScheduledComponentPurgePlans: close: %w", err)
	}
	out := make([]ComponentPurgePlan, 0, len(ids))
	for _, id := range ids {
		p, err := loadPurgePlan(ctx, s.db.QueryRowContext, id)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// ScheduledPurgePosture reduces the scheduled plans to what the org sees on
// the component posture (T-711): per component its LATEST scheduled plan,
// while that plan is open or its last moment (consumed_at, the expiry of an
// expired plan, else the later of created_at and grace_until) falls within
// orgcontract.ScheduledPurgeReportWindowDays of now. Only the id, the state
// and the UTC due date leave; counts, plan ids and the policy version stay
// node-local. The result is never nil on success.
func (s *Store) ScheduledPurgePosture(ctx context.Context, now time.Time) ([]orgcontract.ComponentPurgeEntry, error) {
	plans, err := s.ListScheduledComponentPurgePlans(ctx)
	if err != nil {
		return nil, err
	}
	return scheduledPurgeEntries(plans, now), nil
}

// scheduledPurgeEntries is ScheduledPurgePosture's pure reduction.
func scheduledPurgeEntries(plans []ComponentPurgePlan, now time.Time) []orgcontract.ComponentPurgeEntry {
	latest := map[string]ComponentPurgePlan{}
	for _, p := range plans {
		if p.Kind != PurgeScheduled {
			continue
		}
		if cur, ok := latest[p.Component]; !ok || p.CreatedAt.After(cur.CreatedAt) || (p.CreatedAt.Equal(cur.CreatedAt) && p.ID > cur.ID) {
			latest[p.Component] = p
		}
	}
	cutoff := now.UTC().AddDate(0, 0, -orgcontract.ScheduledPurgeReportWindowDays)
	out := []orgcontract.ComponentPurgeEntry{}
	for _, p := range latest {
		open := p.State == PurgeGracePending || p.State == PurgeEligible
		if !open && scheduledPurgeLastMoment(p).Before(cutoff) {
			continue
		}
		e := orgcontract.ComponentPurgeEntry{ID: p.Component, State: string(p.State)}
		if p.GraceUntil != nil {
			e.DueOn = p.GraceUntil.UTC().Format("2006-01-02")
		}
		out = append(out, e)
	}
	return orgcontract.NormalizeComponentPurges(out, nil)
}

// scheduledPurgeLastMoment is the last time a plan changed that the table
// records: consumed_at, the expiry of an expired plan, else the later of
// created_at and grace_until (a cancellation keeps no timestamp of its own).
func scheduledPurgeLastMoment(p ComponentPurgePlan) time.Time {
	if p.ConsumedAt != nil {
		return *p.ConsumedAt
	}
	if p.State == PurgeExpired {
		return p.ExpiresAt
	}
	last := p.CreatedAt
	if p.GraceUntil != nil && p.GraceUntil.After(last) {
		last = *p.GraceUntil
	}
	return last
}

type purgeRowQuerier func(ctx context.Context, query string, args ...any) *sql.Row

func loadPurgePlan(ctx context.Context, q purgeRowQuerier, id string) (ComponentPurgePlan, error) {
	var (
		p                             ComponentPurgePlan
		kind, state, created, expires string
		grace, consumed               sql.NullString
		counts, result                string
	)
	err := q(ctx, `SELECT id, kind, component, catalog_version, policy_version, state, created_at, grace_until, expires_at, consumed_at, counts_json, result_json
		FROM component_purge_plans WHERE id = ?`, id).Scan(
		&p.ID, &kind, &p.Component, &p.CatalogVersion, &p.PolicyVersion, &state, &created, &grace, &expires, &consumed, &counts, &result)
	if errors.Is(err, sql.ErrNoRows) {
		return ComponentPurgePlan{}, ErrPurgePlanNotFound
	}
	if err != nil {
		return ComponentPurgePlan{}, fmt.Errorf("store.loadPurgePlan: %w", err)
	}
	p.Kind, p.State = PurgeKind(kind), PurgeState(state)
	p.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	p.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	if grace.Valid {
		t, _ := time.Parse(time.RFC3339Nano, grace.String)
		p.GraceUntil = &t
	}
	if consumed.Valid {
		t, _ := time.Parse(time.RFC3339Nano, consumed.String)
		p.ConsumedAt = &t
	}
	p.Counts = map[string]int{}
	_ = json.Unmarshal([]byte(counts), &p.Counts)
	if p.State == PurgeConsumed {
		var r PurgeResult
		if json.Unmarshal([]byte(result), &r) == nil {
			p.Result = &r
		}
	}
	return p, nil
}

func loadPurgeCandidates(ctx context.Context, tx *sql.Tx, planID string) (map[string][]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT tbl, pk FROM component_purge_candidates WHERE plan_id = ?`, planID)
	if err != nil {
		return nil, fmt.Errorf("store.purge: load candidates: %w", err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var tbl, pk string
		if err := rows.Scan(&tbl, &pk); err != nil {
			return nil, fmt.Errorf("store.purge: scan candidate: %w", err)
		}
		out[tbl] = append(out[tbl], pk)
	}
	for k := range out {
		sort.Slice(out[k], func(i, j int) bool { return purgeLessKey(out[k][i], out[k][j]) })
	}
	return out, rows.Err()
}

func purgeLessKey(a, b string) bool {
	ai, ea := strconv.ParseInt(a, 10, 64)
	bi, eb := strconv.ParseInt(b, 10, 64)
	if ea == nil && eb == nil {
		return ai < bi
	}
	return a < b
}

func purgeChunks(xs []string) [][]string {
	var out [][]string
	for len(xs) > 0 {
		n := purgeChunk
		if len(xs) < n {
			n = len(xs)
		}
		out = append(out, xs[:n])
		xs = xs[n:]
	}
	return out
}

// purgeInList renders an IN list. Numeric keys bind as integers: the FTS5
// shadow column action_excerpts_content.c0 has no affinity, so a TEXT bind
// would never match its integer values (a TEXT-affinity column such as
// sessions.id converts an integer bind back, so this is safe there too).
func purgeInList(xs []string) (string, []any) {
	args := make([]any, len(xs))
	for i, x := range xs {
		if n, err := strconv.ParseInt(x, 10, 64); err == nil && strconv.FormatInt(n, 10) == x {
			args[i] = n
			continue
		}
		args[i] = x
	}
	return strings.TrimSuffix(strings.Repeat("?,", len(xs)), ","), args
}

func randomPlanID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("store: purge plan id: %w", err)
	}
	return "cpp_" + hex.EncodeToString(b[:]), nil
}

func purgeTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func purgeTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return purgeTime(*t)
}
