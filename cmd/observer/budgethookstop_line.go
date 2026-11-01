package main

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// budgetHookStopWindow is how far back a hook invocation counts as "the
// tool's hooks run on this node" for the budget line.
const budgetHookStopWindow = 7 * 24 * time.Hour

// recentHookTools lists the tools whose hooks this node's daemon saw within
// budgetHookStopWindow (the node-local hook_activity rows). A read failure
// lists none.
func recentHookTools(ctx context.Context, database *sql.DB, now time.Time) []string {
	rows, err := store.New(database).LoadHookActivity(ctx, now.Add(-budgetHookStopWindow))
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range rows {
		if r.Tool != "" && !seen[r.Tool] {
			seen[r.Tool] = true
			out = append(out, r.Tool)
		}
	}
	return out
}

// budgetHookStopClause is the `observer guard status` budget line's
// hook-path half (WINNODE item 8). coverage=proxy_only is right for what it
// says, the guard's own refusal scan, which only sees proxied requests, and it
// stays the wire value (orgcontract.BudgetCoverageProxyOnly). It was not the
// whole answer on a managed node with budget authority: the hook-path stop
// (T-519) also stops a direct-provider session of a tool whose wired pre-send
// hook can deny, at its next prompt or tool call. The clause names those
// tools from the registry's capability (Capability.BudgetHookStop, never a
// tool name) for the tools whose hooks this node saw recently. An individual
// node, or a managed node without budget authority, gets no clause.
func budgetHookStopClause(granted bool, hookTools []string) string {
	if !granted {
		return ""
	}
	var parts []string
	for _, tool := range hookTools {
		c, ok := integration.For(tool)
		if !ok {
			continue
		}
		if stop := c.BudgetHookStop(); stop != integration.BudgetHookStopNone {
			parts = append(parts, tool+" ("+string(stop)+")")
		}
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "; hook-path stop: none (no tool with a pre-send hook ran here in the last 7 days)"
	}
	return "; hook-path stop: " + strings.Join(parts, ", ") + " (direct-provider sessions stop at the next prompt or tool call)"
}
