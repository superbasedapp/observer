package main

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// arena_permissions.go: may an Agent Arena drive skip the harness's own
// permission checks (OSH-R-005)? The engine asks per drive
// (arena.Options.PermissionBypass); this file answers from two facts only:
// the operator's own [benchmark] arena_allow_skip_permissions, and, on a
// managed node, the organization's verified AI tool settings for the tool.

// arenaBypassFacts is what the seam read for one drive.
type arenaBypassFacts struct {
	// readErr: the config, the database or the enrolment could not be read.
	readErr bool
	// localAllows: [benchmark] arena_allow_skip_permissions is true.
	localAllows bool
	// managed: this node holds a managed enrolment.
	managed bool
	// policyUnreadable: a cached org AI tool settings policy exists but its
	// body could not be read.
	policyUnreadable bool
	// orgForbids / orgWhy: the org's enforced settings forbid the skip.
	orgForbids bool
	orgWhy     string
}

// arenaBypassRule is one row of the decision table, walked top-down.
type arenaBypassRule struct {
	match func(arenaBypassFacts) bool
	allow bool
	why   func(arenaBypassFacts) string
}

const arenaBypassKey = "[benchmark] arena_allow_skip_permissions"

// arenaBypassRules is the decision table (CLAUDE.md #5). Every unreadable
// state refuses: the skip is the dangerous answer, so it needs every fact.
var arenaBypassRules = []arenaBypassRule{
	{
		match: func(f arenaBypassFacts) bool { return f.readErr },
		why:   func(arenaBypassFacts) string { return "the node's config or enrolment could not be read" },
	},
	{
		match: func(f arenaBypassFacts) bool { return !f.localAllows },
		why:   func(arenaBypassFacts) string { return arenaBypassKey + " is off (the default)" },
	},
	{
		match: func(f arenaBypassFacts) bool { return f.managed && f.policyUnreadable },
		why: func(arenaBypassFacts) string {
			return "this node is managed and its organization's AI tool settings could not be read"
		},
	},
	{
		match: func(f arenaBypassFacts) bool { return f.managed && f.orgForbids },
		why:   func(f arenaBypassFacts) string { return f.orgWhy },
	},
	{
		match: func(arenaBypassFacts) bool { return true },
		allow: true,
		why:   func(arenaBypassFacts) string { return "" },
	},
}

// decideArenaBypass walks arenaBypassRules.
func decideArenaBypass(f arenaBypassFacts) (bool, string) {
	for _, r := range arenaBypassRules {
		if r.match(f) {
			return r.allow, r.why(f)
		}
	}
	return false, "no rule matched"
}

// arenaPermissionBypassSeam is the dashboard's arena.Options.PermissionBypass,
// as a plain func so the dashboard options carry no arena type. It re-reads
// the config and the database on every call, so a changed setting or a new
// org policy applies to the next drive without a restart.
func arenaPermissionBypassSeam(configPath string) func(ctx context.Context, tool string) (bool, string) {
	return func(ctx context.Context, tool string) (bool, string) {
		return decideArenaBypass(readArenaBypassFacts(ctx, configPath, tool))
	}
}

// readArenaBypassFacts gathers the facts. It never creates anything: the
// daemon that serves the Arena already holds the database.
func readArenaBypassFacts(ctx context.Context, configPath, tool string) arenaBypassFacts {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return arenaBypassFacts{readErr: true}
	}
	if !cfg.Benchmark.ArenaAllowSkipPermissions {
		return arenaBypassFacts{}
	}
	_, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return arenaBypassFacts{readErr: true}
	}
	defer cleanup()
	st := store.New(database)
	enr, err := st.LoadEnrolment(ctx)
	if err != nil {
		return arenaBypassFacts{readErr: true}
	}
	f := arenaBypassFacts{localAllows: true, managed: arenaNodeManaged(ctx, st, enr)}
	if !f.managed {
		return f
	}
	row, ok, err := st.CurrentOrgAgentConfigPolicy(ctx)
	if err != nil {
		f.policyUnreadable = true
		return f
	}
	if !ok {
		return f
	}
	enforced, err := enforcedAgentConfigValues(row.Body, tool)
	if err != nil {
		f.policyUnreadable = true
		return f
	}
	f.orgForbids, f.orgWhy = agentconfig.BypassForbidden(tool, enforced)
	return f
}

// enforcedAgentConfigValues decodes a verified AI tool settings body into
// the ENFORCED native values for one tool (setting id to decoded value).
// Project-scoped directives count as well as user-scoped ones: an Arena run
// can target any project, so the strict reading is that the org said it.
func enforcedAgentConfigValues(body, tool string) (map[string]any, error) {
	b, err := orgcontract.DecodeAgentConfigPolicyBody(body)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	prefix := tool + "/"
	for _, d := range b.Directives {
		if d.Mode != orgcontract.AgentConfigModeEnforced || !strings.HasPrefix(d.Setting, prefix) {
			continue
		}
		var v any
		if err := json.Unmarshal(d.Value, &v); err != nil {
			return nil, err
		}
		out[d.Setting] = v
	}
	return out, nil
}

// arenaNodeManaged reports whether this node is managed for the Arena's
// org-policy check, through the one node-side predicate (orgclient
// NodeManagedFor, P-204). A read failure counts as managed, so the org's
// settings are still consulted (the strict reading for a permission skip).
func arenaNodeManaged(ctx context.Context, st *store.Store, enr *store.Enrolment) bool {
	managed, err := orgclient.NodeManagedFor(ctx, st, enr)
	return err != nil || managed
}
