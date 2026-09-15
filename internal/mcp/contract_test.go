package mcp

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// contractDocPointer is appended to every failure below so a developer who
// trips one of these pins is sent to the promise they are about to break,
// not just to the test file.
const contractDocPointer = "see docs/mcp-contract.md — the stable tier promises name + required params + " +
	"result invariants across every semver-MINOR release; removal needs a MAJOR plus one minor of deprecation notice"

// TestStableToolNamesPinned pins the exact stable-tier tool-name list. A
// rename, removal, or an accidental tier downgrade of a stable tool must
// fail HERE — that is the whole point of publishing a contract.
//
// Adding a NEW stable tool is a deliberate act: land it as experimental
// first, then promote it in both this list and docs/mcp-contract.md.
func TestStableToolNamesPinned(t *testing.T) {
	t.Parallel()
	want := []string{
		"cache_status",
		"check_command_freshness",
		"check_file_freshness",
		"get_action_details",
		"get_cost_summary",
		"get_failure_context",
		"get_file_history",
		"get_last_test_result",
		"get_model_recommendation",
		"get_project_patterns",
		"get_redundancy_report",
		"get_routing_status",
		"get_session_recovery_context",
		"get_session_summary",
		"get_suggestions",
		"list_actions_around",
		"search_past_outputs",
		"search_symbols",
	}
	got := StableToolNames()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("stable-tier tool list changed:\n got: %v\nwant: %v\n%s", got, want, contractDocPointer)
	}
}

// TestContractTableWellFormed is the table-driven shape check over every
// contract row: a known tier, a non-empty name, ConfigGated set iff the row
// is conditional, and no duplicate names.
func TestContractTableWellFormed(t *testing.T) {
	t.Parallel()
	tiers := map[ContractTier]bool{
		TierStable:       true,
		TierConditional:  true,
		TierExperimental: true,
	}
	seen := map[string]bool{}
	for _, row := range ContractTools() {
		row := row
		t.Run(row.Name, func(t *testing.T) {
			if row.Name == "" {
				t.Fatalf("empty tool name in the contract table — %s", contractDocPointer)
			}
			if !tiers[row.Tier] {
				t.Errorf("tier %q is not one of stable/conditional/experimental — %s", row.Tier, contractDocPointer)
			}
			if wantGated := row.Tier == TierConditional; row.ConfigGated != wantGated {
				t.Errorf("ConfigGated = %v, want %v for tier %q — the conditional tier IS the config-gated tier (%s)",
					row.ConfigGated, wantGated, row.Tier, contractDocPointer)
			}
			if seen[row.Name] {
				t.Errorf("duplicate contract row for %q", row.Name)
			}
			seen[row.Name] = true
		})
	}
}

// TestContractToolsSorted pins that ContractTools() comes back alphabetical
// — the same order tools/list emits, which the contract publishes as an
// invariant.
func TestContractToolsSorted(t *testing.T) {
	t.Parallel()
	rows := ContractTools()
	names := make([]string, len(rows))
	for i, r := range rows {
		names[i] = r.Name
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("ContractTools() not sorted by name: %v — %s", names, contractDocPointer)
	}
}

// TestContractCoversEveryRegisteredTool is the anti-drift pin in the other
// direction: every tool the server ACTUALLY registers must appear in the
// contract table, so a future tool cannot ship unlisted (and therefore
// un-tiered). The fixture enables all four conditional tools so the full
// 25-tool surface is present in one tools/list.
func TestContractCoversEveryRegisteredTool(t *testing.T) {
	_, database, _ := testServer(t)
	s, err := New(v7_12FixtureOpts(t, database, nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	registered := listToolNames(t, s)

	inContract := map[string]ContractTool{}
	for _, row := range ContractTools() {
		inContract[row.Name] = row
	}
	for name := range registered {
		if _, ok := inContract[name]; !ok {
			t.Errorf("tool %q is registered but missing from the contract table (internal/mcp/contract.go) — "+
				"every tool needs a published tier; %s", name, contractDocPointer)
		}
	}
	for name := range inContract {
		if !registered[name] {
			t.Errorf("contract table lists %q but the server does not register it (with all conditional "+
				"tools enabled) — %s", name, contractDocPointer)
		}
	}
}

// TestContractConfigGatedMatchesRegistration pins the config_gated flag
// against reality: a DEFAULT server (no conditional tools enabled) must
// register exactly the non-gated rows, and none of the gated ones.
func TestContractConfigGatedMatchesRegistration(t *testing.T) {
	s, _, _ := testServer(t)
	registered := listToolNames(t, s)
	for _, row := range ContractTools() {
		switch {
		case row.ConfigGated && registered[row.Name]:
			t.Errorf("%q is marked config_gated but registers on a default server — %s", row.Name, contractDocPointer)
		case !row.ConfigGated && !registered[row.Name]:
			t.Errorf("%q is not marked config_gated but is absent from a default server — %s", row.Name, contractDocPointer)
		}
	}
}

// TestContractTierFor covers the lookup helper, including the honest
// not-published result.
func TestContractTierFor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		tool     string
		wantTier ContractTier
		wantOK   bool
	}{
		{name: "stable", tool: "check_file_freshness", wantTier: TierStable, wantOK: true},
		{name: "conditional", tool: "get_file", wantTier: TierConditional, wantOK: true},
		{name: "experimental", tool: "continue_session", wantTier: TierExperimental, wantOK: true},
		{name: "unpublished", tool: "no_such_tool", wantTier: "", wantOK: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := ContractTierFor(tc.tool)
			if got != tc.wantTier || ok != tc.wantOK {
				t.Errorf("ContractTierFor(%q) = (%q, %v), want (%q, %v)", tc.tool, got, ok, tc.wantTier, tc.wantOK)
			}
		})
	}
}

// TestServerNamePinned pins the registration entry name the contract
// publishes: every MCP tool a client sees is namespaced `mcp__observer__*`
// because this constant is "observer".
func TestServerNamePinned(t *testing.T) {
	t.Parallel()
	if ServerName != "observer" {
		t.Errorf("ServerName = %q, want %q — the contract pins this (%s)", ServerName, "observer", contractDocPointer)
	}
}

// -----------------------------------------------------------------------------
// Required-parameter conformance
// -----------------------------------------------------------------------------

// contractRequiredParams is THE literal pin of every published tool's
// required-parameter set, as advertised by `tools/list`'s `inputSchema`.
//
// It is deliberately hand-written rather than derived from InputSchema() —
// deriving it from the same code it checks would make the test tautological.
// This table IS the second half of the stable-tier promise ("required
// parameters do not change"), which until now only the prose in
// docs/mcp-contract.md carried.
//
// Adding a required parameter to a stable tool is a MAJOR-only change; the
// table in docs/mcp-contract.md's "Changing the contract" section says so.
// Editing a row here without a major is the mistake this test catches.
var contractRequiredParams = map[string][]string{
	// stable (18)
	"cache_status":                 {},
	"check_command_freshness":      {"command"},
	"check_file_freshness":         {"project_root", "file_path"},
	"get_action_details":           {"action_ids"},
	"get_cost_summary":             {},
	"get_failure_context":          {"command"},
	"get_file_history":             {"file_path"},
	"get_last_test_result":         {},
	"get_model_recommendation":     {},
	"get_project_patterns":         {"project_root"},
	"get_redundancy_report":        {},
	"get_routing_status":           {},
	"get_session_recovery_context": {"session_id"},
	"get_session_summary":          {},
	"get_suggestions":              {},
	"list_actions_around":          {"action_id"},
	"search_past_outputs":          {"query"},
	"search_symbols":               {"query"},
	// conditional (4) — same SHAPE promise as stable, only presence is gated.
	"get_file":         {"project_root", "path"},
	"get_relations":    {"project_root", "file", "name", "kind"},
	"get_symbols":      {"project_root", "requests"},
	"retrieve_stashed": {"sha"},
	// experimental (3) — no cross-release promise, pinned so a change is
	// at least a deliberate edit rather than an accident.
	"continue_session":       {},
	"get_output_composition": {"session_id"},
	"get_session_message":    {"session_id"},
	"get_session_tasks":      {"session_id"},
}

// listToolSchemas returns the `inputSchema` object tools/list advertises for
// every registered tool, keyed by tool name.
func listToolSchemas(t *testing.T, s *Server) map[string]map[string]any {
	t.Helper()
	resp := rpcCall(t, s, "tools/list", 1, nil)
	tools := resp["result"].(map[string]any)["tools"].([]any)
	out := make(map[string]map[string]any, len(tools))
	for _, raw := range tools {
		tm := raw.(map[string]any)
		schema, _ := tm["inputSchema"].(map[string]any)
		out[tm["name"].(string)] = schema
	}
	return out
}

// requiredFromSchema reads the JSON-Schema `required` array off a tool's
// advertised input schema. Absent means "no required parameters".
func requiredFromSchema(schema map[string]any) []string {
	rawList, ok := schema["required"].([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(rawList))
	for _, r := range rawList {
		if s, ok := r.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// TestContractRequiredParamsPinned is the substance the name-only pins were
// missing: for every published tool, the required-parameter SET advertised by
// tools/list must equal the literal table above — same members, same order.
//
// A stable tool gaining a required parameter, losing one, or renaming one is
// a MAJOR-only break; this test is where that break becomes visible.
func TestContractRequiredParamsPinned(t *testing.T) {
	_, database, _ := testServer(t)
	s, err := New(v7_12FixtureOpts(t, database, nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	schemas := listToolSchemas(t, s)

	// Every contract row must have a pin, and vice versa — so a new tool
	// cannot ship with an un-pinned parameter set.
	for _, row := range ContractTools() {
		if _, ok := contractRequiredParams[row.Name]; !ok {
			t.Errorf("tool %q is in the contract table but has no required-parameter pin in "+
				"contractRequiredParams (internal/mcp/contract_test.go) — %s", row.Name, contractDocPointer)
		}
	}
	for name := range contractRequiredParams {
		if _, ok := ContractTierFor(name); !ok {
			t.Errorf("contractRequiredParams pins %q, which is not in the contract table — %s",
				name, contractDocPointer)
		}
	}

	for _, row := range ContractTools() {
		row := row
		want, pinned := contractRequiredParams[row.Name]
		if !pinned {
			continue
		}
		t.Run(row.Name, func(t *testing.T) {
			schema, ok := schemas[row.Name]
			if !ok {
				t.Fatalf("%q is not registered (with all conditional tools enabled) — %s",
					row.Name, contractDocPointer)
			}
			got := requiredFromSchema(schema)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("%s-tier tool %q required params changed:\n got: %v\nwant: %v\n"+
					"adding/removing/renaming a required parameter of a stable tool is a MAJOR-only "+
					"change — %s", row.Tier, row.Name, got, want, contractDocPointer)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Result-shape conformance
// -----------------------------------------------------------------------------

// contractResultKeys is the literal pin of the top-level result keys each
// stable tool must return. It is a PRESENCE pin, not an exact-set pin:
// the contract explicitly allows new keys to be ADDED in any release
// ("Unknown fields are additive"), so only removal/rename is a break.
//
// Hand-written, deliberately: derived expectations would make the test
// tautological. The `args` are the fixture-compatible invocation; `keys` are
// the documented top-level keys that must survive every semver-minor.
//
// Two tools carry a short list on purpose:
//   - cache_status: the fixture server has [cachewarm] unset, so it answers
//     on the disabled branch, whose only always-present key is `enabled`.
//   - get_last_test_result / get_suggestions: the remaining keys are
//     `omitempty` and depend on captured data, so only the unconditional
//     ones are pinned.
var contractResultKeys = []struct {
	tool string
	args map[string]any
	keys []string
}{
	{tool: "cache_status", args: map[string]any{}, keys: []string{"enabled"}},
	{
		tool: "check_command_freshness",
		args: map[string]any{"command": "go test ./..."},
		keys: []string{"command", "command_hash", "last_success", "edits_since_last_run", "file_changes_seen", "never_run"},
	},
	{
		tool: "check_file_freshness",
		args: map[string]any{"project_root": fixtureProjectRoot, "file_path": "handler.go"},
		keys: []string{"file", "project_root", "freshness", "change_detected"},
	},
	{
		tool: "get_action_details",
		args: map[string]any{"action_ids": []any{fixtureActionID}},
		keys: []string{"actions", "count"},
	},
	{
		tool: "get_cost_summary",
		args: map[string]any{},
		keys: []string{
			"group_by", "days", "source", "rows", "total_input_tokens",
			"total_output_tokens", "total_cost_usd", "reliability", "unknown_model_count",
		},
	},
	{
		tool: "get_failure_context",
		args: map[string]any{"command": "go test ./..."},
		keys: []string{"command", "command_hash", "failures", "count"},
	},
	{
		tool: "get_file_history",
		args: map[string]any{"project_root": fixtureProjectRoot, "file_path": "handler.go"},
		keys: []string{"file", "entries", "count"},
	},
	{tool: "get_last_test_result", args: map[string]any{}, keys: []string{"found", "success"}},
	{
		tool: "get_model_recommendation",
		args: map[string]any{},
		keys: []string{"caveat", "window_days", "recommendations", "note"},
	},
	{
		tool: "get_project_patterns",
		args: map[string]any{"project_root": fixtureProjectRoot},
		keys: []string{"project_root", "hot_files", "common_commands", "derived_patterns"},
	},
	{
		tool: "get_redundancy_report",
		args: map[string]any{},
		keys: []string{"days", "stale_reads", "changed_by_self_reads", "repeated_commands", "top_stale_files", "top_repeated_commands"},
	},
	{
		tool: "get_routing_status",
		args: map[string]any{},
		keys: []string{
			"phase", "mode", "enforcement_available", "templates",
			"tier_table_entries", "router_decisions", "model_calibration_rows", "note",
		},
	},
	{
		tool: "get_session_recovery_context",
		args: map[string]any{"session_id": "sess-A"},
		keys: []string{"session_id", "recent_edited_files", "recent_failures", "counts"},
	},
	{
		tool: "get_session_summary",
		args: map[string]any{"project_root": fixtureProjectRoot},
		keys: []string{"sessions", "count"},
	},
	{tool: "get_suggestions", args: map[string]any{}, keys: []string{"suggestions"}},
	{
		tool: "list_actions_around",
		args: map[string]any{"action_id": fixtureActionID},
		keys: []string{"action_id", "before", "after", "actions", "found"},
	},
	{
		tool: "search_past_outputs",
		args: map[string]any{"query": "FAIL"},
		keys: []string{"query", "hits", "count"},
	},
	{tool: "search_symbols", args: map[string]any{"query": "main"}, keys: []string{"ok", "results"}},
}

// fixtureProjectRoot / fixtureActionID are placeholders substituted at call
// time with the values seed() actually produced — the literal table above
// stays readable while the invocation still targets real fixture rows.
const (
	fixtureProjectRoot = "<project_root>"
	fixtureActionID    = -1
)

// TestContractStableResultKeysPinned invokes every stable tool against the
// shared fixture and pins its documented top-level result keys. All 18 are
// covered: the seed() fixture (one project, one session, a read action and a
// failing `go test ./...` action) is enough for each of them to answer.
//
// This is the third leg of the stable promise — name, required parameters,
// and "documented result fields keep their name and meaning". A renamed or
// dropped top-level key fails here.
func TestContractStableResultKeysPinned(t *testing.T) {
	s, database, _ := testServer(t)
	root := seed(t, database)

	// Resolve a real action id from the fixture so get_action_details and
	// list_actions_around address an actual row.
	hits := callTool(t, s, "search_past_outputs", map[string]any{"query": "FAIL"})["hits"].([]any)
	if len(hits) == 0 {
		t.Fatal("fixture produced no indexed actions — cannot resolve an action_id")
	}
	actionID := int64(hits[0].(map[string]any)["action_id"].(float64))

	// Every stable tool must appear in the table; nothing else may.
	pinned := map[string]bool{}
	for _, c := range contractResultKeys {
		pinned[c.tool] = true
	}
	for _, name := range StableToolNames() {
		if !pinned[name] {
			t.Errorf("stable tool %q has no result-key pin in contractResultKeys "+
				"(internal/mcp/contract_test.go) — %s", name, contractDocPointer)
		}
	}
	for _, c := range contractResultKeys {
		if tier, ok := ContractTierFor(c.tool); !ok || tier != TierStable {
			t.Errorf("contractResultKeys pins %q, which is not a stable-tier tool — %s", c.tool, contractDocPointer)
		}
	}

	for _, c := range contractResultKeys {
		c := c
		t.Run(c.tool, func(t *testing.T) {
			args := make(map[string]any, len(c.args))
			for k, v := range c.args {
				switch tv := v.(type) {
				case string:
					if tv == fixtureProjectRoot {
						v = root
					}
				case int:
					if tv == fixtureActionID {
						v = actionID
					}
				case []any:
					resolved := make([]any, len(tv))
					for i, elem := range tv {
						if n, ok := elem.(int); ok && n == fixtureActionID {
							resolved[i] = actionID
						} else {
							resolved[i] = elem
						}
					}
					v = resolved
				}
				args[k] = v
			}
			out := callTool(t, s, c.tool, args)
			for _, key := range c.keys {
				if _, ok := out[key]; !ok {
					t.Errorf("stable tool %q result is missing documented top-level key %q "+
						"(got keys %v) — removing or renaming a documented result field of a "+
						"stable tool is a MAJOR-only change; %s",
						c.tool, key, sortedKeys(out), contractDocPointer)
				}
			}
		})
	}
}

// sortedKeys renders a result map's key set deterministically for failures.
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// -----------------------------------------------------------------------------
// Prose-doc drift gate
// -----------------------------------------------------------------------------

// contractDocPaths are the two hand-maintained Markdown mirrors of the Go
// tier table, relative to the repo root (internal/mcp → up two).
//
// The Markdown is NOT generated — it is prose a human edits — so this test is
// the drift gate that makes it trustworthy, the same way
// internal/config/recipes_test.go gates the docs/recipes mirror.
var contractDocPaths = []string{
	filepath.Join("docs", "mcp-contract.md"),
	filepath.Join("website", "docs-src", "reference", "mcp-contract.md"),
}

// contractDocRowRe matches one row of the "Tier assignment" table:
//
//	| `cache_status` | stable | always registered |
//
// The tier alternation keeps the regex from matching the server-invariants
// or "Changing the contract" tables, whose first cells are prose.
var contractDocRowRe = regexp.MustCompile(
	"^\\|\\s*`([a-z0-9_]+)`\\s*\\|\\s*(stable|conditional|experimental)\\s*\\|\\s*(.+?)\\s*\\|\\s*$",
)

// TestContractDocTablesMatchGoTable parses the tier table out of BOTH
// Markdown mirrors and compares it tool-by-tool against ContractTools().
//
// Rationale: docs/mcp-contract.md used to claim the prose and the emitter
// "read one table". They do not — the Markdown is hand-maintained. Rather
// than weaken the claim to nothing, this test makes the weaker, TRUE claim
// enforceable: the prose is test-pinned against the Go table.
//
// The doc mirrors are private-repo-only (scripts/release.sh keeps `docs/`
// and `website/` off the public orphan), so a missing file skips rather than
// fails — the gate is real wherever the sources actually live.
func TestContractDocTablesMatchGoTable(t *testing.T) {
	t.Parallel()
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	for _, rel := range contractDocPaths {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(repoRoot, rel)
			body, err := os.ReadFile(path)
			if os.IsNotExist(err) {
				t.Skipf("%s absent (private-repo-only doc mirror) — nothing to gate here", rel)
			}
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}

			type docRow struct {
				tier     ContractTier
				gated    bool
				presence string
			}
			doc := map[string]docRow{}
			var order []string
			for _, line := range strings.Split(string(body), "\n") {
				m := contractDocRowRe.FindStringSubmatch(strings.TrimRight(line, "\r"))
				if m == nil {
					continue
				}
				if _, dup := doc[m[1]]; dup {
					t.Errorf("%s: duplicate tier-table row for %q", rel, m[1])
					continue
				}
				doc[m[1]] = docRow{
					tier: ContractTier(m[2]),
					// The presence column says "always registered" for every
					// ungated tool; anything else names the config flag.
					gated:    !strings.EqualFold(strings.TrimSpace(m[3]), "always registered"),
					presence: strings.TrimSpace(m[3]),
				}
				order = append(order, m[1])
			}
			if len(doc) == 0 {
				t.Fatalf("%s: parsed zero tier-table rows — the table format changed and this "+
					"drift gate went blind; fix the parser in internal/mcp/contract_test.go", rel)
			}

			for _, row := range ContractTools() {
				got, ok := doc[row.Name]
				if !ok {
					t.Errorf("%s: tier table is missing %q (tier %s) — the prose table is "+
						"test-pinned against contractTools in internal/mcp/contract.go; %s",
						rel, row.Name, row.Tier, contractDocPointer)
					continue
				}
				if got.tier != row.Tier {
					t.Errorf("%s: %q documented as %q but the Go table says %q — %s",
						rel, row.Name, got.tier, row.Tier, contractDocPointer)
				}
				if got.gated != row.ConfigGated {
					t.Errorf("%s: %q presence column %q implies config_gated=%v but the Go table "+
						"says %v — %s", rel, row.Name, got.presence, got.gated, row.ConfigGated, contractDocPointer)
				}
			}
			for _, name := range order {
				if _, ok := ContractTierFor(name); !ok {
					t.Errorf("%s: tier table documents %q, which is not in contractTools "+
						"(internal/mcp/contract.go) — %s", rel, name, contractDocPointer)
				}
			}
			if !sort.StringsAreSorted(order) {
				t.Errorf("%s: tier-table rows are not alphabetical (%v) — the doc publishes the "+
					"same order tools/list emits; %s", rel, order, contractDocPointer)
			}
			if len(order) != len(ContractTools()) {
				t.Errorf("%s: tier table has %d rows, the Go table has %d — %s",
					rel, len(order), len(ContractTools()), contractDocPointer)
			}
		})
	}
}
