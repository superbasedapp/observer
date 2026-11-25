package invariant

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/platform/jetbrainshost"
	"github.com/marmutapp/superbased-observer/internal/platform/vscodehost"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// wireKeyClass is how one JSON key of a core push row may ship.
type wireKeyClass int

const (
	// keyMeta ships in every posture, the metadata-only default included:
	// ids, hashes, enums, counts, timestamps and attribution.
	keyMeta wireKeyClass = iota
	// keyContent ships only under shipsRawContent() (full_content,
	// admin_managed or the enterprise grant): raw paths, remotes, branch
	// and workspace names, the action target.
	keyContent
	// keyBodies ships only under FullToolBodies: the four actions body
	// columns, never under shipsRawContent() alone.
	keyBodies
)

// coreWireKeys is the structural allowlist of the four core push rows
// (INFRA-04): every JSON key each orgcontract row type declares, with the
// posture it may ship in. It is the full key set, not a denylist: a new
// field on any of the four types fails TestCoreWireRowKeySetsArePinned
// until it is classified here, which is the privacy review.
var coreWireKeys = map[string]struct {
	typ  reflect.Type
	keys map[string]wireKeyClass
}{
	"sessions": {reflect.TypeOf(orgcontract.SessionRow{}), map[string]wireKeyClass{
		"id": keyMeta, "project_root_hash": keyMeta, "git_remote_hash": keyMeta,
		"tool": keyMeta, "model": keyMeta, "started_at": keyMeta, "ended_at": keyMeta,
		"total_actions": keyMeta, "org_id": keyMeta, "user_email": keyMeta,
		"git_upstream_remote_hash": keyMeta, "git_remote_owner_hash": keyMeta,
		"git_upstream_owner_hash": keyMeta, "root_commit_hash": keyMeta,
		"content_fingerprint_hash": keyMeta, "workspace_hash": keyMeta, "is_worktree": keyMeta,
		"surface": keyMeta, "surface_host": keyMeta, "tool_version": keyMeta,
		"tool_version_last": keyMeta, "parent_thread_id": keyMeta,
		"execution_location": keyMeta, "vendor_session_ref": keyMeta, "node_rev": keyMeta,
		"project_root": keyContent, "git_remote": keyContent, "git_branch": keyContent,
		"git_upstream_remote": keyContent, "workspace": keyContent,
	}},
	"actions": {reflect.TypeOf(orgcontract.ActionRow{}), map[string]wireKeyClass{
		"session_id": keyMeta, "source_event_id": keyMeta, "timestamp": keyMeta,
		"tool": keyMeta, "action_type": keyMeta, "target_hash": keyMeta,
		"source_file_hash": keyMeta, "turn_index": keyMeta, "success": keyMeta,
		"duration_ms": keyMeta, "is_sidechain": keyMeta, "message_id": keyMeta,
		"effort_level": keyMeta, "stop_reason": keyMeta, "org_id": keyMeta,
		"user_email": keyMeta, "node_rev": keyMeta,
		"target": keyContent, "source_file": keyContent,
		"raw_tool_input": keyBodies, "raw_tool_output": keyBodies,
		"preceding_reasoning": keyBodies, "error_message": keyBodies,
	}},
	"api_turns": {reflect.TypeOf(orgcontract.APITurnRow{}), map[string]wireKeyClass{
		"session_id": keyMeta, "project_root_hash": keyMeta, "timestamp": keyMeta,
		"provider": keyMeta, "model": keyMeta, "request_id": keyMeta,
		"input_tokens": keyMeta, "output_tokens": keyMeta, "cache_read_tokens": keyMeta,
		"cache_creation_tokens": keyMeta, "cache_creation_1h_tokens": keyMeta,
		"web_search_requests": keyMeta, "cost_usd": keyMeta, "message_count": keyMeta,
		"tool_use_count": keyMeta, "system_prompt_hash": keyMeta,
		"message_prefix_hash": keyMeta, "time_to_first_token_ms": keyMeta,
		"total_response_ms": keyMeta, "stop_reason": keyMeta, "http_status": keyMeta,
		"error_class": keyMeta, "org_id": keyMeta, "user_email": keyMeta,
		"route": keyMeta, "routing_generation": keyMeta, "authority_source": keyMeta,
		"node_rev": keyMeta, "request_class": keyMeta,
		"project_root": keyContent,
	}},
	"token_usage": {reflect.TypeOf(orgcontract.TokenUsageRow{}), map[string]wireKeyClass{
		"session_id": keyMeta, "project_root_hash": keyMeta, "timestamp": keyMeta,
		"tool": keyMeta, "model": keyMeta, "input_tokens": keyMeta,
		"output_tokens": keyMeta, "cache_read_tokens": keyMeta,
		"cache_creation_tokens": keyMeta, "cache_creation_1h_tokens": keyMeta,
		"reasoning_tokens": keyMeta, "web_search_requests": keyMeta,
		"estimated_cost_usd": keyMeta, "source": keyMeta, "reliability": keyMeta,
		"source_file_hash": keyMeta, "source_event_id": keyMeta, "message_id": keyMeta,
		"is_sidechain": keyMeta, "turn_id": keyMeta, "gen_ms": keyMeta,
		"gen_basis": keyMeta, "org_id": keyMeta, "user_email": keyMeta, "node_rev": keyMeta,
		"source_file": keyContent, "project_root": keyContent,
	}},
}

// jsonKeyOf returns the JSON object key a struct field marshals under, or
// "" for a field encoding/json skips.
func jsonKeyOf(f reflect.StructField) string {
	if !f.IsExported() {
		return ""
	}
	tag := f.Tag.Get("json")
	if tag == "-" {
		return ""
	}
	if name, _, _ := strings.Cut(tag, ","); name != "" {
		return name
	}
	return f.Name
}

// TestCoreWireRowKeySetsArePinned is the structural half of the allowlist
// (INFRA-04): each core row type's JSON key set equals coreWireKeys exactly,
// so a field cannot be added to (or renamed on) the sessions / actions /
// api_turns / token_usage wire without classifying it above.
func TestCoreWireRowKeySetsArePinned(t *testing.T) {
	t.Parallel()
	for name, row := range coreWireKeys {
		got := map[string]bool{}
		for i := 0; i < row.typ.NumField(); i++ {
			f := row.typ.Field(i)
			if f.Anonymous {
				t.Errorf("%s: embedded field %s: its keys would bypass this allowlist", name, f.Name)
				continue
			}
			if k := jsonKeyOf(f); k != "" {
				got[k] = true
			}
		}
		for k := range got {
			if _, ok := row.keys[k]; !ok {
				t.Errorf("%s (%s) gained wire key %q: classify it in coreWireKeys (metadata, content or bodies) after a privacy review, and gate it in internal/store/orgpush.go if it is not metadata", name, row.typ, k)
			}
		}
		for k := range row.keys {
			if !got[k] {
				t.Errorf("%s (%s) no longer declares wire key %q: drop it from coreWireKeys", name, row.typ, k)
			}
		}
	}
}

// TestPushPayloadHasOnlyAllowlistedKeys is the behavioural half of the
// structural allowlist (INFRA-04; a permanent skip until 2026-11-24): the
// real seam (store.SelectUnpushedSince) runs over a corpus whose every
// content-bearing column is filled, the batch is marshalled as it crosses
// the wire, and every sessions / actions / api_turns / token_usage object is
// decoded and checked key by key against coreWireKeys. In the metadata-only
// default no object may carry a content or body key; under full_content only
// content keys join the metadata ones, and under full_tool_bodies only the
// body keys do. Each opted-in posture must actually ship every key of its
// class at least once, so the default's absence is not vacuous.
func TestPushPayloadHasOnlyAllowlistedKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	seed(ctx, t, st)

	// Fill every column a content or body key is built from.
	fills := []struct {
		what  string
		query string
	}{
		{"actions", `UPDATE actions SET target = 'allowlist-target', source_file = '/allowlist/source.jsonl',
			raw_tool_input = 'allowlist-in', raw_tool_output = 'allowlist-out',
			preceding_reasoning = 'allowlist-reasoning', error_message = 'allowlist-error'`},
		{"projects", `UPDATE projects SET root_path = root_path || '-allowlist', git_remote = 'git@example.invalid:o/r.git',
			git_upstream_remote = 'git@example.invalid:up/r.git'`},
		{"sessions", `UPDATE sessions SET git_branch = 'allowlist-branch', workspace = 'allowlist-workspace'`},
		{"token_usage", `UPDATE token_usage SET source_file = '/allowlist/tokens.jsonl'`},
	}
	for _, f := range fills {
		if _, err := database.ExecContext(ctx, f.query); err != nil {
			t.Fatalf("fill %s: %v", f.what, err)
		}
	}

	postures := []struct {
		name    string
		share   store.ShareOptions
		allowed map[wireKeyClass]bool
		// mustShip is the class whose every key must appear at least once.
		mustShip wireKeyClass
	}{
		{"metadata-only default", store.ShareOptions{}, map[wireKeyClass]bool{keyMeta: true}, -1},
		{"full_content", store.ShareOptions{FullContent: true}, map[wireKeyClass]bool{keyMeta: true, keyContent: true}, keyContent},
		{"full_tool_bodies", store.ShareOptions{FullToolBodies: true}, map[wireKeyClass]bool{keyMeta: true, keyBodies: true}, keyBodies},
	}
	for _, p := range postures {
		batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", p.share, store.ScopeOptions{})
		if err != nil {
			t.Fatalf("%s: SelectUnpushedSince: %v", p.name, err)
		}
		raw, err := json.Marshal(batch)
		if err != nil {
			t.Fatalf("%s: marshal: %v", p.name, err)
		}
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("%s: decode batch: %v", p.name, err)
		}
		// PushBatch carries no json tags: its slices marshal under their Go
		// field names.
		fields := map[string]string{"sessions": "Sessions", "actions": "Actions", "api_turns": "APITurns", "token_usage": "TokenUsage"}
		for name, field := range fields {
			var objs []map[string]json.RawMessage
			if err := json.Unmarshal(decoded[field], &objs); err != nil {
				t.Fatalf("%s: decode %s: %v", p.name, name, err)
			}
			if len(objs) == 0 {
				t.Fatalf("%s: the seed shipped no %s rows: the check would be vacuous", p.name, name)
			}
			classes := coreWireKeys[name].keys
			seen := map[string]bool{}
			for _, o := range objs {
				for k := range o {
					seen[k] = true
					c, known := classes[k]
					if !known || !p.allowed[c] {
						t.Errorf("%s: one %s object carries key %q, which this posture must not ship", p.name, name, k)
					}
				}
			}
			for k, c := range classes {
				if c == p.mustShip && !seen[k] {
					t.Errorf("%s: no %s object carried %q: the corpus does not exercise it, so its absence in the default proves nothing", p.name, name, k)
				}
			}
		}
	}
}

// TestRoutingSummaryWireShapeIsAggregateOnly pins the §R19.4 rollup
// contract structurally: the RoutingSummaryRow wire type may carry
// ONLY the allow-listed aggregate keys (attribution, date, enums,
// counts, dollars) — no model ids, no session ids, no paths. A new
// field on the type fails here before it can ship.
func TestRoutingSummaryWireShapeIsAggregateOnly(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{
		"OrgID": true, "UserEmail": true, // agent-stamped attribution
		"Day": true, "Tier": true, "Reason": true, "Mode": true, // date + closed enums
		"Decisions": true, "Applied": true, // counts
		"EstSavingsUSD": true, "CacheForfeitUSD": true, // dollars
	}
	typ := reflect.TypeOf(orgcontract.RoutingSummaryRow{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Errorf("RoutingSummaryRow gained non-aggregate field %q — the §R19.4 wire shape is counts + dollars by tier/reason ONLY", name)
		}
	}
}

// TestUpdatePostureRowWireShapeIsEnumOnly pins the Enterprise Update
// Management posture row (plan §2.1, ruling R10): the ONLY thing a node
// discloses about updating itself may be version strings, coarse platform
// tokens, closed enums and one boolean. A field named Host/Hostname/User/
// Path/Dir/File/Message/Detail/Error(text)/Progress/Bytes — anything that
// could carry a path, an identity or a progress percentage — fails HERE,
// before it can ship.
//
// Modeled on TestRoutingSummaryWireShapeIsAggregateOnly and
// TestPolicyStateRowWireShapeIsHashOnly, including the exact-count assertion:
// merely allow-listing a name is not enough, the SET must match, so a field
// cannot be added without a deliberate edit to this list.
//
// AutoApply is the one field beyond §2.1's own table. It is included because
// org_node_versions carries the column and the Updates board must answer
// "which of my fleet is actually zero-touch" — a boolean configuration fact
// the server cannot otherwise know, since [update].auto_apply is node-owned
// and there is deliberately no remote toggle. Reason is likewise a CLOSED
// vocabulary (update.Reason), not free text: it is the difference between
// "this fleet needs MDM" and "this fleet is broken".
func TestUpdatePostureRowWireShapeIsEnumOnly(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{
		"Version": true, "Channel": true, // version string + closed channel enum
		"OS": true, "Arch": true, // coarse platform tokens
		"State": true, "Reason": true, // closed update.State / update.Reason
		"TargetVersion": true, "ManifestVersion": true, // version string + ordinal
		"ErrorClass":       true, // closed update.ErrorClass, NEVER a message
		"InstallMethod":    true, // closed update.Method
		"AutoApply":        true, // boolean configuration fact
		"ExtensionVersion": true, // version string, empty = "not reported"
	}
	typ := reflect.TypeOf(orgcontract.UpdatePostureRow{})
	if typ.NumField() != len(allowed) {
		t.Errorf("UpdatePostureRow has %d fields, want exactly %d (§2.1 allow-list)", typ.NumField(), len(allowed))
	}
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Errorf("UpdatePostureRow gained non-allow-listed field %q — the §2.1 wire shape is "+
				"version/platform/enum/boolean ONLY: no hostname, no username, no path, no progress, "+
				"no free-text error (ruling R10)", name)
		}
	}
}

// TestPolicyStateRowWireShapeIsHashOnly pins the P0-6 effective-state row
// (docs/plans/plane-a-p0-6-effective-policy-state-plan.md §2.1/§5.1): the
// PolicyStateRow that rides POST /api/agent/policy-ack may carry ONLY the 16
// allow-listed hash/version/enum/timestamp fields — no Body/TOML/Path/Detail/
// Message/Excerpt/Tenant/EndUser/Prompt or any free-text field, forever. A new
// field fails loudly. Modeled on TestRoutingSummaryWireShapeIsAggregateOnly.
//
// gen2 (P4-2) widened the allow-list by exactly three CLOSED-VOCABULARY
// fields — AcceptedAuthority/ExtractionEffective are govern.KnownAuthority /
// govern.ExtractionAuthority token slices, and DroppedClasses is a closed
// directive-class-name -> closed drop-reason map — still enum shape, never
// free text.
//
// Track C of the org guardrail control wave added a FOURTH
// (docs/plans/org-guardrail-control-wave-2026-09-21.md item 3): EffectivePins,
// a closed pinnable-key -> closed-value map. It rides this rail rather than
// the PushEnvelope precisely so the orgpush.go sentinel above stays untouched;
// see its allow-list entry for why its shape makes a content leak structural
// rather than promised.
func TestPolicyStateRowWireShapeIsHashOnly(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{
		"OrgID": true, "UserEmail": true, // server-stamped attribution (empty-on-wire)
		"Family": true, "EnforcementPoint": true, // closed enums
		"DesiredVersion": true, "RunningVersion": true, // integer versions
		"EffectiveHash": true,                 // per-point hex digest
		"Status":        true, "Reason": true, // closed enums (Reason a typed code, never Detail)
		"RestartRequired": true, "Mode": true, // bool + closed enum
		"LastSeen":            true, // RFC3339 liveness
		"AcceptedAuthority":   true, // gen2 — closed authority-token slice
		"ExtractionEffective": true, // gen2 — closed authority-token slice
		"DroppedClasses":      true, // gen2 — closed class-name -> closed reason map
		// Track C item 3 (org guardrail control wave): a closed
		// pinnable-key-name -> closed-value map. The value vocabulary is
		// enforced by internal/policyfam/nodegov.ReportedValueAllowed on BOTH
		// sides, and the KEY vocabulary admits only a bool or a
		// closed-enum string — nodegov.ReportableKeys structurally refuses an
		// int (a threshold the developer chose) and a string_list (paths,
		// action names), so no free text can enter through this field. The
		// value spellings are exactly "true" / "false" / an enum member /
		// "other"; even a config value outside its own enum collapses to the
		// fixed "other" token rather than travelling.
		"EffectivePins": true,
		// gen3 (T-846 / T-848, guard tamper visibility): a closed
		// verified/absent/tampered enum, and the effective local guard
		// posture, which is bools, closed mode enums, closed detector ids and
		// an allow-list COUNT (orgcontract.LocalGuardPosture; pinned field by
		// field below), so no regex or path a developer typed can travel.
		"BundleIntegrity": true,
		"LocalGuard":      true,
		// gen4 (T-864, guard tamper re-test gap 4): the repaired-tamper
		// record, a COUNT, an RFC3339 time and a closed kind token
		// (orgcontract.GuardTamperReport, validated on the server by
		// Valid(); pinned field by field below). The "missing" value it
		// brings to BundleIntegrity stays inside that closed enum.
		"GuardTamper": true,
		// gen5 (SEC-P2B, plans decision log P-063): per project in the
		// signed project mapping the node holds, the org-minted project id
		// (an id the org itself signed to this node) and a closed status
		// (orgcontract.ValidProjectSectionStatus refuses anything else;
		// pinned field by field below), plus a bool saying the node cut the
		// list. No path, directory, repository identity or rule text: which
		// directory matched never travels.
		"ProjectSectionStatus":    true,
		"ProjectSectionTruncated": true,
		// gen6 (SEC-P3): per project family section the node holds, the
		// org-minted project id, the family from a closed set, the section's
		// sequence and a closed status (orgcontract.ValidProjectFamilyStatus
		// refuses anything else; pinned field by field below). No path, no
		// body, no repository identity.
		"ProjectFamilyStatus": true,
		// gen7 (SEC-P4 decision 11): the family list's own truncation flag,
		// a bool (it was missing here since that lane; added by lane
		// LEFT-SHARED, which found this test failing at its base).
		"ProjectFamilyTruncated": true,
		// gen8 (lane LEFT-SHARED, SECP-10): on the security.scanning row,
		// each floor key the node could not apply with a closed reason
		// (orgcontract.ValidateFamilyNotApplicable refuses anything else;
		// pinned field by field below). A dotted body key, never a value.
		"FamilyNotApplicable": true,
	}
	fna := reflect.TypeOf(orgcontract.FamilyKeyNotApplicable{})
	for i := 0; i < fna.NumField(); i++ {
		if n := fna.Field(i).Name; n != "Key" && n != "Reason" {
			t.Errorf("FamilyKeyNotApplicable gained non-allow-listed field %q - it is floor-key/closed-reason ONLY (gen8)", n)
		}
	}
	pf := reflect.TypeOf(orgcontract.ProjectFamilySectionState{})
	pfAllowed := map[string]bool{
		"OrgProjectID": true, "Family": true, "Version": true, "Status": true,
		// RefusedAxes (SEC-P3 merge, finding 2): the names of the section's
		// axes this node did not apply. Its vocabulary is the closed axis
		// table of the security.scanning family
		// (internal/policyfam/securityscanning.Axes, dotted body keys such
		// as "require.online_checks"): the node's only producer,
		// SectionOutcome.RefusedAxes, drops any name LookupAxis does not know
		// (TestProjectFamilyRefusedAxesClosedVocabulary below), and the
		// server's ValidProjectFamilyStatus refuses a list that is unsorted,
		// over MaxProjectFamilyRefusedAxes or not axis-shaped. No path, no
		// body value, no free text.
		"RefusedAxes": true,
	}
	for i := 0; i < pf.NumField(); i++ {
		if !pfAllowed[pf.Field(i).Name] {
			t.Errorf("ProjectFamilySectionState gained non-allow-listed field %q - it is org-project-id/family/version/closed-status ONLY (SEC-P3)", pf.Field(i).Name)
		}
	}
	ps := reflect.TypeOf(orgcontract.ProjectSectionState{})
	psAllowed := map[string]bool{"OrgProjectID": true, "Status": true}
	for i := 0; i < ps.NumField(); i++ {
		if !psAllowed[ps.Field(i).Name] {
			t.Errorf("ProjectSectionState gained non-allow-listed field %q - it is org-project-id/closed-status ONLY (P-063)", ps.Field(i).Name)
		}
	}
	if f, ok := reflect.TypeOf(orgcontract.PolicyStateRow{}).FieldByName("ProjectSectionTruncated"); !ok || f.Type.Kind() != reflect.Bool {
		t.Error("PolicyStateRow.ProjectSectionTruncated must stay a bool flag (P-063)")
	}
	gt := reflect.TypeOf(orgcontract.GuardTamperReport{})
	gtAllowed := map[string]bool{"Repairs": true, "LastAt": true, "LastKind": true}
	for i := 0; i < gt.NumField(); i++ {
		if !gtAllowed[gt.Field(i).Name] {
			t.Errorf("GuardTamperReport gained non-allow-listed field %q - it is count/timestamp/closed-kind ONLY", gt.Field(i).Name)
		}
	}
	lg := reflect.TypeOf(orgcontract.LocalGuardPosture{})
	lgAllowed := map[string]bool{
		"Enabled": true, "Mode": true, "PromptEnabled": true, "PromptMode": true, "DetectorModes": true, "AllowListCount": true,
		// gen9 (managed policy visibility, 2026-11-12): the machine's own
		// rule changes (LocalRuleChange, pinned field by field below), a
		// truncation bool, and the rule ids the daemon removed from a managed
		// machine's config with an RFC3339 time. orgcontract.ValidLocalRuleReport
		// refuses a rule id outside ReportableLocalRuleID's shape on both
		// sides, so no matcher, regex, doc line or path can travel.
		"RuleChanges": true, "RuleChangesTruncated": true, "RemovedDisables": true, "RemovedDisablesAt": true,
		// gen9: the guard engine inputs as list shapes, counts, closed enums
		// and bools (LocalGuardInputs, pinned field by field below).
		"Inputs": true,
		// gen9: the node-local settings that shape policy (LocalNodePosture,
		// pinned by kind below): switches, shaped config tokens, counts.
		"Node": true,
	}
	lnp := reflect.TypeOf(orgcontract.LocalNodePosture{})
	lnpStrings := map[string]bool{
		"GuardLevel": true, "BudgetWindow": true, "RoutingMode": true, "RoutingPolicy": true, "DefaultWorkspace": true,
		"HooksPeriodicRegister": true, "SandboxBackend": true, "SandboxEgress": true, "SandboxMinIsolation": true,
		"MCPRelayMode": true, "MCPRelayAuditMode": true,
	}
	for i := 0; i < lnp.NumField(); i++ {
		f := lnp.Field(i)
		switch {
		case f.Type.Kind() == reflect.Bool, f.Type.Kind() == reflect.Int:
		case f.Type.Kind() == reflect.String && lnpStrings[f.Name]:
			// A config enum or id checked by shape (orgcontract.LocalNodeTokenOK).
		case f.Name == "SandboxBackends" && f.Type.Kind() == reflect.Slice:
		case f.Name == "Share" && f.Type.Kind() == reflect.Map && f.Type.Elem().Kind() == reflect.Bool:
		default:
			t.Errorf("LocalNodePosture gained field %q (%s) - it is switch/shaped-token/count ONLY (gen9)", f.Name, f.Type)
		}
	}
	for i := 0; i < lg.NumField(); i++ {
		if !lgAllowed[lg.Field(i).Name] {
			t.Errorf("LocalGuardPosture gained non-allow-listed field %q - it is bool/enum/detector-id/rule-id/count ONLY", lg.Field(i).Name)
		}
	}
	lrc := reflect.TypeOf(orgcontract.LocalRuleChange{})
	lrcAllowed := map[string]bool{
		"RuleID": true, "Layer": true, "Kind": true, "Observe": true, "Enforce": true,
		"Enforced": true, "EnforceOff": true, "Loosens": true, "Applied": true,
		// The project identity hash the push wire already ships as
		// project_root_hash, never the root path.
		"ProjectRootHash": true,
	}
	lgi := reflect.TypeOf(orgcontract.LocalGuardInputs{})
	for i := 0; i < lgi.NumField(); i++ {
		f := lgi.Field(i)
		switch f.Type.Kind() {
		case reflect.Bool, reflect.Int:
		case reflect.String:
			// Only the closed-enum fields may be strings.
			if f.Name != "BoundaryAllowPaths" && f.Name != "ProtectedBranches" && f.Name != "EgressAction" {
				t.Errorf("LocalGuardInputs gained string field %q - strings there are closed enums ONLY (gen9)", f.Name)
			}
		default:
			t.Errorf("LocalGuardInputs gained field %q of kind %s - it is shape/count/enum/bool ONLY (gen9)", f.Name, f.Type.Kind())
		}
	}
	for i := 0; i < lrc.NumField(); i++ {
		if !lrcAllowed[lrc.Field(i).Name] {
			t.Errorf("LocalRuleChange gained non-allow-listed field %q - it is rule-id/closed-enum/bool/project-hash ONLY (gen9)", lrc.Field(i).Name)
		}
	}
	typ := reflect.TypeOf(orgcontract.PolicyStateRow{})
	if typ.NumField() != len(allowed) {
		t.Errorf("PolicyStateRow has %d fields, want exactly %d (§2.1 allow-list + the gen2 P4-2, Track C, gen5 P-063, gen6 SEC-P3, gen7 SEC-P4 and gen8 LEFT-SHARED widenings)", typ.NumField(), len(allowed))
	}
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Errorf("PolicyStateRow gained non-allow-listed field %q — the P0-6 §2.1 wire shape is hash/version/enum/timestamp ONLY", name)
		}
	}
}

// TestProjectFamilyRefusedAxesClosedVocabulary pins the normalizer behind
// ProjectFamilySectionState.RefusedAxes (allow-listed in
// TestPolicyStateRowWireShapeIsHashOnly): a refusal naming anything but a
// row of the security.scanning axis table, even an axis-shaped one, never
// reaches the wire list, and a list the normalizer returns passes the
// server's check.
func TestProjectFamilyRefusedAxesClosedVocabulary(t *testing.T) {
	t.Parallel()
	o := securityscanning.SectionOutcome{Partial: true, Refused: []securityscanning.AxisRefusal{
		{Axis: "home.alice.secret_repo"},
		{Axis: securityscanning.AxisAllowOnlineChecks},
		{Axis: securityscanning.AxisOnlineChecks},
		{Axis: securityscanning.AxisOnlineChecks},
		{Axis: "require.online_checks /etc/passwd"},
		{Axis: ""},
	}}
	got := o.RefusedAxes()
	want := []string{securityscanning.AxisAllowOnlineChecks, securityscanning.AxisOnlineChecks}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RefusedAxes() = %q, want %q (only the closed axis table may travel)", got, want)
	}
	for _, a := range got {
		if _, ok := securityscanning.LookupAxis(a); !ok {
			t.Errorf("axis %q is not in the family's axis table", a)
		}
	}
	e := orgcontract.ProjectFamilySectionState{OrgProjectID: "P1", Family: orgcontract.ProjectSectionFamilies[0], Version: 1, Status: orgcontract.ProjectFamilyPartial, RefusedAxes: got}
	if !orgcontract.ValidProjectFamilyStatus([]orgcontract.ProjectFamilySectionState{e}) {
		t.Errorf("the normalized list fails the server's check: %+v", e)
	}
	none := securityscanning.SectionOutcome{Refused: []securityscanning.AxisRefusal{{Axis: "free text"}}}
	if got := none.RefusedAxes(); len(got) != 0 {
		t.Errorf("an outcome with only non-vocabulary names yields %q, want none", got)
	}
}

// newInvariantStore opens a fresh migrated agent DB for the routing
// wire-shape tests.
func newInvariantStore(t *testing.T) (*store.Store, func()) {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database), func() { _ = database.Close() }
}

// TestRoutingSummaryGatedOffByDefault pins the consent posture: the
// zero-valued ShareOptions (the default) attaches NO routing summaries
// to a push batch, even when decision rows exist.
func TestRoutingSummaryGatedOffByDefault(t *testing.T) {
	t.Parallel()
	s, _ := newInvariantStore(t)
	ctx := context.Background()
	if err := s.InsertRouterDecisions(ctx, []store.RouterDecisionRow{{
		SessionID: "s1", Timestamp: time.Now().UTC(), Mode: "advise", Channel: "B",
		OriginalModel: "claude-opus-4-8", SelectedModel: "claude-haiku-4-5",
		TurnKind: "read_only", PolicyName: "value", PolicyHash: "h",
		ReasonCodes: []string{"overpowered_read"}, EstSavingsUSD: 1, EstimateVersion: "p1-v1",
	}}); err != nil {
		t.Fatalf("seed decision: %v", err)
	}

	batch, err := s.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x", store.ShareOptions{}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if len(batch.RoutingSummaries) != 0 {
		t.Fatalf("default share shipped %d routing summaries — the §R26.4 consent toggle must gate them", len(batch.RoutingSummaries))
	}

	opted, err := s.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x", store.ShareOptions{RoutingSummary: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("select opted: %v", err)
	}
	if len(opted.RoutingSummaries) == 0 {
		t.Fatal("opt-in shipped no summaries despite decision rows")
	}
	row := opted.RoutingSummaries[0]
	if row.Tier != "opus-class" || row.Decisions != 1 || row.OrgID != "org-1" {
		t.Errorf("summary row = %+v", row)
	}
}

// TestPlatformSurfaceHostsShipVerbatim is the producer-side drift guard for
// the two shared host-token tables (VS Code family, JetBrains family): every
// host they can stamp must cross the org wire as itself, never coarsen to
// "other" (MCP audit #4c, 2026-09-27 — the same class that hid Claude Code's
// print-mode "cli" host). A failure means a new product row needs a reviewed
// entry in internal/store/orgpush.go's knownSurfaceHosts.
func TestPlatformSurfaceHostsShipVerbatim(t *testing.T) {
	var hosts []string
	for _, p := range vscodehost.Products() {
		hosts = append(hosts, p.Host)
	}
	for _, p := range jetbrainshost.Products() {
		hosts = append(hosts, p.Host)
	}
	for _, h := range hosts {
		if !store.SurfaceHostShipsVerbatim(h) {
			t.Errorf("host token %q would ship to the org as \"other\"", h)
		}
	}
}
