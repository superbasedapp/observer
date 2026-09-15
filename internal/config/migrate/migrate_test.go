package migrate

import (
	"fmt"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// mustValidTOML fails if s is not decodable TOML — every Apply output
// must remain a well-formed config file.
func mustValidTOML(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if _, err := toml.Decode(s, &m); err != nil {
		t.Fatalf("result is not valid TOML: %v\n---\n%s", err, s)
	}
	return m
}

func TestApply_BlockForm_MigratesAndCleansUp(t *testing.T) {
	in := `# my observer config
[observer]
log_level = "info"

[compression.code_graph]
enabled = true
auto_index = true
auto_install = false
path = "/home/me/.observer/graph.db"

[compression.shell]
enabled = true
`
	res, err := Apply(in)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Migrated || res.Skipped {
		t.Fatalf("want Migrated, got Migrated=%v Skipped=%v (%s)", res.Migrated, res.Skipped, res.SkipReason)
	}
	out := res.Text
	m := mustValidTOML(t, out)

	// legacy block gone
	if strings.Contains(out, "code_graph") {
		t.Errorf("legacy code_graph still present:\n%s", out)
	}
	// renamed values landed with the user's values preserved
	ci, _ := m["codeintel"].(map[string]any)
	if ci == nil || ci["enabled"] != true {
		t.Errorf("codeintel.enabled not true: %#v", m["codeintel"])
	}
	idx, _ := ci["index"].(map[string]any)
	if idx == nil || idx["on_start"] != true {
		t.Errorf("codeintel.index.on_start not true: %#v", ci["index"])
	}
	// removed keys really gone
	if strings.Contains(out, "auto_install") || strings.Contains(out, "graph.db") {
		t.Errorf("removed keys leaked:\n%s", out)
	}
	// stamp present and correct
	obs, _ := m["observer"].(map[string]any)
	if got := obs["config_version"]; got != int64(LatestVersion()) {
		t.Errorf("config_version = %v, want %d", got, LatestVersion())
	}
	// untouched content preserved verbatim
	if !strings.Contains(out, "# my observer config") ||
		!strings.Contains(out, `log_level = "info"`) ||
		!strings.Contains(out, "[compression.shell]") {
		t.Errorf("untouched content not preserved:\n%s", out)
	}
}

func TestApply_DottedInlineForm(t *testing.T) {
	in := "compression.code_graph.enabled = true\n"
	res, err := Apply(in)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Migrated {
		t.Fatalf("want Migrated")
	}
	m := mustValidTOML(t, res.Text)
	ci, _ := m["codeintel"].(map[string]any)
	if ci == nil || ci["enabled"] != true {
		t.Errorf("codeintel.enabled not migrated from dotted form:\n%s", res.Text)
	}
	if strings.Contains(res.Text, "code_graph") {
		t.Errorf("legacy dotted key remains:\n%s", res.Text)
	}
}

func TestApply_Precedence_CompressionWins(t *testing.T) {
	in := `[compression.code_graph]
enabled = true

[intelligence.code_graph]
enabled = false
`
	res, err := Apply(in)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	m := mustValidTOML(t, res.Text)
	ci, _ := m["codeintel"].(map[string]any)
	if ci["enabled"] != true {
		t.Errorf("compression should win (true), got %#v\n%s", ci["enabled"], res.Text)
	}
	// exactly one codeintel.enabled assignment
	if n := strings.Count(res.Text, "enabled ="); n != 1 {
		t.Errorf("want a single codeintel.enabled, found %d\n%s", n, res.Text)
	}
}

func TestApply_TargetAlreadySet_KeepsTarget(t *testing.T) {
	in := `[codeintel]
enabled = false

[compression.code_graph]
enabled = true
`
	res, err := Apply(in)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	m := mustValidTOML(t, res.Text)
	ci, _ := m["codeintel"].(map[string]any)
	if ci["enabled"] != false {
		t.Errorf("codeintel must stay authoritative (false), got %#v\n%s", ci["enabled"], res.Text)
	}
	if strings.Contains(res.Text, "code_graph") {
		t.Errorf("legacy should be dropped:\n%s", res.Text)
	}
}

func TestApply_Pristine_NoChange(t *testing.T) {
	in := `[observer]
log_level = "info"

[codeintel]
enabled = true
`
	res, err := Apply(in)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Migrated || res.Skipped {
		t.Fatalf("pristine file must be untouched: Migrated=%v Skipped=%v", res.Migrated, res.Skipped)
	}
	if res.Text != in {
		t.Errorf("text changed on pristine file:\n%s", res.Text)
	}
	if strings.Contains(res.Text, "config_version") {
		t.Errorf("must not stamp a pristine file")
	}
}

func TestApply_Idempotent(t *testing.T) {
	in := `[compression.code_graph]
enabled = true
`
	first, err := Apply(in)
	if err != nil || !first.Migrated {
		t.Fatalf("first Apply: err=%v migrated=%v", err, first.Migrated)
	}
	second, err := Apply(first.Text)
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if second.Migrated {
		t.Errorf("second Apply should be a no-op")
	}
	if second.Text != first.Text {
		t.Errorf("idempotency broken:\n---1---\n%s\n---2---\n%s", first.Text, second.Text)
	}
}

func TestApply_FailSafe_UnsafeValueSkips(t *testing.T) {
	// `path` is a removal target; an array value is not single-line
	// scalar, so the whole run must Skip and leave the file untouched.
	in := `[compression.code_graph]
enabled = true
path = ["a", "b"]
`
	res, err := Apply(in)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Skipped || res.Migrated {
		t.Fatalf("want Skipped, got Skipped=%v Migrated=%v", res.Skipped, res.Migrated)
	}
	if res.Text != in {
		t.Errorf("Skipped run must not change text:\n%s", res.Text)
	}
	if res.SkipReason == "" {
		t.Errorf("SkipReason should explain the skip")
	}
}

func TestApply_EmptyTableCleanup_KeepsNonTargetKeys(t *testing.T) {
	in := `[compression.code_graph]
enabled = true
custom_user_key = 42
`
	res, err := Apply(in)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	mustValidTOML(t, res.Text)
	// enabled migrated away, but the user's own key + its table stay.
	if !strings.Contains(res.Text, "custom_user_key = 42") {
		t.Errorf("non-target key was dropped:\n%s", res.Text)
	}
	if !strings.Contains(res.Text, "[compression.code_graph]") {
		t.Errorf("table with remaining keys must stay:\n%s", res.Text)
	}
}

func TestApply_ValuePreservedVerbatimWithInlineComment(t *testing.T) {
	in := "[compression.code_graph]\nenabled = true  # keep me\n"
	res, err := Apply(in)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !strings.Contains(res.Text, "enabled = true  # keep me") {
		t.Errorf("value + inline comment not carried verbatim:\n%s", res.Text)
	}
}

// TestApply_MatchesNestedIndentStyle reproduces a BurntSushi-encoded
// config (2-space nested indentation, no hand comments — the shape
// `observer config set` / the dashboard produce) and asserts the
// migrated additions match that style instead of landing flush-left.
func TestApply_MatchesNestedIndentStyle(t *testing.T) {
	in := "" +
		"[observer]\n" +
		"  db_path = \"/home/me/.observer/observer.db\"\n" +
		"  log_level = \"info\"\n" +
		"  [observer.watch]\n" +
		"    poll_interval_seconds = 2\n" +
		"\n" +
		"[compression]\n" +
		"  [compression.code_graph]\n" +
		"    enabled = true\n" +
		"    auto_index = true\n" +
		"    auto_install = true\n" +
		"    path = \"\"\n" +
		"  [compression.shell]\n" +
		"    enabled = true\n"
	res, err := Apply(in)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Migrated {
		t.Fatalf("want Migrated")
	}
	mustValidTOML(t, res.Text)
	out := res.Text

	stampLine := fmt.Sprintf("  config_version = %d", LatestVersion())
	wantLines := []string{
		stampLine,               // stamp indented to match [observer]'s keys
		"[codeintel]",           // new top-level table flush-left
		"  enabled = true",      // its key at one level
		"  [codeintel.index]",   // sub-table indented one level
		"    on_start = true",   // its key at two levels
		"  [compression.shell]", // untouched sibling kept verbatim
	}
	for _, w := range wantLines {
		if !strings.Contains(out, w+"\n") && !strings.HasSuffix(out, w) {
			t.Errorf("expected line %q in output:\n%s", w, out)
		}
	}
	// The stamp must NOT be flush-left in a nested file.
	if strings.Contains(out, fmt.Sprintf("\nconfig_version = %d", LatestVersion())) {
		t.Errorf("stamp landed flush-left, should match nested indent:\n%s", out)
	}
	// legacy block cleaned up
	if strings.Contains(out, "code_graph") {
		t.Errorf("legacy block not removed:\n%s", out)
	}
}

func TestLatestVersion(t *testing.T) {
	if LatestVersion() != 3 {
		t.Errorf("LatestVersion = %d, want 3", LatestVersion())
	}
}

// TestApply_RemovesDiskBudget pins step 3 (corpus-archival P4): the removed
// codeintel.index.disk_budget_mb key is DROPPED from the file — durably, so the
// deprecation warning stops recurring — while its siblings in the same block
// survive untouched. A migration that took the whole block with it would
// silently reset the operator's indexer settings.
func TestApply_RemovesDiskBudget(t *testing.T) {
	in := `[codeintel]
enabled = true

[codeintel.index]
on_start = false
disk_budget_mb = 500
workers = 4
`
	res, err := Apply(in)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Migrated {
		t.Fatalf("Migrated = false; the removed key should have been dropped\n%s", res.Text)
	}
	if strings.Contains(res.Text, "disk_budget_mb") {
		t.Errorf("disk_budget_mb survived the migration:\n%s", res.Text)
	}
	for _, keep := range []string{"on_start = false", "workers = 4", "enabled = true"} {
		if !strings.Contains(res.Text, keep) {
			t.Errorf("migration lost %q — only the removed key may be dropped:\n%s", keep, res.Text)
		}
	}
	var removed bool
	for _, c := range res.Changes {
		if c.From == "codeintel.index.disk_budget_mb" && c.Kind == "remove" && c.To == "" {
			removed = true
		}
	}
	if !removed {
		t.Errorf("no removal change reported for disk_budget_mb: %+v", res.Changes)
	}
}

// TestApply_OrgShareObsNesting pins the step-2 migration: the flat
// [org_client.share] obs_* keys move into the nested [org_client.share.obs]
// sub-table, values preserved, the sibling full_content untouched, and the
// result re-parses to the expected nested values (plane-separation audit M1).
func TestApply_OrgShareObsNesting(t *testing.T) {
	in := `[observer]
config_version = 1

[org_client.share]
full_content = true
obs_summary = true
obs_traces = true
obs_content = false
obs_eval_summary = true
`
	res, err := Apply(in)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Migrated || res.Skipped {
		t.Fatalf("want Migrated, got Migrated=%v Skipped=%v (%s)", res.Migrated, res.Skipped, res.SkipReason)
	}
	out := res.Text
	m := mustValidTOML(t, out)

	// Flat obs_* keys gone.
	if strings.Contains(out, "obs_summary") || strings.Contains(out, "obs_eval_summary") ||
		strings.Contains(out, "obs_traces") || strings.Contains(out, "obs_content") {
		t.Errorf("legacy flat obs_* keys still present:\n%s", out)
	}
	oc, _ := m["org_client"].(map[string]any)
	share, _ := oc["share"].(map[string]any)
	if share == nil || share["full_content"] != true {
		t.Errorf("full_content not preserved in [org_client.share]: %#v", share)
	}
	obs, _ := share["obs"].(map[string]any)
	if obs == nil {
		t.Fatalf("[org_client.share.obs] missing: %#v", share)
	}
	if obs["summary"] != true || obs["traces"] != true || obs["content"] != false || obs["eval_summary"] != true {
		t.Errorf("nested obs values wrong: %#v", obs)
	}
	stampObs, _ := m["observer"].(map[string]any)
	if got := stampObs["config_version"]; got != int64(LatestVersion()) {
		t.Errorf("config_version = %v, want %d", got, LatestVersion())
	}
}

// TestApply_OrgShareObsNesting_NestedWins pins that when the nested target
// is already set, the flat source is dropped and the nested value stays.
func TestApply_OrgShareObsNesting_NestedWins(t *testing.T) {
	in := `[org_client.share]
obs_summary = false

[org_client.share.obs]
summary = true
`
	res, err := Apply(in)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Migrated || res.Skipped {
		t.Fatalf("want Migrated, got Migrated=%v Skipped=%v", res.Migrated, res.Skipped)
	}
	m := mustValidTOML(t, res.Text)
	if strings.Contains(res.Text, "obs_summary") {
		t.Errorf("flat obs_summary should be dropped:\n%s", res.Text)
	}
	oc, _ := m["org_client"].(map[string]any)
	share, _ := oc["share"].(map[string]any)
	obs, _ := share["obs"].(map[string]any)
	if obs == nil || obs["summary"] != true {
		t.Errorf("nested obs.summary=true must win: %#v", obs)
	}
}
