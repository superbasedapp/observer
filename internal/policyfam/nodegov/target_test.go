package nodegov

import (
	"errors"
	"strings"
	"testing"
)

// releasedKeys are the pinned / share / feature key sets the released builds
// compiled, by key generation, taken from the tags (`git show
// <tag>:internal/policyfam/nodegov/pinnable.go`). They are literal on purpose:
// the generation table is a claim about what RELEASED builds compile, so it is
// checked against what they actually compiled, not against today's lists.
// Generation 3 is v1.33.0, every v1.34.0 rc and v1.34.0 (identical sets).
var releasedKeys = map[int]struct{ pinned, share, features []string }{
	1: { // v1.31.0
		pinned: []string{
			"browser.enabled", "cachetrack.enabled", "codeintel.enabled", "compression.conversation.enabled",
			"guard.enabled", "guard.mode", "observer.process.enabled", "observer.secrets.enable_scrubbing",
			"predict.enabled", "remote.enabled",
		},
		share: []string{
			"full_content", "obs.admission", "obs.content", "obs.eval_items", "obs.eval_summary", "obs.summary",
			"obs.traces", "policy_state", "routing_summary", "target_action_allowlist",
		},
		features: []string{
			"browser_capture", "codeintel", "compression_conversation", "guard", "process_observer",
			"remote_access", "secrets",
		},
	},
	2: { // v1.32.0
		share: []string{
			"cache_detail", "codeintel_detail", "full_tool_bodies", "limit_gauge", "process_detail",
			"routing_detail", "terminal_detail",
		},
	},
	3: { // v1.33.0 .. v1.34.0
		pinned: []string{"guard.budget.from_org", "guard.budget.hard", "guard.strict", "routing.enabled", "tasks.enabled"},
		share:  []string{"intelligence.org_enrichment", "obs.egress", "task_detail", "tool_account_detail"},
	},
	4: { // v1.36.0 (the held v1.35.0 shipped inside it)
		pinned: []string{"guard.budget.fail_closed", "org_client.push_interval_seconds"},
	},
}

// TestKeyGenerationsCoverEveryKey fails when a pinned key, share key or
// feature joins without a since-generation: the server would then serve it to
// released builds that fail the whole body on it.
func TestKeyGenerationsCoverEveryKey(t *testing.T) {
	firstSeen := func(pick func(g int) []string) map[string]int {
		out := map[string]int{}
		for g := FirstKeyGen; g < CurrentKeyGen; g++ {
			for _, k := range pick(g) {
				if _, dup := out[k]; !dup {
					out[k] = g
				}
			}
		}
		return out
	}
	check := func(name string, current []string, released map[string]int, since func(string) int) {
		cur := setOf(current)
		for k := range released {
			if !cur[k] {
				t.Errorf("%s %q was released but this build no longer knows it: a key was renamed or removed, and released nodes still compile it by that name", name, k)
			}
		}
		for _, k := range current {
			want, wasReleased := released[k]
			if !wasReleased {
				want = CurrentKeyGen
			}
			if got := since(k); got != want {
				t.Errorf("%s %q: since = %d, want %d (add it to the since table and, for a new key, bump CurrentKeyGen)", name, k, got, want)
			}
		}
	}
	var pinned, share, features []string
	for _, k := range PinnableKeys {
		pinned = append(pinned, k.Key)
	}
	for _, k := range ShareKeys {
		share = append(share, k.Key)
	}
	for _, f := range Features {
		features = append(features, f.ID)
	}
	check("pinned", pinned, firstSeen(func(g int) []string { return releasedKeys[g].pinned }), PinnedKeySince)
	check("share", share, firstSeen(func(g int) []string { return releasedKeys[g].share }), ShareKeySince)
	check("feature", features, firstSeen(func(g int) []string { return releasedKeys[g].features }), FeatureSince)

	maxSince := FirstKeyGen
	for _, table := range []map[string]int{pinSince, shareSince, featureSince} {
		for _, g := range table {
			maxSince = max(maxSince, g)
		}
	}
	if maxSince != CurrentKeyGen {
		t.Errorf("highest key since-generation is %d but CurrentKeyGen is %d", maxSince, CurrentKeyGen)
	}
}

func TestCompareRelease(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.34.0", "1.34.0", 0, true},
		{"v1.34.0", "1.34.0", 0, true},
		{"1.34.0-rc.11", "1.34.0", -1, true}, // a pre-release is OLDER than its release
		{"1.34.0-rc.1", "1.34.0-rc.11", -1, true},
		{"1.34.0-rc.2", "1.34.0-rc.11", -1, true}, // numeric identifiers compare numerically
		{"1.34.0-rc.11", "1.34.0-rc.1", 1, true},
		{"1.34.0-rc.12+node1.017ca5210", "1.34.0-rc.12", 0, true}, // build metadata ignored
		{"1.34.0-rc.12+node1.017ca5210", "1.34.0-rc.1", 1, true},
		{"1.34.0-alpha", "1.34.0-1", 1, true}, // alphanumeric above numeric
		{"1.34.0-rc", "1.34.0-rc.1", -1, true},
		{"1.33.9", "1.34.0-rc.1", -1, true},
		{"1.35.0-rc.1", "1.34.0", 1, true},
		{"dev", "1.34.0", 0, false},
		{"", "1.34.0", 0, false},
		{"1.34", "1.34.0", 0, false},
		{"1.34.0-", "1.34.0", 0, false},
		{"1.34.0-rc..1", "1.34.0", 0, false},
	}
	for _, tc := range cases {
		got, ok := compareRelease(tc.a, tc.b)
		if got != tc.want || ok != tc.ok {
			t.Errorf("compareRelease(%q, %q) = %d,%v want %d,%v", tc.a, tc.b, got, ok, tc.want, tc.ok)
		}
	}
}

// TestTargetForAgentVersion is the version fallback for a node that sends no
// capability token, on all three axes.
func TestTargetForAgentVersion(t *testing.T) {
	v134 := Target{Level: 3, MaxSchema: 2, KeyGen: 3}
	cases := []struct {
		name, version string
		want          Target
	}{
		{"v1.34.0-rc.1", "1.34.0-rc.1", v134},
		{"v1.34.0-rc.11", "v1.34.0-rc.11", v134},
		{"the v1.34.0 release", "1.34.0", v134},
		{"a stamped dev build of the v1.34 line", "1.34.0-rc.12+node1.017ca5210", v134},
		{"a later version with no token", "1.35.0", v134},
		{"v1.33.0", "1.33.0", Target{Level: 2, MaxSchema: 2, KeyGen: 3}},
		{"an rc of v1.33.0 is older than v1.33.0", "1.33.0-rc.2", Target{Level: 1, MaxSchema: 2, KeyGen: 2}},
		{"v1.32.0", "1.32.0", Target{Level: 1, MaxSchema: 2, KeyGen: 2}},
		{"v1.31.0", "1.31.0", oldestTarget},
		{"an unstamped dev build", "dev", oldestTarget},
		{"no version", "", oldestTarget},
	}
	for _, tc := range cases {
		if got := TargetForAgentVersion(tc.version); got != tc.want {
			t.Errorf("%s: TargetForAgentVersion(%q) = %+v, want %+v", tc.name, tc.version, got, tc.want)
		}
	}
	if LastUncappedTarget() != v134 {
		t.Errorf("LastUncappedTarget = %+v, want the v1.34 line %+v", LastUncappedTarget(), v134)
	}
	// No pre-capability build decodes schema 3 or knows a generation-4 key:
	// both arrived with (or before) the capability tokens.
	for _, row := range releasedTargets {
		if row.Target.MaxSchema >= 3 || row.Target.KeyGen >= CurrentKeyGen || row.Target.Level >= 4 {
			t.Errorf("released row %s claims %+v, beyond every pre-capability build", row.MinVersion, row.Target)
		}
	}
}

func TestTargetForCapabilities(t *testing.T) {
	cases := []struct {
		name   string
		tokens []string
		want   Target
		ok     bool
	}{
		{"no token: an older build", []string{"selectors"}, Target{}, false},
		{"a schema token alone is not a capability", []string{"nodegov-schema-3"}, Target{}, false},
		{"this build", append([]string{"selectors"}, CapabilityTokens()...), CurrentTarget(), true},
		{"vocab 5 only (tab builds)", []string{"nodegov-vocab-5"}, Target{Level: 5, MaxSchema: 3, KeyGen: 4}, true},
		{"vocab 4 only (adapter-config builds)", []string{"nodegov-vocab-4"}, Target{Level: 4, MaxSchema: 3, KeyGen: 4}, true},
		{"vocab 3 hand-written: the v1.34 line", []string{"nodegov-vocab-3"}, Target{Level: 3, MaxSchema: 2, KeyGen: 3}, true},
		{"vocab 1 hand-written: the oldest build", []string{"nodegov-vocab-1"}, Target{Level: 1, MaxSchema: 2, KeyGen: 1}, true},
		{"explicit schema wins over the era", []string{"nodegov-vocab-5", "nodegov-schema-2"}, Target{Level: 5, MaxSchema: 2, KeyGen: 4}, true},
		{"explicit keys win over the era", []string{"nodegov-vocab-5", "nodegov-keys-3"}, Target{Level: 5, MaxSchema: 3, KeyGen: 3}, true},
		{"a newer node is clamped to this server", []string{"nodegov-vocab-99", "nodegov-schema-99", "nodegov-keys-99"}, CurrentTarget(), true},
		{"garbage axis tokens are ignored", []string{"nodegov-vocab-5", "nodegov-schema-x", "nodegov-keys-0"}, Target{Level: 5, MaxSchema: 3, KeyGen: 4}, true},
	}
	for _, tc := range cases {
		got, ok := TargetForCapabilities(tc.tokens)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: TargetForCapabilities(%v) = %+v,%v want %+v,%v", tc.name, tc.tokens, got, ok, tc.want, tc.ok)
		}
	}
	for level := FirstVocabLevel; level <= CurrentVocabLevel; level++ {
		if _, ok := capabilityEra[level]; !ok {
			t.Errorf("capabilityEra has no row for level %d", level)
		}
	}
}

// TestProjectToTargetSchemaAndKeys pins the two axes the section projection
// did not cover: the body schema and the key vocabularies.
func TestProjectToTargetSchemaAndKeys(t *testing.T) {
	full := Body{
		Schema: 3,
		Sections: SectionsV1{
			Hidden:          []string{"benchmarks", "security/prompt-guard"},
			Visible:         []string{"security"},
			SettingsVisible: []string{"process"},
		},
		Pinned:   map[string]any{"guard.enabled": true, "guard.strict": true, "org_client.push_interval_seconds": int64(300)},
		Share:    map[string]any{"full_content": false, "cache_detail": false, "task_detail": false},
		Features: map[string]bool{"secrets": true},
	}
	cases := []struct {
		name    string
		target  Target
		schema  int
		hidden  string
		visible string
		pinned  string
		share   string
		removed string
	}{
		{"this build: unchanged", CurrentTarget(), 3, "benchmarks,security/prompt-guard", "security", "guard.enabled,guard.strict,org_client.push_interval_seconds", "cache_detail,full_content,task_detail", ""},
		{
			"the v1.34 line",
			Target{Level: 3, MaxSchema: 2, KeyGen: 3},
			2, "benchmarks", "", "guard.enabled,guard.strict", "cache_detail,full_content,task_detail",
			"sections.hidden:security/prompt-guard,pinned:org_client.push_interval_seconds,sections.visible:*,sections.settings_visible:*,schema:3->2",
		},
		{
			"v1.32",
			Target{Level: 1, MaxSchema: 2, KeyGen: 2},
			2, "benchmarks", "", "guard.enabled", "cache_detail,full_content",
			"sections.hidden:security/prompt-guard,pinned:guard.strict,pinned:org_client.push_interval_seconds,share:task_detail,sections.visible:*,sections.settings_visible:*,schema:3->2",
		},
		{
			"a schema-2 node that knows everything else",
			Target{Level: CurrentVocabLevel, MaxSchema: 2, KeyGen: CurrentKeyGen},
			2, "benchmarks,security/prompt-guard", "", "guard.enabled,guard.strict,org_client.push_interval_seconds", "cache_detail,full_content,task_detail",
			"sections.visible:*,sections.settings_visible:*,schema:3->2",
		},
	}
	for _, tc := range cases {
		got, removed, err := ProjectToTarget(full, tc.target)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got.Schema != tc.schema ||
			strings.Join(got.Sections.Hidden, ",") != tc.hidden ||
			strings.Join(got.Sections.Visible, ",") != tc.visible ||
			strings.Join(sortedKeys(got.Pinned), ",") != tc.pinned ||
			strings.Join(sortedKeys(got.Share), ",") != tc.share ||
			strings.Join(removed, ",") != tc.removed {
			t.Errorf("%s:\n got schema %d %+v pinned %v share %v\n removed %q\nwant schema %d hidden %q visible %q pinned %q share %q\n removed %q",
				tc.name, got.Schema, got.Sections, sortedKeys(got.Pinned), sortedKeys(got.Share), strings.Join(removed, ","),
				tc.schema, tc.hidden, tc.visible, tc.pinned, tc.share, tc.removed)
		}
		if got.Features["secrets"] != true {
			t.Errorf("%s: the secrets feature lock (a v1.31 feature) was dropped", tc.name)
		}
		// Whatever was served must compile, and declare no more schema than
		// the target decodes.
		if _, err := CanonicalJSON(got); err != nil {
			t.Errorf("%s: projected body does not compile: %v", tc.name, err)
		}
		if got.Schema > tc.target.MaxSchema {
			t.Errorf("%s: projected schema %d exceeds the target's %d", tc.name, got.Schema, tc.target.MaxSchema)
		}
	}
	if len(full.Pinned) != 3 || len(full.Sections.Visible) != 1 || full.Schema != 3 {
		t.Fatalf("ProjectToTarget modified its input: %+v", full)
	}

	// A body that only DECLARES schema 3 is lowered for a schema-2 node even
	// though nothing else has to go.
	declared, removed, err := ProjectToTarget(Body{Schema: 3, Sections: SectionsV1{Hidden: []string{"cost"}}}, Target{Level: 3, MaxSchema: 2, KeyGen: 3})
	if err != nil || declared.Schema != 1 || strings.Join(removed, ",") != "schema:3->1" {
		t.Errorf("declared-only schema 3: got schema %d removed %v err %v, want 1 [schema:3->1]", declared.Schema, removed, err)
	}

	// Pins can never be dropped for a schema reason: refused, not omitted.
	_, _, err = ProjectToTarget(Body{Schema: 2, Pinned: map[string]any{"guard.enabled": true}}, Target{Level: 3, MaxSchema: 1, KeyGen: 3})
	if !errors.Is(err, ErrNotExpressible) {
		t.Errorf("pins for a schema-1 node: err = %v, want ErrNotExpressible", err)
	}

	// A feature whose key a node lacks goes with the key.
	pinOnly, removed, _ := ProjectToTarget(Body{Schema: 2, Features: map[string]bool{"guard": true}}, Target{Level: 3, MaxSchema: 2, KeyGen: 1})
	if len(removed) != 0 || !pinOnly.Features["guard"] {
		t.Errorf("a v1.31 feature must reach a v1.31 node: removed %v", removed)
	}
}

// TestProjectServedBody: nil when the node compiles the stored body as is
// (the stored envelope is served byte for byte), canonical otherwise.
func TestProjectServedBody(t *testing.T) {
	raw := []byte(`{"schema":3,"sections":{"hidden":["benchmarks"],"visible":["security"]}}`)
	if p, removed, err := ProjectServedBody(raw, 1<<16, CurrentTarget()); p != nil || removed != nil || err != nil {
		t.Fatalf("current target: %s %v %v, want nil", p, removed, err)
	}
	p, removed, err := ProjectServedBody(raw, 1<<16, LastUncappedTarget())
	if err != nil || string(p) != `{"schema":1,"sections":{"hidden":["benchmarks"]}}` || len(removed) != 2 {
		t.Fatalf("v1.34 target: %s %v %v", p, removed, err)
	}
	if _, _, err := ProjectServedBody([]byte(`{`), 1<<16, LastUncappedTarget()); err == nil {
		t.Fatal("an undecodable stored body must be an error")
	}
}

// TestIsVocabProjectionAcrossAxes: a body held after a schema or key
// projection is recognised once the node upgrades, so the full body at the
// same version is not refused as a replay.
func TestIsVocabProjectionAcrossAxes(t *testing.T) {
	full := Body{
		Schema:   3,
		Sections: SectionsV1{Hidden: []string{"benchmarks"}, Visible: []string{"security"}},
		Pinned:   map[string]any{"guard.enabled": true, "org_client.push_interval_seconds": int64(300)},
	}
	heldV134, _, _ := ProjectToTarget(full, LastUncappedTarget())
	heldSchema2, _, _ := ProjectToTarget(full, Target{Level: CurrentVocabLevel, MaxSchema: 2, KeyGen: CurrentKeyGen})
	heldKeys3, _, _ := ProjectToTarget(full, Target{Level: CurrentVocabLevel, MaxSchema: MaxSchema, KeyGen: 3})
	cases := []struct {
		name string
		held Body
		want bool
	}{
		{"held by a v1.34 node", heldV134, true},
		{"held by a schema-2 node", heldSchema2, true},
		{"held by a key-generation-3 node", heldKeys3, true},
		{"the full body itself", full, false},
		{"a looser body is not a projection", Body{Schema: 2, Sections: SectionsV1{Hidden: []string{"benchmarks"}}, Pinned: map[string]any{"guard.enabled": false}}, false},
	}
	for _, tc := range cases {
		if got := IsVocabProjection(full, tc.held); got != tc.want {
			t.Errorf("%s: IsVocabProjection = %v, want %v", tc.name, got, tc.want)
		}
	}
}
