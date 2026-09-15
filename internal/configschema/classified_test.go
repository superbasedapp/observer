package configschema

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
)

// TestEveryLeafKeyClassified is THE gate (plan §1.4 half 2): every leaf of
// the LIVE config.Config must resolve a tier, a restart class and a Settings
// section that is a member of nodegov.SettingsSectionIDs. An unclassified
// key fails the build, so adding a config block to Go without deciding its
// tier and restart semantics does not compile in CI — which is what keeps
// "every setting is manageable from the dashboard" true past the day it
// shipped.
func TestEveryLeafKeyClassified(t *testing.T) {
	leaves := Leaves()
	if len(leaves) < 400 {
		t.Fatalf("walk found only %d leaves — the reflect walk is broken", len(leaves))
	}
	validTier := map[Tier]bool{TierPlain: true, TierSensitive: true, TierSecret: true, TierOwnerElsewhere: true}
	validRestart := map[Restart]bool{RestartLive: true, RestartLivePersist: true, RestartNextSpawn: true, RestartRequired: true}
	validProm := map[Prominence]bool{ProminencePrimary: true, ProminenceAdvanced: true, ProminenceExpert: true}
	for _, l := range leaves {
		if !validTier[l.Tier] {
			t.Errorf("%s: no tier — add an annotation row (block rule or key rule) in annotations.go", l.Path)
		}
		if !validRestart[l.Restart] {
			t.Errorf("%s: no restart class — add an annotation row in annotations.go", l.Path)
		}
		if l.Section == "" {
			t.Errorf("%s: no Settings section — add a section rule in annotations.go", l.Path)
		} else if !nodegov.IsSettingsSection(l.Section) {
			t.Errorf("%s: section %q is not a member of nodegov.SettingsSectionIDs (closed org-facing vocabulary; map onto an existing id — plan §4.5)", l.Path, l.Section)
		}
		if !validProm[l.Prominence] {
			t.Errorf("%s: invalid prominence %q", l.Path, l.Prominence)
		}
		if l.Tier == TierOwnerElsewhere && l.OwnedBy == "" {
			t.Errorf("%s: owner-elsewhere leaf must name its owner (honest disabled copy)", l.Path)
		}
		if l.Secret != (l.Tier == TierSecret) {
			t.Errorf("%s: secret=%v but tier=%s", l.Path, l.Secret, l.Tier)
		}
		if l.Kind == KindTable && l.Tier != TierOwnerElsewhere && l.Tier != TierSecret {
			t.Errorf("%s: compound table must be owner-elsewhere (the generic route cannot write it)", l.Path)
		}
		if l.Deprecated != "" && l.Tier != TierOwnerElsewhere {
			t.Errorf("%s: deprecated alias must be read-only (owner-elsewhere)", l.Path)
		}
	}
}

// TestSecretLeavesAreExactlyTheT2Set pins the T2 membership: the four keys
// the plan names (§4.3), the browser listener token added at landing review
// (security ledger CFG-1), and [email].password. Growing this set is a
// security decision that must be visible in a diff of this test.
func TestSecretLeavesAreExactlyTheT2Set(t *testing.T) {
	want := map[string]bool{
		"selfobs.secret":             true,
		"selfobs.token":              true,
		"observer.process.etw.token": true,
		"browser.listener.token":     true,
		"routing.key_pool":           true,
		"email.password":             true,
	}
	got := map[string]bool{}
	for _, l := range Leaves() {
		if l.Secret {
			got[l.Path] = true
		}
	}
	for k := range want {
		if !got[k] {
			t.Errorf("expected T2 leaf %s is not marked secret", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("unexpected T2 leaf %s — if intended, add it to this test AND to dashboard/config_secrets.go's table", k)
		}
	}
}

// TestNoCredentialShapedKeyIsPlain is the belt to the T2 braces: a leaf
// whose NAME says it holds a credential must be secret, or be an `*_env` /
// `*_file` / `*_path` indirection (which names where a credential lives and
// is T1, per plan §4.3), or be explicitly listed as a known non-credential.
func TestNoCredentialShapedKeyIsPlain(t *testing.T) {
	knownNotCredential := map[string]bool{
		// A local DECISION (allow|flag|ask|deny), not a secret.
		"observability.admission.secret_remote_judge": true,
		// Toggle for the scrubber, not a secret.
		"observer.secrets.enable_scrubbing": true,
		"observer.secrets.extra_patterns":   true,
		// A key ID is an identifier, never key material.
		"selfobs.key_id": true,
	}
	for _, l := range Leaves() {
		last := l.Path[strings.LastIndex(l.Path, ".")+1:]
		shaped := last == "secret" || strings.HasSuffix(last, "_secret") || last == "token" || strings.HasSuffix(last, "_token") ||
			strings.Contains(last, "password") || strings.Contains(last, "api_key") || last == "key_pool"
		if !shaped || knownNotCredential[l.Path] {
			continue
		}
		indirection := strings.HasSuffix(last, "_env") || strings.HasSuffix(last, "_file") || strings.HasSuffix(last, "_path")
		if indirection {
			if l.Tier == TierPlain {
				t.Errorf("%s names where a credential lives and must be at least sensitive", l.Path)
			}
			continue
		}
		if !l.Secret {
			t.Errorf("%s looks like a credential but is tier %s — mark it secret or list it as a known non-credential", l.Path, l.Tier)
		}
	}
}

// TestEveryBlockHasABlockRule makes the "new block forces a decision"
// property explicit: each top-level block must be matched by a rule whose
// prefix IS the block, carrying tier + restart + section.
func TestEveryBlockHasABlockRule(t *testing.T) {
	for _, b := range Blocks() {
		var found bool
		for _, r := range rules {
			if r.prefix == b && !r.exact && r.tier != "" && r.restart != "" && r.section != "" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("block %q has no block-level rule carrying tier + restart + section", b)
		}
	}
}

// TestRulesNameRealKeys guards the table against typos: every rule prefix
// must match at least one live leaf, otherwise it silently protects nothing.
func TestRulesNameRealKeys(t *testing.T) {
	for _, r := range rules {
		var hit bool
		for _, l := range Leaves() {
			if r.matches(l.Path) {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("rule prefix %q (exact=%v) matches no config key — stale row or typo", r.prefix, r.exact)
		}
	}
}

// TestLookupAndFieldPaths spot-checks the walk against known keys, including
// the nested-table and json-tag cases.
func TestLookupAndFieldPaths(t *testing.T) {
	cases := []struct {
		path, fieldPath string
		kind            Kind
		block, table    string
	}{
		{"observer.watch.poll_interval_seconds", "Observer.Watch.PollIntervalSeconds", KindInt, "observer", "observer.watch"},
		{"observer.log_level", "Observer.LogLevel", KindString, "observer", "observer"},
		{"terminal.launch.allowed_tools", "Terminal.Launch.AllowedTools", KindStringList, "terminal", "terminal.launch"},
		{"profiles.by_tool", "Profiles.ByTool", KindStringMap, "profiles", "profiles"},
		{"intelligence.pricing.models", "Intelligence.Pricing.Models", KindTable, "intelligence", "intelligence.pricing"},
		{"experiments", "Experiments", KindTable, "experiments", ""},
		{"compression.conversation.target_ratio", "Compression.Conversation.TargetRatio", KindFloat, "compression", "compression.conversation"},
		{"email.password", "Email.Cred", KindString, "email", "email"},
	}
	for _, c := range cases {
		l, ok := Lookup(c.path)
		if !ok {
			t.Errorf("Lookup(%q): not found", c.path)
			continue
		}
		if l.FieldPath != c.fieldPath || l.Kind != c.kind || l.Block != c.block || l.Table != c.table {
			t.Errorf("Lookup(%q) = {field %s kind %s block %s table %s}; want {%s %s %s %s}",
				c.path, l.FieldPath, l.Kind, l.Block, l.Table, c.fieldPath, c.kind, c.block, c.table)
		}
	}
	if _, ok := Lookup("observer.nope"); ok {
		t.Error("Lookup of an unknown key must fail")
	}
	if _, ok := Lookup("observer.watch"); ok {
		t.Error("Lookup of a table path must fail (tables are not leaves)")
	}
}
