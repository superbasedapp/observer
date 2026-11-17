package nodegov

import (
	"strings"
	"testing"
)

// TestScopeRaiseDirectiveRows pins R3-85's vocabulary: the two project-scope
// raise directives are ShareKeys rows with their OWN kinds (not the list
// fields they act on), served as managed_raise_only, accepted only with a
// value that raises, and projected away for a build that predates them.
func TestScopeRaiseDirectiveRows(t *testing.T) {
	rows := []struct {
		key        string
		kind       string
		raise      ShareRaise
		configKind string
	}{
		{"scope.unrestricted", "bool", ShareRaiseScopeUnrestricted, "string_list"},
		{"scope.denylist_remove", "string_list", ShareRaiseScopeDenylistRemoval, "string_list"},
	}
	vocab := map[string]VocabShareKey{}
	for _, k := range Vocabulary().ShareKeys {
		vocab[k.Key] = k
	}
	for _, r := range rows {
		row, ok := LookupShareKey(r.key)
		if !ok {
			t.Fatalf("%s is not in ShareKeys", r.key)
		}
		if row.Kind != r.kind || row.Raise != r.raise || row.ConfigFieldKind() != r.configKind {
			t.Errorf("%s = kind %q raise %q config kind %q, want %q %q %q", r.key, row.Kind, row.Raise, row.ConfigFieldKind(), r.kind, r.raise, r.configKind)
		}
		if v := vocab[r.key]; v.Direction != ShareDirectionManagedRaise || v.Help == "" {
			t.Errorf("served %s = %+v, want direction %q with help", r.key, v, ShareDirectionManagedRaise)
		}
		if ShareKeySince(r.key) != CurrentKeyGen {
			t.Errorf("%s joined at generation %d, want %d", r.key, ShareKeySince(r.key), CurrentKeyGen)
		}
	}
	// Every tier row stays lowering_only.
	for _, k := range Vocabulary().ShareKeys {
		row, _ := LookupShareKey(k.Key)
		if row.Raise == "" && k.Direction != string(DirLoweringOnly) {
			t.Errorf("tier %s served as %q", k.Key, k.Direction)
		}
	}
}

// TestScopeRaiseDirectiveValues is the compile table: a raise directive takes
// only a value that raises.
func TestScopeRaiseDirectiveValues(t *testing.T) {
	cases := []struct {
		name    string
		share   map[string]any
		wantErr string
	}{
		{"unrestricted true", map[string]any{"scope.unrestricted": true}, ""},
		{"unrestricted false", map[string]any{"scope.unrestricted": false}, "raise directive"},
		{"unrestricted as a list", map[string]any{"scope.unrestricted": []any{"/w"}}, "share.scope.unrestricted"},
		{"denylist removal list", map[string]any{"scope.denylist_remove": []any{"/w/vendor", "/w/tmp"}}, ""},
		{"denylist removal empty", map[string]any{"scope.denylist_remove": []any{}}, "raise directive"},
		{"denylist removal as a bool", map[string]any{"scope.denylist_remove": true}, "share.scope.denylist_remove"},
		{"the old field-shaped key", map[string]any{"scope.project_root_allowlist": true}, "not an organization-directable sharing key"},
		{"a tier may still be false", map[string]any{"full_content": false}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := Compile(PolicyInput{Share: tc.share})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Compile: %v", err)
				}
				if len(spec.Share) != len(tc.share) {
					t.Fatalf("share = %v", spec.Share)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Compile error = %v, want one naming %q", err, tc.wantErr)
			}
		})
	}
}

// TestScopeRaiseDirectivesProjectAwayForOlderBuilds: a generation-5 node
// (v1.37.x) is served the body without the two keys rather than refusing it.
func TestScopeRaiseDirectivesProjectAwayForOlderBuilds(t *testing.T) {
	b := Body{Schema: 2, Share: map[string]any{
		"scope.unrestricted": true, "scope.denylist_remove": []string{"/w"}, "full_content": false,
	}}
	old := CurrentTarget()
	old.KeyGen = 5
	got, _, err := ProjectToTarget(b, old)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Share["scope.unrestricted"]; ok {
		t.Fatalf("a generation-5 node was served scope.unrestricted: %v", got.Share)
	}
	if _, ok := got.Share["scope.denylist_remove"]; ok {
		t.Fatalf("a generation-5 node was served scope.denylist_remove: %v", got.Share)
	}
	if _, ok := got.Share["full_content"]; !ok {
		t.Fatalf("the projection dropped a tier the older node knows: %v", got.Share)
	}
}
