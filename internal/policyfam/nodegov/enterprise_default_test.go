package nodegov

import (
	"encoding/json"
	"testing"
)

// enterprise_default_test.go pins the default enterprise body: that it
// COMPILES (the property the whole helper exists for), that the two budget
// pins are unconditional, that the share block follows the grant, and that the
// content tiers stay out of it.

// TestEnterpriseDefaultBodyCompilesThroughTheRealVocabulary is the load-bearing
// one: the body is produced through CanonicalJSON, which runs Compile, so a
// key that left PinnableKeys/ShareKeys fails HERE rather than as a 400 an
// admin meets while flipping their org's posture.
func TestEnterpriseDefaultBodyCompilesThroughTheRealVocabulary(t *testing.T) {
	t.Parallel()

	_, raw, err := EnterpriseDefaultBody(EnterpriseDefaultInput{
		GrantedAuthority: []string{
			"extract.routing", "extract.policy_state", "extract.predictions",
			"extract.tasks", "extract.tool_accounts",
		},
	})
	if err != nil {
		t.Fatalf("EnterpriseDefaultBody: %v", err)
	}
	// The bytes a caller publishes must survive the accept path unchanged.
	spec, canon, err := CompileBody(raw, 1<<20)
	if err != nil {
		t.Fatalf("CompileBody(default body): %v", err)
	}
	if string(canon) != string(raw) {
		t.Errorf("the default body is not canonical:\n got %s\nwant %s", raw, canon)
	}
	if spec.Pinned["guard.budget.from_org"] != true {
		t.Errorf("guard.budget.from_org did not survive compilation: %+v", spec.Pinned)
	}
	if spec.Pinned["guard.budget.hard"] != true {
		t.Errorf("guard.budget.hard did not survive compilation: %+v", spec.Pinned)
	}
}

// TestEnterpriseDefaultBodyTable walks the grant -> share-block relation.
func TestEnterpriseDefaultBodyTable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		authority  []string
		extra      map[string]any
		wantShare  []string
		wantAbsent []string
	}{
		{
			name:       "no authority: the budget pins still land, no share key does",
			authority:  nil,
			wantAbsent: []string{"routing_summary", "policy_state", "full_content"},
		},
		{
			name:       "one tier: only that tier is turned on",
			authority:  []string{"extract.routing"},
			wantShare:  []string{"routing_summary"},
			wantAbsent: []string{"policy_state", "limit_gauge"},
		},
		{
			name:      "the umbrella alias authorizes every tier in the table",
			authority: []string{"extract.managed"},
			wantShare: []string{
				"routing_summary", "policy_state", "limit_gauge",
				"task_detail", "tool_account_detail",
			},
			// Even under the umbrella, a DEFAULT body never turns on content.
			wantAbsent: []string{"full_content", "full_tool_bodies", "obs.content"},
		},
		{
			name:      "extra pins are merged UNDER the budget pins",
			authority: nil,
			extra: map[string]any{
				"guard.mode":            "enforce",
				"guard.budget.from_org": false,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body, _, err := EnterpriseDefaultBody(EnterpriseDefaultInput{
				GrantedAuthority: tc.authority, ExtraPins: tc.extra,
			})
			if err != nil {
				t.Fatalf("EnterpriseDefaultBody: %v", err)
			}
			if body.Pinned["guard.budget.from_org"] != true || body.Pinned["guard.budget.hard"] != true {
				t.Fatalf("the budget pins are not unconditional: %+v", body.Pinned)
			}
			for _, key := range tc.wantShare {
				if body.Share[key] != true {
					t.Errorf("share[%q] missing; got %+v", key, body.Share)
				}
			}
			for _, key := range tc.wantAbsent {
				if _, ok := body.Share[key]; ok {
					t.Errorf("share[%q] present and must not be; got %+v", key, body.Share)
				}
			}
			if tc.extra != nil && body.Pinned["guard.mode"] != "enforce" {
				t.Errorf("extra pins were dropped: %+v", body.Pinned)
			}
		})
	}
}

// TestEnterpriseDefaultTablesAreDocumented: every row carries its Why, so a
// future key cannot be added to a fleet-wide default without saying why it is
// there.
func TestEnterpriseDefaultTablesAreDocumented(t *testing.T) {
	t.Parallel()
	for _, p := range enterpriseDefaultPins {
		if p.Why == "" {
			t.Errorf("pin %q has no Why", p.Key)
		}
		if _, ok := pinnableByKey[p.Key]; !ok {
			t.Errorf("pin %q is not in PinnableKeys", p.Key)
		}
	}
	for _, s := range enterpriseDefaultShares {
		if s.Why == "" || s.Authority == "" {
			t.Errorf("share %q is missing a Why or an Authority", s.Key)
		}
		if _, ok := shareByKey[s.Key]; !ok {
			t.Errorf("share %q is not in ShareKeys", s.Key)
		}
	}
}

// TestEnterpriseDefaultBodyIsValidJSON guards the one thing a publisher does
// with the bytes: hand them to a decoder.
func TestEnterpriseDefaultBodyIsValidJSON(t *testing.T) {
	t.Parallel()
	_, raw, err := EnterpriseDefaultBody(EnterpriseDefaultInput{})
	if err != nil {
		t.Fatalf("EnterpriseDefaultBody: %v", err)
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("the default body is not valid JSON: %v", err)
	}
	if probe["schema"] != float64(MaxSchema) {
		t.Errorf("schema = %v, want %d", probe["schema"], MaxSchema)
	}
}
