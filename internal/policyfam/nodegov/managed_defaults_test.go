package nodegov

import (
	"strings"
	"testing"
)

// TestManagedDefaultsCoverVocabularyExactlyOnce pins the two default tables to
// the closed vocabularies: every page and Settings section has exactly one
// row, in vocabulary order, with a valid level and a reason. A page added to
// nav.ts (and so to NavSectionIDs by vocab_source_test.go) without a managed
// classification fails HERE, not silently as "visible" on a managed fleet.
func TestManagedDefaultsCoverVocabularyExactlyOnce(t *testing.T) {
	for _, tc := range []struct {
		name  string
		vocab []string
		rows  []ManagedDefault
	}{
		{"nav", NavSectionIDs, ManagedNavDefaults},
		{"settings", SettingsSectionIDs, ManagedSettingsDefaults},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.rows) != len(tc.vocab) {
				t.Fatalf("%d default rows for %d vocabulary ids", len(tc.rows), len(tc.vocab))
			}
			for i, id := range tc.vocab {
				r := tc.rows[i]
				if r.ID != id {
					t.Errorf("row %d is %q, vocabulary order says %q", i, r.ID, id)
				}
				if !IsVisibility(string(r.Level)) {
					t.Errorf("%s: level %q is not a visibility", r.ID, r.Level)
				}
				if strings.TrimSpace(r.Why) == "" {
					t.Errorf("%s: a default needs a reason", r.ID)
				}
				if strings.Contains(r.Why, "—") {
					t.Errorf("%s: no em dashes in copy", r.ID)
				}
			}
		})
	}
}

// TestManagedDefaultsRespectTheFloor: the T8 floor is visible by default, the
// same way no org body may hide or lock it.
func TestManagedDefaultsRespectTheFloor(t *testing.T) {
	for _, id := range UnhideableNavSectionIDs {
		if got := ManagedNavDefault(id); got != VisibilityVisible {
			t.Errorf("nav %q defaults to %q, the floor must be visible", id, got)
		}
	}
	for _, id := range UnhideableSettingsSectionIDs {
		if got := ManagedSettingsDefault(id); got != VisibilityVisible {
			t.Errorf("settings %q defaults to %q, the floor must be visible", id, got)
		}
	}
}

// TestManagedDefaultsClassification pins the rows the operator ruling is
// about, one case per row, so a reclassification is a reviewed diff.
func TestManagedDefaultsClassification(t *testing.T) {
	nav := map[string]Visibility{
		"overview": VisibilityVisible, "sessions": VisibilityVisible, "cost": VisibilityVisible,
		"terminals": VisibilityVisible, "privacy": VisibilityVisible, "settings": VisibilityVisible,
		"security": VisibilityHidden, "egress": VisibilityHidden, "routing": VisibilityHidden,
		"policies": VisibilityHidden, "compression": VisibilityReadOnly, "remote": VisibilityReadOnly,
		// Code security is hidden by default like Guard's page (roadmap
		// section 8 item 4, lane gov-tabs); the organization exposes it.
		"code-security": VisibilityHidden,
	}
	for id, want := range nav {
		if got := ManagedNavDefault(id); got != want {
			t.Errorf("nav %q: got %q, want %q", id, got, want)
		}
	}
	settings := map[string]Visibility{
		"guard": VisibilityHidden, "routing": VisibilityHidden, "otel": VisibilityHidden,
		"observability": VisibilityHidden, "pricing": VisibilityReadOnly, "proxy": VisibilityReadOnly,
		"hooks": VisibilityReadOnly, "secrets": VisibilityReadOnly, "cloud": VisibilityHidden, "intel": VisibilityReadOnly,
		"enrolment": VisibilityVisible, "org": VisibilityVisible, "health": VisibilityVisible,
		"storage": VisibilityVisible, "terminal": VisibilityVisible,
	}
	for id, want := range settings {
		if got := ManagedSettingsDefault(id); got != want {
			t.Errorf("settings %q: got %q, want %q", id, got, want)
		}
	}
	if got := ManagedNavDefault("not-a-page"); got != VisibilityVisible {
		t.Errorf("an unknown id must default visible, got %q", got)
	}
}

func TestSchemaFor(t *testing.T) {
	for _, tc := range []struct {
		name string
		body Body
		want int
	}{
		{"empty", Body{}, 1},
		{"sections only", Body{Sections: SectionsV1{Hidden: []string{"remote"}}}, 1},
		{"pinned", Body{Pinned: map[string]any{"guard.enabled": true}}, 2},
		{"share", Body{Share: map[string]any{"routing_summary": true}}, 2},
		{"visible", Body{Sections: SectionsV1{Visible: []string{"security"}}}, 3},
		{"settings visible", Body{Sections: SectionsV1{SettingsVisible: []string{"guard"}}}, 3},
	} {
		if got := SchemaFor(tc.body); got != tc.want {
			t.Errorf("%s: SchemaFor = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestDecodeBodyExposeListsNeedSchema3(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     string
		wantErr string
	}{
		{"visible at schema 2", `{"schema":2,"sections":{"visible":["security"]}}`, "requires schema 3"},
		{"settings_visible at schema 1", `{"schema":1,"sections":{"settings_visible":["guard"]}}`, "requires schema 3"},
		{"visible at schema 3", `{"schema":3,"sections":{"visible":["security"],"settings_visible":["guard"]}}`, ""},
		{"schema 4 refused", `{"schema":4}`, "understands up to 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeBody([]byte(tc.raw), 1<<16)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestCompileExposeLists(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      PolicyInput
		wantErr string
	}{
		{"expose a page", PolicyInput{VisibleSections: []string{"security", "routing"}}, ""},
		{"expose and hide the same page", PolicyInput{HiddenSections: []string{"security"}, VisibleSections: []string{"security"}}, "exactly one of"},
		{"expose and lock the same section", PolicyInput{ReadOnlySettings: []string{"guard"}, VisibleSettings: []string{"guard"}}, "exactly one of"},
		{"unknown page", PolicyInput{VisibleSections: []string{"nope"}}, "not a known nav section"},
		{"floor page", PolicyInput{VisibleSections: []string{"privacy"}}, "can never be hidden"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := Compile(tc.in)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(spec.VisibleSections) != len(tc.in.VisibleSections) {
					t.Fatalf("visible = %v", spec.VisibleSections)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// TestExposeListsRoundTripAndHash: the expose lists survive canonicalization
// and change the content hash (a body that only exposes a page is a different
// policy from an empty one).
func TestExposeListsRoundTripAndHash(t *testing.T) {
	raw := []byte(`{"schema":3,"sections":{"visible":["security"],"settings_visible":["guard"]}}`)
	spec, canon, err := CompileBody(raw, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeBody(canon, 1<<16)
	if err != nil {
		t.Fatalf("canonical body does not decode: %v (%s)", err, canon)
	}
	if len(back.Sections.Visible) != 1 || len(back.Sections.SettingsVisible) != 1 || back.Schema != 3 {
		t.Fatalf("round trip lost the expose lists: %s", canon)
	}
	empty, err := Compile(PolicyInput{})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Hash == empty.Hash {
		t.Fatal("an exposing body hashes like an empty one")
	}
}

// TestEnterpriseDefaultBodyStaysSchema2: the automatic enterprise body must
// not jump to schema 3 just because this build understands it; that would
// strand every pre-3 managed agent on decode_failed.
func TestEnterpriseDefaultBodyStaysSchema2(t *testing.T) {
	body, _, err := EnterpriseDefaultBody(EnterpriseDefaultInput{GrantedAuthority: []string{"extract.managed"}})
	if err != nil {
		t.Fatal(err)
	}
	if body.Schema != 2 {
		t.Fatalf("enterprise default body schema = %d, want 2", body.Schema)
	}
}
