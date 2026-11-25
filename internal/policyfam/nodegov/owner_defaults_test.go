package nodegov

import (
	"slices"
	"testing"
)

// TestStateAudienceDefaults pins the statement table: for the owner audience
// every id whose owner level differs from the team level is stated in the
// list of its owner level, an id the body already names keeps the body's
// level, and the team audience states nothing.
func TestStateAudienceDefaults(t *testing.T) {
	var wantNav, wantSettings []string
	for _, r := range ManagedNavDefaults {
		if r.LevelFor(ManagedAudienceOwner) != r.Level {
			wantNav = append(wantNav, r.ID)
		}
	}
	for _, r := range ManagedSettingsDefaults {
		if r.LevelFor(ManagedAudienceOwner) != r.Level {
			wantSettings = append(wantSettings, r.ID)
		}
	}
	slices.Sort(wantNav)
	slices.Sort(wantSettings)

	t.Run("empty body, owner: every differing id is exposed", func(t *testing.T) {
		got, added := StateAudienceDefaults(Body{Schema: 1}, ManagedAudienceOwner)
		if !slices.Equal(got.Sections.Visible, wantNav) || !slices.Equal(got.Sections.SettingsVisible, wantSettings) {
			t.Fatalf("visible %v / settings_visible %v, want %v / %v", got.Sections.Visible, got.Sections.SettingsVisible, wantNav, wantSettings)
		}
		if len(got.Sections.Hidden)+len(got.Sections.ReadOnly)+len(got.Sections.SettingsHidden)+len(got.Sections.SettingsReadOnly) != 0 {
			t.Fatalf("the owner column restricts nothing, yet the body hides or locks: %+v", got.Sections)
		}
		if got.Schema != 3 || len(added) != len(wantNav)+len(wantSettings) {
			t.Fatalf("schema %d, %d added, want 3 and %d", got.Schema, len(added), len(wantNav)+len(wantSettings))
		}
		// The stated body compiles: no floor id, no unknown id, no id in
		// two lists.
		if _, err := Compile(PolicyInput{
			HiddenSections: got.Sections.Hidden, ReadOnlySections: got.Sections.ReadOnly, VisibleSections: got.Sections.Visible,
			HiddenSettings: got.Sections.SettingsHidden, ReadOnlySettings: got.Sections.SettingsReadOnly, VisibleSettings: got.Sections.SettingsVisible,
		}); err != nil {
			t.Fatalf("the stated body does not compile: %v", err)
		}
	})

	t.Run("an org directive wins over the statement", func(t *testing.T) {
		in := Body{Schema: 1, Sections: SectionsV1{
			ReadOnly: []string{"security"}, SettingsHidden: []string{"otel"}, Hidden: []string{"routing"},
		}}
		got, added := StateAudienceDefaults(in, ManagedAudienceOwner)
		for _, id := range []string{"security", "routing"} {
			if slices.Contains(got.Sections.Visible, id) {
				t.Errorf("page %q the org named was restated visible", id)
			}
		}
		if slices.Contains(got.Sections.SettingsVisible, "otel") {
			t.Error("settings otel the org hid was restated visible")
		}
		// The Settings "routing" section is a different id from the page.
		if !slices.Contains(got.Sections.SettingsVisible, "routing") {
			t.Error("settings routing was not stated though only the page is named")
		}
		if !slices.Equal(got.Sections.ReadOnly, []string{"security"}) || !slices.Equal(got.Sections.SettingsHidden, []string{"otel"}) {
			t.Errorf("the org's own lists changed: %+v", got.Sections)
		}
		if slices.Contains(added, "security") || slices.Contains(added, "settings:otel") || !slices.Contains(added, "settings:routing") {
			t.Errorf("added %v", added)
		}
		// The input is not modified.
		if len(in.Sections.Visible) != 0 || len(in.Sections.SettingsVisible) != 0 {
			t.Errorf("the input body was modified: %+v", in.Sections)
		}
	})

	t.Run("team audience: nothing stated, body unchanged", func(t *testing.T) {
		in := Body{Schema: 2, Pinned: map[string]any{"guard.enabled": true}}
		for _, a := range []ManagedAudience{ManagedAudienceTeam, "not-an-audience"} {
			got, added := StateAudienceDefaults(in, a)
			if added != nil || got.Schema != 2 || len(got.Sections.Visible) != 0 {
				t.Errorf("audience %q stated %v (schema %d)", a, added, got.Schema)
			}
		}
	})

	t.Run("everything already named: nothing added, schema kept", func(t *testing.T) {
		in := Body{Schema: 3, Sections: SectionsV1{Visible: wantNav, SettingsVisible: wantSettings}}
		got, added := StateAudienceDefaults(in, ManagedAudienceOwner)
		if added != nil || got.Schema != 3 {
			t.Fatalf("added %v schema %d", added, got.Schema)
		}
	})
}

// TestOwnerStatementCoversEveryOlderBuild is the coverage argument ruling 3
// rests on: a released build's team column only ever grew, so every id today's
// team column restricts is a superset of what an older build restricts, and
// stating the owner level for every one of them leaves an older build nothing
// hidden or read-only that the owner audience shows.
func TestOwnerStatementCoversEveryOlderBuild(t *testing.T) {
	got, _ := StateAudienceDefaults(Body{Schema: 1}, ManagedAudienceOwner)
	exposed := map[string]bool{}
	for _, id := range got.Sections.Visible {
		exposed[id] = true
	}
	for _, id := range got.Sections.SettingsVisible {
		exposed["settings:"+id] = true
	}
	for _, r := range ManagedNavDefaults {
		if r.Level != VisibilityVisible && !exposed[r.ID] {
			t.Errorf("page %q is restricted for a team member but not stated for the owner", r.ID)
		}
	}
	for _, r := range ManagedSettingsDefaults {
		if r.Level != VisibilityVisible && !exposed["settings:"+r.ID] {
			t.Errorf("settings %q is restricted for a team member but not stated for the owner", r.ID)
		}
	}
}
