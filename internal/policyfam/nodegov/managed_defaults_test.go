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
				if strings.Contains(r.Why, "—") || strings.Contains(r.OwnerWhy, "—") {
					t.Errorf("%s: no em dashes in copy", r.ID)
				}
				// The owner level is optional (empty = the team level), but
				// one that is set is a real level, and one that differs from
				// the team level says why.
				if r.Owner != "" && !IsVisibility(string(r.Owner)) {
					t.Errorf("%s: owner level %q is not a visibility", r.ID, r.Owner)
				}
				if r.Owner != "" && r.Owner != r.Level && strings.TrimSpace(r.OwnerWhy) == "" {
					t.Errorf("%s: an owner level that differs from the team level needs its own reason", r.ID)
				}
				if r.Owner == "" && r.OwnerWhy != "" {
					t.Errorf("%s: an owner reason without an owner level is never shown", r.ID)
				}
			}
		})
	}
}

// visibilityRank orders the three levels from most to least restrictive.
var visibilityRank = map[Visibility]int{VisibilityHidden: 0, VisibilityReadOnly: 1, VisibilityVisible: 2}

// TestManagedDefaultsOwnerNeverStricter: a machine its owner manages is never
// more restricted than a team member's on any row (the consent screen's
// "fewer than a team member's machine" relies on it), and it is strictly less
// restricted overall.
func TestManagedDefaultsOwnerNeverStricter(t *testing.T) {
	for _, rows := range [][]ManagedDefault{ManagedNavDefaults, ManagedSettingsDefaults} {
		for _, r := range rows {
			if visibilityRank[r.LevelFor(ManagedAudienceOwner)] < visibilityRank[r.LevelFor(ManagedAudienceTeam)] {
				t.Errorf("%s: owner level %q is stricter than the team level %q", r.ID, r.LevelFor(ManagedAudienceOwner), r.Level)
			}
		}
	}
	teamNav, teamSet := ManagedRestrictions(ManagedAudienceTeam)
	ownerNav, ownerSet := ManagedRestrictions(ManagedAudienceOwner)
	if len(ownerNav)+len(ownerSet) >= len(teamNav)+len(teamSet) {
		t.Fatalf("owner restrictions %d+%d are not fewer than the team's %d+%d", len(ownerNav), len(ownerSet), len(teamNav), len(teamSet))
	}
}

// TestManagedRestrictionsComeFromTheTable: the consent screen's lists are the
// table's non-visible rows for the audience, in table order, labelled by
// SectionLabel, and nothing else.
func TestManagedRestrictionsComeFromTheTable(t *testing.T) {
	for _, a := range []ManagedAudience{ManagedAudienceTeam, ManagedAudienceOwner} {
		nav, settings := ManagedRestrictions(a)
		for _, tc := range []struct {
			name string
			rows []ManagedDefault
			got  []ManagedRestriction
		}{{"nav", ManagedNavDefaults, nav}, {"settings", ManagedSettingsDefaults, settings}} {
			var want []ManagedRestriction
			for _, r := range tc.rows {
				if lvl := r.LevelFor(a); lvl != VisibilityVisible {
					want = append(want, ManagedRestriction{ID: r.ID, Label: SectionLabel(r.ID), Level: lvl})
				}
			}
			if len(tc.got) != len(want) {
				t.Fatalf("audience %q %s: %d restrictions, want %d", a, tc.name, len(tc.got), len(want))
			}
			for i := range want {
				if tc.got[i] != want[i] {
					t.Errorf("audience %q %s row %d: %+v, want %+v", a, tc.name, i, tc.got[i], want[i])
				}
			}
		}
	}
}

// TestManagedDefaultsRespectTheFloor: the T8 floor is visible by default, the
// same way no org body may hide or lock it.
func TestManagedDefaultsRespectTheFloor(t *testing.T) {
	for _, a := range []ManagedAudience{ManagedAudienceTeam, ManagedAudienceOwner} {
		for _, id := range UnhideableNavSectionIDs {
			if got := ManagedNavDefault(id, a); got != VisibilityVisible {
				t.Errorf("audience %q: nav %q defaults to %q, the floor must be visible", a, id, got)
			}
		}
		for _, id := range UnhideableSettingsSectionIDs {
			if got := ManagedSettingsDefault(id, a); got != VisibilityVisible {
				t.Errorf("audience %q: settings %q defaults to %q, the floor must be visible", a, id, got)
			}
		}
	}
}

// TestManagedDefaultsClassification pins the rows the operator ruling is
// about, one case per row and audience, so a reclassification is a reviewed
// diff. The team column is today's managed defaults byte-for-byte; the owner
// column is finding F12's (a personal organization of one keeps its own AI
// Apps pages, Routing and Policies, and the two Settings sections behind
// them).
func TestManagedDefaultsClassification(t *testing.T) {
	const (
		H = VisibilityHidden
		R = VisibilityReadOnly
		V = VisibilityVisible
	)
	nav := []struct {
		id          string
		team, owner Visibility
	}{
		{"overview", V, V},
		{"sessions", V, V},
		{"cost", V, V},
		{"terminals", V, V},
		{"privacy", V, V},
		{"settings", V, V},
		{"security", H, H},
		{"compression", R, R},
		{"remote", R, R},
		{"agent-config", R, R},
		// Code security is hidden by default like Guard's page (roadmap
		// section 8 item 4, lane gov-tabs); the organization exposes it.
		{"code-security", H, H},
		// F12: the owner's own pages. Egress joined them by operator ruling
		// R2 (2026-11-23): it sits in the Your AI apps group.
		{"egress", H, V},
		{"routing", H, V},
		{"policies", H, V},
		{"app-traces", H, V},
		{"app-sessions", H, V},
		{"app-analytics", H, V},
		{"app-end-users", H, V},
		{"app-evals", H, V},
		{"app-scores", H, V},
		{"app-prompts", H, V},
		{"app-alerts", H, V},
	}
	for _, tc := range nav {
		if got := ManagedNavDefault(tc.id, ManagedAudienceTeam); got != tc.team {
			t.Errorf("team nav %q: got %q, want %q", tc.id, got, tc.team)
		}
		if got := ManagedNavDefault(tc.id, ManagedAudienceOwner); got != tc.owner {
			t.Errorf("owner nav %q: got %q, want %q", tc.id, got, tc.owner)
		}
	}
	settings := []struct {
		id          string
		team, owner Visibility
	}{
		{"guard", H, H},
		{"otel", H, H},
		{"cloud", H, H},
		{"pricing", R, R},
		{"proxy", R, R},
		{"hooks", R, R},
		{"secrets", R, R},
		{"intel", R, R},
		{"enrolment", V, V},
		{"org", V, V},
		{"health", V, V},
		{"storage", V, V},
		{"terminal", V, V},
		// F12: the sections that configure the owner's own pages.
		{"routing", H, V},
		{"observability", H, V},
	}
	for _, tc := range settings {
		if got := ManagedSettingsDefault(tc.id, ManagedAudienceTeam); got != tc.team {
			t.Errorf("team settings %q: got %q, want %q", tc.id, got, tc.team)
		}
		if got := ManagedSettingsDefault(tc.id, ManagedAudienceOwner); got != tc.owner {
			t.Errorf("owner settings %q: got %q, want %q", tc.id, got, tc.owner)
		}
	}
	for _, a := range []ManagedAudience{ManagedAudienceTeam, ManagedAudienceOwner, "not-an-audience"} {
		if got := ManagedNavDefault("not-a-page", a); got != VisibilityVisible {
			t.Errorf("audience %q: an unknown id must default visible, got %q", a, got)
		}
	}
	// An audience this build does not know resolves the team level.
	if got := ManagedNavDefault("app-traces", "not-an-audience"); got != VisibilityHidden {
		t.Errorf("an unknown audience must resolve the team level, got %q", got)
	}
}

// TestAudienceFor: the one capability-to-audience mapping.
func TestAudienceFor(t *testing.T) {
	if AudienceFor(true) != ManagedAudienceOwner || AudienceFor(false) != ManagedAudienceTeam {
		t.Fatalf("AudienceFor(true)=%q AudienceFor(false)=%q", AudienceFor(true), AudienceFor(false))
	}
}

// TestVocabularyForPicksTheAudience: the admin vocabulary's managed default
// and reason follow the audience it is built for, and Vocabulary() is the
// team audience's.
func TestVocabularyForPicksTheAudience(t *testing.T) {
	team, owner, def := VocabularyFor(ManagedAudienceTeam), VocabularyFor(ManagedAudienceOwner), Vocabulary()
	find := func(rows []VocabSection, id string) VocabSection {
		for _, r := range rows {
			if r.ID == id {
				return r
			}
		}
		t.Fatalf("no vocabulary row %q", id)
		return VocabSection{}
	}
	for _, tc := range []struct {
		rows  func(Vocab) []VocabSection
		id    string
		table map[string]ManagedDefault
	}{
		{func(v Vocab) []VocabSection { return v.NavSections }, "app-traces", managedNavIndex},
		{func(v Vocab) []VocabSection { return v.NavSections }, "security", managedNavIndex},
		{func(v Vocab) []VocabSection { return v.SettingsSections }, "observability", managedSettingsIndex},
	} {
		row := tc.table[tc.id]
		for _, c := range []struct {
			v Vocab
			a ManagedAudience
		}{{team, ManagedAudienceTeam}, {def, ManagedAudienceTeam}, {owner, ManagedAudienceOwner}} {
			got := find(tc.rows(c.v), tc.id)
			if got.ManagedDefault != row.LevelFor(c.a) || got.ManagedWhy != row.WhyFor(c.a) {
				t.Errorf("audience %q %s: (%q, %q), want (%q, %q)", c.a, tc.id, got.ManagedDefault, got.ManagedWhy, row.LevelFor(c.a), row.WhyFor(c.a))
			}
		}
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
