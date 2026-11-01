package orgcontract

import (
	"strings"
	"testing"
)

func TestValidProjectSectionStatus(t *testing.T) {
	many := make([]ProjectSectionState, MaxProjectMappingProjects+1)
	for i := range many {
		many[i] = ProjectSectionState{OrgProjectID: "p" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + string(rune('a'+i/26)), Status: ProjectSectionApplied}
	}
	cases := []struct {
		name string
		list []ProjectSectionState
		want bool
	}{
		{"nil is nothing reported", nil, true},
		{"every status", []ProjectSectionState{
			{"a", ProjectSectionApplied}, {"b", ProjectSectionNotMatched}, {"c", ProjectSectionUnknown}, {"d", ProjectSectionNotDelivered},
		}, true},
		{"unknown status", []ProjectSectionState{{"a", "matched"}}, false},
		{"empty id", []ProjectSectionState{{"", ProjectSectionApplied}}, false},
		{"duplicate id", []ProjectSectionState{{"a", ProjectSectionApplied}, {"a", ProjectSectionUnknown}}, false},
		{"a path is not an id", []ProjectSectionState{{"/home/dev/repo x", ProjectSectionApplied}}, false},
		{"overlong id", []ProjectSectionState{{strings.Repeat("a", MaxProjectIDLen+1), ProjectSectionApplied}}, false},
		{"too many entries", many, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidProjectSectionStatus(tc.list); got != tc.want {
				t.Fatalf("ValidProjectSectionStatus = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProjectSectionAcked(t *testing.T) {
	for status, want := range map[string]bool{
		ProjectSectionApplied: true, ProjectSectionNotMatched: true,
		ProjectSectionUnknown: false, ProjectSectionNotDelivered: false, "bogus": false,
	} {
		if got := ProjectSectionAcked(status); got != want {
			t.Errorf("ProjectSectionAcked(%q) = %v, want %v", status, got, want)
		}
	}
}
