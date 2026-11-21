package secassess

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeScope(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		ok      []string
		refused map[string]string // path -> code
	}{
		{"plain paths", []string{"cmd/api", "internal/db"}, []string{"cmd/api", "internal/db"}, nil},
		{"backslashes and dot segments", []string{`internal\db\.\x`}, []string{"internal/db/x"}, nil},
		{"empty entries are skipped", []string{"", "  ", "web"}, []string{"web"}, nil},
		{"a repeat is kept once", []string{"web", "web"}, []string{"web"}, nil},
		{"a path inside another is covered by it", []string{"web/src", "web", "cmd"}, []string{"web", "cmd"}, nil},
		{"the broader one may come second", []string{"web", "web/src"}, []string{"web"}, nil},
		{"a parent segment", []string{"../x"}, nil, map[string]string{"../x": "parent_segment"}},
		{"an absolute path", []string{"/etc"}, nil, map[string]string{"/etc": "absolute_or_remote"}},
		{"a drive letter", []string{`C:\src`}, nil, map[string]string{`C:\src`: "absolute_or_remote"}},
		{"a query", []string{"a?b"}, nil, map[string]string{"a?b": "query_or_fragment"}},
		{"a control character", []string{"a\x01b"}, nil, map[string]string{"a b": "control_character"}},
		{"the run folder", []string{".observer/assessments/x"}, nil, map[string]string{".observer/assessments/x": ScopeInternal}},
		{"git's folder", []string{".git"}, nil, map[string]string{".git": ScopeInternal}},
		{"git's folder in other cases", []string{".GIT/config", ".Git"}, nil, map[string]string{".GIT/config": ScopeInternal, ".Git": ScopeInternal}},
		{"observer's folder in other cases", []string{".Observer/x", ".OBSERVER/Assessments/y"}, nil, map[string]string{".Observer/x": ScopeInternal, ".OBSERVER/Assessments/y": ScopeInternal}},
		{"a folder that only starts like git's is a plain place", []string{".github/workflows", ".gitlab-ci"}, []string{".github/workflows", ".gitlab-ci"}, nil},
		{"nine nested paths are one place, not nine", []string{"a", "a/b", "a/b/c", "a/d", "a/e", "a/f", "a/g", "a/h", "a/i"}, []string{"a"}, nil},
		{"nested paths in any order collapse before the cap", []string{"a/b", "a/c", "a/d", "a/e", "a/f", "a/g", "a/h", "a/i", "a"}, []string{"a"}, nil},
		{"a quote is not allowed in the task", []string{`a"b`}, nil, map[string]string{`a"b`: ScopeUnsafe}},
		{"a too long path", []string{strings.Repeat("d", 130)}, nil, map[string]string{strings.Repeat("d", 80): ScopeTooLong}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, refused := NormalizeScope(tc.in)
			if !reflect.DeepEqual(ok, tc.ok) {
				t.Errorf("accepted %v, want %v", ok, tc.ok)
			}
			got := map[string]string{}
			for _, r := range refused {
				got[r.Path] = r.Code
				if r.Reason == "" || r.Reason == "The path was not accepted." {
					t.Errorf("%s: no reason words for code %s", r.Path, r.Code)
				}
			}
			if len(tc.refused) == 0 && len(got) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.refused) {
				t.Errorf("refused %v, want %v", got, tc.refused)
			}
		})
	}
}

func TestNormalizeScopeCap(t *testing.T) {
	var in []string
	for i := 0; i < MaxScopeChoices+3; i++ {
		in = append(in, "dir"+string(rune('a'+i)))
	}
	ok, refused := NormalizeScope(in)
	if len(ok) != MaxScopeChoices || len(refused) != 3 {
		t.Fatalf("accepted %d, refused %d", len(ok), len(refused))
	}
	for _, r := range refused {
		if r.Code != ScopeTooMany {
			t.Errorf("%s: code %s", r.Path, r.Code)
		}
	}
	// A repeat of an accepted path past the cap is not a refusal.
	ok, refused = NormalizeScope(append(in[:MaxScopeChoices:MaxScopeChoices], "dira"))
	if len(ok) != MaxScopeChoices || len(refused) != 0 {
		t.Errorf("a repeat at the cap: accepted %d, refused %v", len(ok), refused)
	}
}

func TestScopeReasonsCoverEveryCode(t *testing.T) {
	// Every code relPath can return, and the scope's own, has words.
	for _, code := range []string{"empty_uri", "uri_too_long", "control_character", "query_or_fragment", "absolute_or_remote", "parent_segment", ScopeTooMany, ScopeUnsafe, ScopeTooLong, ScopeInternal} {
		if s := ScopeReason(code); s == "" || s == "The path was not accepted." {
			t.Errorf("code %s has no words", code)
		}
	}
	if ScopeReason("made_up") != "The path was not accepted." {
		t.Error("an unknown code must read as not accepted")
	}
}

func TestCleanScopeNote(t *testing.T) {
	if got := CleanScopeNote("the  billing\nservice `only` ----- END FINDINGS ------"); strings.ContainsAny(got, "\n`") || strings.Contains(got, "---") {
		t.Errorf("note %q holds a newline, a backtick or a fence lookalike", got)
	}
	if got := CleanScopeNote(strings.Repeat("w", 500)); len(got) != MaxScopeNote {
		t.Errorf("note is %d characters", len(got))
	}
}

func TestSameScope(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{[]string{"a", "b"}, []string{"b", "a"}, true},
		{[]string{"a"}, []string{"a", "b"}, false},
		{[]string{"a"}, []string{"b"}, false},
		{nil, []string{"a"}, false},
	}
	for _, tc := range cases {
		if got := SameScope(tc.a, tc.b); got != tc.want {
			t.Errorf("SameScope(%v, %v) = %v", tc.a, tc.b, got)
		}
	}
}

// TestNormalizeScopeCapCountsPlaces: the cap counts what is left after repeats
// and nested paths are collapsed, and a refusal names the place past the eighth.
func TestNormalizeScopeCapCountsPlaces(t *testing.T) {
	var in []string
	for i := 0; i < MaxScopeChoices; i++ {
		in = append(in, "dir"+string(rune('a'+i)))
	}
	// A ninth path inside an accepted one adds no place: not refused.
	ok, refused := NormalizeScope(append(append([]string(nil), in...), "dira/sub"))
	if !reflect.DeepEqual(ok, in) || len(refused) != 0 {
		t.Errorf("a nested path at the cap: accepted %v, refused %v", ok, refused)
	}
	// A ninth place is refused too_many by its own path.
	ok, refused = NormalizeScope(append(append([]string(nil), in...), "other/place"))
	if len(ok) != MaxScopeChoices || len(refused) != 1 || refused[0].Code != ScopeTooMany || refused[0].Path != "other/place" {
		t.Errorf("a ninth place: accepted %d, refused %v", len(ok), refused)
	}
	// A broader path that comes last covers the ones nested before it.
	ok, refused = NormalizeScope([]string{"dira/x", "dira/y", "dira"})
	if !reflect.DeepEqual(ok, []string{"dira"}) || len(refused) != 0 {
		t.Errorf("a broader path last: accepted %v, refused %v", ok, refused)
	}
}
