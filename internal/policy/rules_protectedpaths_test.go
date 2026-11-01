package policy

import (
	"testing"
	"time"
)

// TestR166ProtectedPaths: R-166 is inert by default and, with path classes
// configured, flags in observe and denies in enforce a write to a protected
// test, CI or coverage path, by a file tool or a shell command. One case
// per table class plus the inert and the read cases.
func TestR166ProtectedPaths(t *testing.T) {
	const home, root = "/home/u", "/home/u/proj"
	cases := []struct {
		name       string
		classes    []string
		kind       EventKind
		actionType string
		target     string
		want       bool
	}{
		{"off by default", nil, KindFileAccess, "edit_file", root + "/tests/test_auth.py", false},
		{"test file edit", []string{"tests"}, KindFileAccess, "edit_file", root + "/tests/test_auth.py", true},
		{"go test write", []string{"tests"}, KindFileAccess, "write_file", root + "/internal/x/x_test.go", true},
		{"jest config", []string{"tests"}, KindFileAccess, "edit_file", root + "/jest.config.ts", true},
		{"workflow edit", []string{"ci"}, KindFileAccess, "edit_file", root + "/.github/workflows/ci.yml", true},
		{"coverage threshold", []string{"coverage"}, KindFileAccess, "edit_file", root + "/.coveragerc", true},
		{"class not chosen", []string{"ci"}, KindFileAccess, "edit_file", root + "/tests/test_auth.py", false},
		{"a read is fine", []string{"tests", "ci"}, KindFileAccess, "read_file", root + "/tests/test_auth.py", false},
		{"ordinary source", []string{"tests", "ci", "coverage"}, KindFileAccess, "edit_file", root + "/src/latest.java", false},
		{"shell delete of a test", []string{"tests"}, KindShellExec, "run_command", "rm tests/test_auth.py", true},
		{"shell write to a workflow", []string{"ci"}, KindShellExec, "run_command", "echo 'on: push' > .github/workflows/x.yml", true},
		{"shell read of a test", []string{"tests"}, KindShellExec, "run_command", "cat tests/test_auth.py", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev := Event{
				Kind: tc.kind, ActionType: tc.actionType, Target: tc.target,
				Cwd: root, ProjectRoot: root, SessionID: "s1",
				Now: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC),
			}
			for _, mode := range []Mode{ModeObserve, ModeEnforce} {
				e, err := New(Config{Mode: mode, Home: home, ProtectedPathClasses: tc.classes})
				if err != nil {
					t.Fatal(err)
				}
				v := e.Evaluate(ev)
				hit := v.RuleID == "R-166"
				if hit != tc.want {
					t.Fatalf("%s: rule %s (%s), want R-166 hit %v", mode, v.RuleID, v.Reason, tc.want)
				}
				if !hit {
					continue
				}
				want := DecisionFlag
				if mode == ModeEnforce {
					want = DecisionDeny
				}
				if v.Decision != want {
					t.Errorf("%s: decision %s, want %s", mode, v.Decision, want)
				}
			}
		})
	}
}

// TestR166MatchesProjectRelativePaths (plans decision log P-004): R-166
// judges a path by its place in the project, so a project that lives under
// a folder named test, tests or spec is not wholly protected; a path
// outside the project is judged by its file name only.
func TestR166MatchesProjectRelativePaths(t *testing.T) {
	const home, root = "/home/u", "/home/u/test/proj"
	cases := []struct {
		name, kind, target string
		want               bool
	}{
		{"source in a project under ~/test", "edit_file", root + "/src/main.go", false},
		{"README in a project under ~/test", "write_file", root + "/README.md", false},
		{"a test inside that project", "edit_file", root + "/tests/test_auth.py", true},
		{"a workflow inside that project", "edit_file", root + "/.github/workflows/ci.yml", true},
		{"outside the project, a test file name", "edit_file", "/home/u/other/pkg/x_test.go", true},
		{"outside the project, a source file under a test folder", "edit_file", "/home/u/spec/other/main.go", false},
		{"outside the project, a workflow directory", "edit_file", "/home/u/other/.github/workflows/ci.yml", false},
		{"outside the project, a CI file name", "edit_file", "/home/u/other/.gitlab-ci.yml", true},
		{"shell write in the project under ~/test", "run_command", "echo x > src/gen.go", false},
		{"shell delete of a test in that project", "run_command", "rm tests/test_auth.py", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind := KindFileAccess
			if tc.kind == "run_command" {
				kind = KindShellExec
			}
			ev := Event{Kind: kind, ActionType: tc.kind, Target: tc.target, Cwd: root, ProjectRoot: root, SessionID: "s1"}
			e, err := New(Config{Mode: ModeEnforce, Home: home, ProtectedPathClasses: []string{"tests", "ci", "coverage"}})
			if err != nil {
				t.Fatal(err)
			}
			v := e.Evaluate(ev)
			if hit := v.RuleID == "R-166"; hit != tc.want {
				t.Fatalf("rule %s (%s), want R-166 hit %v", v.RuleID, v.Reason, tc.want)
			}
		})
	}
}

// TestProtectedPathClassesVocabulary: every class has patterns, and the
// vocabulary is exactly the table's.
func TestProtectedPathClassesVocabulary(t *testing.T) {
	want := []string{ProtectedClassTests, ProtectedClassCI, ProtectedClassCoverage}
	got := ProtectedPathClasses()
	if len(got) != len(want) {
		t.Fatalf("classes %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] || len(protectedPatterns([]string{want[i]})) == 0 {
			t.Errorf("class %q missing or empty", want[i])
		}
	}
}

// TestA613Evasion: A-613 is inert without the guard layer's stamp, flags
// in both modes with it, and EvaluateRule surfaces it beside a stricter
// verdict on the same action.
func TestA613Evasion(t *testing.T) {
	ev := Event{
		Kind: KindShellExec, ActionType: "run_command", Target: "git commit -n -m x",
		Cwd: "/p", ProjectRoot: "/p", SessionID: "s1",
	}
	for _, mode := range []Mode{ModeObserve, ModeEnforce} {
		e, err := New(Config{Mode: mode, Home: "/home/u"})
		if err != nil {
			t.Fatal(err)
		}
		if v := e.EvaluateRule("A-613", ev); v.Decision != DecisionAllow {
			t.Fatalf("%s: unstamped A-613 = %s", mode, v.Decision)
		}
		stamped := ev
		stamped.EvasionOf, stamped.EvasionShapes = "R-112", 2
		if v := e.Evaluate(stamped); v.RuleID != "R-112" {
			t.Fatalf("%s: full evaluation winner %s, want the stricter R-112", mode, v.RuleID)
		}
		v := e.EvaluateRule("A-613", stamped)
		if v.RuleID != "A-613" || v.Decision != DecisionFlag {
			t.Fatalf("%s: A-613 = %s/%s, want A-613/flag", mode, v.RuleID, v.Decision)
		}
	}
	e, err := New(Config{Mode: ModeEnforce, Disabled: []string{"A-613"}})
	if err != nil {
		t.Fatal(err)
	}
	stamped := ev
	stamped.EvasionOf, stamped.EvasionShapes = "R-112", 1
	if v := e.EvaluateRule("A-613", stamped); v.Decision != DecisionAllow {
		t.Errorf("disabled A-613 still fires: %s", v.Decision)
	}
}
