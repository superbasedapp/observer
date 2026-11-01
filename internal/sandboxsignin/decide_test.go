package sandboxsignin

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var files = []string{".claude/.credentials.json"}

// TestDecideTable pins one case per rule row, in table order.
func TestDecideTable(t *testing.T) {
	t.Parallel()
	base := Input{Tool: "claude-code", Files: files, Projected: true}
	with := func(f func(*Input)) Input { in := base; f(&in); return in }
	cases := []struct {
		name    string
		in      Input
		verdict Verdict
		code    string
		seed    bool
	}{
		{"R1 hosted refuses even with consent", with(func(i *Input) { i.Hosted, i.Launch, i.Remembered = true, AnswerYes, true }), VerdictRefused, "hosted", false},
		{"R2 no row refuses", with(func(i *Input) { i.Files, i.Launch = nil, AnswerYes }), VerdictRefused, "no_row", false},
		{"R3 keychain refuses with its reason", with(func(i *Input) { i.Keychain, i.Launch = true, AnswerYes }), VerdictRefused, "keychain", false},
		{"R4 bound row copies nothing", with(func(i *Input) { i.Projected, i.Launch = false, AnswerYes }), VerdictBound, "bound", false},
		{"R5 org forbid beats a remembered consent", with(func(i *Input) { i.OrgForbidden, i.Remembered = true, true }), VerdictRefused, "org_forbidden", false},
		{"R5 org forbid beats a launch consent", with(func(i *Input) { i.OrgForbidden, i.Launch = true, AnswerYes }), VerdictRefused, "org_forbidden", false},
		{"R6 no for this launch beats remembered", with(func(i *Input) { i.Launch, i.Remembered = AnswerNo, true }), VerdictNotConsented, "declined", false},
		{"R7 launch yes seeds", with(func(i *Input) { i.Launch = AnswerYes }), VerdictSeed, "consented", true},
		{"R8 remembered seeds headless", with(func(i *Input) { i.Remembered = true }), VerdictSeed, "remembered", true},
		{"R9 interactive asks", with(func(i *Input) { i.Interactive = true }), VerdictAsk, "ask", false},
		{"R10 headless and nothing remembered: off by default", base, VerdictNotConsented, "headless", false},
	}
	for _, tc := range cases {
		d := Decide(tc.in)
		if d.Verdict != tc.verdict || d.Code != tc.code {
			t.Errorf("%s: got %s/%s (%s), want %s/%s", tc.name, d.Verdict, d.Code, d.Rule, tc.verdict, tc.code)
		}
		if tc.seed != (d.Verdict == VerdictSeed) || (tc.seed && strings.Join(d.Files, ",") != strings.Join(files, ",")) {
			t.Errorf("%s: files %v", tc.name, d.Files)
		}
		if d.Reason == "" {
			t.Errorf("%s: no reason", tc.name)
		}
	}
	if d := Decide(with(func(i *Input) { i.Keychain = true })); d.Reason != KeychainReason || !d.RefusesExplicit() {
		t.Errorf("keychain reason %q", d.Reason)
	}
	if d := Decide(with(func(i *Input) { i.Hosted = true })); d.Reason != HostedReason || !d.RefusesExplicit() {
		t.Errorf("hosted reason %q", d.Reason)
	}
	if d := Decide(with(func(i *Input) { i.OrgForbidden, i.Launch = true, AnswerYes })); !strings.Contains(d.Reason, "organization") {
		t.Errorf("org reason %q does not name the organization", d.Reason)
	}
}

// TestConsentTextNamesEverything pins ruling P-180 (6) 2.
func TestConsentTextNamesEverything(t *testing.T) {
	t.Parallel()
	s := ConsentText("codex", []string{".codex/auth.json"})
	for _, want := range []string{"codex", "~/.codex/auth.json", "can read and use it", "allowed network can carry it", "removed when the run ends"} {
		if !strings.Contains(s, want) {
			t.Errorf("consent text lacks %q: %s", want, s)
		}
	}
	if strings.ContainsAny(s, "\u2013\u2014") {
		t.Error("consent text holds an en or em dash")
	}
}

// TestPostureLineNamesFilesOnly: the posture names the tool and the file
// names.
func TestPostureLineNamesFilesOnly(t *testing.T) {
	t.Parallel()
	d := Decide(Input{Tool: "claude-code", Files: files, Projected: true, Launch: AnswerYes})
	s := PostureLine("claude-code", d, files)
	if !strings.Contains(s, "claude-code") || !strings.Contains(s, ".claude/.credentials.json") || !strings.Contains(s, "removed when the run ends") {
		t.Errorf("posture %q", s)
	}
	if s := PostureLine("claude-code", d, nil); !strings.Contains(s, "nothing copied") {
		t.Errorf("posture without a file %q", s)
	}
}

// TestPure pins the package free of file, network and database imports.
func TestPure(t *testing.T) {
	t.Parallel()
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(".", e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range f.Imports {
			switch strings.Trim(im.Path.Value, `"`) {
			case "os", "io", "io/fs", "net", "net/http", "database/sql", "os/exec", "path/filepath":
				t.Errorf("%s imports %s", e.Name(), im.Path.Value)
			}
		}
	}
}

// TestRuleIDsAreDistinct: one id per table row.
func TestRuleIDsAreDistinct(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.id] {
			t.Errorf("rule id %s is used twice", r.id)
		}
		seen[r.id] = true
	}
}

// TestKeychainCapableMissingFile and TestSharedLine (audit F5, ruling P-183).
func TestKeychainCapableMissingFile(t *testing.T) {
	t.Parallel()
	d := Decide(Input{Tool: "codex", Files: []string{".codex/auth.json"}, MayUseKeychain: true, Projected: true, Launch: AnswerYes})
	if s := PostureLine("codex", d, nil); !strings.Contains(s, KeychainReason) {
		t.Errorf("a keyring store is not given the keychain reason: %s", s)
	}
}

func TestSharedLine(t *testing.T) {
	t.Parallel()
	s := SharedLine("claude-code", []string{".claude/.credentials.json"})
	for _, want := range []string{"claude-code", "~/.claude/.credentials.json", "sign-in included", "not the tool's own login"} {
		if !strings.Contains(s, want) {
			t.Errorf("shared line lacks %q: %s", want, s)
		}
	}
}
