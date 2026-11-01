package seccustom

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// TestCheckToolchainSkewTable: a Go program built with an older Go release
// than the version its go companion reports is skewed (the gosec Go 1.27
// case, JSP-12), checked here without a real gosec; an unknown version on
// either side, or a companion of another format, is no skew.
func TestCheckToolchainSkewTable(t *testing.T) {
	t.Parallel()
	m := Manifest{Companions: []Companion{{Path: "/usr/local/go/bin/go", VersionFormat: GoToolchainFormat}, {Path: "/usr/bin/git"}}}
	cases := []struct {
		name      string
		builtWith string
		versions  map[string]string
		skewed    bool
	}{
		{"gosec built with Go 1.26 against Go 1.27", "go1.26.3", map[string]string{"/usr/local/go/bin/go": "1.27.2"}, true},
		{"same minor, older patch", "go1.27.0", map[string]string{"/usr/local/go/bin/go": "1.27.2"}, false},
		{"built newer than the toolchain", "go1.28.1", map[string]string{"/usr/local/go/bin/go": "1.27.2"}, false},
		{"older major", "go1.99", map[string]string{"/usr/local/go/bin/go": "2.0"}, true},
		{"release candidate spelling", "go1.26rc2", map[string]string{"/usr/local/go/bin/go": "go1.27"}, true},
		{"not a Go program", "", map[string]string{"/usr/local/go/bin/go": "1.27.2"}, false},
		{"toolchain version unknown", "go1.26.3", map[string]string{}, false},
		{"only a companion of another format reports", "go1.26.3", map[string]string{"/usr/bin/git": "2.48.1"}, false},
		{"unreadable build version", "devel +abc", map[string]string{"/usr/local/go/bin/go": "1.27.2"}, false},
	}
	for _, tc := range cases {
		got := CheckToolchainSkew(tc.builtWith, m, tc.versions)
		if got.Skewed != tc.skewed || (got.Skewed && !strings.Contains(got.Detail, "never complete")) {
			t.Errorf("%s: %+v, want skewed %v", tc.name, got, tc.skewed)
		}
	}
}

// TestSkewedRunIsNeverComplete: a skewed run with findings is incomplete,
// with none it is unknown (never clean), and it closes nothing.
func TestSkewedRunIsNeverComplete(t *testing.T) {
	t.Parallel()
	base := RunFacts{Runner: extrun.OutcomeOK, Exit: extrun.ExitResult, SelfTestCurrent: true, ToolchainSkew: true}
	if v := Classify(base); v.Outcome != secscan.OutcomeUnknown || v.Reason != "toolchain_skew" {
		t.Fatalf("no findings: %+v", v)
	}
	withFindings := base
	withFindings.Findings = 2
	v := Classify(withFindings)
	if v.Outcome != secscan.OutcomeFindings || v.Reason != "incomplete" {
		t.Fatalf("findings: %+v", v)
	}
	if CanCloseMissing(withFindings, v) {
		t.Fatal("a skewed run closed earlier findings")
	}
	clean := base
	clean.ToolchainSkew = false
	if v := Classify(clean); v.Outcome != secscan.OutcomeClean {
		t.Fatalf("no skew: %+v", v)
	}
}
