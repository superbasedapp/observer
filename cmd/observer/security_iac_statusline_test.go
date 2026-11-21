//go:build !sbo_omit_security

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/seciac"
)

// TestIaCStatusLineSurfaces: an engine that is selected but not installed
// names its guided install in each surface's own words (dashboard CLI parity
// plan B-CS2): the CLI names its verb, the dashboard names the IaC scanners
// card on the same tab (never a Settings place that does not exist, never a
// terminal command); an engine with no guided install, or no hint, says
// "install it yourself" only.
func TestIaCStatusLineSurfaces(t *testing.T) {
	notInstalled := seciac.Inspection{Reason: seciac.ReasonNotInstalled}
	guided := seciac.Engine{ID: seciac.Trivy, Title: "Trivy", ReleaseBase: "https://example.test/v"}
	manual := seciac.Engine{ID: seciac.KICS, Title: "KICS"}
	cases := []struct {
		name    string
		engine  seciac.Engine
		hint    iacInstallHint
		want    string
		without []string
	}{
		{"cli", guided, iacInstallHintCLI, "(`observer security iac install --engine trivy` or install it yourself)", nil},
		{"dashboard", guided, iacInstallHintDash, "(install Trivy from the IaC scanners card on this tab or install it yourself)", []string{"observer ", "Settings"}},
		{"no guided install", manual, iacInstallHintDash, "(install it yourself)", []string{"card"}},
		{"no hint", guided, nil, "(install it yourself)", []string{"observer "}},
	}
	for _, c := range cases {
		got := iacStatusLine(c.engine, notInstalled, c.hint)
		if !strings.HasSuffix(got, c.want) || !strings.HasPrefix(got, c.engine.Title+": selected, not installed") {
			t.Errorf("%s: %q, want suffix %q", c.name, got, c.want)
		}
		for _, w := range c.without {
			if strings.Contains(got, w) {
				t.Errorf("%s: %q must not contain %q", c.name, got, w)
			}
		}
	}
}
