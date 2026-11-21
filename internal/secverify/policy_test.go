package secverify

import (
	"errors"
	"strings"
	"testing"
)

func TestParsePolicy(t *testing.T) {
	p, err := ParsePolicy([]byte(`
version = 1
mode = "observe"
require = ["secrets"]
fixture_paths = ["fixtures/**"]
max_files = 100
[detectors]
agent_config = "flag"
`), SourceProtected)
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != ModeObserve || p.Source != SourceProtected || p.Detectors["agent_config"] != ActionFlag ||
		len(p.Require) != 1 || p.MaxFiles != 100 || p.FixturePaths[0] != "fixtures/**" {
		t.Errorf("policy = %+v", p)
	}
	// Absent fields keep the defaults.
	p, err = ParsePolicy([]byte("version = 1\n"), SourceBaseCommit)
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != ModeEnforce || strings.Join(p.Require, ",") != "secrets,agent_config,ci_workflow,test_tampering,container_config" || len(p.FixturePaths) == 0 {
		t.Errorf("defaults = %+v", p)
	}
}

func TestParsePolicyRefusals(t *testing.T) {
	cases := map[string]string{
		"no version":           `mode = "enforce"`,
		"future version":       "version = 2",
		"unknown key":          "version = 1\nallow_everything = true",
		"unknown nested key":   "version = 1\n[detectors.secrets]\nx = 1",
		"unknown mode":         "version = 1\nmode = \"lenient\"",
		"unknown action":       "version = 1\n[detectors]\nsecrets = \"allow\"",
		"unknown detector":     "version = 1\n[detectors]\nsecretz = \"flag\"",
		"require unknown":      "version = 1\nrequire = [\"nope\"]",
		"required and off":     "version = 1\n[detectors]\nsecrets = \"off\"",
		"absolute fixture":     "version = 1\nfixture_paths = [\"/etc/**\"]",
		"negative cap":         "version = 1\nmax_files = -1",
		"not toml":             "version = = 1",
		"oversized":            "version = 1\n#" + strings.Repeat("x", MaxPolicyBytes),
		"source field ignored": "version = 1\nSource = \"protected_file\"",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParsePolicy([]byte(body), SourceProtected)
			if err == nil {
				t.Fatal("accepted")
			}
			if !errors.Is(err, ErrPolicy) {
				t.Errorf("err %v does not wrap ErrPolicy", err)
			}
		})
	}
}

// TestDefaultPolicyRequiresEveryBuiltDetector: every built detector is
// required by default unless its row says why not (NotRequired).
func TestDefaultPolicyRequiresEveryBuiltDetector(t *testing.T) {
	p := DefaultPolicy()
	req := map[string]bool{}
	for _, id := range p.Require {
		req[id] = true
	}
	for _, d := range Detectors() {
		if (d.Run != nil && d.NotRequired == "") != req[d.ID] {
			t.Errorf("detector %s built=%v not-required=%q required=%v", d.ID, d.Run != nil, d.NotRequired, req[d.ID])
		}
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}
