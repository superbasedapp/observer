package depscan

import (
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// actions_test.go pins the GitHub Actions ecosystem row (S-779 on the
// node): it is a store ecosystem with a canary, osv-scanner's required set
// leaves it out (as it leaves out Julia, whose Manifest.toml osv-scanner
// does not read), and its findings carry the workflow line, the moving-tag
// note and the S-779 identity.

func TestEcosystemListsSplitByReader(t *testing.T) {
	all := Ecosystems()
	wantAll := []string{
		"CRAN", "GitHub Actions", "Go", "Hackage", "Hex", "Julia", "Maven", "NuGet",
		"Packagist", "Pub", "PyPI", "RubyGems", "SwiftURL", "crates.io", "npm",
	}
	if !slices.Equal(all, wantAll) {
		t.Fatalf("store ecosystems %v, want %v", all, wantAll)
	}
	osv := OSVScannerEcosystems()
	want := []string{
		"CRAN", "Go", "Hackage", "Hex", "Maven", "NuGet", "Packagist", "Pub",
		"PyPI", "RubyGems", "SwiftURL", "crates.io", "npm",
	}
	if !slices.Equal(osv, want) {
		t.Fatalf("osv-scanner's required set %v, want %v", osv, want)
	}
	if OSVScannerReads("GitHub Actions") || OSVScannerReads("Julia") || !OSVScannerReads("npm") || !OSVScannerReads("Pub") {
		t.Fatal("osv-scanner does not read workflows or Julia manifests; it reads npm and Pub")
	}
	files := CanaryFiles()
	for name := range files {
		if strings.Contains(name, ".github") || strings.HasSuffix(name, ".yml") {
			t.Fatalf("osv-scanner's canary project must not carry a workflow: %s", name)
		}
	}
	if len(files) != len(osv) {
		t.Fatalf("%d canary files for %d osv-scanner ecosystems", len(files), len(osv))
	}
	c, ok := CanaryFor("GitHub Actions")
	if !ok || c.Name != "tj-actions/changed-files" || c.Version != "v45.0.0" || c.Advisory != "CVE-2025-30066" {
		t.Fatalf("GitHub Actions canary %+v", c)
	}
}

func TestActionFindings(t *testing.T) {
	pkgs := []Package{
		{Ecosystem: "GitHub Actions", Name: "tj-actions/changed-files", Version: "v45.0.0", Path: ".github/workflows/ci.yml", Line: 12},
		{Ecosystem: "GitHub Actions", Name: "azure/setup-kubectl", Version: "v2", Path: ".github/workflows/ci.yml", Line: 20, MovingTag: true},
		{Ecosystem: "GitHub Actions", Name: "reviewdog/action-setup", Version: "v1.3.0", Path: "sub/.github/workflows/lint.yaml", Line: 7, VersionFromComment: true},
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Path: "package-lock.json"},
	}
	groups := []Group{
		{Index: 0, IDs: []string{"CVE-2025-30066", "GHSA-mrrh-fwg8-r2c3"}, Primary: "CVE-2025-30066", Severity: policy.FindingSeverityHigh},
		{Index: 1, IDs: []string{"GHSA-p756-rfxh-x63h"}, Primary: "GHSA-p756-rfxh-x63h", Severity: policy.FindingSeverityMedium},
		{Index: 2, IDs: []string{"GHSA-qmg3-hpqr-gqvc"}, Primary: "GHSA-qmg3-hpqr-gqvc", Severity: policy.FindingSeverityHigh},
		{Index: 3, IDs: []string{"CVE-2021-23337"}, Primary: "CVE-2021-23337", Severity: policy.FindingSeverityHigh},
	}
	fs, _ := Findings(FindingInput{Packages: pkgs, Groups: groups, RootHash: "r", Scope: "manual", DriverID: ScalibrID, Engine: secscan.EngineIdentity{Version: "0.5.3"}})
	if len(fs) != 4 {
		t.Fatalf("%d findings", len(fs))
	}
	tag := fs[0]
	if tag.Rule.ID != "CVE-2025-30066" || tag.Category != policy.FindingVulnerableDependency || tag.Confidence != policy.FindingConfidenceHigh {
		t.Fatalf("exact tag finding %+v", tag)
	}
	if tag.EvidenceRedacted != "GitHub Actions tj-actions/changed-files@v45.0.0" || tag.Location.RelPath != ".github/workflows/ci.yml" || tag.Location.StartLine != 12 {
		t.Fatalf("evidence %q location %+v", tag.EvidenceRedacted, tag.Location)
	}
	if !strings.HasPrefix(tag.Message, "Known vulnerability in a GitHub Actions action (") || strings.Contains(tag.FixHint, "lockfile") {
		t.Fatalf("message %q fix %q", tag.Message, tag.FixHint)
	}
	moving := fs[1]
	if moving.Confidence != policy.FindingConfidenceMedium || !strings.Contains(moving.Message, "Moving tag: the version that runs may differ.") {
		t.Fatalf("moving tag finding %+v", moving)
	}
	if c := fs[2]; c.Confidence != policy.FindingConfidenceHigh || !strings.Contains(c.Message, "Version from the pin's comment") {
		t.Fatalf("comment finding %+v", c)
	}
	if npm := fs[3]; npm.Message != "Known vulnerability in a npm dependency (CVE-2021-23337)." || !strings.Contains(npm.FixHint, "lockfile") || npm.Location.StartLine != 0 {
		t.Fatalf("npm finding changed: %+v", npm)
	}
	for i, want := range []string{"GitHub Actions", "GitHub Actions", "GitHub Actions", "npm"} {
		if got := EcosystemOfFinding(fs[i]); got != want {
			t.Fatalf("EcosystemOfFinding %d = %q, want %q", i, got, want)
		}
	}
	if NativeRuleOf(fs[0]) != "S-779" || NativeRuleOf(fs[3]) != "" {
		t.Fatal("an action finding is S-779; an npm one has no native rule")
	}
	// A run that scanned GitHub Actions in full closes its stale findings
	// (the ecosystem with a space is read back whole).
	open := []secfinding.Finding{fs[0]}
	open[0].ID, open[0].Status, open[0].Engine.Driver = "f1", policy.FindingStatusOpen, ScalibrID
	if got := StaleFindings(open, ScalibrID, nil, map[string]bool{"GitHub Actions": true}); len(got) != 1 {
		t.Fatalf("stale %v", got)
	}
	if got := StaleFindings(open, ScalibrID, nil, map[string]bool{"GitHub": true}); len(got) != 0 {
		t.Fatalf("a first-word ecosystem must not close an action finding: %v", got)
	}
}

// TestActionGaps: a SHA pin with no comment and a branch ref are gaps of
// their workflow file, so GitHub Actions is never counted scanned in full.
func TestActionGaps(t *testing.T) {
	resp := ChildResponse{
		Packages: []Package{
			{Ecosystem: "GitHub Actions", Name: "actions/checkout", Path: ".github/workflows/ci.yml", PinnedBySHA: true},
			{Ecosystem: "GitHub Actions", Name: "actions/cache", Version: "main", Path: ".github/workflows/ci.yml", NotAVersion: true},
			{Ecosystem: "GitHub Actions", Name: "actions/setup-go", Version: "v5.0.0", Path: ".github/workflows/ci.yml"},
		},
		Ecosystems: []EcoResult{{Ecosystem: "GitHub Actions", Outcome: EcoScanned, Packages: 1}},
	}
	out, gaps := Finalize(resp)
	if len(gaps) != 2 {
		t.Fatalf("gaps %+v", gaps)
	}
	words := map[string]bool{}
	for _, g := range gaps {
		words[ReasonWords(g.Reason)] = true
	}
	if !words["pinned by a commit SHA with no version comment"] || !words["no exact version pinned"] {
		t.Fatalf("gap words %v", words)
	}
	cov := Coverage(RunFacts{Ecosystems: out.Ecosystems, Gaps: gaps})
	if cov.Outcome != secscan.OutcomeUnknown || slices.Contains(cov.Scanned, "GitHub Actions") {
		t.Fatalf("coverage %+v: a gap is never clean", cov)
	}
}
