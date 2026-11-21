package depscan

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

func TestOnlineCovers(t *testing.T) {
	cases := []struct {
		rel  string
		want bool
	}{
		{".gitmodules", true},
		{"third_party/grpc/.gitmodules", true},
		{"conan.lock", false},
		{"conanfile.txt", false},
		{"vcpkg.json", false},
		{"gitmodules", false},
		{".gitmodules.bak", false},
	}
	for _, c := range cases {
		if got := OnlineCovers(c.rel); got != c.want {
			t.Errorf("OnlineCovers(%q) = %v", c.rel, got)
		}
	}
}

// submoduleTestResp is a response with an npm package and the gap the gap
// probe records for a .gitmodules file the run cannot check offline.
func submoduleTestResp() ChildResponse {
	return ChildResponse{
		Version: ProtocolVersion, Compiled: true,
		Packages:   []Package{{Ecosystem: "npm", Name: "lodash", Version: "4.17.21", Path: "package-lock.json"}},
		Ecosystems: []EcoResult{{Ecosystem: "npm", Outcome: EcoScanned, Packages: 1, Epoch: "e1"}},
		Gaps: []Gap{
			{Ecosystem: "C/C++", Path: ".gitmodules", Reason: "needs_online"},
			{Ecosystem: "C/C++", Path: "conan.lock", Reason: "not_supported"},
		},
	}
}

const testZlibCommit = "cacf7f1d4e3d44d871b605da3b647f07d718623f"

func TestApplySubmodules(t *testing.T) {
	pin := SubmodulePin{Path: "third_party/zlib", Name: "zlib", Commit: testZlibCommit, Advisories: []Advisory{
		{ID: "CVE-2018-25032", Aliases: []string{"GHSA-jc36-42cf-vqwj"}, Severity: "HIGH"},
		{ID: "CVE-2022-37434"},
	}}
	cases := []struct {
		name string
		c    SubmoduleCheck
		// want
		outcome    secscan.Outcome
		gapPaths   []string
		gitOutcome EcoOutcome // "" when no GIT result is expected
		findings   int
	}{
		{
			name:    "checked in full: the gap is dropped and the findings sit at the submodule path",
			c:       SubmoduleCheck{Covered: []string{".gitmodules"}, Pins: []SubmodulePin{pin}, Ran: true, CanaryHit: true, Epoch: "online:api.osv.dev t"},
			outcome: secscan.OutcomeFindings, gapPaths: []string{"conan.lock"}, gitOutcome: EcoScanned, findings: 2,
		},
		{
			name:    "the self-test did not answer: nothing is dropped, GIT is not scanned",
			c:       SubmoduleCheck{Covered: []string{".gitmodules"}, Pins: []SubmodulePin{pin}, Ran: true, CanaryHit: false},
			outcome: secscan.OutcomeUnknown, gapPaths: []string{".gitmodules", "conan.lock"}, gitOutcome: EcoNotScanned,
		},
		{
			name:    "the self-test query failed",
			c:       SubmoduleCheck{Covered: []string{".gitmodules"}, Ran: true, MatchError: true},
			outcome: secscan.OutcomeUnknown, gapPaths: []string{".gitmodules", "conan.lock"}, gitOutcome: EcoNotScanned,
		},
		{
			name: "one pin failed: its file stays a gap, the checked pin still reports",
			c:    SubmoduleCheck{Pins: []SubmodulePin{pin}, Ran: true, CanaryHit: true, Unchecked: []Gap{{Path: ".gitmodules", Reason: ReasonSubmoduleCheckFailed, Packages: 1}}},
			// Sorted by ecosystem first: the probe's two C/C++ gaps, then GIT's.
			outcome: secscan.OutcomeFindings, gapPaths: []string{".gitmodules", "conan.lock", ".gitmodules"}, gitOutcome: EcoScanned, findings: 2,
		},
		{
			name:    "no pin to check: the file is covered with no query and no GIT result",
			c:       SubmoduleCheck{Covered: []string{".gitmodules"}},
			outcome: secscan.OutcomeUnknown, gapPaths: []string{"conan.lock"},
		},
		{
			name:    "a covered path that is not a .gitmodules drops nothing",
			c:       SubmoduleCheck{Covered: []string{"conan.lock"}},
			outcome: secscan.OutcomeUnknown, gapPaths: []string{".gitmodules", "conan.lock"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := submoduleTestResp()
			out := ApplySubmodules(in, c.c)
			if len(in.Packages) != 1 || len(in.Gaps) != 2 || len(in.Ecosystems) != 1 {
				t.Fatal("ApplySubmodules changed its input")
			}
			resp, gaps := Finalize(out)
			var paths []string
			for _, g := range gaps {
				paths = append(paths, g.Path)
			}
			if strings.Join(paths, ",") != strings.Join(c.gapPaths, ",") {
				t.Errorf("gaps %v, want %v", paths, c.gapPaths)
			}
			var git *EcoResult
			for i := range resp.Ecosystems {
				if resp.Ecosystems[i].Ecosystem == SubmoduleEcosystem {
					git = &resp.Ecosystems[i]
				}
			}
			switch {
			case c.gitOutcome == "" && git != nil:
				t.Fatalf("unexpected GIT result %+v", *git)
			case c.gitOutcome != "" && (git == nil || git.Outcome != c.gitOutcome):
				t.Fatalf("GIT result %+v, want %s", git, c.gitOutcome)
			}
			var advs []Advisory
			for _, e := range resp.Ecosystems {
				if e.Outcome == EcoScanned {
					advs = append(advs, e.Advisories...)
				}
			}
			groups := GroupByAliases(advs, policy.FindingSeverityMedium)
			fs, _ := Findings(FindingInput{Packages: resp.Packages, Groups: groups, RootHash: "r", Scope: policy.FindingScopeManual, DriverID: "scalibr"})
			if len(fs) != c.findings {
				t.Fatalf("%d findings, want %d: %+v", len(fs), c.findings, fs)
			}
			for _, f := range fs {
				if f.Location.RelPath != "third_party/zlib" || f.EvidenceRedacted != "GIT zlib@"+testZlibCommit {
					t.Errorf("finding at %q with evidence %q", f.Location.RelPath, f.EvidenceRedacted)
				}
				if !strings.HasPrefix(f.Message, "Known vulnerability in a git submodule (") || !strings.Contains(f.FixHint, "submodule") {
					t.Errorf("message %q fix %q", f.Message, f.FixHint)
				}
				if EcosystemOfFinding(f) != SubmoduleEcosystem {
					t.Errorf("ecosystem of finding %q", EcosystemOfFinding(f))
				}
			}
			cov := Coverage(RunFacts{Ecosystems: resp.Ecosystems, Gaps: gaps, Findings: len(fs)})
			if cov.Outcome != c.outcome {
				t.Errorf("coverage %s (%s), want %s", cov.Outcome, cov.Reason, c.outcome)
			}
		})
	}
}

// TestApplySubmodulesCleanAndClosing: a project whose only dependencies are
// submodules, checked in full with no advisory, is clean and names GIT as
// scanned, so a later complete run may close an older GIT finding; a run
// with a gap in GIT does not.
func TestApplySubmodulesCleanAndClosing(t *testing.T) {
	base := ChildResponse{Version: ProtocolVersion, Compiled: true, Gaps: []Gap{{Path: ".gitmodules", Reason: "needs_online"}}}
	pin := SubmodulePin{Path: "libs/x", Name: "x", Commit: testZlibCommit}
	resp, gaps := Finalize(ApplySubmodules(base, SubmoduleCheck{Covered: []string{".gitmodules"}, Pins: []SubmodulePin{pin}, Ran: true, CanaryHit: true}))
	cov := Coverage(RunFacts{Ecosystems: resp.Ecosystems, Gaps: gaps})
	if cov.Outcome != secscan.OutcomeClean || !ScannedEcosystems(cov)[SubmoduleEcosystem] {
		t.Fatalf("coverage %+v", cov)
	}
	partial := SubmoduleCheck{Pins: []SubmodulePin{pin}, Ran: true, CanaryHit: true, Unchecked: []Gap{{Path: ".gitmodules", Reason: ReasonSubmoduleCheckFailed, Packages: 1}}}
	resp, gaps = Finalize(ApplySubmodules(base, partial))
	cov = Coverage(RunFacts{Ecosystems: resp.Ecosystems, Gaps: gaps})
	if cov.Outcome == secscan.OutcomeClean || ScannedEcosystems(cov)[SubmoduleEcosystem] {
		t.Fatalf("a partial submodule check must neither be clean nor close: %+v", cov)
	}
}

// TestSubmoduleEcosystemIsNeverDownloaded: GIT is matched online only, so
// it is not in the table the database store downloads.
func TestSubmoduleEcosystemIsNeverDownloaded(t *testing.T) {
	for _, eco := range Ecosystems() {
		if eco == SubmoduleEcosystem {
			t.Fatal("GIT must not be a downloaded ecosystem")
		}
	}
	if ReasonWords(ReasonSubmoduleCheckFailed) == ReasonSubmoduleCheckFailed || ReasonWords(ReasonSubmodulePinsUnreadable) == ReasonSubmodulePinsUnreadable {
		t.Fatal("the submodule gap reasons have no words")
	}
}
