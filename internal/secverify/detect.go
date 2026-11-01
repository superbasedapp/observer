package secverify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// CoverageStatus is how far a detector got.
type CoverageStatus string

// The closed coverage vocabulary.
const (
	// CoverageComplete: the detector read every changed file it covers.
	CoverageComplete CoverageStatus = "complete"
	// CoveragePartial: a cap cut it short; what it found stands, but it
	// cannot claim the rest is clean.
	CoveragePartial CoverageStatus = "partial"
	// CoverageNotInBuild: the detector belongs to a phase this binary does
	// not carry yet.
	CoverageNotInBuild CoverageStatus = "not_in_build"
	// CoverageOff: the policy switched it off.
	CoverageOff CoverageStatus = "off"
	// CoverageFailed: it returned an error or was cancelled.
	CoverageFailed CoverageStatus = "failed"
)

// Coverage is one detector's account of its run, reported whatever the
// verdict so an empty result list never reads as "clean".
type Coverage struct {
	Detector string
	Status   CoverageStatus
	// Files is how many changed files it read; Skipped how many it could
	// not read (binary files for a text detector) and why.
	Files      int
	Skipped    int
	SkipReason string
	// Note is a fixed, templated sentence; never repository text.
	Note string
}

// Input is what a detector sees: the changed files of the diff, already
// parsed and capped. Detectors read nothing else.
type Input struct {
	Files []ChangedFile
	// ReadHead, when set, reads one changed file as it is at the head
	// commit, capped (over reports the cap was hit). The ci_workflow
	// detector reads a modified workflow whole through it; nil leaves only
	// the parsed diff.
	ReadHead func(path string) (content []byte, over bool, err error)
	// Dependencies is the install_index detector's injected index; nil
	// when the caller supplied none.
	Dependencies DependencyCheck
}

// Result is one detector's output.
type Result struct {
	Findings []Finding
	Coverage Coverage
}

// Detector is one row of the closed native detector table.
type Detector struct {
	// ID is the stable detector id the policy names.
	ID       string
	Category Category
	// Phase names the security plan phase that builds the detector, for the
	// "not in this build" note.
	Phase string
	// Run is nil for a detector that is not in this build.
	Run func(ctx context.Context, in Input) Result
	// NotRequired, when set, says why the built-in policy does not require
	// the detector (it still runs and its findings still act).
	NotRequired string
}

// detectorTable is the native detector table, walked in order. Rows with
// a nil Run belong to phases built in other lanes (security plan 7.9 "What
// it runs"); each is wired by adding its function here when its phase
// merges, and until then it reports CoverageNotInBuild, never clean.
var detectorTable = []Detector{
	{ID: "secrets", Category: CategorySecret, Phase: "F1", Run: detectSecrets},
	{ID: "agent_config", Category: CategoryAgentConfig, Phase: "F1", Run: detectAgentConfig},
	{ID: "repo_trust", Category: CategoryRepoTrust, Phase: "B", Run: repoTrustRun, NotRequired: "it sees only the added lines of a modified file, so a structured file it cannot parse makes it partial; agent_config reports the change itself"},
	{ID: "ci_workflow", Category: CategoryCIConfig, Phase: "C", Run: detectCIWorkflow},
	{ID: "test_tampering", Category: CategoryTestTampering, Phase: "C", Run: detectTestTampering},
	{ID: "install_index", Category: CategoryMalicious, Phase: "D1", Run: detectInstallIndex, NotRequired: "its data is supplied by the caller (a verified install index), so a run without one must not turn every default check unknown"},
}

// Detectors returns a copy of the detector table.
func Detectors() []Detector {
	out := make([]Detector, len(detectorTable))
	copy(out, detectorTable)
	return out
}

// builtDetectorIDs lists the detectors this build carries, the default
// require list.
func builtDetectorIDs() []string {
	var out []string
	for _, d := range detectorTable {
		if d.Run != nil && d.NotRequired == "" {
			out = append(out, d.ID)
		}
	}
	return out
}

// fingerprint is the stable code-scanning id of a finding: rule, path and
// occurrence index, never a matched value.
func fingerprint(rule, rel string, occurrence int) string {
	sum := sha256.Sum256([]byte(rule + "\x00" + rel + "\x00" + strconv.Itoa(occurrence)))
	return hex.EncodeToString(sum[:16])
}

// matchGlob is the guidance-style glob ("**" crosses segments) the
// agent-config path table already uses.
func matchGlob(pattern, rel string) bool { return agentconfig.MatchGlob(pattern, rel) }

// sortFindings orders findings by path, line and rule.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Path != fs[j].Path {
			return fs[i].Path < fs[j].Path
		}
		if fs[i].Line != fs[j].Line {
			return fs[i].Line < fs[j].Line
		}
		return fs[i].RuleID < fs[j].RuleID
	})
}
