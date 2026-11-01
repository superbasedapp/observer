package secverify

import (
	"context"
	"strings"
)

// DependencyHit is one dependency a manifest change adds that the install
// index flags. Verdict is the install gate's verdict vocabulary
// ("malicious", "near_miss"); Name is already charset-filtered and capped
// by the checker.
type DependencyHit struct {
	Ecosystem string
	Name      string
	Verdict   string
	// NearMiss is the popular name a near miss resembles.
	NearMiss string
}

// DependencyCheck is the install_index detector's data source (security
// Phase D1): given a changed file's path and its added text, it reports
// whether the file is a manifest it reads and the added dependencies the
// offline index flags. The caller injects it with a verified index (the
// node's installed one, or one named on the command line); verify reads no
// file of its own, so the check stays hermetic.
type DependencyCheck func(path, added string) (hits []DependencyHit, manifest bool)

// installRule is how verify treats one install verdict.
type installRule struct {
	Severity   Severity
	Confidence Confidence
	Action     Action
	Message    string
}

// installRules maps the index verdicts that reach CI to a judgement. Only
// a malicious listing denies (S-741's rule: the one deny-eligible verdict).
var installRules = map[string]installRule{
	"malicious": {
		SeverityCritical, ConfidenceHigh, ActionDeny,
		"This change adds a dependency an authenticated source lists as malicious. Remove it and check whether it was ever installed.",
	},
	"near_miss": {
		SeverityMedium, ConfidenceMedium, ActionFlag,
		"This change adds a dependency one edit from a popular package name, a possible typosquat. Check the name is the one you meant.",
	},
}

// detectInstallIndex reads the dependencies changed manifests add and
// checks them against the injected index. Without an index it cannot claim
// anything about a changed manifest: the coverage is partial, never
// complete. A change that touches no manifest is complete with nothing to
// read.
func detectInstallIndex(ctx context.Context, in Input) Result {
	cov := Coverage{Detector: "install_index", Status: CoverageComplete}
	var out []Finding
	for _, f := range in.Files {
		if ctx.Err() != nil {
			cov.Status = CoverageFailed
			cov.Note = "cancelled before every file was read"
			break
		}
		if f.Status == StatusDeleted || f.Binary || len(f.Added) == 0 {
			continue
		}
		var b strings.Builder
		for _, l := range f.Added {
			b.WriteString(l.Text)
			b.WriteByte('\n')
		}
		if in.Dependencies == nil {
			if isManifestPath(f.Path) {
				cov.Skipped++
				cov.SkipReason = "no verified install index was supplied"
				cov.Status = CoveragePartial
				cov.Note = "a manifest changed and no verified install index was supplied, so its added dependencies were not checked"
			}
			continue
		}
		hits, manifest := in.Dependencies(f.Path, b.String())
		if !manifest {
			continue
		}
		cov.Files++
		if f.Partial {
			cov.Status = CoveragePartial
			cov.Note = "a manifest's added text was over the cap and was read only in part"
		}
		occ := map[string]int{}
		for _, h := range hits {
			r, ok := installRules[h.Verdict]
			if !ok {
				continue
			}
			rule := "install/" + h.Verdict
			msg := r.Message + " (" + clipSafe(h.Ecosystem, 16) + " " + clipSafe(h.Name, 80)
			if h.NearMiss != "" {
				msg += ", near " + clipSafe(h.NearMiss, 80)
			}
			msg += ")"
			out = append(out, Finding{
				RuleID: rule, Detector: "install_index", Category: CategoryMalicious,
				Severity: r.Severity, Confidence: r.Confidence, Path: f.Path, Line: lineOf(f.Added, h.Name),
				Message: msg, Fingerprint: fingerprint(rule+"/"+h.Name, f.Path, occ[h.Name]), DefaultAction: r.Action,
			})
			occ[h.Name]++
		}
	}
	return Result{Findings: out, Coverage: cov}
}

// manifestBases are the manifest file names verify knows without an
// index, so a missing index is reported only where it matters.
var manifestBases = map[string]bool{
	"package.json": true, "composer.json": true, "pyproject.toml": true, "Pipfile": true,
	"Cargo.toml": true, "go.mod": true, "Gemfile": true, "Directory.Packages.props": true,
}

func isManifestPath(p string) bool {
	base := p[strings.LastIndex(p, "/")+1:]
	return manifestBases[base] || strings.HasSuffix(base, ".csproj") ||
		(strings.HasSuffix(base, ".txt") && (strings.HasPrefix(base, "requirements") || strings.HasPrefix(base, "constraints")))
}

// lineOf returns the first added line that mentions name, 0 when none.
func lineOf(lines []AddedLine, name string) int {
	for _, l := range lines {
		if name != "" && strings.Contains(strings.ToLower(l.Text), strings.ToLower(name)) {
			return l.N
		}
	}
	return 0
}
