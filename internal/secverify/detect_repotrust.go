//go:build !sbo_omit_security_trust

package secverify

import (
	"context"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sectrust"
)

// repoTrustRun is the repo_trust row's Run in a build with the
// security.trust component; detect_repotrust_omit.go leaves it nil, so the
// row reports "not in this build" and internal/sectrust is not linked.
var repoTrustRun = detectRepoTrust

// maxTrustRoots caps the launch directories the repo_trust detector checks
// for one change; past it the detector is partial.
const maxTrustRoots = 64

// detectRepoTrust is security Phase B's repository trust check over a
// change (security plan 5.1 and 7.9): the files the change adds or modifies
// are laid out in memory and sectrust.Check reads its fixed path table at
// the repository root and at every directory a changed file sits under, up
// to its first dot-directory (the monorepo package a config belongs to).
// Nothing is accepted in CI, so a command the repository makes an agent
// run is untrusted.
//
// Verify sees only the added lines of a modified file. Those lines are the
// file's content here, which is exact for an added file and for the
// line-based classes (dotenv, .git/config, .gitattributes, hidden Unicode),
// but not for a structured file: a parse error on a modified file is
// therefore dropped and the detector reports partial coverage (the
// agent_config detector still reports the change itself).
func detectRepoTrust(ctx context.Context, in Input) Result {
	cov := Coverage{Detector: "repo_trust", Status: CoverageComplete}
	files := map[string][]byte{}
	modified := map[string]bool{}
	roots := map[string]bool{"": true}
	for _, f := range in.Files {
		if f.Status == StatusDeleted {
			continue
		}
		if f.Binary {
			cov.Skipped++
			cov.SkipReason = "binary files are not read"
			continue
		}
		cov.Files++
		var b strings.Builder
		for _, l := range f.Added {
			b.WriteString(l.Text)
			b.WriteByte('\n')
		}
		files[f.Path] = []byte(b.String())
		if f.Status != StatusAdded || f.Partial {
			modified[f.Path] = true
		}
		roots[trustLaunchDir(f.Path)] = true
	}
	launches := make([]string, 0, len(roots))
	for r := range roots {
		launches = append(launches, r)
	}
	sort.Strings(launches)
	if len(launches) > maxTrustRoots {
		launches = launches[:maxTrustRoots]
		partial(&cov, "more package directories changed than the detector checks")
	}
	fsys := sectrust.MemFS(files)
	seen := map[string]bool{}
	var out []Finding
	occ := map[string]int{}
	for _, launch := range launches {
		if ctx.Err() != nil {
			cov.Status = CoverageFailed
			cov.Note = "cancelled before every directory was checked"
			break
		}
		res, err := sectrust.Check(ctx, fsys, sectrust.Request{LaunchRel: launch})
		if err != nil {
			cov.Status = CoverageFailed
			cov.Note = "the repository trust check did not run"
			break
		}
		for _, r := range res.Reasons {
			if r.Level == sectrust.LevelInfo {
				continue
			}
			if modified[r.File] && (r.Code == "parse_error" || r.Code == "file_over_cap") {
				partial(&cov, "a modified structured file was seen only through its added lines")
				continue
			}
			key := r.Code + "\x00" + r.File + "\x00" + r.Key
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, trustFinding(r, occ))
		}
	}
	return Result{Findings: out, Coverage: cov}
}

// partial marks coverage partial with a fixed note, once.
func partial(cov *Coverage, note string) {
	if cov.Status == CoverageComplete {
		cov.Status = CoveragePartial
		cov.Note = note
	}
}

// trustLaunchDir is the directory a changed file's config belongs to: its
// directory, cut at the first dot-directory (".claude/settings.json" is
// the root's; "packages/app/.claude/settings.json" is packages/app's).
func trustLaunchDir(rel string) string {
	segs := strings.Split(rel, "/")
	segs = segs[:len(segs)-1]
	for i, s := range segs {
		if strings.HasPrefix(s, ".") {
			segs = segs[:i]
			break
		}
	}
	return strings.Join(segs, "/")
}

// trustCodeWhat says, per reason code, what the finding is about; the
// message is built only from this table and the code table's own text,
// never from repository content.
func trustCodeWhat(code string) string {
	for _, row := range sectrust.Codes() {
		if row.Code == code {
			return row.Input
		}
	}
	return code
}

// trustFinding turns one trust reason into a finding: untrusted denies,
// flagged flags.
func trustFinding(r sectrust.Reason, occ map[string]int) Finding {
	rule := "repo-trust/" + r.Code
	sev, conf, act := SeverityMedium, ConfidenceMedium, ActionFlag
	if r.Level == sectrust.LevelUntrusted {
		sev, conf, act = SeverityHigh, ConfidenceHigh, ActionDeny
	}
	n := occ[rule+"\x00"+r.File]
	occ[rule+"\x00"+r.File] = n + 1
	return Finding{
		RuleID:        rule,
		Detector:      "repo_trust",
		Category:      CategoryRepoTrust,
		Severity:      sev,
		Confidence:    conf,
		Path:          r.File,
		Message:       "The repository trust check reports " + r.Code + ": " + trustCodeWhat(r.Code) + ". A coding agent started in this repository would read it before anyone looks.",
		Fingerprint:   fingerprint(rule, r.File, n),
		DefaultAction: act,
	}
}
