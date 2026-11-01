// Package secquickscan is the commit gate's quick scan (security pillar
// plan docs/plans/security-pillar-plan-2026-10-19.md section 4.8 "The quick
// scan", D-761, D-764 Q21, D-791 Q27; security Phase C).
//
// At an agent's git_commit or git_push the hook asks the daemon for one
// quick scan. The daemon computes exactly what the commit would record (the
// staged diff, the tracked working-tree diff for `commit -a`, the named
// paths for `commit <pathspec>`, the commits not yet on the upstream for a
// push) through the read-only git envelope it is given, looks the diff's
// hash up in its cache of clean results, and otherwise runs the native
// detectors over the added lines within its budget: a fixed 2 seconds on an
// individual node, the floor's budget on a managed node under a floor. It
// answers clean (and reports the dirty counter value it covered, so the
// next commit is clean without a wait), blocking with the findings, or
// unknown (over budget, git unavailable, output over its cap, a detector
// that did not finish). Unknown is never clean.
//
// Today the native detector set is the secret rows (internal/secdetect);
// the trust, install-index, CI-workflow and test-tampering detectors join
// as their phases land. External engines are never part of the quick scan.
//
// The package is pure: git is an injected function (production passes
// gitview.RunReadOnlyTimeout), the clock is injected, and the result is
// plain data. It never stores content: findings carry a path, a line and a
// detector type.
package secquickscan
