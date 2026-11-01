package main

import "github.com/marmutapp/superbased-observer/internal/componentstate"

// securityOptIn lists the security children that, until their fix lanes
// land, run only when a [components] block selects them. A config with no
// block resolves every compiled module active (componentstate.Legacy), so
// without this an existing install would gain a check it never chose while
// its known defects are open. security.scan.custom: opt-in by design, off in every distro (P-023). security.githooks: plans decision
// log P-025, opt-in until its pre-push stdin and exit-code defects are
// fixed. security.deps and its two driver children security.scan.scalibr
// and security.scan.osv were offered by lane sec-deps4 (decision log P-036,
// after the operator's download rulings PT-19): they now run on an install
// with no block wherever they are compiled. security.trust was offered the
// same way (decision log P-044) once lanes sec-trustfix to sec-trust4 had
// closed its offer blockers. security.scan.opengrep: the code-rules driver
// of lane sec-g1, off in every distro and opt-in until its offer
// (TestOpengrepOfferedByDefault describes the one step).
// security.feedback: off by design (security pillar plan section 6.5,
// Q13), offered in one step by the orchestrator
// (TestFeedbackOfferedByDefault, lane sec-h). security.provenance: the
// signed AI change records, off in every distro by ruling Q9 (security
// pillar plan 4.2 and 7.10, lane sec-f2a); with no block no key is made,
// nothing is recorded or pushed and no repository is written.
// security.scan.sarif-import and security.scan.actionlint: the Phase G
// drivers of lane sec-g5, off in every distro (dist(out, off, off, off),
// actionlint compiled only in managed and full) and opt-in until the
// orchestrator offers them. security.scan.trivy and security.scan.kics: the
// IaC process drivers of lane GATES-SEC (operator ruling P-129), off in
// every distro and opt-in: with no block nothing runs, downloads or is
// probed beyond "not selected".
var securityOptIn = map[string]bool{
	"security.scan.custom":       true,
	"security.githooks":          true,
	"security.scan.opengrep":     true,
	"security.feedback":          true,
	"security.provenance":        true,
	"security.scan.sarif-import": true,
	"security.scan.actionlint":   true,
	"security.scan.trivy":        true,
	"security.scan.kics":         true,
}

// securitySelected is the optional-module predicate for a security id with
// the opt-in rule above applied.
func securitySelected(snap componentstate.Snapshot, id string) bool {
	if securityOptIn[id] && !snap.BlockSelects(id) {
		return false
	}
	return snap.ModuleActive(id)
}
