package secassess

// The honest limits of an assessment (depth plan section 13), as a Go table.
// The web owns the wording today (HONEST_LIMITS in
// web/src/lib/secAssessModel.ts); this table is the same list for the
// exports, which are written by Go and must say the same things the page says.
// limits_test.go reads the TypeScript and fails when the two differ in order,
// id, group or text, so a drift is loud on whichever side moves.
//
// None of the sentences says that a project is free of weaknesses; the
// wording pin in reading_test.go (testdata/clearance_words.json) applies to
// them too.

// The groups of limits: who a limit applies to.
const (
	// LimitsBoth marks a limit every assessment reads.
	LimitsBoth = "both"
	// LimitsThreatModel marks a limit of a threat model only.
	LimitsThreatModel = "threatmodel"
	// LimitsPentest marks a limit of a penetration test or red team run only.
	LimitsPentest = "pentest"
)

// Limit is one honest limit: what an assessment does not tell the reader.
type Limit struct {
	// ID is the limit's id in the plan ("l1" to "l20").
	ID string
	// Applies is the group the limit belongs to (LimitsBoth,
	// LimitsThreatModel or LimitsPentest).
	Applies string
	// Text is the sentence or sentences, in plain words.
	Text string
}

// HonestLimits is section 13 of the depth plan, in its order. It is the same
// list as HONEST_LIMITS in web/src/lib/secAssessModel.ts.
var HonestLimits = []Limit{
	{"l1", LimitsBoth, "The agent wrote this, and Observer checked only its structure, its closed word lists, the files it cites and git state. It did not check that the reasoning is right, that a weakness it names can be exploited, or that nothing was missed."},
	{"l2", LimitsBoth, "Two runs of the same prompt differ, and how well a run finds a kind of flaw depends on the model and the prompt version. What was measured on the test project applies to that project's kinds of flaw, for one model and one prompt version at a time."},
	{"l3", LimitsBoth, "Nothing reported is not a clearance. A run that reports no threats or findings always comes with its coverage line, which says what was and was not covered, and an empty list is never a sign that the project has no flaw left to find."},
	{"l4", LimitsBoth, "This is not compliance evidence. No PCI, SOC 2, ISO or customer-assurance claim follows from it, and it does not replace a test by a person."},
	{"l5", LimitsBoth, "Imported findings are flags. They carry low confidence, their severity is capped at medium, they close nothing, and they stay outside the high-confidence findings the commit gate blocks on. The band lives in this view."},
	{"l6", LimitsBoth, "Reports can be wrong in confident prose. The narrative is shown as text Observer has not checked. Hiding secrets hides only the ones Observer recognises, not all sensitive content, and the files on disk are as the agent wrote them."},
	{"l7", LimitsBoth, "The git check looks at git state only: edits to tracked files, HEAD, the branch, the stash and refs. It does not see ignored files (.env files, local databases, caches, node_modules), reads, or anything you changed meanwhile. It is not a trace."},
	{"l8", LimitsThreatModel, "The model comes from code and docs only. It has no business context, no deployed layout, no cloud or SaaS service the code does not show, and no organisational or physical threats. A component that is not in the model is unknown; it is not ruled out."},
	{"l9", LimitsThreatModel, "Likelihood and impact are judgements. The band is an ordinal heuristic, the product of two ratings from 1 to 5, not a probability or a loss figure. No residual score is computed."},
	{"l10", LimitsThreatModel, "Found near the cited line does not mean a working control. It means the file, the cited lines and a quoted text of 8 characters or more on a code line near the cited line exist. The control may be wrong or unreachable, and a quoted text inside a string literal on a code line still matches. Location exists, nothing matched earns no credit."},
	{"l11", LimitsThreatModel, "Completeness is structural. For each element and category, Observer checks that the model has a threat or a stated reason that none applies, and counts the waived cells apart. It does not check that the threats named are the right ones."},
	{"l12", LimitsPentest, "The target is a copy of your working tree in a box, with development settings. It is not production: no deployed headers or TLS, no firewall or reverse proxy, no production data volumes, no real identity provider or outside integration (the box has no route to them) and no infrastructure. One origin only."},
	{"l13", LimitsPentest, "Helper log matches means that a logged request returned the indicated response in that copy, for an attack request and not for its control request, and that the request helper Observer wrote was unchanged when the run was checked. The log is a file the agent can write. It does not show the weakness can be used against production, and it is not proof of impact. A run that did not start the app tested nothing in a running application."},
	{"l14", LimitsPentest, "The coverage matrix is the agent's claim, set beside a log; it is not a trace. A request made with curl or with the agent's own code is not logged, and Observer cannot see loopback traffic inside the box's network namespace."},
	{"l15", LimitsPentest, "Scope holds by the sandbox, not by the prompt. With the proxy-only network tier the box has no route out except the model proxy, whose upstream lanes can include a local model server. Under a wider tier, staying on the target is held by the prompt, the host list and your word, and the dialog says so."},
	{"l16", LimitsPentest, "The workspace is your live tree, and the box can read .env files there. The git check reports changes, not reads."},
	{"l17", LimitsPentest, "The band is likelihood times impact, from the agent's two ratings. A finding may also carry a CVSS 4.0 base vector the agent wrote, and Observer computes its base score from that vector alone. That score is the weakness as logged in an in-box copy, not a production risk, and it changes neither the band nor the severity an import carries."},
	{"l18", LimitsPentest, "A red team run is one application in one box: no pivoting, no social engineering, no persistence and no real detection testing. Observer's own guard and observability were not tested by it."},
	{"l19", LimitsPentest, "Numbers measured on the test project are not coverage, and a public test project may be in a model's training data. Recall on seeded flaws says how one model and prompt pair does on those kinds of flaw."},
	{"l20", LimitsPentest, "A retest repeats the stored requests of findings from an earlier run and labels each one reproduced, not reproduced or inconclusive. The label reads one replay against the response condition stored with the finding, in an in-box copy. Not reproduced does not mean the weakness is gone from your code or from production, and for a request that had values hidden when it was stored the log does not back it at all. A retest closes nothing and changes no finding's status."},
}

// limitGroupOfContract says which group of limits a result contract reads
// besides LimitsBoth. A contract not listed (the SARIF contract, or one this
// build does not know) reads the limits of both kinds only.
var limitGroupOfContract = map[Contract]string{
	ContractThreatModel: LimitsThreatModel,
	ContractPentest:     LimitsPentest,
	ContractRetest:      LimitsPentest,
}

// LimitsFor returns the limits that apply to a contract, in the plan's order:
// every limit of LimitsBoth and every limit of the contract's own group. It
// returns a new slice; the table is not shared.
func LimitsFor(c Contract) []Limit {
	group := limitGroupOfContract[c]
	var out []Limit
	for _, l := range HonestLimits {
		if l.Applies == LimitsBoth || (group != "" && l.Applies == group) {
			out = append(out, l)
		}
	}
	return out
}

// limitText returns the text of the limit with the given id, "" when there is
// none. The exports quote limit l1 for what the check covered, so the sentence
// has one owner.
func limitText(id string) string {
	for _, l := range HonestLimits {
		if l.ID == id {
			return l.Text
		}
	}
	return ""
}
