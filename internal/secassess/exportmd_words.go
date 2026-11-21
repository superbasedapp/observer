package secassess

// The words of the Markdown export that are Observer's own and are looked up
// by a value of the model: what a reference's state is called, how the agent's
// basis for a finding is worded, and what a validation state means. Every
// other word of the export is a literal in the renderer or a name from the
// vocabulary tables (vocab_*.go). A value no table here knows is never
// guessed: the reference states read as "not checked", the other two print the
// agent's word as the agent's.

// refStateWords says in words what Observer found when it looked at a
// reference. They are the web's MIT_STATE_WORDS labels (web/src/lib/
// secAssessModel.ts) in sentence case, one row per reference state; a missing
// place and a malformed one both read "cited place not found", as the web's
// not_located does. Only the first row earns the label "found near the cited
// line", and that label does not say the control works (limit l10).
var refStateWords = []struct {
	State RefState
	Words string
}{
	{RefFound, "found near the cited line"},
	{RefExists, "location exists, nothing matched"},
	{RefClaimedNotFound, "claimed, not found"},
	{RefUnchecked, "not checked"},
	{RefMissing, "cited place not found"},
	{RefInvalid, "cited place not found"},
}

// refStateUnknown is what a reference whose state is empty or not in the table
// reads as: Observer cannot say it looked.
const refStateUnknown = "not checked"

// refStateWord is the words of one reference state.
func refStateWord(s RefState) string {
	for _, r := range refStateWords {
		if r.State == s {
			return r.Words
		}
	}
	return refStateUnknown
}

// basisWords are the agent's two bases for a pen test finding, said as the
// agent's claim and never as Observer's.
var basisWords = map[string]string{
	"observed": "the agent says it saw this in a request",
	"inferred": "the agent says it inferred this from the code",
}

// validationStateWords say what each validation state means, in Observer's
// words.
var validationStateWords = map[ValidationState]string{
	ValidationValid:   "The file was read and nothing was refused.",
	ValidationPartial: "The file was read, and some items were refused or left out (the issues below say which).",
	ValidationInvalid: "The file was refused and no model was kept.",
}

// contractPlainNames are the kind titles used when the kind id is not in the
// kind table: the plain name of what the contract holds.
var contractPlainNames = map[Contract]string{
	ContractThreatModel: "Threat model",
	ContractPentest:     "Penetration test",
}

// contractPlainFallback names an assessment whose kind and contract are both
// unknown.
const contractPlainFallback = "Security assessment"
