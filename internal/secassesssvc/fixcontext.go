package secassesssvc

import "github.com/marmutapp/superbased-observer/internal/secassess"

// FixContext is the one seam the Findings tab's "Fix with an agent" has into the
// security assessments module (depth plan W6b, decision D24). For a finding
// that an assessment's import created (a rule id of the form
// other/assess.<tag>[.<run>].<suffix>) it returns one Observer-templated
// sentence: the class of the weakness, named from Observer's own tables, and the
// reminder to confirm the weakness in the code and to add a regression test.
// The finding's place and its band are already in the task from the finding's
// own row, so they are not repeated here. ok is false for every other rule id.
//
// Nothing the assessment's agent wrote reaches the sentence: the rule id is the
// only input, and the only parts of it that are read are looked up in tables.
func FixContext(ruleID string) (string, bool) { return secassess.FixHintFor(ruleID) }
