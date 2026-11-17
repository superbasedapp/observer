package secassess

import "fmt"

// The red team exercise (depth plan W7.3): the developer's own objective and
// the chain of steps a red team run took towards it. The objective is the
// developer's own words, cleaned and held to MaxObjective characters; the
// chain is structured (a step, the finding it used or produced, how it went,
// and the agent's opinion of what would have detected or stopped it), and
// Observer renders the narrative from that structure. There is no technique
// table and no objective library: nothing here names an ATT&CK technique.
//
// What this does not do, said once: the exercise is one application in one
// box. It does not pivot, does not test people, leaves nothing behind and does
// not test Observer's own guard or observability (limit l18). The chain is the
// agent's account and is checked only for its shape (row V16): that the steps
// are in the closed vocabulary and that a step names a finding that exists.

// MaxObjective is the longest objective, in characters.
const MaxObjective = 200

// CleanObjective cleans the developer's objective for the task and the record:
// one line, no backticks or invisible characters, dash runs shortened, at most
// MaxObjective characters.
func CleanObjective(s string) string { return clean(s, MaxObjective) }

// ruleV16 checks a red team run's exercise: the chain is capped at
// maxChainSteps steps, every text is cleaned, a step's result is one of
// EnumChainResult, and a finding a step cites must be a kept finding (a
// citation that is not is left out and the step stays). The objective is the
// developer's own when the run recorded one; the agent's own, cleaned the same
// way, when it did not. A kind that does not ask for an exercise has none: one
// in its file is left out and named.
func ruleV16(v *validator) {
	p := v.pt
	if p == nil {
		return
	}
	ex := p.Exercise
	if !v.o.Exercise {
		if ex != nil {
			v.issue("V16", "exercise_not_asked", SevDropped, "exercise", "This kind of assessment does not ask for an exercise, so the exercise in the file was left out.")
			p.Exercise = nil
		}
		return
	}
	if ex == nil {
		// The developer's objective belongs to the run, whatever the agent wrote.
		if obj := CleanObjective(v.o.Objective); obj != "" {
			p.Exercise = &PTExercise{Objective: obj, ObjectiveBy: ObjectiveByDeveloper}
		}
		return
	}
	switch obj := CleanObjective(v.o.Objective); {
	case obj != "":
		ex.Objective, ex.ObjectiveBy = obj, ObjectiveByDeveloper
	default:
		ex.Objective = v.cleanText(ex.Objective, MaxObjective, "objective")
		ex.ObjectiveBy = ""
		if ex.Objective != "" {
			ex.ObjectiveBy = ObjectiveByAgent
		}
	}
	v.read("chain", len(ex.Chain))
	if len(ex.Chain) > maxChainSteps {
		v.leftOut("chain", len(ex.Chain)-maxChainSteps)
		v.issue("V16", "cap_exceeded", SevRefused, "exercise.chain",
			fmt.Sprintf("exercise.chain: %d steps past the cap of %d were left out.", len(ex.Chain)-maxChainSteps, maxChainSteps))
		ex.Chain = ex.Chain[:maxChainSteps]
	}
	known := map[string]bool{}
	for i := range p.Findings {
		known[p.Findings[i].ID] = true
	}
	kept := make([]PTChainStep, 0, len(ex.Chain))
	for i, s := range ex.Chain {
		path := fmt.Sprintf("exercise.chain[%d]", i)
		s.Step = v.cleanText(s.Step, capShort, "chain step")
		s.Stop = v.cleanText(s.Stop, capShort, "chain stop")
		s.Finding = v.probeID(s.Finding)
		switch {
		case s.Step == "":
			v.refuseChain(path, "empty_text", "The chain step has no text.")
			continue
		case !EnumChainResult.Has(s.Result):
			v.refuseChain(path, "bad_enum", "The result "+clip(s.Result, 30)+" of a chain step must be achieved, partly or blocked.")
			continue
		}
		if s.Finding != "" && !known[s.Finding] {
			v.issue("V16", "unknown_finding", SevDropped, path,
				"The finding "+clip(s.Finding, 48)+" that the chain step cites is not one of the kept findings, so the citation was left out.")
			s.Finding = ""
		}
		kept = append(kept, s)
	}
	ex.Chain = kept
}

// refuseChain records a refused step of the exercise's chain.
func (v *validator) refuseChain(path, code, msg string) {
	c := v.rep.Counts["chain"]
	c.Refused++
	v.rep.Counts["chain"] = c
	v.issue("V16", code, SevRefused, path, msg)
}

// ChainResultWords are the words the narrative uses for a step's result.
var ChainResultWords = map[string]string{
	"achieved": "achieved",
	"partly":   "partly achieved",
	"blocked":  "blocked",
}

// ExerciseHonestLimit is the sentence that says what an exercise is not: it
// is limit l18 of the honest limits, quoted so the narrative and the page have
// one owner of the words.
func ExerciseHonestLimit() string { return limitText("l18") }

// ExerciseStopNote says whose opinion the "what would have detected or stopped
// this" column is.
const ExerciseStopNote = "What would have detected or stopped a step is the agent's opinion. Observer did not test any of it."

// mdPTExercise writes the exercise as a narrative in the order of the chain:
// the objective, the steps (each with the finding it cites, how it went and the
// agent's opinion of what would have stopped it) and what an exercise is not.
// Observer renders every line here from the structure the agent wrote; the
// agent's report is not read.
func mdPTExercise(w *mdWriter, pt *PentestDoc) {
	ex := pt.Exercise
	if ex == nil {
		return
	}
	w.heading(2, "Exercise")
	switch {
	case mdText(ex.Objective) == "":
		w.para("No objective is recorded for this exercise.")
	case ex.ObjectiveBy == ObjectiveByDeveloper:
		w.para("Objective, in the developer's own words: " + mdText(ex.Objective))
	default:
		w.para("Objective, as the agent states it: " + mdText(ex.Objective))
	}
	w.para(ExerciseHonestLimit())
	if len(ex.Chain) == 0 {
		w.para("The agent recorded no chain of steps in the model.")
		return
	}
	titles := map[string]string{}
	for _, f := range pt.Findings {
		titles[f.ID] = f.Title
	}
	w.para("The steps, in the order the agent lists them. " + ExerciseStopNote)
	for i, s := range ex.Chain {
		line := "Step " + mdInt(i+1) + ": " + mdText(s.Step)
		if s.Finding != "" {
			line += " Finding: " + mdLabel(s.Finding, titles[s.Finding]) + "."
		}
		line += " Result, as the agent says: " + mdText(ChainResultWords[s.Result]) + "."
		if st := mdText(s.Stop); st != "" {
			line += " What would have detected or stopped it, in the agent's opinion: " + st
		}
		w.bullet(0, line)
	}
	w.blank()
}
