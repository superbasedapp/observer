package secassess

// State is a run's derived state, computed live from the result files and the
// recorded import outcome so a file the agent writes later still moves the run
// forward.
type State string

// The run states.
const (
	// StateStarted: launched, no result file yet.
	StateStarted State = "started"
	// StateReportReady: the report exists, the findings file does not.
	StateReportReady State = "report_ready"
	// StateFindingsReady: the findings file exists and has not been imported.
	StateFindingsReady State = "findings_ready"
	// StateImported: the findings were imported.
	StateImported State = "imported"
	// StateImportFailed: the last import attempt failed (the file was
	// refused or the node could not record it).
	StateImportFailed State = "import_failed"
	// StateImportUnavailable: the SARIF import component is not selected.
	StateImportUnavailable State = "import_unavailable"
	// StateModelReady: (model contract) assessment.json is present and has not
	// been validated, or changed since it was.
	StateModelReady State = "model_ready"
	// StateValidated: (model contract) the model was validated; nothing was
	// refused or some items were (the validation record says which).
	StateValidated State = "validated"
	// StateInvalid: (model contract) the model was refused whole.
	StateInvalid State = "invalid"
	// StateNoFindings: (model contract) the model was validated and the import
	// derived no finding from it. It says nothing about the project: a model
	// with no located missing mitigation derives none, and so does one whose
	// items sit under the developer's minimum band. It is never "clean".
	StateNoFindings State = "no_findings"
	// StateEndedEmpty: the run's terminal ended and the agent wrote no result
	// file at all: no report, no model, no findings file. Nothing was produced
	// to read or check. The first live run (2026-11-15) had a launch whose
	// terminal exited with code 1 within seconds (the box refused it) and the
	// card read "running, waiting for the agent" for hours beside "ended when
	// the terminal closed": a run that is over must not read as running. How it
	// ended (the terminal closed, the time box, Stop) is the run's EndWhy; the
	// state says only that the ending produced nothing.
	StateEndedEmpty State = "ended_empty"
)

// ImportOutcome is what the last import attempt recorded ("" none).
type ImportOutcome string

// The import outcomes.
const (
	ImportNone        ImportOutcome = ""
	ImportDone        ImportOutcome = "imported"
	ImportFailed      ImportOutcome = "failed"
	ImportUnavailable ImportOutcome = "unavailable"
	// ImportNoFindings: a model's import derived no result to import.
	ImportNoFindings ImportOutcome = "no_findings"
)

// FilesPresent says which result files exist as regular files.
type FilesPresent struct {
	Report   bool
	SARIF    bool
	Commands bool
	// Model is the assessment.json of a kind with a model contract.
	Model bool
}

// StateOf derives a run's state. An import attempt recorded after the
// findings file changed is the caller's business (it clears the outcome when
// it sees the file change); here the outcome wins while the findings file is
// there.
func StateOf(f FilesPresent, imp ImportOutcome) State {
	switch {
	case f.SARIF && imp == ImportDone:
		return StateImported
	case f.SARIF && imp == ImportFailed:
		return StateImportFailed
	case f.SARIF && imp == ImportUnavailable:
		return StateImportUnavailable
	case f.SARIF:
		return StateFindingsReady
	case f.Report:
		return StateReportReady
	default:
		return StateStarted
	}
}

// ModelState is what the recorded validation says about a run's assessment.json.
type ModelState struct {
	// Validation is the last validation's outcome ("" none).
	Validation ValidationState
	// Stale: the file changed after that validation (size or time differ), so
	// the outcome describes an older file.
	Stale bool
}

// StateOfModel derives the state of a run launched under a model contract
// (threatmodel.v1, pentest.v1). The agent's own findings.sarif plays no part:
// the import takes the findings Observer derives from the validated model. An
// import outcome is honoured only while the validated model it came from is
// still the file on disk, the same rule StateOf has for the findings file.
func StateOfModel(f FilesPresent, m ModelState, imp ImportOutcome) State {
	validated := f.Model && !m.Stale && (m.Validation == ValidationValid || m.Validation == ValidationPartial)
	switch {
	case validated && imp == ImportDone:
		return StateImported
	case validated && imp == ImportNoFindings:
		return StateNoFindings
	case validated && imp == ImportFailed:
		return StateImportFailed
	case validated && imp == ImportUnavailable:
		return StateImportUnavailable
	case validated:
		return StateValidated
	case f.Model && !m.Stale && m.Validation == ValidationInvalid:
		return StateInvalid
	case f.Model:
		return StateModelReady
	case f.Report:
		return StateReportReady
	default:
		return StateStarted
	}
}

// endedStates is the one table of what a run's state becomes once its terminal
// has ended (EndedAt recorded). A state that is not a row stays as it is: a
// run that wrote a report, a model or a findings file has something to read,
// and its state already says how far it got. Only "launched, nothing written
// yet" means something different after the end than before it: before, the
// agent may still write; after, nothing will.
var endedStates = []struct {
	From State
	To   State
}{
	{StateStarted, StateEndedEmpty},
}

// StateWhenEnded folds the end of a run's terminal into its derived state. It
// is applied after StateOf or StateOfModel, never inside them: those two judge
// the files and the recorded import; whether the terminal is still there is a
// fact about the run, not the files.
func StateWhenEnded(s State, ended bool) State {
	if !ended {
		return s
	}
	for _, r := range endedStates {
		if r.From == s {
			return r.To
		}
	}
	return s
}

// States returns every run state the server can send, in lifecycle order. The
// web's word table (web/src/lib/secAssess.ts ASSESS_STATE) is checked against
// this list by a test that parses both, so a new state cannot ship without its
// words.
func States() []State {
	return []State{
		StateStarted, StateEndedEmpty, StateReportReady, StateModelReady, StateValidated, StateInvalid,
		StateFindingsReady, StateImported, StateNoFindings, StateImportFailed, StateImportUnavailable,
	}
}
