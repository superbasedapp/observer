//go:build !sbo_omit_security

package dashboard

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
)

// security_assess_depth.go is the model-contract part of the Security
// assessments routes (docs/plans/security-assessments-depth-plan-2026-11-14.md,
// W1c): the one place a prompt's input is assembled from the settings, the
// digest the plan hands back so the launch can tell the developer when the
// prompt changed after they read it, the sets a model is checked against and
// the settings the import derives its findings under.

// codePlanChanged is the refusal of a launch whose prompt is no longer the one
// the developer read in the plan.
const codePlanChanged = "plan_changed"

// codeNotValidated is the refusal of an import of a model run whose model has
// no current, accepted check.
const codeNotValidated = "not_validated"

// The refusals of a request that needs the run record when it cannot be used.
const (
	codeRunRecordUnreadable = "run_record_unreadable"
	codeRunRecordFull       = "run_record_full"
	codeRunRecordBusy       = "run_record_busy"
)

// writeSecurityAssessRecordErr answers an error of the run record with its own
// 409 and says so (true), or reports false for any other error. The words name
// what happened and the way out; the answer also carries the file's path.
func (s *Server) writeSecurityAssessRecordErr(w http.ResponseWriter, err error) bool {
	var code, msg string
	switch {
	case errors.Is(err, secassesssvc.ErrUnreadable):
		code, msg = codeRunRecordUnreadable, "The run history file (secassess-runs.json, in the Observer data folder) cannot be read, so no assessment run is started or changed: a run that could not be recorded would have no time limit, no Stop and no closing check. Nothing in the file was changed. To recover, close any other Observer that is open, rename the file (for example to secassess-runs.json.bad) and try again. The runs it listed then stop being listed and their stored checks are cleared; their reports stay in each project's .observer/assessments folder."
	case errors.Is(err, secassesssvc.ErrFull):
		code, msg = codeRunRecordFull, "The run history is full of runs that are still in use, so a new run could not be recorded. Stop a running assessment, or wait for it to end, and try again."
	case errors.Is(err, secassesssvc.ErrLockBusy):
		code, msg = codeRunRecordBusy, "Another Observer process is writing the run history. Try again in a moment."
	default:
		return false
	}
	writeJSONStatus(w, http.StatusConflict, map[string]string{"error": msg, "code": code, "file": secassesssvc.Path(s.opts.DBPath)})
	return true
}

// writeSecurityAssessRunErr answers an error of a run lookup: the run record's
// own 409 when that is the cause, a 500 otherwise.
func (s *Server) writeSecurityAssessRunErr(w http.ResponseWriter, err error) {
	if !s.writeSecurityAssessRecordErr(w, err) {
		writeErrStatus(w, err, http.StatusInternalServerError)
	}
}

// securityAssessSetsOf reads the three preset settings of the model contract.
func securityAssessSetsOf(a config.SecurityAssessmentsConfig) secassesssvc.RunSets {
	return secassesssvc.RunSets{Frameworks: a.TMFrameworks, MethodExtras: a.TMMethodExtras, Categories: a.PTCategories}
}

// securityAssessResolveSets turns preset ids into the member lists the pure
// package takes. An id that names no preset (a hand-edited file the loader
// would have refused) takes the widest preset.
func securityAssessResolveSets(s secassesssvc.RunSets) (frameworks, extras, categories []string) {
	pick := func(list []secassess.Preset, id string) []string {
		if m, ok := secassess.ResolvePreset(list, id); ok {
			return m
		}
		m, _ := secassess.ResolvePreset(list, list[0].ID)
		return m
	}
	return pick(secassess.FrameworkPresets, s.Frameworks), pick(secassess.MethodExtraPresets, s.MethodExtras), pick(secassess.CategoryPresets, s.Categories)
}

// securityAssessPromptInput is the ONE place a prompt's input is assembled, for
// the plan and for the launch alike (G16): given the same settings and the same
// ticks the two builds are byte-identical, and the digest check tells the
// developer when they are not.
//
// backend is the sandbox backend the run is confined by (the eligibility
// verdict's: "" for a run that names none), which decides, with the daemon's own
// path, how the self-check line spells its command (secassess.SelfCheckBinary).
func securityAssessPromptInput(k secassess.Kind, runID, name string, target *secassess.Target, relax []secassess.InForce, lim securityAssessLimits, a config.SecurityAssessmentsConfig, backend string) secassess.PromptInput {
	in := secassess.PromptInput{Kind: k.ID, RunID: runID, ProjectName: name, Target: target, Relax: relax, TimeBoxMinutes: lim.Minutes}
	if k.ModelContract() {
		in.Frameworks, in.MethodExtras, in.Categories = securityAssessResolveSets(securityAssessSetsOf(a))
		in.SelfCheck = a.PromptSelfcheck
		in.Binary = secassess.BinaryFacts{Path: securityAssessObserverPath(), Backend: backend}
	}
	return in
}

// securityAssessObserverPath is the ONE seam that reads the daemon's own binary
// path for a prompt: what the operating system reports for the running
// executable, "" when it cannot say or the file is not a regular file any more
// (a binary replaced under the running daemon reads "<path> (deleted)" on Linux,
// which is not one). It reads nothing from the file. A test replaces
// osExecutable and securityAssessIsFile.
func securityAssessObserverPath() string {
	exe, err := osExecutable()
	if err != nil || exe == "" || !securityAssessIsFile(exe) {
		return ""
	}
	return exe
}

// securityAssessIsFile says whether p is a regular file: an existence check on
// the running executable, nothing read from it.
var securityAssessIsFile = func(p string) bool {
	fi, err := os.Stat(p) //nolint:gosec // G703: an existence check on the running executable
	return err == nil && fi.Mode().IsRegular()
}

// securityAssessDeriveSettings are the settings the import derives its findings
// under.
func securityAssessDeriveSettings(a config.SecurityAssessmentsConfig) secassesssvc.DeriveSettings {
	return secassesssvc.DeriveSettings{MinBand: secassess.Band(a.ImportMinBand), Cap: a.FindingsCap, Dedup: a.RerunDedup}
}

// securityAssessModelLimitsJS is the model contract's part of the plan's
// "settings in force": what the prompt asks for and what the import will do.
type securityAssessModelLimitsJS struct {
	PromptVersion string `json:"prompt_version"`
	Frameworks    string `json:"frameworks,omitempty"`
	MethodExtras  string `json:"method_extras,omitempty"`
	Categories    string `json:"categories,omitempty"`
	SelfCheck     bool   `json:"self_check"`
	ImportMinBand string `json:"import_min_band"`
	FindingsCap   int    `json:"findings_cap"`
	RerunDedup    bool   `json:"rerun_dedup"`
	// Grounding is the project-facts setting; SecretMode the environment-files
	// setting as chosen and SecretModeEffective the value in force (the sandbox
	// may not be able to do what was chosen); the request limits belong to a
	// penetration test or red team (depth plan W3.2, W4.4, W4.6).
	Grounding           string `json:"grounding,omitempty"`
	SecretMode          string `json:"secret_mode,omitempty"`
	SecretModeEffective string `json:"secret_mode_effective,omitempty"`
	// SecretModeDowngrade is why a configured mask acts as warn (a closed word,
	// secassess.MaskDowngradeWhy); omitted when it does not.
	SecretModeDowngrade string `json:"secret_mode_downgrade,omitempty"`
	RequestBudget       int    `json:"request_budget,omitempty"`
	PaceRPS             int    `json:"pace_rps,omitempty"`
}

// securityAssessModelLimitsView is the block for a kind with a model contract,
// nil for any other. A threat model reports its two sets and a penetration test
// its categories; the others stay empty so the dialog shows only what applies.
func securityAssessModelLimitsView(k secassess.Kind, a config.SecurityAssessmentsConfig) *securityAssessModelLimitsJS {
	if !k.ModelContract() {
		return nil
	}
	js := &securityAssessModelLimitsJS{
		PromptVersion: k.PromptVersion, SelfCheck: a.PromptSelfcheck,
		ImportMinBand: a.ImportMinBand, FindingsCap: a.FindingsCap, RerunDedup: a.RerunDedup,
	}
	if k.Contract == secassess.ContractThreatModel {
		js.Frameworks, js.MethodExtras = a.TMFrameworks, a.TMMethodExtras
	} else if !k.Retest {
		// A retest replays stored requests and tests no category.
		js.Categories = a.PTCategories
	}
	return js
}

// securityAssessLaunchModelFields sets the contract fields a run records at
// launch: the contract it is held to, the prompt version and the sets the
// prompt asked for. A kind without a model contract records none, so its runs
// read as they always did.
func securityAssessLaunchModelFields(run *secassesssvc.Run, k secassess.Kind, a config.SecurityAssessmentsConfig) {
	if !k.ModelContract() {
		return
	}
	sets := securityAssessSetsOf(a)
	run.Contract, run.PromptVersion, run.Sets = string(k.Contract), k.PromptVersion, &sets
}

// writePlanChanged answers a launch whose prompt differs from the plan's: the
// new prompt and its digest go back so the dialog can show what changed and ask
// again.
func writePlanChanged(w http.ResponseWriter, prompt string) {
	writeJSONStatus(w, http.StatusConflict, map[string]string{
		"error":         "The task changed after you read it (a setting or the project changed). Close this window and open the assessment again to read the new task before you start.",
		"code":          codePlanChanged,
		"prompt":        prompt,
		"prompt_sha256": secassess.PromptSHA256(prompt),
	})
}

// securityAssessValidateOptions are the sets a validation of the run is held to:
// the ones its prompt asked for, recorded at launch, else the settings now.
func (s *Server) securityAssessValidateOptions(run secassesssvc.Run) secassess.ValidateOptions {
	o := secassess.DefaultValidateOptions(secassess.Contract(run.Contract), run.ID)
	cfg := s.securityAssessConfig()
	a := cfg.Security.Assessments
	sets := securityAssessSetsOf(a)
	if run.Sets != nil {
		sets = *run.Sets
	}
	o.Frameworks, o.MethodExtras, o.Categories = securityAssessResolveSets(sets)
	// What Observer keeps is redacted when it is written, whatever
	// display_redaction says, with the developer's own extra patterns too.
	o.Redact = scrub.NewWithExtra(cfg.Observer.Secrets.ExtraPatterns).String
	o.ScopePaths = run.ScopePaths
	if run.Sets != nil {
		o.AIApp = run.Sets.AIApp
	}
	o.RefWindow, o.MaxBytes = a.RefMatchWindowLines, a.ModelMaxMiB<<20
	return o
}

// securityAssessRefBudget is the reference check's budget from the settings.
func securityAssessRefBudget(a config.SecurityAssessmentsConfig) secassesssvc.RefBudget {
	return secassesssvc.RefBudget{
		Files: a.RefBudgetFiles, TotalBytes: int64(a.RefBudgetMiB) << 20,
		Deadline: time.Duration(a.RefBudgetSeconds) * time.Second,
	}
}

// securityAssessImportDetail is the import audit row's content-free line: ids,
// outcome words and counts, never a finding, a path or any text from the model.
func securityAssessImportDetail(runID string, rec secassesssvc.ImportRecord) string {
	d := fmt.Sprintf("run %s outcome %s; %d findings, %d new, %d with lineage", runID, rec.Outcome, rec.Findings, rec.New, rec.WithLineage)
	if x := rec.Derived; x != nil {
		d += fmt.Sprintf("; derived %d of %d (no_location %d, under_min_band %d, duplicate %d, over_cap %d, over_ceiling %d)",
			x.Kept, x.Considered, x.NoLocation, x.UnderMinBand, x.Duplicate, x.OverCap, x.OverCeiling)
	}
	return d
}

// securityAssessValidatedDetail is the validated audit row's content-free line.
func securityAssessValidatedDetail(runID string, v secassesssvc.ValidationRecord) string {
	return fmt.Sprintf("run %s state %s; refs found %d exists %d claimed_not_found %d missing %d invalid %d unchecked %d; issues %d refused %d",
		runID, v.State, v.Refs.Found, v.Refs.Exists, v.Refs.ClaimedNotFound, v.Refs.Missing, v.Refs.Invalid, v.Refs.Unchecked, v.Issues, v.Refused)
}
