package secassesssvc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// ModelSchema is the schema version of the stored model.json.
const ModelSchema = 1

// Errors a validation can return.
var (
	// ErrNoModelContract: the run was not launched under a model contract, so
	// there is no assessment.json to validate.
	ErrNoModelContract = errors.New("secassesssvc: the run was not launched under a model contract")
	// ErrRunNotStarted: the run is held or cancelled, so it has no run folder.
	ErrRunNotStarted = errors.New("secassesssvc: the run has not started")
	// ErrRunRunning: the run has not ended, so its model may still be written.
	// Validate again after it ends, or ask to validate anyway.
	ErrRunRunning = errors.New("secassesssvc: the run has not ended")
	// ErrValidationTimeout: the validation did not finish in time. A walk
	// stopped by its own deadline marks the rest unchecked and still finishes;
	// this is the backstop for a file system that hangs.
	ErrValidationTimeout = errors.New("secassesssvc: the validation did not finish in time")
)

// hardGrace is how long past the reference walk's own deadline ValidateRun waits
// for the validator before it gives up on it (the walk's deadline ends it
// cleanly; this is the backstop for a file system that hangs).
const hardGrace = 4 * time.Second

// ModelRecord is the stored copy of a validation (side file model.json): the
// checked model, the report of what the validator found, and what the files it
// looked at read like then. It is Observer's own text and numbers; the agent's
// file is never copied as it was.
type ModelRecord struct {
	Schema      int                `json:"schema"`
	RunID       string             `json:"run_id"`
	ValidatedAt time.Time          `json:"validated_at"`
	Contract    secassess.Contract `json:"contract"`
	// Anyway: validated before the run ended; the model may have been partial.
	Anyway bool `json:"anyway,omitempty"`
	// SourceSHA identifies the assessment.json that was validated (the first
	// 8 bytes of its SHA-256, hex), SourceBytes its size.
	SourceSHA   string `json:"source_sha,omitempty"`
	SourceBytes int64  `json:"source_bytes"`
	// Files are the project files the references were checked against.
	Files []FileStamp `json:"files,omitempty"`
	// Truncated: the model did not fit the side file's cap and was left out;
	// the report is kept.
	Truncated bool             `json:"truncated,omitempty"`
	Result    secassess.Result `json:"result"`
	// RefBudget is the read budget the reference walk ran under (settings
	// ref_budget_*). A reference the walk ran out of budget for reads "not
	// checked", so with the match window (Result.Report.RefCheck) it is one of the
	// settings the reference tally depends on; a stored copy that predates the
	// field has none.
	RefBudget *RefBudgetRecord `json:"ref_budget,omitempty"`
	// Compared is the earlier run this model was compared with once it was
	// checked ("" none was chosen); CompareState says how that went: "ok",
	// "previous_missing" (the earlier run's checked copy is gone, was too large
	// to keep or is not a threat model) or "too_large" (the comparison did not
	// fit the stored copy and was left out). Diff is the comparison. Nothing
	// from the earlier run was ever given to the agent.
	Compared     string               `json:"compared,omitempty"`
	CompareState string               `json:"compare_state,omitempty"`
	Diff         *secassess.ModelDiff `json:"diff,omitempty"`
}

// The comparison states of a stored model.
const (
	CompareOK              = "ok"
	ComparePreviousMissing = "previous_missing"
	CompareTooLarge        = "too_large"
)

// RefBudgetRecord is a reference walk's budget in the units the settings use.
type RefBudgetRecord struct {
	Files   int `json:"files"`
	MiB     int `json:"mib"`
	Seconds int `json:"seconds"`
}

// refBudgetRecordOf is the record of a budget (the defaults filled in), in whole
// units: a partial MiB or second rounds up, so the record never says less than
// was allowed.
func refBudgetRecordOf(b RefBudget) *RefBudgetRecord {
	b = b.orDefault()
	return &RefBudgetRecord{
		Files:   b.Files,
		MiB:     int((b.TotalBytes + (1 << 20) - 1) >> 20),
		Seconds: int((b.Deadline + time.Second - 1) / time.Second),
	}
}

// ValidationRecord is the scalar part of a validation kept on the run (the run
// record holds scalars only; the model itself is side data).
type ValidationRecord struct {
	At     time.Time `json:"at"`
	State  string    `json:"state"`
	Fatal  string    `json:"fatal,omitempty"`
	Anyway bool      `json:"anyway,omitempty"`
	// ModelBytes and ModelMod (Unix nanoseconds) identify the file that was
	// validated, so a later change is seen without reading it again.
	ModelBytes int64              `json:"model_bytes"`
	ModelMod   int64              `json:"model_mod,omitempty"`
	Refs       secassess.RefTally `json:"refs"`
	// RefWindow is the match window the references were checked under (setting
	// ref_match_window_lines) and RefTextHidden how many references quoted text
	// the redactor changed and did not read found: the conditions of Refs, so a
	// count on the row is never read without them. Zero for a check that
	// predates them or looked at no files.
	RefWindow     int `json:"ref_window,omitempty"`
	RefTextHidden int `json:"ref_text_hidden,omitempty"`
	// Issues counts what the validator reported (including the ones it did not
	// keep); Refused counts items it refused.
	Issues  int `json:"issues,omitempty"`
	Refused int `json:"refused,omitempty"`
	// CompareState says how the comparison with the earlier run went when one
	// was chosen (ok, previous_missing, too_large; "" none was chosen or the
	// model was not a threat model), so the run row can say so without opening
	// the stored copy.
	CompareState string `json:"compare_state,omitempty"`
}

// ModelInput is one validation.
type ModelInput struct {
	ProjectRoot string
	Run         Run
	// Options carries the sets in force (frameworks, categories, scope); the
	// service fills Contract, RunID, TargetURL and Refs.
	Options secassess.ValidateOptions
	// Anyway allows a run that has not ended.
	Anyway bool
	Now    time.Time
	// Budget limits the reference walk (settings ref_budget_*); zero fields
	// read as the defaults.
	Budget RefBudget
	// PreviousRun is the earlier threat model run to compare with ("" none) and
	// Previous its checked model; a nil Previous with a PreviousRun says the
	// earlier copy is gone.
	PreviousRun string
	Previous    *secassess.ThreatModelDoc
	// Retest is the basis a retest's file is held to: the findings of the earlier
	// run it was asked to replay, from that run's own stored model. Required for a
	// run of a retest kind; unused otherwise.
	Retest *secassess.RetestBasis
}

// scalars is the record the run keeps for a validation.
func (m ModelRecord) scalars(mod time.Time) ValidationRecord {
	rep := m.Result.Report
	v := ValidationRecord{
		At: m.ValidatedAt, State: string(rep.State), Fatal: rep.Fatal, Anyway: m.Anyway,
		ModelBytes: m.SourceBytes, Refs: rep.Refs, Issues: len(rep.Issues) + rep.IssuesMore,
		CompareState: m.CompareState,
	}
	if rc := rep.RefCheck; rc != nil {
		v.RefWindow, v.RefTextHidden = rc.WindowLines, rc.TextHidden
	}
	if !mod.IsZero() {
		v.ModelMod = mod.UnixNano()
	}
	for _, c := range rep.Counts {
		v.Refused += c.Refused
	}
	return v
}

// refusedResult is the result of a file that could not be read for validation.
func refusedResult(c secassess.Contract, code, msg string) secassess.Result {
	return secassess.Result{Report: secassess.Report{
		State: secassess.ValidationInvalid, Contract: c, Fatal: code,
		Issues: []secassess.Issue{{Row: "V1", Code: code, Severity: secassess.SevRefused, Message: msg}},
	}}
}

type validated struct {
	res    secassess.Result
	stamps []FileStamp
}

// ValidateRun reads the run's assessment.json (through os.Root, a regular file
// only, at most the size cap the options carry: 4 MiB by default, the setting
// model_max_mib), validates it with the project's files as the reference
// ground truth, and returns the stored copy and the run's scalar record. The
// caller keeps the scalar record on the run (Store.SetValidation); when side is
// not nil the stored copy is written to model.json here.
func ValidateRun(ctx context.Context, side *SideData, in ModelInput) (ModelRecord, ValidationRecord, error) {
	contract := secassess.Contract(in.Run.Contract)
	if contract.Schema() == "" {
		return ModelRecord{}, ValidationRecord{}, ErrNoModelContract
	}
	if !in.Run.IsStarted() {
		return ModelRecord{}, ValidationRecord{}, ErrRunNotStarted
	}
	if in.Run.EndedAt.IsZero() && !in.Anyway {
		return ModelRecord{}, ValidationRecord{}, ErrRunRunning
	}
	paths := secassess.ResultPaths(in.Run.ID)
	if in.ProjectRoot == "" || paths.Dir == "" {
		return ModelRecord{}, ValidationRecord{}, ErrAbsent
	}
	capBytes := in.Options.ModelCap()
	data, fi, err := readResultStat(in.ProjectRoot, paths.Model, int64(capBytes))
	rec := ModelRecord{Schema: ModelSchema, RunID: in.Run.ID, ValidatedAt: in.Now.UTC(), Contract: contract, Anyway: in.Anyway}
	switch {
	case errors.Is(err, ErrAbsent):
		return rec, ValidationRecord{}, ErrAbsent
	case errors.Is(err, ErrTooLarge):
		rec.Result = refusedResult(contract, "too_large", fmt.Sprintf("The file is over its size cap of %d MiB (the setting model_max_mib), so it was not read.", capBytes>>20))
	case errors.Is(err, ErrNotRegular):
		rec.Result = refusedResult(contract, "not_regular", "The path is not a regular file (a link, a folder or a device), so it was not read.")
	case err != nil:
		return rec, ValidationRecord{}, err
	}
	var mod time.Time
	var facts secassess.ProbeFacts
	if err == nil {
		sum := sha256.Sum256(data)
		rec.SourceSHA, rec.SourceBytes, mod = hex.EncodeToString(sum[:8]), int64(len(data)), fi.ModTime()
		if contract == secassess.ContractPentest || contract == secassess.ContractRetest {
			facts = ReadProbeFacts(in.ProjectRoot, in.Run)
		}
		out, verr := runValidator(ctx, in, contract, data, facts)
		if verr != nil {
			return rec, ValidationRecord{}, verr
		}
		rec.Result, rec.Files = out.res, out.stamps
		if out.res.Report.RefCheck != nil {
			rec.RefBudget = refBudgetRecordOf(in.Budget)
		}
		compare(&rec, in)
		keepComparison(&rec, side)
	}
	scalars := rec.scalars(mod)
	if side != nil {
		scalars.CompareState = storedCompareState(rec, sideCaps[SideModel])
		if blob, truncated := fitModel(rec); blob != nil {
			rec.Truncated = truncated
			if perr := side.Put(in.Run.ID, SideModel, blob); perr != nil {
				return rec, scalars, nil // the verdict stands; only the stored copy was lost
			}
		}
		storeProbes(side, rec, facts, in.Options.Redact)
	}
	return rec, scalars, nil
}

// storedCompareState is the comparison state the stored copy will carry: the
// record's own, except that a comparison the copy is too large to hold is
// "too_large" (fitModelWithin drops the diff first and says so), so the run row
// never claims a comparison the stored copy cannot show.
func storedCompareState(rec ModelRecord, limit int) string {
	if rec.Diff == nil {
		return rec.CompareState
	}
	if b, err := marshalStored(rec); err == nil && len(b) <= limit {
		return rec.CompareState
	}
	return CompareTooLarge
}

// compare adds the comparison with the earlier run to the stored copy, when the
// run asked for one and its own model was kept.
func compare(rec *ModelRecord, in ModelInput) {
	if in.PreviousRun == "" || rec.Contract != secassess.ContractThreatModel || rec.Result.TM == nil {
		return
	}
	rec.Compared = in.PreviousRun
	if in.Previous == nil {
		rec.CompareState = ComparePreviousMissing
		return
	}
	d := secassess.DiffModels(in.Previous, rec.Result.TM)
	d.PrevRun = in.PreviousRun
	rec.CompareState, rec.Diff = CompareOK, &d
}

// keepComparison keeps the comparison a run's stored copy already holds when the
// run is validated again after the earlier run's copy was pruned (compare then
// finds no earlier model and says previous_missing). The stored comparison was
// made from this very file against that very earlier run, so it is still true:
// it is kept when the run names the same earlier run, the stored state is "ok"
// and the assessment.json is the same (the same SourceSHA). A different file or
// a different earlier run is a new question the missing copy cannot answer, and
// the state stays previous_missing.
func keepComparison(rec *ModelRecord, side *SideData) {
	if side == nil || rec.CompareState != ComparePreviousMissing {
		return
	}
	old, ok := ReadModel(side, rec.RunID)
	if !ok || old.CompareState != CompareOK || old.Diff == nil || old.Compared != rec.Compared || old.SourceSHA == "" || old.SourceSHA != rec.SourceSHA {
		return
	}
	rec.CompareState, rec.Diff = CompareOK, old.Diff
}

// runValidator runs the pure validator over data with a reference checker
// whose own deadline ends the walk cleanly. The validator runs in a goroutine
// the caller can abandon, and the goroutine owns (and closes) the checker.
func runValidator(ctx context.Context, in ModelInput, contract secassess.Contract, data []byte, probe secassess.ProbeFacts) (validated, error) {
	budget := in.Budget.orDefault()
	chk, err := NewRefChecker(in.ProjectRoot, time.Now().Add(budget.Deadline), nil)
	if err != nil {
		return validated{}, err
	}
	chk.WithBudget(budget)
	opts := in.Options
	opts.Contract, opts.RunID, opts.Refs = contract, in.Run.ID, chk
	switch contract {
	case secassess.ContractPentest:
		opts.TargetURL, opts.Probe = in.Run.Target, probe
		// A kind that asks for an exercise has its objective and chain read (row
		// V16); the run holds the developer's own words.
		if k, ok := secassess.KindByID(in.Run.Kind); ok && k.Exercise {
			opts.Exercise, opts.Objective = true, in.Run.Objective
		}
	case secassess.ContractRetest:
		opts.Probe, opts.Retest = probe, in.Retest
	}
	done := make(chan validated, 1)
	go func() {
		defer chk.Close()
		res := secassess.Validate(data, opts)
		done <- validated{res: res, stamps: chk.Files()}
	}()
	timer := time.NewTimer(budget.Deadline + hardGrace)
	defer timer.Stop()
	select {
	case v := <-done:
		return v, nil
	case <-timer.C:
		return validated{}, ErrValidationTimeout
	case <-ctx.Done():
		return validated{}, ctx.Err()
	}
}

// fitModel marshals the record to at most the side file's cap: the whole
// record, else the report without the model, else the report without its
// issues. truncated says the model was left out. nil: nothing fits.
func fitModel(rec ModelRecord) (blob []byte, truncated bool) {
	return fitModelWithin(rec, sideCaps[SideModel])
}

// fitModelWithin is fitModel under an explicit size limit.
func fitModelWithin(rec ModelRecord, limit int) (blob []byte, truncated bool) {
	try := func(r ModelRecord) []byte {
		b, err := marshalStored(r)
		if err != nil || len(b) > limit {
			return nil
		}
		return b
	}
	if b := try(rec); b != nil {
		return b, false
	}
	if rec.Diff != nil {
		// The comparison goes first: it is derived, and can be made again from
		// the two stored copies while both exist.
		rec.Diff, rec.CompareState = nil, CompareTooLarge
		if b := try(rec); b != nil {
			return b, false
		}
	}
	rec.Result.TM, rec.Result.PT, rec.Result.RT, rec.Truncated = nil, nil, nil, true
	if b := try(rec); b != nil {
		return b, true
	}
	rec.Result.Report.IssuesMore += len(rec.Result.Report.Issues)
	rec.Result.Report.Issues = nil
	rec.Files = nil
	if b := try(rec); b != nil {
		return b, true
	}
	return nil, true
}

// marshalStored is the stored copy's encoding: JSON without the standard
// encoder's markup escaping. The escaping writes each "<", ">" and "&" as six
// bytes, so a text made of them (which the validator's cleaner keeps) would grow
// six times in the stored copy and break the bound maxSideModel is sized from
// (three times the file). Reading it back needs no change: both spellings
// decode to the same text.
func marshalStored(r ModelRecord) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// ReadModel reads a run's stored model (the side file). ok is false when there
// is none or it cannot be read.
func ReadModel(side *SideData, runID string) (ModelRecord, bool) {
	data, ok := side.Get(runID, SideModel)
	if !ok {
		return ModelRecord{}, false
	}
	var rec ModelRecord
	if err := json.Unmarshal(data, &rec); err != nil || rec.RunID != runID {
		return ModelRecord{}, false
	}
	return rec, true
}
