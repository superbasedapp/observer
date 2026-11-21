package secassesssvc

import (
	"context"
	"errors"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// Counts is what the SARIF import reported, as plain numbers.
type Counts struct {
	Findings    int
	New         int
	WithLineage int
	Refused     map[string]int
	Truncated   bool
}

// ImportFunc is the existing SARIF import seam, adapted by its caller:
// record data (one SARIF document) on the project at root and report counts.
// An error wrapping ErrInputRefused is the import refusing the file itself.
type ImportFunc func(ctx context.Context, root string, data []byte) (Counts, error)

// ErrInputRefused marks an import the file itself was refused by (not SARIF,
// an unsupported version, a malformed result); any other error is the node's.
var ErrInputRefused = errors.New("secassesssvc: the import refused the file")

// ErrNoFindingsFile is returned by RunImport when the run has no findings
// file to import.
var ErrNoFindingsFile = errors.New("secassesssvc: the run has no findings file")

// ErrNotValidated is returned by RunImport for a run launched under a model
// contract that has no current, accepted validation: the import takes the
// findings Observer derives from the checked model, so there is nothing to
// import until the model has been checked.
var ErrNotValidated = errors.New("secassesssvc: the run's model has not been validated, or has changed since")

// The closed reasons an ImportRecord carries.
const (
	ReasonNotSARIF        = "not_sarif"
	ReasonTooLarge        = "too_large"
	ReasonTooDeep         = "too_deep"
	ReasonNoUsableResult  = "no_usable_result"
	ReasonUnreadable      = "unreadable"
	ReasonImportRefused   = "import_refused"
	ReasonNodeError       = "node_error"
	ReasonNotSelected     = "component_not_selected"
	ReasonSeamUnavailable = "import_not_in_build"
	// ReasonModelUnavailable: the checked copy of the model is gone (the stored
	// data was deleted or could not be written); validating the run again
	// rebuilds it.
	ReasonModelUnavailable = "model_unavailable"
	// ReasonModelTooLarge: the checked copy did not fit the stored file's cap and
	// was left out (only a model near the size setting's largest value can reach
	// this). Validating again cannot change that, so the run does not offer it.
	ReasonModelTooLarge = "model_too_large_to_keep"
)

// ImportInput is one import.
type ImportInput struct {
	ProjectRoot string
	Run         Run
	// Selected: the SARIF import component (and its parent) is selected on
	// this node. A node without it answers unavailable and reads no file.
	Selected bool
	// Seam is the SARIF import; nil is a build without it.
	Seam ImportFunc
	Now  time.Time
	// Side is where the checked model is kept (a run under a model contract).
	Side *SideData
	// Derive are the settings the derivation of a model's findings runs under.
	Derive DeriveSettings
}

// DeriveSettings are the import settings in force: plain values the caller
// reads from configuration.
type DeriveSettings struct {
	// MinBand is the lowest band imported ("" is low).
	MinBand secassess.Band
	// Cap is the most findings imported, highest risk first; 0 is no cap.
	Cap int
	// Dedup gives imported findings a rule id and fingerprint without a run id.
	Dedup bool
}

// RunImport reads the run's findings file, prepares it, hands it to the SARIF
// import and returns the record of the attempt. It never returns an error for
// an outcome that is a record (failed, unavailable); it returns an error only
// when there is nothing to record (no findings file, no project root). The
// caller stores the record with Store.SetImport.
func RunImport(ctx context.Context, in ImportInput) (ImportRecord, error) {
	rec := ImportRecord{At: in.Now.UTC()}
	paths := secassess.ResultPaths(in.Run.ID)
	model := secassess.Contract(in.Run.Contract).Schema() != ""
	if in.ProjectRoot == "" || paths.Dir == "" {
		if model {
			return rec, ErrNotValidated
		}
		return rec, ErrNoFindingsFile
	}
	if in.Seam == nil {
		rec.Outcome, rec.Reason = string(secassess.ImportUnavailable), ReasonSeamUnavailable
		return rec, nil
	}
	if !in.Selected {
		rec.Outcome, rec.Reason = string(secassess.ImportUnavailable), ReasonNotSelected
		return rec, nil
	}
	if model {
		return runModelImport(ctx, in, rec)
	}
	data, err := ReadResult(in.ProjectRoot, paths.SARIF, secassess.MaxSARIFBytes)
	switch {
	case errors.Is(err, ErrAbsent):
		return rec, ErrNoFindingsFile
	case errors.Is(err, ErrTooLarge):
		rec.Outcome, rec.Reason = string(secassess.ImportFailed), ReasonTooLarge
		return rec, nil
	case err != nil:
		rec.Outcome, rec.Reason = string(secassess.ImportFailed), ReasonUnreadable
		return rec, nil
	}
	prep, err := secassess.PrepareSARIF(data, secassess.ID(in.Run.Kind), in.Run.ID)
	rec.Prepared, rec.PrepRefused, rec.Dropped, rec.Truncated = prep.Kept, prep.Refused, prep.Dropped, prep.Truncated
	if err != nil {
		rec.Outcome = string(secassess.ImportFailed)
		switch {
		case errors.Is(err, secassess.ErrSARIFTooLarge):
			rec.Reason = ReasonTooLarge
		case errors.Is(err, secassess.ErrSARIFTooDeep):
			rec.Reason = ReasonTooDeep
		case errors.Is(err, secassess.ErrNoPreparable):
			rec.Reason = ReasonNoUsableResult
		default:
			rec.Reason = ReasonNotSARIF
		}
		return rec, nil
	}
	counts, err := in.Seam(ctx, in.ProjectRoot, prep.Data)
	if err != nil {
		rec.Outcome = string(secassess.ImportFailed)
		if errors.Is(err, ErrInputRefused) {
			rec.Reason = ReasonImportRefused
		} else {
			rec.Reason = ReasonNodeError
		}
		return rec, nil
	}
	rec.Outcome = string(secassess.ImportDone)
	rec.Findings, rec.New, rec.WithLineage = counts.Findings, counts.New, counts.WithLineage
	rec.Refused = counts.Refused
	rec.Truncated = rec.Truncated || counts.Truncated
	return rec, nil
}

// DerivedRecord is what the derivation of a model's findings did, as plain
// numbers, with the settings it ran under. Nothing is left out silently: every
// candidate not imported is in one of the counts.
type DerivedRecord struct {
	// Considered are the candidates (a threat model's missing mitigations, a
	// penetration test's findings); Kept how many became importable results.
	Considered int `json:"considered"`
	Kept       int `json:"kept"`
	// NoLocation had no reference that names a place that exists and whose file
	// name an imported finding may carry (secassess.FixPathOK); UnderMinBand
	// were under the developer's minimum band; Duplicate repeated another's
	// fingerprint; OverCap were past the developer's own cap; OverCeiling were
	// past the import's own 1000-result ceiling.
	NoLocation   int `json:"no_location,omitempty"`
	UnderMinBand int `json:"under_min_band,omitempty"`
	Duplicate    int `json:"duplicate,omitempty"`
	OverCap      int `json:"over_cap,omitempty"`
	OverCeiling  int `json:"over_ceiling,omitempty"`
	// MinBand, Cap and Dedup are the settings in force for this import.
	MinBand string `json:"min_band,omitempty"`
	Cap     int    `json:"cap,omitempty"`
	Dedup   bool   `json:"dedup,omitempty"`
}

// derivedRecord turns a derivation and the settings it ran under into the
// record's numbers.
func derivedRecord(d secassess.Derivation, o secassess.DeriveOptions) *DerivedRecord {
	return &DerivedRecord{
		Considered: d.Considered, Kept: d.Kept, NoLocation: d.Excluded.NoLocation, UnderMinBand: d.Excluded.UnderMinBand,
		Duplicate: d.Excluded.Duplicate, OverCap: d.Excluded.OverCap, OverCeiling: d.Excluded.OverCeiling,
		MinBand: string(o.MinBand), Cap: o.Cap, Dedup: o.Dedup,
	}
}

// modelCurrent reports whether the run's model has a current, accepted
// validation: the file is there, it is the file that was validated, and the
// validation read it (valid or partial; a refused file has no model).
func modelCurrent(in ImportInput) bool {
	rec := in.Run.Validation
	if rec == nil {
		return false
	}
	v := Describe(in.ProjectRoot, in.Run)
	st := secassess.ValidationState(rec.State)
	return v.Files.Model && !v.ModelStale && (st == secassess.ValidationValid || st == secassess.ValidationPartial)
}

// runModelImport imports the findings Observer derives from a run's checked
// model. The agent's own findings.sarif plays no part: the derivation is built
// from the checked copy of the model, from Observer's tables and the ids that
// passed the id grammar, never from the agent's prose.
func runModelImport(ctx context.Context, in ImportInput, rec ImportRecord) (ImportRecord, error) {
	if !modelCurrent(in) {
		return rec, ErrNotValidated
	}
	stored, ok := ReadModel(in.Side, in.Run.ID)
	switch {
	case ok && stored.Truncated:
		rec.Outcome, rec.Reason = string(secassess.ImportFailed), ReasonModelTooLarge
		return rec, nil
	case !ok || (stored.Result.TM == nil && stored.Result.PT == nil):
		rec.Outcome, rec.Reason = string(secassess.ImportFailed), ReasonModelUnavailable
		return rec, nil
	}
	k, _ := secassess.KindByID(in.Run.Kind)
	opts := secassess.DeriveOptions{Tag: k.Tag, RunID: in.Run.ID, MinBand: in.Derive.MinBand, Cap: in.Derive.Cap, Dedup: in.Derive.Dedup}
	d := secassess.DeriveSARIF(stored.Result, opts)
	rec.Derived, rec.Prepared = derivedRecord(d, opts), d.Kept
	if d.Kept == 0 {
		// Nothing to hand the import. This says nothing about the project.
		rec.Outcome = string(secassess.ImportNoFindings)
		return rec, nil
	}
	counts, err := in.Seam(ctx, in.ProjectRoot, d.Doc)
	if err != nil {
		rec.Outcome = string(secassess.ImportFailed)
		if errors.Is(err, ErrInputRefused) {
			rec.Reason = ReasonImportRefused
		} else {
			rec.Reason = ReasonNodeError
		}
		return rec, nil
	}
	rec.Outcome = string(secassess.ImportDone)
	rec.Findings, rec.New, rec.WithLineage = counts.Findings, counts.New, counts.WithLineage
	rec.Refused = counts.Refused
	rec.Truncated = counts.Truncated
	return rec, nil
}
