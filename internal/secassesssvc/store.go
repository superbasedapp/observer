package secassesssvc

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// Filename is the run record's name beside the node database.
const Filename = "secassess-runs.json"

// Schema is the file's schema version.
const Schema = 1

// Bounds.
const (
	// MaxRuns is how many runs the file keeps (oldest dropped).
	MaxRuns  = 100
	maxBytes = 1 << 20
	maxField = 256
)

// ErrDuplicateRun is returned by Record for a run id already recorded.
var ErrDuplicateRun = errors.New("secassesssvc: that run id is already recorded")

// ErrUnreadable is returned by every write when the run record exists but
// cannot be read (over the size cap, not JSON, another schema, an I/O error).
// A write from an empty view of such a file would erase every recorded run, so
// the write is refused and the file is left as it is.
var ErrUnreadable = errors.New("secassesssvc: the run record cannot be read")

// ErrFull is returned by a write that would take the file over its size cap
// when no ended run is left to drop: every remaining run is held, started or
// still has a relaxation to end.
var ErrFull = errors.New("secassesssvc: the run record is full of runs that are still in use")

// ImportRecord is the outcome of the last import attempt of a run.
type ImportRecord struct {
	At time.Time `json:"at"`
	// Outcome is "imported", "failed" or "unavailable" (secassess.ImportOutcome).
	Outcome string `json:"outcome"`
	// Reason is a closed code for a failure or an unavailable import.
	Reason string `json:"reason,omitempty"`
	// Prepared is how many results the preparation kept; PrepRefused how many
	// it refused, by reason; Dropped how many it could not read at all.
	Prepared    int            `json:"prepared"`
	PrepRefused map[string]int `json:"prep_refused,omitempty"`
	Dropped     int            `json:"dropped,omitempty"`
	// What the SARIF import reported.
	Findings    int            `json:"findings"`
	New         int            `json:"new"`
	WithLineage int            `json:"with_lineage"`
	Refused     map[string]int `json:"refused,omitempty"`
	Truncated   bool           `json:"truncated,omitempty"`
	// Derived is set for the import of a checked model: how many findings
	// Observer derived from it and how many it left out, by reason.
	Derived *DerivedRecord `json:"derived,omitempty"`
}

// Run is one assessment launch.
type Run struct {
	ID              string    `json:"id"`
	CreatedAt       time.Time `json:"created_at"`
	Kind            string    `json:"kind"`
	Tool            string    `json:"tool"`
	ProjectRootHash string    `json:"project_root_hash"`
	ProjectName     string    `json:"project_name,omitempty"`
	// Handle is the dashboard terminal's handle.
	Handle string `json:"handle,omitempty"`
	// Seeded says the prompt was passed on the agent's argv.
	Seeded bool `json:"seeded"`
	// Target is the confirmed loopback target (a kind with one).
	Target string `json:"target,omitempty"`
	// Backend and Tier are the sandbox in force at launch ("" unsandboxed).
	Backend string `json:"backend,omitempty"`
	Tier    string `json:"tier,omitempty"`
	// Sandboxed is whether the launch asked for a sandbox.
	Sandboxed bool `json:"sandboxed"`
	// ConfirmedAt is when the developer confirmed the launch.
	ConfirmedAt time.Time     `json:"confirmed_at"`
	Import      *ImportRecord `json:"import,omitempty"`

	// The fields below belong to the relaxations addendum (plan section 13) and
	// are all additive: a run recorded before it reads as started, with none.

	// Phase is held, claimed, started or cancelled; "" reads as started.
	Phase string `json:"phase,omitempty"`
	// Held is the org request a held run waits on.
	Held *Held `json:"held,omitempty"`
	// Relax are the relaxations asked for this run.
	Relax []Relax `json:"relax,omitempty"`
	// RelaxMinutes is the hard cap of a local approval for this run.
	RelaxMinutes int `json:"relax_minutes,omitempty"`
	// Reported says the run writes lifecycle audit rows (secassess.ReportRoute
	// at launch); Tenancy is the tenancy read at launch.
	Reported bool   `json:"reported,omitempty"`
	Tenancy  string `json:"tenancy,omitempty"`
	// EndedAt is when the terminal was seen gone (the `end` row was written).
	EndedAt time.Time `json:"ended_at,omitzero"`
	// Relaxed counts the verdicts the run's relaxations changed, taken at the
	// end: Exact for a local approval, Approx for an org grant.
	Relaxed *RelaxedCount `json:"relaxed,omitempty"`

	// The fields below belong to the depth work (plan sections 3.6 and W0): all
	// scalars and additive, so a run recorded before them reads as having none.

	// TimeBoxMinutes is the time box in force at launch and TimeBoxAction what
	// happens at the deadline ("stop_button" or "auto_close"; "" reads as
	// stop_button). They are recorded so a later settings change never moves a
	// run's deadline.
	TimeBoxMinutes int    `json:"time_box_minutes,omitempty"`
	TimeBoxAction  string `json:"time_box_action,omitempty"`
	// EndWhy says how the end came about: "terminal_gone" (the terminal was
	// seen gone), "time_box" (Observer closed it at the deadline) or "stopped"
	// (the developer pressed Stop).
	EndWhy string `json:"end_why,omitempty"`
	// Audit is the boundary audit verdict (secassess.AuditVerdict): set at launch
	// when the audit is off or the kind is not audited, otherwise at the end.
	// AuditAt is when the closing snapshot was taken.
	Audit   string    `json:"audit,omitempty"`
	AuditAt time.Time `json:"audit_at,omitzero"`
	// Contract is the result contract the run was launched under
	// (secassess.Contract: threatmodel.v1, pentest.v1). Empty is the SARIF
	// contract, which is every run recorded before the model contracts.
	Contract string `json:"contract,omitempty"`
	// Validation is the outcome of the last validation of the run's
	// assessment.json (the stored model is side data).
	Validation *ValidationRecord `json:"validation,omitempty"`
	// PromptVersion is the prompt version the run was launched with (tm.7,
	// pt.7); Sets are the preset ids of the frameworks, method extras and test
	// categories the prompt asked for, so the check holds the model to what the
	// agent was asked, whatever the settings say later.
	PromptVersion string   `json:"prompt_version,omitempty"`
	Sets          *RunSets `json:"sets,omitempty"`

	// The fields below belong to threat-model and penetration-test depth (plan
	// W3 and W4): the choices the developer made in the plan, recorded so the
	// check and the run row read as the run was started. Short scalars and one
	// short list only; nothing the agent wrote.

	// ScopePaths and ScopeNote are the scope of a threat model (at most
	// secassess.MaxScopeChoices paths and a note of at most
	// secassess.MaxScopeNote characters, both cleaned).
	ScopePaths []string `json:"scope_paths,omitempty"`
	ScopeNote  string   `json:"scope_note,omitempty"`
	// PreviousRun is the earlier checked threat model of the project this run
	// is compared with once its own model is checked.
	PreviousRun string `json:"previous_run,omitempty"`
	// Start is the start choice of a penetration test as the plan sent it back
	// (secassess.StartSelection.Choice: the command, with its folder when the
	// project's file names one; "" none), at most secassess.MaxStartChoice bytes.
	Start string `json:"start,omitempty"`
	// Prepare says the developer ticked the project's preparation steps (a
	// migrate, a seed) to run first; they are never part of the task otherwise.
	Prepare bool `json:"prepare,omitempty"`
	// SecretMode is the environment-files mode that was IN FORCE for the run
	// ("mask" reads "warn" when the run's sandbox could not hide files), not the
	// one the setting says, so a later reader does not take a configured value
	// for what happened. SecretModeWhy is the closed word for why a configured
	// mask acted as warn (secassess.MaskDowngradeWhy; "" when it did not).
	SecretMode    string `json:"secret_mode,omitempty"`
	SecretModeWhy string `json:"secret_mode_why,omitempty"`
	// SecretMask is what the workspace secret mask covered once the run's box
	// had started: counts and closed words, never a path (secassess.MaskReport).
	// nil when the launch did not ask the sandbox to hide files.
	SecretMask *secassess.MaskReport `json:"secret_mask,omitempty"`
	// Grounding is the mode of the digest the task carried.
	Grounding string `json:"grounding,omitempty"`

	// The fields below belong to the request helper (plan W5b), for a kind that
	// probes: Helper is the mode at launch (secassess.HelperOn, HelperOff or
	// HelperWithheld; "" is a run recorded before the helper and reads as off),
	// HelperSHA and ConfigSHA the SHA-256 (hex) of probe.py and probe.json as
	// Observer wrote them, which a validation compares with the files in the
	// run folder.
	Helper    string `json:"helper,omitempty"`
	HelperSHA string `json:"helper_sha,omitempty"`
	ConfigSHA string `json:"config_sha,omitempty"`

	// The fields below belong to the red team exercise and the retest (plan W7.3
	// and W7.2): the developer's choices recorded as the plan sent them back, as
	// short scalars and one short list. Objective is the developer's own objective
	// for an exercise (secassess.CleanObjective has run on it, at most
	// secassess.MaxObjective characters; "" none). RetestOf is the earlier run a
	// retest replays and RetestFindings the ids of its findings (at most
	// secassess.MaxRetestFindings), in the order the developer chose them. They
	// never carry anything the agent wrote.
	Objective      string   `json:"objective,omitempty"`
	RetestOf       string   `json:"retest_of,omitempty"`
	RetestFindings []string `json:"retest_findings,omitempty"`
}

// RunSets are the preset ids (the settings' own words) a model run was asked
// for at launch.
type RunSets struct {
	Frameworks   string `json:"frameworks,omitempty"`
	MethodExtras string `json:"method_extras,omitempty"`
	Categories   string `json:"categories,omitempty"`
	// AIApp says the project looked like an AI application when the task was
	// built, so the check holds the model to the AI frameworks it was asked for.
	AIApp bool `json:"ai_app,omitempty"`
}

// The most a run records of the plan's choices.
const (
	maxRunScopePaths = secassess.MaxScopeChoices
	maxRunScopePath  = 120
)

// ErrStartTooLong is returned by Record for a run whose start choice is over
// secassess.MaxStartChoice. The plan never makes one (the validator bounds the
// command and the folder by the same constants); a record keeps a command whole
// or not at all, because a cut command is one nobody wrote and a held run would
// replay it.
var ErrStartTooLong = errors.New("secassesssvc: the start command is longer than a start choice can be")

// The run phases.
const (
	PhaseHeld      = "held"
	PhaseClaimed   = "claimed"
	PhaseStarted   = "started"
	PhaseCancelled = "cancelled"
)

// IsStarted reports whether the run has (or had) a terminal: an old record has
// no phase and reads as started.
func (r Run) IsStarted() bool { return r.Phase == "" || r.Phase == PhaseStarted }

// Held is the org request a held run waits on (plan section 13.6).
type Held struct {
	At time.Time `json:"at"`
	// Rules are the org-approved rule ids this run waits on. RequestIDs and
	// QueuedIDs are parallel to Rules (0 where none): the org request id of a
	// request that was filed, and the outbox id of one that could not be sent
	// yet. A rule an existing grant already covered has neither.
	Rules      []string `json:"rules,omitempty"`
	RequestIDs []int64  `json:"request_ids,omitempty"`
	QueuedIDs  []int64  `json:"queued_ids,omitempty"`
	// Covered are the rules an existing grant already covered at the request.
	Covered []string `json:"covered,omitempty"`
}

// RelaxedCount is the count of verdicts a run's relaxations changed.
type RelaxedCount struct {
	Exact  int `json:"exact"`
	Approx int `json:"approx"`
}

// Relax is one relaxation on a run.
type Relax struct {
	// Key is the guard rule id, or "tier".
	Key  string `json:"key"`
	Type string `json:"type"`
	// Route is self or org_request (secassess.Route).
	Route string `json:"route"`
	// State is the lifecycle state (secassess.RelaxState).
	State string `json:"state"`
	Scope string `json:"scope,omitempty"`
	// ApprovalID, GrantedBy and ExpiresAt describe the approval row the run
	// created (ExpiresAt is the last expiry it wrote); SessionID is the session
	// it was bound to.
	ApprovalID int64     `json:"approval_id,omitempty"`
	GrantedBy  string    `json:"granted_by,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitzero"`
	SessionID  string    `json:"session_id,omitempty"`
	// GrantID is the org grant that covered an org_request rule at launch.
	GrantID   int64  `json:"grant_id,omitempty"`
	EndReason string `json:"end_reason,omitempty"`
	// Note is a closed code that says why a relaxation did not take effect or
	// stopped early (existing_row, create_failed, row_changed).
	Note string `json:"note,omitempty"`
	// Hosts is the host list of the tier row at launch.
	Hosts []string `json:"hosts,omitempty"`
}

type file struct {
	Schema int   `json:"schema"`
	Runs   []Run `json:"runs"`
}

// Path returns the run record beside dbPath ("" when dbPath is empty).
func Path(dbPath string) string {
	if dbPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(dbPath), Filename)
}

// Store serializes this process's reads and writes of one run record.
type Store struct {
	path string
	mu   sync.Mutex
	side *SideData
}

// New returns a store for path. An empty path keeps nothing: Recent is empty
// and Record only returns the run (tests, demo).
func New(path string) *Store {
	return &Store{path: path, side: NewSideData(SideDataPath(path))}
}

var (
	sharedMu sync.Mutex
	shared   = map[string]*Store{}
)

// Shared returns the one process-wide store for path, so a path has one owner
// and one mutex however many callers ask. The dashboard's Server struct holds
// no field of this module (a field would link the module into a build that
// compiles it out). An empty path returns a fresh keep-nothing store.
func Shared(path string) *Store {
	if path == "" {
		return New("")
	}
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if s, ok := shared[path]; ok {
		return s
	}
	s := New(path)
	shared[path] = s
	return s
}

// NewRunID mints a run id (16 lower-case hex characters).
func NewRunID() string {
	var b [secassess.RunIDLen / 2]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Record appends r, stamping CreatedAt from now when zero and capping its
// fields; the file keeps the newest MaxRuns. A run needs a valid id (mint one
// with NewRunID) that is not already recorded.
func (s *Store) Record(r Run, now time.Time) (Run, error) {
	out, err := s.record(r, now)
	if err == nil {
		// Side data of runs that fell out of the record goes with them.
		s.PruneSide(0, now)
	}
	return out, err
}

func (s *Store) record(r Run, now time.Time) (Run, error) {
	if !secassess.ValidRunID(r.ID) {
		return r, errors.New("secassesssvc.Record: bad run id")
	}
	if len(r.Start) > secassess.MaxStartChoice {
		return r, ErrStartTooLong
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	r.CreatedAt = r.CreatedAt.UTC()
	r = capRun(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return r, nil
	}
	unlock, err := s.lockRecord()
	if err != nil {
		return r, fmt.Errorf("secassesssvc.Record: %w", err)
	}
	defer unlock()
	f, err := s.read()
	if err != nil {
		return r, fmt.Errorf("secassesssvc.Record: %w", err)
	}
	for _, have := range f.Runs {
		if have.ID == r.ID {
			return r, ErrDuplicateRun
		}
	}
	f.Runs = append(f.Runs, r)
	if f.Runs, err = trimToMax(f.Runs, r.ID); err != nil {
		return r, fmt.Errorf("secassesssvc.Record: %w", err)
	}
	if err := s.write(f, r.ID); err != nil {
		return r, fmt.Errorf("secassesssvc.Record: %w", err)
	}
	return r, nil
}

// trimToMax keeps the newest MaxRuns runs. Only a run that can be forgotten
// (droppable) is ever dropped for the count, oldest first, never keepID: a held
// org request, a running terminal or an open relaxation is not evicted by the
// hundred-and-first launch, and when too few runs can go the record is full.
func trimToMax(runs []Run, keepID string) ([]Run, error) {
	n := len(runs) - MaxRuns
	if n <= 0 {
		return runs, nil
	}
	out := make([]Run, 0, len(runs))
	for _, r := range runs {
		if n > 0 && r.ID != keepID && droppable(r) {
			n--
			continue
		}
		out = append(out, r)
	}
	if n > 0 {
		return runs, ErrFull
	}
	return out, nil
}

// canRecordBytes is the room one more run is assumed to need when CanRecord
// asks whether a launch could be recorded (a run's scalars are capped well
// below it).
const canRecordBytes = 8 << 10

// CanRecord reports whether a new run could be recorded now: nil when it
// could, an error wrapping ErrUnreadable when the record cannot be read, or
// ErrFull when it holds only runs that are still in use and is out of room.
// A launch asks before it claims or starts anything, so an assessment never
// runs without a record of it.
func (s *Store) CanRecord() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return nil
	}
	f, err := s.read()
	if err != nil {
		return err
	}
	probe := f
	probe.Runs = append(append([]Run(nil), f.Runs...), Run{ID: "0000000000000000"})
	if _, err := trimToMax(probe.Runs, "0000000000000000"); err != nil {
		return err
	}
	data, err := json.Marshal(f)
	if err != nil || len(data)+canRecordBytes <= maxBytes {
		return nil
	}
	for _, r := range f.Runs {
		if droppable(r) {
			return nil
		}
	}
	return ErrFull
}

// Exists reports whether a run id is recorded.
func (s *Store) Exists(id string) bool {
	_, ok := s.Get(id)
	return ok
}

// Get returns the run with id.
func (s *Store) Get(id string) (Run, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.load().Runs {
		if r.ID == id {
			return r, true
		}
	}
	return Run{}, false
}

// Recent returns at most n runs, newest first. A missing, oversized or
// unreadable file holds none.
func (s *Store) Recent(n int) []Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.load().Runs
	out := make([]Run, 0, min(n, len(all)))
	for i := len(all) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, all[i])
	}
	return out
}

// SetImport stores the outcome of an import attempt on a run.
func (s *Store) SetImport(id string, rec ImportRecord) error {
	rec.PrepRefused, rec.Refused = capMap(rec.PrepRefused), capMap(rec.Refused)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return nil
	}
	unlock, err := s.lockRecord()
	if err != nil {
		return fmt.Errorf("secassesssvc.SetImport: %w", err)
	}
	defer unlock()
	f, err := s.read()
	if err != nil {
		return fmt.Errorf("secassesssvc.SetImport: %w", err)
	}
	for i := range f.Runs {
		if f.Runs[i].ID == id {
			rec.Reason = clip(rec.Reason, maxField)
			f.Runs[i].Import = &rec
			if err := s.write(f, id); err != nil {
				return fmt.Errorf("secassesssvc.SetImport: %w", err)
			}
			return nil
		}
	}
	return errors.New("secassesssvc.SetImport: no such run")
}

func capMap(m map[string]int) map[string]int {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]int, min(len(m), 32))
	for k, v := range m {
		if len(out) == 32 {
			break
		}
		out[clip(k, 64)] = v
	}
	return out
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func capRun(r Run) Run {
	r.Relax, r.Held = capRelax(r.Relax), capHeld(r.Held)
	for _, p := range []*string{&r.ID, &r.Kind, &r.Tool, &r.ProjectRootHash, &r.ProjectName, &r.Handle, &r.Target, &r.Backend, &r.Tier, &r.Phase, &r.Tenancy, &r.TimeBoxAction, &r.EndWhy, &r.Audit, &r.Contract} {
		*p = clip(*p, maxField)
	}
	if r.Validation != nil {
		v := *r.Validation
		v.State, v.Fatal = clip(v.State, maxField), clip(v.Fatal, maxField)
		r.Validation = &v
	}
	r.ScopePaths = capScopePaths(r.ScopePaths)
	r.ScopeNote = clip(r.ScopeNote, secassess.MaxScopeNote*4) // the note is characters, the clip bytes
	r.PreviousRun, r.Grounding = clip(r.PreviousRun, maxField), clip(r.Grounding, maxField)
	r.SecretMode, r.SecretModeWhy = clip(r.SecretMode, maxField), clip(r.SecretModeWhy, maxField)
	if r.SecretMask != nil {
		m := secassess.CleanMaskReport(*r.SecretMask)
		r.SecretMask = &m
	}
	r.Helper, r.HelperSHA, r.ConfigSHA = clip(r.Helper, maxField), clip(r.HelperSHA, maxField), clip(r.ConfigSHA, maxField)
	r.Objective = clip(r.Objective, secassess.MaxObjective*4) // characters in the bound, bytes in the clip
	r.RetestOf, r.RetestFindings = clip(r.RetestOf, maxField), capRetestFindings(r.RetestFindings)
	// Start is never cut here: Record refuses a start choice over its bound
	// (ErrStartTooLong), and a stored run was recorded under that check.
	return r
}

// capScopePaths keeps at most maxRunScopePaths paths of at most maxRunScopePath
// bytes each; the plan validated them already, so this only bounds the record.
func capScopePaths(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, p := range in {
		if len(out) == maxRunScopePaths {
			break
		}
		out = append(out, clip(p, maxRunScopePath))
	}
	return out
}

// SetValidation records the outcome of a validation on the run.
func (s *Store) SetValidation(id string, rec ValidationRecord) error {
	rec.State, rec.Fatal = clip(rec.State, maxField), clip(rec.Fatal, maxField)
	_, found, err := s.Mutate(id, func(r *Run) error {
		r.Validation = &rec
		return nil
	})
	switch {
	case err != nil:
		return fmt.Errorf("secassesssvc.SetValidation: %w", err)
	case !found:
		return errors.New("secassesssvc.SetValidation: no such run")
	}
	return nil
}

// load is read for the readers: a record that cannot be read holds no runs
// (the readers show nothing; only a write must not trust that empty view).
func (s *Store) load() file {
	f, _ := s.read()
	return f
}

// read returns the run record. A missing file (or a keep-nothing store) is an
// empty record with no error. Any other failure to read it, whatever the cause,
// is an error: the caller must not write from the empty view that comes back
// with it, or the next write erases every run the file still holds.
func (s *Store) read() (file, error) {
	out := file{Schema: Schema}
	if s.path == "" {
		return out, nil
	}
	fh, err := os.Open(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	defer func() { _ = fh.Close() }()
	data, err := io.ReadAll(io.LimitReader(fh, maxBytes+1))
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	if len(data) > maxBytes {
		return out, fmt.Errorf("%w: over %d bytes", ErrUnreadable, maxBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return out, nil // an empty file holds nothing a write could erase
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return out, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	if f.Schema != Schema {
		return out, fmt.Errorf("%w: schema %d", ErrUnreadable, f.Schema)
	}
	return f, nil
}

// droppable says the run can be forgotten to make room: it is not held or
// claimed (an org request is waiting on it), has no relaxation still open, and
// nothing is owed for it (a started run's end has been recorded, or it has
// neither an open relaxation nor an audit row to write, which is what the
// reconcile pass looks at). Only such runs are ever dropped for size.
func droppable(r Run) bool {
	switch r.Phase {
	case PhaseHeld, PhaseClaimed:
		return false
	case PhaseCancelled:
		return !openRelax(r)
	}
	return !openRelax(r) && !needsPass(r)
}

// write stores f, keeping the file under maxBytes by construction: when it
// would be over, the oldest droppable runs go first (never the run named by
// keepID, which is the one this write is about), and when none is left the
// write is refused with ErrFull and the file is left as it was.
func (s *Store) write(f file, keepID string) error {
	f.Schema = Schema
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	for len(data) > maxBytes {
		drop := -1
		for i, r := range f.Runs {
			if r.ID != keepID && droppable(r) {
				drop = i
				break
			}
		}
		if drop < 0 {
			return ErrFull
		}
		f.Runs = append(append([]Run(nil), f.Runs[:drop]...), f.Runs[drop+1:]...)
		if data, err = json.Marshal(f); err != nil {
			return err
		}
	}
	return fsatomic.WriteFile(s.path, data, fsatomic.Options{TempPattern: ".secassess-*.tmp"})
}

// All returns every recorded run, oldest first. An unreadable record holds
// none; a caller that must tell that from an empty record uses AllErr.
func (s *Store) All() []Run {
	runs, _ := s.AllErr()
	return runs
}

// AllErr is All with the reason the record could not be read.
func (s *Store) AllErr() ([]Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.read()
	return append([]Run(nil), f.Runs...), err
}

// Mutate applies fn to the run with id under the store's lock and writes the
// result. fn may change any field; if it returns an error nothing is written
// and the error is returned. found is false when no run has that id. It is the
// one way a recorded run changes after Record, so every change is atomic
// against every other.
func (s *Store) Mutate(id string, fn func(r *Run) error) (Run, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockRecord()
	if err != nil {
		return Run{}, false, fmt.Errorf("secassesssvc.Mutate: %w", err)
	}
	defer unlock()
	f, err := s.read()
	if err != nil {
		return Run{}, false, fmt.Errorf("secassesssvc.Mutate: %w", err)
	}
	for i := range f.Runs {
		if f.Runs[i].ID != id {
			continue
		}
		r := f.Runs[i]
		if err := fn(&r); err != nil {
			return f.Runs[i], true, err
		}
		r = capRun(r)
		f.Runs[i] = r
		if s.path == "" {
			return r, true, nil
		}
		if err := s.write(f, id); err != nil {
			return r, true, fmt.Errorf("secassesssvc.Mutate: %w", err)
		}
		return r, true, nil
	}
	return Run{}, false, nil
}

// ErrNotHeld is returned by ClaimHeld for a run that is not held.
var ErrNotHeld = errors.New("secassesssvc: the run is not held")

// ClaimHeld moves a held run to claimed in one conditional update, so two
// clicks of Start start one terminal. It returns ErrNotHeld when the run is
// anything else (already claimed, started, cancelled).
func (s *Store) ClaimHeld(id string) (Run, error) {
	r, found, err := s.Mutate(id, func(r *Run) error {
		if r.Phase != PhaseHeld {
			return ErrNotHeld
		}
		r.Phase = PhaseClaimed
		return nil
	})
	switch {
	case err != nil:
		return r, err
	case !found:
		return Run{}, ErrNotHeld
	}
	return r, nil
}

// ReleaseClaim puts a claimed run back to held (the terminal did not start).
func (s *Store) ReleaseClaim(id string) error {
	_, _, err := s.Mutate(id, func(r *Run) error {
		if r.Phase == PhaseClaimed {
			r.Phase = PhaseHeld
		}
		return nil
	})
	return err
}

func capRelax(rs []Relax) []Relax {
	if len(rs) > 8 {
		rs = rs[:8]
	}
	for i := range rs {
		for _, p := range []*string{&rs[i].Key, &rs[i].Type, &rs[i].Route, &rs[i].State, &rs[i].Scope, &rs[i].GrantedBy, &rs[i].SessionID, &rs[i].EndReason, &rs[i].Note} {
			*p = clip(*p, maxField)
		}
		if len(rs[i].Hosts) > 16 {
			rs[i].Hosts = rs[i].Hosts[:16]
		}
		for j := range rs[i].Hosts {
			rs[i].Hosts[j] = clip(rs[i].Hosts[j], 128)
		}
	}
	return rs
}

func capHeld(h *Held) *Held {
	if h == nil {
		return nil
	}
	if len(h.Rules) > 8 {
		h.Rules = h.Rules[:8]
	}
	if len(h.Covered) > 8 {
		h.Covered = h.Covered[:8]
	}
	if len(h.RequestIDs) > 8 {
		h.RequestIDs = h.RequestIDs[:8]
	}
	if len(h.QueuedIDs) > 8 {
		h.QueuedIDs = h.QueuedIDs[:8]
	}
	return h
}

// capRetestFindings keeps at most secassess.MaxRetestFindings ids of at most
// maxField bytes each; the plan validated them already, so this only bounds the
// record.
func capRetestFindings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, id := range in {
		if len(out) == secassess.MaxRetestFindings {
			break
		}
		out = append(out, clip(id, maxField))
	}
	return out
}
