package secassesssvc

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// Side data (plan section 3.6): the bulky things a run produces (the boundary
// snapshots, the checked model, the request log) are not kept in the run
// record, which holds scalars and counts only. They live in per-run files
// beside it, node-local, mode 0600, written atomically through one owner.
//
//	secassess-data/<run id>/tree.json    boundary snapshots, at most 64 KiB
//	secassess-data/<run id>/model.json   the checked model and its report, at most 97 MiB (three times the largest model the setting allows)
//	secassess-data/<run id>/probes.json  the redacted request log copy, at most 1 MiB
//
// The names are an allow-list and each has its own cap. A lost side file loses
// a snapshot or a stored model, never a finding.

// SideDirName is the side data directory's name beside the run record.
const SideDirName = "secassess-data"

// The side file names.
const (
	SideTree   = "tree.json"
	SideModel  = "model.json"
	SideProbes = "probes.json"
)

// maxSideModel is the cap of model.json: room for any model the validator
// accepts, whatever the setting model_max_mib is (up to
// secassess.MaxModelBytesCeiling). The stored copy is the normalised model with
// Observer's computed fields (a reference's state and match line, a threat's
// scores) and the report, which is larger than the file it came from; the test
// TestStoredModelHoldsAnythingTheValidatorAccepts pins that the growth stays
// under three times the file for the densest model the structure allows (the
// stored copy is written without markup escaping, which would otherwise grow a
// text of "<" six times), so three times the ceiling is the bound, plus room for
// the report and the file stamps (TestStoredModelStructuralOverhead). A stored
// model that is still too large is left out and the run says "too large to
// keep"; it never reads as valid and fails later.
const maxSideModel = 3*secassess.MaxModelBytesCeiling + 1<<20

// sideCaps is the allow-list of side file names with their size caps.
var sideCaps = map[string]int{
	SideTree:   64 << 10,
	SideModel:  maxSideModel,
	SideProbes: 1 << 20,
}

// MaxSideTree is the cap of tree.json, for callers that fit a snapshot to it.
const MaxSideTree = 64 << 10

// Side data errors.
var (
	// ErrSideName is returned for a name that is not on the allow-list.
	ErrSideName = errors.New("secassesssvc: not a side data file name")
	// ErrSideTooLarge is returned for content over its file's cap.
	ErrSideTooLarge = errors.New("secassesssvc: the side file is over its size cap")
	// ErrSideRun is returned for a bad run id.
	ErrSideRun = errors.New("secassesssvc: not a run id")
)

// SideData is the one owner of the side data directory. A nil or keep-nothing
// SideData (no path) reads as empty and writes nothing.
type SideData struct {
	dir string
	mu  sync.Mutex
}

// SideDataPath returns the side data directory beside the run record at
// recordPath ("" when recordPath is empty).
func SideDataPath(recordPath string) string {
	if recordPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(recordPath), SideDirName)
}

// NewSideData returns the side data for the directory dir ("" keeps nothing).
func NewSideData(dir string) *SideData { return &SideData{dir: dir} }

// Side returns the side data that belongs to this run record.
func (s *Store) Side() *SideData { return s.side }

func (d *SideData) path(runID, name string) (string, error) {
	if !secassess.ValidRunID(runID) {
		return "", ErrSideRun
	}
	if _, ok := sideCaps[name]; !ok {
		return "", ErrSideName
	}
	return filepath.Join(d.dir, runID, name), nil
}

// Put writes one side file of a run, replacing it. Content over the file's cap
// is refused (callers fit their content to the cap first).
func (d *SideData) Put(runID, name string, data []byte) error {
	if d == nil || d.dir == "" {
		return nil
	}
	p, err := d.path(runID, name)
	if err != nil {
		return err
	}
	if len(data) > sideCaps[name] {
		return ErrSideTooLarge
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := fsatomic.WriteFile(p, data, fsatomic.Options{TempPattern: ".side-*.tmp"}); err != nil {
		return fmt.Errorf("secassesssvc.SideData.Put: %w", err)
	}
	return nil
}

// Get reads one side file of a run, up to its cap. ok is false when it is
// absent or unreadable.
func (d *SideData) Get(runID, name string) (data []byte, ok bool) {
	if d == nil || d.dir == "" {
		return nil, false
	}
	p, err := d.path(runID, name)
	if err != nil {
		return nil, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	fh, err := os.Open(p)
	if err != nil {
		return nil, false
	}
	defer func() { _ = fh.Close() }()
	data, err = io.ReadAll(io.LimitReader(fh, int64(sideCaps[name])+1))
	if err != nil || len(data) > sideCaps[name] {
		return nil, false
	}
	return data, true
}

// Delete removes every side file of one run.
func (d *SideData) Delete(runID string) error {
	if d == nil || d.dir == "" {
		return nil
	}
	if !secassess.ValidRunID(runID) {
		return ErrSideRun
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := os.RemoveAll(filepath.Join(d.dir, runID)); err != nil {
		return fmt.Errorf("secassesssvc.SideData.Delete: %w", err)
	}
	return nil
}

// Prune removes the directory of every run that keep reports false for, and
// anything in the side directory that is not a run's directory. It returns how
// many directories it removed. keep is asked once per directory whose name is
// a run id.
func (d *SideData) Prune(keep func(runID string) bool) int {
	return d.PruneOlder(keep, time.Time{})
}

// PruneGrace is how long a side directory is left alone after it was last
// written whatever the run record says: a run that is launching has stored its
// "before" snapshot but is not recorded yet, and a prune pass in that window
// must not take it.
const PruneGrace = 15 * time.Minute

// PruneOlder is Prune that leaves an entry alone when it was modified after
// notBefore (a zero notBefore leaves nothing alone).
func (d *SideData) PruneOlder(keep func(runID string) bool, notBefore time.Time) int {
	if d == nil || d.dir == "" {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() && secassess.ValidRunID(name) && keep(name) {
			continue
		}
		if !notBefore.IsZero() {
			if info, err := e.Info(); err != nil || info.ModTime().After(notBefore) {
				continue
			}
		}
		if os.RemoveAll(filepath.Join(d.dir, name)) == nil {
			removed++
		}
	}
	return removed
}

// Has reports whether a run has any side file.
func (d *SideData) Has(runID string) bool {
	if d == nil || d.dir == "" || !secassess.ValidRunID(runID) {
		return false
	}
	_, err := os.Stat(filepath.Join(d.dir, runID))
	return err == nil
}

// HasFile reports whether a run has the side file name (the checked model, for
// one).
func (d *SideData) HasFile(runID, name string) bool {
	if d == nil || d.dir == "" {
		return false
	}
	p, err := d.path(runID, name)
	if err != nil {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// PruneSide removes the side data of runs that are no longer recorded and, when
// retentionDays is positive, of recorded runs older than that many days (by
// the time the run ended, or was created if it never ended). It runs after a
// record and in the reconcile pass. It returns how many run directories it
// removed. It does nothing while the run record cannot be read: an empty view
// of an unreadable record would otherwise read as "no run is recorded" and take
// every stored model and snapshot. A directory written within PruneGrace is
// left alone, so a launch in progress keeps its "before" snapshot.
func (s *Store) PruneSide(retentionDays int, now time.Time) int {
	if s == nil || s.side == nil {
		return 0
	}
	runs, err := s.AllErr()
	if err != nil {
		return 0
	}
	known := make(map[string]time.Time, len(runs))
	for _, r := range runs {
		at := r.EndedAt
		if at.IsZero() {
			at = r.CreatedAt
		}
		known[r.ID] = at
	}
	return s.side.PruneOlder(func(id string) bool {
		at, ok := known[id]
		if !ok {
			return false
		}
		return retentionDays <= 0 || now.Sub(at) <= time.Duration(retentionDays)*24*time.Hour
	}, now.Add(-PruneGrace))
}

// Unreadable returns the error that makes the run record unreadable (it wraps
// ErrUnreadable), nil when the record reads or does not exist yet. The runs
// list says "the run history could not be read" instead of showing an empty
// list.
func (s *Store) Unreadable() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.read()
	return err
}

// ---- the run directory (plan W0.6) ----

// runDirGitignore is what the run directory's .gitignore holds: everything,
// itself included, so a run's files are never committed by accident.
const runDirGitignore = "*\n"

// PrepareRunDir creates the run directory under the project root and writes a
// .gitignore holding "*" into it, before the agent starts. Every path goes
// through os.Root, so a symlink in the project cannot move the writes outside
// it. It returns a function that removes what it created (call it when the
// terminal does not start). An existing directory is reused and left alone by
// the cleanup.
func PrepareRunDir(projectRoot, runID string) (cleanup func(), err error) {
	noop := func() {}
	p := secassess.ResultPaths(runID)
	if p.Dir == "" {
		return noop, ErrSideRun
	}
	root, err := os.OpenRoot(projectRoot)
	if err != nil {
		return noop, fmt.Errorf("secassesssvc.PrepareRunDir: %w", err)
	}
	defer func() { _ = root.Close() }()
	created, wroteGI := false, false
	if _, serr := root.Stat(p.Dir); errors.Is(serr, fs.ErrNotExist) {
		created = true
	}
	// The parents MkdirAll will create, so the cleanup can take them too when
	// they are empty: a launch that fails to start must not leave an untracked
	// .observer folder behind.
	var madeParents []string
	for parent := path.Dir(p.Dir); parent != "." && parent != "/"; parent = path.Dir(parent) {
		if _, serr := root.Stat(parent); errors.Is(serr, fs.ErrNotExist) {
			madeParents = append(madeParents, parent)
		}
	}
	if err := root.MkdirAll(p.Dir, 0o755); err != nil {
		return noop, fmt.Errorf("secassesssvc.PrepareRunDir: %w", err)
	}
	gi := p.Dir + "/.gitignore"
	fh, err := root.OpenFile(gi, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	switch {
	case err == nil:
		wroteGI = true
		_, werr := fh.WriteString(runDirGitignore)
		cerr := fh.Close()
		if werr != nil || cerr != nil {
			_ = root.Remove(gi)
			return noop, fmt.Errorf("secassesssvc.PrepareRunDir: %w", errors.Join(werr, cerr))
		}
	case errors.Is(err, fs.ErrExist):
		// An earlier attempt for this run already wrote it.
	default:
		return noop, fmt.Errorf("secassesssvc.PrepareRunDir: %w", err)
	}
	return func() {
		r, err := os.OpenRoot(projectRoot)
		if err != nil {
			return
		}
		defer func() { _ = r.Close() }()
		if wroteGI {
			_ = r.Remove(gi)
		}
		if created {
			_ = r.Remove(p.Dir)
			// Deepest first; Remove refuses a folder that is not empty, so only
			// what this launch made, and only when nothing else is in it, goes.
			for _, parent := range madeParents {
				_ = r.Remove(parent)
			}
		}
	}, nil
}
