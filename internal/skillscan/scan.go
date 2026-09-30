package skillscan

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
)

// Defaults for the per-tick bounds.
const (
	defaultTreesPerTick   = 50
	defaultReflogPage     = 500
	defaultReflogMaxPages = 20
	defaultMaxOutputBytes = 1 << 20
	probeRefresh          = 24 * time.Hour
	maxErrorLen           = 300
)

// Target is one successfully scanned project root, as the commit scanner
// hands it over.
type Target struct {
	ProjectID int64
	RootPath  string
	HeadSHA   string // "" = the repository has no commits yet
	Subtree   string // project prefix inside the repository, "" at toplevel
}

// State mirrors the store's per-project skill-scan row.
// Field order matches store.SkillScanState exactly (the wiring converts
// between the two).
type State struct {
	ProjectID   int64
	LastScanAt  time.Time
	HeadSHA     string
	ReflogSince time.Time
	// ProbedAt is when the repository probes last ran; they refresh every
	// probeRefresh, independently of LastScanAt (which every tick sets).
	ProbedAt time.Time
	// A probe that fails keeps the previous answer; with none, the *Known
	// flag stays false and the answer is unknown, never false.
	IgnoreCase          bool
	IgnoreCaseKnown     bool
	Shallow             bool
	ShallowKnown        bool
	ObjectFormat        string
	LastError           string
	ConsecutiveFailures int
}

// Move is one reflog entry to persist.
type Move struct {
	MovedAt time.Time
	SHA     string
	Kind    string
}

// TreeFile is one skill path in a commit's tree.
type TreeFile struct {
	RelPath string
	Mode    string
	BlobOID string
}

// WorktreeEntry is one non-clean skill path (project-relative).
type WorktreeEntry struct {
	RelPath string
	State   string
}

// Options wires the step's dependencies. Exec and every store func are
// required; Pathspecs must be the literal skill directory prefixes
// (skillhistory.Pathspecs over the guidance discovery table).
type Options struct {
	// Exec runs one read-only git invocation rooted at root. Production:
	// internal/gitview.RunReadOnlyTimeout (the one envelope).
	Exec func(ctx context.Context, root string, maxBytes int, args ...string) ([]byte, bool, error)
	// MissingObject classifies an Exec error as "that object does not
	// exist here" (gc'd, rebased away, beyond a shallow boundary).
	// Production: gitview.IsMissingObjectError. Nil means never.
	MissingObject func(err error) bool

	HasSignal func(ctx context.Context, projectID int64, root string, prefixes []string) (bool, error)
	// NewestMove returns the newest stored reflog entry's time (ok=false
	// when none): paging stops once a page reaches entries older than it.
	NewestMove      func(ctx context.Context, projectID int64) (time.Time, bool, error)
	State           func(ctx context.Context, projectID int64) (State, bool, error)
	SetState        func(ctx context.Context, st State) error
	InsertMoves     func(ctx context.Context, projectID int64, moves []Move) (inserted int, sawExisting bool, err error)
	TreeCandidates  func(ctx context.Context, projectID int64, prefixes []string, limit int) ([]string, error)
	TreeKnown       func(ctx context.Context, projectID int64, sha string) (bool, error)
	SaveTree        func(ctx context.Context, projectID int64, sha, state string, files []TreeFile, at time.Time) error
	ReplaceWorktree func(ctx context.Context, projectID int64, entries []WorktreeEntry) error

	Pathspecs      []string
	TreesPerTick   int
	ReflogPage     int
	ReflogMaxPages int
	MaxOutputBytes int
	Now            func() time.Time
	Logger         *slog.Logger
}

// Stepper runs the step. Build it once with New and call Step from the
// commit scanner's AfterScan.
type Stepper struct {
	opts Options
}

// New fills defaults and returns a Stepper.
func New(opts Options) *Stepper {
	if opts.TreesPerTick <= 0 {
		opts.TreesPerTick = defaultTreesPerTick
	}
	if opts.ReflogPage <= 0 {
		opts.ReflogPage = defaultReflogPage
	}
	if opts.ReflogMaxPages <= 0 {
		opts.ReflogMaxPages = defaultReflogMaxPages
	}
	if opts.MaxOutputBytes <= 0 {
		opts.MaxOutputBytes = defaultMaxOutputBytes
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Stepper{opts: opts}
}

// Step runs one skills-history pass for a successfully scanned root. It
// returns an error only for a store failure; git failures are recorded on
// the state row (LastError, ConsecutiveFailures) and never abort the
// remaining sub-steps, because each sub-step's output is independently
// useful and independently idempotent.
func (s *Stepper) Step(ctx context.Context, t Target) error {
	if len(s.opts.Pathspecs) == 0 {
		return nil
	}
	ok, err := s.opts.HasSignal(ctx, t.ProjectID, t.RootPath, s.opts.Pathspecs)
	if err != nil {
		return fmt.Errorf("skillscan: signal: %w", err)
	}
	if !ok {
		return nil
	}
	st, had, err := s.opts.State(ctx, t.ProjectID)
	if err != nil {
		return fmt.Errorf("skillscan: state: %w", err)
	}
	now := s.opts.Now()
	st.ProjectID = t.ProjectID
	var errs []string

	if !had || st.ProbedAt.IsZero() || now.Sub(st.ProbedAt) >= probeRefresh {
		s.probe(ctx, t, &st)
		st.ProbedAt = now
	}
	if t.HeadSHA != "" {
		if err := s.reflog(ctx, t, &st); err != nil {
			errs = append(errs, "reflog: "+err.Error())
		}
		if err := s.trees(ctx, t, now); err != nil {
			errs = append(errs, "ls-tree: "+err.Error())
		}
	}
	if err := s.worktree(ctx, t); err != nil {
		errs = append(errs, "status: "+err.Error())
	}

	st.LastScanAt, st.HeadSHA = now, t.HeadSHA
	if len(errs) > 0 {
		st.LastError = truncate(strings.Join(errs, "; "), maxErrorLen)
		st.ConsecutiveFailures++
		s.warn("skillscan: step partially failed", "project_id", t.ProjectID, "error", st.LastError)
	} else {
		st.LastError, st.ConsecutiveFailures = "", 0
	}
	if err := s.opts.SetState(ctx, st); err != nil {
		return fmt.Errorf("skillscan: set state: %w", err)
	}
	return nil
}

func (s *Stepper) warn(msg string, args ...any) {
	if s.opts.Logger != nil {
		s.opts.Logger.Warn(msg, args...)
	}
}

func truncate(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n]
}

// probe refreshes the three repository facts. Each is its own invocation:
// one unsupported flag on an old git only loses that one field. A failed
// probe keeps the previous answer (or leaves it unknown), never "false".
func (s *Stepper) probe(ctx context.Context, t Target, st *State) {
	// --default=false: an UNSET key answers "false" with exit 0, so a
	// non-zero exit is a real failure (timeout, old git), not "unset".
	if out, _, err := s.opts.Exec(ctx, t.RootPath, 4<<10, "config", "--type=bool", "--default=false", "core.ignorecase"); err == nil {
		st.IgnoreCase, st.IgnoreCaseKnown = strings.TrimSpace(string(out)) == "true", true
	}
	if out, _, err := s.opts.Exec(ctx, t.RootPath, 4<<10, "rev-parse", "--show-object-format"); err == nil {
		if v := strings.TrimSpace(string(out)); v != "" {
			st.ObjectFormat = v
		}
	}
	if out, _, err := s.opts.Exec(ctx, t.RootPath, 4<<10, "rev-parse", "--is-shallow-repository"); err == nil {
		st.Shallow, st.ShallowKnown = strings.TrimSpace(string(out)) == "true", true
	}
}

// reflog persists HEAD's reflog. Pages are read newest first until a page
// reaches entries older than the newest one already stored (or a short
// page, or the page cap), then inserted as ONE newest-first capture so the
// store can assign each entry's sequence (the order among entries that
// share one reflog second) from the reflog's own order.
func (s *Stepper) reflog(ctx context.Context, t Target, st *State) error {
	var newest time.Time
	var haveNewest bool
	if s.opts.NewestMove != nil {
		var err error
		if newest, haveNewest, err = s.opts.NewestMove(ctx, t.ProjectID); err != nil {
			return err
		}
	}
	var moves []Move
	for page := 0; page < s.opts.ReflogMaxPages; page++ {
		out, overflow, err := s.opts.Exec(ctx, t.RootPath, s.opts.MaxOutputBytes,
			commitlog.ReflogArgs(s.opts.ReflogPage, page*s.opts.ReflogPage)...)
		if err != nil {
			return err
		}
		if overflow {
			return fmt.Errorf("reflog page %d exceeded the output cap", page)
		}
		entries := commitlog.ParseReflog(out)
		reachedStored := false
		for _, e := range entries {
			moves = append(moves, Move{MovedAt: e.MovedAt, SHA: e.SHA, Kind: e.Kind})
			if st.ReflogSince.IsZero() || e.MovedAt.Before(st.ReflogSince) {
				st.ReflogSince = e.MovedAt
			}
			if haveNewest && e.MovedAt.Before(newest) {
				reachedStored = true
			}
		}
		if reachedStored || len(entries) < s.opts.ReflogPage {
			break
		}
	}
	if _, _, err := s.opts.InsertMoves(ctx, t.ProjectID, moves); err != nil {
		return err
	}
	return nil
}

// trees memoises the skill-directory tree of HEAD first, then of the
// store's candidates (timeline commits and reflog positions), capped.
func (s *Stepper) trees(ctx context.Context, t Target, now time.Time) error {
	var shas []string
	if known, err := s.opts.TreeKnown(ctx, t.ProjectID, t.HeadSHA); err != nil {
		return err
	} else if !known {
		shas = append(shas, t.HeadSHA)
	}
	cands, err := s.opts.TreeCandidates(ctx, t.ProjectID, s.opts.Pathspecs, s.opts.TreesPerTick)
	if err != nil {
		return err
	}
	for _, c := range cands {
		if c != t.HeadSHA && len(shas) < s.opts.TreesPerTick {
			shas = append(shas, c)
		}
	}
	// One bad sha (a timeout, an output overflow) must not starve every
	// other tree: remember the first failure and keep going.
	var firstErr error
	for _, sha := range shas {
		if err := ctx.Err(); err != nil {
			return err
		}
		args := append(commitlog.LsTreeArgs(sha, ""), s.opts.Pathspecs...)
		out, overflow, err := s.opts.Exec(ctx, t.RootPath, s.opts.MaxOutputBytes, args...)
		if err != nil {
			if s.opts.MissingObject != nil && s.opts.MissingObject(err) {
				if serr := s.opts.SaveTree(ctx, t.ProjectID, sha, "missing", nil, now); serr != nil {
					return serr
				}
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if overflow {
			if firstErr == nil {
				firstErr = fmt.Errorf("tree %s exceeded the output cap", sha)
			}
			continue
		}
		var files []TreeFile
		for _, e := range commitlog.ParseLsTree(out) {
			files = append(files, TreeFile{RelPath: e.RelPath, Mode: e.Mode, BlobOID: e.OID})
		}
		if err := s.opts.SaveTree(ctx, t.ProjectID, sha, "ok", files, now); err != nil {
			return err
		}
	}
	return firstErr
}

// worktree replaces the skill paths' status. The porcelain prints paths
// relative to the REPOSITORY root, so a sub-directory project's prefix is
// stripped (and paths outside it dropped) to make them project-relative.
func (s *Stepper) worktree(ctx context.Context, t Target) error {
	args := append(commitlog.StatusArgs(""), s.opts.Pathspecs...)
	out, overflow, err := s.opts.Exec(ctx, t.RootPath, s.opts.MaxOutputBytes, args...)
	if err != nil {
		return err
	}
	if overflow {
		return fmt.Errorf("status exceeded the output cap")
	}
	var entries []WorktreeEntry
	for _, p := range commitlog.ParseStatus(out) {
		rel := p.RelPath
		if t.Subtree != "" {
			if !strings.HasPrefix(rel, t.Subtree) {
				continue
			}
			rel = strings.TrimPrefix(rel, t.Subtree)
		}
		entries = append(entries, WorktreeEntry{RelPath: rel, State: p.State})
	}
	return s.opts.ReplaceWorktree(ctx, t.ProjectID, entries)
}
