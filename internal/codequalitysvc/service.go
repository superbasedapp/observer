// Package codequalitysvc is the I/O boundary of the Projects page's quality
// metrics (docs/projects-page.md "Quality metrics"): it finds and reads a
// project's coverage report files through an fs.FS, reads the codeintel
// duplication and complexity facts and the daily trend through the store
// seam, and hands them to the pure internal/codequality, which decides every number and
// state. It also runs the daemon pass that records one daily point per
// active project (cmd/observer/codequality_wire.go).
//
// It never runs a project's tests or any other process, never writes into
// a project, and makes no network call. A report file is read under a byte
// cap, never followed through a symbolic link, and only its numbers reach
// the database.
package codequalitysvc

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codequality"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/platform/pathnorm"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Store is the store seam the service reads and writes through
// (*store.Store implements it).
type Store interface {
	ProjectRootByID(ctx context.Context, id int64) (string, error)
	ActiveProjectRoots(ctx context.Context, sinceDays int) ([]store.ProjectRoot, error)
	LoadCodeQualityDuplication(ctx context.Context, keys []string) (codequality.DuplicationInput, error)
	LoadCodeQualityComplexity(ctx context.Context, keys []string) (codequality.ComplexityInput, error)
	UpsertProjectQualityDay(ctx context.Context, projectID int64, p codequality.DayPoint) error
	LoadProjectQualityHistory(ctx context.Context, projectID int64, since time.Time) ([]codequality.DayPoint, error)
	LatestProjectQualityDay(ctx context.Context, projectID int64) (codequality.DayPoint, bool, error)
}

// Config is the service's tunables.
type Config struct {
	// Enabled is [projects].quality_metrics.
	Enabled bool
	// CodeIntelOn is [codeintel].enabled: it only decides between the
	// codeintel_off and not_indexed answers when there is no index.
	CodeIntelOn bool
	// ActiveProjectDays bounds the daemon pass to projects with a session
	// in this many days ([projects].active_project_days; <= 0 means 30).
	ActiveProjectDays int
	// Remeasure is how old a project's last point may get before the
	// daemon pass measures it again (default 6h). A new UTC day is always
	// due.
	Remeasure time.Duration
	// MaxPerPass bounds how many projects one daemon pass measures
	// (default 25); the rest wait for the next pass.
	MaxPerPass int
}

// Defaults.
const (
	DefaultRemeasure  = 6 * time.Hour
	DefaultMaxPerPass = 25
	DefaultTick       = 30 * time.Minute
	defaultActiveDays = 30
)

// Service measures projects and records their daily points.
type Service struct {
	st     Store
	cfg    Config
	fsFor  func(root string) fs.FS
	now    func() time.Time
	logger *slog.Logger
}

// Option configures a Service.
type Option func(*Service)

// WithFS replaces the root -> fs.FS mapping (tests use fstest.MapFS). The
// default is os.DirFS of the normalized root.
func WithFS(f func(root string) fs.FS) Option { return func(s *Service) { s.fsFor = f } }

// WithClock replaces time.Now.
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// WithLogger sets the logger of the daemon pass.
func WithLogger(l *slog.Logger) Option { return func(s *Service) { s.logger = l } }

// New builds a Service.
func New(st Store, cfg Config, opts ...Option) *Service {
	if cfg.Remeasure <= 0 {
		cfg.Remeasure = DefaultRemeasure
	}
	if cfg.MaxPerPass <= 0 {
		cfg.MaxPerPass = DefaultMaxPerPass
	}
	if cfg.ActiveProjectDays <= 0 {
		cfg.ActiveProjectDays = defaultActiveDays
	}
	s := &Service{st: st, cfg: cfg, fsFor: os.DirFS, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Enabled reports [projects].quality_metrics.
func (s *Service) Enabled() bool { return s.cfg.Enabled }

// Measure measures one project now. It never writes. An error is a store
// failure; a missing folder, an absent report or an unindexed project is a
// state of the answer, never an error.
func (s *Service) Measure(ctx context.Context, projectID int64) (codequality.Measurement, error) {
	root, err := s.st.ProjectRootByID(ctx, projectID)
	if err != nil {
		return codequality.Measurement{}, err
	}
	return s.MeasureRoot(ctx, root)
}

// MeasureRoot measures the project stored at root.
func (s *Service) MeasureRoot(ctx context.Context, stored string) (codequality.Measurement, error) {
	m := codequality.Measurement{MeasuredAt: s.now().UTC()}
	root := pathnorm.Normalize(stored)

	var found []codequality.Found
	var problems []codequality.Problem
	rootMissing := true
	if s.cfg.Enabled && isAbsRoot(root) {
		fsys := s.fsFor(root)
		if fi, err := fs.Stat(fsys, "."); err == nil && fi.IsDir() {
			rootMissing = false
			found, problems = discover(ctx, fsys)
		}
	}
	m.Coverage = codequality.MeasureCoverage(s.cfg.Enabled, rootMissing, found, problems)
	relativizeCoverage(&m.Coverage, root)

	var dup codequality.DuplicationInput
	var cx codequality.ComplexityInput
	if s.cfg.Enabled {
		keys := codeIntelKeys(stored, root)
		var err error
		if dup, err = s.st.LoadCodeQualityDuplication(ctx, keys); err != nil {
			return m, err
		}
		if cx, err = s.st.LoadCodeQualityComplexity(ctx, keys); err != nil {
			return m, err
		}
	}
	m.Duplication = codequality.MeasureDuplication(s.cfg.Enabled, s.cfg.CodeIntelOn, dup)
	base := m.Duplication.Index.Key
	if base == "" {
		base = root
	}
	for gi := range m.Duplication.TopGroups {
		for mi := range m.Duplication.TopGroups[gi].Members {
			mem := &m.Duplication.TopGroups[gi].Members[mi]
			mem.File = relTo(base, mem.File)
		}
	}
	m.Complexity = codequality.MeasureComplexity(s.cfg.Enabled, s.cfg.CodeIntelOn, cx)
	cxBase := m.Complexity.Index.Key
	if cxBase == "" {
		cxBase = root
	}
	for i := range m.Complexity.Top {
		m.Complexity.Top[i].File = relTo(cxBase, m.Complexity.Top[i].File)
	}
	return m, nil
}

// Record measures one project and stores the day's point.
func (s *Service) Record(ctx context.Context, projectID int64) (codequality.Measurement, error) {
	m, err := s.Measure(ctx, projectID)
	if err != nil {
		return m, err
	}
	return m, s.st.UpsertProjectQualityDay(ctx, projectID, codequality.PointFrom(m))
}

// History returns projectID's daily points of the last days days.
func (s *Service) History(ctx context.Context, projectID int64, days int) ([]codequality.DayPoint, error) {
	if days <= 0 {
		days = 90
	}
	return s.st.LoadProjectQualityHistory(ctx, projectID, s.now().UTC().AddDate(0, 0, -days+1))
}

// RecordDue is one daemon pass: every active project whose last point is
// from an earlier UTC day or older than Remeasure is measured and recorded,
// at most MaxPerPass of them. It returns how many it recorded. A failing
// project is logged and skipped.
func (s *Service) RecordDue(ctx context.Context) (int, error) {
	if !s.cfg.Enabled {
		return 0, nil
	}
	roots, err := s.st.ActiveProjectRoots(ctx, s.cfg.ActiveProjectDays)
	if err != nil {
		return 0, err
	}
	now := s.now().UTC()
	var n int
	for _, r := range roots {
		if n >= s.cfg.MaxPerPass || ctx.Err() != nil {
			break
		}
		last, ok, err := s.st.LatestProjectQualityDay(ctx, r.ID)
		if err != nil {
			return n, err
		}
		if ok && last.Day == codequality.Day(now) && now.Sub(last.MeasuredAt) < s.cfg.Remeasure {
			continue
		}
		m, err := s.MeasureRoot(ctx, r.RootPath)
		if err == nil {
			err = s.st.UpsertProjectQualityDay(ctx, r.ID, codequality.PointFrom(m))
		}
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("codequality: measure failed", "project_id", r.ID, "error", err)
			}
			continue
		}
		n++
	}
	return n, nil
}

// Run is the daemon loop: one pass shortly after start, then one every
// tick (DefaultTick when <= 0), until ctx ends.
func (s *Service) Run(ctx context.Context, tick time.Duration) {
	if !s.cfg.Enabled {
		return
	}
	if tick <= 0 {
		tick = DefaultTick
	}
	first := time.NewTimer(time.Minute)
	defer first.Stop()
	select {
	case <-ctx.Done():
		return
	case <-first.C:
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		if _, err := s.RecordDue(ctx); err != nil && s.logger != nil && ctx.Err() == nil {
			s.logger.Warn("codequality: pass failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// codeIntelKeys are the codeintel project keys stored may be indexed under:
// codeintel keys a project by its absolute root as the indexer saw it.
func codeIntelKeys(stored, normalized string) []string {
	keys := []string{stored, normalized}
	if stored != "" {
		keys = append(keys, filepath.Clean(stored))
	}
	return keys
}

// discover probes fsys at codequality.PlanProbes and reads every report it
// finds, up to codequality.MaxReports.
func discover(ctx context.Context, fsys fs.FS) ([]codequality.Found, []codequality.Problem) {
	var children []string
	if entries, err := fs.ReadDir(fsys, "."); err == nil {
		for _, e := range entries {
			if e.IsDir() && e.Type()&fs.ModeSymlink == 0 {
				children = append(children, e.Name())
			}
		}
	}
	var found []codequality.Found
	var problems []codequality.Problem
	for _, rel := range codequality.PlanProbes(children) {
		if ctx.Err() != nil {
			break
		}
		fi, kind, ok := probe(fsys, rel)
		if !ok {
			continue
		}
		if kind != "" {
			problems = append(problems, codequality.Problem{RelPath: rel, Kind: kind})
			continue
		}
		if len(found) >= codequality.MaxReports {
			problems = append(problems, codequality.Problem{RelPath: rel, Kind: codequality.ProblemCapped})
			continue
		}
		data, kind := readCapped(fsys, rel)
		if kind != "" {
			problems = append(problems, codequality.Problem{RelPath: rel, Kind: kind})
			continue
		}
		rep, err := codequality.ParseCoverage(data)
		switch {
		case errors.Is(err, codequality.ErrUnrecognized):
			problems = append(problems, codequality.Problem{RelPath: rel, Kind: codequality.ProblemUnrecognized})
		case errors.Is(err, codequality.ErrNoLines):
			problems = append(problems, codequality.Problem{RelPath: rel, Kind: codequality.ProblemNoLines})
		case err != nil:
			problems = append(problems, codequality.Problem{RelPath: rel, Kind: codequality.ProblemParse})
		default:
			found = append(found, codequality.Found{RelPath: rel, ModTime: fi.ModTime().UTC(), Report: rep})
		}
	}
	return found, problems
}

// probe checks rel without following a link: ok=false when it does not
// exist or is not a regular file; kind names a problem (a symbolic link on
// the path, a file over the cap).
func probe(fsys fs.FS, rel string) (fs.FileInfo, codequality.ProblemKind, bool) {
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		fi, err := fs.Lstat(fsys, path.Join(parts[:i]...))
		if err != nil {
			return nil, "", false
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return nil, codequality.ProblemSymlink, true
		}
		if !fi.IsDir() {
			return nil, "", false
		}
	}
	fi, err := fs.Lstat(fsys, rel)
	if err != nil {
		return nil, "", false
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fi, codequality.ProblemSymlink, true
	}
	if !fi.Mode().IsRegular() {
		return nil, "", false
	}
	if fi.Size() > codequality.MaxReportBytes {
		return fi, codequality.ProblemTooLarge, true
	}
	return fi, "", true
}

// readCapped reads rel, refusing more than codequality.MaxReportBytes.
func readCapped(fsys fs.FS, rel string) ([]byte, codequality.ProblemKind) {
	f, err := fsys.Open(rel)
	if err != nil {
		return nil, codequality.ProblemUnreadable
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, codequality.MaxReportBytes+1))
	if err != nil {
		return nil, codequality.ProblemUnreadable
	}
	if len(data) > codequality.MaxReportBytes {
		return nil, codequality.ProblemTooLarge
	}
	return data, ""
}

// relativizeCoverage shows report file paths relative to the project root
// when a report names them absolutely.
func relativizeCoverage(c *codequality.CoverageResult, root string) {
	for i := range c.LeastCovered {
		c.LeastCovered[i].Path = relTo(root, c.LeastCovered[i].Path)
	}
}

// relTo returns p relative to base when p lies under it (slash or
// backslash separated), else p unchanged.
func relTo(base, p string) string {
	if base == "" || p == "" {
		return p
	}
	nb := strings.TrimRight(strings.ReplaceAll(base, "\\", "/"), "/") + "/"
	np := strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(np, nb) {
		return np[len(nb):]
	}
	return p
}

// isAbsRoot reports whether root is an absolute path on this host or a
// slash-rooted one. A relative or placeholder root ("[cursor]") would read
// the daemon's own working directory, so it reads as not on this machine.
func isAbsRoot(root string) bool {
	return root != "" && (filepath.IsAbs(root) || strings.HasPrefix(root, "/"))
}

// ConfigFrom is the one mapping from the node config to the service's
// tunables, shared by the daemon loop (cmd/observer/codequality_wire.go)
// and the dashboard's Quality tab (which reads the live config file).
func ConfigFrom(cfg config.Config) Config {
	return Config{
		Enabled:           cfg.Projects.QualityMetrics,
		CodeIntelOn:       cfg.CodeIntel.Enabled,
		ActiveProjectDays: cfg.Projects.ActiveProjectDays,
	}
}
