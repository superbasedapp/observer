//go:build !sbo_omit_security

package seccustomsvc

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/seccustom"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// FindingStore is the findings store seam the service writes through
// (internal/store, migration 177).
type FindingStore interface {
	UpsertSecFinding(ctx context.Context, f secfinding.Finding, now time.Time) (string, bool, error)
	InsertSecScanRun(ctx context.Context, r store.SecScanRun) error
	ListSecFindings(ctx context.Context, f store.SecFindingFilter) ([]secfinding.Finding, error)
	SetSecFindingStatus(ctx context.Context, id string, status secfinding.Status, exceptionID string, now time.Time) error
	// CloseSecFindingNotReproduced is the hold-aware close (lane
	// sec-gate4 milestone 1c).
	CloseSecFindingNotReproduced(ctx context.Context, id string, now time.Time) (bool, error)
}

// OrgSource returns the delivered org policy and the node facts it needs
// (managed with enforce.security). The server half and the pull that
// delivers it are security Phase E; until then the cmd layer passes nil and
// every node behaves as an individual one.
type OrgSource func(ctx context.Context) (seccustom.OrgPolicy, bool)

// Options wire the service.
type Options struct {
	Layout Layout
	// CacheRoot is an Observer-owned directory OUTSIDE ~/.observer (the
	// isolation engine refuses a run that reaches it), for the per-driver
	// caches and the per-run directories.
	CacheRoot string
	// ConfigDir is the global config directory; the "a scanner was added"
	// finding is recorded against its hash.
	ConfigDir string
	Store     FindingStore
	// Resolve discovers an executable (toolresolve with the shim
	// exclusion).
	Resolve func(integration.BinaryResolveSpec) toolresolve.Resolution
	// NewRunner builds the hardened runner for one run, with the isolation
	// provider when the run is isolated (nil otherwise). The cmd layer
	// shares one executor across runs.
	NewRunner func(extrun.IsolationProvider) *extrun.Runner
	// Isolation is the isolation component's one-shot factory; nil when the
	// component is omitted or inactive.
	Isolation extrun.IsolationFactory
	Org       OrgSource
	Now       func() time.Time
}

// runMu makes runs single-flight per process (one heavy scan at a time,
// section 4.4): the dashboard's service and the scheduled loop's share it.
var runMu sync.Mutex

// Service is the custom driver service. Safe for concurrent use: runs are
// single-flight per machine (one heavy scan at a time, section 4.4).
type Service struct {
	o     Options
	recMu sync.Mutex
	// schedMu guards lastSched, the scheduled loop's last run per driver
	// and project, seeded from the store's scan runs (LastRunReader) so a
	// daemon restart keeps it.
	schedMu   sync.Mutex
	lastSched map[string]time.Time
}

// New returns a service.
func New(o Options) *Service {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{o: o}
}

// Layout returns the records layout.
func (s *Service) Layout() Layout { return s.o.Layout }

// Source names what is being imported: a manifest file's bytes or a
// built-in template id (exactly one).
type Source struct {
	File     []byte
	Template string
}

// Prepared is an import before it is accepted: the manifest as it would be
// stored (executable and companions chosen and checked, digests computed),
// what discovery found for each picker, and the digests the confirm dialog
// shows.
type Prepared struct {
	ID             string
	Manifest       seccustom.Manifest
	FileSHA256     string
	ManifestSHA256 string
	Candidates     seccustom.Candidates
	Pin            seccustom.PinScope
	ExecNote       string
	OrgApproved    bool
	Replaces       bool
	// Template is the template's note, "" for a file.
	Note string
}

// Prepare reads the source, discovers the executable and companions,
// applies the choices, checks every path and computes the digests. It
// writes nothing.
func (s *Service) Prepare(ctx context.Context, src Source, c seccustom.Choices) (Prepared, error) {
	var p Prepared
	var tpl *seccustom.Template
	var m seccustom.Manifest
	switch {
	case (src.File == nil) == (src.Template == ""):
		return p, errors.New("import a manifest file or a template, not both")
	case src.Template != "":
		t, ok := seccustom.TemplateByID(src.Template)
		if !ok {
			return p, fmt.Errorf("%q is not a built-in template", src.Template)
		}
		tpl = &t
		p.Note = t.Note
	default:
		var err error
		// Lenient on blocking_rules here; checked against the org catalog
		// once the final digest is known.
		m, err = seccustom.Parse(src.File, seccustom.Options{OrgApproved: true, GOOS: goos()})
		if err != nil {
			return p, err
		}
		p.FileSHA256 = seccustom.FileDigest(src.File)
		if m.Template != "" {
			if t, ok := seccustom.TemplateByID(m.Template); ok {
				tpl = &t
			}
		}
	}
	cand, err := s.discover(tpl, m)
	if err != nil {
		return p, err
	}
	p.Candidates = cand
	if src.Template != "" {
		if m, cand, err = fromTemplate(*tpl, cand); err != nil {
			return p, err
		}
		p.Candidates = cand
	}
	final, err := seccustom.Apply(m, c, cand, seccustom.Options{OrgApproved: true, GOOS: goos()})
	if err != nil {
		return p, err
	}
	if err := s.pinDigests(&final); err != nil {
		return p, err
	}
	ex := checkExecutable(final.Executable)
	if !ex.OK {
		return p, errors.New(ex.Reason)
	}
	p.ExecNote = ex.Note
	for _, comp := range final.Companions {
		if ce := checkExecutable(comp.Path); !ce.OK {
			return p, fmt.Errorf("companion: %s", ce.Reason)
		}
	}
	in := checkInterpreter(final.Executable, final.Companions)
	if in.Reason != "" {
		return p, errors.New(in.Reason)
	}
	p.Pin = seccustom.PinScopeFor(tpl, in.Named != "")
	p.Manifest = final
	p.ManifestSHA256 = final.Digest()
	p.ID, err = seccustom.DriverID(final.Name)
	if err != nil {
		return p, err
	}
	if _, err := s.o.Layout.Load(p.ID); err == nil {
		p.Replaces = true
	}
	if pol, managed := s.org(ctx); managed {
		d := seccustom.DecideOrg(pol, seccustom.OrgFacts{Managed: true}, seccustom.Record{ManifestSHA256: p.ManifestSHA256, Manifest: final})
		p.OrgApproved = d.OrgApproved
	}
	if len(final.BlockingRules) > 0 && !p.OrgApproved {
		return p, errors.New("blocking_rules are allowed only in a manifest from the org's pre-approved catalog")
	}
	return p, nil
}

// fromTemplate builds a template's manifest from what discovery found: the
// first executable candidate and the first candidate of each companion.
// A "#!" interpreter companion with no candidate is fine only when the
// launcher has no "#!" at all; one whose interpreter failed its check is
// refused with the reason, never silently dropped. The companion
// candidates are re-indexed on the companions kept.
func fromTemplate(tpl seccustom.Template, cand seccustom.Candidates) (seccustom.Manifest, seccustom.Candidates, error) {
	if len(cand.Executable) == 0 {
		return seccustom.Manifest{}, cand, fmt.Errorf("%s is not installed in a standard location Observer can see", tpl.Title)
	}
	var comps []string
	for i, tc := range tpl.Companions {
		switch {
		case i < len(cand.Companions) && len(cand.Companions[i]) > 0:
			comps = append(comps, cand.Companions[i][0])
		case !tc.FromShebang:
			return seccustom.Manifest{}, cand, fmt.Errorf("%s needs a companion program Observer cannot find", tpl.Title)
		default:
			if in := checkInterpreter(cand.Executable[0], nil); in.Named != "" || in.Reason != "" {
				why := in.Reason
				if r := checkExecutable(in.Resolved); in.Resolved != "" && !r.OK {
					why = r.Reason
				}
				return seccustom.Manifest{}, cand, fmt.Errorf("%s's interpreter is refused: %s", tpl.Title, why)
			}
			comps = append(comps, "")
		}
	}
	m := seccustom.FromTemplate(tpl, cand.Executable[0], comps)
	var kept [][]string
	for i := range tpl.Companions {
		if i < len(comps) && comps[i] != "" {
			kept = append(kept, cand.Companions[i])
		}
	}
	cand.Companions = kept
	return m, cand, nil
}

// pinDigests computes the executable and companion digests and checks any
// digest the file pinned (a mismatch is refused, driver_unverified).
func (s *Service) pinDigests(final *seccustom.Manifest) error {
	sum, err := hashFile(final.Executable)
	if err != nil {
		return fmt.Errorf("the executable could not be hashed: %w", err)
	}
	if final.ExecutableSHA256 != "" && final.ExecutableSHA256 != sum {
		return errors.New("driver_unverified: the executable's digest does not match the manifest's executable_sha256")
	}
	final.ExecutableSHA256 = sum
	for i := range final.Companions {
		c := &final.Companions[i]
		sum, err := hashFile(c.Path)
		if err != nil {
			return fmt.Errorf("the companion %s could not be hashed: %w", c.Path, err)
		}
		if c.SHA256 != "" && c.SHA256 != sum {
			return fmt.Errorf("driver_unverified: the companion %s does not match its pinned digest", c.Path)
		}
		c.SHA256 = sum
	}
	return nil
}

// discover finds the candidates of every picker that takes a path: through
// the template's resolve spec, or for a file, through its executable's
// file name looked up on PATH, the standard locations and the file's own
// directory. A candidate is kept only when it passes the executable checks;
// a symlinked install is offered by its resolved path.
func (s *Service) discover(tpl *seccustom.Template, m seccustom.Manifest) (seccustom.Candidates, error) {
	var cand seccustom.Candidates
	if s.o.Resolve == nil {
		return cand, errors.New("executable discovery is not wired")
	}
	exeSpec := integration.BinaryResolveSpec{}
	if tpl != nil {
		exeSpec = tpl.Binary
	}
	if m.Executable != "" {
		exeSpec.Names = integration.BinaryNames{Unix: []string{filepath.Base(m.Executable)}, Windows: []string{filepath.Base(m.Executable)}}
		exeSpec.ProbeDirs = append(append([]integration.ProbeDir(nil), exeSpec.ProbeDirs...), probeAbs(filepath.Dir(m.Executable))...)
	}
	cand.Executable = s.candidates(exeSpec, m.Executable)
	exe := m.Executable
	if exe == "" && len(cand.Executable) > 0 {
		exe = cand.Executable[0]
	}
	switch {
	case tpl != nil && m.Executable == "":
		for _, tc := range tpl.Companions {
			if tc.FromShebang {
				cand.Companions = append(cand.Companions, s.shebangCandidates(exe))
				continue
			}
			cand.Companions = append(cand.Companions, s.candidates(tc.Binary, ""))
		}
	default:
		for _, c := range m.Companions {
			spec := integration.BinaryResolveSpec{
				Names:     integration.BinaryNames{Unix: []string{filepath.Base(c.Path)}, Windows: []string{filepath.Base(c.Path)}},
				ProbeDirs: probeAbs(filepath.Dir(c.Path)),
			}
			cand.Companions = append(cand.Companions, s.candidates(spec, c.Path))
		}
	}
	return cand, nil
}

// probeAbs is an absolute probe directory for every OS.
func probeAbs(dir string) []integration.ProbeDir {
	return []integration.ProbeDir{
		{OS: integration.ProbeUnix, Rel: dir, Abs: true},
		{OS: integration.ProbeDarwin, Rel: dir, Abs: true},
		{OS: integration.ProbeWindows, Rel: dir, Abs: true},
	}
}

// candidates resolves spec and returns the checked candidate paths: the
// chosen binary, then every other considered one, each by its resolved
// path, then want itself when it checks out.
func (s *Service) candidates(spec integration.BinaryResolveSpec, want string) []string {
	var paths []string
	res := s.o.Resolve(spec)
	if res.Bin != "" {
		paths = append(paths, res.Bin)
	}
	for _, c := range res.Considered {
		if !c.Foreign {
			paths = append(paths, c.Path)
		}
	}
	if want != "" {
		paths = append(paths, want)
	}
	var out []string
	for _, p := range paths {
		if p == "" {
			continue
		}
		r := realPath(p)
		if slices.Contains(out, r) || !checkExecutable(r).OK {
			continue
		}
		out = append(out, r)
	}
	return out
}

// shebangCandidates is the interpreter an interpreted launcher names, by
// its resolved path.
func (s *Service) shebangCandidates(exe string) []string {
	if exe == "" {
		return nil
	}
	in := seccustom.Shebang(readHead(exe))
	if in == "" {
		return nil
	}
	r := realPath(in)
	if !checkExecutable(r).OK {
		// Prepare reports why (the import is refused, never the companion
		// dropped).
		return nil
	}
	return []string{r}
}

func (s *Service) org(ctx context.Context) (seccustom.OrgPolicy, bool) {
	if s.o.Org == nil {
		return seccustom.OrgPolicy{}, false
	}
	return s.o.Org(ctx)
}

// Accept re-prepares the import (rediscovering and re-hashing), refuses
// unless the manifest digest equals the one the confirm dialog showed,
// writes the record, appends the audit line and raises the agent_config
// finding. A changed manifest invalidates the self-test.
func (s *Service) Accept(ctx context.Context, src Source, c seccustom.Choices, confirmedDigest, via string) (seccustom.Record, error) {
	if via != "dashboard" && via != "cli" {
		return seccustom.Record{}, errors.New("an accept comes from the dashboard or the CLI")
	}
	p, err := s.Prepare(ctx, src, c)
	if err != nil {
		return seccustom.Record{}, err
	}
	if confirmedDigest == "" || confirmedDigest != p.ManifestSHA256 {
		return seccustom.Record{}, errors.New("the manifest changed since it was shown; review it again before accepting")
	}
	s.recMu.Lock()
	defer s.recMu.Unlock()
	now := s.o.Now().UTC()
	rec := seccustom.Record{
		ID: p.ID, Manifest: p.Manifest, ManifestSHA256: p.ManifestSHA256, FileSHA256: p.FileSHA256,
		Pin: p.Pin, AcceptedAt: now, AcceptedVia: via, OrgApproved: p.OrgApproved, ExecNote: p.ExecNote,
	}
	action := AuditAdded
	if old, err := s.o.Layout.Load(p.ID); err == nil {
		action = AuditChanged
		if old.ManifestSHA256 == rec.ManifestSHA256 {
			// The same manifest again keeps its self-test.
			rec.SelfTest = old.SelfTest
		}
	}
	if err := s.o.Layout.save(rec); err != nil {
		return seccustom.Record{}, err
	}
	if err := s.o.Layout.appendAudit(AuditEntry{
		At: now, Action: action, ID: rec.ID, Via: via, ManifestSHA256: rec.ManifestSHA256,
		FileSHA256: rec.FileSHA256, ExecutableSHA256: rec.Manifest.ExecutableSHA256,
	}); err != nil {
		return rec, err
	}
	return rec, s.raiseTrustFinding(ctx, rec, action, now)
}

// Remove deletes a record and audits it.
func (s *Service) Remove(ctx context.Context, id, via string) error {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	old, err := s.o.Layout.Load(id)
	if errors.Is(err, ErrNotFound) {
		return err
	}
	// A record that no longer loads (edited by hand) can still be removed.
	if err := s.o.Layout.remove(id); err != nil {
		return err
	}
	now := s.o.Now().UTC()
	return s.o.Layout.appendAudit(AuditEntry{At: now, Action: AuditRemoved, ID: id, Via: via, ManifestSHA256: old.ManifestSHA256})
}

// TrustRuleID is the finding rule id of "a custom scanner was added or
// changed" (a finding rule id, not a guard rule id).
const TrustRuleID = "custom-scanner-changed"

// raiseTrustFinding records the agent_config finding for an accept, against
// the global config directory's hash (the change is to the node's own
// config, not to a project). It is flag-only: medium confidence, baseline
// unknown.
func (s *Service) raiseTrustFinding(ctx context.Context, rec seccustom.Record, action string, now time.Time) error {
	return s.upsertTrustFinding(ctx, rec, now, fmt.Sprintf("A custom scanner was %s: %s (manifest %s, accepted from the %s)", action, rec.ID, shortDigest(rec.ManifestSHA256), rec.AcceptedVia))
}

// upsertTrustFinding writes the custom-scanner-changed finding for rec. Its
// key is the driver id and the manifest digest, so raising it again for the
// same record is a no-op update, never a second finding.
func (s *Service) upsertTrustFinding(ctx context.Context, rec seccustom.Record, now time.Time, msg string) error {
	if s.o.Store == nil {
		return nil
	}
	root := secposture.ProjectRootHash(s.o.ConfigDir)
	f := secfinding.Finding{
		Rule:     secfinding.Rule{ID: TrustRuleID, Pack: seccustom.ComponentID},
		Engine:   secfinding.Engine{Driver: seccustom.ComponentID},
		Category: policy.FindingAgentConfig, Severity: policy.FindingSeverityMedium, Confidence: policy.FindingConfidenceMedium,
		Scope:    policy.FindingScopeManual,
		Project:  secfinding.Project{RootHash: root},
		Message:  msg,
		Baseline: policy.FindingBaselineUnknown, Status: policy.FindingStatusOpen,
	}
	f.LocalKey = secfinding.LocalKey(root, TrustRuleID, secfinding.TextIdentity("driver:"+rec.ID+":"+rec.ManifestSHA256))
	_, _, err := s.o.Store.UpsertSecFinding(ctx, secfinding.Normalize(f), now)
	return err
}

func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// ErrUnaudited reports a record with no matching accept in the audit log:
// it was written into the drivers directory by something other than the
// dashboard or the CLI.
var ErrUnaudited = errors.New("driver_unaudited: this scanner record was not written by an accept from the dashboard or the CLI; it was flagged and will not run until it is imported again")

// loadChecked is the one load path for a record that is about to run or be
// shown as runnable. On top of the layout's self-consistency check it
// (1) refuses a record the audit log does not account for and raises the
// custom-scanner-changed finding for it (a record planted with a
// self-consistent digest is never run unnoticed), (2) re-derives
// OrgApproved from the delivered org policy instead of the file, and
// (3) re-runs the executable checks on the executable and every companion,
// because the files on disk may have changed since the accept.
func (s *Service) loadChecked(ctx context.Context, id string) (seccustom.Record, error) {
	rec, err := s.o.Layout.Load(id)
	if err != nil {
		return rec, err
	}
	if !s.o.Layout.audited(rec) {
		msg := fmt.Sprintf("A custom scanner record was written outside the dashboard and the CLI: %s (manifest %s); it will not run until it is imported again", rec.ID, shortDigest(rec.ManifestSHA256))
		if ferr := s.upsertTrustFinding(ctx, rec, s.o.Now().UTC(), msg); ferr != nil {
			return seccustom.Record{}, fmt.Errorf("%w (and the finding could not be recorded: %w)", ErrUnaudited, ferr)
		}
		return seccustom.Record{}, ErrUnaudited
	}
	if pol, managed := s.org(ctx); managed {
		rec.OrgApproved = seccustom.DecideOrg(pol, seccustom.OrgFacts{Managed: true}, rec).OrgApproved
	}
	if len(rec.Manifest.BlockingRules) > 0 && !rec.OrgApproved {
		return seccustom.Record{}, errors.New("blocking_rules are allowed only in a manifest from the org's pre-approved catalog, and the delivered catalog does not list this one")
	}
	if ex := checkExecutable(rec.Manifest.Executable); !ex.OK {
		return seccustom.Record{}, errors.New(ex.Reason)
	}
	for _, comp := range rec.Manifest.Companions {
		if ce := checkExecutable(comp.Path); !ce.OK {
			return seccustom.Record{}, fmt.Errorf("companion: %s", ce.Reason)
		}
	}
	if in := checkInterpreter(rec.Manifest.Executable, rec.Manifest.Companions); in.Reason != "" {
		return seccustom.Record{}, errors.New(in.Reason)
	}
	return rec, nil
}

// Records returns every record that passes loadChecked, sorted by id, and
// the ids that did not with why (the Scanners tab and the CLI list).
func (s *Service) Records(ctx context.Context) ([]seccustom.Record, map[string]string) {
	recs, bad := s.o.Layout.List()
	if bad == nil {
		bad = map[string]string{}
	}
	var out []seccustom.Record
	for _, r := range recs {
		got, err := s.loadChecked(ctx, r.ID)
		if err != nil {
			bad[r.ID] = err.Error()
			continue
		}
		out = append(out, got)
	}
	return out, bad
}

// RequiredMissing lists the manifest digests a require-mode org policy
// names that no accepted record matches (empty on an individual node or
// without an org policy). It reads the CHECKED records (Records, through
// loadChecked), so a record planted outside the dashboard and the CLI, or
// one whose executable no longer passes, never makes a requirement read as
// met: only a scanner that would actually run counts.
func (s *Service) RequiredMissing(ctx context.Context) []string {
	recs, _ := s.Records(ctx)
	return s.RequiredMissingAmong(ctx, recs)
}

// RequiredMissingAmong is RequiredMissing over records the caller already
// took from Records (checked, in the same request), so a caller that shows
// the records too checks each one once, not twice. Pass only what Records
// returned: an unchecked record must never make a requirement read as met.
func (s *Service) RequiredMissingAmong(ctx context.Context, checked []seccustom.Record) []string {
	pol, managed := s.org(ctx)
	return seccustom.RequiredMissing(pol, seccustom.OrgFacts{Managed: managed}, checked)
}
