//go:build !sbo_omit_security

package seccustomsvc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/seccustom"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// memStore is an in-memory FindingStore.
type memStore struct {
	mu       sync.Mutex
	findings map[string]secfinding.Finding
	runs     []store.SecScanRun
	n        int
}

func newMemStore() *memStore { return &memStore{findings: map[string]secfinding.Finding{}} }

func (m *memStore) UpsertSecFinding(_ context.Context, f secfinding.Finding, _ time.Time) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, old := range m.findings {
		if old.Project.RootHash == f.Project.RootHash && old.LocalKey == f.LocalKey {
			f.ID = id
			m.findings[id] = f
			return id, false, nil
		}
	}
	m.n++
	f.ID = "f" + string(rune('a'+m.n))
	m.findings[f.ID] = f
	return f.ID, true, nil
}

func (m *memStore) InsertSecScanRun(_ context.Context, r store.SecScanRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs = append(m.runs, r)
	return nil
}

// SecLastDriverRun makes memStore a LastRunReader, as *store.Store is.
func (m *memStore) SecLastDriverRun(_ context.Context, rootHash, driver string, scope secfinding.Scope) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var last time.Time
	for _, r := range m.runs {
		if r.ProjectRootHash == rootHash && r.Driver == driver && r.Scope == scope && r.StartedAt.After(last) {
			last = r.StartedAt
		}
	}
	return last, nil
}

func (m *memStore) ListSecFindings(_ context.Context, f store.SecFindingFilter) ([]secfinding.Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []secfinding.Finding
	for _, v := range m.findings {
		if v.Project.RootHash == f.ProjectRootHash && (f.Status == "" || v.Status == f.Status) {
			out = append(out, v)
		}
	}
	return out, nil
}

func (m *memStore) SetSecFindingStatus(_ context.Context, id string, st secfinding.Status, _ string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.findings[id]
	f.Status = st
	m.findings[id] = f
	return nil
}

// CloseSecFindingNotReproduced closes like the store's hold-aware close
// for a finding nothing holds (the store test covers the hold).
func (m *memStore) CloseSecFindingNotReproduced(ctx context.Context, id string, now time.Time) (bool, error) {
	return true, m.SetSecFindingStatus(ctx, id, policy.FindingStatusNotReproduced, "", now)
}

// privateDir is a directory under HOME (not the shared sticky /tmp, which
// the executable checks refuse), mode 0755 with 0755 parents up to HOME.
func privateDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home")
	}
	d, err := os.MkdirTemp(home, "seccustomsvc-test-")
	if err != nil {
		t.Skip("home not writable")
	}
	_ = os.Chmod(d, 0o755)
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// absResolver resolves a spec by looking for its names in its absolute
// probe directories only.
func absResolver(spec integration.BinaryResolveSpec) toolresolve.Resolution {
	for _, pd := range spec.ProbeDirs {
		if !pd.Abs || pd.OS != integration.ProbeUnix {
			continue
		}
		for _, n := range spec.Names.Unix {
			p := filepath.Join(pd.Rel, n)
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
				return toolresolve.Resolution{Verdict: toolresolve.VerdictOKOffPath, Bin: p}
			}
		}
	}
	return toolresolve.Resolution{Verdict: toolresolve.VerdictNotFound}
}

// fakeScanner writes a /bin/sh scanner that writes the SARIF named by its
// mode argument to the output path.
const fakeScanner = `#!/bin/sh
mode="$1"; out="$2"
case "$mode" in
findings) printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"fake","rules":[{"id":"F1"}]}},"results":[{"ruleId":"F1","level":"error","message":{"text":"password=hunter2"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":2,"snippet":{"text":"hunter2"}}}}]}]}]}' > "$out" ;;
empty) printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"fake"}},"results":[]}]}' > "$out" ;;
hostile) printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"fake"}},"results":[{"ruleId":"F1","level":"error","locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///etc/passwd"}}}]}]}]}' > "$out" ;;
esac
echo "progress: skipping SSA analysis" >&2
exit 0
`

func fakeManifest(exe, mode string, stderrMarker bool) []byte {
	m := map[string]any{
		"schema": seccustom.SchemaV1, "name": "fake scanner", "version": "1", "executable": exe,
		"argv": []string{mode, "{output_file}"}, "input": "stdin", "output": "sarif_file",
		"limits": seccustom.DefaultLimits, "cache": "none",
		"exit_codes": []map[string]any{{"code": 0, "meaning": "result"}},
		"network":    map[string]any{"mode": "none"}, "category": "code_vuln",
		// The "#!/bin/sh" interpreter, pinned as a companion.
		"companions":     []map[string]any{{"path": realPath("/bin/sh")}},
		"severity_map":   map[string]any{"source": "level", "levels": map[string]string{"error": "high", "warning": "medium"}},
		"confidence_map": map[string]any{"source": "fixed", "fixed": "high"},
	}
	if stderrMarker {
		m["unknown_stderr"] = []string{"skipping SSA analysis"}
	}
	b, _ := json.Marshal(m)
	return b
}

type fixture struct {
	svc   *Service
	store *memStore
	dir   string
	exe   string
	proj  string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dir := privateDir(t)
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(bin, "fake-scan")
	if err := os.WriteFile(exe, []byte(fakeScanner), 0o755); err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(dir, "proj")
	_ = os.Mkdir(proj, 0o755)
	st := newMemStore()
	ex := &host.Executor{DrainTimeout: 300 * time.Millisecond}
	svc := New(Options{
		Layout: LayoutFor(filepath.Join(dir, ".observer")), CacheRoot: filepath.Join(dir, "cache"),
		ConfigDir: filepath.Join(dir, ".observer"), Store: st, Resolve: absResolver,
		NewRunner: func(p extrun.IsolationProvider) *extrun.Runner {
			return host.NewRunner(host.Options{Isolation: p, Executor: ex})
		},
	})
	return fixture{svc: svc, store: st, dir: dir, exe: exe, proj: proj}
}

func (f fixture) accept(t *testing.T, mode string, marker bool) seccustom.Record {
	t.Helper()
	src := Source{File: fakeManifest(f.exe, mode, marker)}
	p, err := f.svc.Prepare(context.Background(), src, seccustom.Choices{})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := f.svc.Accept(context.Background(), src, seccustom.Choices{}, p.ManifestSHA256, "cli")
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestAcceptNeedsTheShownDigestAndAudits(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	src := Source{File: fakeManifest(f.exe, "findings", false)}
	p, err := f.svc.Prepare(context.Background(), src, seccustom.Choices{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Pin != seccustom.PinPartial || p.ID != "fake-scanner" || len(p.Candidates.Executable) != 1 || p.ManifestSHA256 == "" {
		t.Fatalf("prepared %+v", p)
	}
	if _, err := f.svc.Accept(context.Background(), src, seccustom.Choices{}, strings.Repeat("0", 64), "cli"); err == nil {
		t.Fatal("an accept with a digest that was never shown went through")
	}
	if _, err := f.svc.Accept(context.Background(), src, seccustom.Choices{}, p.ManifestSHA256, "agent"); err == nil {
		t.Fatal("an accept from neither the dashboard nor the CLI went through")
	}
	rec, err := f.svc.Accept(context.Background(), src, seccustom.Choices{}, p.ManifestSHA256, "dashboard")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.svc.Layout().Load(rec.ID); err != nil || got.ManifestSHA256 != p.ManifestSHA256 {
		t.Fatalf("load: %v", err)
	}
	if a := f.svc.Layout().Audit(10); len(a) != 1 || a[0].Action != AuditAdded || a[0].Via != "dashboard" {
		t.Fatalf("audit %+v", a)
	}
	var trust int
	for _, fd := range f.store.findings {
		if fd.Rule.ID == TrustRuleID && fd.Category == policy.FindingAgentConfig {
			trust++
		}
	}
	if trust != 1 {
		t.Fatalf("trust findings: %d", trust)
	}
	if err := f.svc.Remove(context.Background(), rec.ID, "cli"); err != nil {
		t.Fatal(err)
	}
	if a := f.svc.Layout().Audit(10); a[len(a)-1].Action != AuditRemoved {
		t.Fatalf("audit %+v", a)
	}
}

func TestPrepareRefusesASymlinkedExecutable(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	link := filepath.Join(f.dir, "bin", "linked-scan")
	if err := os.Symlink(f.exe, link); err != nil {
		t.Fatal(err)
	}
	// The symlink is offered by its resolved path, never as itself.
	p, err := f.svc.Prepare(context.Background(), Source{File: fakeManifest(link, "findings", false)}, seccustom.Choices{Executable: link})
	if err == nil {
		t.Fatalf("a symlinked executable was accepted: %+v", p)
	}
	if p, err := f.svc.Prepare(context.Background(), Source{File: fakeManifest(link, "findings", false)}, seccustom.Choices{Executable: f.exe}); err != nil || p.Manifest.Executable != f.exe {
		t.Fatalf("the resolved path: %+v %v", p, err)
	}
}

func TestRunFindingsAreFlagOnlyAndContentFree(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	rec := f.accept(t, "findings", false)
	rep, err := f.svc.Run(context.Background(), rec.ID, f.proj, policy.FindingScopeManual)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict.Outcome != secscan.OutcomeFindings || rep.Findings != 1 || rep.Containment.Rung == "" || rep.Containment.Label == "" {
		t.Fatalf("report %+v", rep)
	}
	if rep.Isolation != "" || rep.NotIsolatedWhy == "" {
		t.Fatalf("no isolation factory: must be labelled not isolated: %+v", rep)
	}
	for _, fd := range f.store.findings {
		if fd.Engine.Driver != rec.Driver() {
			continue
		}
		b, _ := json.Marshal(fd)
		if strings.Contains(string(b), "hunter2") || fd.Confidence == policy.FindingConfidenceHigh || fd.Baseline != policy.FindingBaselineUnknown {
			t.Fatalf("finding %s", b)
		}
	}
	if len(f.store.runs) != 1 || f.store.runs[0].Outcome != "findings" || f.store.runs[0].Driver != "custom:fake-scanner" {
		t.Fatalf("runs %+v", f.store.runs)
	}
	eng, _ := json.Marshal(f.store.runs[0].Engine)
	if !strings.Contains(string(eng), `"Rung":"`) {
		t.Fatalf("the run record does not name its containment rung: %s", eng)
	}
}

func TestEmptySARIFWithoutSelfTestIsUnknown(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	rec := f.accept(t, "empty", false)
	rep, err := f.svc.Run(context.Background(), rec.ID, f.proj, policy.FindingScopeManual)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict.Outcome != secscan.OutcomeUnknown || rep.Verdict.Reason != "no_self_test" {
		t.Fatalf("exit 0 with an empty SARIF must be unknown: %+v", rep.Verdict)
	}
	rec2 := f.accept(t, "findings", true)
	rep, _ = f.svc.Run(context.Background(), rec2.ID, f.proj, policy.FindingScopeManual)
	if rep.Verdict.Outcome != secscan.OutcomeFindings {
		t.Fatalf("marker with findings: %+v", rep.Verdict)
	}
}

func TestHostileSARIFIsRefusedNotStored(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	rec := f.accept(t, "hostile", false)
	rep, err := f.svc.Run(context.Background(), rec.ID, f.proj, policy.FindingScopeManual)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Findings != 0 || rep.Refused != 1 || rep.Verdict.Reason != "results_refused" {
		t.Fatalf("report %+v", rep)
	}
}

func TestADigestChangeRefusesTheRun(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	rec := f.accept(t, "findings", false)
	if err := os.WriteFile(f.exe, []byte(fakeScanner+"\n# changed\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rep, err := f.svc.Run(context.Background(), rec.ID, f.proj, policy.FindingScopeManual)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict.Outcome != secscan.OutcomeFailed || rep.Verdict.Reason != "driver_unverified" || rep.RunnerOut != extrun.OutcomeRefused {
		t.Fatalf("report %+v", rep)
	}
}

func TestOrgForbidStopsTheRun(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	rec := f.accept(t, "findings", false)
	f.svc.o.Org = func(context.Context) (seccustom.OrgPolicy, bool) {
		return seccustom.OrgPolicy{Mode: seccustom.OrgModeForbid}, true
	}
	if _, err := f.svc.Run(context.Background(), rec.ID, f.proj, policy.FindingScopeManual); err == nil || !strings.Contains(err.Error(), "org_forbids") {
		t.Fatalf("forbid: %v", err)
	}
}

func TestRecordsOutsideTheLayoutAreNeverRead(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	rec := f.accept(t, "findings", false)
	p, _ := f.svc.Layout().recordPath(rec.ID)
	b, _ := os.ReadFile(p)
	// A hand edit (the executable swapped) breaks the accepted digest.
	b = []byte(strings.Replace(string(b), f.exe, "/bin/sh", 1))
	_ = os.WriteFile(p, b, 0o600)
	if _, err := f.svc.Layout().Load(rec.ID); err == nil {
		t.Fatal("a hand-edited record loaded")
	}
	if _, err := f.svc.Layout().Load("../../etc/passwd"); err == nil {
		t.Fatal("a path id loaded")
	}
}

// TestRealScannersEndToEnd runs the gosec and Bandit templates against
// their self-test fixtures (live check, gated): set SECCUSTOM_E2E_GOSEC,
// SECCUSTOM_E2E_GO (a go binary, not a symlink) and SECCUSTOM_E2E_BANDIT.
func TestRealScannersEndToEnd(t *testing.T) {
	gosec, goBin, bandit := os.Getenv("SECCUSTOM_E2E_GOSEC"), os.Getenv("SECCUSTOM_E2E_GO"), os.Getenv("SECCUSTOM_E2E_BANDIT")
	if gosec == "" && bandit == "" {
		t.Skip("set SECCUSTOM_E2E_GOSEC / SECCUSTOM_E2E_GO / SECCUSTOM_E2E_BANDIT to run")
	}
	f := newFixture(t)
	f.svc.o.Resolve = func(spec integration.BinaryResolveSpec) toolresolve.Resolution {
		for _, n := range spec.Names.Unix {
			for _, p := range []string{gosec, goBin, bandit} {
				if p != "" && filepath.Base(p) == n {
					return toolresolve.Resolution{Verdict: toolresolve.VerdictOKOffPath, Bin: p}
				}
			}
		}
		return absResolver(spec)
	}
	for _, tpl := range []string{"gosec", "bandit"} {
		if (tpl == "gosec" && (gosec == "" || goBin == "")) || (tpl == "bandit" && bandit == "") {
			continue
		}
		t.Run(tpl, func(t *testing.T) {
			src := Source{Template: tpl}
			p, err := f.svc.Prepare(context.Background(), src, seccustom.Choices{})
			if err != nil {
				t.Fatal(err)
			}
			rec, err := f.svc.Accept(context.Background(), src, seccustom.Choices{}, p.ManifestSHA256, "cli")
			if err != nil {
				t.Fatal(err)
			}
			st, err := f.svc.SelfTest(context.Background(), rec.ID)
			if err != nil || !st.Passed {
				t.Fatalf("self-test %+v %v", st, err)
			}
			files, paths, _ := seccustom.FixtureFiles(rec.Manifest.SelfTest.Fixture)
			proj := filepath.Join(f.dir, "e2e-"+tpl)
			for _, pth := range paths {
				_ = os.MkdirAll(filepath.Dir(filepath.Join(proj, pth)), 0o755)
				_ = os.WriteFile(filepath.Join(proj, pth), files[pth], 0o644)
			}
			rep, err := f.svc.Run(context.Background(), rec.ID, proj, policy.FindingScopeManual)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s: verdict %+v findings %d rung %s (%s) toolchain %+v", tpl, rep.Verdict, rep.Findings, rep.Containment.Rung, rep.Containment.Label, rep.Toolchain)
			if rep.Verdict.Outcome != secscan.OutcomeFindings || rep.Findings == 0 {
				t.Fatalf("report %+v", rep)
			}
		})
	}
}

// pidnsIsolation stands in for the isolation component's one-shot: it
// keeps the plan and declares its own pid namespace.
type pidnsIsolation struct{ dirs extrun.OneShotDirs }

func (pidnsIsolation) Name() string { return "test.oneshot" }
func (p pidnsIsolation) Wrap(_ context.Context, pl extrun.Plan) (extrun.Plan, error) {
	return pl, nil
}
func (pidnsIsolation) PIDNamespace() bool { return true }

// TestIsolatedRunAndOrgBlocking: through the injected factory the run is
// isolated and contained; on a managed node an org-approved manifest's
// catalog rule may block only on that isolated run (D7), and stays
// flag-only when the run is not isolated. The runner's containment table
// puts a per-run cgroup above the isolation pid namespace
// (extrun.ContainmentRungs), so a host whose cgroup rung starts holds the
// isolated run in its cgroup and any other host in the provider's pid
// namespace: the containment check accepts exactly those two rungs.
func TestIsolatedRunAndOrgBlocking(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	var gotDirs extrun.OneShotDirs
	f.svc.o.Isolation = func(d extrun.OneShotDirs) (extrun.IsolationProvider, error) {
		gotDirs = d
		return pidnsIsolation{dirs: d}, nil
	}
	rec := f.accept(t, "findings", false)
	pol := seccustom.OrgPolicy{Mode: seccustom.OrgModeCatalogOnly, Entries: []seccustom.OrgEntry{{
		ManifestSHA256: rec.ManifestSHA256, ExecutableSHA256: rec.Manifest.ExecutableSHA256,
		BlockingRules: []seccustom.OrgBlockingRule{{RuleID: "F1", Precision: 0.95}},
	}}}
	// The local record names no blocking rule, so even the catalog's rule
	// stays flag-only: only an org-approved manifest that lists the rule
	// may block.
	f.svc.o.Org = func(context.Context) (seccustom.OrgPolicy, bool) { return pol, true }
	rep, err := f.svc.Run(context.Background(), rec.ID, f.proj, policy.FindingScopeManual)
	if err != nil {
		t.Fatal(err)
	}
	// heldBy is the containment an isolated run may have, by rung: the
	// cgroup rung must also name where its cgroup came from.
	heldBy := map[extrun.Rung]func(extrun.Containment) bool{
		extrun.RungCgroup:       func(c extrun.Containment) bool { return c.CgroupSource != "" },
		extrun.RungPIDNamespace: func(extrun.Containment) bool { return true },
	}
	held, ok := heldBy[rep.Containment.Rung]
	if rep.Isolation != "test.oneshot" || !ok || !held(rep.Containment) || !rep.Containment.Contained {
		t.Fatalf("isolated run: %+v", rep)
	}
	if gotDirs.Project != f.proj || gotDirs.Output == "" || gotDirs.Cache == "" || strings.HasPrefix(gotDirs.Output, filepath.Join(f.dir, ".observer")) {
		t.Fatalf("one-shot dirs %+v", gotDirs)
	}
	if !rep.Org.OrgApproved || len(rep.Org.Blocking) != 0 {
		t.Fatalf("org decision %+v", rep.Org)
	}
	// Now the record lists the rule (as an org catalog manifest would).
	rec.Manifest.BlockingRules = []string{"F1"}
	rec.OrgApproved = true
	rec.ManifestSHA256 = rec.Manifest.Digest()
	pol.Entries[0].ManifestSHA256 = rec.ManifestSHA256
	if err := f.svc.Layout().save(rec); err != nil {
		t.Fatal(err)
	}
	// The audit line an org catalog accept writes (a record with no
	// matching line is refused as planted).
	if err := f.svc.Layout().appendAudit(AuditEntry{Action: AuditChanged, ID: rec.ID, ManifestSHA256: rec.ManifestSHA256, ExecutableSHA256: rec.Manifest.ExecutableSHA256}); err != nil {
		t.Fatal(err)
	}
	rep, err = f.svc.Run(context.Background(), rec.ID, f.proj, policy.FindingScopeManual)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Org.Blocking) != 1 {
		t.Fatalf("isolated org-approved run: %+v", rep.Org)
	}
	blocking := 0
	for _, fd := range f.store.findings {
		if fd.Engine.Driver == rec.Driver() && fd.Baseline == policy.FindingBaselineUntrusted && fd.Confidence == policy.FindingConfidenceHigh {
			blocking++
		}
	}
	if blocking != 1 {
		t.Fatalf("blocking-eligible findings: %d", blocking)
	}
	// Not isolated: flag-only, whatever the manifest says.
	f.svc.o.Isolation = nil
	rep, _ = f.svc.Run(context.Background(), rec.ID, f.proj, policy.FindingScopeManual)
	if len(rep.Org.Blocking) != 0 || !rep.Org.NotIsolated {
		t.Fatalf("not isolated: %+v", rep.Org)
	}
}

// plant writes rec straight into the drivers directory with a recomputed,
// self-consistent manifest digest, as something other than an accept would.
func plant(t *testing.T, f fixture, rec seccustom.Record) seccustom.Record {
	t.Helper()
	rec.ManifestSHA256 = rec.Manifest.Digest()
	if err := f.svc.Layout().save(rec); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Layout().Load(rec.ID); err != nil {
		t.Fatalf("the planted record is not self-consistent: %v", err)
	}
	return rec
}

func trustFindings(f fixture) int {
	f.store.mu.Lock()
	defer f.store.mu.Unlock()
	n := 0
	for _, fd := range f.store.findings {
		if fd.Rule.ID == TrustRuleID {
			n++
		}
	}
	return n
}

// TestPlantedRecordNeverRunsUnnoticed: a record written straight into the
// drivers directory with a recomputed digest is refused by Run, SelfTest
// and the list, raises the custom-scanner-changed finding exactly once per
// digest, and its OrgApproved claim is never trusted.
func TestPlantedRecordNeverRunsUnnoticed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	// A brand-new record with no audit line at all.
	m, err := seccustom.Parse(fakeManifest(f.exe, "findings", false), seccustom.Options{GOOS: goos()})
	if err != nil {
		t.Fatal(err)
	}
	sum, _ := hashFile(f.exe)
	m.ExecutableSHA256 = sum
	planted := plant(t, f, seccustom.Record{ID: "planted", Manifest: m, AcceptedVia: "dashboard"})
	for i := 0; i < 2; i++ {
		if _, err := f.svc.Run(ctx, planted.ID, f.proj, policy.FindingScopeManual); !errors.Is(err, ErrUnaudited) {
			t.Fatalf("a planted record ran: %v", err)
		}
	}
	if _, err := f.svc.SelfTest(ctx, planted.ID); !errors.Is(err, ErrUnaudited) {
		t.Fatalf("self-test of a planted record: %v", err)
	}
	recs, bad := f.svc.Records(ctx)
	if len(recs) != 0 || !strings.Contains(bad[planted.ID], "driver_unaudited") {
		t.Fatalf("list: %+v %+v", recs, bad)
	}
	if n := trustFindings(f); n != 1 {
		t.Fatalf("trust findings after repeated loads: %d, want 1 (idempotent by digest)", n)
	}
	if len(f.store.runs) != 0 {
		t.Fatalf("a planted record left a scan run: %+v", f.store.runs)
	}

	// An accepted record changed in place (argv rewritten, digest
	// recomputed): the audit line names the old digest, so it is refused
	// and raises a second finding (a new digest).
	rec := f.accept(t, "findings", false)
	before := trustFindings(f)
	rec.Manifest.Argv = []string{"hostile", "{output_file}"}
	plant(t, f, rec)
	if _, err := f.svc.Run(ctx, rec.ID, f.proj, policy.FindingScopeManual); !errors.Is(err, ErrUnaudited) {
		t.Fatalf("a changed record ran: %v", err)
	}
	if n := trustFindings(f); n != before+1 {
		t.Fatalf("trust findings: %d, want %d", n, before+1)
	}

	// A planted OrgApproved with blocking rules is never trusted: even with
	// a matching audit line, an individual node refuses it.
	rec.Manifest.Argv = []string{"findings", "{output_file}"}
	rec.Manifest.BlockingRules = []string{"F1"}
	rec.OrgApproved = true
	rec = plant(t, f, rec)
	if err := f.svc.Layout().appendAudit(AuditEntry{Action: AuditChanged, ID: rec.ID, ManifestSHA256: rec.ManifestSHA256, ExecutableSHA256: rec.Manifest.ExecutableSHA256}); err != nil {
		t.Fatal(err)
	}
	if got, err := f.svc.Layout().Load(rec.ID); err != nil || got.OrgApproved {
		t.Fatalf("OrgApproved read from the file: %+v %v", got.OrgApproved, err)
	}
	if _, err := f.svc.Run(ctx, rec.ID, f.proj, policy.FindingScopeManual); err == nil || !strings.Contains(err.Error(), "pre-approved catalog") {
		t.Fatalf("a planted org approval ran: %v", err)
	}

	// The executable check is re-run on load: a file made group-writable
	// after the accept is refused before the runner sees it.
	ok := f.accept(t, "findings", false)
	if err := os.Chmod(f.exe, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Run(ctx, ok.ID, f.proj, policy.FindingScopeManual); err == nil || errors.Is(err, ErrUnaudited) {
		t.Fatalf("a group-writable executable ran: %v", err)
	}
	_ = os.Chmod(f.exe, 0o755)
	if _, err := f.svc.Run(ctx, ok.ID, f.proj, policy.FindingScopeManual); err != nil {
		t.Fatalf("an accepted record no longer runs: %v", err)
	}

	// A removed record planted back is refused (the newest line is the
	// removal).
	if err := f.svc.Remove(ctx, ok.ID, "cli"); err != nil {
		t.Fatal(err)
	}
	plant(t, f, ok)
	if _, err := f.svc.Run(ctx, ok.ID, f.proj, policy.FindingScopeManual); !errors.Is(err, ErrUnaudited) {
		t.Fatalf("a removed record planted back ran: %v", err)
	}
}

// TestShebangInterpreterIsAPinnedCompanion: a "#!" script imports only with
// its interpreter declared as a companion (pinned and checked), and a
// template whose launcher names an interpreter that fails its check is
// refused with the reason, never imported without it.
func TestShebangInterpreterIsAPinnedCompanion(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	// A file manifest with no companion for its "#!/bin/sh".
	var m map[string]any
	_ = json.Unmarshal(fakeManifest(f.exe, "findings", false), &m)
	delete(m, "companions")
	bare, _ := json.Marshal(m)
	if _, err := f.svc.Prepare(ctx, Source{File: bare}, seccustom.Choices{}); err == nil || !strings.Contains(err.Error(), "declared, digest-pinned companions") {
		t.Fatalf("a script with an unpinned interpreter imported: %v", err)
	}
	// With it declared, the import goes through and the pin is partial.
	p, err := f.svc.Prepare(ctx, Source{File: fakeManifest(f.exe, "findings", false)}, seccustom.Choices{})
	if err != nil || p.Pin != seccustom.PinPartial || len(p.Manifest.Companions) != 1 || p.Manifest.Companions[0].SHA256 == "" {
		t.Fatalf("pinned interpreter: %+v %v", p, err)
	}

	// A template launcher whose interpreter sits in a group-writable
	// directory: the interpreter check fails, so the import is refused.
	loose := filepath.Join(f.dir, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	sh, err := os.ReadFile(realPath("/bin/sh"))
	if err != nil {
		t.Skip("cannot copy /bin/sh")
	}
	interp := filepath.Join(loose, "py")
	if err := os.WriteFile(interp, sh, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(loose, 0o775)
	launcher := filepath.Join(f.dir, "bin", "bandit")
	if err := os.WriteFile(launcher, []byte("#!"+interp+"\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.svc.o.Resolve = func(spec integration.BinaryResolveSpec) toolresolve.Resolution {
		if len(spec.Names.Unix) > 0 && spec.Names.Unix[0] == "bandit" {
			return toolresolve.Resolution{Verdict: toolresolve.VerdictOKOffPath, Bin: launcher}
		}
		return absResolver(spec)
	}
	if _, err := f.svc.Prepare(ctx, Source{Template: "bandit"}, seccustom.Choices{}); err == nil || !strings.Contains(err.Error(), "interpreter is refused") || !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("a template with a failed interpreter check imported: %v", err)
	}
	// Fixed, the same template imports with the interpreter as its
	// companion.
	_ = os.Chmod(loose, 0o755)
	p, err = f.svc.Prepare(ctx, Source{Template: "bandit"}, seccustom.Choices{})
	if err != nil || len(p.Manifest.Companions) != 1 || p.Manifest.Companions[0].Path != interp {
		t.Fatalf("template with a checked interpreter: %+v %v", p.Manifest.Companions, err)
	}
}

// TestHostsManifestRunSaysNotEnforced: a run of a manifest with declared
// hosts says on its report and its scan-run record that the hosts are not
// enforced.
func TestHostsManifestRunSaysNotEnforced(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	var m map[string]any
	_ = json.Unmarshal(fakeManifest(f.exe, "findings", false), &m)
	m["network"] = map[string]any{"mode": "hosts", "hosts": []string{"example.com"}}
	b, _ := json.Marshal(m)
	src := Source{File: b}
	p, err := f.svc.Prepare(ctx, src, seccustom.Choices{})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := f.svc.Accept(ctx, src, seccustom.Choices{}, p.ManifestSHA256, "cli")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := f.svc.Run(ctx, rec.ID, f.proj, policy.FindingScopeManual)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rep.Network, "example.com") || !strings.Contains(rep.Network, "not enforced") || !strings.Contains(rep.NotIsolatedWhy, "not enforced") {
		t.Fatalf("report %q / %q", rep.Network, rep.NotIsolatedWhy)
	}
	eng, _ := json.Marshal(f.store.runs[len(f.store.runs)-1].Engine)
	if !strings.Contains(string(eng), "not enforced") {
		t.Fatalf("the run record does not say the hosts are not enforced: %s", eng)
	}
}

// TestGoBuildVersionReadsAGoProgram: the boundary read behind the skew
// check names this test binary's Go release and nothing for a script.
func TestGoBuildVersionReadsAGoProgram(t *testing.T) {
	t.Parallel()
	self, err := os.Executable()
	if err != nil {
		t.Skip("no executable path")
	}
	if v := goBuildVersion(self); !strings.HasPrefix(v, "go1.") {
		t.Fatalf("this test binary: %q", v)
	}
	f := newFixture(t)
	if v := goBuildVersion(f.exe); v != "" {
		t.Fatalf("a shell script: %q", v)
	}
}

// TestRunScheduled: off by default, held on battery and while the power
// state is unknown, runs each due pair once per interval with scope
// scheduled, and skips a planted record.
func TestRunScheduled(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	rec := f.accept(t, "findings", false)
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	f.svc.o.Now = func() time.Time { return now }
	in := ScheduleInput{PauseOnBattery: true, Power: "ac", Projects: []string{f.proj}}

	if rep := f.svc.RunScheduled(ctx, in); rep.Ran != 0 || rep.Held[seccustom.ScheduleOff] != 1 {
		t.Fatalf("off: %+v", rep)
	}
	in.Every = 24 * time.Hour
	for power, reason := range map[string]string{"battery": seccustom.SchedulePausedOnBatt, "unknown": seccustom.SchedulePowerUnknown} {
		in.Power = power
		if rep := f.svc.RunScheduled(ctx, in); rep.Ran != 0 || rep.Held[reason] != 1 {
			t.Fatalf("%s: %+v", power, rep)
		}
	}
	if len(f.store.runs) != 0 {
		t.Fatalf("a held pass ran: %+v", f.store.runs)
	}
	in.Power = "ac"
	if rep := f.svc.RunScheduled(ctx, in); rep.Ran != 1 {
		t.Fatalf("due: %+v", rep)
	}
	if len(f.store.runs) != 1 || f.store.runs[0].Scope != policy.FindingScopeScheduled || f.store.runs[0].Driver != rec.Driver() {
		t.Fatalf("runs %+v", f.store.runs)
	}
	if rep := f.svc.RunScheduled(ctx, in); rep.Ran != 0 || rep.Held[seccustom.ScheduleNotDue] != 1 {
		t.Fatalf("not due: %+v", rep)
	}
	now = now.Add(25 * time.Hour)
	if rep := f.svc.RunScheduled(ctx, in); rep.Ran != 1 {
		t.Fatalf("due again: %+v", rep)
	}
	// A planted record never runs on the schedule either.
	m, _ := seccustom.Parse(fakeManifest(f.exe, "findings", false), seccustom.Options{GOOS: goos()})
	sum, _ := hashFile(f.exe)
	m.ExecutableSHA256 = sum
	plant(t, f, seccustom.Record{ID: "planted", Manifest: m})
	now = now.Add(25 * time.Hour)
	if rep := f.svc.RunScheduled(ctx, in); rep.Ran != 1 {
		t.Fatalf("with a planted record: %+v", rep)
	}
	for _, r := range f.store.runs {
		if r.Driver == "custom:planted" {
			t.Fatal("a planted record ran on the schedule")
		}
	}
}

// TestRunScheduledKeepsLastRunAcrossRestart: a new service over the same
// store (a daemon restart) reads each pair's last scheduled run from the
// recorded scan runs, so a pair that ran an hour ago is not due again, and
// one whose last run is older than the interval is. A manual run does not
// count as a scheduled one.
func TestRunScheduledKeepsLastRunAcrossRestart(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	f.accept(t, "findings", false)
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	f.svc.o.Now = clock
	in := ScheduleInput{Every: 24 * time.Hour, PauseOnBattery: true, Power: "ac", Projects: []string{f.proj}}
	if rep := f.svc.RunScheduled(ctx, in); rep.Ran != 1 {
		t.Fatalf("first pass: %+v", rep)
	}
	restart := func() *Service {
		o := f.svc.o
		o.Now = clock
		return New(o)
	}
	now = now.Add(time.Hour)
	if rep := restart().RunScheduled(ctx, in); rep.Ran != 0 || rep.Held[seccustom.ScheduleNotDue] != 1 {
		t.Fatalf("after a restart an hour later: %+v", rep)
	}
	now = now.Add(24 * time.Hour)
	if rep := restart().RunScheduled(ctx, in); rep.Ran != 1 {
		t.Fatalf("after a restart a day later: %+v", rep)
	}
	// Only scheduled runs count: a manual run of a fresh pair leaves it due.
	g := newFixture(t)
	rec := g.accept(t, "findings", false)
	g.svc.o.Now = clock
	if _, err := g.svc.Run(ctx, rec.ID, g.proj, policy.FindingScopeManual); err != nil {
		t.Fatal(err)
	}
	o := g.svc.o
	if rep := New(o).RunScheduled(ctx, in2(in, g.proj)); rep.Ran != 1 {
		t.Fatalf("a manual run counted as the scheduled one: %+v", rep)
	}
}

// TestRunScheduledRecordsAFailureBeforeRecording: a scheduled run that
// fails before Run records a scan run (here the runner is not wired) still
// records a failed scheduled scan run with its error, so after a daemon
// restart the pair is not due again until its interval passes (PT-32).
func TestRunScheduledRecordsAFailureBeforeRecording(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	rec := f.accept(t, "findings", false)
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	f.svc.o.Now = clock
	f.svc.o.NewRunner = nil
	in := ScheduleInput{Every: 24 * time.Hour, PauseOnBattery: true, Power: "ac", Projects: []string{f.proj}}
	if rep := f.svc.RunScheduled(ctx, in); rep.Failed != 1 || rep.Ran != 0 {
		t.Fatalf("first pass: %+v", rep)
	}
	var failed []store.SecScanRun
	for _, r := range f.store.runs {
		if r.Driver == rec.Driver() && r.Scope == policy.FindingScopeScheduled {
			failed = append(failed, r)
		}
	}
	if len(failed) != 1 || failed[0].Outcome != string(secscan.OutcomeFailed) || !failed[0].StartedAt.Equal(now) {
		t.Fatalf("the failed scheduled run: %+v", f.store.runs)
	}
	cov, ok := failed[0].Coverage.(scheduledFailure)
	if !ok || cov.Reason != "not_run" || !strings.Contains(cov.Error, "runner is not wired") {
		t.Fatalf("its coverage: %#v", failed[0].Coverage)
	}
	// A restart an hour later reads the failed run as the pair's last one.
	o := f.svc.o
	o.Now = clock
	now = now.Add(time.Hour)
	if rep := New(o).RunScheduled(ctx, in); rep.Failed != 0 || rep.Held[seccustom.ScheduleNotDue] != 1 {
		t.Fatalf("after a restart an hour later: %+v", rep)
	}
	// A manual run that fails records nothing extra (only the schedule does).
	n := len(f.store.runs)
	if _, err := f.svc.Run(ctx, rec.ID, f.proj, policy.FindingScopeManual); err == nil {
		t.Fatal("a manual run with no runner succeeded")
	}
	if len(f.store.runs) != n {
		t.Fatalf("a failed manual run recorded a scan run: %+v", f.store.runs[n:])
	}
}

// in2 is in with its projects replaced by proj.
func in2(in ScheduleInput, proj string) ScheduleInput {
	in.Projects = []string{proj}
	return in
}

// TestRequiredMissingIgnoresPlantedRecords: a require-mode org policy names
// a manifest; a record planted with exactly those digests (no audit line)
// does not mark the requirement met, because RequiredMissing reads only
// the checked records. The same record imported through the audited path
// does.
func TestRequiredMissingIgnoresPlantedRecords(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	m, err := seccustom.Parse(fakeManifest(f.exe, "findings", false), seccustom.Options{GOOS: goos()})
	if err != nil {
		t.Fatal(err)
	}
	sum, _ := hashFile(f.exe)
	m.ExecutableSHA256 = sum
	planted := plant(t, f, seccustom.Record{ID: "required", Manifest: m, AcceptedVia: "dashboard"})
	pol := seccustom.OrgPolicy{Mode: seccustom.OrgModeRequire, Entries: []seccustom.OrgEntry{{
		ManifestSHA256: planted.ManifestSHA256, ExecutableSHA256: planted.Manifest.ExecutableSHA256,
	}}}
	f.svc.o.Org = func(context.Context) (seccustom.OrgPolicy, bool) { return pol, true }

	if got := f.svc.RequiredMissing(ctx); len(got) != 1 || got[0] != planted.ManifestSHA256 {
		t.Fatalf("a planted record met the org requirement: missing = %v", got)
	}
	// The audited path (the line an accept writes) makes it count.
	if err := f.svc.Layout().appendAudit(AuditEntry{Action: AuditChanged, ID: planted.ID, ManifestSHA256: planted.ManifestSHA256, ExecutableSHA256: planted.Manifest.ExecutableSHA256}); err != nil {
		t.Fatal(err)
	}
	if got := f.svc.RequiredMissing(ctx); len(got) != 0 {
		t.Fatalf("an audited record still reads missing: %v", got)
	}
	// RequiredMissingAmong over the records Records returned gives the same
	// answer (the dashboard GET checks each record once).
	recs, _ := f.svc.Records(ctx)
	if got := f.svc.RequiredMissingAmong(ctx, recs); len(got) != 0 {
		t.Fatalf("RequiredMissingAmong over the checked records: %v", got)
	}
	if got := f.svc.RequiredMissingAmong(ctx, nil); len(got) != 1 {
		t.Fatalf("RequiredMissingAmong over no records: %v", got)
	}
}
