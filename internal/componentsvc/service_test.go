package componentsvc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

type fakeTeardown struct {
	calls []string
}

func (f *fakeTeardown) RemoveToolWiring(tool string, parts []string, dryRun bool) []StepOutcome {
	f.calls = append(f.calls, "wiring:"+tool+":"+strings.Join(parts, ","))
	return []StepOutcome{{Target: tool, Changed: !dryRun}}
}

func (f *fakeTeardown) RemoveBrowserHost(dryRun bool) StepOutcome {
	f.calls = append(f.calls, "browser")
	return StepOutcome{Target: "browser", Changed: !dryRun}
}

// auditRec records audit rows. The mutex matters for the lock tests: a purge
// and an Apply in two goroutines are ordered only by the production
// cross-process FILE lock, which the race detector cannot see, while the real
// Audit sink is a concurrency-safe store write.
type auditRec struct {
	mu   sync.Mutex
	rows []string
}

func (a *auditRec) audit(_ context.Context, action, detail string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rows = append(a.rows, action+" "+detail)
}

const seedConfig = `# operator comment that must survive
[observer]
log_level = "info" # inline comment
`

func newSvc(t *testing.T, body string) (*Service, string, *fakeTeardown, *auditRec) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if body != "" {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	td, au := &fakeTeardown{}, &auditRec{}
	full := []string{}
	for _, c := range components.ForBinary(components.BinaryNode) {
		full = append(full, c.ID)
	}
	s, err := New(Options{
		ConfigPath: path, Compiled: full, Teardown: td, Audit: au.audit,
		Load: func() (config.Config, error) {
			return config.Load(config.LoadOptions{GlobalPath: path, Env: func(string) string { return "" }, GovernanceSidecar: config.NoGovernanceSidecar})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, path, td, au
}

func TestPreviewRemoveCascadesAndPlansTeardownRouteFirst(t *testing.T) {
	s, _, _, _ := newSvc(t, seedConfig)
	p, err := s.Preview(context.Background(), Change{Remove: []string{"terminals", "adapter.claude-code", "integration.hooks", "capture.browser"}})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(p.Cascade, "benchmark") {
		t.Fatalf("benchmark requires terminals and must be removed with it: %v", p.Cascade)
	}
	for _, id := range []string{"terminals", "benchmark", "adapter.claude-code", "integration.hooks", "capture.browser"} {
		if !contains(p.Deactivated, id) {
			t.Errorf("%s not deactivated: %v", id, p.Deactivated)
		}
	}
	if len(p.Teardown) == 0 || p.Teardown[0].Parts[0] != PartRoute {
		t.Fatalf("route removal must run first: %+v", p.Teardown)
	}
	if !p.RestartRequired || p.NoChange || p.Fingerprint == "" {
		t.Fatalf("preview flags: %+v", p)
	}
	// The proposed block names the explicit removals plus every cascaded
	// dependant (benchmark, terminals.*, the browser-chat adapters), so the
	// written selection says exactly what is off.
	if p.Proposed.Distro != "" {
		t.Fatalf("proposed block: %+v", p.Proposed)
	}
	for _, id := range append([]string{"terminals", "adapter.claude-code", "integration.hooks", "capture.browser"}, p.Cascade...) {
		if !contains(p.Proposed.Remove, id) {
			t.Errorf("proposed block lacks %s: %+v", id, p.Proposed.Remove)
		}
	}
}

func TestPreviewRefusals(t *testing.T) {
	s, _, _, _ := newSvc(t, seedConfig)
	bad := "tiny"
	p, err := s.Preview(context.Background(), Change{SetBase: &bad, Remove: []string{"core", "nope"}, Add: []string{"org.saml"}})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(p.Refused, "\n")
	for _, want := range []string{"core cannot be removed", "nope: not a component", "org.saml: an org server component", `base "tiny"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("refused lacks %q: %s", want, joined)
		}
	}
	if !p.NoChange {
		t.Fatal("an all-refused change must be a no-op")
	}
	if _, err := s.Apply(context.Background(), Change{Remove: []string{"core"}}, ApplyOptions{}); err == nil {
		t.Fatal("applying an all-refused change must error")
	}
}

func TestApplyWritesBlockKeepsCommentsRunsTeardownAndAudits(t *testing.T) {
	s, path, td, au := newSvc(t, seedConfig)
	ctx := context.Background()
	p, _ := s.Preview(ctx, Change{Remove: []string{"adapter.codex", "capture.browser"}})
	res, err := s.Apply(ctx, Change{Remove: []string{"adapter.codex", "capture.browser"}}, ApplyOptions{ExpectFingerprint: p.Fingerprint, Principal: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Wrote {
		t.Fatal("block not written")
	}
	body, _ := os.ReadFile(path)
	text := string(body)
	for _, want := range []string{"# operator comment that must survive", "# inline comment", "[components]", `"adapter.codex"`, `"capture.browser"`} {
		if !strings.Contains(text, want) {
			t.Errorf("config lacks %q:\n%s", want, text)
		}
	}
	// codex gets its wiring parts (route first); the capture-only
	// browser-chat adapters that cascade off capture.browser wrote nothing
	// into a tool config, so only the native-host step follows.
	if len(td.calls) != 2 || !strings.HasPrefix(td.calls[0], "wiring:codex:route,") || td.calls[1] != "browser" {
		t.Fatalf("teardown calls: %v", td.calls)
	}
	if len(au.rows) != 1 || !strings.Contains(au.rows[0], "adapter.codex") || !strings.Contains(au.rows[0], "capture.browser") {
		t.Fatalf("audit: %v", au.rows)
	}
	snap, _ := s.State(ctx)
	if snap.Active("adapter.codex") || !snap.Active("adapter.zed") {
		t.Fatal("state after apply wrong")
	}
	// Stale preview refused, nothing written.
	if _, err := s.Apply(ctx, Change{Add: []string{"adapter.codex"}}, ApplyOptions{ExpectFingerprint: p.Fingerprint}); !errors.Is(err, ErrStalePreview) {
		t.Fatalf("stale: %v", err)
	}
	// Add back clears the removal; an empty block deletes the keys.
	if _, err := s.Apply(ctx, Change{Reset: true}, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	snap, _ = s.State(ctx)
	if snap.Configured {
		t.Fatalf("reset left the block configured: %+v", snap.Section())
	}
	body, _ = os.ReadFile(path)
	if !strings.Contains(string(body), "# operator comment that must survive") {
		t.Fatal("reset lost the operator comment")
	}
}

func TestApplyDryRunAndSkipTeardown(t *testing.T) {
	s, path, td, au := newSvc(t, seedConfig)
	ctx := context.Background()
	res, err := s.Apply(ctx, Change{Remove: []string{"adapter.zed"}}, ApplyOptions{DryRun: true})
	if err != nil || res.Wrote {
		t.Fatalf("dry run wrote: %+v %v", res, err)
	}
	body, _ := os.ReadFile(path)
	if string(body) != seedConfig {
		t.Fatal("dry run changed the file")
	}
	if len(au.rows) != 0 {
		t.Fatal("dry run audited")
	}
	td.calls = nil
	res, err = s.Apply(ctx, Change{Remove: []string{"adapter.codex"}}, ApplyOptions{SkipTeardown: true})
	if err != nil || !res.TeardownSkipped || len(td.calls) != 0 {
		t.Fatalf("skip teardown: %+v %v %v", res, err, td.calls)
	}
}

func TestSetBaseDistro(t *testing.T) {
	s, _, _, _ := newSvc(t, "")
	minimal := "minimal"
	p, err := s.Preview(context.Background(), Change{SetBase: &minimal})
	if err != nil {
		t.Fatal(err)
	}
	if p.Proposed.Distro != "minimal" || !contains(p.Deactivated, "codeintel") || contains(p.Deactivated, "guard") {
		t.Fatalf("minimal base: %+v", p)
	}
}

func TestTeardownTableCoversEveryNodeComponentThatWritesOutsideObserver(t *testing.T) {
	for _, c := range components.ForBinary(components.BinaryNode) {
		if len(c.Surface.VendorConfigs) == 0 {
			continue
		}
		if len(TeardownFor(c.ID)) == 0 {
			t.Errorf("%s edits other tools' config (%v) but has no teardown row", c.ID, c.Surface.VendorConfigs)
		}
	}
}

func TestPurgeThroughService(t *testing.T) {
	ctx := context.Background()
	s, _, _, au := newSvc(t, seedConfig)
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	s.opts.Purge = store.New(database)
	for _, q := range []string{
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/p', '2026-10-07T00:00:00Z')`,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('z', 1, 'zed', '2026-10-07T00:00:00Z')`,
		`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target, source_file, source_event_id) VALUES ('z', 1, '2026-10-07T00:00:01Z', 'read_file', 'zed', 1, 't', 'f', 'e1')`,
	} {
		if _, err := database.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.PurgePreview(ctx, "adapter.zed"); err == nil || !strings.Contains(err.Error(), "is active") {
		t.Fatalf("active component purge: %v", err)
	}
	if _, err := s.PurgePreview(ctx, "codeintel"); err == nil {
		t.Fatal("a component without a reviewed plan must be refused")
	}
	if _, err := s.Apply(ctx, Change{Remove: []string{"adapter.zed"}}, ApplyOptions{SkipTeardown: true}); err != nil {
		t.Fatal(err)
	}
	plan, err := s.PurgePreview(ctx, "adapter.zed")
	if err != nil {
		t.Fatal(err)
	}
	// Re-activated between preview and confirmation: refused.
	if _, err := s.Apply(ctx, Change{Add: []string{"adapter.zed"}}, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PurgeExecute(ctx, plan.ID); !errors.Is(err, store.ErrPurgePlanNotExecutable) {
		t.Fatalf("reactivated: %v", err)
	}
	if _, err := s.Apply(ctx, Change{Remove: []string{"adapter.zed"}}, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	res, err := s.PurgeExecute(ctx, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Deleted["actions"] != 1 || res.Deleted["sessions"] != 1 {
		t.Fatalf("purge result: %+v", res)
	}
	if last := au.rows[len(au.rows)-1]; !strings.HasPrefix(last, "components.purge") {
		t.Fatalf("purge not audited: %v", au.rows)
	}
}

// TestManagedNodeRefusesNarrowing is ledger MODPKG-7 / ruling D-434
// (T-677): on an org-managed node select, remove and reset are refused with
// a reason naming the organization and nothing is written; an add the
// policy blocks is refused too; an individual node is unchanged.
func TestManagedNodeRefusesNarrowing(t *testing.T) {
	ctx := context.Background()
	s, path, td, au := newSvc(t, seedConfig)
	// A legacy managed node: the org's set is every compiled component but
	// codeintel (the shape nodecomponents.Govern produces).
	var req []string
	for _, c := range components.ForBinary(components.BinaryNode) {
		if c.Class != components.ClassCore && c.ID != "codeintel" {
			req = append(req, c.ID)
		}
	}
	s.opts.Governed = func(context.Context) componentstate.Governed {
		return componentstate.Governed{
			OrgManaged: true, OrgName: "Acme", Source: "legacy_pinned",
			Governance: &components.Governance{Policy: &components.PolicySets{Source: "legacy_pinned", Require: req}},
		}
	}
	before, _ := os.ReadFile(path)
	minimal := "minimal"
	for _, ch := range []Change{
		{Remove: []string{"org.client"}},
		{SetBase: &minimal},
		{Reset: true},
		{Add: []string{"codeintel"}},
	} {
		p, err := s.Preview(ctx, ch)
		if err != nil {
			t.Fatal(err)
		}
		if p.ManagedBy != "Acme" || len(p.ManagedRefused) == 0 {
			t.Fatalf("%+v: preview not refused: managed_by %q refused %v", ch, p.ManagedBy, p.ManagedRefused)
		}
		if len(p.Deactivated) != 0 {
			t.Fatalf("%+v: preview deactivates %v on a managed node", ch, p.Deactivated)
		}
		_, err = s.Apply(ctx, ch, ApplyOptions{Principal: "cli"})
		if !errors.Is(err, ErrManagedByOrg) || !strings.Contains(err.Error(), "Acme") {
			t.Fatalf("%+v: apply = %v, want ErrManagedByOrg naming Acme", ch, err)
		}
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatalf("a refused change wrote the config:\n%s", after)
	}
	if len(td.calls) != 0 || len(au.rows) != 0 {
		t.Fatalf("a refused change ran teardown %v or audited %v", td.calls, au.rows)
	}
	snap, err := s.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Active("org.client") || !snap.View().OrgManaged {
		t.Fatalf("managed state lost: org.client active %v", snap.Active("org.client"))
	}

	// The same change on an individual node still applies.
	s.opts.Governed = nil
	if _, err := s.Apply(ctx, Change{Remove: []string{"remote"}}, ApplyOptions{Principal: "cli"}); err != nil {
		t.Fatalf("individual node: %v", err)
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// TestRemovingAModuleRootDeactivatesEveryDependent pins the contract the
// first-run chooser relies on instead of a `withDependents` helper (lane
// OPTMOD, sandbox plan v2 section 11.2): a "no" removes only the module
// root, and the removal cascades to every active component whose requires
// closure reaches it (an optional module's drivers use Requires, never
// Bundles), so one "no" leaves the module and every driver inactive. The
// test walks the whole catalog, so a future module root (security,
// terminals.sandbox with its drivers) is covered by the same row.
func TestRemovingAModuleRootDeactivatesEveryDependent(t *testing.T) {
	s, _, _, _ := newSvc(t, seedConfig)
	ctx := context.Background()
	before, err := s.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	active := map[string]bool{}
	for _, id := range before.ActiveIDs() {
		active[id] = true
	}
	roots := 0
	for _, c := range components.ForBinary(components.BinaryNode) {
		if c.Class == components.ClassCore || !active[c.ID] {
			continue
		}
		var deps []string
		for _, d := range components.ForBinary(components.BinaryNode) {
			if d.Class != components.ClassCore && active[d.ID] && contains(requiresClosure(d.ID), c.ID) {
				deps = append(deps, d.ID)
			}
		}
		if len(deps) == 0 {
			continue
		}
		roots++
		p, err := s.Preview(ctx, Change{Remove: []string{c.ID}})
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range deps {
			if !contains(p.Deactivated, d) {
				t.Errorf("removing %s leaves its dependant %s active: deactivated %v", c.ID, d, p.Deactivated)
			}
		}
	}
	if roots == 0 {
		t.Fatal("no active component with dependants; the walk is stale")
	}
}
