package componentstate

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// unstamped pins the build to the unstamped release (base: everything
// compiled), so these cases read the same in a distro or custom build.
func unstamped(t *testing.T) {
	t.Helper()
	prevD, prevC := buildDistro, buildCustomDefaults
	t.Cleanup(func() { buildDistro, buildCustomDefaults = prevD, prevC })
	buildDistro = func() components.Distro { return "" }
	buildCustomDefaults = func() ([]string, bool) { return nil, false }
}

// TestModuleActiveFailsInvisible is the shared optional-module contract:
// ModuleActive agrees with Active on every catalog id and answers false
// where Active answers true for lack of a decision.
func TestModuleActiveFailsInvisible(t *testing.T) {
	unstamped(t)
	all := Resolve(config.ComponentsConfig{}, fullCompiled())
	// Removing a module removes only the named id (P-057): its selected
	// driver children (every terminals.sandbox.* row) are removed with it
	// here.
	off := Resolve(config.ComponentsConfig{Remove: sandboxModuleAndDrivers()}, fullCompiled())
	var withoutSandbox []string
	for _, id := range fullCompiled() {
		if id != "terminals.sandbox" {
			withoutSandbox = append(withoutSandbox, id)
		}
	}
	absent := Resolve(config.ComponentsConfig{}, withoutSandbox)

	cases := []struct {
		name       string
		snap       Snapshot
		id         string
		active     bool // Snapshot.Active
		moduleWant bool // Snapshot.ModuleActive
	}{
		{"known and active", all, "terminals.sandbox", true, true},
		{"known and removed", off, "terminals.sandbox", false, false},
		{"compiled out", absent, "terminals.sandbox", false, false},
		{"unknown id", all, "no.such.module", true, false},
		{"misspelt id", all, "terminals.sandbx", true, false},
		{"org server id", all, "org.core", true, false},
		{"zero snapshot", Snapshot{}, "terminals.sandbox", true, false},
		{"core", all, "core", true, true},
	}
	for _, tc := range cases {
		if got := tc.snap.Active(tc.id); got != tc.active {
			t.Errorf("%s: Active(%q) = %v, want %v", tc.name, tc.id, got, tc.active)
		}
		if got := tc.snap.ModuleActive(tc.id); got != tc.moduleWant {
			t.Errorf("%s: ModuleActive(%q) = %v, want %v", tc.name, tc.id, got, tc.moduleWant)
		}
	}
	// On every catalog node id of a resolved snapshot the two agree.
	for _, c := range components.ForBinary(components.BinaryNode) {
		if all.Active(c.ID) != all.ModuleActive(c.ID) || off.Active(c.ID) != off.ModuleActive(c.ID) {
			t.Errorf("%s: Active and ModuleActive disagree on a catalog id", c.ID)
		}
	}
}

func TestAnyModuleActive(t *testing.T) {
	unstamped(t)
	all := Resolve(config.ComponentsConfig{}, fullCompiled())
	if all.AnyModuleActive() {
		t.Error("no ids must answer false (a module surface always names its owner)")
	}
	if all.AnyModuleActive("no.such.module", "also.missing") {
		t.Error("only unknown ids must answer false")
	}
	if !all.AnyModuleActive("no.such.module", "terminals.sandbox") {
		t.Error("one active id must answer true")
	}
}

func TestUnknownNodeIDs(t *testing.T) {
	got := UnknownNodeIDs("terminals.sandbox", "core", "org.core", "nope", "nope", " terminals ")
	if strings.Join(got, ",") != "nope,org.core" {
		t.Fatalf("UnknownNodeIDs = %v", got)
	}
	if UnknownNodeIDs("terminals", "terminals.sandbox") != nil {
		t.Fatal("known node ids must yield nil")
	}
}

// TestModuleGateIsRegistered: linking this package makes config.Load
// component-aware for the sections optional components own.
func TestModuleGateIsRegistered(t *testing.T) {
	prev := config.SetComponentGate(nil)
	t.Cleanup(func() { config.SetComponentGate(prev) })
	if prev == nil {
		t.Fatal("componentstate must register config's component gate when linked")
	}
	if prev(config.ComponentsConfig{}, "no.such.module") {
		t.Error("the registered gate must fail invisible on an unknown id")
	}
}

// TestLoadSetsAsideInactiveSandboxSection is item 3 end to end through the
// real Load and the registered gate: a bad [terminal.sandbox] fails Load while
// terminals.sandbox is active and is set aside, with one line, while it is
// not.
func TestLoadSetsAsideInactiveSandboxSection(t *testing.T) {
	unstamped(t)
	const bad = "[terminal.sandbox]\nbackend = \"no-such-backend\"\nenabled = true\n"
	load := func(body string) (config.Config, error) {
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return config.Load(config.LoadOptions{GlobalPath: path, Env: func(string) string { return "" }, GovernanceSidecar: config.NoGovernanceSidecar})
	}

	cfg, err := load("[components]\nremove = " + sandboxRemoveTOML() + "\n" + bad)
	if err != nil {
		t.Fatalf("an inactive component's bad section must not fail Load: %v", err)
	}
	if len(cfg.Inert) != 1 || !strings.Contains(cfg.Inert[0], "[terminal.sandbox]") || !strings.Contains(cfg.Inert[0], "terminals.sandbox") {
		t.Fatalf("Inert = %q", cfg.Inert)
	}
	if !reflect.DeepEqual(cfg.Terminal.Sandbox, config.Default().Terminal.Sandbox) {
		t.Fatalf("the set-aside section must hold its defaults: %+v", cfg.Terminal.Sandbox)
	}
	if err := config.Validate(cfg); err != nil {
		t.Fatalf("the loaded copy must validate: %v", err)
	}

	// Active (the module is selected): today's strict load error. In a build
	// that compiles the module out, the module is never active.
	_, err = load(bad)
	if Resolve(config.ComponentsConfig{}, nil).ModuleActive("terminals.sandbox") {
		if err == nil || !strings.Contains(err.Error(), "terminal.sandbox.backend") {
			t.Fatalf("an active component's bad section must fail Load: %v", err)
		}
	} else if err != nil {
		t.Fatalf("a compiled-out or inactive component's bad section must not fail Load: %v", err)
	}

	// A valid section of an inactive component loads unchanged, with no line.
	cfg, err = load("[components]\nremove = " + sandboxRemoveTOML() + "\n[terminal.sandbox]\nhome_mode = \"readonly\"\n")
	if err != nil || len(cfg.Inert) != 0 || cfg.Terminal.Sandbox.HomeMode != "readonly" {
		t.Fatalf("valid inactive section: err=%v inert=%q home_mode=%q", err, cfg.Inert, cfg.Terminal.Sandbox.HomeMode)
	}
}

// TestComponentSectionsNameOptionalNodeComponents pins config's component
// section table to the catalog: each row names an optional node component
// (an unknown id would leave the section validated, or with ModuleActive set
// it aside forever) whose ConfigKeys cover the section's top-level key.
func TestComponentSectionsNameOptionalNodeComponents(t *testing.T) {
	rows := config.ComponentSections()
	if len(rows) == 0 {
		t.Fatal("no component sections; terminals.sandbox owns [terminal.sandbox]")
	}
	for _, r := range rows {
		if bad := UnknownNodeIDs(r.Component); len(bad) > 0 {
			t.Errorf("[%s] names %q, not a node component", r.Section, r.Component)
			continue
		}
		c, _ := components.Get(r.Component)
		if c.Class == components.ClassCore {
			t.Errorf("[%s] names core component %q; core sections are always validated", r.Section, r.Component)
		}
		top, _, _ := strings.Cut(r.Section, ".")
		covered := false
		for _, k := range c.ConfigKeys {
			if k == top || k == r.Section || strings.HasPrefix(r.Section, k+".") {
				covered = true
			}
		}
		if !covered {
			t.Errorf("[%s]: component %s does not declare it in ConfigKeys %v", r.Section, r.Component, c.ConfigKeys)
		}
	}
}

// TestChildRowsRequireTheirParent is the child-row coverage of the shared
// optional-module contract: a node row whose dotted id extends another node
// row's id (`terminals.sandbox` under `terminals`, a future
// `terminals.sandbox.oci` under `terminals.sandbox`, `security.trust` under
// `security`) reaches that nearest parent row through Requires, and neither
// Bundles the other. That is what makes one "no" on a module root in the
// first-run chooser, or one removal in Settings > Components, take every
// child with it (componentsvc's removal cascade follows Requires; Bundles
// means compiled and chosen together and forces equal distros). A driver
// whose Requires names a sibling (`security.scan.scalibr` requires
// `security.deps`) passes as long as the closure reaches the parent.
func TestChildRowsRequireTheirParent(t *testing.T) {
	closure := func(id string) map[string]bool {
		seen := map[string]bool{}
		var walk func(string)
		walk = func(id string) {
			c, ok := components.Get(id)
			if !ok {
				return
			}
			for _, r := range c.Requires {
				if !seen[r] {
					seen[r] = true
					walk(r)
				}
			}
		}
		walk(id)
		return seen
	}
	contains := func(xs []string, x string) bool {
		for _, v := range xs {
			if v == x {
				return true
			}
		}
		return false
	}
	children := 0
	for _, c := range components.ForBinary(components.BinaryNode) {
		parent := ""
		for i := len(c.ID) - 1; i > 0 && parent == ""; i-- {
			if c.ID[i] != '.' {
				continue
			}
			if p, ok := components.Get(c.ID[:i]); ok && p.Binary == components.BinaryNode {
				parent = p.ID
			}
		}
		if parent == "" {
			continue
		}
		children++
		if !closure(c.ID)[parent] {
			t.Errorf("%s does not require %s (directly or through a sibling); removing %s would leave it active", c.ID, parent, parent)
		}
		p, _ := components.Get(parent)
		if contains(c.Bundles, parent) || contains(p.Bundles, c.ID) {
			t.Errorf("%s and %s are joined by Bundles; a child row uses Requires", c.ID, parent)
		}
	}
	if children == 0 {
		t.Fatal("no child rows found; terminals.sandbox is a child of terminals, so the walk is stale")
	}
}

// TestRemovingAModuleWithChildrenKeepsItAndSaysSo pins the core rule the
// SBX-P3A merge kept (plans decision log P-057): a removal names one
// component, never its dotted children, so `remove = ["security"]` or
// `remove = ["terminals.sandbox"]` leaves the module active while a selected
// child requires it, and the snapshot says which child holds it. A module
// that wants root-removal semantics implements them in its own resolution
// (the sandbox module: cmd/observer sandboxModuleActive).
func TestRemovingAModuleWithChildrenKeepsItAndSaysSo(t *testing.T) {
	unstamped(t)
	for _, root := range []string{"security", "terminals.sandbox"} {
		snap := Resolve(config.ComponentsConfig{Remove: []string{root}}, fullCompiled())
		var child string
		for _, id := range snap.Selected {
			if strings.HasPrefix(id, root+".") {
				child = id
				break
			}
		}
		if child == "" {
			t.Fatalf("no selected child of %s in the full build; the walk is stale", root)
		}
		if !snap.ModuleActive(root) || !snap.ModuleActive(child) {
			t.Fatalf("remove %s: the module or its child %s is not active (the core removal now reaches children): %v", root, child, snap.Issues)
		}
		if !strings.Contains(strings.Join(snap.Issues, ";"), "\""+root+"\" stays active because") {
			t.Fatalf("remove %s: no stays-active issue: %v", root, snap.Issues)
		}
	}
}

// sandboxModuleAndDrivers is the sandbox module root and every driver child
// the catalog names (terminals.sandbox.*), so a removal test does not go
// stale when a driver row is added.
func sandboxModuleAndDrivers() []string {
	out := []string{"terminals.sandbox"}
	for _, c := range components.ForBinary(components.BinaryNode) {
		if strings.HasPrefix(c.ID, "terminals.sandbox.") {
			out = append(out, c.ID)
		}
	}
	return out
}

// sandboxRemoveTOML is sandboxModuleAndDrivers as a TOML string array.
func sandboxRemoveTOML() string {
	ids := sandboxModuleAndDrivers()
	q := make([]string, len(ids))
	for i, id := range ids {
		q[i] = strconv.Quote(id)
	}
	return "[" + strings.Join(q, ", ") + "]"
}
