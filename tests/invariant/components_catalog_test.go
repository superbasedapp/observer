package invariant

import (
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter/defaults"
	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// components_catalog_test.go: the catalog checked against the real tree
// (plan 3.2 "truth is enforced by tests, not by care", lane MP-CAT).

func TestComponentsCatalogValid(t *testing.T) {
	if p := components.Validate(); len(p) != 0 {
		t.Fatalf("internal/components has %d problems:\n%s", len(p), strings.Join(p, "\n"))
	}
}

// TestComponentsAdapterRowsMatchRegistry pins the adapter rows one to one
// to integration.Tools() (plan 3.2 item 5), and their stability to the
// registry lifecycle.
func TestComponentsAdapterRowsMatchRegistry(t *testing.T) {
	want := map[string]bool{}
	for _, tool := range integration.Tools() {
		want[components.AdapterID(tool)] = true
	}
	got := map[string]components.Component{}
	for _, c := range components.All() {
		if c.Class == components.ClassAdapter {
			got[c.ID] = c
		}
	}
	for id := range want {
		if _, ok := got[id]; !ok {
			t.Errorf("registry tool %s has no catalog row", id)
		}
	}
	for id, c := range got {
		if !want[id] {
			t.Errorf("catalog row %s has no registry tool", id)
			continue
		}
		lc, _, _ := integration.LifecycleFor(strings.TrimPrefix(id, "adapter."))
		dep := lc != integration.LifecycleActive
		if dep != (c.Stability == components.StabilityDeprecated) {
			t.Errorf("%s: stability %s disagrees with registry lifecycle %q", id, c.Stability, lc)
		}
	}
}

// TestComponentsAdapterPackagesMatchFanIn pins each adapter row's package to
// the package of the adapter the fan-in actually constructs for that tool.
// It holds in any build: with adapter omit tags the rows the fan-in no
// longer builds must be exactly the ones the binary reports compiled out.
func TestComponentsAdapterPackagesMatchFanIn(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range defaults.Adapters() {
		typ := reflect.TypeOf(a)
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		pkg := relPkg(typ.PkgPath())
		id := components.AdapterID(a.Name())
		c, ok := components.Get(id)
		if !ok {
			t.Errorf("fan-in adapter %s (%s) has no catalog row", a.Name(), pkg)
			continue
		}
		seen[id] = true
		if !contains(c.Packages, pkg) && !contains(c.HostedIn, pkg) {
			t.Errorf("%s: fan-in builds it from %s, catalog says packages %v hosted in %v", id, pkg, c.Packages, c.HostedIn)
		}
	}
	// Consistency within the compiled set (lane MP-ADP): a row the fan-in
	// does not build must be one this binary reports compiled out, and a
	// row it reports compiled out must not be built.
	omitted := map[string]bool{}
	for _, id := range components.Omitted() {
		omitted[id] = true
	}
	for _, c := range components.All() {
		if c.Class != components.ClassAdapter {
			continue
		}
		switch {
		case !seen[c.ID] && !omitted[c.ID]:
			t.Errorf("%s: no adapter in internal/adapter/defaults reports this tool name", c.ID)
		case seen[c.ID] && omitted[c.ID]:
			t.Errorf("%s: reported compiled out but the fan-in still builds it", c.ID)
		}
	}
}

// TestComponentsDocsInSync is the drift gate for the generated reference:
// docs/components.md must equal what cmd/sbo-components gen-docs writes.
func TestComponentsDocsInSync(t *testing.T) {
	root := repoRoot(t)
	skipInPublicTree(t, root, components.DocsPath)
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(components.DocsPath)))
	if err != nil {
		t.Fatalf("%s: %v (run go run ./cmd/sbo-components gen-docs)", components.DocsPath, err)
	}
	if string(b) != components.RenderMarkdown() {
		t.Fatalf("%s is stale: run go run ./cmd/sbo-components gen-docs and commit the result", components.DocsPath)
	}
}

// TestComponentsListenersMatchConfigDefaults: every declared listener that
// names a config key binds the address config.Default() resolves for it.
// Ports in the catalog that drift from the config are a disclosure lie.
func TestComponentsListenersMatchConfigDefaults(t *testing.T) {
	def := reflect.ValueOf(config.Default())
	checked := 0
	for _, c := range components.ForBinary(components.BinaryNode) {
		for _, l := range c.Surface.Listeners {
			if l.ConfigKey == "" || l.Proto != "tcp" {
				continue
			}
			v, ok := tomlLookup(def, l.ConfigKey)
			if !ok {
				t.Errorf("%s: listener config key %s does not exist in config.Config", c.ID, l.ConfigKey)
				continue
			}
			switch v.Kind() {
			case reflect.String:
				if v.String() == "" {
					// Resolved in cmd (the dashboard's built-in default);
					// the CLI test pins that one.
					continue
				}
				if v.String() != l.Addr {
					t.Errorf("%s: catalog listener %s, config default %s = %s", c.ID, l.Addr, l.ConfigKey, v.String())
				}
			case reflect.Int, reflect.Int64:
				if !strings.HasSuffix(l.Addr, ":"+strconv.FormatInt(v.Int(), 10)) {
					t.Errorf("%s: catalog listener %s, config default port %s = %d", c.ID, l.Addr, l.ConfigKey, v.Int())
				}
			default:
				t.Errorf("%s: config key %s is a %s, not an address", c.ID, l.ConfigKey, v.Kind())
			}
			checked++
		}
	}
	if checked < 4 {
		t.Fatalf("only %d listeners checked; the catalog lost its config keys", checked)
	}
}

// TestComponentsEgressMatchesConfigDefaults: the vendor-run hosts the
// catalog discloses are the hosts the config defaults actually call.
func TestComponentsEgressMatchesConfigDefaults(t *testing.T) {
	cases := []struct {
		id, endpoint string
	}{
		{"egress.pricing-feed", config.DefaultPricingFeedURL},
		{"egress.aggregate-share", config.DefaultAggregateEndpoint},
	}
	for _, tc := range cases {
		u, err := url.Parse(tc.endpoint)
		if err != nil {
			t.Fatal(err)
		}
		c, ok := components.Get(tc.id)
		if !ok {
			t.Fatalf("%s missing", tc.id)
		}
		found := false
		for _, e := range c.Surface.Egress {
			if e.Host == u.Hostname() {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: config default calls %s, catalog egress does not list it", tc.id, u.Hostname())
		}
	}
	// DEFAULT (automatic) egress lives only in a removable component whose
	// job is that egress, never on core. Core may disclose egress that only
	// a user's own action opens (a linked cloud-agent account, a command the
	// user runs): the cloud agents' lanes are core, and an honest catalog
	// lists their hosts rather than hiding them (security review
	// 2026-11-02, ledger MODPKG-4). Each such row must say what opens it.
	for _, c := range components.ForBinary(components.BinaryNode) {
		if c.Class != components.ClassCore {
			continue
		}
		for _, e := range c.Surface.Egress {
			if e.Trigger != components.TriggerOptIn && e.Trigger != components.TriggerUserTriggered {
				t.Errorf("core declares %s egress to %s; default egress lives in a removable component", e.Trigger, e.Host)
			}
			if strings.TrimSpace(e.Gate) == "" {
				t.Errorf("core egress to %s names no gate", e.Host)
			}
		}
	}
}

// TestComponentsConfigKeysExist: every declared config section is a
// top-level [section] of config.Config.
func TestComponentsConfigKeysExist(t *testing.T) {
	top := map[string]bool{}
	typ := reflect.TypeOf(config.Config{})
	for i := 0; i < typ.NumField(); i++ {
		if tag := strings.Split(typ.Field(i).Tag.Get("toml"), ",")[0]; tag != "" {
			top[tag] = true
		}
	}
	for _, c := range components.ForBinary(components.BinaryNode) {
		for _, k := range c.ConfigKeys {
			if !top[k] {
				t.Errorf("%s: config section [%s] does not exist", c.ID, k)
			}
		}
	}
}

// createTable matches a node migration's CREATE TABLE.
var createTable = regexp.MustCompile(`(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?([a-z_0-9]+)`)

// TestComponentsTablesAndMigrationsExist: every declared node table is
// created by a node migration, and every declared migration file exists.
func TestComponentsTablesAndMigrationsExist(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "internal", "db", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	tables := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range createTable.FindAllStringSubmatch(string(b), -1) {
			tables[strings.ToLower(m[1])] = true
		}
	}
	for _, c := range components.ForBinary(components.BinaryNode) {
		for _, tb := range c.Tables {
			if !tables[tb] {
				t.Errorf("%s: table %s is created by no node migration", c.ID, tb)
			}
		}
		for _, d := range c.Data {
			if !tables[d.Table] {
				t.Errorf("%s: data ownership names table %s, which no node migration creates", c.ID, d.Table)
			}
		}
	}
	for _, c := range components.All() {
		for _, m := range c.Migrations {
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(m.File))); err != nil {
				t.Errorf("%s: migration %s: %v", c.ID, m.File, err)
			}
		}
	}
}

// dashRoutePattern matches a reg("...") registration in the node dashboard.
var dashRoutePattern = regexp.MustCompile(`reg\("((?:[A-Z]+ )?/(?:api|ws)/[^"]*)"`)

// obsRoutePattern matches a Plane A route internal/obs/httpapi serves; those
// reach the dashboard only through ExtraRoutes from the obs wiring.
var obsRoutePattern = regexp.MustCompile(`"((?:[A-Z]+ )?/api/obs/[^"]*)"`)

// scanRoutes returns every route pattern re matches in the non-test Go files
// of dir, without the method prefix. A missing dir yields nothing.
func scanRoutes(t *testing.T, dir string, re *regexp.Regexp) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var routes []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			p := m[1]
			if i := strings.Index(p, " "); i >= 0 {
				p = p[i+1:]
			}
			routes = append(routes, p)
		}
	}
	return routes
}

// TestComponentsRoutesExist: every declared node route prefix matches at
// least one registered dashboard route, including the websocket routes and
// the Plane A routes the obs wiring adds (T-670 folded the dashboard's
// override table into the catalog). The public tree carries no
// internal/obs, so there a route of a component whose packages are absent
// is skipped.
func TestComponentsRoutesExist(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "internal", "intelligence", "dashboard")
	if _, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	}
	routes := scanRoutes(t, dir, dashRoutePattern)
	routes = append(routes, scanRoutes(t, filepath.Join(root, "internal", "obs", "httpapi"), obsRoutePattern)...)
	for _, c := range components.ForBinary(components.BinaryNode) {
		if len(c.Packages) > 0 {
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(c.Packages[0]))); err != nil {
				continue // stripped from this tree
			}
		}
		for _, r := range c.Routes {
			ok := false
			for _, have := range routes {
				if have == r || strings.HasPrefix(have, r+"/") || strings.HasPrefix(have, r+"?") {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("%s: route %s matches no registered dashboard route", c.ID, r)
			}
		}
	}
	if !contains(routes, "/api/components") {
		t.Error("the read-only /api/components route is not registered")
	}
}

// TestComponentsArtifactsRequireRealComponents: each artifact names node
// components that exist, and a helper artifact's source command exists.
func TestComponentsArtifactsRequireRealComponents(t *testing.T) {
	root := repoRoot(t)
	for _, a := range components.Artifacts() {
		for _, r := range a.Requires {
			if _, ok := components.Get(r); !ok {
				t.Errorf("%s requires unknown %s", a.ID, r)
			}
		}
	}
	for _, cmd := range []string{"cmd/antigravity-bridge", "cmd/observer-node-inspection"} {
		if !dirExists(root, cmd) {
			t.Errorf("helper artifact source %s is missing", cmd)
		}
	}
}

// tomlLookup walks a dotted TOML key through struct fields by their toml
// tags.
func tomlLookup(v reflect.Value, key string) (reflect.Value, bool) {
	for _, part := range strings.Split(key, ".") {
		for v.Kind() == reflect.Pointer {
			v = v.Elem()
		}
		if v.Kind() != reflect.Struct {
			return reflect.Value{}, false
		}
		found := false
		typ := v.Type()
		for i := 0; i < typ.NumField(); i++ {
			if strings.Split(typ.Field(i).Tag.Get("toml"), ",")[0] == part {
				v = v.Field(i)
				found = true
				break
			}
		}
		if !found {
			return reflect.Value{}, false
		}
	}
	return v, true
}

// TestComponentsCoreDisclosesCloudAgentHosts: every reviewed cloud-agent
// API host (cloudAgentsAPIHosts, the one pinned table) is disclosed as core
// egress, and the cloud-agent keychain service as a core credential store,
// so Settings > Components cannot under-report the cloud.agents lane
// (security review 2026-11-02, ledger MODPKG-4).
func TestComponentsCoreDisclosesCloudAgentHosts(t *testing.T) {
	core, ok := components.Get("core")
	if !ok {
		t.Fatal("core row missing")
	}
	hosts := map[string]bool{}
	for _, e := range core.Surface.Egress {
		hosts[e.Host] = true
	}
	for _, h := range cloudAgentsAPIHosts {
		if !hosts[h] {
			t.Errorf("cloud-agent API host %s is not disclosed on the core row", h)
		}
	}
	if !strings.Contains(strings.Join(core.Surface.Credentials, "\n"), "sbo-cloudagents-v1") {
		t.Error("core does not disclose the sbo-cloudagents-v1 keychain service")
	}
	for _, v := range []string{"cloud-agents", "cloud-session"} {
		if !contains(core.Verbs, v) {
			t.Errorf("core does not own verb %s", v)
		}
	}
}
