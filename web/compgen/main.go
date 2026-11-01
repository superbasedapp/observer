// Command compgen writes web/src/lib/components.gen.ts, the node dashboard's
// generated route and page registry (modular packaging plan section 5.1 rev
// N5 and section 7.3, lane MP-DASH, T-659).
//
// # Why this exists
//
// The plan builds the web app once per distro: a page whose component is not
// in the distro must not be in the bundle at all (its lazy chunk, and the
// heavy modules only it imports). That needs ONE place where page modules
// are imported, so excluding a page is a generator decision instead of a
// hand edit of App.tsx. components.gen.ts is that place: App.tsx consumes its
// PAGE_ROUTES table, and src/lib/componentRegistry.test.ts (the lint rule)
// fails on any other file importing a registry page module.
//
// The same table carries each page's owning component, which the SPA's nav
// filter and NotInstalled route guard read, so "which component owns this
// page" has one owner as well.
//
// # Usage
//
//	go run ./web/compgen                   # every page (today's single build)
//	go run ./web/compgen -distro developer # only pages whose component the distro compiles
//
// Lane MP-REL consumes -distro for the per-distro builds and their Rollup
// module-graph proof. main_test.go is the drift gate for the default output.
//
// # Determinism
//
// Pure: no clock, no environment, no filesystem reads; pages are emitted in
// table order, which is the nav order.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// page is one routed page of the node dashboard.
type page struct {
	// NavID is the NAV_ITEMS id ("" for a page with no nav entry).
	NavID string
	// Path is the react-router path relative to the app root ("" = index).
	Path string
	// Module is the module under web/src/pages that exports the page.
	Module string
	// Export is the page component's named export.
	Export string
	// Component is the owning catalog component ("core" = always present).
	Component string
}

// pages is the routed page table, in nav order. A page whose data comes
// from one optional component's API is owned by that component; a page
// several components feed stays core and hides the tiles of absent ones
// itself. TestPagesNameNodeComponents pins every Component to a catalog row.
var pages = []page{
	{"overview", "", "Overview", "OverviewPage", "core"},
	{"live", "live", "Live", "LivePage", "core"},
	{"search", "search", "Search", "SearchPage", "compression.indexing"},
	{"cost", "cost", "Cost", "CostPage", "core"},
	{"plans", "plans", "Plans", "PlansPage", "core"},
	{"analysis", "analysis", "Analysis", "AnalysisPage", "core"},
	{"sessions", "sessions", "Sessions", "SessionsPage", "core"},
	{"actions", "actions", "Actions", "ActionsPage", "core"},
	{"projects", "projects", "Projects", "ProjectsPage", "projects"},
	// Plane split (T-671, TestPagesFollowThePlaneSplit): Security is the
	// Plane B guard page (internal/guard + internal/policy, /api/guard), so
	// every distro keeps it. Egress and Policies are Plane A pages despite
	// their names: Egress is the node-local G22 audit of internal/obs/egress
	// (the one deliberate Plane A exception on the node dashboard,
	// docs/deployment-models.md) and Policies authors [observability.admission]
	// and [observability.egress]; both read only /api/obs, so they leave the
	// developer distro with obs (D-389).
	{"security", "security", "Security", "SecurityPage", "guard"},
	// Code security (the security pillar, security pillar plan section
	// 4.10): its own page id beside Guard's, owned by component `security`
	// (the component id and Guard's page id are different namespaces).
	{"code-security", "code-security", "CodeSecurity", "CodeSecurityPage", "security"},
	{"egress", "egress", "Egress", "EgressPage", "obs"},
	{"policies", "policies", "Policies", "PoliciesPage", "obs"},
	{"agent-config", "agent-config", "AgentConfig", "AgentConfigPage", "integration.agent-config"},
	{"tools", "tools", "Tools", "ToolsPage", "core"},
	{"compression", "compression", "Compression", "CompressionPage", "proxy.compression"},
	{"cache", "cache", "Cache", "CachePage", "analytics"},
	{"suggestions", "suggestions", "Suggestions", "SuggestionsPage", "analytics"},
	{"routing", "routing", "Routing", "RoutingPage", "proxy.routing"},
	{"benchmarks", "benchmarks", "Benchmarks", "BenchmarksPage", "benchmark"},
	{"discovery", "discovery", "Discovery", "DiscoveryPage", "analytics"},
	{"patterns", "patterns", "Patterns", "PatternsPage", "analytics"},
	{"privacy", "privacy", "Privacy", "PrivacyPage", "core"},
	{"messages", "messages", "Messages", "MessagesPage", "org.client"},
	{"requests", "requests", "Requests", "RequestsPage", "org.client"},
	{"settings", "settings", "Settings", "SettingsPage", "core"},
	{"", "settings/components", "Components", "ComponentsPage", "core"},
	{"remote", "remote", "Remote", "RemotePage", "remote"},
	{"terminals", "terminals", "Terminals", "TerminalsPage", "terminals"},
}

// feature is a component-owned module that a page OUTSIDE that component
// renders (the dock in main.tsx, a Settings card). Importing it directly
// would put its chunks (xterm for LaunchTerminal) into every distro's bundle,
// which is exactly what the minimal bundle carried (lane MP-REL2, T-687). The
// registry instead exports a lazy component, or null when the distro does not
// compile the owner, and callers render nothing for null.
type feature struct {
	Const     string // exported constant name in components.gen.ts
	Module    string // path under src/ without extension
	Export    string // named export of the module
	Component string // owning catalog component
}

var features = []feature{
	{"LAUNCH_TERMINAL", "components/LaunchTerminal", "LaunchTerminal", "terminals"},
	// The Sandboxes and VMs module's Terminals > Settings card and the New
	// Terminal dialog's Isolation picker (sandbox plan v2 section 11.1).
	{"SANDBOX_SETTINGS_CARD", "components/SandboxSettingsCard", "SandboxSettingsCard", "terminals.sandbox"},
	{"SANDBOX_ISOLATION_PICKER", "components/SandboxIsolationPicker", "SandboxIsolationPicker", "terminals.sandbox"},
}

// packages maps an npm package that only a component's pages and features
// import to that component. The per-distro proof (vite.config.ts
// sboDistroProof) fails the build when a package of an absent component is in
// any emitted chunk.
var packages = []struct{ Name, Component string }{
	{"@xterm/xterm", "terminals"},
	{"@xterm/addon-fit", "terminals"},
	{"react-grid-layout", "terminals"},
	{"qrcode", "remote"},
}

// proof is the forbidden-module list for one distro's web build.
type proof struct {
	Distro           string   `json:"distro"`
	ForbiddenSources []string `json:"forbidden_sources"`
	ForbiddenPackage []string `json:"forbidden_packages"`
}

func componentIn(component string, d components.Distro) bool {
	return inDistro(page{Component: component}, d)
}

// buildProof lists what the distro must not ship: the page and feature
// modules (paths under src/, no extension) and the packages of every
// component it does not compile. The full distro forbids nothing.
func buildProof(d components.Distro) proof {
	pr := proof{Distro: string(d), ForbiddenSources: []string{}, ForbiddenPackage: []string{}}
	switch {
	case customSet != nil:
		pr.Distro = customLabel
	case pr.Distro == "":
		pr.Distro = string(components.DistroFull)
	}
	for _, p := range pages {
		if !inDistro(p, d) {
			pr.ForbiddenSources = append(pr.ForbiddenSources, "src/pages/"+p.Module)
		}
	}
	for _, f := range features {
		if !componentIn(f.Component, d) {
			pr.ForbiddenSources = append(pr.ForbiddenSources, "src/"+f.Module)
		}
	}
	for _, pk := range packages {
		if !componentIn(pk.Component, d) {
			pr.ForbiddenPackage = append(pr.ForbiddenPackage, pk.Name)
		}
	}
	return pr
}

func main() {
	out := flag.String("o", "web/src/lib/components.gen.ts", "output path")
	distro := flag.String("distro", "", "only pages whose component this prebuilt distro compiles (empty = every page)")
	proofOut := flag.String("proof", "", "also write the distro's forbidden-module list (JSON) for the vite build proof")
	manifest := flag.String("manifest", "", "only pages whose component this custom build compiles: the canonical manifest JSON `sbo-components build` writes (<custom distro>.sbo-distro.json)")
	flag.Parse()
	if *manifest != "" {
		if *distro != "" {
			log.Fatal("compgen: -distro and -manifest are exclusive")
		}
		if err := useManifest(*manifest); err != nil {
			log.Fatal(err)
		}
	}
	if *proofOut != "" {
		if d := components.Distro(*distro); d != "" && !d.Valid() {
			log.Fatalf("compgen: %q is not a prebuilt distro", d)
		}
		js, err := json.MarshalIndent(buildProof(components.Distro(*distro)), "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(*proofOut, append(js, '\n'), 0o644); err != nil { //nolint:gosec // a build input, not a secret
			log.Fatal(err)
		}
	}
	src, err := render(components.Distro(*distro))
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil { //nolint:gosec // a generated source file, world-readable like every other
		log.Fatal(err)
	}
}

// inDistro reports whether a page's component is compiled into d (core and
// the empty distro always are).
func inDistro(p page, d components.Distro) bool {
	if customSet != nil {
		return p.Component == "core" || customSet[p.Component]
	}
	if d == "" || p.Component == "core" {
		return true
	}
	c, ok := components.Get(p.Component)
	return ok && c.Distros[d].Compiled()
}

// customSet, when non-nil, is a custom build's compiled set (-manifest,
// modular packaging plan 5.3, lane MP-CUST): it replaces the distro
// predicate, so the custom web bundle carries exactly the pages, and so the
// lazy chunks, of the components the custom binary compiles. customLabel is
// its custom distro id.
var (
	customSet   map[string]bool
	customLabel string
)

// useManifest resolves a canonical manifest and selects its compiled set.
func useManifest(path string) error {
	raw, err := os.ReadFile(path) //nolint:gosec // the build input the operator pointed this generator at
	if err != nil {
		return fmt.Errorf("compgen: %w", err)
	}
	m, err := components.DecodeManifestJSON(raw)
	if err != nil {
		return fmt.Errorf("compgen: %s: %w", path, err)
	}
	cb, problems := components.ResolveManifest(m)
	if len(problems) > 0 {
		return fmt.Errorf("compgen: %s does not resolve: %s", path, strings.Join(problems, "; "))
	}
	customSet = map[string]bool{}
	for _, id := range cb.Compiled {
		customSet[id] = true
	}
	customLabel = cb.Distro
	return nil
}

// render emits the TypeScript registry.
func render(d components.Distro) ([]byte, error) {
	if d != "" && !d.Valid() {
		return nil, fmt.Errorf("compgen: %q is not a prebuilt distro", d)
	}
	var b bytes.Buffer
	b.WriteString("// GENERATED by web/compgen from its page table and internal/components. DO NOT EDIT.\n")
	b.WriteString("// Regenerate with `go run ./web/compgen`; web/compgen/main_test.go is the drift gate.\n")
	b.WriteString("//\n")
	b.WriteString("// The ONLY module that imports routed page modules (modular packaging plan 5.1,\n")
	b.WriteString("// rev N5): App.tsx renders PAGE_ROUTES, and src/lib/componentRegistry.test.ts\n")
	b.WriteString("// fails on any other import of a page listed here. A per-distro build\n")
	b.WriteString("// regenerates this file with `-distro <name>`, which drops the pages of\n")
	b.WriteString("// components the distro does not compile, and with them their chunks.\n")
	switch {
	case customSet != nil:
		fmt.Fprintf(&b, "//\n// Custom distro: %s.\n", customLabel)
	case d != "":
		fmt.Fprintf(&b, "//\n// Distro: %s.\n", d)
	}
	b.WriteString("\nimport { lazy, type ComponentType, type LazyExoticComponent } from \"react\";\n\n")
	b.WriteString("/** One routed page and the component that owns it. */\n")
	b.WriteString("export type PageRoute = {\n")
	b.WriteString("  /** NAV_ITEMS id, or \"\" for a page without a nav entry. */\n")
	b.WriteString("  navId: string;\n")
	b.WriteString("  /** react-router path relative to the app root (\"\" is the index). */\n")
	b.WriteString("  path: string;\n")
	b.WriteString("  /** Owning catalog component id (\"core\" is always present). */\n")
	b.WriteString("  component: string;\n")
	b.WriteString("  Page: LazyExoticComponent<ComponentType>;\n")
	b.WriteString("};\n\n")
	b.WriteString("export const PAGE_ROUTES: readonly PageRoute[] = [\n")
	for _, p := range pages {
		if !inDistro(p, d) {
			continue
		}
		fmt.Fprintf(&b, "  {\n    navId: %q,\n    path: %q,\n    component: %q,\n", p.NavID, p.Path, p.Component)
		fmt.Fprintf(&b, "    Page: lazy(() => import(\"@/pages/%s\").then((m) => ({ default: m.%s }))),\n  },\n", p.Module, p.Export)
	}
	b.WriteString("];\n\n")
	b.WriteString("/** NAV_COMPONENTS maps a nav id to its owning component (pure data). */\n")
	b.WriteString("export const NAV_COMPONENTS: Readonly<Record<string, string>> = {\n")
	for _, p := range pages {
		if p.NavID == "" || !inDistro(p, d) {
			continue
		}
		fmt.Fprintf(&b, "  %s: %q,\n", tsKey(p.NavID), p.Component)
	}
	b.WriteString("};\n")
	for _, f := range features {
		fmt.Fprintf(&b, "\n/** %s from @/%s (component %s), or null when this build does not compile it. */\n", f.Export, f.Module, f.Component)
		fmt.Fprintf(&b, "export const %s: LazyExoticComponent<typeof import(\"@/%s\").%s> | null =", f.Const, f.Module, f.Export)
		if componentIn(f.Component, d) {
			fmt.Fprintf(&b, "\n  lazy(() => import(\"@/%s\").then((m) => ({ default: m.%s })));\n", f.Module, f.Export)
		} else {
			b.WriteString(" null;\n")
		}
	}
	return b.Bytes(), nil
}

// tsKey quotes an object key only when it is not a plain identifier.
func tsKey(k string) string {
	if strings.ContainsAny(k, "-.") {
		return fmt.Sprintf("%q", k)
	}
	return k
}
