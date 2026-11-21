package invariant

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// sandbox_absence_test.go holds the sandbox module's absence rows (security
// ledger SBX-MOD-1, sandbox plan v2 section 11, lane LEFT-SBX). With the
// module off (`remove = ["terminals.sandbox"]`, or a build without it) no
// sandbox route answers, no sandbox CLI verb runs and no Settings row or
// Card renders. The live proof is tests/distro TestSandboxModuleInertWhenInactive
// (a real daemon); these rows prove the static half for EVERY surface, so a
// new route, verb or panel that slips past the module's gates fails here
// rather than only when someone remembers to add it to the smoke.

// sandboxModuleRoot is the module's catalog id; its drivers are the rows
// below it ("terminals.sandbox.oci", ...).
const sandboxModuleRoot = "terminals.sandbox"

func inSandboxModule(id string) bool {
	return id == sandboxModuleRoot || strings.HasPrefix(id, sandboxModuleRoot+".")
}

// sandboxCoreResidue lists the core surfaces that name the sandbox but stay
// when the module is off, each with its reason (plan v2 section 11.1, "the
// core residue listed honestly"). A new entry needs the reason to hold: it
// must show or do nothing while no sandboxed run exists.
var sandboxCoreResidue = map[string]string{
	// `observer workspaces` (component terminals) lists and removes the
	// clone workspaces sandboxed runs left behind; it must keep working
	// after the module is removed so the leftovers can be cleaned up, and
	// with none on disk it prints an empty list.
	"verb workspaces": "cleanup of leftovers after removal",
	// The restart banner's live-runs question (core) renders only when the
	// daemon reports a live sandboxed run, which an inactive module cannot
	// have.
	"web components/LiveSandboxRunsDialog": "renders only with a live sandboxed run",
}

// sandboxRouteOwner mirrors the dashboard's route guard
// (internal/intelligence/dashboard/components_manage.go routeComponent):
// the longest catalog Routes prefix on a segment boundary, else core.
func sandboxRouteOwner(path string) string {
	best, bestLen := "core", -1
	for _, c := range components.ForBinary(components.BinaryNode) {
		for _, r := range c.Routes {
			p := strings.TrimSuffix(r, "/")
			if path != p && !strings.HasPrefix(path, p+"/") {
				continue
			}
			if len(p) > bestLen {
				best, bestLen = c.ID, len(p)
			}
		}
	}
	return best
}

// TestSandboxModuleRoutesAnswerOnlyWhenActive: every registered dashboard
// route with a sandbox path segment is owned by the module (or one of its
// drivers), so the route guard answers 404 component_not_installed for it
// while the module is inactive and a build without the module registers its
// omit twin. Removing the module's Routes row from the catalog fails this
// test (the routes fall to terminals, which stays active).
func TestSandboxModuleRoutesAnswerOnlyWhenActive(t *testing.T) {
	root := repoRoot(t)
	routes := scanRoutes(t, filepath.Join(root, "internal", "intelligence", "dashboard"), dashRoutePattern)
	seen := 0
	for _, r := range routes {
		if !hasSandboxSegment(r) {
			continue
		}
		seen++
		if owner := sandboxRouteOwner(r); !inSandboxModule(owner) {
			t.Errorf("route %s is owned by %s, not by the sandbox module: it would answer while the module is off", r, owner)
		}
	}
	if seen == 0 {
		t.Fatal("no sandbox route found: the scan is broken")
	}
}

func hasSandboxSegment(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, "sandbox") {
			return true
		}
	}
	return false
}

// sandboxVerbUse matches a cobra command's Use line naming a sandbox verb.
var sandboxVerbUse = regexp.MustCompile(`Use:\s*"(sandbox[a-z-]*|workspaces)\b`)

// TestSandboxModuleVerbsRefuseWhenInactive: every cobra verb that names the
// sandbox is a catalog Verb of the module, so the verb gate
// (cmd/observer/components_gate.go gateComponentVerbs) refuses it, and every
// subcommand below it, with exit 3 while the module is inactive. The
// `observer <tool> --observer-sandbox` path runs before cobra and checks the
// module itself before it reads anything else. The argv helper verbs the
// launch path spawns (sandbox-host, sandbox-oci-init, ...) are not CLI verbs:
// they have no help entry, are started only by a sandboxed launch, and are
// registered only from files the module's omit tags compile out.
func TestSandboxModuleVerbsRefuseWhenInactive(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "cmd", "observer")
	owned := map[string]string{}
	for _, c := range components.ForBinary(components.BinaryNode) {
		for _, v := range c.Verbs {
			owned[v] = c.ID
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var helperFiles []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, m := range sandboxVerbUse.FindAllStringSubmatch(src, -1) {
			verb := m[1]
			if _, ok := sandboxCoreResidue["verb "+verb]; ok {
				continue
			}
			// Only a top-level verb is gated by name; a subcommand (a Use
			// under `sandbox`) rides its parent's wrap. A top-level verb is
			// one the catalog could name; any sandbox-named Use that is not
			// a known subcommand must be a module verb.
			if id, ok := owned[verb]; ok {
				if !inSandboxModule(id) {
					t.Errorf("%s: verb %q is owned by %s, not by the sandbox module", name, verb, id)
				}
				continue
			}
			if verb != "sandbox" {
				t.Errorf("%s: sandbox-named verb %q is in no catalog row: the verb gate would not refuse it", name, verb)
			}
		}
		if strings.Contains(src, "sandboxHelperFuncs[") || strings.Contains(src, "var sandboxHelperFuncs") {
			helperFiles = append(helperFiles, name)
			if !buildLineOmits(src, "sbo_omit_terminals_sandbox") {
				t.Errorf("%s registers a sandbox helper verb but its build line does not carry !sbo_omit_terminals_sandbox: a build without the module would still run it", name)
			}
		}
	}
	if owned["sandbox"] != sandboxModuleRoot {
		t.Errorf("verb sandbox is owned by %q, want %s", owned["sandbox"], sandboxModuleRoot)
	}
	if len(helperFiles) == 0 {
		t.Fatal("no sandbox helper registration found: the scan is broken")
	}
	cli, err := os.ReadFile(filepath.Join(dir, "terminal_sandbox_cli.go"))
	if err != nil {
		t.Fatal(err)
	}
	body := funcBody(string(cli), "func runSandboxCLI(")
	gate := strings.Index(body, "sandboxModuleActive(")
	if gate < 0 {
		t.Fatal("runSandboxCLI does not check sandboxModuleActive: `observer <tool> --observer-sandbox` would run with the module off")
	}
	for _, later := range []string{"prepareSandbox", "exec.Command", "os.StartProcess"} {
		if i := strings.Index(body, later); i >= 0 && i < gate {
			t.Errorf("runSandboxCLI reaches %s before the module check", later)
		}
	}
}

// buildLineOmits reports whether src's //go:build line negates tag.
func buildLineOmits(src, tag string) bool {
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			return false
		}
		if strings.HasPrefix(line, "//go:build ") && strings.Contains(line, "!"+tag) {
			return true
		}
	}
	return false
}

// funcBody returns src from the line starting with sig to the next
// top-level closing brace.
func funcBody(src, sig string) string {
	i := strings.Index(src, sig)
	if i < 0 {
		return ""
	}
	rest := src[i:]
	if j := strings.Index(rest, "\n}\n"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// sandboxWebImport matches an import of a sandbox web module.
var sandboxWebImport = regexp.MustCompile(`from\s+"@/(components/[A-Za-z]*Sandbox[A-Za-z]*)"`)

// TestSandboxModuleWebRendersNothingWhenOff: the module's Settings Card and
// the New Terminal Isolation picker are compgen feature rows the module owns
// (web/compgen features), so a distro without the module ships neither; the
// Card's panels (and with them every sandbox Settings row) are imported only
// by the Card or by another module file; no core page imports a sandbox
// module directly; and both entry points render nothing on the route
// guard's 404 component_not_installed, so an installed but inactive module
// shows no element.
func TestSandboxModuleWebRendersNothingWhenOff(t *testing.T) {
	root := repoRoot(t)
	web := filepath.Join(root, "web")
	gen, err := os.ReadFile(filepath.Join(web, "compgen", "main.go"))
	if err != nil {
		t.Skip("web tree not present") // public tree
	}
	featureRow := regexp.MustCompile(`\{"([A-Z_]+)",\s*"(components/[A-Za-z]+)",\s*"[A-Za-z]+",\s*"([a-z.\-]+)"\}`)
	entry := map[string]bool{}
	for _, m := range featureRow.FindAllStringSubmatch(string(gen), -1) {
		if strings.Contains(m[2], "Sandbox") {
			if !inSandboxModule(m[3]) {
				t.Errorf("compgen feature %s (%s) is owned by %s, not by the sandbox module", m[1], m[2], m[3])
			}
			entry[m[2]] = true
		}
	}
	for _, want := range []string{"components/SandboxSettingsCard", "components/SandboxIsolationPicker", "components/SandboxSetupPanel"} {
		if !entry[want] {
			t.Errorf("%s is not a module-owned compgen feature row", want)
		}
	}
	src := filepath.Join(web, "src")
	importers := map[string][]string{} // sandbox module -> files importing it
	walkErr := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		name := info.Name()
		if !(strings.HasSuffix(name, ".ts") || strings.HasSuffix(name, ".tsx")) || strings.Contains(name, ".test.") || name == "components.gen.ts" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		rel = strings.TrimSuffix(strings.TrimSuffix(filepath.ToSlash(rel), ".tsx"), ".ts")
		for _, m := range sandboxWebImport.FindAllStringSubmatch(string(b), -1) {
			importers[m[1]] = append(importers[m[1]], rel)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	moduleFile := func(rel string) bool {
		// components/sandboxHosted/ holds the Hosted sandboxes panel's own
		// fields (the sandbox terminal decisions' settings), module files
		// imported only by that panel or the module's dialog pieces.
		return entry[rel] || strings.HasPrefix(rel, "components/Sandbox") || strings.HasPrefix(rel, "components/sandboxHosted/")
	}
	mods := make([]string, 0, len(importers))
	for m := range importers {
		mods = append(mods, m)
	}
	sort.Strings(mods)
	for _, m := range mods {
		if _, ok := sandboxCoreResidue["web "+m]; ok {
			continue
		}
		for _, from := range importers[m] {
			if !moduleFile(from) {
				t.Errorf("%s imports %s directly: a core page would render a sandbox element without the module's gate (use a compgen feature row)", from, m)
			}
		}
	}
	card, err := os.ReadFile(filepath.Join(src, "components", "SandboxSettingsCard.tsx"))
	if err != nil {
		t.Fatal(err)
	}
	// The card's shape table (web/src/lib/sandboxSettingsView.ts): a build
	// without the module, or a hidden section, renders nothing; an installed
	// but inactive module renders only the pointer card with its Turn it on
	// button (decision SBXD-9), which sends none of the module's reads.
	if !strings.Contains(string(card), `if (shape === "hidden") return null;`) {
		t.Error("SandboxSettingsCard.tsx no longer returns null for the hidden shape: a build without the module would render its Card")
	}
	if !regexp.MustCompile(`shape === "module_off"[^\n]*\{\s*return \(\s*<SandboxModuleOffCard`).Match(card) {
		t.Error("SandboxSettingsCard.tsx renders more than the pointer card while the module is off")
	}
	dialog, err := os.ReadFile(filepath.Join(src, "components", "NewTerminalDialog.tsx"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dialog), "!sandboxModuleAbsent && SANDBOX_ISOLATION_PICKER") {
		t.Error("NewTerminalDialog.tsx renders the Isolation picker without the module-absent check")
	}
}

// The sandbox installation lifecycle's surfaces (plan
// docs/plans/sandbox-installation-lifecycle-plan-2026-11-06.md section 8,
// "Components fencing"): every route, verb and panel it added, one row each,
// so a node with the module off proves none of them answers or renders.

// sandboxSetupRouteRows are the setup routes and the hosted connect route.
// path is a concrete request path; registered is the pattern a source file
// registers it under (the setup subtree is one prefix registration, since
// Go mux patterns "setup/op/{id}" and "setup/{backend}/check" conflict).
var sandboxSetupRouteRows = []struct {
	path       string
	registered string
	file       string
}{
	{"/api/terminal/sandbox/setup", `reg("/api/terminal/sandbox/setup", `, "internal/intelligence/dashboard/dashboard.go"},
	{"/api/terminal/sandbox/setup/bwrap", `reg("/api/terminal/sandbox/setup/", `, "internal/intelligence/dashboard/dashboard.go"},
	{"/api/terminal/sandbox/setup/bwrap/check", `reg("/api/terminal/sandbox/setup/", `, "internal/intelligence/dashboard/dashboard.go"},
	{"/api/terminal/sandbox/setup/bwrap/run", `reg("/api/terminal/sandbox/setup/", `, "internal/intelligence/dashboard/dashboard.go"},
	{"/api/terminal/sandbox/setup/op/op-1", `reg("/api/terminal/sandbox/setup/", `, "internal/intelligence/dashboard/dashboard.go"},
	{"/api/terminal/sandbox/hosted/connect", `"POST /api/terminal/sandbox/hosted/connect"`, "cmd/observer/terminal_sandbox_hosted_connect_route.go"},
}

// TestSandboxSetupRoutesAnswerOnlyWhenActive: each setup route is
// registered where the row says and is owned by the sandbox module, so the
// route guard answers 404 component_not_installed for it while the module
// is off; the hosted connect route's file is compiled out of a build
// without the module.
func TestSandboxSetupRoutesAnswerOnlyWhenActive(t *testing.T) {
	root := repoRoot(t)
	for _, row := range sandboxSetupRouteRows {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(row.file)))
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		if !strings.Contains(src, row.registered) {
			t.Errorf("%s: %s does not register %s", row.path, row.file, row.registered)
		}
		if strings.HasPrefix(row.file, "cmd/") && !buildLineOmits(src, "sbo_omit_terminals_sandbox") {
			t.Errorf("%s: %s is not compiled out of a build without the module", row.path, row.file)
		}
		if owner := sandboxRouteOwner(row.path); !inSandboxModule(owner) {
			t.Errorf("%s is owned by %s, not by the sandbox module: it would answer while the module is off", row.path, owner)
		}
	}
}

// sandboxSetupVerbRows are the `observer sandbox setup` verbs and how
// sandbox_setup_cmd.go declares each.
var sandboxSetupVerbRows = []struct {
	verb string
	decl string
}{
	{"status", `Use:   "status `},
	{"check", `Use:   "check `},
	{"run", `Use:   "run `},
	{"undo", `dashapi.SandboxSetupActionUndo`},
	{"update", `dashapi.SandboxSetupActionUpdate`},
	{"repair", `dashapi.SandboxSetupActionRepair`},
	{"records", `Use:   "records"`},
}

// TestSandboxSetupVerbsRefuseWhenInactive: each setup verb is declared in
// sandbox_setup_cmd.go, which the module's omit tags compile out; the
// `setup` tree hangs under `observer sandbox` (a module verb, so the verb
// gate refuses it and every subcommand with exit 3 while the module is
// off); and neither omit twin of newSandboxCmd adds it.
func TestSandboxSetupVerbsRefuseWhenInactive(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "cmd", "observer")
	b, err := os.ReadFile(filepath.Join(dir, "sandbox_setup_cmd.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, tag := range []string{"sbo_omit_terminals_sandbox", "sbo_omit_isolation", "sbo_omit_terminals"} {
		if !buildLineOmits(src, tag) {
			t.Errorf("sandbox_setup_cmd.go is not compiled out by %s", tag)
		}
	}
	for _, row := range sandboxSetupVerbRows {
		if !strings.Contains(src, row.decl) {
			t.Errorf("verb sandbox setup %s: %q not found in sandbox_setup_cmd.go", row.verb, row.decl)
		}
	}
	owned := map[string]string{}
	for _, c := range components.ForBinary(components.BinaryNode) {
		for _, v := range c.Verbs {
			owned[v] = c.ID
		}
	}
	if owned["sandbox"] != sandboxModuleRoot {
		t.Errorf("verb sandbox is owned by %q, want %s: the setup verbs would run with the module off", owned["sandbox"], sandboxModuleRoot)
	}
	status, err := os.ReadFile(filepath.Join(dir, "sandbox_status.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(funcBody(string(status), "func newSandboxCmd("), "newSandboxSetupCmd()") {
		t.Error("newSandboxCmd does not add the setup tree: the rows above no longer describe where it lives")
	}
	for _, twin := range []string{"terminal_sandbox_omit.go", "terminals_omit.go"} {
		tb, err := os.ReadFile(filepath.Join(dir, twin))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(funcBody(string(tb), "func newSandboxCmd("), "newSandboxSetupCmd") {
			t.Errorf("%s adds the setup tree in a build without the module", twin)
		}
	}
}

// TestSandboxSetupPanelRendersNothingWhenOff: the setup panel is the
// module-owned compgen row SANDBOX_SETUP_PANEL, and both places that render
// it (the New Terminal dialog and the Settings card) render it only through
// that row, the dialog also behind its module-absent check.
func TestSandboxSetupPanelRendersNothingWhenOff(t *testing.T) {
	root := repoRoot(t)
	web := filepath.Join(root, "web")
	gen, err := os.ReadFile(filepath.Join(web, "compgen", "main.go"))
	if err != nil {
		t.Skip("web tree not present") // public tree
	}
	row := regexp.MustCompile(`\{"SANDBOX_SETUP_PANEL",\s*"components/SandboxSetupPanel",\s*"[A-Za-z]+",\s*"([a-z.\-]+)"\}`)
	m := row.FindStringSubmatch(string(gen))
	if m == nil {
		t.Fatal("no SANDBOX_SETUP_PANEL compgen feature row")
	}
	if !inSandboxModule(m[1]) {
		t.Errorf("SANDBOX_SETUP_PANEL is owned by %s, not by the sandbox module", m[1])
	}
	src := filepath.Join(web, "src", "components")
	dialog, err := os.ReadFile(filepath.Join(src, "NewTerminalDialog.tsx"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dialog), "!sandboxModuleAbsent && setupOffered && setupOpen && SANDBOX_SETUP_PANEL") {
		t.Error("NewTerminalDialog.tsx renders the setup panel without the module-absent check and the compgen row")
	}
	for _, f := range []string{"NewTerminalDialog.tsx", "SandboxSettingsCard.tsx"} {
		b, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			t.Fatal(err)
		}
		if regexp.MustCompile(`import\s+\{[^}]*\}\s+from\s+"@/components/SandboxSetupPanel"`).Match(b) {
			t.Errorf("%s imports SandboxSetupPanel directly: it would render without the compgen row", f)
		}
		if !strings.Contains(string(b), "SANDBOX_SETUP_PANEL") {
			t.Errorf("%s no longer renders the panel through SANDBOX_SETUP_PANEL", f)
		}
	}
}
