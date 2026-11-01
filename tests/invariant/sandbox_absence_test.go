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
	for _, want := range []string{"components/SandboxSettingsCard", "components/SandboxIsolationPicker"} {
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
		return entry[rel] || strings.HasPrefix(rel, "components/Sandbox")
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
	if !regexp.MustCompile(`moduleNotInstalled\([^)]*\)[^\n]*return null`).Match(card) {
		t.Error("SandboxSettingsCard.tsx no longer returns null on 404 component_not_installed: an inactive module would render its Card")
	}
	dialog, err := os.ReadFile(filepath.Join(src, "components", "NewTerminalDialog.tsx"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dialog), "!sandboxModuleAbsent && SANDBOX_ISOLATION_PICKER") {
		t.Error("NewTerminalDialog.tsx renders the Isolation picker without the module-absent check")
	}
}
