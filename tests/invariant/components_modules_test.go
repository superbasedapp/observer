package invariant

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// componentModuleBinaries are the binaries whose module closures the
// catalog declares in full.
var componentModuleBinaries = []components.Binary{components.BinaryNode, components.BinaryOrg}

// TestComponentsPackagesInClosure: every package a component owns or is
// hosted in is really in its binary's dependency closure (for some GOOS),
// unless the package is absent from this tree (the public tree strips
// private paths, plan rev S1). A row naming a package the binary never
// links is a false claim.
func TestComponentsPackagesInClosure(t *testing.T) {
	root := repoRoot(t)
	for _, b := range componentModuleBinaries {
		if !dirExists(root, b.CmdPath()) {
			continue // binary stripped from this tree (public tree)
		}
		var graphs []*depGraph
		for _, goos := range binaryGOOS(b) {
			graphs = append(graphs, goListDeps(t, b.CmdPath(), goos, ""))
		}
		// A component this tree compiles out of every build (the public
		// tree's unconditional obs stub) is rightly absent from the closure.
		forced := forcedOmitted(t, root, b.CmdPath())
		for _, c := range components.ForBinary(b) {
			if forced[c.ID] {
				continue
			}
			for _, p := range append(append([]string(nil), c.Packages...), c.HostedIn...) {
				if !dirExists(root, p) {
					continue
				}
				found := false
				for _, g := range graphs {
					if g.hasRel(p) {
						found = true
					}
				}
				// -short analyses linux only, so a windows- or darwin-only
				// package (processobs/etw) cannot be judged there.
				if !found && !testing.Short() {
					t.Errorf("%s (%s): package %s is not in %s's dependency closure", c.ID, b, p, b.CmdPath())
				}
			}
		}
	}
}

// TestComponentsDirectModules is the catalog-truth check for third-party
// modules (plan 3.2 item 1, rev M5, 8.3). Modules are many-to-many, so
// DirectModules lists expected direct consumers, never exclusive owners:
//
//  1. every direct import edge from one of our packages to a third-party
//     module is declared: by the package's owning component (core when
//     unowned) or by a component whose code the package hosts; an edge
//     from the cmd wiring package is declared by any component of that
//     binary. So a new dependency cannot sneak into a binary without a
//     DirectModules entry on some component;
//  2. nothing declared is stale: each (component, module) pair has at
//     least one such edge, checked only for components whose packages are
//     present in the closure (a stripped tree or a compiled-out component
//     declares modules it does not link).
//
// "Modules this component removes" is derived output for the disclosure,
// never asserted here.
func TestComponentsDirectModules(t *testing.T) {
	for _, b := range componentModuleBinaries {
		ix := newOwnerIndex(b)
		declared := map[string]map[string]bool{}
		anyDeclared := map[string]bool{}
		for _, c := range components.ForBinary(b) {
			declared[c.ID] = map[string]bool{}
			for _, m := range c.DirectModules {
				declared[c.ID][m] = true
				anyDeclared[m] = true
			}
		}
		used := map[string]map[string]bool{} // component -> module -> seen
		present := map[string]bool{}         // component -> has a package in the closure
		var missing []string
		for _, goos := range binaryGOOS(b) {
			g := goListDeps(t, b.CmdPath(), goos, "")
			for full, p := range g.pkgs {
				if !ownPkg(full) {
					continue
				}
				rel := relPkg(full)
				isCmd := strings.HasPrefix(rel, "cmd/")
				owner := ix.ownerOf(b, rel)
				present[owner] = true
				for _, h := range ix.hosted[rel] {
					present[h] = true
				}
				for _, imp := range p.imports {
					m := g.moduleOf(imp)
					if m == "" || m == componentsModule {
						continue
					}
					if isCmd {
						// The cmd wiring package's edges are declared by
						// any component of the binary; core is the one
						// they count toward for staleness.
						if core := coreID(b); declared[core][m] {
							if used[core] == nil {
								used[core] = map[string]bool{}
							}
							used[core][m] = true
						}
						if !anyDeclared[m] {
							missing = append(missing, fmt.Sprintf("%s: %s imports %s (no component of %s declares it)", goos, rel, m, b))
						}
						continue
					}
					cands := append([]string{owner}, ix.hosted[rel]...)
					ok := false
					for _, cid := range cands {
						if declared[cid][m] {
							ok = true
							if used[cid] == nil {
								used[cid] = map[string]bool{}
							}
							used[cid][m] = true
						}
					}
					if !ok {
						missing = append(missing, fmt.Sprintf("%s: %s imports %s; declare it on %s", goos, rel, m, strings.Join(cands, " or ")))
					}
				}
			}
		}
		for _, msg := range uniqueSorted(missing) {
			t.Errorf("%s: undeclared module edge: %s", b, msg)
		}
		if testing.Short() {
			// -short analyses linux only, so a module a component imports
			// only on windows or darwin (go-winio, dpapi, x/sys) cannot be
			// judged stale.
			continue
		}
		for _, c := range components.ForBinary(b) {
			if !present[c.ID] {
				continue
			}
			for _, m := range c.DirectModules {
				if !used[c.ID][m] {
					t.Errorf("%s: %s declares %s but none of its packages imports it directly", b, c.ID, m)
				}
			}
		}
	}
}

// TestComponentsL1PackageAbsence is the L1 proof (plan 3.2 item 1) and the
// only one the plan accepts: building a component's binary with its omit tag
// must leave every package it owns out of the go list -deps closure.
//
// It runs for EVERY component whose target includes L1, not only for the
// ones that claim it (phase PB, lane MP-BND: "the package-absence test
// running, red rows allowed, each one a PB work item"):
//
//   - a component that CLAIMS L1 (Levels.Implemented) must be absent with
//     its tag on every GOOS, and must have no componentsFenceBaseline entry
//     left: a package that core still imports cannot leave the binary, so a
//     claim over open fence debt is refused even if a stub happens to hide
//     it;
//   - a component that only TARGETS L1 and is still present with its tag is
//     a red row. Red rows are a ratchet in componentsAbsenceRed: a new red
//     row fails (an L1 target was added without sign-off), and a listed row
//     that turns green fails too (delete it; the component may now claim
//     L1).
//
// Cost: a tag can only change the dependency graph through a file whose
// build constraint names it, so go list is re-run only for tags some file
// mentions; every other tagged closure is the default closure, already
// cached. The scan reads build constraints, never trusts the catalog.
func TestComponentsL1PackageAbsence(t *testing.T) {
	root := repoRoot(t)
	tagged := buildTagsInTree(t, root)
	fenceDebt := map[string]int{}
	for _, k := range componentsFenceBaseline {
		if i := strings.LastIndex(k, " ("); i >= 0 {
			fenceDebt[strings.TrimSuffix(k[i+2:], ")")]++
		}
	}
	red := map[string]bool{}
	for _, c := range components.All() {
		if !c.Levels.Targets(components.L1) || len(c.Packages) == 0 {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(c.Binary.CmdPath()))); err != nil {
			continue // binary stripped from this tree (public tree)
		}
		claims := c.Levels.Has(components.L1)
		if claims && fenceDebt[c.ID] > 0 {
			t.Errorf("%s claims L1 but has %d componentsFenceBaseline entries left: core still imports its packages", c.ID, fenceDebt[c.ID])
		}
		tags := ""
		if tagged[c.BuildTag()] {
			tags = c.BuildTag()
		}
		for _, goos := range binaryGOOS(c.Binary) {
			g := goListDeps(t, c.Binary.CmdPath(), goos, tags)
			for _, p := range c.Packages {
				if !g.hasRel(p) {
					continue
				}
				if claims {
					t.Errorf("%s claims L1 but %s stays in %s with -tags %s (%s)", c.ID, p, c.Binary.CmdPath(), c.BuildTag(), goos)
				}
				red[c.ID] = true
			}
		}
	}
	listed := map[string]bool{}
	for _, id := range componentsAbsenceRed {
		listed[id] = true
	}
	var got []string
	for id := range red {
		got = append(got, id)
		if c, _ := components.Get(id); !listed[id] && !c.Levels.Has(components.L1) {
			t.Errorf("new red absence row (an L1-target component still present with its omit tag; needs the orchestrator's sign-off to list): %s", id)
		}
	}
	sort.Strings(got)
	if testing.Short() {
		return // linux only: a windows/darwin-only package cannot be judged
	}
	for _, id := range componentsAbsenceRed {
		if !red[id] {
			t.Errorf("stale absence row (%s is now absent with %s; delete it from componentsAbsenceRed, it may claim L1)", id, components.BuildTagFor(id))
		}
	}
	if os.Getenv("SBO_COMPONENTS_PRINT_ABSENCE") != "" {
		for _, id := range got {
			fmt.Printf("\t%q,\n", id)
		}
	}
}

// buildTagsInTree returns every sbo_omit_* tag named in a //go:build line of
// a Go file under root (vendored and generated web trees skipped).
func buildTagsInTree(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	re := regexp.MustCompile(`sbo_omit_[A-Za-z0-9_]+`)
	skip := map[string]bool{"node_modules": true, ".git": true, "testdata": true, "web": true, "web2": true, "webcloud": true, "website": true}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skip[d.Name()] && (filepath.Dir(path) == root || d.Name() == "node_modules" || d.Name() == ".git") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "package ") {
				break
			}
			if strings.HasPrefix(line, "//go:build") {
				for _, m := range re.FindAllString(line, -1) {
					out[m] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan build tags: %v", err)
	}
	return out
}
