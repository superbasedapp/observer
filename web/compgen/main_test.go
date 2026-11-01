package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// TestGeneratedRegistryIsCurrent is the drift gate: the committed
// web/src/lib/components.gen.ts equals the generator's default output.
func TestGeneratedRegistryIsCurrent(t *testing.T) {
	want, err := render("")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../src/lib/components.gen.ts")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("web/src/lib/components.gen.ts is stale: run go run ./web/compgen")
	}
}

// TestPagesNameNodeComponents: every page names core or a node component,
// and every page module and path is unique.
func TestPagesNameNodeComponents(t *testing.T) {
	seenPath, seenNav := map[string]bool{}, map[string]bool{}
	for _, p := range pages {
		if p.Component != "core" {
			c, ok := components.Get(p.Component)
			if !ok || c.Binary != components.BinaryNode {
				t.Errorf("page %s names %q, not a node component", p.Module, p.Component)
			}
		}
		if seenPath[p.Path] {
			t.Errorf("duplicate path %q", p.Path)
		}
		seenPath[p.Path] = true
		if p.NavID != "" {
			if seenNav[p.NavID] {
				t.Errorf("duplicate nav id %q", p.NavID)
			}
			seenNav[p.NavID] = true
		}
	}
}

// TestPagesCoverNav: every nav item in web/src/lib/nav.ts has a page row,
// so a new page cannot be routed outside the registry.
func TestPagesCoverNav(t *testing.T) {
	raw, err := os.ReadFile("../src/lib/nav.ts")
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, p := range pages {
		have[p.NavID] = true
	}
	for _, line := range strings.Split(string(raw), "\n") {
		i := strings.Index(line, "id: \"")
		if i < 0 || !strings.Contains(line, "path:") && !strings.Contains(line, "costNavItem") {
			continue
		}
		id, _, ok := strings.Cut(line[i+5:], "\"")
		if !ok {
			continue
		}
		if !have[id] {
			t.Errorf("nav item %q has no page row in web/compgen", id)
		}
	}
	if !have["cost"] {
		t.Error("the cost page has no row")
	}
}

// TestDistroDropsAbsentPages: a minimal build's registry carries no page of
// a component minimal does not compile, and keeps every core page.
func TestDistroDropsAbsentPages(t *testing.T) {
	src, err := render(components.DistroMinimal)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pages {
		in := strings.Contains(string(src), "\"@/pages/"+p.Module+"\"")
		want := inDistro(p, components.DistroMinimal)
		if in != want {
			t.Errorf("minimal registry has %s = %v, want %v", p.Module, in, want)
		}
		if p.Component == "core" && !in {
			t.Errorf("core page %s dropped", p.Module)
		}
	}
	if _, err := render("nope"); err == nil {
		t.Error("an unknown distro must be refused")
	}
}

// pageSources returns the source of a page module and of its same-named
// lowercase subdirectory (pages/Policies.tsx plus pages/policies/*.tsx).
func pageSources(t *testing.T, module string) string {
	t.Helper()
	var b strings.Builder
	for _, name := range []string{"../src/pages/" + module + ".tsx", "../src/pages/" + module + "/index.tsx"} {
		if raw, err := os.ReadFile(name); err == nil {
			b.Write(raw)
		}
	}
	sub := "../src/pages/" + strings.ToLower(module)
	if entries, err := os.ReadDir(sub); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".tsx") && !strings.HasSuffix(e.Name(), ".ts") {
				continue
			}
			if strings.Contains(e.Name(), ".test.") {
				continue
			}
			raw, err := os.ReadFile(sub + "/" + e.Name())
			if err != nil {
				t.Fatal(err)
			}
			b.Write(raw)
		}
	}
	if b.Len() == 0 {
		t.Fatalf("no source found for page module %s", module)
	}
	return b.String()
}

// TestPagesFollowThePlaneSplit (T-671) pins page ownership to the plane
// split in CLAUDE.md and docs/deployment-models.md, from what each page
// actually fetches: a page that reads Plane A observability (/api/obs) is
// owned by obs, a page that reads the Plane B guard (/api/guard) is never
// owned by obs (so the developer distro, which omits obs under D-389,
// keeps every developer guardrail page), and an obs page reads no guard
// route.
func TestPagesFollowThePlaneSplit(t *testing.T) {
	sawObs, sawGuard := false, false
	for _, p := range pages {
		src := pageSources(t, p.Module)
		readsObs := strings.Contains(src, "/api/obs/")
		readsGuard := strings.Contains(src, "/api/guard/")
		sawObs = sawObs || readsObs
		sawGuard = sawGuard || readsGuard
		if readsObs && p.Component != "obs" {
			t.Errorf("page %s reads /api/obs (Plane A) but is owned by %q", p.Module, p.Component)
		}
		if readsGuard && p.Component == "obs" {
			t.Errorf("page %s reads /api/guard (Plane B) but is owned by obs; it would leave the developer distro", p.Module)
		}
		if p.Component == "obs" && !readsObs {
			t.Errorf("page %s is owned by obs but reads no /api/obs route", p.Module)
		}
	}
	if !sawObs || !sawGuard {
		t.Fatalf("the plane split test lost its subjects (obs=%v guard=%v)", sawObs, sawGuard)
	}
}

// TestFeaturesAreGatedPerDistro: a component-owned feature module is a lazy
// component where the distro compiles its owner and null where it does not,
// so the minimal bundle carries no LaunchTerminal (and so no xterm chunk).
func TestFeaturesAreGatedPerDistro(t *testing.T) {
	for _, f := range features {
		if c, ok := components.Get(f.Component); !ok || c.Binary != components.BinaryNode {
			t.Errorf("feature %s names %q, not a node component", f.Const, f.Component)
		}
	}
	minimal, err := render(components.DistroMinimal)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(minimal), "export const LAUNCH_TERMINAL: LazyExoticComponent<typeof import(\"@/components/LaunchTerminal\").LaunchTerminal> | null = null;") {
		t.Error("the minimal registry must export LAUNCH_TERMINAL as null")
	}
	if strings.Contains(string(minimal), "import(\"@/components/LaunchTerminal\").then") {
		t.Error("the minimal registry still imports LaunchTerminal")
	}
	full, _ := render("")
	if !strings.Contains(string(full), "import(\"@/components/LaunchTerminal\").then") {
		t.Error("the full registry must import LaunchTerminal lazily")
	}
}

// TestProofTable: each distro forbids exactly the pages, features and
// packages of the components it does not compile; full forbids nothing.
func TestProofTable(t *testing.T) {
	has := func(xs []string, x string) bool {
		for _, v := range xs {
			if v == x {
				return true
			}
		}
		return false
	}
	cases := []struct {
		d                components.Distro
		forbid, allow    []string
		forbidPk, allowP []string
	}{
		{
			components.DistroMinimal,
			[]string{"src/pages/Terminals", "src/pages/Remote", "src/components/LaunchTerminal", "src/pages/CodeSecurity"},
			[]string{"src/pages/Overview"},
			[]string{"@xterm/xterm", "@xterm/addon-fit", "react-grid-layout", "qrcode"},
			nil,
		},
		{
			components.DistroManaged,
			[]string{"src/pages/Remote"},
			[]string{"src/pages/Terminals", "src/components/LaunchTerminal"},
			[]string{"qrcode"},
			[]string{"@xterm/xterm"},
		},
		{components.DistroDeveloper, nil, []string{"src/pages/Terminals", "src/pages/Remote", "src/pages/CodeSecurity"}, nil, []string{"@xterm/xterm", "qrcode"}},
		{"", nil, []string{"src/pages/Terminals"}, nil, []string{"@xterm/xterm"}},
	}
	for _, c := range cases {
		pr := buildProof(c.d)
		for _, x := range c.forbid {
			if !has(pr.ForbiddenSources, x) {
				t.Errorf("%s: %s not forbidden", pr.Distro, x)
			}
		}
		for _, x := range c.allow {
			if has(pr.ForbiddenSources, x) {
				t.Errorf("%s: %s forbidden", pr.Distro, x)
			}
		}
		for _, x := range c.forbidPk {
			if !has(pr.ForbiddenPackage, x) {
				t.Errorf("%s: package %s not forbidden", pr.Distro, x)
			}
		}
		for _, x := range c.allowP {
			if has(pr.ForbiddenPackage, x) {
				t.Errorf("%s: package %s forbidden", pr.Distro, x)
			}
		}
	}
	if pr := buildProof(""); pr.Distro != "full" || len(pr.ForbiddenSources)+len(pr.ForbiddenPackage) != 0 {
		t.Errorf("full: %+v", pr)
	}
}
