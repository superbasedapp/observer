package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// components_require_test.go: the constraints a test of this package carries
// when it exercises a component (lane MP-GOV3, the MP-L1D remainder). The
// omit-tag CI job (scripts/omit-tag-check.sh) runs this package under every
// distro tag set; a stamped distro build (minimal, developer, managed) starts
// an unconfigured node from its distro's default set rather than from every
// compiled component, so a test that needs, say, the MCP server or the
// claude-code adapter active says so here and is skipped (with the reason)
// where the build leaves it inactive. A plain (full) build resolves every
// compiled component active with no [components] block, so none of these ever
// skips there: the full product's coverage is unchanged.

// defaultSnapshot is the component resolution of an unconfigured node in
// this binary (no [components] block, no governance).
func defaultSnapshot() componentstate.Snapshot {
	return componentstate.Resolve(config.ComponentsConfig{}, nil)
}

// defaultActive reports whether id is active on an unconfigured node.
func defaultActive(id string) bool { return defaultSnapshot().Active(id) }

// requireComponents skips t unless every id is active on an unconfigured
// node of this build (compiled in, and in the default set of a stamped
// distro).
func requireComponents(t *testing.T, ids ...string) {
	t.Helper()
	snap := defaultSnapshot()
	for _, id := range ids {
		if !snap.Active(id) {
			t.Skipf("needs component %s, which is not active by default in this build (distro %q)", id, components.BuildDistro())
		}
	}
}

// requireActiveAdapters is requireComponents for adapter rows by tool name.
func requireActiveAdapters(t *testing.T, tools ...string) {
	t.Helper()
	ids := make([]string, 0, len(tools))
	for _, tool := range tools {
		ids = append(ids, components.AdapterID(tool))
	}
	requireComponents(t, ids...)
}

// requireCompiled skips t unless every id is offered by this build (compiled
// in and, in a stamped distro, part of it), whether or not it is active by
// default: for tests that select or govern the component themselves.
func requireCompiled(t *testing.T, ids ...string) {
	t.Helper()
	offered := map[string]bool{}
	for _, id := range components.Compiled(components.BinaryNode) {
		offered[id] = true
	}
	for _, id := range ids {
		if !offered[id] {
			t.Skipf("needs component %s, which this build does not contain (distro %q)", id, components.BuildDistro())
		}
	}
}

// compiledOut reports whether an omit tag removed component id from this
// test binary (its omit file called components.MarkOmitted), itself or with
// its module root: a child (security.githooks) of an omitted root
// (security) is gone with it, its verbs under the root's compiled-out
// stand-in, though only the root's omit file marks anything. Tests use it
// to assert the build's "not in this build" answer instead of the full
// behaviour (D-535).
func compiledOut(id string) bool {
	omitted := components.Omitted()
	for cur := id; cur != ""; {
		if slices.Contains(omitted, cur) {
			return true
		}
		i := strings.LastIndexByte(cur, '.')
		if i < 0 {
			break
		}
		cur = cur[:i]
	}
	return false
}

// unstampedBuild reports a plain build (the full product), whose unconfigured
// node keeps the legacy "everything compiled is active" base.
func unstampedBuild() bool { return components.BuildDistro() == "" }

// requireUnstampedBuild skips a test that pins that legacy base, which a
// stamped distro build replaces by design with its distro's default set.
func requireUnstampedBuild(t *testing.T) {
	t.Helper()
	if !unstampedBuild() {
		t.Skipf("pins the plain build's legacy everything-active base; this build is stamped %q", components.BuildDistro())
	}
}

// requireSimulatedDistro skips a test that drives the chooser with a fake
// snapshot of other distros (componentstate.ResolveGoverned over
// components.InDistro(d)) when the test binary is stamped with a different
// one: a stamped build's own distro replaces the snapshot's base by design
// (componentstate.ResolveGoverned), so the simulated distro is not what
// the chooser sees. A plain build simulates every distro; a stamped build
// still runs the rows for its own distro.
func requireSimulatedDistro(t *testing.T, distros ...components.Distro) {
	t.Helper()
	stamp := components.BuildDistro()
	if stamp == "" {
		return
	}
	for _, d := range distros {
		if d != stamp {
			t.Skipf("simulates distro %q; this build is stamped %q, whose own distro is the base the chooser sees", d, stamp)
		}
	}
}

// requireFullCompiledBuild skips a test that pins the plain build's FULL
// base: an unstamped build with nothing omitted. An omit tag (or the public
// tree, where obs is compiled out) makes the build's own distro developer or
// custom, so a "full" expectation does not hold there by design (T-767).
func requireFullCompiledBuild(t *testing.T) {
	t.Helper()
	requireUnstampedBuild(t)
	if om := components.Omitted(); len(om) > 0 {
		t.Skipf("pins the plain full build; this build omits %v", om)
	}
}

// TestComponentRequirementsNeverSkipAFullBuild pins the promise above: in a
// plain build every compiled component is active by default, so no
// requireComponents call can skip there.
func TestComponentRequirementsNeverSkipAFullBuild(t *testing.T) {
	if !unstampedBuild() || len(components.Omitted()) > 0 {
		t.Skip("a stamped distro build, or a build with an omit tag, may leave a component inactive by design")
	}
	snap := defaultSnapshot()
	for _, id := range components.Compiled(components.BinaryNode) {
		if !snap.Active(id) {
			t.Errorf("%s is compiled but not active by default in a plain build", id)
		}
	}
}

// selectIfInactive adds ids to cfg's [components] block when an unconfigured
// node of this build leaves them inactive (a published edition starts from
// its own default set, which may not hold the module a test exercises), so
// the test still exercises the active module in every edition; in a build
// where they are active by default (the full build) cfg is left unchanged.
// An id this build does not offer cannot be selected and fails the test:
// such a test needs the component's omit tag instead.
func selectIfInactive(t *testing.T, cfg *config.Config, ids ...string) {
	t.Helper()
	offered := components.Compiled(components.BinaryNode)
	for _, id := range ids {
		if defaultActive(id) {
			continue
		}
		if !slices.Contains(offered, id) {
			t.Fatalf("component %s is not offered by this build (distro %q): the test needs its omit tag", id, components.BuildDistro())
		}
		if !slices.Contains(cfg.Components.Add, id) {
			cfg.Components.Add = append(cfg.Components.Add, id)
		}
	}
}

// selectionTOMLIfInactive is selectIfInactive for a test that writes its
// config file: the [components] lines that select ids where this edition
// leaves them inactive by default, or "" (the full build's file unchanged).
func selectionTOMLIfInactive(t *testing.T, ids ...string) string {
	t.Helper()
	var cfg config.Config
	selectIfInactive(t, &cfg, ids...)
	if len(cfg.Components.Add) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(cfg.Components.Add))
	for _, id := range cfg.Components.Add {
		quoted = append(quoted, `"`+id+`"`)
	}
	return "\n[components]\nadd = [" + strings.Join(quoted, ", ") + "]\n"
}

// securityInertByDefault reports a published edition whose unconfigured
// node leaves the security module inactive: the managed edition, inert until
// the organization's policy allows it (security pillar plan section 6.5).
// A test of what an install with no [components] block sees asserts that
// inert answer there; everywhere else (the full and developer builds) the
// module is active with no block, as such a test assumes.
func securityInertByDefault() bool { return !defaultActive("security") }
