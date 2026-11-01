package main

import (
	"sort"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// security_keepingbases.go computes R-165's base check for this binary
// (plans decision log P-045): which prebuilt base selections keep active
// every code security component, and every component the security tree
// requires, that THIS binary compiles in and runs today. The policy package
// reads neither the catalog nor the compiled set, so the binary computes
// the list once, on first use, and injects it.

func init() {
	policy.SetSecurityKeepingBases(thisBuildKeepingBases)
}

// thisBuildKeepingBases is this binary's list: its own compiled set, and
// what it runs on an install with no [components] block.
var thisBuildKeepingBases = sync.OnceValue(func() []string {
	return securityKeepingBasesFor(nil, componentstate.Resolve(config.ComponentsConfig{}, nil))
})

// securityKeepingBasesFor returns the prebuilt distros whose selection
// keeps active every watched component (the security tree and what it
// requires) that today runs. compiled is the build's compiled set (nil:
// this binary's); a distro is resolved against it, so a component the
// build does not compile is never one a selection could drop.
func securityKeepingBasesFor(compiled []string, today componentstate.Snapshot) []string {
	var running []string
	for _, id := range securityWatchedIDs() {
		if securityRunning(today, id) {
			running = append(running, id)
		}
	}
	var out []string
	for _, d := range components.Distros() {
		snap := componentstate.Resolve(config.ComponentsConfig{Distro: string(d)}, compiled)
		keeps := true
		for _, id := range running {
			if !snap.ModuleActive(id) {
				keeps = false
				break
			}
		}
		if keeps {
			out = append(out, string(d))
		}
	}
	return out
}

// securityRunning reports whether a watched component runs in snap: a
// security child with the opt-in rule applied, anything else when active.
func securityRunning(snap componentstate.Snapshot, id string) bool {
	if isSecurityTreeID(id) {
		return securitySelected(snap, id)
	}
	return snap.ModuleActive(id)
}

// isSecurityTreeID reports whether id is the security module or a child.
func isSecurityTreeID(id string) bool {
	return id == "security" || strings.HasPrefix(id, "security.")
}

// securityWatchedIDs are the security tree's ids and every id it requires,
// directly or through another component, from the catalog.
func securityWatchedIDs() []string {
	byID := map[string]components.Component{}
	for _, c := range components.All() {
		byID[c.ID] = c
	}
	seen := map[string]bool{}
	var walk func(id string)
	walk = func(id string) {
		if seen[id] {
			return
		}
		seen[id] = true
		for _, r := range byID[id].Requires {
			walk(r)
		}
	}
	for id := range byID {
		if isSecurityTreeID(id) {
			walk(id)
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
