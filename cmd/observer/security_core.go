package main

import (
	"log/slog"
	"strings"
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// security_core.go is the security pillar's core residue in the daemon
// (security pillar plan section 4.3): compiled into every build, including
// sbo_omit_security, because the hook reads the guard posture's signed
// module state whether or not the module is in this build.

// daemonSecurityActive is whether the security module was active when this
// daemon started (the module's RestartClass is "restart"). The guard
// posture writer signs it in, so a hook reads a missing security posture
// file as unknown only while the module really is active.
var daemonSecurityActive atomic.Bool

// daemonSecurityPacks is the active pack set this daemon started with,
// signed into the guard posture beside daemonSecurityActive so the hook
// keeps the right rows firing when a project's own posture file cannot be
// used (lane SEC-GATEFIX).
var daemonSecurityPacks atomic.Pointer[[]string]

// daemonSecurityPackSet returns the pack set to sign (nil while the module
// is not active).
func daemonSecurityPackSet() []string {
	if !daemonSecurityActive.Load() {
		return nil
	}
	if p := daemonSecurityPacks.Load(); p != nil {
		return append([]string(nil), (*p)...)
	}
	return nil
}

// securityTreeIDs returns the catalog ids of the security tree (the root
// and every security.* row), the active pack set's universe.
func securityTreeIDs() []string {
	var out []string
	for _, c := range components.ForBinary(components.BinaryNode) {
		if c.ID == "security" || strings.HasPrefix(c.ID, "security.") {
			out = append(out, c.ID)
		}
	}
	return out
}

// securityActivePacks is the active pack set signed into every posture
// file: the security tree's ids that are selected (securitySelected: active,
// and for the opt-in children of security_optin.go, chosen by a
// [components] block).
func securityActivePacks(snap componentstate.Snapshot) []string {
	var out []string
	for _, id := range securityTreeIDs() {
		if securitySelected(snap, id) {
			out = append(out, id)
		}
	}
	return out
}

// setDaemonSecurityState records the module's state for the guard posture
// and, when the module is not active, deletes every security posture file
// and its key (section 4.3: no sidecar file while inactive). The dirty
// markers and seen marks stay: they are monotonic and hold no findings.
func setDaemonSecurityState(configPath string, snap componentstate.Snapshot, logger *slog.Logger) {
	active := snap.ModuleActive("security")
	packs := securityActivePacks(snap)
	daemonSecurityPacks.Store(&packs)
	daemonSecurityActive.Store(active)
	if active {
		return
	}
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return
	}
	if err := secposture.RemoveAllPostures(secposture.LayoutFor(resolved)); err != nil && logger != nil {
		logger.Warn("security: could not remove the inactive module's posture files", "err", err)
	}
}
