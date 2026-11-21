//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// hook_security_deps.go is the install gate's hook-side provider (security
// pillar plan sections 5.4 and 8.3): for an agent's install command or a
// manifest edit it reads the offline index the daemon installed, decides
// each package through secfeed.Gate and stamps the checks into
// Event.Security, where S-741 to S-748 decide. The hook never makes a
// network call (security plan section 8.3 "The hook path").

// hookInstallLimit caps the whole install check in the hook: the index
// load plus the install-gate wait (default 1.5 s, picker up to 3 s), plus a
// margin. A check that overruns records unknown, never clean.
const hookInstallLimit = 4 * time.Second

// securityInstallChecker returns the hook's install provider.
func securityInstallChecker(configPath string) hookctx.InstallChecker {
	return func(ctx context.Context, req hookctx.InstallRequest) (hookctx.InstallResult, error) {
		specs, registry, manifest := secfeed.EventSpecs(req.Event)
		if len(specs) == 0 && !registry {
			return hookctx.InstallResult{}, nil
		}
		resolved, err := config.ResolveGlobalPath(configPath)
		if err != nil {
			return hookctx.InstallResult{}, err
		}
		store := depsContentStore(resolved)
		if depsNotSetUp(store, secposture.LayoutFor(resolved).Dir) {
			// Not set up: nothing checks a package yet, so a custom
			// registry is not flagged either (S-745 stays quiet until the
			// gate is set up; lane SEC-D1FIX2 milestone 2d).
			checks := notSetUpChecks(specs, secposture.LayoutFor(resolved).Dir, req.Event.SessionID)
			return hookctx.InstallResult{Checks: checks, Manifest: manifest}, nil
		}
		online := hookOnlineSources(ctx, resolved, req)
		ix, fresh := loadInstallIndexCachedFloor(store, depsTrust(), online.maxAge)
		checks := secfeed.Gate(ctx, secfeed.GateInput{
			Specs: specs, Index: ix, IndexFreshness: fresh,
			Public: online.public, Cache: online.cache, Ask: online.ask,
			MinAge: online.minAge, Now: time.Now(),
		})
		// The node's unknown-package actions (lane LEFT-SEC): the daemon's
		// settings file carries them, floors applied.
		checks = readDepsHookSettings(secposture.LayoutFor(resolved).Dir).stampActions(checks)
		return hookctx.InstallResult{Checks: checks, CustomRegistry: registry, Manifest: manifest}, nil
	}
}

// hookOnline is what the online half of the gate gets in the hook: the
// classifier, the hook-readable cache and the daemon ask. Each is nil
// until it is available, which keeps every name off the online path.
type hookOnline struct {
	public secfeed.Classifier
	cache  secfeed.CacheLookup
	ask    secfeed.Asker
	minAge time.Duration
	// maxAge is the index age floor in force (lane SEC-E4; 0: the kind's).
	maxAge time.Duration
}

// securityDepsEnrich runs the install check for an event after the hook
// context was filled, when the posture says the install gate's pack is
// active.
func securityDepsEnrich(ctx context.Context, hc *hookctx.Context, pe *policy.Event, projectRoot string) {
	if hc == nil || !depsPackActive(hc.Security) {
		return
	}
	hc.CheckInstall(ctx, hookctx.InstallRequest{ProjectRoot: projectRoot, Event: pe})
}

// depsNotSetUp reports the "package checks not set up" state (milestone
// 3a): no signed index was ever installed, and online checks are off or
// not yet disclosed. Nothing can check a package then, so an install is
// not flagged S-744 every time: it gets one quiet note per session.
func depsNotSetUp(store contentchan.Store, dir string) bool {
	if st, err := store.State(content.MaliciousPackages); err != nil || st.Accepted != nil {
		// An index was installed (or its state cannot be read, which is a
		// fault to report, not a setup step): the full gate runs.
		return false
	}
	set := readDepsHookSettings(dir)
	return !set.Online || !readDepsDisclosure(dir).Shown()
}

// depsNotesDir holds one marker per session that has had its note.
const depsNotesDir = "deps-notes"

// notSetUpChecks answers every spec not checked (reason not_set_up), except
// that the first install of a session carries one S-744 flag on its first
// package: the quiet note that package checks are not set up yet. With no
// session id there is no note.
func notSetUpChecks(specs []secfeed.InstallSpec, dir, sessionID string) []policy.InstallCheck {
	out := make([]policy.InstallCheck, 0, len(specs))
	note := sessionID != "" && firstNoteThisSession(dir, sessionID)
	for _, s := range specs {
		c := policy.InstallCheck{Ecosystem: string(s.Eco), Name: secfeed.SafeName(s.Name), Version: secfeed.SafeName(s.Version), Private: s.Private, Reason: secfeed.ReasonNotSetUp}
		if s.Invalid {
			c.Name, c.Reason = secfeed.SafeName(s.Spec), secfeed.ReasonInvalidLocation
		} else if note {
			c.Verdict, c.Source, note = policy.InstallUnknownName, policy.InstallSourceNone, false
		}
		out = append(out, c)
	}
	return out
}

// firstNoteThisSession creates the session's marker and reports whether it
// was new. Markers older than a week are pruned when there are many.
func firstNoteThisSession(dir, sessionID string) bool {
	nd := filepath.Join(dir, depsNotesDir)
	if err := os.MkdirAll(nd, 0o700); err != nil { //nolint:gosec // G703: false positive; the notes dir under the caller's own state dir, a fixed name
		return false
	}
	sum := sha256.Sum256([]byte(sessionID))
	f, err := os.OpenFile(filepath.Join(nd, hex.EncodeToString(sum[:8])), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G703: false positive; a hex digest of the session id under the fixed notes dir
	if err != nil {
		return false
	}
	_ = f.Close()
	if ents, err := os.ReadDir(nd); err == nil && len(ents) > 256 {
		cutoff := time.Now().Add(-7 * 24 * time.Hour)
		for _, e := range ents {
			if fi, err := e.Info(); err == nil && fi.ModTime().Before(cutoff) {
				_ = os.Remove(filepath.Join(nd, e.Name())) //nolint:gosec // G703: false positive; an entry ReadDir listed in the notes dir itself
			}
		}
	}
	return true
}
