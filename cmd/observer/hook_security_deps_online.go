//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/secask"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// hookOnlineSources returns the online half of the hook's install gate
// (security plan section 8.3 "The hook path"): the cache file the daemon
// maintains, and the ask over the owner-only local IPC within the
// install-gate wait. The hook dials nothing but the daemon, which classifies
// each name again with its own configuration and environment and answers a
// private one as private, unsent. The settings the hook needs
// (the wait, the minimum age) come from the daemon's settings file; while
// it is missing the defaults apply.
func hookOnlineSources(ctx context.Context, resolved string, req hookctx.InstallRequest) hookOnline {
	dir := secposture.LayoutFor(resolved).Dir
	set := readDepsHookSettings(dir)
	// The hook classifies with the files of every directory the install
	// reads its configuration from, and the developer's source-naming
	// variables only ever restrict: a name it cannot call public is never
	// asked about and never called a near miss; the daemon classifies again
	// (its own environment and the scope's) before anything is sent. The
	// environment comes through the hook context: the hook process's own
	// on the host path, only the frame's declared variables on the relay.
	scope := hookDepsScope(req, hookctx.From(ctx).Environ())
	on := hookOnline{minAge: set.minAge(), maxAge: set.maxAge(), public: hookDepsClassifier(scope)}
	now := time.Now()
	if b, err := readDepsFile(filepath.Join(dir, depsCacheFile), secfeed.MaxCacheFileBytes); err == nil {
		if c, err := secfeed.DecodeCacheFile(b, now); err == nil {
			on.cache = c.Lookup
		}
	}
	if !set.Ask {
		return on
	}
	ep, err := secask.Endpoint(dir)
	if err != nil {
		return on
	}
	wait := set.wait()
	on.ask = func(ctx context.Context, specs []secfeed.InstallSpec) ([]secfeed.OnlineAnswer, error) {
		return depsAskOrOffline(secask.Ask(ctx, ep, scope, specs, wait))(specs)
	}
	return on
}

// depsAskOrOffline maps a daemon that did not understand the ask (an older
// daemon left running across an upgrade, secask.ErrNotUnderstood) to "not
// asked" for every spec, so the hook keeps its own offline answer instead
// of an ask failure (S-748 under enforce) on every public install (lane
// SEC-DEPS3 item 11). Any other result passes through.
func depsAskOrOffline(answers []secfeed.OnlineAnswer, err error) func([]secfeed.InstallSpec) ([]secfeed.OnlineAnswer, error) {
	return func(specs []secfeed.InstallSpec) ([]secfeed.OnlineAnswer, error) {
		if !errors.Is(err, secask.ErrNotUnderstood) {
			return answers, err
		}
		out := make([]secfeed.OnlineAnswer, 0, len(specs))
		for _, s := range specs {
			out = append(out, secfeed.OnlineAnswer{Eco: s.Eco, Name: secfeed.Normalize(s.Eco, s.Name), Version: s.Version, Status: secfeed.OnlineNotAsked})
		}
		return out, nil
	}
}

// readDepsFile reads one of Observer's own state files, capped, without
// following a symlink at the final element.
func readDepsFile(path string, limit int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, os.ErrInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, os.ErrInvalid
	}
	return b, nil
}

// readDepsHookSettings reads the daemon's settings file for the hook.
func readDepsHookSettings(dir string) depsHookSettings {
	b, err := readDepsFile(filepath.Join(dir, depsSettingsFile), 4096)
	if err != nil {
		return depsHookSettings{}
	}
	return decodeDepsHookSettings(b)
}
