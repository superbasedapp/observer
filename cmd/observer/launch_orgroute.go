package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// launch_orgroute.go is the managed-node base-URL rewrite (surface-gap arc
// finding CLI-8, operator decision D13, 2026-10-25). applyBaseURLEnv keeps a
// developer's own non-empty base-URL value ("using yours"). That stays the
// rule on an individual node. On a managed node whose organization owns the
// AI tools' proxy routes (govern.Effective.RoutePosture is maintain: the
// admin's proxy.maintain_routes pin is ON, or unset with a proxy-resident
// enforce authority), the organization decides: a preset value that points
// anywhere but the launcher's own proxy URL is rewritten to it for this run,
// the launcher says so, and the launch evidence records the rewritten keys.
//
// Never on an unreachable proxy: rewriting a working endpoint to a proxy
// that is not listening would only break the run, so the preset stays and the
// launcher's unreachable notice and the managed budget gate decide as before.

// baseURLRewrite is one preset the organization's route replaced.
type baseURLRewrite struct {
	Key string
	// Was is the developer's value (a base URL, never a secret; callers pass
	// only base-URL keys to applyBaseURLEnv).
	Was string
}

// rewriteManagedPresets replaces, in env, every entry of each preset key
// whose value differs from inject's with inject's value. Only a BASE-URL
// key is rewritten: both the preset and the launcher's value must be
// http(s) URLs with a host (isBaseURLValue), so a non-URL routing key the
// launcher also sets (a provider type, a model) keeps the developer's
// value and the managed budget gate judges the route as before. A preset
// equal to the launcher's own value is kept as a preset. It returns the
// env, the presets that remain, and the rewrites in key order. Pure.
func rewriteManagedPresets(env []string, inject map[string]string, presets []string) (out, kept []string, rewrote []baseURLRewrite) {
	out = append([]string(nil), env...)
	for _, k := range presets {
		want, ok := inject[k]
		was := envValue(out, k)
		if !ok || strings.TrimSpace(want) == "" || was == want || !isBaseURLValue(want) || !isBaseURLValue(was) {
			kept = append(kept, k)
			continue
		}
		for i, kv := range out {
			if j := strings.IndexByte(kv, '='); j > 0 && kv[:j] == k {
				out[i] = k + "=" + want
			}
		}
		rewrote = append(rewrote, baseURLRewrite{Key: k, Was: was})
	}
	sort.Slice(rewrote, func(a, b int) bool { return rewrote[a].Key < rewrote[b].Key })
	return out, kept, rewrote
}

// isBaseURLValue reports whether v is an http(s) URL with a host.
func isBaseURLValue(v string) bool {
	u, err := url.Parse(strings.TrimSpace(v))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// printableBaseURL renders a base URL for a stderr notice without anything
// that can carry a secret: userinfo, the query and the fragment are dropped
// and a route token path is masked (redactRouteURL). A value that does not
// parse is not printed.
func printableBaseURL(v string) string {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || u.Host == "" {
		return "(a value that is not a URL)"
	}
	u.User, u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = nil, "", false, "", ""
	return redactRouteURL(u.String())
}

// launchOrgOwnsRoute reports whether this node's organization owns the AI
// tools' proxy routes (route posture maintain). It reads the config first
// and opens the database only when the verified org lock records managed
// tenancy (governanceEffectiveIfManaged), so a launch on an individual node
// never opens one. Any read failure answers false: the preset stays, which
// is today's behaviour, and the managed budget gate still refuses a launch a
// hard cap needs controlled. A seam for tests.
var launchOrgOwnsRoute = func(ctx context.Context, configPath string) bool {
	eff, ok := governanceEffectiveIfManaged(ctx, configPath)
	return ok && eff.RoutePosture().Posture == govern.RoutePostureMaintain
}

// governanceEffectiveIfManaged is governanceEffectiveFor behind the cheap
// gate every lane w6-governance check takes first: the config's verified
// org lock must record managed tenancy (config.GuardOrgLock TenancyKnown and
// Managed), else ok is false and no database is opened.
func governanceEffectiveIfManaged(ctx context.Context, configPath string) (govern.Effective, bool) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil || !cfg.Guard.Lock.TenancyKnown || !cfg.Guard.Lock.Managed {
		return govern.Effective{}, false
	}
	eff, err := governanceEffectiveFor(ctx, configPath)
	if err != nil {
		return govern.Effective{}, false
	}
	return eff, true
}

// governanceEffectiveFor resolves this node's live governance posture from a
// cold CLI process (the identity loader plus the last-known-good body, as
// the daemon resolves it), for the launcher and applier gates of lane
// w6-governance.
func governanceEffectiveFor(ctx context.Context, configPath string) (govern.Effective, error) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return govern.Effective{}, err
	}
	defer cleanup()
	return enterpriseContentEffective(ctx, cfg, store.New(database), slog.New(slog.DiscardHandler)), nil
}

// applyManagedPresetRewrite runs the CLI-8 rule over a launcher's merged env:
// nothing to do without presets or on an unrouted launch; otherwise, when
// the organization owns the route and the proxy answers, the presets that
// point elsewhere are rewritten and each rewrite is printed. It returns the
// env, the presets still kept and the rewritten keys.
func applyManagedPresetRewrite(ctx context.Context, w io.Writer, tool, configPath, proxyURL string, env []string, inject map[string]string, presets []string, unrouted bool) ([]string, []string, []string) {
	if len(presets) == 0 || unrouted || !launchOrgOwnsRoute(ctx, configPath) || !proxyReachable(proxyURL, 250*time.Millisecond) {
		return env, presets, nil
	}
	out, kept, rewrote := rewriteManagedPresets(env, inject, presets)
	keys := make([]string, 0, len(rewrote))
	for _, r := range rewrote {
		fmt.Fprintf(w, "observer %s: %s was %s; your organization routes AI tools through the Observer proxy on this managed machine, so this run uses %s.\n",
			tool, r.Key, printableBaseURL(r.Was), printableBaseURL(inject[r.Key]))
		keys = append(keys, r.Key)
	}
	return out, kept, keys
}
