//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secask"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secfeed/online"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_deps_daemon.go is the daemon side of the install gate (security
// pillar plan sections 8.3 and 8.5, Phase D1): the security.deps.ask loop
// serves the hook's asks over the owner-only local IPC and runs the online
// lookups, and the security.deps.feed loop refreshes the signed index
// through the content channel and prefetches the names active projects
// declare. Both are moduleGates rows (components_gate.go): they start only
// while security.deps is active.
//
// Which source answers is decided per lookup, never once at start and never
// mixed (X19): an individual node gets the public client
// (internal/secfeed/online); a managed node gets only the org relay
// (orgclient.SecurityLookup) and is never handed the public client
// (security plan section 8.3, JSP-11; the zero-request test); a tenancy
// that cannot be read makes no lookup at all. A node that enrols as managed
// while the daemon runs stops using the public client at its next lookup.
// No query of either kind runs before the disclosure has been shown
// (P-011).

// Feed and cache cadence.
const (
	depsFeedEvery       = 6 * time.Hour
	depsFeedRetry       = 15 * time.Minute
	depsCacheKeep       = 7 * 24 * time.Hour
	depsPrefetchPerRoot = 100
	depsLookupBudget    = 3 * time.Second
)

// depsFeedKinds are the content kinds the install gate installs, with the
// artifact each carries.
var depsFeedKinds = []struct {
	kind content.Kind
	name string
}{
	{content.MaliciousPackages, secfeed.MaliciousArtifact},
	{content.PopularNames, secfeed.PopularArtifact},
}

// startSecurityDeps starts the install gate's two loops on ng.
func startSecurityDeps(ctx context.Context, ng *gatedGroup, configPath string, snap componentstate.Snapshot) {
	if !securitySelected(snap, securityDepsComponent) {
		return
	}
	rt := &depsRuntime{configPath: configPath, confirmed: &depsConfirmed{}}
	ng.Go("security.deps.ask", func() error {
		rt.serveAsk(ctx)
		return nil
	})
	ng.Go("security.deps.feed", func() error {
		rt.feedLoop(ctx)
		return nil
	})
}

// depsRuntime is one daemon's install gate.
type depsRuntime struct {
	configPath string
	// client builds the public client (the feed download and, on an
	// individual node, the lookups); nil is the production client. Tests
	// point it at a local server.
	client func() *online.Client
	// confirmed is shared by the two loops: the ask records the names it
	// classified public, the prefetch sends only those.
	confirmed *depsConfirmed
}

// publicClient returns a public client.
func (rt *depsRuntime) publicClient() *online.Client {
	if rt.client != nil {
		return rt.client()
	}
	return online.New(online.Options{})
}

// depsEnv is what both loops open.
type depsEnv struct {
	cfg      config.Config
	st       *store.Store
	dir      string
	managed  bool
	tenancy  func(context.Context) depsTenancy
	lookup   secfeed.Lookup
	cleanup  func()
	logger   *slog.Logger
	disclose secfeed.Disclosure
	// live re-reads [security.deps] while a long-lived loop runs (the ask
	// loop); nil reads cfg as loaded.
	live *depsLiveDeps
}

func (rt *depsRuntime) open(ctx context.Context) (*depsEnv, error) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, rt.configPath)
	if err != nil {
		return nil, err
	}
	resolved, err := config.ResolveGlobalPath(rt.configPath)
	if err != nil {
		cleanup()
		return nil, err
	}
	st := store.New(database)
	env := &depsEnv{cfg: cfg, st: st, dir: secposture.LayoutFor(resolved).Dir, cleanup: cleanup, logger: newLogger(cfg.Observer.LogLevel)}
	env.tenancy = depsTenancyOf(st)
	env.managed = env.tenancy(ctx) == depsManaged
	env.lookup = depsLookupFor(env.tenancy, func() secfeed.Lookup { return publicDepsLookup(rt.publicClient()) }, func() secfeed.Lookup { return relayDepsLookup(ctx, rt.configPath) })
	env.disclose = readDepsDisclosure(env.dir)
	return env, nil
}

// depsTenancy is the node's tenancy as the install gate reads it.
type depsTenancy int

// The tenancies. The zero value is unknown: no lookup of either kind.
const (
	depsTenancyUnknown depsTenancy = iota
	depsIndividual
	depsManaged
)

// depsTenancyOf reads the tenancy per call: managed when the enrolment
// says managed or the signed grant resolves managed (the same loader and
// govern.Resolve pair every other tenancy consumer uses); individual when
// both reads succeed and neither says managed; unknown on any read error.
func depsTenancyOf(st *store.Store) func(context.Context) depsTenancy {
	gov := governanceIdentityLoader(st)
	return func(ctx context.Context) depsTenancy {
		if st == nil {
			return depsTenancyUnknown
		}
		enr, err := st.LoadEnrolment(ctx)
		if err != nil {
			return depsTenancyUnknown
		}
		if enr.IsManaged() {
			return depsManaged
		}
		if gov == nil {
			return depsTenancyUnknown
		}
		grant, live, err := gov(ctx)
		if err != nil {
			return depsTenancyUnknown
		}
		if grant != nil && govern.Resolve(govern.Delivered{}, grant, live, time.Now().UTC()).Managed {
			return depsManaged
		}
		return depsIndividual
	}
}

// depsLookupFor returns the one online source, picked per lookup: the
// relay on a managed node (the public constructor is never called while
// the node is managed), the public client on an individual node, and no
// lookup at all while the tenancy cannot be read (every name failed,
// S-748). Each constructor runs at most once, on first use.
func depsLookupFor(tenancy func(context.Context) depsTenancy, public, relay func() secfeed.Lookup) secfeed.Lookup {
	var (
		mu       sync.Mutex
		pub, rel secfeed.Lookup
	)
	pick := func(t depsTenancy) secfeed.Lookup {
		mu.Lock()
		defer mu.Unlock()
		switch t {
		case depsManaged:
			if rel == nil {
				rel = relay()
			}
			return rel
		case depsIndividual:
			if pub == nil {
				pub = public()
			}
			return pub
		}
		return nil
	}
	return func(ctx context.Context, specs []secfeed.InstallSpec) []secfeed.OnlineAnswer {
		if lk := pick(tenancy(ctx)); lk != nil {
			return lk(ctx, specs)
		}
		return depsFailedAll(specs, secfeed.ReasonTenancyUnknown)
	}
}

// depsFailedAll answers every spec failed with reason.
func depsFailedAll(specs []secfeed.InstallSpec, reason string) []secfeed.OnlineAnswer {
	out := make([]secfeed.OnlineAnswer, 0, len(specs))
	for _, s := range specs {
		out = append(out, secfeed.OnlineAnswer{Eco: s.Eco, Name: secfeed.Normalize(s.Eco, s.Name), Version: s.Version, Status: secfeed.OnlineFailed, Reason: reason})
	}
	return out
}

// publicDepsLookup adapts the public client.
func publicDepsLookup(c *online.Client) secfeed.Lookup {
	return func(ctx context.Context, specs []secfeed.InstallSpec) []secfeed.OnlineAnswer {
		return c.Lookup(ctx, specs)
	}
}

// relayDepsLookup adapts the org relay: public names only (the service has
// classified them), answers matched by the client; any failure is every
// name failed, never a public fallback.
func relayDepsLookup(ctx context.Context, configPath string) secfeed.Lookup {
	return relayDepsLookupVia(func(lctx context.Context, req orgcontract.SecurityLookupRequest) (orgcontract.SecurityLookupResponse, error) {
		c, cleanup, enabled, err := buildOrgClient(ctx, configPath)
		if err != nil || !enabled {
			return orgcontract.SecurityLookupResponse{}, errors.New("relay_unavailable")
		}
		defer cleanup()
		return c.SecurityLookup(lctx, req)
	})
}

// relayDepsLookupVia is relayDepsLookup over one relay call (the org
// client's SecurityLookup in production; a test passes a call to a real
// relay server).
func relayDepsLookupVia(call func(context.Context, orgcontract.SecurityLookupRequest) (orgcontract.SecurityLookupResponse, error)) secfeed.Lookup {
	return func(lctx context.Context, specs []secfeed.InstallSpec) []secfeed.OnlineAnswer {
		req := orgcontract.SecurityLookupRequest{}
		for _, s := range specs {
			req.Queries = append(req.Queries, orgcontract.SecurityLookupQuery{Ecosystem: string(s.Eco), Name: secfeed.Normalize(s.Eco, s.Name), Version: s.Version})
		}
		resp, err := call(lctx, req)
		if err != nil {
			return depsFailedAll(specs, "relay_unavailable")
		}
		out := make([]secfeed.OnlineAnswer, 0, len(resp.Answers))
		for _, a := range resp.Answers {
			oa := secfeed.OnlineAnswer{Eco: secfeed.Ecosystem(a.Ecosystem), Name: a.Name, Version: a.Version, Status: secfeed.OnlineStatus(a.Status), MalIDs: a.MalIDs, VulnIDs: a.VulnIDs, MalAllVersions: a.MalAllVersions, Reason: a.Reason, FetchedAt: time.Now()}
			if t, err := time.Parse(time.RFC3339, a.FirstPublished); err == nil {
				oa.FirstPublished = t
			}
			switch oa.Status {
			case secfeed.OnlineAnswered, secfeed.OnlineNotFound, secfeed.OnlineFailed:
			default:
				oa.Status, oa.Reason = secfeed.OnlineFailed, "bad_answer"
			}
			out = append(out, oa)
		}
		return out
	}
}

// onlineReady reports whether online checks may run: the setting in force
// (floors applied) is on and the disclosure was shown.
func (e *depsEnv) onlineReady() bool {
	return e.deps().Online && e.disclose.Shown()
}

// onlineReadyAt is onlineReady for one project root (lane sec-p3): the
// setting in force in that directory, the org-wide floor with the matched
// projects' security.scanning sections merged over it
// (securityFloorsAppliedAt), so a project section that forbids online checks
// stops them in that project only. An empty root is onlineReady.
func (e *depsEnv) onlineReadyAt(root string) bool {
	if root == "" {
		return e.onlineReady()
	}
	sec := e.cfg.Security
	if e.live != nil {
		sec = e.live.security()
	}
	return securityFloorsAppliedAt(sec, root).Deps.Online && e.disclose.Shown()
}

// onlineReadyFor is onlineReadyAt for an ask's scope (secfeed's EnabledFor).
func (e *depsEnv) onlineReadyFor(scope secfeed.Scope) bool {
	return e.onlineReadyAt(scope.ProjectRoot)
}

// deps is the [security.deps] in force: re-read live when the loop has a
// live reader, else as loaded, and in both cases read through the org
// floors' seam securityFloorsApplied (SEC-E merge audit finding 3), so
// allow.online_checks = forbidden turns the online checks off here too.
func (e *depsEnv) deps() config.SecurityDepsConfig {
	if e.live != nil {
		return e.live.get()
	}
	return depsInForce(e.cfg.Security)
}

// depsInForce is [security.deps] with the managed pull and the org floors
// applied: THE value every online-check reader and the hook's settings file
// use.
func depsInForce(sc config.SecurityConfig) config.SecurityDepsConfig {
	return securityFloorsApplied(sc).Deps
}

// depsLiveEvery is how often the ask loop checks the config file for a
// changed [security.deps] while no ask arrives, so the hook's settings file
// follows a change within seconds (lane SEC-D1FIX2 milestone 2c).
const depsLiveEvery = 5 * time.Second

// depsLiveDeps re-reads [security.deps] when the config file changes (its
// size or modification time), so turning online checks off takes effect
// at the next ask without a daemon restart, and rewrites the hook's
// settings file whenever the values change. A config that no longer loads
// turns online checks off until it loads again: an unreadable setting
// never sends a query.
type depsLiveDeps struct {
	path string
	dir  string
	load func() (config.Config, error)
	// inForce applies the managed pull and the floors (depsInForce; a test
	// seam).
	inForce func(config.SecurityConfig) config.SecurityDepsConfig

	mu    sync.Mutex
	stamp string
	// sec is the [security] section as last loaded (the floors read the
	// whole section); deps is the value in force, as last written.
	sec     config.SecurityConfig
	deps    config.SecurityDepsConfig
	serving bool
}

// newDepsLiveDeps returns a reader seeded with what was loaded at start.
func newDepsLiveDeps(configPath, dir string, initial config.SecurityConfig) *depsLiveDeps {
	resolved := depsConfigPath(configPath)
	return &depsLiveDeps{
		path: resolved, dir: dir, sec: initial, deps: depsInForce(initial), stamp: depsConfigStamp(resolved),
		load:    func() (config.Config, error) { return config.Load(config.LoadOptions{GlobalPath: configPath}) },
		inForce: depsInForce,
	}
}

// depsConfigStamp is a config file's change stamp ("" when unresolvable).
func depsConfigStamp(path string) string {
	if path == "" {
		return ""
	}
	fi, err := os.Stat(path) //nolint:gosec // G703: a metadata read of the user's own local path; no privilege boundary is crossed
	if err != nil {
		return "missing"
	}
	return fmt.Sprintf("%d:%d", fi.ModTime().UnixNano(), fi.Size())
}

// get returns the setting in force, reloading on a changed stamp. The org
// floors and the managed pull are applied on every call, so a floor that
// arrives or leaves while the daemon runs rewrites the hook's settings file
// within one tick, with no config edit.
func (l *depsLiveDeps) get() config.SecurityDepsConfig {
	l.mu.Lock()
	defer l.mu.Unlock()
	if st := depsConfigStamp(l.path); st != l.stamp {
		l.stamp = st
		if cfg, err := l.load(); err == nil {
			l.sec = cfg.Security
		} else {
			l.sec.Deps.Online = false
		}
	}
	next := l.sec.Deps
	if l.inForce != nil {
		next = l.inForce(l.sec)
	}
	if !reflect.DeepEqual(next, l.deps) {
		l.deps = next
		_ = writeDepsSettingsFor(l.dir, next, l.serving)
	}
	return l.deps
}

// security returns the [security] section as last loaded (reloading on a
// changed stamp), before the floors: the project-aware seam applies them
// per directory.
func (l *depsLiveDeps) security() config.SecurityConfig {
	l.get()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sec
}

// setServing records whether the ask endpoint serves and writes the
// settings file for it.
func (l *depsLiveDeps) setServing(serving bool) {
	l.mu.Lock()
	l.serving = serving
	deps := l.deps
	l.mu.Unlock()
	_ = writeDepsSettingsFor(l.dir, deps, serving)
}

// watch polls the config file until ctx ends.
func (l *depsLiveDeps) watch(ctx context.Context) {
	t := time.NewTicker(depsLiveEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.get()
		}
	}
}

// showDisclosureOnTerminal prints the disclosure when the daemon was
// started on a terminal and online checks wait for it. It records nothing:
// consent is an explicit action (the dashboard's Code security page, or
// `observer security deps disclosure`), never a side effect of starting
// the daemon. A headless daemon logs where to find it.
func (e *depsEnv) showDisclosureOnTerminal(w io.Writer, isTerminal bool) {
	if !e.deps().Online || e.disclose.Shown() {
		return
	}
	if !isTerminal {
		e.logger.Info("security: online package checks wait for you to read what they send; open the dashboard's Code security page or run `observer security deps disclosure`")
		return
	}
	text := secfeed.DisclosureText
	if e.managed {
		text = secfeed.DisclosureTextManaged
	}
	fmt.Fprintf(w, "\nPackage checks (Code security): online checks are waiting for you.\n%s\n"+
		"To turn them on, use the dashboard's Code security page or run `observer security deps disclosure`.\n\n", text)
}

// serveAsk runs the ask endpoint until ctx ends.
func (rt *depsRuntime) serveAsk(ctx context.Context) {
	env, err := rt.open(ctx)
	if err != nil {
		slog.Default().Warn("security: package checks not started", "err", err)
		return
	}
	defer env.cleanup()
	cfgPath := rt.configPath
	depsActiveConfig.Store(&cfgPath)
	defer depsActiveConfig.Store(nil)
	env.live = newDepsLiveDeps(rt.configPath, env.dir, env.cfg.Security)
	env.showDisclosureOnTerminal(os.Stderr, term.IsTerminal(int(os.Stderr.Fd())))
	initial := loadDepsCache(ctx, env.st)
	svc := secfeed.NewService(secfeed.ServiceOptions{
		Classify:  depsClassifier,
		Confirmed: rt.confirmed.add,
		Lookup:    env.lookup,
		Enabled: func() bool {
			// The disclosure can be accepted while the daemon runs.
			if !env.disclose.Shown() {
				env.disclose = readDepsDisclosure(env.dir)
			}
			return env.onlineReady()
		},
		// Per ask: the project's floor decides (lane sec-p3).
		EnabledFor: func(scope secfeed.Scope) bool {
			if !env.disclose.Shown() {
				env.disclose = readDepsDisclosure(env.dir)
			}
			return env.onlineReadyFor(scope)
		},
		Save:      func(ctx context.Context, es []secfeed.CacheEntry) { saveDepsCache(ctx, env.st, es) },
		WriteFile: func(b []byte) error { return writeDepsFile(filepath.Join(env.dir, depsCacheFile), b) },
		Initial:   initial,
	})
	if b, err := secfeed.EncodeCacheFile(initial, time.Now()); err == nil {
		_ = writeDepsFile(filepath.Join(env.dir, depsCacheFile), b)
	}
	ln, _, err := secask.Listen(env.dir)
	if err != nil {
		env.logger.Warn("security: package check endpoint not started", "err", err)
		env.live.setServing(false)
		return
	}
	env.live.setServing(true)
	defer env.live.setServing(false)
	go env.live.watch(ctx)
	_ = secask.Serve(ctx, ln, svc.Answer)
}

// feedLoop refreshes the signed index and prefetches, every depsFeedEvery.
// A failure retries with a doubling back-off from depsFeedRetry up to
// depsFeedEvery, and is logged as a warning only when it differs from the
// last one logged; a feed that is not published yet is noted once and
// retried at the normal cadence (milestone 3d).
func (rt *depsRuntime) feedLoop(ctx context.Context) {
	var b depsFeedBackoff
	for {
		wait, msg, level := b.next(rt.feedOnce(ctx))
		if msg != "" {
			slog.Default().Log(ctx, level, msg)
		}
		if !rt.waitFeed(ctx, wait) {
			return
		}
	}
}

// depsFeedSwitchEvery is how often the feed loop, while it waits, re-reads
// [security.deps].index_download, so turning the download back on takes
// effect within this long, no restart (PT-19). Turning it off needs no
// wake: every refresh reloads the config before it fetches.
var depsFeedSwitchEvery = 30 * time.Second

// waitFeed waits up to d, returning early (true) when the index download
// switch moves from off to on; false when ctx ends.
func (rt *depsRuntime) waitFeed(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	tick := time.NewTicker(depsFeedSwitchEvery)
	defer tick.Stop()
	path := depsConfigPath(rt.configPath)
	stamp := depsConfigStamp(path)
	was := rt.indexDownloadOn()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		case <-tick.C:
			// Reload only when the file changed (its size or time).
			if st := depsConfigStamp(path); st != stamp {
				stamp = st
				now := rt.indexDownloadOn()
				if now && !was {
					return true
				}
				was = now
			}
		}
	}
}

// indexDownloadOn reads the switch from the config file now; a config that
// does not load reads off (nothing is fetched on an unreadable setting).
func (rt *depsRuntime) indexDownloadOn() bool {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: rt.configPath})
	if err != nil {
		return false
	}
	return depsIndexDownloadAllowed(cfg.Security.Deps)
}

// depsFeedBackoff is the feed loop's retry state.
type depsFeedBackoff struct {
	failures int
	lastLog  string
}

// next returns the wait before the next refresh and what to log (msg ""
// logs nothing) after one refresh ended with err.
func (b *depsFeedBackoff) next(err error) (time.Duration, string, slog.Level) {
	if err == nil {
		b.failures, b.lastLog = 0, ""
		return depsFeedEvery, "", slog.LevelDebug
	}
	text := err.Error()
	if errors.Is(err, online.ErrFeedNotPublished) {
		b.failures = 0
		if b.lastLog == text {
			return depsFeedEvery, "", slog.LevelDebug
		}
		b.lastLog = text
		return depsFeedEvery, "security: the package index feed is not published yet; package checks use what is installed, and the daemon checks again every 6 hours", slog.LevelInfo
	}
	b.failures++
	wait := depsFeedRetry
	for i := 1; i < b.failures && wait < depsFeedEvery; i++ {
		wait *= 2
	}
	wait = min(wait, depsFeedEvery)
	if b.lastLog == text {
		return wait, "", slog.LevelDebug
	}
	b.lastLog = text
	return wait, "security: package index refresh failed; the last verified index stays (" + text + ")", slog.LevelWarn
}

// feedOnce is one refresh: the two content kinds, the cache prune, then the
// prefetch. Nothing goes out before the disclosure.
func (rt *depsRuntime) feedOnce(ctx context.Context) error {
	env, err := rt.open(ctx)
	if err != nil {
		return err
	}
	defer env.cleanup()
	if _, err := env.st.PruneSecPkgCache(ctx, time.Now().Add(-depsCacheKeep)); err != nil {
		env.logger.Warn("security: package cache prune failed", "err", err)
	}
	// The signed index is a plain download of public files, not a query
	// about the developer's packages: it needs no consent, and
	// [security.deps].index_download is its off switch (PT-19;
	// depsIndexDownloadAllowed). The prefetch below is a query, and always
	// waits for the setting and the disclosure.
	store := depsContentStore(depsConfigPath(rt.configPath))
	var errs []error
	switch env.tenancy(ctx) {
	case depsIndividual:
		if !depsIndexDownloadAllowed(env.cfg.Security.Deps) {
			// Switched off by the developer: not a failure, nothing to
			// retry; the index on disk stays in use.
			break
		}
		c := rt.publicClient()
		for _, k := range depsFeedKinds {
			if err := fetchAndInstallKind(ctx, c, store, k.kind, k.name); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", k.kind, err))
			}
		}
		// Verify the installed index once now, so the first install after
		// a refresh does not pay for it in the hook.
		_, _ = loadInstallIndexCached(store, depsTrust())
	case depsTenancyUnknown:
		errs = append(errs, errors.New("node tenancy unreadable: no feed fetched"))
	case depsManaged:
		// A managed node never reaches the vendor feed. It fetches the
		// index from its org server's mirror (lane SEC-E4) only while the
		// managed pull in force names the mirror and the floors allow it;
		// otherwise it makes no request and keeps what an operator imported
		// (observer security deps import). A failed fetch keeps the
		// last-known-good, shown with its freshness, never as clean.
		if !depsMirrorNamedFor(ctx, env.cfg, env.st) || !depsScannerSourceAllowed(env.cfg.Security, depsScannerSourceOrgMirror) {
			break
		}
		kinds := make([]content.Kind, 0, len(depsFeedKinds))
		for _, k := range depsFeedKinds {
			kinds = append(kinds, k.kind)
		}
		if err := fetchFromOrgMirror(ctx, rt.configPath, store, kinds, depsTrust()); err != nil {
			errs = append(errs, err)
		}
		_, _ = loadInstallIndexCached(store, depsTrust())
	}
	if env.onlineReady() {
		rt.prefetch(ctx, env)
	}
	return errors.Join(errs...)
}

// depsIndexDownloadAllowed is the ONE reader of
// [security.deps].index_download (operator ruling PT-19, decision log
// P-036): the signed index download is automatic, with no consent, unless
// the developer turned it off. While it is off nothing is fetched and the
// checks run with whatever index is on disk.
func depsIndexDownloadAllowed(deps config.SecurityDepsConfig) bool {
	return deps.IndexDownload
}

// depsIndexOffNote is the one sentence every surface (the status command,
// the doctor row, the Package checks card's seam) shows while the download
// is off.
const depsIndexOffNote = "index download off (security.deps.index_download = false): package checks use the index already on disk and nothing is fetched from superbased.app"

// depsIndexDownloadLine is the status and doctor line for the switch.
func depsIndexDownloadLine(deps config.SecurityDepsConfig) string {
	if depsIndexDownloadAllowed(deps) {
		return "index download: on (the signed lists from superbased.app every 6 hours; it sends nothing about your packages)"
	}
	return depsIndexOffNote
}

// fetchAndInstallKind downloads one kind's envelope and artifact from the
// vendor feed and installs them through the content channel; any refusal
// keeps the last-known-good and records why. The envelope is revalidated
// with its ETag (If-None-Match), so an unchanged feed costs one 304; the
// ETag is kept only for an envelope that is installed (or already the
// accepted one).
func fetchAndInstallKind(ctx context.Context, c *online.Client, st contentchan.Store, kind content.Kind, name string) error {
	tags := readDepsFeedETags(st)
	prev, perr := st.State(kind)
	have := perr == nil && prev.Accepted != nil
	etag := ""
	if have {
		etag = tags[string(kind)]
	}
	env, newTag, err := c.FetchFeedFileIfChanged(ctx, string(kind), contentchan.ManifestFile, etag)
	if errors.Is(err, online.ErrFeedNotModified) {
		return nil // unchanged
	}
	if err != nil {
		return err
	}
	if have && content.HashBytes(envelopeBody(env)) == prev.Accepted.ManifestHash {
		writeDepsFeedETag(st, tags, kind, newTag)
		return nil // unchanged
	}
	data, err := c.FetchFeedFile(ctx, string(kind), name)
	if err != nil {
		return err
	}
	if _, err := st.Install(kind, env, map[string][]byte{name: data}, depsTrust()); err != nil {
		return err
	}
	writeDepsFeedETag(st, tags, kind, newTag)
	return nil
}

// depsFeedETagFile keeps the feed envelopes' ETags beside the content
// store, per kind.
const depsFeedETagFile = "deps-feed-etag.json"

// readDepsFeedETags reads the kept ETags; anything unreadable is none.
func readDepsFeedETags(st contentchan.Store) map[string]string {
	out := map[string]string{}
	if b, err := readDepsFile(filepath.Join(filepath.Dir(st.Root), depsFeedETagFile), 4096); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

// writeDepsFeedETag records one kind's ETag (an empty one is dropped).
func writeDepsFeedETag(st contentchan.Store, tags map[string]string, kind content.Kind, tag string) {
	if len(tag) > 256 {
		tag = ""
	}
	if tags[string(kind)] == tag {
		return
	}
	if tag == "" {
		delete(tags, string(kind))
	} else {
		tags[string(kind)] = tag
	}
	if b, err := json.Marshal(tags); err == nil {
		_ = writeDepsFile(filepath.Join(filepath.Dir(st.Root), depsFeedETagFile), b)
	}
}

// envelopeBody returns an envelope's decoded manifest bytes, or nil.
func envelopeBody(env []byte) []byte {
	var e content.Envelope
	if json.Unmarshal(env, &e) != nil {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(e.ManifestB64)
	if err != nil {
		return nil
	}
	return b
}

// prefetch looks up, for the active projects, the dependencies their
// manifests declare whose names an ask already classified public for that
// project (X4: never the raw dependency list), so an agent's later install
// of another version finds it cached. A project no ask has confirmed a
// name for sends nothing.
func (rt *depsRuntime) prefetch(ctx context.Context, env *depsEnv) {
	roots, err := env.st.SecActiveProjectRoots(ctx, time.Now().Add(-7*24*time.Hour))
	if err != nil {
		return
	}
	svc := secfeed.NewService(secfeed.ServiceOptions{
		Classify: depsClassifier, Lookup: env.lookup, Enabled: env.onlineReady, EnabledFor: env.onlineReadyFor,
		Save:    func(ctx context.Context, es []secfeed.CacheEntry) { saveDepsCache(ctx, env.st, es) },
		Initial: loadDepsCache(ctx, env.st),
	})
	for _, root := range roots {
		// A root that is not rooted on this host: its manifests are never
		// read relative to the working directory (audit finding 1 on the
		// w14 hand-back).
		if !git.HostRooted(root) {
			continue
		}
		scope, specs, ok := rt.confirmed.filter(root, projectManifestSpecs(root, depsPrefetchPerRoot))
		if !ok {
			continue
		}
		for len(specs) > 0 {
			n := min(len(specs), secask.MaxSpecs)
			lctx, cancel := context.WithTimeout(ctx, depsLookupBudget*4)
			svc.Prefetch(lctx, scope, specs[:n])
			cancel()
			specs = specs[n:]
		}
	}
}

// projectManifestMaxBytes caps one manifest read for the prefetch.
const projectManifestMaxBytes = 1 << 20

// projectManifestSpecs reads the dependency names a project's top-level
// manifests declare.
func projectManifestSpecs(root string, limit int) []secfeed.InstallSpec {
	var out []secfeed.InstallSpec
	for _, name := range []string{"package.json", "requirements.txt", "pyproject.toml", "Cargo.toml", "go.mod"} {
		b, err := readDepsFile(filepath.Join(root, name), projectManifestMaxBytes)
		if err != nil {
			continue
		}
		for _, s := range secfeed.ManifestAdditions(name, "", string(b)) {
			if len(out) >= limit {
				return out
			}
			out = append(out, s)
		}
	}
	return out
}

// readDepsConfigFile reads one package-manager configuration file, capped.
// Unlike Observer's own state files it follows a symlink (dotfile managers
// link these), and still refuses anything that is not a regular file.
func readDepsConfigFile(path string, limit int64) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > limit {
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

// depsConfigMaxBytes caps one configuration file read; a larger file is
// unreadable (its ecosystem private).
const depsConfigMaxBytes = 256 << 10

// globalNpmrcPaths are the usual global npmrc locations ($PREFIX/etc/npmrc
// for the common prefixes), read without running npm.
func globalNpmrcPaths() []string {
	out := []string{"/usr/local/etc/npmrc", "/usr/etc/npmrc", "/etc/npmrc", "/opt/homebrew/etc/npmrc"}
	if a := os.Getenv("APPDATA"); a != "" {
		out = append(out, filepath.Join(a, "npm", "etc", "npmrc"))
	}
	return out
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Lstat(p); err == nil {
			return p
		}
	}
	return ""
}

// loadDepsCache reads the live cache rows.
func loadDepsCache(ctx context.Context, st *store.Store) []secfeed.CacheEntry {
	rows, err := st.LiveSecPkgCache(ctx, time.Now(), secfeed.MaxCacheFileEntries)
	if err != nil {
		return nil
	}
	out := make([]secfeed.CacheEntry, 0, len(rows))
	for _, r := range rows {
		var a secfeed.OnlineAnswer
		if json.Unmarshal([]byte(r.AnswerJSON), &a) != nil {
			continue
		}
		out = append(out, secfeed.CacheEntry{Answer: a, ExpiresAt: r.ExpiresAt})
	}
	return out
}

// saveDepsCache writes new cache entries.
func saveDepsCache(ctx context.Context, st *store.Store, es []secfeed.CacheEntry) {
	rows := make([]store.SecPkgCacheRow, 0, len(es))
	for _, e := range es {
		b, err := json.Marshal(e.Answer)
		if err != nil {
			continue
		}
		rows = append(rows, store.SecPkgCacheRow{
			Ecosystem: string(e.Answer.Eco), Name: e.Answer.Name, Version: e.Answer.Version, Status: string(e.Answer.Status),
			AnswerJSON: string(b), FetchedAt: e.Answer.FetchedAt, ExpiresAt: e.ExpiresAt,
		})
	}
	_ = st.UpsertSecPkgCache(ctx, rows)
}

// writeDepsSettings writes the hook's settings file from the setting in
// force (floors applied, depsInForce).
func writeDepsSettings(dir string, cfg config.Config, serving bool) error {
	return writeDepsSettingsFor(dir, depsInForce(cfg.Security), serving)
}

// writeDepsSettingsFor writes the hook's settings file from [security.deps]
// as given; every caller passes the value in force (depsInForce).
func writeDepsSettingsFor(dir string, deps config.SecurityDepsConfig, serving bool) error {
	b, err := json.Marshal(depsHookSettings{
		Ask:       serving && deps.Online,
		Online:    deps.Online,
		WaitMS:    int64(deps.InstallWaitMS),
		MinAgeHrs: deps.MinPackageAgeH,
		MaxAgeH:   deps.MaxAdvisoryDBAgeH,
		// The unknown-package actions in force (lane LEFT-SEC).
		UnknownAction:       depsStrictAction(deps.UnknownAction),
		OnlineUnknownAction: depsStrictAction(deps.OnlineUnknownAction),
	})
	if err != nil {
		return err
	}
	return writeDepsFile(filepath.Join(dir, depsSettingsFile), b)
}

// readDepsDisclosure reads the disclosure record, verified under the
// posture key: a record with no MAC or one that does not verify (a
// hand-written file, lane sec-deps4 audit finding 1) reads not shown.
func readDepsDisclosure(dir string) secfeed.Disclosure {
	b, err := readDepsFile(filepath.Join(dir, depsDisclosureFile), 4096)
	if err != nil {
		return secfeed.Disclosure{}
	}
	return secfeed.DecodeDisclosure(b, depsRecordKey(dir))
}

// recordDepsDisclosure records that the disclosure was shown on surface,
// signed under the posture key.
func recordDepsDisclosure(dir, surface string, at time.Time) (secfeed.Disclosure, error) {
	key, err := depsRecordSigningKey(dir)
	if err != nil {
		return secfeed.Disclosure{}, err
	}
	b, err := secfeed.EncodeDisclosure(secfeed.Disclosure{Version: secfeed.DisclosureVersion, ShownAt: at.UTC(), Surface: surface}, key)
	if err != nil {
		return secfeed.Disclosure{}, err
	}
	if err := writeDepsFile(filepath.Join(dir, depsDisclosureFile), b); err != nil {
		return secfeed.Disclosure{}, err
	}
	return secfeed.DecodeDisclosure(b, key), nil
}

// depsRecordKeyPath is the key that signs the developer's consent records
// in the security directory dir (the online checks' disclosure and the
// scanners' database accept): the guard posture key, which lives beside
// the global config, the security directory's parent
// (secposture.LayoutFor). "" when dir is.
func depsRecordKeyPath(dir string) string {
	if dir == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(dir), guardposture.KeyFilename)
}

// depsRecordKey is the key a reader verifies a consent record with; nil
// when there is none or it is malformed, and every record then reads
// unverified (not accepted).
func depsRecordKey(dir string) []byte {
	key, err := guardposture.ReadKey(depsRecordKeyPath(dir))
	if err != nil {
		return nil
	}
	return key
}

// depsRecordSigningKey is the key an accept path (the CLI or the
// dashboard, the developer's explicit action) signs a consent record
// with. It creates the posture key when no daemon has written one yet,
// marked not yet published so the first start initialises rather than
// reports a tamper (live check macOS 2026-10-22, D4); the daemon's posture
// writer loads the same file on its first publish.
func depsRecordSigningKey(dir string) ([]byte, error) {
	path := depsRecordKeyPath(dir)
	if path == "" {
		return nil, errors.New("no security directory to sign a consent record in")
	}
	return guardposture.LoadOrCreateKeyBeforePosture(path)
}

// writeDepsFile writes one of the install gate's files atomically, 0600,
// creating the security directory 0700.
func writeDepsFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-deps-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}

// depsConfigPath resolves the global config path ("" when unresolvable).
func depsConfigPath(configPath string) string {
	p, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return ""
	}
	return p
}
