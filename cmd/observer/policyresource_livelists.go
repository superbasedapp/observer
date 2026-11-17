package main

import (
	"context"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

// Live policy accept lists for the policy-resource poller (demo finding #23,
// 2026-11-10).
//
// The poller's accept / preauthorize lists and node attributes live in
// config.toml ([org_client.policy]). A managed enrolment made while the
// daemon runs, by `observer enroll` in another process or from the
// dashboard, writes them there (ensureManagedPolicyBlock). The poller used
// to resolve them once at daemon start, so a node that started individual and
// was re-enrolled managed kept answering node.governance "delivered, not
// accepted": `GET /api/governance` stayed at version 0 / no_policy, the
// Security page stayed hidden and the node never sent an authority report,
// until someone restarted the daemon (which a live proxy route makes
// expensive).
//
// livePolicyLists is the ONE owner of the poller's view of those lists. Every
// poll cycle re-reads them (a stat, and a config load only when the file
// changed), and a small watcher wakes the poll the moment they, or the
// enrolment identity, change, so the first fetch under the new enrolment
// happens within policyListsCheckInterval instead of at the next hourly poll.

// policyListsCheckInterval is how often the watcher looks at config.toml and
// the enrolment identity. A stat and one indexed SELECT pair per tick.
var policyListsCheckInterval = 3 * time.Second

// policyListsFacts is the part of the config the poller's options depend on,
// compared to decide whether a reload changed anything.
type policyListsFacts struct {
	accept, preauth []string
	workspace, env  string
	service         string
}

func policyListsFactsOf(p config.OrgClientPolicyConfig) policyListsFacts {
	return policyListsFacts{
		accept:    slices.Clone(p.AcceptedFamilies()),
		preauth:   slices.Clone(p.PreauthorizedFamilies()),
		workspace: p.NodeWorkspace,
		env:       p.NodeEnvironment,
		service:   p.NodeService,
	}
}

func (a policyListsFacts) equal(b policyListsFacts) bool {
	return slices.Equal(a.accept, b.accept) && slices.Equal(a.preauth, b.preauth) &&
		a.workspace == b.workspace && a.env == b.env && a.service == b.service
}

// policyFileStamp identifies one version of a file without reading it.
type policyFileStamp struct {
	mod  time.Time
	size int64
	ok   bool
}

func statStamp(path string) policyFileStamp {
	fi, err := os.Stat(path)
	if err != nil {
		return policyFileStamp{}
	}
	return policyFileStamp{mod: fi.ModTime(), size: fi.Size(), ok: true}
}

// livePolicyLists holds the current [org_client.policy] lists for one
// poller. path empty means a static view (tests, or a caller with no config
// file): the lists the poller started with are used for its lifetime.
type livePolicyLists struct {
	path   string
	caps   []string
	load   func(path string) (config.Config, error)
	logger *slog.Logger

	mu       sync.Mutex
	cfg      config.Config
	stamp    policyFileStamp
	loadFail bool
}

func newLivePolicyLists(cfg config.Config, path string, liveCaps []string, logger *slog.Logger) *livePolicyLists {
	if logger == nil {
		logger = slog.Default()
	}
	return &livePolicyLists{
		path: path, caps: liveCaps, cfg: cfg, logger: logger,
		load: func(p string) (config.Config, error) { return config.Load(config.LoadOptions{GlobalPath: p}) },
	}
}

// options is the poll loop's per-cycle options: the shared builder over the
// newest lists. It refreshes first, so a kick that follows a config write
// always fetches under the lists that write produced.
func (l *livePolicyLists) options() orgclient.PolicyResourceOptions {
	l.refresh()
	l.mu.Lock()
	defer l.mu.Unlock()
	return policyResourceOptionsFor(l.cfg, l.caps)
}

// refresh reloads the lists when config.toml changed and reports whether the
// lists themselves changed. Only [org_client.policy] is taken from the
// reload; everything else the options depend on (cache dir, live
// capabilities) is fixed for the daemon's lifetime. A config that does not
// load keeps the lists in force and is retried on the next call.
func (l *livePolicyLists) refresh() bool {
	if l == nil || l.path == "" {
		return false
	}
	st := statStamp(l.path)
	l.mu.Lock()
	defer l.mu.Unlock()
	if !st.ok || st == l.stamp {
		return false
	}
	next, err := l.load(l.path)
	if err != nil {
		if !l.loadFail {
			l.logger.Warn("policy resource: config.toml did not load; keeping the policy accept lists in force", "err", err)
		}
		l.loadFail = true
		return false
	}
	l.loadFail = false
	l.stamp = st
	if policyListsFactsOf(next.OrgClient.Policy).equal(policyListsFactsOf(l.cfg.OrgClient.Policy)) {
		return false
	}
	l.cfg.OrgClient.Policy = next.OrgClient.Policy
	return true
}

// policyIdentity is the enrolment identity the watcher compares.
type policyIdentity struct {
	orgKey     string
	generation int64
	ok         bool
}

// watchPolicyListsAndIdentity wakes the policy-resource poll when the accept
// lists or the enrolment identity change while the daemon runs. It returns
// when ctx ends. identity may be nil (lists only).
func watchPolicyListsAndIdentity(ctx context.Context, lists *livePolicyLists, identity func(context.Context) policyIdentity, kick func(), interval time.Duration, logger *slog.Logger) {
	if kick == nil || (lists == nil && identity == nil) {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	var last policyIdentity
	if identity != nil {
		last = identity(ctx)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		wake := false
		if lists.refresh() {
			logger.Info("policy resource: [org_client.policy] lists changed (enrolment or config edit); fetching now")
			wake = true
		}
		if identity != nil {
			if cur := identity(ctx); cur != last {
				logger.Info("policy resource: enrolment identity changed; fetching now",
					"generation", cur.generation, "enrolled", cur.ok)
				last = cur
				wake = true
			}
		}
		if wake {
			kick()
		}
	}
}

// resolvedPolicyConfigPath is the config.toml a daemon loaded (the explicit
// --config, else the default under the home); "" when the home cannot be
// resolved, which keeps the start-time lists.
func resolvedPolicyConfigPath(explicit string) string {
	p, err := config.ResolveGlobalPath(explicit)
	if err != nil {
		return ""
	}
	return p
}

// orgClientPolicyIdentity adapts the org client's live identity read.
func orgClientPolicyIdentity(oc *orgclient.Client) func(context.Context) policyIdentity {
	if oc == nil {
		return nil
	}
	return func(ctx context.Context) policyIdentity {
		k, g, ok := oc.ActiveIdentity(ctx)
		return policyIdentity{orgKey: k, generation: g, ok: ok}
	}
}
