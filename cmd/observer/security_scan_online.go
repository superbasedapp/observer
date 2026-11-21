//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"errors"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secscan/depdriver"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvnet"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
)

// security_scan_online.go is online matching (security plan section 8.2:
// "the online query first where allowed, the local database as the
// fallback"), used on a manual run only: `observer security scan --online`
// and the dashboard's Scan now with "Also check online" (decision P-1 of
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md), both through
// depsRunMatchers, for the ecosystems the local database could not match.
// The daemon's own schedule never matches online. It runs in the
// scanning process (no database is loaded, so no memory peak) through
// SCALIBR's osvdev enricher with the security.scan.osv.db lane's client and
// a short deadline. It sends ecosystem, public package name and version
// only: a name the security.deps classifier cannot place as public (a
// private registry, a scope routed elsewhere, an ecosystem outside its
// table) is withheld, never sent, and the run is then never clean.
//
// Each package is classified with its own lockfile's configuration (lane
// SEC-DEPS3 item 2, P-029/P-030): the lockfile's directory and every parent
// up to the project root (depsDirChain, the hook's walk), one cached
// classifier per directory, so a sub-package's own .npmrc scope or
// pip.conf index keeps its names private. A lockfile path that leaves the
// root or whose chain cannot be resolved withholds its packages. The
// process environment (the developer's shell when the command is typed)
// only ever restricts: every directory is read with no environment AND
// under the process's, and a name is public only when both say so.

// depsOnlineDeadline bounds one ecosystem's online match (SCALIBR's retry
// loop alone took about 20 s to give up against a blocked API, JSP-9b).
const depsOnlineDeadline = 30 * time.Second

// depsRunOnline is the matching side of one manual dependency run of one
// project.
type depsRunOnline struct {
	// matcher is what the linked driver is handed: the SuperBased lookup
	// first (lane RM-2, when its own gate is open), then the online
	// matcher when it is attached; nil when neither is.
	matcher depdriver.OnlineMatcher
	// direct reports that the online matcher (api.osv.dev, or the org
	// relay on a managed node) is attached.
	direct bool
	// blocked is the online gate's first closed reason for the project
	// when online matching was asked and refused; "" otherwise.
	blocked string
}

// depsRunMatchers builds the matching of one manual dependency run of the
// project at root, the one owner for `observer security scan` and the
// dashboard's Scan now (decision P-1 of
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md): the SuperBased
// lookup always where its gate is open; with online asked and the online
// gate (depsOnlineGate) open for root, the online matcher and the git
// submodule check (e.submodules, nil on a managed node). A closed gate
// attaches neither and says why in blocked; the caller decides whether that
// refuses the run (the CLI) or leaves it local and says so (the dashboard).
func (e *depsScanEnv) depsRunMatchers(root string, online bool) depsRunOnline {
	var out depsRunOnline
	var direct depdriver.OnlineMatcher
	if online {
		if out.blocked = e.onlineBlockedAt(root); out.blocked == "" {
			direct = e.onlineMatcher(root)
			// Git submodules by their pinned commit ids only (spike CPP-0);
			// nil on a managed node.
			e.submodules = e.submoduleMatcher()
		}
	}
	out.direct = direct != nil
	out.matcher = chainMatchers(e.remoteMatcher(root), direct)
	return out
}

// onlineMatcher returns the online matcher for a project, or nil when the
// online gate is closed (online checks on, disclosure shown:
// depsOnlineGate). A managed node matches through the org relay only
// (relayOnlineMatcher, lane SEC-H2).
func (e *depsScanEnv) onlineMatcher(root string) depdriver.OnlineMatcher {
	if e.onlineBlockedAt(root) != "" {
		return nil
	}
	if e.managed {
		return e.relayOnlineMatcher(root)
	}
	public := newDepsLockfileClassifiers(root, depsOnlineScanClassifier)
	client := osvnet.New(osvnet.Options{}).HTTPClient()
	return func(ctx context.Context, eco string, pkgs []depscan.Package, idx []int) (depscan.EcoResult, bool) {
		sfEco, ok := secfeed.EcosystemFromOSV(eco)
		if !ok {
			return depscan.EcoResult{}, false
		}
		var send []int
		for _, i := range idx {
			p := pkgs[i]
			if public.public(p.Path, secfeed.InstallSpec{Eco: sfEco, Spec: p.Name, Name: p.Name, Version: p.Version}) {
				send = append(send, i)
			}
		}
		res := depscan.EcoResult{Ecosystem: eco, Packages: len(send), Withheld: len(idx) - len(send)}
		canary, hasCanary := depscan.CanaryFor(eco)
		facts := depscan.MatchFacts{DatabaseInstalled: true, HasCanary: hasCanary}
		if hasCanary {
			m, err := scalibrfacade.Match(ctx, scalibrfacade.NewInventory(facadeRows(pkgs)), scalibrfacade.MatchRequest{
				Ecosystem: eco, Indices: send, Canary: &scalibrfacade.Canary{Name: canary.Name, Version: canary.Version},
			}, scalibrfacade.MatchOptions{Online: true, HTTPClient: client, OnlineTimeout: depsOnlineDeadline})
			switch {
			case errors.Is(err, scalibrfacade.ErrNotCompiled):
				return depscan.EcoResult{}, false
			case err != nil:
				facts.MatchError = true
			default:
				facts.CanaryHit = m.CanaryHit
				for _, v := range m.Vulns {
					res.Advisories = append(res.Advisories, depscan.Advisory{ID: v.ID, Aliases: v.Aliases, Severity: v.Severity, Index: v.Index})
				}
			}
		}
		res.Outcome, res.Reason = depscan.DecideEcosystem(facts)
		if res.Outcome == depscan.EcoScanned {
			res.Epoch = "online:" + osvnet.APIHost + " " + time.Now().UTC().Format(time.RFC3339)
		} else {
			res.Advisories = nil
		}
		return res, true
	}
}

// facadeRows maps the child's rows back onto the facade's.
func facadeRows(pkgs []depscan.Package) []scalibrfacade.Package {
	out := make([]scalibrfacade.Package, len(pkgs))
	for i, p := range pkgs {
		out[i] = scalibrfacade.Package{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version, Path: p.Path, Extractor: p.Extractor, Local: p.Local, Restored: p.Restored}
	}
	return out
}

// depsOnlineScanClassifier classifies a scope for the online matcher: every
// directory read with no environment and under the process's own, so the
// environment only restricts (as the hook's variables do).
func depsOnlineScanClassifier(scope secfeed.Scope) secfeed.Classifier {
	return depsScopeClassifier(scope, []depsEnvSource{{}, depsDaemonEnv()})
}

// depsLockfileClassifiers caches one classifier per lockfile directory of
// one project.
type depsLockfileClassifiers struct {
	root  string
	build func(secfeed.Scope) secfeed.Classifier
	byDir map[string]secfeed.Classifier
}

// newDepsLockfileClassifiers returns the per-directory cache for root
// (spelled with its symlinks resolved, as depsDirChain spells a chain).
func newDepsLockfileClassifiers(root string, build func(secfeed.Scope) secfeed.Classifier) *depsLockfileClassifiers {
	if root != "" {
		if r, err := filepath.EvalSymlinks(root); err == nil {
			root = r
		}
		root = filepath.Clean(root)
	}
	return &depsLockfileClassifiers{root: root, build: build, byDir: map[string]secfeed.Classifier{}}
}

// public reports whether spec, from the lockfile at rel (relative to the
// root, forward slashes), may be sent. A path that is absolute or leaves
// the root, an unknown root and an unresolved chain all withhold.
func (c *depsLockfileClassifiers) public(rel string, spec secfeed.InstallSpec) bool {
	cls := c.forLockfile(rel)
	return cls != nil && cls(spec)
}

func (c *depsLockfileClassifiers) forLockfile(rel string) secfeed.Classifier {
	if c.root == "" || rel == "" || strings.Contains(rel, "\\") || path.IsAbs(rel) || filepath.IsAbs(rel) || filepath.VolumeName(rel) != "" {
		return nil
	}
	dirRel := path.Dir(path.Clean(rel))
	if dirRel == ".." || strings.HasPrefix(dirRel, "../") {
		return nil
	}
	if cls, ok := c.byDir[dirRel]; ok {
		return cls
	}
	chain, ok := depsDirChain(filepath.Join(c.root, filepath.FromSlash(dirRel)), c.root)
	var cls secfeed.Classifier
	if ok && len(chain) > 0 && chain[len(chain)-1] == c.root {
		cls = c.build(secfeed.Scope{ProjectRoot: c.root, Dirs: chain})
	}
	c.byDir[dirRel] = cls
	return cls
}

// Managed nodes (lane SEC-H2): online matching goes to the org relay
// (org.security.relay, POST /api/agent/security/lookup, the install gate's
// route) and never to a public host. The relay already answers each pinned
// public package with its OSV vulnerability ids, writes its audit rows
// before it asks anything, refuses private names under the org's own
// configuration (that package only is then withheld), and caches. A relay in mirror mode holds no vulnerability
// data, so its answers are not a match and the scan keeps the local
// database (the org mirror's OSV exports); a relay that is off, down or
// refusing leaves the ecosystem unmatched (a match error, never clean).
// Relayed matches carry advisory ids only: no severity label (the default
// severity applies) and no alias folding.

// depsRelayScanLookup is the relay call (the org client's SecurityLookup in
// production; a test passes a call to a real relay handler).
var depsRelayScanLookup = func(ctx context.Context, configPath string, req orgcontract.SecurityLookupRequest) (orgcontract.SecurityLookupResponse, error) {
	c, cleanup, enabled, err := buildOrgClient(ctx, configPath)
	if err != nil || !enabled {
		return orgcontract.SecurityLookupResponse{}, errors.New("relay_unavailable")
	}
	defer cleanup()
	return c.SecurityLookup(ctx, req)
}

// errRelayNotMatching is a relay that answered in a mode with no
// vulnerability data (mirror): the local database decides.
var errRelayNotMatching = errors.New("the org relay holds no vulnerability data in this mode")

// Relay pacing (SEC-H2 merge, audit finding 1). The relay limits each node
// to orgcontract.SecurityLookupDefaultPerMinute lookups a minute (one lookup
// is one batch of up to SecurityLookupMaxQueries names), and the install
// gate's lookups share that same per-node budget. A dependency scan
// therefore sends at most one batch per depsRelayScanInterval, half the
// default rate, so the bucket refills faster than the scan drains it and an
// install lookup is never starved into online_unknown by a scan. A 429 is
// waited out (its Retry-After, capped) and the same batch is sent again, at
// most depsRelayRateLimitRetries times. The relay still writes one audit
// row per name before it asks anything (audit before data): a scan of a
// 1,000-package lockfile writes 1,001 rows per run (every package plus the
// canary), cached answers included, in 16 batches over about 32 seconds.
//
// Since lane LEFT-SHARED the pause follows the relay's own per-node budget
// when the relay sends it (security_relay_pace.go, depsRelayInterval);
// depsRelayScanInterval is the pause at the default budget.
var (
	depsRelayScanInterval      = time.Minute / time.Duration(orgcontract.SecurityLookupDefaultPerMinute/2)
	depsRelayRateLimitRetries  = 3
	depsRelayDefaultRetryAfter = time.Minute
	depsRelayRetryAfterCap     = 2 * time.Minute
)

// relayPacer spaces the scan's relay batches. One pacer serves the whole
// process (every project and ecosystem of one scan), since the relay's
// budget is per node.
type relayPacer struct {
	mu    sync.Mutex
	next  time.Time
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

// depsRelayScanPacer is the process's pacer (a test swaps it for one on a
// fake clock).
var depsRelayScanPacer = &relayPacer{now: time.Now, sleep: sleepCtx}

// sleepCtx waits d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// wait blocks until the next batch may go, then books the one after it.
func (p *relayPacer) wait(ctx context.Context, interval time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if d := p.next.Sub(now); d > 0 {
		if err := p.sleep(ctx, d); err != nil {
			return err
		}
		now = p.now()
	}
	p.next = now.Add(interval)
	return nil
}

// hold moves the next batch to at least d from now (a Retry-After).
func (p *relayPacer) hold(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t := p.now().Add(d); t.After(p.next) {
		p.next = t
	}
}

// relayRetryAfter is the relay's 429 (orgclient.SecurityRelayRateLimitedError
// in production), read through its method so this file needs no org client
// import.
type relayRetryAfter interface {
	SecurityRelayRetryAfter() time.Duration
}

// relayMatchVulns sends specs to the relay in paced batches the route
// accepts and returns each spec's vulnerability ids, and which specs the
// relay withheld: a name the relay refuses as private under the org's own
// configuration (reason not_public) is withheld for that package only and
// never fails the rest. A batch that fails after its rate-limit retries, or
// answers a spec as failed for any other reason, fails the whole match.
func relayMatchVulns(ctx context.Context, configPath string, specs []secfeed.InstallSpec) ([][]string, []bool, error) {
	out := make([][]string, len(specs))
	withheld := make([]bool, len(specs))
	for start := 0; start < len(specs); start += orgcontract.SecurityLookupMaxQueries {
		end := min(start+orgcontract.SecurityLookupMaxQueries, len(specs))
		req := orgcontract.SecurityLookupRequest{}
		for _, s := range specs[start:end] {
			req.Queries = append(req.Queries, orgcontract.SecurityLookupQuery{Ecosystem: string(s.Eco), Name: secfeed.Normalize(s.Eco, s.Name), Version: s.Version})
		}
		var resp orgcontract.SecurityLookupResponse
		for attempt := 0; ; attempt++ {
			if err := depsRelayScanPacer.wait(ctx, depsRelayInterval()); err != nil {
				return nil, nil, err
			}
			bctx, cancel := context.WithTimeout(ctx, depsOnlineDeadline)
			r, err := depsRelayScanLookup(bctx, configPath, req)
			cancel()
			var rl relayRetryAfter
			if err != nil && errors.As(err, &rl) && attempt < depsRelayRateLimitRetries {
				d := rl.SecurityRelayRetryAfter()
				if d <= 0 {
					d = depsRelayDefaultRetryAfter
				}
				depsRelayScanPacer.hold(min(d, depsRelayRetryAfterCap))
				continue
			}
			if err != nil {
				return nil, nil, err
			}
			resp = r
			break
		}
		if resp.Mode != "relay" {
			return nil, nil, errRelayNotMatching
		}
		if len(resp.Answers) != end-start {
			return nil, nil, errors.New("the org relay answered a different number of packages")
		}
		for k, a := range resp.Answers {
			switch secfeed.OnlineStatus(a.Status) {
			case secfeed.OnlineAnswered:
				out[start+k] = a.VulnIDs
			case secfeed.OnlineNotFound:
			default:
				if a.Reason == orgcontract.SecurityLookupReasonNotPublic {
					withheld[start+k] = true
					continue
				}
				return nil, nil, errors.New("the org relay could not answer every package: " + a.Reason)
			}
		}
	}
	return out, withheld, nil
}

// relayOnlineMatcher is onlineMatcher on a managed node.
func (e *depsScanEnv) relayOnlineMatcher(root string) depdriver.OnlineMatcher {
	public := newDepsLockfileClassifiers(root, depsOnlineScanClassifier)
	return func(ctx context.Context, eco string, pkgs []depscan.Package, idx []int) (depscan.EcoResult, bool) {
		sfEco, ok := secfeed.EcosystemFromOSV(eco)
		if !ok {
			return depscan.EcoResult{}, false
		}
		var send []int
		var specs []secfeed.InstallSpec
		for _, i := range idx {
			p := pkgs[i]
			spec := secfeed.InstallSpec{Eco: sfEco, Spec: p.Name, Name: p.Name, Version: p.Version}
			if p.Version != "" && public.public(p.Path, spec) {
				send = append(send, i)
				specs = append(specs, spec)
			}
		}
		res := depscan.EcoResult{Ecosystem: eco, Packages: len(send), Withheld: len(idx) - len(send)}
		canary, hasCanary := depscan.CanaryFor(eco)
		facts := depscan.MatchFacts{DatabaseInstalled: true, HasCanary: hasCanary}
		if hasCanary {
			specs = append(specs, secfeed.InstallSpec{Eco: sfEco, Spec: canary.Name, Name: canary.Name, Version: canary.Version})
			vulns, withheld, err := relayMatchVulns(ctx, e.configPath, specs)
			switch {
			case errors.Is(err, errRelayNotMatching):
				return depscan.EcoResult{}, false
			case err != nil, withheld != nil && withheld[len(withheld)-1]:
				// A canary the relay refuses proves nothing: unmatched.
				facts.MatchError = true
			default:
				facts.CanaryHit = len(vulns[len(vulns)-1]) > 0
				for k, ids := range vulns[:len(vulns)-1] {
					if withheld[k] {
						res.Packages--
						res.Withheld++
						continue
					}
					for _, id := range ids {
						res.Advisories = append(res.Advisories, depscan.Advisory{ID: id, Index: send[k]})
					}
				}
			}
		}
		res.Outcome, res.Reason = depscan.DecideEcosystem(facts)
		if res.Outcome == depscan.EcoScanned {
			res.Epoch = "online:org relay " + time.Now().UTC().Format(time.RFC3339)
		} else {
			res.Advisories = nil
		}
		return res, true
	}
}
