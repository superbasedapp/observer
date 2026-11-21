//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secscan/depdriver"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvshard"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvshard/shardnet"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvshardkey"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_osv_remote.go is the node side of the SuperBased package lookup
// (OS and CI vulnerability scanning plan section 13, mode M1, with the
// binding spike results of 13.11; lane RM-2). In lookup mode "remote"
// ([security.deps] match) no OSV database is downloaded: each dependency
// scan looks every ecosystem up in SuperBased's hash-prefix shards; in
// "both" the local databases answer first and the shards fill only the
// ecosystems with none (ruling Q11 (a)).
//
// The walk, per ecosystem the scan's inventory holds:
//
//  1. the signed security.osv_shards manifest and its set descriptors,
//     through the security.scan.osv.db lane's content feed client and the
//     content channel's trust (signature, rollback against the kind's own
//     high-water mark, epoch, expiry, every descriptor's digest), ETag'd,
//     at most every depsDBEvery from the daemon (remoteSets);
//  2. the shards the packages' hash prefixes fall in, through the
//     security.scan.osv.shards lane (internal/secscan/osvshard/shardnet,
//     shards.superbased.app only), verified through the digest chain and
//     cached under ~/.observer/security/osv-shards/ (osvshard.Lookup);
//  3. the records that match, merged and written as the ecosystem's
//     all.zip in a run directory outside ~/.observer, matched by
//     SCALIBR's own osvlocal (scalibrfacade.Match) with the ecosystem's
//     canary, exactly as the online matcher does through the same seam
//     (depdriver.OnlineMatcher, applied to every ecosystem the local match
//     left without a database).
//
// What leaves the machine is the prefixes: no package name, version or
// path. A name the security.deps classifier cannot place as public is
// withheld (never even hashed into a request) unless the developer chose
// remote_private = send with its own consent; withheld packages keep the
// run from ever reading clean. A shard that fails makes its packages gaps
// (remote_lookup_failed); a manifest that cannot be read, or a canary whose
// shard failed, makes the ecosystem not scanned (remote_unavailable); a
// canary not flagged is self_test_failed. Every scanned ecosystem's epoch
// names the shard set and its epoch, so a finding says which data matched
// it.
//
// The gate (depsRemoteGate). On an individual node: the mode remote or
// both, the developer's signed remote-lookup consent, a content-feed key in
// this build. On a managed node the organization decides (plan section
// 13.10, lane RM-3): only its signed security policy in force
// (package_lookup = org_mirror, security_managedpull.go) turns the lookup on,
// in mode both (local databases from the org mirror first, the shards for
// the rest), with the org's private-names rule and kinds; the manifest
// comes from the org mirror's content route and every shard object from its
// shard route, through the org.client lane (orgclient.FetchSecurityShard):
// a managed node never contacts shards.superbased.app, and while the policy
// does not turn the lookup on it sends nothing at all, not even a digest.
// Turning the lookup off stops sending at once: every request re-checks the
// posture first (lookupLive: the config file's and the consent record's
// change stamps on an individual node, the stored signed policy on a
// managed one).

// The lookup modes ([security.deps] match).
const (
	lookupLocal  = "local"
	lookupRemote = "remote"
	lookupBoth   = "both"
)

// The remote kinds ([security.deps] remote_kinds).
const (
	lookupKindLanguage = "language"
	lookupKindActions  = "actions"
)

// lookupKindOf is the remote kind an OSV ecosystem belongs to.
func lookupKindOf(eco string) string {
	if eco == "GitHub Actions" {
		return lookupKindActions
	}
	return lookupKindLanguage
}

// lookupMode is the effective lookup mode: the configured one, else
// "local" for an install that already uses local databases (the accept
// recorded, an import-only source, or a database on disk), else "" (not
// chosen: a fresh install, ruling Q8 (a)). A managed node reads what its
// organization decided: "both" while the org's signed security policy turns
// the lookup on (the org mirror's databases first, its shards for the
// rest), else "local" (its organization's mirror serves its databases).
func (e *depsScanEnv) lookupMode() string {
	if e.managed {
		if e.orgLookup.On {
			return lookupBoth
		}
		return lookupLocal
	}
	if m := e.cfg.Security.Deps.Match; m != "" {
		return m
	}
	if e.consent.Accepted() || e.osvImportOnly() || e.localInstalled() {
		return lookupLocal
	}
	return ""
}

// localInstalled reports a language database on disk.
func (e *depsScanEnv) localInstalled() bool {
	eps, err := e.db.Installed()
	return err == nil && len(eps) > 0
}

// remoteMode reports a mode that looks up remotely.
func remoteMode(m string) bool { return m == lookupRemote || m == lookupBoth }

// lookupKinds are the kinds a remote lookup covers: on a managed node the
// org's (package_lookup_kinds), never the node config's.
func (e *depsScanEnv) lookupKinds() []string {
	if e.managed {
		if len(e.orgLookup.Kinds) > 0 {
			return slices.Clone(e.orgLookup.Kinds)
		}
		return slices.Clone(config.SecurityDepsRemoteKinds)
	}
	if ks := e.cfg.Security.Deps.RemoteKinds; len(ks) > 0 {
		return slices.Clone(ks)
	}
	return slices.Clone(config.SecurityDepsRemoteKinds)
}

// remotePrivateSending reports that private names are looked up too: the
// setting is send AND its own consent is recorded; on a managed node the
// org's rule (package_lookup_private = send) alone.
func (e *depsScanEnv) remotePrivateSending() bool {
	if e.managed {
		return e.orgLookup.On && e.orgLookup.Private
	}
	return e.cfg.Security.Deps.RemotePrivate == "send" && e.remotePrivate.Accepted()
}

// depsRemoteGate is the gate in front of the remote lookup, walked top
// down.
var depsRemoteGate = depsGate{
	// A managed node: only the org's signed policy turns it on (lane RM-3).
	{orgLookupOffReason, func(e *depsScanEnv) bool { return e.managed && !e.orgLookup.On }},
	{"lookup_mode_local", func(e *depsScanEnv) bool { return !remoteMode(e.lookupMode()) }},
	// The developer's consent is an individual node's; a managed node's
	// lookup is its organization's decision, never the developer's.
	{depscan.ReasonRemoteNotAccepted, func(e *depsScanEnv) bool { return !e.managed && !e.remoteConsent.Accepted() }},
	{"not_verifiable_no_feed_key", func(*depsScanEnv) bool { return len(depsTrust().FeedKeys) == 0 }},
}

// remoteBlocked returns the remote gate's first closed reason, "" when a
// remote lookup may run.
func (e *depsScanEnv) remoteBlocked() string { return depsRemoteGate.first(e) }

// scanWaitReason is why no dependency scan may run yet, "" when one may: a
// fresh install that chose nothing (lookup_not_chosen), local mode before
// the database accept with nothing on disk (database_not_accepted), remote
// mode before the remote consent (remote_not_accepted). Such a run starts
// no driver and claims nothing. A managed node and an import-only node
// never wait.
func (e *depsScanEnv) scanWaitReason() string {
	if e.managed || e.osvImportOnly() {
		return ""
	}
	installed := e.localInstalled()
	switch e.lookupMode() {
	case "":
		if installed {
			return ""
		}
		return depscan.ReasonLookupNotChosen
	case lookupLocal:
		if e.consent.Accepted() || installed {
			return ""
		}
		return depscan.ReasonDBNotAccepted
	case lookupRemote:
		if e.remoteConsent.Accepted() {
			return ""
		}
		return depscan.ReasonRemoteNotAccepted
	case lookupBoth:
		if e.remoteConsent.Accepted() || e.consent.Accepted() || installed {
			return ""
		}
		return depscan.ReasonRemoteNotAccepted
	}
	return depscan.ReasonLookupNotChosen
}

// postureNote is the fixed-text note a run records about the lookup posture
// it ran under; "" in plain local mode (nothing to say).
func (e *depsScanEnv) postureNote(driverID string) string {
	if e.managed && !e.orgLookup.On {
		return ""
	}
	mode := e.lookupMode()
	if !remoteMode(mode) {
		return ""
	}
	if e.remoteBlocked() != "" {
		return "package lookup: " + mode + ", the superbased lookup did not run (" + e.remoteBlocked() + ")"
	}
	if driverID != depscan.ScalibrID {
		return "package lookup: " + mode + "; this driver matches local databases only"
	}
	private := "private names withheld"
	if e.remotePrivateSending() {
		private = "private names sent"
	}
	if e.managed {
		return "package lookup: set by your organization, " + mode + " via its org server's mirror; kinds " + strings.Join(e.lookupKinds(), ", ") + "; " + private
	}
	return "package lookup: " + mode + " via " + osvdb.RemoteShardHost + "; kinds " + strings.Join(e.lookupKinds(), ", ") + "; " + private
}

// matchEpochs is the local epochs a driver matches against: none in mode
// remote (every ecosystem is looked up), all of them otherwise.
func (e *depsScanEnv) matchEpochs(eps map[string]string) map[string]string {
	if !e.managed && e.lookupMode() == lookupRemote {
		return map[string]string{}
	}
	return eps
}

// --- the signed shard manifest -------------------------------------------

// remoteSetsState memoizes one env's shard sets.
type remoteSetsState struct {
	once sync.Once
	sets map[string]osvshardkey.SetDescriptor // by OSV ecosystem
	err  error
}

// remoteManifestEvery is how often the daemon re-fetches the shard
// manifest (an ETag'd GET; the CLI always does).
var remoteManifestEvery = depsDBEvery

// remoteManifestLast is the process's last manifest fetch.
var remoteManifestLast struct {
	sync.Mutex
	at time.Time
}

// errRemoteUnavailable is a shard manifest that cannot serve.
var errRemoteUnavailable = errors.New(depscan.ReasonRemoteUnavailable)

// remoteSets returns the verified shard sets by OSV ecosystem: the
// security.osv_shards kind fetched (when due, or always with
// e.remoteFetchAlways) into the content root and loaded with the content
// channel's trust. A manifest that does not load, or one past its age
// floor, is an error: every remote ecosystem then reads remote_unavailable.
func (e *depsScanEnv) remoteSets(ctx context.Context) (map[string]osvshardkey.SetDescriptor, error) {
	if e.remote == nil {
		e.remote = &remoteSetsState{}
	}
	e.remote.once.Do(func() { e.remote.sets, e.remote.err = e.loadRemoteSets(ctx) })
	return e.remote.sets, e.remote.err
}

func (e *depsScanEnv) loadRemoteSets(ctx context.Context) (map[string]osvshardkey.SetDescriptor, error) {
	if why := e.remoteBlocked(); why != "" {
		return nil, fmt.Errorf("%w: %s", errRemoteUnavailable, why)
	}
	tr := depsTrust()
	st := depsContentStore(depsConfigPath(e.configPath))
	remoteManifestLast.Lock()
	due := e.remoteFetchAlways || time.Since(remoteManifestLast.at) >= remoteManifestEvery
	remoteManifestLast.Unlock()
	if _, err := st.State(content.OSVShards); err != nil {
		due = true
	}
	if due && lookupLive(e) && e.managed {
		// A managed node takes the manifest from its org mirror only (the
		// org.client lane), never from the vendor feed.
		ferr := fetchFromOrgMirror(ctx, e.configPath, st, []content.Kind{content.OSVShards}, tr)
		remoteManifestLast.Lock()
		remoteManifestLast.at = time.Now()
		if ferr != nil {
			remoteManifestLast.at = time.Now().Add(time.Hour - remoteManifestEvery)
		}
		remoteManifestLast.Unlock()
		if ferr != nil {
			e.logger.Warn("security: the shard manifest could not be fetched from the org mirror; the installed one stays in use", "err", ferr)
		}
	} else if due && lookupLive(e) {
		tags := readDepsFeedETags(st)
		res, ferr := st.FetchInstall(ctx, content.OSVShards, tr, osvFeedSource{c: depsOSVFeed()}, tags[string(content.OSVShards)])
		if ferr == nil {
			writeDepsFeedETag(st, tags, content.OSVShards, res.ETag)
			remoteManifestLast.Lock()
			remoteManifestLast.at = time.Now()
			remoteManifestLast.Unlock()
		} else {
			// Retry within the hour, not at every 15-minute tick.
			remoteManifestLast.Lock()
			remoteManifestLast.at = time.Now().Add(time.Hour - remoteManifestEvery)
			remoteManifestLast.Unlock()
			e.logger.Warn("security: the shard manifest could not be fetched; the installed one stays in use", "err", ferr)
		}
	}
	l, err := st.Load(content.OSVShards, tr, depsAdvisoryFloor(e.cfg.Security))
	if err != nil {
		return nil, fmt.Errorf("%w: no verified shard manifest: %w", errRemoteUnavailable, err)
	}
	if l.Freshness == content.Unknown {
		return nil, fmt.Errorf("%w: the shard manifest is past its age floor", errRemoteUnavailable)
	}
	out := map[string]osvshardkey.SetDescriptor{}
	for _, d := range shardSetsOf(l) {
		out[d.Ecosystem] = d
	}
	return out, nil
}

// shardSetsOf decodes the set descriptors a verified manifest names (each
// one's bytes already checked against the signed digest by the content
// channel), in set order; a descriptor that does not decode, or whose set
// does not match its file name, is skipped (its ecosystem then has no set
// and reads remote_unavailable).
func shardSetsOf(l contentchan.Loaded) []osvshardkey.SetDescriptor {
	var out []osvshardkey.SetDescriptor
	for _, ent := range l.Manifest.Entries {
		if !strings.HasSuffix(ent.Name, ".set.json") {
			continue
		}
		b, err := l.ReadArtifact(ent.Name)
		if err != nil {
			continue
		}
		d, err := osvshardkey.DecodeSet(b)
		if err != nil || osvshardkey.SetFile(d.Set) != ent.Name {
			continue
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Set < out[j].Set })
	return out
}

// remoteTag names the shard sets' epochs for the scan due-ness check, so a
// new epoch makes every project due (the role the database epoch plays
// locally); "" when no remote lookup applies.
func (e *depsScanEnv) remoteTag(ctx context.Context) string {
	if e.remoteBlocked() != "" {
		return ""
	}
	sets, err := e.remoteSets(ctx)
	if err != nil {
		return "unavailable"
	}
	parts := make([]string, 0, len(sets))
	for _, d := range sets {
		parts = append(parts, d.Set+"@"+strconv.FormatInt(d.Epoch, 10))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// scanEpoch is what a scan is recorded and due-checked against: the local
// epochs it matches and, with a remote lookup, the shard sets' epochs.
func (e *depsScanEnv) scanEpoch(ctx context.Context) string {
	eps, _ := e.db.Installed()
	s := depdriver.EpochSummary(e.matchEpochs(eps))
	if tag := e.remoteTag(ctx); tag != "" {
		s += " | remote " + tag
	}
	return s
}

// --- the lookup ---------------------------------------------------------

// depsShardFetcher is the shard lane (shardnet); a test swaps it.
var depsShardFetcher = func() osvshard.Fetcher { return shardnet.New(shardnet.Options{}) }

// lookupLive re-reads the posture before a request (plan section 13.10:
// turning a lookup off stops sending at once): on an individual node the
// config file's mode and the remote consent record, by their change stamps,
// so an unchanged posture costs two stats; on a managed node the stored
// signed policy (orgLookupLive), at most every orgLookupRecheck.
func lookupLive(e *depsScanEnv) bool {
	if e.live == nil {
		return true
	}
	return e.live.allowed()
}

// lookupGate is a posture re-check before each request.
type lookupGate interface{ allowed() bool }

// orgLookupRecheck bounds how stale a managed node's re-read of its org's
// posture may be (a read of the verified store, not a request).
const orgLookupRecheck = 5 * time.Second

// orgLookupLive re-reads a managed node's org posture before a request.
type orgLookupLive struct {
	mu   sync.Mutex
	read func() orgLookupPosture
	at   time.Time
	ok   bool
}

func (o *orgLookupLive) allowed() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.at.IsZero() && time.Since(o.at) < orgLookupRecheck {
		return o.ok
	}
	o.ok, o.at = o.read().On, time.Now()
	return o.ok
}

// lookupStamp watches the files the posture lives in.
type lookupStamp struct {
	mu         sync.Mutex
	configPath string
	dir        string
	cfgStamp   time.Time
	recStamp   time.Time
	ok         bool
}

func fileStamp(p string) time.Time {
	if fi, err := os.Stat(p); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}

func newLookupStamp(e *depsScanEnv) *lookupStamp {
	resolved, _ := config.ResolveGlobalPath(e.configPath)
	s := &lookupStamp{configPath: resolved, dir: e.dir, ok: true}
	s.cfgStamp, s.recStamp = fileStamp(resolved), fileStamp(filepath.Join(e.dir, osvdb.RemoteConsentFile))
	return s
}

func (s *lookupStamp) allowed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, r := fileStamp(s.configPath), fileStamp(filepath.Join(s.dir, osvdb.RemoteConsentFile))
	if c.Equal(s.cfgStamp) && r.Equal(s.recStamp) {
		return s.ok
	}
	s.cfgStamp, s.recStamp = c, r
	cfg, err := config.Load(config.LoadOptions{GlobalPath: s.configPath})
	if err != nil || !remoteMode(cfg.Security.Deps.Match) {
		s.ok = false
		return false
	}
	s.ok = osvdb.ReadRemoteConsent(s.dir, depsRecordKey(s.dir)).Accepted()
	return s.ok
}

// gatedFetcher refuses every request once the posture no longer allows it.
type gatedFetcher struct {
	inner osvshard.Fetcher
	live  func() bool
}

func (g gatedFetcher) Fetch(ctx context.Context, path string, max int64) ([]byte, error) {
	if !g.live() {
		return nil, errors.New("the superbased lookup was turned off")
	}
	return g.inner.Fetch(ctx, path, max)
}

// remoteMatcher returns the remote lookup matcher for a project, or nil
// when the remote gate is closed. It answers an ecosystem the local match
// left without a database (every one in mode remote), of a kind the
// developer chose.
func (e *depsScanEnv) remoteMatcher(root string) depdriver.OnlineMatcher {
	if e.remoteBlocked() != "" {
		return nil
	}
	if e.live == nil {
		if e.managed {
			e.live = &orgLookupLive{read: e.readOrgLookup}
		} else {
			e.live = newLookupStamp(e)
		}
	}
	public := newDepsLockfileClassifiers(root, depsOnlineScanClassifier)
	sendPrivate := e.remotePrivateSending()
	kinds := e.lookupKinds()
	cache := osvshard.Cache{Dir: filepath.Join(e.dir, osvshard.CacheDirName)}
	source := osvdb.RemoteShardHost
	if e.managed {
		source = orgMirrorSource
	}
	// fetcher opens the lane for one walk: the shard host on an individual
	// node; the org client (org.client lane) on a managed node, closed when
	// the walk ends.
	fetcher := func(ctx context.Context) (osvshard.Fetcher, func(), error) {
		if e.managed {
			return depsOrgShardFetcher(ctx, e.configPath)
		}
		return depsShardFetcher(), func() {}, nil
	}
	return func(ctx context.Context, eco string, pkgs []depscan.Package, idx []int) (depscan.EcoResult, bool) {
		if !slices.Contains(kinds, lookupKindOf(eco)) {
			return depscan.EcoResult{}, false
		}
		res := depscan.EcoResult{Ecosystem: eco, Packages: len(idx)}
		notScanned := func(reason string) (depscan.EcoResult, bool) {
			res.Outcome, res.Reason, res.Advisories = depscan.EcoNotScanned, reason, nil
			return res, true
		}
		canary, hasCanary := depscan.CanaryFor(eco)
		if !hasCanary {
			return notScanned(depscan.ReasonNoCanary)
		}
		send := remoteSendable(eco, pkgs, idx, public, sendPrivate)
		res.Packages, res.Withheld = len(send), len(idx)-len(send)
		sets, err := e.remoteSets(ctx)
		if err != nil {
			return notScanned(depscan.ReasonRemoteUnavailable)
		}
		set, ok := sets[eco]
		if !ok {
			return notScanned(depscan.ReasonRemoteUnavailable)
		}
		names := osvshard.Spellings(eco, canary.Name)
		for _, i := range send {
			names = append(names, osvshard.Spellings(eco, pkgs[i].Name)...)
		}
		f, done, ferr := fetcher(ctx)
		if ferr != nil {
			return notScanned(depscan.ReasonRemoteUnavailable)
		}
		lookup := osvshard.Lookup{Fetch: gatedFetcher{inner: f, live: func() bool { return lookupLive(e) }}, Cache: cache}
		ans, err := lookup.Run(ctx, osvshard.Query{Set: set, Names: names})
		done()
		_ = lookup.Cache.Trim()
		if err != nil || ans.NameFailed(set.Base, canary.Name) {
			return notScanned(depscan.ReasonRemoteUnavailable)
		}
		var match []int
		for _, i := range send {
			if ans.NameFailed(set.Base, pkgs[i].Name) {
				res.LookupGaps++
				continue
			}
			match = append(match, i)
		}
		res.Packages = len(match)
		m, merr := matchAssembled(ctx, eco, ans.Records, pkgs, match, canary)
		facts := depscan.MatchFacts{DatabaseInstalled: true, HasCanary: true}
		switch {
		case errors.Is(merr, scalibrfacade.ErrNotCompiled):
			return depscan.EcoResult{}, false
		case errors.Is(merr, scalibrfacade.ErrNoDatabase):
			facts.NoDatabase = true
		case merr != nil:
			facts.MatchError = true
		default:
			facts.CanaryHit = m.CanaryHit
			for _, v := range m.Vulns {
				res.Advisories = append(res.Advisories, depscan.Advisory{ID: v.ID, Aliases: v.Aliases, Severity: v.Severity, Index: v.Index})
			}
		}
		res.Outcome, res.Reason = depscan.DecideEcosystem(facts)
		if res.Outcome == depscan.EcoScanned {
			res.Epoch = remoteEpochFrom(source, set)
		} else {
			res.Advisories = nil
		}
		return res, true
	}
}

// remoteEpochFrom is what a remotely matched ecosystem records as its
// epoch: the source (the shard host, or the org mirror on a managed node),
// the set and its epoch, so every finding names its data.
func remoteEpochFrom(source string, d osvshardkey.SetDescriptor) string {
	return "remote:" + source + " " + d.Set + "@" + strconv.FormatInt(d.Epoch, 10)
}

// orgMirrorSource names the org mirror as a remote epoch's source.
const orgMirrorSource = "org mirror"

// remoteSendable are the packages of idx whose name may be looked up: each
// classified with its own lockfile's configuration exactly as online
// matching does; an ecosystem the classifier cannot prove public offline
// withholds every name, unless private names are sent too: Maven, GitHub
// Actions and the six mirrored since 2026-11-06 (Pub, SwiftURL, Hex,
// Hackage, Julia, CRAN) have no row in its table, RubyGems and Packagist a
// row but no classifier (docs/dependency-scanning.md "Remote lookup",
// "Which ecosystems can send names", says why each one is not provable;
// TestRemoteSendableWithholdsUnprovableNames pins it).
func remoteSendable(eco string, pkgs []depscan.Package, idx []int, public *depsLockfileClassifiers, sendPrivate bool) []int {
	if sendPrivate {
		return append([]int(nil), idx...)
	}
	sfEco, ok := secfeed.EcosystemFromOSV(eco)
	if !ok {
		return nil
	}
	var out []int
	for _, i := range idx {
		p := pkgs[i]
		if public.public(p.Path, secfeed.InstallSpec{Eco: sfEco, Spec: p.Name, Name: p.Name, Version: p.Version}) {
			out = append(out, i)
		}
	}
	return out
}

// matchAssembled writes the records as eco's all.zip in a run directory
// outside ~/.observer and matches the packages and the canary against it
// with SCALIBR's own matcher; the directory is removed after.
func matchAssembled(ctx context.Context, eco string, recs []osvshard.Record, pkgs []depscan.Package, idx []int, canary depscan.Canary) (scalibrfacade.MatchResult, error) {
	base, err := depsScanCacheRoot()
	if err != nil {
		return scalibrfacade.MatchResult{}, err
	}
	runs := filepath.Join(base, "remote")
	if err := os.MkdirAll(runs, 0o700); err != nil {
		return scalibrfacade.MatchResult{}, err
	}
	dir, err := os.MkdirTemp(runs, "lookup-")
	if err != nil {
		return scalibrfacade.MatchResult{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	// SCALIBR's default logger would print the run directory's path.
	scalibrfacade.SetLog(nil)
	if err := osvshard.InstallExport(dir, eco, recs); err != nil {
		return scalibrfacade.MatchResult{}, err
	}
	return scalibrfacade.Match(ctx, scalibrfacade.NewInventory(facadeRows(pkgs)), scalibrfacade.MatchRequest{
		Ecosystem: eco, Indices: idx, Canary: &scalibrfacade.Canary{Name: canary.Name, Version: canary.Version},
	}, scalibrfacade.MatchOptions{DBDir: dir})
}

// chainMatchers tries each matcher in order; the first that answers wins.
func chainMatchers(ms ...depdriver.OnlineMatcher) depdriver.OnlineMatcher {
	var live []depdriver.OnlineMatcher
	for _, m := range ms {
		if m != nil {
			live = append(live, m)
		}
	}
	switch len(live) {
	case 0:
		return nil
	case 1:
		return live[0]
	}
	return func(ctx context.Context, eco string, pkgs []depscan.Package, idx []int) (depscan.EcoResult, bool) {
		for _, m := range live {
			if r, ok := m(ctx, eco, pkgs, idx); ok {
				return r, true
			}
		}
		return depscan.EcoResult{}, false
	}
}

// --- the managed half (lane RM-3) -----------------------------------------

// orgLookupOffReason is the remote gate's reason on a managed node whose
// org's signed security policy does not turn the package lookup on.
const orgLookupOffReason = "org_lookup_not_enabled"

// orgLookupPosture is a managed node's package lookup posture, as its org's
// signed security policy in force decides it (orgcontract
// SecurityManagedPolicyV1: package_lookup, package_lookup_private,
// package_lookup_kinds). The zero value is off.
type orgLookupPosture struct {
	// On: package_lookup = org_mirror in a body in force.
	On bool
	// Private: package_lookup_private = send.
	Private bool
	// Kinds: package_lookup_kinds (nil: every kind this build looks up).
	Kinds []string
	// Version is the signed document's version (0 with none stored).
	Version int64
}

// depsOrgLookupFor reads the managed node's org posture from the verified
// store (the same read in the daemon and in a CLI process); a test swaps
// it. Nothing stored, nothing in force or a body this build refuses reads
// off.
var depsOrgLookupFor = func(ctx context.Context, cfg config.Config, st *store.Store) orgLookupPosture {
	s, err := securityManagedPersisted(ctx, cfg, st, securityManagedConsent(ctx, st, time.Now()))
	if err != nil {
		return orgLookupPosture{}
	}
	return orgLookupFromPolicy(s.Policy, s.Outcome.Version)
}

// orgLookupFromPolicy is the pure half of depsOrgLookupFor.
func orgLookupFromPolicy(p *orgcontract.SecurityManagedPolicyV1, version int64) orgLookupPosture {
	out := orgLookupPosture{Version: version}
	if !orgcontract.SecurityPackageLookupOn(p) {
		return out
	}
	out.On = true
	out.Private = p.PackageLookupPrivate == "send"
	out.Kinds = slices.Clone(p.PackageLookupKinds)
	return out
}

// readOrgLookup re-reads the env's org posture (orgLookupLive).
func (e *depsScanEnv) readOrgLookup() orgLookupPosture {
	if e.st == nil {
		return e.orgLookup
	}
	return depsOrgLookupFor(context.Background(), e.cfg, e.st)
}

// depsOrgShardFetcher opens the org client as the walk's Fetcher on a
// managed node: the enrolled org server's shard route only, over the
// org.client lane. A test swaps it.
var depsOrgShardFetcher = func(ctx context.Context, configPath string) (osvshard.Fetcher, func(), error) {
	c, cleanup, enabled, err := buildOrgClient(ctx, configPath)
	if err != nil {
		return nil, nil, err
	}
	if !enabled {
		cleanup()
		return nil, nil, errors.New("not enrolled with an org server")
	}
	return orgclient.SecurityShardFetcher{Client: c}, cleanup, nil
}
