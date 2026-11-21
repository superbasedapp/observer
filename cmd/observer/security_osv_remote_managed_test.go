//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvshard"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// TestOrgLookupFromPolicy pins the pure read of the org's signed policy
// (lane RM-3): only package_lookup = org_mirror turns the lookup on; the
// private-names rule and the kinds ride along only then.
func TestOrgLookupFromPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *orgcontract.SecurityManagedPolicyV1
		want orgLookupPosture
	}{
		{"no body in force", nil, orgLookupPosture{Version: 4}},
		{"absent is off", &orgcontract.SecurityManagedPolicyV1{Version: 1, PackageLookupPrivate: "send"}, orgLookupPosture{Version: 4}},
		{"off", &orgcontract.SecurityManagedPolicyV1{Version: 1, PackageLookup: "off"}, orgLookupPosture{Version: 4}},
		{"on", &orgcontract.SecurityManagedPolicyV1{Version: 1, PackageLookup: "org_mirror"}, orgLookupPosture{On: true, Version: 4}},
		{
			"on, private sent, kinds",
			&orgcontract.SecurityManagedPolicyV1{Version: 1, PackageLookup: "org_mirror", PackageLookupPrivate: "send", PackageLookupKinds: []string{"language"}},
			orgLookupPosture{On: true, Private: true, Kinds: []string{"language"}, Version: 4},
		},
	} {
		got := orgLookupFromPolicy(tc.p, 4)
		if got.On != tc.want.On || got.Private != tc.want.Private || strings.Join(got.Kinds, ",") != strings.Join(tc.want.Kinds, ",") || got.Version != tc.want.Version {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// TestManagedLookupGateRows walks the remote gate on a managed node: closed
// (org_lookup_not_enabled) until the org's policy turns the lookup on,
// whatever the node config or the developer's records say; open then with
// no developer consent, in mode both, with the org's private-names rule and
// kinds; and the developer's own settings never count.
func TestManagedLookupGateRows(t *testing.T) {
	feedTrust(t, true)
	remoteOK := osvdb.RemoteConsent{Consent: osvdb.Consent{Version: osvdb.RemoteConsentVersion, Surface: "cli", Verified: true}}
	cfg := config.Default()
	cfg.Security.Deps.Match = lookupRemote
	cfg.Security.Deps.RemotePrivate = "send"
	cfg.Security.Deps.RemoteKinds = []string{"actions"}
	off := depsScanEnv{cfg: cfg, managed: true, remoteConsent: remoteOK, db: osvdb.Open(t.TempDir())}
	if got := off.remoteBlocked(); got != orgLookupOffReason {
		t.Fatalf("org off: gate %q, want %q", got, orgLookupOffReason)
	}
	if off.lookupMode() != lookupLocal || off.remoteMatcher(t.TempDir()) != nil || off.postureNote(depscan.ScalibrID) != "" || off.remotePrivateSending() {
		t.Fatal("a managed node whose org did not turn the lookup on must not look anything up")
	}
	on := depsScanEnv{cfg: cfg, managed: true, db: osvdb.Open(t.TempDir()), orgLookup: orgLookupPosture{On: true}}
	if got := on.remoteBlocked(); got != "" {
		t.Fatalf("org on: gate %q (the developer's consent is not part of a managed node's posture)", got)
	}
	if on.lookupMode() != lookupBoth || on.scanWaitReason() != "" {
		t.Fatalf("org on: mode %q wait %q", on.lookupMode(), on.scanWaitReason())
	}
	if on.remotePrivateSending() || strings.Join(on.lookupKinds(), ",") != strings.Join(config.SecurityDepsRemoteKinds, ",") {
		t.Fatalf("org on: the node config's private and kinds leaked in: %v %v", on.remotePrivateSending(), on.lookupKinds())
	}
	if n := on.postureNote(depscan.ScalibrID); !strings.Contains(n, "set by your organization") || strings.Contains(n, osvdb.RemoteShardHost) {
		t.Fatalf("posture note %q", n)
	}
	sending := depsScanEnv{cfg: cfg, managed: true, db: osvdb.Open(t.TempDir()), orgLookup: orgLookupPosture{On: true, Private: true, Kinds: []string{"language"}}}
	if !sending.remotePrivateSending() || strings.Join(sending.lookupKinds(), ",") != "language" {
		t.Fatalf("org rule: private %v kinds %v", sending.remotePrivateSending(), sending.lookupKinds())
	}
	// The download gate is unchanged: a managed node downloads from its
	// org mirror only.
	if got := on.downloadBlocked(); got != "managed_node_uses_org_mirror" {
		t.Fatalf("download gate %q", got)
	}
}

// managedRemoteEnv opens a managed env whose org turns the lookup on: the
// shard manifest comes from the fake org mirror, the objects from the fake
// org shard route (bucket); the public feed and the public shard host fail
// the test if reached.
func managedRemoteEnv(t *testing.T, bucket *remoteBucket, posture *atomic.Pointer[orgLookupPosture]) (*depsScanEnv, *fakeOrgMirror, *atomic.Int64) {
	t.Helper()
	priv := feedTrust(t, true)
	set, objs := remoteShardSet(t, "npm", "npm", 13, []remoteTestRecord{
		remoteRecord("GHSA-canary-0001", "npm", "lodash", "4.17.20", "4.17.21"),
		remoteRecord("GHSA-leftpad-0001", "npm", "left-pad", "1.0.0", "1.0.1"),
	})
	for k, v := range objs {
		bucket.objs[k] = v
	}
	files := remoteManifestFiles(t, priv, set)
	arts := map[string][]byte{}
	prefix := string(content.OSVShards) + "/"
	for k, v := range files {
		if n := strings.TrimPrefix(k, prefix); n != contentchan.ManifestFile {
			arts[n] = v
		}
	}
	fm := &fakeOrgMirror{kinds: map[content.Kind]struct {
		env  []byte
		arts map[string][]byte
	}{content.OSVShards: {files[prefix+contentchan.ManifestFile], arts}}}
	prevMirror := depsOrgMirror
	depsOrgMirror = func(context.Context, string) (depsMirrorInstaller, func(), error) { return fm, func() {}, nil }
	t.Cleanup(func() { depsOrgMirror = prevMirror })
	opened := &atomic.Int64{}
	prevOrg := depsOrgShardFetcher
	depsOrgShardFetcher = func(context.Context, string) (osvshard.Fetcher, func(), error) {
		opened.Add(1)
		return bucket, func() {}, nil
	}
	t.Cleanup(func() { depsOrgShardFetcher = prevOrg })
	public := &fakeOSVFeed{files: map[string][]byte{}, down: true}
	useOSVFeed(t, public)
	t.Cleanup(func() {
		if public.requests.Load() != 0 {
			t.Errorf("a managed node reached the vendor feed %d times", public.requests.Load())
		}
	})
	prevPublic := depsShardFetcher
	depsShardFetcher = func() osvshard.Fetcher {
		t.Error("a managed node opened the public shard lane")
		return &remoteBucket{objs: map[string][]byte{}}
	}
	t.Cleanup(func() { depsShardFetcher = prevPublic })
	prevPosture := depsOrgLookupFor
	depsOrgLookupFor = func(context.Context, config.Config, *store.Store) orgLookupPosture { return *posture.Load() }
	t.Cleanup(func() { depsOrgLookupFor = prevPosture })
	e, err := openDepsScanEnv(context.Background(), managedDepsConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.cleanup)
	// The tenancy read needs an honoured governance grant, which the test
	// store does not carry; the env is opened as openDepsScanEnv opens a
	// managed one (the managed tenancy itself is pinned elsewhere).
	e.managed = true
	e.orgLookup = depsOrgLookupFor(context.Background(), e.cfg, e.st)
	e.remoteFetchAlways = true
	return e, fm, opened
}

// TestManagedLookupThroughTheOrgMirror (lane RM-3): with the org's policy on,
// the manifest comes from the org mirror and every object from the org's
// shard route; requests name only digests; the epoch names the org mirror;
// the status shows the org's posture read-only. With it off, nothing is
// requested at all, and turning it off mid-scan stops sending at once.
func TestManagedLookupThroughTheOrgMirror(t *testing.T) {
	if !scalibrfacade.Compiled {
		t.Skip("SCALIBR is not compiled into this build")
	}
	posture := &atomic.Pointer[orgLookupPosture]{}
	posture.Store(&orgLookupPosture{On: true, Version: 11})
	bucket := &remoteBucket{objs: map[string][]byte{}}
	e, fm, opened := managedRemoteEnv(t, bucket, posture)
	if e.remoteBlocked() != "" || e.lookupMode() != lookupBoth {
		t.Fatalf("gate %q mode %q", e.remoteBlocked(), e.lookupMode())
	}
	m := e.remoteMatcher(t.TempDir())
	if m == nil {
		t.Fatal("no remote matcher on a managed node whose org turned the lookup on")
	}
	pkgs := []depscan.Package{{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0", Path: "package-lock.json"}}
	res, ok := m(context.Background(), "npm", pkgs, []int{0})
	if !ok || res.Outcome != depscan.EcoScanned || len(res.Advisories) != 1 || res.Advisories[0].ID != "GHSA-leftpad-0001" {
		t.Fatalf("result %+v %v", res, ok)
	}
	if !strings.HasPrefix(res.Epoch, "remote:org mirror npm@7") {
		t.Fatalf("epoch %q does not name the org mirror", res.Epoch)
	}
	if len(fm.calls) == 0 || fm.calls[0] != content.OSVShards || opened.Load() == 0 {
		t.Fatalf("manifest from the org mirror %v, org fetcher opened %d", fm.calls, opened.Load())
	}
	for _, p := range bucket.asked {
		if strings.Contains(p, "left-pad") || strings.Contains(p, "lodash") || !strings.HasPrefix(p, "npm/") {
			t.Fatalf("request %s names a package or leaves the set", p)
		}
	}
	var out bytes.Buffer
	writeLookupState(context.Background(), &out, e)
	st := lookupStatus(context.Background(), e)
	if st.Org == nil || !st.Org.On || st.Org.Version != 11 || st.Org.Private != "withhold" || !strings.Contains(out.String(), "set by your organization (security policy version 11)") ||
		!strings.Contains(out.String(), "mirror mode") || strings.Contains(out.String(), osvdb.RemoteShardHost) {
		t.Fatalf("status %+v\n%s", st.Org, out.String())
	}
	if err := applyLookupChange(context.Background(), e, lookupChange{surface: "cli"}); !errors.Is(err, errLookupManaged) {
		t.Fatalf("a managed node's posture changed: %v", err)
	}

	// Turned off by the org: the next request is refused before it leaves
	// (the cache is emptied so the walk would have to ask).
	posture.Store(&orgLookupPosture{Version: 12})
	live := e.live.(*orgLookupLive)
	live.mu.Lock()
	live.at = live.at.Add(-2 * orgLookupRecheck)
	live.mu.Unlock()
	if err := os.RemoveAll(filepath.Join(e.dir, osvshard.CacheDirName)); err != nil {
		t.Fatal(err)
	}
	before := len(bucket.asked)
	res, _ = m(context.Background(), "npm", pkgs, []int{0})
	if len(bucket.asked) != before {
		t.Fatalf("%d requests after the org turned the lookup off", len(bucket.asked)-before)
	}
	if res.Outcome == depscan.EcoScanned {
		t.Fatalf("an ecosystem read scanned with the lookup turned off: %+v", res)
	}
}

// TestManagedLookupOffSendsNothing: a managed node whose org's policy does
// not turn the lookup on opens no fetcher, fetches no shard manifest and
// sends not even a digest.
func TestManagedLookupOffSendsNothing(t *testing.T) {
	posture := &atomic.Pointer[orgLookupPosture]{}
	posture.Store(&orgLookupPosture{Version: 3})
	bucket := &remoteBucket{objs: map[string][]byte{}}
	e, fm, opened := managedRemoteEnv(t, bucket, posture)
	if e.remoteBlocked() != orgLookupOffReason || e.remoteMatcher(t.TempDir()) != nil {
		t.Fatalf("gate %q", e.remoteBlocked())
	}
	if _, err := e.remoteSets(context.Background()); err == nil {
		t.Fatal("the shard manifest loaded with the lookup off")
	}
	if e.remoteTag(context.Background()) != "" {
		t.Fatal("a remote tag with the lookup off")
	}
	if len(fm.calls) != 0 || opened.Load() != 0 || len(bucket.asked) != 0 {
		t.Fatalf("sent with the lookup off: mirror %v, fetcher %d, objects %v", fm.calls, opened.Load(), bucket.asked)
	}
	var out bytes.Buffer
	writeLookupState(context.Background(), &out, e)
	if !strings.Contains(out.String(), "off by your organization's policy") {
		t.Fatalf("status:\n%s", out.String())
	}
}
