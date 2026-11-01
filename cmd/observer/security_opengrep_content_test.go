//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep/opengrepnet"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_opengrep_content_test.go is lane SEC-G2 milestone 2: the rule
// pack and the engine manifest from the vendor feed and from the org
// mirror, through the signed content channel with its rules unchanged.

// fakeFeed is the vendor feed: kind/file to bytes, or err for every call.
type fakeFeed struct {
	files map[string][]byte
	err   error
	calls int
}

func (f *fakeFeed) FetchFeedFile(_ context.Context, kind, file string, _ int64) ([]byte, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.files[kind+"/"+file]
	if !ok {
		return nil, opengrepnet.ErrNotPublished
	}
	return b, nil
}

func useFeed(t *testing.T, f *fakeFeed) {
	t.Helper()
	prev := codeFeedNet
	codeFeedNet = func() codeFeedClient { return f }
	t.Cleanup(func() { codeFeedNet = prev })
}

// signPack returns a signed rule pack envelope and its bundle.
func signPack(t *testing.T, priv ed25519.PrivateKey, p *secrulepack.Pack, mv int64) (env, bundle []byte) {
	t.Helper()
	bundle, err := secrulepack.EncodeBundle(p)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: content.RulePack, ManifestVersion: mv, Epoch: mv,
		IssuedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
		Entries: []content.Entry{{
			Name: secrulepack.BundleName, Version: p.Version(), SizeBytes: int64(len(bundle)), SHA256: content.HashBytes(bundle),
			License: "Apache-2.0", Upstream: content.UpstreamCheck{Method: content.UpstreamNone},
		}},
	}
	e, err := content.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	env, _ = content.EncodeEnvelope(e)
	return env, bundle
}

// feedEngineInstalled stands in an installed engine for the feed's P-061
// precondition.
func feedEngineInstalled(t *testing.T) {
	t.Helper()
	prev := codeContentEngineInstalled
	codeContentEngineInstalled = func(context.Context, *codeEnv) bool { return true }
	t.Cleanup(func() { codeContentEngineInstalled = prev })
}

func TestFeedRulePackNewestWinsAndOutageKeepsLastKnownGood(t *testing.T) {
	// The fed versions sit above the embedded pack (9.x), so the test does
	// not go stale when the floor's version moves (it did at pack 1.3.0;
	// lane LEFT-SEC moved it to 1.3.1).
	priv := codeTestKeys(t)
	feedEngineInstalled(t)
	e := openSelected(t, priv, nil)
	env, bundle := signPack(t, priv, packAtVersion(t, "9.2.5"), 3)
	feed := &fakeFeed{files: map[string][]byte{
		"security.rule_pack/manifest.json":             env,
		"security.rule_pack/" + secrulepack.BundleName: bundle,
	}}
	useFeed(t, feed)
	rep := e.refreshCodeContent(context.Background())
	if rep.Err != nil {
		t.Fatalf("refresh: %v", rep.Err)
	}
	if e.pack.Source != secrulepack.SourceImported || e.pack.Pack.Version() != "9.2.5" || e.pack.Freshness != content.Fresh {
		t.Fatalf("pack in use %s %s %s", e.pack.Source, e.pack.Pack.Version(), e.pack.Freshness)
	}
	// An outage: the feed is down. The installed pack stays in use, and the
	// fetch failure is recorded and shown, never read as current.
	feed.err = errors.New("dial tcp: connection refused")
	rep = e.refreshCodeContent(context.Background())
	if rep.Err == nil || e.pack.Pack.Version() != "9.2.5" {
		t.Fatalf("outage: %v, pack %s", rep.Err, e.pack.Pack.Version())
	}
	st := e.dashStatus(context.Background())
	if st.FetchError == "" || st.PackVersion != "9.2.5" || st.PackSource != string(secrulepack.SourceImported) {
		t.Fatalf("status after the outage %+v", st)
	}
	// A pack signed by another key, and an older manifest version, are
	// refused; the last-known-good stays.
	feed.err = nil
	_, other, _ := ed25519.GenerateKey(nil)
	bad, badBundle := signPack(t, other, packAtVersion(t, "9.3.0"), 4)
	feed.files["security.rule_pack/manifest.json"], feed.files["security.rule_pack/"+secrulepack.BundleName] = bad, badBundle
	if rep := e.refreshCodeContent(context.Background()); rep.Err == nil || e.pack.Pack.Version() != "9.2.5" {
		t.Fatalf("another key: %v, pack %s", rep.Err, e.pack.Pack.Version())
	}
	old, oldBundle := signPack(t, priv, packAtVersion(t, "9.0.5"), 2)
	feed.files["security.rule_pack/manifest.json"], feed.files["security.rule_pack/"+secrulepack.BundleName] = old, oldBundle
	if rep := e.refreshCodeContent(context.Background()); rep.Err == nil || e.pack.Pack.Version() != "9.2.5" {
		t.Fatalf("rollback: %v, pack %s", rep.Err, e.pack.Pack.Version())
	}
}

func TestFeedOffFetchesNothing(t *testing.T) {
	priv := codeTestKeys(t)
	e := openSelected(t, priv, nil)
	e.cfg.Security.Scan.Opengrep.Feed = false
	feed := &fakeFeed{}
	useFeed(t, feed)
	e.refreshCodeContent(context.Background())
	if feed.calls != 0 {
		t.Fatalf("%d feed requests with the feed off", feed.calls)
	}
}

func TestFeedEnginePinsInstalledBinaryOrWaitsPending(t *testing.T) {
	priv := codeTestKeys(t)
	body := bytes.Repeat([]byte("installed"), 512)
	e := openSelected(t, priv, nil)
	// The guided install's binary is already in place.
	if err := os.MkdirAll(filepath.Dir(codeInstalledPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codeInstalledPath(), body, 0o700); err != nil {
		t.Fatal(err)
	}
	feed := &fakeFeed{files: map[string][]byte{
		"security.engine/manifest.json": signEngine(t, priv, 1, []content.Entry{engineEntry("1.30.1", body)}),
	}}
	useFeed(t, feed)
	if rep := e.refreshCodeContent(context.Background()); rep.Err != nil {
		t.Fatalf("refresh: %v", rep.Err)
	}
	if e.manifest == nil || len(e.manifest.Pins) != 1 || e.manifest.Version != 1 {
		t.Fatalf("a manifest pinning the installed binary was not installed: %+v", e.manifest)
	}
	// A newer manifest pins a binary not installed: it waits as pending,
	// the plan shows it and asks the consent again.
	newer := bytes.Repeat([]byte("newer"), 700)
	feed.files["security.engine/manifest.json"] = signEngine(t, priv, 2, []content.Entry{engineEntry("1.31.0", newer)})
	if rep := e.refreshCodeContent(context.Background()); rep.Err != nil {
		t.Fatalf("refresh 2: %v", rep.Err)
	}
	if e.manifest.Version != 1 {
		t.Fatal("a manifest whose binary is not here was accepted without it")
	}
	p := secengine.PlanInstall(e.installInput(context.Background()))
	if p.PinFrom != secengine.PinFromPending || p.Pin.Version != "1.31.0" || !p.NeedsConsent {
		t.Fatalf("plan %+v", p)
	}
	// After the consent, the install brings the binary and the manifest in
	// together, and the pending copy goes.
	fakeRelease(t, newer)
	if _, err := e.installEngine(context.Background(), codeSurfaceCLI, true); err != nil {
		t.Fatalf("install of the pending pin: %v", err)
	}
	if e.manifest == nil || e.manifest.Version != 2 {
		t.Fatalf("the pending manifest was not installed with its binary: %+v", e.manifest)
	}
	if _, err := os.Stat(e.pendingPath()); err == nil {
		t.Error("the pending manifest is still there")
	}
	// A manifest that revokes the installed digest installs with no bytes,
	// and the decision table refuses that engine from then on.
	elsewhere := engineEntry("1.31.0", []byte("another platform"))
	elsewhere.Name, elsewhere.OS = "opengrep_plan9", "plan9"
	feed.files["security.engine/manifest.json"] = signEngine(t, priv, 3, []content.Entry{elsewhere}, engineEntry("1.31.0", newer).SHA256)
	if rep := e.refreshCodeContent(context.Background()); rep.Err != nil {
		t.Fatalf("refresh 3: %v", rep.Err)
	}
	d := secengine.Decide(secengine.Input{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Digest: engineEntry("1.31.0", newer).SHA256, Manifest: e.manifest})
	if d.Run() || d.Detail != secengine.DetailRevoked {
		t.Fatalf("a revoked engine still runs: %+v", d)
	}
}

// fakeMirrorPack serves the rule pack kind too.
type fakeMirrorPack struct {
	fakeMirror
	packEnv, bundle []byte
	packCalls       int
}

func (m *fakeMirrorPack) InstallSecurityContent(ctx context.Context, st contentchan.Store, kind content.Kind, tr contentchan.Trust) (orgclient.SecurityContentResult, error) {
	if kind == content.RulePack {
		m.packCalls++
		s, err := st.Install(kind, m.packEnv, map[string][]byte{secrulepack.BundleName: m.bundle}, tr)
		return orgclient.SecurityContentResult{Kind: kind, State: s}, err
	}
	return m.fakeMirror.InstallSecurityContent(ctx, st, kind, tr)
}

func TestManagedContentComesFromTheMirrorOnly(t *testing.T) {
	priv := codeTestKeys(t)
	e := openSelected(t, priv, nil)
	e.managed = true
	feed := &fakeFeed{}
	useFeed(t, feed)
	env, bundle := signPack(t, priv, packAtVersion(t, "9.3.0"), 5)
	mirror := &fakeMirrorPack{packEnv: env, bundle: bundle}
	prevOrg, prevNamed := codeOrgMirror, codeMirrorNamedFor
	t.Cleanup(func() { codeOrgMirror, codeMirrorNamedFor = prevOrg, prevNamed })
	codeOrgMirror = func(context.Context, string) (codeMirrorInstaller, func(), error) { return mirror, func() {}, nil }
	codeMirrorNamedFor = func(context.Context, config.Config, *store.Store) bool { return false }
	e.refreshCodeContent(context.Background())
	if mirror.packCalls != 0 || feed.calls != 0 {
		t.Fatalf("fetched with no mirror named: mirror %d, feed %d", mirror.calls, feed.calls)
	}
	codeMirrorNamedFor = func(context.Context, config.Config, *store.Store) bool { return true }
	rep := e.refreshCodeContent(context.Background())
	if rep.Err != nil || e.pack.Pack.Version() != "9.3.0" || mirror.packCalls != 1 {
		t.Fatalf("mirror refresh: %v, pack %s", rep.Err, e.pack.Pack.Version())
	}
	if feed.calls != 0 {
		t.Fatalf("a managed node reached the vendor feed %d times", feed.calls)
	}
	// No engine installed: the engine kind (which carries the binary) is
	// not fetched unasked.
	if mirror.fakeMirror.calls != 0 {
		t.Fatalf("the engine kind was fetched with no engine installed")
	}
	if f := readCodeFetch(e.secDir)[string(content.RulePack)]; f.Source != "org_mirror" || f.Error != "" {
		t.Fatalf("fetch record %+v", f)
	}
}
