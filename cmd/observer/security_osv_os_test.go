//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvnet"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_osv_os_test.go is lane OS-2 N1: the OS release databases, on
// demand and per release, from the signed mirror only (an individual node,
// after the one OS accept) or the org mirror only (a managed node), with no
// network: a fake feed and a fake org mirror stand in for the lane.

// osFakeFeed serves <kind>/<file> from files and records every file asked
// for; down fails every request; a missing file answers not published.
type osFakeFeed struct {
	mu    sync.Mutex
	files map[string][]byte
	down  bool
	asked []string
}

func (f *osFakeFeed) FetchFeedFile(_ context.Context, kind, file, etag string) ([]byte, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, kind+"/"+file)
	if f.down {
		return nil, "", errors.New("test: connection refused")
	}
	b, ok := f.files[kind+"/"+file]
	if !ok {
		return nil, "", fmt.Errorf("test: %w", osvnet.ErrFeedNotPublished)
	}
	tag := fmt.Sprintf(`"%s"`, content.HashBytes(b)[:16])
	if etag == tag {
		return nil, "", osvnet.ErrFeedNotModified
	}
	return b, tag, nil
}

func (f *osFakeFeed) StreamFeedArtifact(_ context.Context, kind, file string, size int64, w io.Writer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, kind+"/"+file)
	if f.down {
		return errors.New("test: connection refused")
	}
	b, ok := f.files[kind+"/"+file]
	if !ok || int64(len(b)) != size {
		return errors.New("test: not served")
	}
	_, err := w.Write(b)
	return err
}

// artifacts are the artifact files asked for (manifests left out), sorted.
func (f *osFakeFeed) artifacts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, a := range f.asked {
		if !strings.HasSuffix(a, "/"+contentchan.ManifestFile) {
			out = append(out, strings.TrimPrefix(a, string(osvOSKind)+"/"))
		}
	}
	sort.Strings(out)
	return out
}

func (f *osFakeFeed) reset() {
	f.mu.Lock()
	f.asked = nil
	f.mu.Unlock()
}

func useOSFeed(t *testing.T, f *osFakeFeed) {
	t.Helper()
	old := depsOSVFeed
	depsOSVFeed = func() osvFeedClient { return f }
	t.Cleanup(func() { depsOSVFeed = old })
}

// osTestManifest builds a security.osv_os_export manifest of the given
// releases (artifact base -> set) and its artifacts, under kind/ names.
func osTestManifest(t *testing.T, version int64, issued time.Time, sets map[string]osvTestSet) (content.Manifest, map[string][]byte) {
	t.Helper()
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: osvOSKind, ManifestVersion: version, Epoch: version,
		IssuedAt: issued.UTC().Format(time.RFC3339), ExpiresAt: issued.Add(5 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}
	arts := map[string][]byte{}
	for art, s := range sets {
		r, ok := osvdb.ReleaseByArtifact(art)
		if !ok {
			t.Fatalf("no release %s", art)
		}
		m.Entries = append(m.Entries, content.Entry{Name: r.ExportArtifact(), SizeBytes: int64(len(s.base)), SHA256: content.HashBytes(s.base), Upstream: content.UpstreamCheck{Method: content.UpstreamNone}})
		arts[r.ExportArtifact()] = s.base
		if s.delta != nil {
			m.Entries = append(m.Entries, content.Entry{
				Name: r.DeltaArtifact(), SizeBytes: int64(len(s.delta)), SHA256: content.HashBytes(s.delta), Upstream: content.UpstreamCheck{Method: content.UpstreamNone},
				Delta: &content.DeltaOf{Base: r.ExportArtifact(), BaseSHA256: content.HashBytes(s.base), Records: s.records, Drop: s.drop},
			})
			arts[r.DeltaArtifact()] = s.delta
		}
	}
	content.SortEntries(m.Entries)
	return m, arts
}

// osFeedSet signs the manifest with the content-feed key and lays it out
// as the feed serves it.
func osFeedSet(t *testing.T, priv ed25519.PrivateKey, version int64, issued time.Time, sets map[string]osvTestSet) map[string][]byte {
	t.Helper()
	m, arts := osTestManifest(t, version, issued, sets)
	env, err := content.SignFeed(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := content.EncodeEnvelope(env)
	files := map[string][]byte{string(osvOSKind) + "/" + contentchan.ManifestFile: b}
	for n, a := range arts {
		files[string(osvOSKind)+"/"+n] = a
	}
	return files
}

// osTestEnv opens a scan env over a temp config, with the OS accept given
// when accepted, and the [security.deps] body extra appended.
func osTestEnv(t *testing.T, accepted bool, extra string) (*depsScanEnv, string) {
	t.Helper()
	cfgPath, secDir := scanConsentConfig(t)
	if extra != "" {
		f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString(extra)
		_ = f.Close()
	}
	if accepted {
		if _, err := osvdb.RecordOSConsent(secDir, "cli", "dev", time.Now(), testDepsSigningKey(t, secDir)); err != nil {
			t.Fatal(err)
		}
	}
	e, err := openDepsScanEnv(context.Background(), cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.cleanup)
	return e, secDir
}

var osFixedReasons = map[string]bool{
	osReasonNotAccepted: true, osReasonMissing: true, osReasonFeedUnavailable: true, osReasonNotPublished: true,
}

// TestEnsureOSReleaseGate walks the gate and the feed's failure rows: each
// answers one fixed reason, never an error's text, and a row that must
// not reach the network makes no request.
func TestEnsureOSReleaseGate(t *testing.T) {
	debian, _ := osvdb.ReleaseFor("debian", "12")
	cases := []struct {
		name      string
		accepted  bool
		withKey   bool
		extra     string
		files     func(priv ed25519.PrivateKey) map[string][]byte
		down      bool
		want      string
		noTraffic bool
	}{
		{name: "not accepted", withKey: true, want: osReasonNotAccepted, noTraffic: true},
		{name: "accepted, no content-feed key in the build", accepted: true, want: osReasonFeedUnavailable, noTraffic: true},
		{name: "db_source = import fetches no OS database", accepted: true, withKey: true, extra: "db_source = \"import\"\n", want: osReasonMissing, noTraffic: true},
		{name: "db_source = upstream: the bucket serves no OS release", accepted: true, withKey: true, extra: "db_source = \"upstream\"\n", want: osReasonMissing, noTraffic: true},
		{name: "the kind is not published", accepted: true, withKey: true, files: func(ed25519.PrivateKey) map[string][]byte { return map[string][]byte{} }, want: osReasonNotPublished},
		{name: "the mirror is down", accepted: true, withKey: true, down: true, want: osReasonFeedUnavailable},
		{
			name: "the set does not carry the release", accepted: true, withKey: true, want: osReasonNotPublished,
			files: func(p ed25519.PrivateKey) map[string][]byte {
				return osFeedSet(t, p, 1, time.Now().Add(-time.Hour), map[string]osvTestSet{"Alpine-v3.20": {base: osvTestZip(t, "0", "ALPINE-1")}})
			},
		},
		{
			name: "an artifact that does not match its digest", accepted: true, withKey: true, want: osReasonFeedUnavailable,
			files: func(p ed25519.PrivateKey) map[string][]byte {
				f := osFeedSet(t, p, 1, time.Now().Add(-time.Hour), map[string]osvTestSet{"Debian-12": {base: osvTestZip(t, "0", "DSA-1")}})
				b := f[string(osvOSKind)+"/Debian-12.zip"]
				f[string(osvOSKind)+"/Debian-12.zip"] = bytes.Replace(b, []byte("DSA-1"), []byte("DSA-9"), 1)
				return f
			},
		},
		{
			name: "a manifest signed by another key", accepted: true, withKey: true, want: osReasonFeedUnavailable,
			files: func(ed25519.PrivateKey) map[string][]byte {
				_, other, _ := ed25519.GenerateKey(nil)
				return osFeedSet(t, other, 1, time.Now().Add(-time.Hour), map[string]osvTestSet{"Debian-12": {base: osvTestZip(t, "0", "DSA-1")}})
			},
		},
		{
			name: "an expired manifest", accepted: true, withKey: true, want: osReasonFeedUnavailable,
			files: func(p ed25519.PrivateKey) map[string][]byte {
				return osFeedSet(t, p, 1, time.Now().Add(-6*24*time.Hour), map[string]osvTestSet{"Debian-12": {base: osvTestZip(t, "0", "DSA-1")}})
			},
		},
		{
			name: "a delta whose record count is wrong", accepted: true, withKey: true, want: osReasonFeedUnavailable,
			files: func(p ed25519.PrivateKey) map[string][]byte {
				return osFeedSet(t, p, 1, time.Now().Add(-time.Hour), map[string]osvTestSet{"Debian-12": {base: osvTestZip(t, "0", "DSA-1"), delta: osvTestZip(t, "1", "DSA-2"), records: 7}})
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv := feedTrust(t, tc.withKey)
			feed := &osFakeFeed{down: tc.down}
			if tc.files != nil {
				feed.files = tc.files(priv)
			}
			useOSFeed(t, feed)
			e, _ := osTestEnv(t, tc.accepted, tc.extra)
			ep, why := ensureOSRelease(context.Background(), e, debian)
			if ep != "" || why != tc.want || !osFixedReasons[why] {
				t.Fatalf("got (%q, %q), want (\"\", %q)", ep, why, tc.want)
			}
			if tc.noTraffic && len(feed.asked) != 0 {
				t.Fatalf("a closed gate made requests: %v", feed.asked)
			}
			if _, ok := e.db.OSInstalled(debian); ok {
				t.Fatal("a refused release was installed")
			}
		})
	}
}

// TestEnsureOSReleaseFetchesOnlyThatRelease: after the OS accept a release
// an image needs is fetched from the signed mirror, ITS artifacts only
// (the subset rule), merged base and delta, installed with source=feed in
// its epoch; a second call is answered from disk with no request; the
// language accept is neither needed nor recorded.
func TestEnsureOSReleaseFetchesOnlyThatRelease(t *testing.T) {
	priv := feedTrust(t, true)
	sets := map[string]osvTestSet{
		"Debian-12":        {base: osvTestZip(t, "0", "DSA-1", "DSA-2"), delta: osvTestZip(t, "1", "DSA-3"), records: 2, drop: []string{"DSA-1.json"}},
		"Ubuntu-24.04-LTS": {base: osvTestZip(t, "0", "USN-1"), delta: osvTestZip(t, "1", "USN-2"), records: 2},
		"Alpine-v3.20":     {base: osvTestZip(t, "0", "ALPINE-1")},
	}
	feed := &osFakeFeed{files: osFeedSet(t, priv, 1, time.Now().Add(-time.Hour), sets)}
	useOSFeed(t, feed)
	e, secDir := osTestEnv(t, true, "")
	debian, _ := osvdb.ReleaseFor("debian", "12")
	ep, why := ensureOSRelease(context.Background(), e, debian)
	if why != "" || !strings.Contains(ep, "source="+osvdb.SourceFeed) {
		t.Fatalf("ensure: (%q, %q)", ep, why)
	}
	if got, want := feed.artifacts(), []string{"Debian-12.delta.zip", "Debian-12.zip"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("artifacts fetched %v, want only %v", got, want)
	}
	// The installed export is the merge: DSA-1 dropped, DSA-3 added.
	ids := zipIDs(t, e.db.OSZipPath(debian))
	if strings.Join(ids, ",") != "DSA-2.json,DSA-3.json" {
		t.Fatalf("installed export holds %v", ids)
	}
	feed.reset()
	if again, why := ensureOSRelease(context.Background(), e, debian); why != "" || again != ep || len(feed.asked) != 0 {
		t.Fatalf("second ensure (%q, %q) asked %v", again, why, feed.asked)
	}
	// A release with no delta installs its base as is.
	alpine, _ := osvdb.ReleaseFor("alpine", "3.20.3")
	if _, why := ensureOSRelease(context.Background(), e, alpine); why != "" {
		t.Fatalf("alpine: %q", why)
	}
	if got := feed.artifacts(); strings.Join(got, ",") != "Alpine-v3.20.zip" {
		t.Fatalf("alpine fetched %v", got)
	}
	if osvdb.ReadConsent(secDir, depsRecordKey(secDir)).Accepted() {
		t.Fatal("the OS accept recorded the language accept")
	}
	if len(e.db.OSReleasesInstalled()) != 2 {
		t.Fatalf("installed %v", e.db.OSReleasesInstalled())
	}
	if e.db.OSDiskBytes() <= 0 {
		t.Fatal("no disk use reported")
	}
}

// TestRefreshOSReleases: the refresh touches only the installed releases
// (never a new one), installs a changed delta, keeps the last-known-good
// with the reason recorded when the mirror is down or what it serves does
// not verify, and makes no request when nothing is installed.
func TestRefreshOSReleases(t *testing.T) {
	priv := feedTrust(t, true)
	base := osvTestZip(t, "0", "DSA-1")
	v1 := map[string]osvTestSet{
		"Debian-12":        {base: base, delta: osvTestZip(t, "1", "DSA-2"), records: 2},
		"Ubuntu-24.04-LTS": {base: osvTestZip(t, "0", "USN-1")},
	}
	feed := &osFakeFeed{files: osFeedSet(t, priv, 1, time.Now().Add(-2*time.Hour), v1)}
	useOSFeed(t, feed)
	e, _ := osTestEnv(t, true, "")
	ctx := context.Background()
	if rep := e.refreshOSReleases(ctx, time.Now()); len(feed.asked) != 0 || len(rep.Changed)+len(rep.Unchanged)+len(rep.Failed) != 0 {
		t.Fatalf("a refresh with nothing installed asked %v (%+v)", feed.asked, rep)
	}
	debian, _ := osvdb.ReleaseFor("debian", "12")
	ep1, why := ensureOSRelease(ctx, e, debian)
	if why != "" {
		t.Fatal(why)
	}
	// The same set: nothing changes, nothing but the manifest is asked.
	feed.reset()
	rep := e.refreshOSReleases(ctx, time.Now())
	if len(rep.Unchanged) != 1 || len(rep.Changed) != 0 || len(feed.artifacts()) != 0 {
		t.Fatalf("unchanged refresh %+v asked %v", rep, feed.asked)
	}
	// A new delta over the same base: only the delta is fetched (the base
	// is kept), Ubuntu (not installed) is never fetched.
	v2 := map[string]osvTestSet{
		"Debian-12":        {base: base, delta: osvTestZip(t, "2", "DSA-2", "DSA-4"), records: 3},
		"Ubuntu-24.04-LTS": {base: osvTestZip(t, "1", "USN-2")},
	}
	feed.files = osFeedSet(t, priv, 2, time.Now().Add(-time.Hour), v2)
	feed.reset()
	rep = e.refreshOSReleases(ctx, time.Now())
	if len(rep.Changed) != 1 || rep.Changed[0] != "Debian-12" {
		t.Fatalf("changed refresh %+v", rep)
	}
	if got := feed.artifacts(); strings.Join(got, ",") != "Debian-12.delta.zip" {
		t.Fatalf("changed refresh fetched %v", got)
	}
	ep2, _ := e.db.OSInstalled(debian)
	if ep2 == ep1 || len(zipIDs(t, e.db.OSZipPath(debian))) != 3 {
		t.Fatalf("epoch %q (was %q), ids %v", ep2, ep1, zipIDs(t, e.db.OSZipPath(debian)))
	}
	// The mirror goes down: the installed export stays, the reason is
	// recorded, the accepted manifest still serves the age floor.
	feed.down = true
	rep = e.refreshOSReleases(ctx, time.Now())
	if len(rep.Changed) != 0 {
		t.Fatalf("down refresh %+v", rep)
	}
	if got, _ := e.db.OSInstalled(debian); got != ep2 {
		t.Fatalf("down refresh moved the epoch: %q", got)
	}
	// A rolled-back manifest (version 1 again) is refused; the accepted
	// one stays and nothing is reinstalled.
	feed.down = false
	feed.files = osFeedSet(t, priv, 1, time.Now().Add(-time.Minute), v1)
	rep = e.refreshOSReleases(ctx, time.Now())
	if got, _ := e.db.OSInstalled(debian); got != ep2 || len(rep.Changed) != 0 {
		t.Fatalf("a rollback reinstalled: %q %+v", got, rep)
	}
	// Every reason a refresh records is a fixed one.
	feed.files = map[string][]byte{}
	_ = os.Remove(filepath.Join(e.db.OSFeedDir(), osFeedStateFile))
	_ = os.Remove(filepath.Join(e.db.OSFeedDir(), osFeedManifestFile))
	rep = e.refreshOSReleases(ctx, time.Now())
	for art, why := range rep.Failed {
		if !osFixedReasons[why] {
			t.Errorf("%s: reason %q is not a fixed one", art, why)
		}
	}
	if len(rep.Failed) != 1 {
		t.Fatalf("unpublished refresh %+v", rep)
	}
	eps, _ := e.db.Epochs()
	if le := eps[osvdb.OSEpochKey(debian)].LastError; le != osReasonNotPublished {
		t.Fatalf("recorded %q", le)
	}
	if got, ok := e.db.OSInstalled(debian); !ok || got != ep2 {
		t.Fatalf("the last-known-good was lost: %q %v", got, ok)
	}
}

// TestEnsureOSReleaseManagedTakesTheOrgMirrorOnly: a managed node never
// reaches the feed; without the mirror named it reads database_missing;
// with it, the release installs from the org mirror (source=org_mirror),
// with no accept.
func TestEnsureOSReleaseManagedTakesTheOrgMirrorOnly(t *testing.T) {
	_, vpriv, _ := ed25519.GenerateKey(nil)
	prev := depsTrust
	depsTrust = func() contentchan.Trust {
		return contentchan.Trust{VendorKeys: []ed25519.PublicKey{vpriv.Public().(ed25519.PublicKey)}}
	}
	t.Cleanup(func() { depsTrust = prev })
	m, arts := osTestManifest(t, 1, time.Now().Add(-time.Hour), map[string]osvTestSet{
		"Debian-12": {base: osvTestZip(t, "0", "DSA-1"), delta: osvTestZip(t, "1", "DSA-2"), records: 2},
	})
	env, err := content.Sign(m, vpriv)
	if err != nil {
		t.Fatal(err)
	}
	envB, _ := content.EncodeEnvelope(env)
	fm := &fakeOrgMirror{kinds: map[content.Kind]struct {
		env  []byte
		arts map[string][]byte
	}{osvOSKind: {envB, arts}}}
	prevMirror := depsOrgMirror
	t.Cleanup(func() { depsOrgMirror = prevMirror })
	depsOrgMirror = func(context.Context, string) (depsMirrorInstaller, func(), error) { return fm, func() {}, nil }
	feed := &osFakeFeed{}
	useOSFeed(t, feed)

	e, _ := osTestEnv(t, false, "")
	e.managed = true
	debian, _ := osvdb.ReleaseFor("debian", "12")
	if ep, why := ensureOSRelease(context.Background(), e, debian); ep != "" || why != osReasonMissing || len(fm.calls) != 0 {
		t.Fatalf("mirror not named: (%q, %q), mirror calls %v", ep, why, fm.calls)
	}
	e.mirror = true
	ep, why := ensureOSRelease(context.Background(), e, debian)
	if why != "" || !strings.Contains(ep, "source="+osvdb.SourceOrgMirror) {
		t.Fatalf("managed ensure (%q, %q)", ep, why)
	}
	if len(feed.asked) != 0 {
		t.Fatalf("a managed node reached the feed: %v", feed.asked)
	}
	if ids := zipIDs(t, e.db.OSZipPath(debian)); len(ids) != 2 {
		t.Fatalf("installed %v", ids)
	}
	// The content store's copy is untouched (never renamed away).
	st := depsContentStore(depsConfigPath(e.configPath))
	l, err := st.Load(osvOSKind, depsTrust(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.ArtifactPath(debian.ExportArtifact()); err != nil {
		t.Fatalf("the org mirror's base was consumed: %v", err)
	}
}

// TestRunDBAcceptOS: the CLI's OS accept asks on a terminal, records with
// --yes, records nothing without a terminal and without --yes, never
// records the language accept, and a managed node has nothing to accept.
func TestRunDBAcceptOS(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		managed    bool
		yes, tty   bool
		input      string
		wantAccept bool
		wantText   string
	}{
		{name: "no terminal, no --yes", wantText: "Nothing recorded"},
		{name: "terminal, answered no", tty: true, input: "n\n", wantText: "Nothing recorded"},
		{name: "terminal, answered yes", tty: true, input: "y\n", wantAccept: true, wantText: "Recorded"},
		{name: "--yes", yes: true, wantAccept: true, wantText: "Recorded"},
		{name: "managed node", managed: true, yes: true, wantText: "nothing to accept"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, secDir := osTestEnv(t, false, "")
			e.managed = tc.managed
			var out bytes.Buffer
			if err := runDBAcceptOS(&out, strings.NewReader(tc.input), e, tc.yes, tc.tty, now); err != nil {
				t.Fatal(err)
			}
			got := osvdb.ReadOSConsent(secDir, depsRecordKey(secDir)).Accepted()
			if got != tc.wantAccept || !strings.Contains(out.String(), tc.wantText) {
				t.Fatalf("accepted %v, output:\n%s", got, out.String())
			}
			if !tc.managed && !strings.Contains(out.String(), osvdb.OSConsentText) {
				t.Fatal("the accept text was not shown")
			}
			if osvdb.ReadConsent(secDir, depsRecordKey(secDir)).Accepted() {
				t.Fatal("the OS accept recorded the language accept")
			}
		})
	}
}

// TestOSDBStatus: the state the Scanners card and `scan status` show.
func TestOSDBStatus(t *testing.T) {
	feedTrust(t, true)
	e, _ := osTestEnv(t, false, "")
	st := osDBStatus(e)
	if st.Accepted || st.Blocked != osReasonNotAccepted || st.Source != osvdb.FeedHost || len(st.Sizes) != 5 || st.Text != osvdb.OSConsentText || st.Installed == nil {
		t.Fatalf("before the accept %+v", st)
	}
	var out bytes.Buffer
	writeOSDBState(&out, e)
	if !strings.Contains(out.String(), "accept --os") || !strings.Contains(out.String(), "no OS release database installed") {
		t.Fatalf("status before the accept:\n%s", out.String())
	}
	key := testDepsSigningKey(t, e.dir)
	c, err := osvdb.RecordOSConsent(e.dir, "dashboard", "dev", time.Now(), key)
	if err != nil {
		t.Fatal(err)
	}
	e.osConsent = c
	st = osDBStatus(e)
	if !st.Accepted || st.AcceptedOn != "dashboard" || st.Blocked != "" {
		t.Fatalf("after the accept %+v", st)
	}
	full := scannerDBStatus(e)
	if full.OS == nil || !full.OS.Accepted {
		t.Fatalf("the scanner database state carries no OS state: %+v", full)
	}
}

// zipIDs lists a zip's entry names, sorted.
func zipIDs(t *testing.T, path string) []string {
	t.Helper()
	n := zipNames(t, path)
	if n == "" {
		return nil
	}
	return strings.Split(n, ",")
}
