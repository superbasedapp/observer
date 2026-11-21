//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvshard"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvshardkey"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// TestLookupWaitReasons walks the package lookup posture's wait reasons
// (plan sections 13.9 and 13.10): a fresh install that chose nothing reads
// lookup_not_chosen, never database_not_accepted; each mode waits only for
// its own consent; a managed node never waits.
func TestLookupWaitReasons(t *testing.T) {
	ok := osvdb.Consent{Version: osvdb.ConsentVersion, AcceptedAt: time.Now(), Surface: "cli", Verified: true}
	remoteOK := osvdb.RemoteConsent{Consent: osvdb.Consent{Version: osvdb.RemoteConsentVersion, AcceptedAt: time.Now(), Surface: "dashboard", Verified: true}}
	withMode := func(m string) config.Config {
		c := config.Default()
		c.Security.Deps.Match = m
		return c
	}
	for _, tc := range []struct {
		name string
		e    depsScanEnv
		want string
		mode string
	}{
		{"fresh install", depsScanEnv{cfg: withMode("")}, depscan.ReasonLookupNotChosen, ""},
		{"the old accept reads local", depsScanEnv{cfg: withMode(""), consent: ok}, "", lookupLocal},
		{"local before the accept", depsScanEnv{cfg: withMode(lookupLocal)}, depscan.ReasonDBNotAccepted, lookupLocal},
		{"local after the accept", depsScanEnv{cfg: withMode(lookupLocal), consent: ok}, "", lookupLocal},
		{"remote before its consent", depsScanEnv{cfg: withMode(lookupRemote), consent: ok}, depscan.ReasonRemoteNotAccepted, lookupRemote},
		{"remote after its consent", depsScanEnv{cfg: withMode(lookupRemote), remoteConsent: remoteOK}, "", lookupRemote},
		{"both with only the database accept", depsScanEnv{cfg: withMode(lookupBoth), consent: ok}, "", lookupBoth},
		{"both with neither", depsScanEnv{cfg: withMode(lookupBoth)}, depscan.ReasonRemoteNotAccepted, lookupBoth},
		{"managed never waits", depsScanEnv{cfg: withMode(lookupRemote), managed: true}, "", lookupLocal},
	} {
		e := tc.e
		e.db = osvdb.Open(t.TempDir())
		if got := e.scanWaitReason(); got != tc.want {
			t.Errorf("%s: wait %q, want %q", tc.name, got, tc.want)
		}
		if got := e.lookupMode(); got != tc.mode {
			t.Errorf("%s: mode %q, want %q", tc.name, got, tc.mode)
		}
	}
	// Remote mode downloads nothing and matches no local database.
	e := depsScanEnv{cfg: withMode(lookupRemote), consent: ok, remoteConsent: remoteOK, db: osvdb.Open(t.TempDir())}
	if got := e.downloadBlocked(); got != "lookup_mode_remote" {
		t.Errorf("remote mode download gate: %q", got)
	}
	if got := e.matchEpochs(map[string]string{"npm": "x"}); len(got) != 0 {
		t.Errorf("remote mode matched local epochs %v", got)
	}
	if got := (&depsScanEnv{cfg: withMode(lookupBoth), db: osvdb.Open(t.TempDir())}).matchEpochs(map[string]string{"npm": "x"}); len(got) != 1 {
		t.Errorf("both mode dropped the local epochs: %v", got)
	}
}

// --- a synthetic shard set, signed like the publisher's --------------------

type remoteTestRecord struct {
	ID       string `json:"id"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

func remoteRecord(id, eco, name, version, fixed string) remoteTestRecord {
	rangeType := "SEMVER"
	if eco != "npm" {
		rangeType = "ECOSYSTEM"
	}
	r := remoteTestRecord{ID: id}
	r.Affected = make([]struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	}, 1)
	a := &r.Affected[0]
	a.Package.Ecosystem, a.Package.Name, a.Versions = eco, name, []string{version}
	a.Ranges = make([]struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	}, 1)
	a.Ranges[0].Type = rangeType
	a.Ranges[0].Events = []map[string]string{{"introduced": "0"}, {"fixed": fixed}}
	return r
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// remoteShardSet builds one set's descriptor and bucket objects through
// osvshardkey's format functions (strip mode).
func remoteShardSet(t *testing.T, set, eco string, bits int, recs []remoteTestRecord) (osvshardkey.SetDescriptor, map[string][]byte) {
	t.Helper()
	base := osvshardkey.Base(eco)
	byPrefix := map[uint32][]remoteTestRecord{}
	for _, r := range recs {
		p := osvshardkey.PrefixOf(base, r.Affected[0].Package.Name, bits)
		byPrefix[p] = append(byPrefix[p], r)
	}
	objs := map[string][]byte{}
	byByte := map[int][]osvshardkey.ShardRef{}
	var total int64
	for p, rs := range byPrefix {
		js, _ := json.Marshal(rs)
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(js)
		_ = zw.Close()
		data := buf.Bytes()
		objs[osvshardkey.ShardPath(set, sha(data))] = data
		b := osvshardkey.FirstByte(p, bits)
		byByte[b] = append(byByte[b], osvshardkey.ShardRef{Prefix: p, Object: sha(data), Size: int64(len(data)), Records: len(rs)})
		total += int64(len(data))
	}
	d := osvshardkey.SetDescriptor{
		Schema: osvshardkey.SetSchema, Set: set, Ecosystem: eco, Base: base, Bits: bits, Mode: osvshardkey.ModeStrip,
		Epoch: 7, Records: len(recs), Shards: len(byPrefix), ShardBytes: total,
		MaxShardBytes: osvshardkey.MaxShardBytes, MaxIndexBytes: osvshardkey.MaxIndexBytes,
	}
	var firsts []int
	for b := range byByte {
		firsts = append(firsts, b)
	}
	sort.Ints(firsts)
	for _, b := range firsts {
		refs := byByte[b]
		sort.Slice(refs, func(i, j int) bool { return refs[i].Prefix < refs[j].Prefix })
		raw, err := osvshardkey.EncodeIndex(osvshardkey.IndexFile{Schema: osvshardkey.IndexSchema, Set: set, Bits: bits, Byte: b, Shards: refs}, d)
		if err != nil {
			t.Fatal(err)
		}
		objs[osvshardkey.IndexPath(set, sha(raw))] = raw
		d.Index = append(d.Index, osvshardkey.IndexRef{Byte: b, Object: sha(raw), Size: int64(len(raw))})
	}
	return d, objs
}

// remoteManifestFiles signs a security.osv_shards manifest over the
// descriptors, as `vendorsign osvshards` does.
func remoteManifestFiles(t *testing.T, priv ed25519.PrivateKey, descs ...osvshardkey.SetDescriptor) map[string][]byte {
	t.Helper()
	now := time.Now().UTC()
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: content.OSVShards, ManifestVersion: 1, Epoch: 1,
		IssuedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(5 * 24 * time.Hour).Format(time.RFC3339),
	}
	files := map[string][]byte{}
	k := string(content.OSVShards) + "/"
	for _, d := range descs {
		b, err := osvshardkey.EncodeSet(d)
		if err != nil {
			t.Fatal(err)
		}
		name := osvshardkey.SetFile(d.Set)
		m.Entries = append(m.Entries, content.Entry{Name: name, SizeBytes: int64(len(b)), SHA256: content.HashBytes(b), Upstream: content.UpstreamCheck{Method: content.UpstreamNone}})
		files[k+name] = b
	}
	content.SortEntries(m.Entries)
	env, err := content.SignFeed(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := content.EncodeEnvelope(env)
	files[k+contentchan.ManifestFile] = b
	return files
}

// remoteBucket is the shard lane's stand-in: it serves objects by path and
// logs every path asked for.
type remoteBucket struct {
	mu    sync.Mutex
	objs  map[string][]byte
	asked []string
}

func (b *remoteBucket) Fetch(_ context.Context, path string, max int64) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.asked = append(b.asked, path)
	o, ok := b.objs[path]
	if !ok || int64(len(o)) > max {
		return nil, errors.New("HTTP 404")
	}
	return append([]byte(nil), o...), nil
}

func useShardBucket(t *testing.T, b *remoteBucket) {
	t.Helper()
	old := depsShardFetcher
	depsShardFetcher = func() osvshard.Fetcher { return b }
	t.Cleanup(func() { depsShardFetcher = old })
}

// remoteEnv opens a remote-mode env with the consent recorded, the shard
// manifest served by the feed and the objects by bucket.
func remoteEnv(t *testing.T, deps string, bucket *remoteBucket) *depsScanEnv {
	t.Helper()
	priv := feedTrust(t, true)
	set, objs := remoteShardSet(t, "npm", "npm", 13, []remoteTestRecord{
		remoteRecord("GHSA-canary-0001", "npm", "lodash", "4.17.20", "4.17.21"),
		remoteRecord("GHSA-leftpad-0001", "npm", "left-pad", "1.0.0", "1.0.1"),
		remoteRecord("GHSA-other-0001", "npm", "express", "4.0.0", "4.0.1"),
	})
	mvn, mobjs := remoteShardSet(t, "Maven", "Maven", 9, []remoteTestRecord{
		remoteRecord("GHSA-canary-maven", "Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "2.15.0"),
	})
	for _, m := range []map[string][]byte{objs, mobjs} {
		for k, v := range m {
			bucket.objs[k] = v
		}
	}
	useOSVFeed(t, &fakeOSVFeed{files: remoteManifestFiles(t, priv, set, mvn)})
	useShardBucket(t, bucket)
	cfgPath, secDir := scanConsentConfig(t)
	f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("match = \"remote\"\n" + deps)
	_ = f.Close()
	if _, err := osvdb.RecordRemoteConsent(secDir, "cli", "dev", time.Now(), testDepsSigningKey(t, secDir)); err != nil {
		t.Fatal(err)
	}
	e, err := openDepsScanEnv(context.Background(), cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.cleanup)
	e.remoteFetchAlways = true
	return e
}

// TestRemoteLookupEndToEnd: in lookup mode remote the matcher reads the
// signed shard manifest, fetches only digests (never a package name),
// matches through SCALIBR's own matcher with the canary, names the shard set
// and its epoch, and turns a shard that fails into a gap.
func TestRemoteLookupEndToEnd(t *testing.T) {
	if !scalibrfacade.Compiled {
		t.Skip("SCALIBR is not compiled into this build")
	}
	bucket := &remoteBucket{objs: map[string][]byte{}}
	e := remoteEnv(t, "", bucket)
	if why := e.remoteBlocked(); why != "" {
		t.Fatalf("remote gate closed: %s", why)
	}
	root := t.TempDir()
	m := e.remoteMatcher(root)
	if m == nil {
		t.Fatal("no remote matcher")
	}
	pkgs := []depscan.Package{{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0", Path: "package-lock.json"}}
	res, ok := m(context.Background(), "npm", pkgs, []int{0})
	if !ok {
		t.Fatal("the matcher did not answer npm")
	}
	if res.Outcome != depscan.EcoScanned {
		t.Fatalf("outcome %s (%s), want scanned", res.Outcome, res.Reason)
	}
	if len(res.Advisories) != 1 || res.Advisories[0].ID != "GHSA-leftpad-0001" {
		t.Fatalf("advisories %+v", res.Advisories)
	}
	if !strings.HasPrefix(res.Epoch, "remote:shards.superbased.app npm@7") {
		t.Fatalf("epoch %q does not name the shard set", res.Epoch)
	}
	for _, p := range bucket.asked {
		if strings.Contains(p, "left-pad") || strings.Contains(p, "lodash") || !strings.HasPrefix(p, "npm/") {
			t.Fatalf("request %s names a package or leaves the set", p)
		}
	}
	if ep := e.scanEpoch(context.Background()); !strings.Contains(ep, "| remote ") || !strings.Contains(ep, "npm@7") {
		t.Fatalf("scan epoch %q does not carry the shard epoch", e.scanEpoch(context.Background()))
	}
	if n := e.postureNote(depscan.ScalibrID); !strings.Contains(n, "package lookup: remote via shards.superbased.app") || !strings.Contains(n, "private names withheld") {
		t.Fatalf("posture note %q", n)
	}
	if n := e.postureNote(depscan.OSVID); !strings.Contains(n, "local databases only") {
		t.Fatalf("osv-scanner posture note %q", n)
	}
	// The status lists the set and the cache.
	st := lookupStatus(context.Background(), e)
	if st.Mode != lookupRemote || !st.Remote.Accepted || len(st.Sets) != 2 || st.Sets[1].Epoch != 7 || st.CacheBytes == 0 {
		t.Fatalf("status %+v", st)
	}

	// A shard that fails to verify is a gap for its packages, never clean.
	bad := &remoteBucket{objs: map[string][]byte{}}
	e2 := remoteEnv(t, "", bad)
	for k, v := range bad.objs {
		if strings.Contains(k, "/obj/") {
			var r []remoteTestRecord
			zr, _ := gzip.NewReader(bytes.NewReader(v))
			_ = json.NewDecoder(zr).Decode(&r)
			if len(r) > 0 && r[0].Affected[0].Package.Name == "left-pad" {
				bad.objs[k] = append([]byte{0}, v[1:]...)
			}
		}
	}
	res, ok = e2.remoteMatcher(root)(context.Background(), "npm", pkgs, []int{0})
	if !ok || res.LookupGaps != 1 || res.Packages != 0 {
		t.Fatalf("a failed shard: %+v", res)
	}
}

// TestRemoteLookupKindsAndPrivateNames: a kind the developer did not choose
// is not looked up, and a name the classifier cannot place as public is
// withheld (never hashed into a request) unless private names are sent.
func TestRemoteLookupKindsAndPrivateNames(t *testing.T) {
	if !scalibrfacade.Compiled {
		t.Skip("SCALIBR is not compiled into this build")
	}
	bucket := &remoteBucket{objs: map[string][]byte{}}
	e := remoteEnv(t, "remote_kinds = [\"actions\"]\n", bucket)
	pkgs := []depscan.Package{{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0", Path: "package-lock.json"}}
	if _, ok := e.remoteMatcher(t.TempDir())(context.Background(), "npm", pkgs, []int{0}); ok {
		t.Fatal("npm was looked up with only the actions kind chosen")
	}
	// Maven: the classifier knows no public registry, so every name is
	// withheld and the canary alone is fetched.
	bucket2 := &remoteBucket{objs: map[string][]byte{}}
	e2 := remoteEnv(t, "", bucket2)
	mvn := []depscan.Package{{Ecosystem: "Maven", Name: "com.example:secret-lib", Version: "1.0", Path: "pom.xml"}}
	res, ok := e2.remoteMatcher(t.TempDir())(context.Background(), "Maven", mvn, []int{0})
	if !ok || res.Withheld != 1 || res.Packages != 0 || res.Outcome != depscan.EcoScanned || len(res.Advisories) != 0 {
		t.Fatalf("maven: %+v", res)
	}
	if len(bucket2.asked) == 0 {
		t.Fatal("the canary's shard was not fetched")
	}
	for _, p := range bucket2.asked {
		if strings.Contains(p, "secret") {
			t.Fatalf("a withheld name reached a request: %s", p)
		}
	}
}

// TestApplyLookupChange: the one writer of the posture records each
// consent before the key that needs it, refuses a data-sending choice
// without its consent, and refuses every change on a managed node.
func TestApplyLookupChange(t *testing.T) {
	cfgPath, secDir := scanConsentConfig(t)
	_ = testDepsSigningKey(t, secDir)
	open := func() *depsScanEnv {
		e, err := openDepsScanEnv(context.Background(), cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(e.cleanup)
		return e
	}
	ctx := context.Background()
	str := func(s string) *string { return &s }
	e := open()
	if err := applyLookupChange(ctx, e, lookupChange{PackageLookupChange: dashapi.PackageLookupChange{Mode: str("remote")}, surface: "dashboard"}); err == nil {
		t.Fatal("remote without its consent was written")
	}
	if open().cfg.Security.Deps.Match != "" {
		t.Fatal("a refused change wrote the key")
	}
	if err := applyLookupChange(ctx, e, lookupChange{PackageLookupChange: dashapi.PackageLookupChange{Mode: str("remote"), AcceptRemote: true}, surface: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	e = open()
	if e.cfg.Security.Deps.Match != "remote" || !e.remoteConsent.Accepted() || e.remoteConsent.Surface != "dashboard" || e.consent.Accepted() {
		t.Fatalf("after remote: match %q remote %+v download %v", e.cfg.Security.Deps.Match, e.remoteConsent, e.consent.Accepted())
	}
	if err := applyLookupChange(ctx, e, lookupChange{PackageLookupChange: dashapi.PackageLookupChange{Private: str("send")}, surface: "cli"}); err == nil {
		t.Fatal("private send without its consent was written")
	}
	if err := applyLookupChange(ctx, e, lookupChange{PackageLookupChange: dashapi.PackageLookupChange{Private: str("send"), AcceptPrivate: true, Kinds: &[]string{"language"}}, surface: "cli"}); err != nil {
		t.Fatal(err)
	}
	e = open()
	if !e.remotePrivateSending() || len(e.lookupKinds()) != 1 {
		t.Fatalf("private %v kinds %v", e.remotePrivateSending(), e.lookupKinds())
	}
	if err := applyLookupChange(ctx, e, lookupChange{PackageLookupChange: dashapi.PackageLookupChange{Kinds: &[]string{"os"}}, surface: "cli"}); err == nil || !strings.Contains(err.Error(), "not in this build") {
		t.Fatalf("the reserved os kind: %v", err)
	}
	if err := applyLookupChange(ctx, e, lookupChange{PackageLookupChange: dashapi.PackageLookupChange{WithdrawRemote: true, WithdrawPrivate: true}, surface: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	e = open()
	if e.remoteConsent.Accepted() || e.remotePrivate.Accepted() || e.scanWaitReason() != depscan.ReasonRemoteNotAccepted {
		t.Fatalf("after withdrawal: wait %q", e.scanWaitReason())
	}
	if err := applyLookupChange(ctx, e, lookupChange{PackageLookupChange: dashapi.PackageLookupChange{Mode: str("local")}, surface: "cli"}); err == nil {
		t.Fatal("local without the database accept was written")
	}
	if err := applyLookupChange(ctx, e, lookupChange{PackageLookupChange: dashapi.PackageLookupChange{Mode: str("local"), AcceptDownload: true}, surface: "cli"}); err != nil {
		t.Fatal(err)
	}
	e = open()
	if e.lookupMode() != lookupLocal || !e.consent.Accepted() {
		t.Fatalf("after local: mode %q", e.lookupMode())
	}
	if err := applyLookupChange(ctx, e, lookupChange{PackageLookupChange: dashapi.PackageLookupChange{Mode: str("remote")}, surface: "agent"}); err == nil {
		t.Fatal("an unknown surface changed the posture")
	}
	e.managed = true
	if err := applyLookupChange(ctx, e, lookupChange{PackageLookupChange: dashapi.PackageLookupChange{Mode: str("remote"), AcceptRemote: true}, surface: "dashboard"}); !errors.Is(err, errLookupManaged) {
		t.Fatalf("managed: %v", err)
	}
	// A managed node's status reads what its org decided (lane RM-3): the
	// org has not turned the lookup on here, so the mode is local and the
	// org block says off.
	if st := lookupStatus(ctx, e); !st.Managed || st.Mode != lookupLocal || st.Configured != "" || st.Org == nil || st.Org.On {
		t.Fatalf("managed status %+v", st)
	}
}

// TestLookupLiveStopsSending: a lookup turned off in the config file stops
// the next request, read by the files' change stamps.
func TestLookupLiveStopsSending(t *testing.T) {
	bucket := &remoteBucket{objs: map[string][]byte{}}
	e := remoteEnv(t, "", bucket)
	s := newLookupStamp(e)
	if !s.allowed() {
		t.Fatal("an unchanged posture is not allowed")
	}
	resolved, _ := config.ResolveGlobalPath(e.configPath)
	b, _ := os.ReadFile(resolved)
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(resolved, bytes.Replace(b, []byte(`match = "remote"`), []byte(`match = "local"`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(resolved, future, future)
	if s.allowed() {
		t.Fatal("a lookup turned off still sends")
	}
	g := gatedFetcher{inner: bucket, live: s.allowed}
	if _, err := g.Fetch(context.Background(), "npm/obj/x.json.gz", 10); err == nil || len(bucket.asked) != 0 {
		t.Fatal("the gated fetcher sent after the lookup was turned off")
	}
}
