package main

import (
	"archive/zip"
	"context"
	"crypto/ed25519"
	"crypto/md5" //nolint:gosec // the fixture's source.json carries the bucket's MD5 spelling
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secrules"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// secindex_test.go pins `vendorsign secindex`: one kind per run, signed
// with the content-feed key, every install-gate ecosystem required, the
// node's check before anything is signed, the flags publish.sh passes, and
// (TestPopularNamesInstalledAsksS742) a popular list it publishes,
// installed through the node's content store, turning a one-edit
// typosquat into an S-742 ask. Every report id and list is synthetic.

// gateMalName is a synthetic malicious package per install-gate ecosystem,
// spelled as that ecosystem's names are.
var gateMalName = map[secfeed.Ecosystem]string{
	secfeed.EcoNpm: "synth-evil-npm", secfeed.EcoPyPI: "synth-evil-py", secfeed.EcoGo: "example.com/synth/evil",
	secfeed.EcoCargo: "synth-evil-rs", secfeed.EcoNuGet: "Synth.Evil", secfeed.EcoRubyGems: "synth-evil-gem",
	secfeed.EcoPackagist: "synthvendor/evil",
}

// osvRecordJSON is one synthetic OSV record.
func osvRecordJSON(id, osvEco, name string, versions ...string) string {
	b, _ := json.Marshal(map[string]any{"id": id, "affected": []map[string]any{{
		"package": map[string]string{"ecosystem": osvEco, "name": name}, "versions": versions,
	}}})
	return string(b)
}

// writeOSVExportDir writes one publisher input directory: all.zip with the
// records (entry name to body) and a source.json carrying its MD5.
func writeOSVExportDir(t *testing.T, dir string, records map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	zpath := filepath.Join(dir, osvExportFile)
	zf, err := os.Create(zpath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	for name, body := range records {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zf.Close(); err != nil {
		t.Fatal(err)
	}
	raw := mustRead(t, zpath)
	sum := md5.Sum(raw) //nolint:gosec // the bucket's checksum spelling
	src := fmt.Sprintf(`{"object":"https://osv-vulnerabilities.storage.googleapis.com/%s/all.zip","last_modified":"Thu, 05 Nov 2026 13:01:00 GMT","md5":"%s","generation":"1793648903481089"}`,
		filepath.Base(dir), base64.StdEncoding.EncodeToString(sum[:]))
	if err := os.WriteFile(filepath.Join(dir, osvSourceFile), []byte(src+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeGateExports writes an export for every install-gate ecosystem: one
// MAL- report and one GHSA advisory each (extra adds records to npm).
func writeGateExports(t *testing.T, in string, extra map[string]string) {
	t.Helper()
	for _, spec := range secfeed.Ecosystems() {
		recs := map[string]string{
			"MAL-2026-" + string(spec.Eco) + ".json":   osvRecordJSON("MAL-2026-"+string(spec.Eco), spec.OSV, gateMalName[spec.Eco]),
			"GHSA-synth-" + string(spec.Eco) + ".json": osvRecordJSON("GHSA-synth-"+string(spec.Eco), spec.OSV, "synth-good-"+string(spec.Eco)),
		}
		if spec.Eco == secfeed.EcoNpm {
			for k, v := range extra {
				recs[k] = v
			}
		}
		writeOSVExportDir(t, filepath.Join(in, spec.OSV), recs)
	}
}

// writePopularLists writes one list per install-gate ecosystem, shaped as
// the ranked lists publish.sh fetches (a JSON array of names), except pypi,
// which is a line list; lists overrides an ecosystem's names.
func writePopularLists(t *testing.T, dir string, lists map[secfeed.Ecosystem][]string) map[secfeed.Ecosystem]string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	out := map[secfeed.Ecosystem]string{}
	for _, spec := range secfeed.Ecosystems() {
		names, ok := lists[spec.Eco]
		if !ok {
			names = []string{"synthpopular-alpha-" + string(spec.Eco), "synthpopular-beta-" + string(spec.Eco)}
		}
		p := filepath.Join(dir, string(spec.Eco)+".json")
		var body []byte
		if spec.Eco == secfeed.EcoPyPI {
			p = filepath.Join(dir, "pypi.txt")
			body = []byte("# a line list\n" + strings.Join(names, "\n") + "\n")
		} else {
			body, _ = json.Marshal(names)
		}
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
		out[spec.Eco] = p
	}
	return out
}

// publishedSigner reads the signer field of a kind's published envelope.
func publishedSigner(t *testing.T, out string, kind content.Kind) string {
	t.Helper()
	var env content.Envelope
	if err := json.Unmarshal(mustRead(t, filepath.Join(out, string(kind), "manifest.json")), &env); err != nil {
		t.Fatal(err)
	}
	return env.Signer
}

func popularOpts(f exploitFixture, now time.Time, lists map[secfeed.Ecosystem]string) secIndexOptions {
	return secIndexOptions{
		singleFeedOptions: f.opts(now), Kind: content.PopularNames, Popular: lists, MinNames: 1,
		Source: "synthetic ranked lists", License: "CC-BY-SA-4.0", SourceURL: "https://popular.example/api/v1/registries",
	}
}

func TestSecIndexMaliciousFromExports(t *testing.T) {
	f := newExploitFixture(t)
	in := filepath.Join(f.root, "in")
	writeGateExports(t, in, nil)
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	o := secIndexOptions{singleFeedOptions: f.opts(now), Kind: content.MaliciousPackages, OSVExport: in, MinReports: 7}
	res, err := buildSecIndex(o)
	if err != nil || res.Unchanged || res.ManifestVersion != 1 {
		t.Fatalf("first publish: %+v %v", res, err)
	}
	if len(res.Lines) != len(secfeed.Ecosystems())+1 || !strings.Contains(res.Lines[len(res.Lines)-1], "7 MAL- reports kept (7 not MAL-") {
		t.Errorf("summary %q", res.Lines)
	}
	// f.verify trusts the content-feed key alone; the envelope says so too.
	r, data := f.verify(t, content.MaliciousPackages, secfeed.MaliciousArtifact, now, nil)
	if s := publishedSigner(t, f.out, content.MaliciousPackages); s != content.SignerFeed {
		t.Errorf("signer %q, want the content-feed key", s)
	}
	e := r.Manifest.Entries[0]
	if e.Upstream.Object != maliciousExportURL || e.License != maliciousLicense || !strings.HasPrefix(e.Version, "osv 2026-11-05") {
		t.Errorf("entry %+v", e)
	}
	issued, _ := time.Parse(time.RFC3339, r.Manifest.IssuedAt)
	expires, _ := time.Parse(time.RFC3339, r.Manifest.ExpiresAt)
	if expires.Sub(issued) != maliciousValidity {
		t.Errorf("validity %s, want %s", expires.Sub(issued), maliciousValidity)
	}
	ix, err := secfeed.ParseIndex(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	for eco, name := range gateMalName {
		if a := ix.Lookup(eco, name, ""); !a.Malicious {
			t.Errorf("%s %s not listed: %+v", eco, name, a)
		}
		if a := ix.Lookup(eco, "synth-good-"+string(eco), ""); a.Malicious || a.ListedVersions {
			t.Errorf("a GHSA advisory entered the malicious list for %s: %+v", eco, a)
		}
	}

	// The same input an hour later: unchanged, nothing written.
	o.Now = now.Add(time.Hour)
	if res, err := buildSecIndex(o); err != nil || !res.Unchanged {
		t.Errorf("unchanged input: %+v %v", res, err)
	}
	// 21 hours later: re-signed, same epoch (the bytes did not move).
	o.Now = now.Add(21 * time.Hour)
	if res, err := buildSecIndex(o); err != nil || res.ManifestVersion != 2 || res.Epoch != 1 {
		t.Errorf("re-sign: %+v %v", res, err)
	}
	// A new report: a new version and a new epoch.
	writeGateExports(t, in, map[string]string{"MAL-2026-new.json": osvRecordJSON("MAL-2026-new", "npm", "synth-evil-two", "1.0.0")})
	o.Now = now.Add(22 * time.Hour)
	if res, err := buildSecIndex(o); err != nil || res.ManifestVersion != 3 || res.Epoch != 2 {
		t.Errorf("changed input: %+v %v", res, err)
	}
}

func TestSecIndexMaliciousRefusals(t *testing.T) {
	rows := []struct {
		name  string
		setup func(t *testing.T, in string, o *secIndexOptions)
		want  string
	}{
		{"an install-gate ecosystem's export is missing", func(t *testing.T, in string, _ *secIndexOptions) {
			if err := os.RemoveAll(filepath.Join(in, "RubyGems")); err != nil {
				t.Fatal(err)
			}
		}, "every ecosystem the install gate checks"},
		{"an export does not match its source.json", func(t *testing.T, in string, _ *secIndexOptions) {
			p := filepath.Join(in, "PyPI", osvSourceFile)
			src := strings.Replace(string(mustRead(t, p)), `"md5":"`, `"md5":"AAAA`, 1)
			if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "md5"},
		{"fewer reports than -min-reports", func(_ *testing.T, _ string, o *secIndexOptions) { o.MinReports = 8 }, "under -min-reports 8"},
		{"both inputs", func(_ *testing.T, in string, o *secIndexOptions) { o.OSVDir = in }, "exactly one of"},
		{"no input", func(_ *testing.T, _ string, o *secIndexOptions) { o.OSVExport = "" }, "exactly one of"},
		{"a popular list in a malicious run", func(_ *testing.T, in string, o *secIndexOptions) {
			o.Popular = map[secfeed.Ecosystem]string{secfeed.EcoNpm: in}
		}, "its own run"},
		{"no kind", func(_ *testing.T, _ string, o *secIndexOptions) { o.Kind = "" }, "-kind must be"},
		{"a kind secindex does not build", func(_ *testing.T, _ string, o *secIndexOptions) { o.Kind = content.KEV }, "-kind must be"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			f := newExploitFixture(t)
			in := filepath.Join(f.root, "in")
			writeGateExports(t, in, nil)
			o := secIndexOptions{singleFeedOptions: f.opts(time.Now().UTC()), Kind: content.MaliciousPackages, OSVExport: in, MinReports: 1}
			r.setup(t, in, &o)
			if _, err := buildSecIndex(o); err == nil || !strings.Contains(err.Error(), r.want) {
				t.Fatalf("err %v, want %q", err, r.want)
			}
			if _, err := os.Stat(filepath.Join(f.out, string(content.MaliciousPackages), "manifest.json")); !os.IsNotExist(err) {
				t.Error("a refused run wrote a manifest")
			}
		})
	}
}

// TestSecIndexMaliciousLooseRecords: the -osv form (a directory of loose
// records) still builds; an empty one is refused.
func TestSecIndexMaliciousLooseRecords(t *testing.T) {
	f := newExploitFixture(t)
	recs := filepath.Join(f.root, "osv", "malicious", "npm")
	if err := os.MkdirAll(recs, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"MAL-2026-1.json": osvRecordJSON("MAL-2026-1", "npm", "synth-evil"),
		"GHSA-1.json":     osvRecordJSON("GHSA-1", "npm", "synth-good"),
		"README.md":       "not a record",
	} {
		if err := os.WriteFile(filepath.Join(recs, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Add(-time.Minute)
	res, err := buildSecIndex(secIndexOptions{singleFeedOptions: f.opts(now), Kind: content.MaliciousPackages, OSVDir: filepath.Join(f.root, "osv"), MinReports: 1})
	if err != nil || res.ManifestVersion != 1 {
		t.Fatalf("loose records: %+v %v", res, err)
	}
	r, _ := f.verify(t, content.MaliciousPackages, secfeed.MaliciousArtifact, now, nil)
	if r.Manifest.Entries[0].Upstream.Object != maliciousRecordsURL {
		t.Errorf("object %q", r.Manifest.Entries[0].Upstream.Object)
	}
	g := newExploitFixture(t)
	if _, err := buildSecIndex(secIndexOptions{singleFeedOptions: g.opts(now), Kind: content.MaliciousPackages, OSVDir: t.TempDir(), MinReports: 1}); err == nil {
		t.Error("an empty malicious list must not be published")
	}
}

func TestSecIndexPopular(t *testing.T) {
	f := newExploitFixture(t)
	lists := writePopularLists(t, filepath.Join(f.root, "pop"), map[secfeed.Ecosystem][]string{
		secfeed.EcoPyPI: {"Synth_Requests", "synth-requests", "synth.numpy"},
	})
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	res, err := buildSecIndex(popularOpts(f, now, lists))
	if err != nil || res.ManifestVersion != 1 {
		t.Fatalf("popular: %+v %v", res, err)
	}
	r, data := f.verify(t, content.PopularNames, secfeed.PopularArtifact, now, nil)
	e := r.Manifest.Entries[0]
	if s := publishedSigner(t, f.out, content.PopularNames); e.Source != "synthetic ranked lists" || e.License != "CC-BY-SA-4.0" || e.Upstream.Object != "https://popular.example/api/v1/registries" || s != content.SignerFeed {
		t.Errorf("entry %+v signer %q", e, s)
	}
	issued, _ := time.Parse(time.RFC3339, r.Manifest.IssuedAt)
	expires, _ := time.Parse(time.RFC3339, r.Manifest.ExpiresAt)
	if expires.Sub(issued) != popularValidity {
		t.Errorf("validity %s, want %s", expires.Sub(issued), popularValidity)
	}
	ix, err := secfeed.ParseIndex(nil, data)
	if err != nil {
		t.Fatal(err)
	}
	if a := ix.Lookup(secfeed.EcoPyPI, "synth_requests", ""); !a.Popular {
		t.Errorf("a line-list name, normalized, is popular: %+v", a)
	}
	if a := ix.Lookup(secfeed.EcoGo, "synthpopular-alpha-go", ""); !a.Popular {
		t.Errorf("a JSON-array name is popular: %+v", a)
	}

	rows := []struct {
		name string
		edit func(o *secIndexOptions)
		want string
	}{
		{"an install-gate ecosystem has no list", func(o *secIndexOptions) { delete(o.Popular, secfeed.EcoCargo) }, "no -popular list for cargo"},
		{"a list under -min-names", func(o *secIndexOptions) { o.MinNames = 3 }, "under -min-names 3"},
		{"no source label", func(o *secIndexOptions) { o.Source = "" }, "needs -source"},
		{"no license", func(o *secIndexOptions) { o.License = "" }, "needs -source"},
		{"a source URL that is not https", func(o *secIndexOptions) { o.SourceURL = "http://popular.example/" }, "https"},
		{"an OSV input in a popular run", func(o *secIndexOptions) { o.OSVExport = f.root }, "its own run"},
		{"a broken JSON list", func(o *secIndexOptions) {
			p := filepath.Join(f.root, "broken.json")
			_ = os.WriteFile(p, []byte(`["synth-a", 7]`), 0o600)
			o.Popular[secfeed.EcoNpm] = p
		}, "not a JSON array of names"},
		{"trailing data after the array", func(o *secIndexOptions) {
			p := filepath.Join(f.root, "trailing.json")
			_ = os.WriteFile(p, []byte(`["synth-a"] ["synth-b"]`), 0o600)
			o.Popular[secfeed.EcoNpm] = p
		}, "trailing data"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			g := newExploitFixture(t)
			o := popularOpts(g, now, map[secfeed.Ecosystem]string{})
			for k, v := range lists {
				o.Popular[k] = v
			}
			r.edit(&o)
			if _, err := buildSecIndex(o); err == nil || !strings.Contains(err.Error(), r.want) {
				t.Fatalf("err %v, want %q", err, r.want)
			}
			if _, err := os.Stat(filepath.Join(g.out, string(content.PopularNames), "manifest.json")); !os.IsNotExist(err) {
				t.Error("a refused run wrote a manifest")
			}
		})
	}
}

// TestSecIndexKindsNeedTheirOwnState: the two kinds never share a state
// directory, so their counters and cadences stay apart.
func TestSecIndexKindsNeedTheirOwnState(t *testing.T) {
	f := newExploitFixture(t)
	in := filepath.Join(f.root, "in")
	writeGateExports(t, in, nil)
	now := time.Now().UTC().Add(-time.Minute)
	if _, err := buildSecIndex(secIndexOptions{singleFeedOptions: f.opts(now), Kind: content.MaliciousPackages, OSVExport: in, MinReports: 1}); err != nil {
		t.Fatal(err)
	}
	lists := writePopularLists(t, filepath.Join(f.root, "pop"), nil)
	if _, err := buildSecIndex(popularOpts(f, now, lists)); err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Errorf("a shared state directory: %v", err)
	}
}

// TestSecIndexValidityInsideKindBounds: each kind's lifetime is inside the
// kind table's bound, and the small-feed path refuses one past it.
func TestSecIndexValidityInsideKindBounds(t *testing.T) {
	for kind, v := range map[content.Kind]time.Duration{content.MaliciousPackages: maliciousValidity, content.PopularNames: popularValidity} {
		ks, ok := content.KindOf(kind)
		if !ok || v <= 0 || v > ks.MaxValidity || v > ks.AgeFloor {
			t.Errorf("%s: validity %s against max %s, floor %s", kind, v, ks.MaxValidity, ks.AgeFloor)
		}
	}
	f := newExploitFixture(t)
	o := f.opts(time.Now().UTC())
	o.Validity = 15 * 24 * time.Hour
	if _, err := publishSingleFeed(o, "secindex", content.MaliciousPackages, []singleFeedArtifact{{name: "malicious.idx", data: []byte("x")}}); err == nil || !strings.Contains(err.Error(), "bound") {
		t.Errorf("a validity past the kind's bound: %v", err)
	}
}

// TestSecIndexCLI runs both kinds through the command line with the flags
// deploy/feed-publisher/publish.sh passes.
func TestSecIndexCLI(t *testing.T) {
	keyDir := t.TempDir()
	stdout, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdout.Close() }()
	if err := run([]string{"keygen", "-feed", "-out", keyDir}, stdout); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, contentFeedKeyFile)
	priv, err := loadPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	restore := acceptedFeedKeys
	t.Cleanup(func() { acceptedFeedKeys = restore })
	acceptedFeedKeys = func() []ed25519.PublicKey { return []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)} }

	root := t.TempDir()
	in := filepath.Join(root, "in")
	writeGateExports(t, in, nil)
	lists := writePopularLists(t, filepath.Join(root, "in-popular"), nil)
	out := filepath.Join(root, "out")
	mal := []string{"secindex", "-kind", "security.malicious_packages", "-key", keyPath, "-osv-export", in,
		"-min-reports", "7", "-state", filepath.Join(root, "state-malicious"), "-out", out}
	if err := run(mal, stdout); err != nil {
		t.Fatalf("malicious: %v", err)
	}
	pop := []string{"secindex", "-kind", "security.popular_names", "-key", keyPath, "-min-names", "2",
		"-source", "synthetic ranked lists", "-license", "CC-BY-SA-4.0", "-source-url", "https://popular.example/api/v1/registries",
		"-reissue-hours", "168", "-state", filepath.Join(root, "state-popular"), "-out", out}
	for _, spec := range secfeed.Ecosystems() {
		pop = append(pop, "-popular", string(spec.Eco)+"="+lists[spec.Eco])
	}
	if err := run(pop, stdout); err != nil {
		t.Fatalf("popular: %v", err)
	}
	for _, k := range []string{"security.malicious_packages/malicious.idx", "security.malicious_packages/manifest.json", "security.popular_names/popular.idx", "security.popular_names/manifest.json"} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(k))); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	printed := string(mustRead(t, stdout.Name()))
	if !strings.Contains(printed, "secindex: npm: generation 1793648903481089") || !strings.Contains(printed, "secindex: pypi: 2 names") {
		t.Errorf("summary:\n%s", printed)
	}
	if err := run([]string{"secindex", "-kind", "security.popular_names", "-key", keyPath, "-popular", "cobol=x", "-state", root, "-out", out}, stdout); err == nil || !strings.Contains(err.Error(), "unknown ecosystem") {
		t.Errorf("an unknown ecosystem flag: %v", err)
	}
}

// TestPopularNamesInstalledAsksS742 is the end to end the publish side
// exists for: a popular list secindex publishes from a ranked name array
// is installed through the node's content store with the content-feed key,
// loaded the way the hook loads it (signature, digest and format checked,
// then searched in place), and an agent's install of a name one edit from
// a popular one is an S-742 ask in both modes; the popular name itself is
// not.
func TestPopularNamesInstalledAsksS742(t *testing.T) {
	f := newExploitFixture(t)
	lists := writePopularLists(t, filepath.Join(f.root, "pop"), map[secfeed.Ecosystem][]string{
		secfeed.EcoPyPI: {"requests", "synth-numpy"},
		secfeed.EcoNpm:  {"synth-lodash", "synth-react"},
	})
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	if _, err := buildSecIndex(popularOpts(f, now, lists)); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.out, string(content.PopularNames))
	tr := contentchan.Trust{FeedKeys: []ed25519.PublicKey{f.pub}}
	store := contentchan.Store{Root: t.TempDir()}
	if _, err := store.Install(content.PopularNames, mustRead(t, filepath.Join(dir, "manifest.json")),
		map[string][]byte{secfeed.PopularArtifact: mustRead(t, filepath.Join(dir, secfeed.PopularArtifact))}, tr); err != nil {
		t.Fatalf("install: %v", err)
	}
	l, err := store.Load(content.PopularNames, tr, 0)
	if err != nil || l.Freshness != content.Fresh {
		t.Fatalf("load: %v freshness %s", err, l.Freshness)
	}
	pop, err := l.ReadArtifact(secfeed.PopularArtifact)
	if err != nil || secfeed.ValidateIndex(pop, true) != nil {
		t.Fatalf("installed artifact: %v", err)
	}
	ix, err := secfeed.ParseIndexVerified(nil, pop)
	if err != nil {
		t.Fatal(err)
	}

	comp, err := secrules.Compose(func(id string) bool { return id == "security.deps" })
	if err != nil {
		t.Fatal(err)
	}
	gate := func(cmd string) (policy.InstallCheck, map[policy.Mode]policy.Verdict) {
		ev := policy.Event{Kind: policy.KindShellExec, Target: cmd, ActionType: "run_command", Cwd: "/r", ProjectRoot: "/r",
			Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true}, Now: now}
		specs, _, _ := secfeed.EventSpecs(&ev)
		checks := secfeed.Gate(context.Background(), secfeed.GateInput{
			Specs: specs, Public: func(secfeed.InstallSpec) bool { return true }, Index: ix, IndexFreshness: l.Freshness, Now: now,
		})
		if len(checks) != 1 {
			t.Fatalf("%s: checks %+v", cmd, checks)
		}
		ev.Security = &policy.Security{Posture: policy.SecurityPostureClean, Packs: []string{"security", "security.deps"}, Installs: checks}
		out := map[policy.Mode]policy.Verdict{}
		for _, mode := range []policy.Mode{policy.ModeObserve, policy.ModeEnforce} {
			eng, err := policy.New(policy.Config{Mode: mode, Home: "/home/u", ExtraRules: comp.Rules})
			if err != nil {
				t.Fatal(err)
			}
			out[mode] = eng.Evaluate(ev)
		}
		return checks[0], out
	}

	c, verdicts := gate("pip install reqeusts")
	if c.Verdict != policy.InstallNearMiss || c.NearMiss != "requests" || c.Source != policy.InstallSourceOffline {
		t.Fatalf("typosquat check %+v", c)
	}
	for mode, v := range verdicts {
		if v.RuleID != "S-742" || v.Decision != policy.DecisionAsk || !strings.Contains(v.Reason, "requests") {
			t.Errorf("%s: %s %s %q, want an S-742 ask naming requests", mode, v.RuleID, v.Decision, v.Reason)
		}
	}
	if c, verdicts := gate("npm install synth-lodahs"); c.Verdict != policy.InstallNearMiss || verdicts[policy.ModeEnforce].RuleID != "S-742" {
		t.Errorf("an adjacent swap in npm: %+v %+v", c, verdicts[policy.ModeEnforce])
	}
	c, verdicts = gate("pip install requests")
	if c.Verdict == policy.InstallNearMiss || verdicts[policy.ModeEnforce].RuleID == "S-742" {
		t.Errorf("the popular name itself: %+v %+v", c, verdicts[policy.ModeEnforce])
	}
}
