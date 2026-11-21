package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvshardkey"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// shardRec is a pretty-printed OSV record whose affected entries are the
// given ecosystem/name pairs ("npm/lodash"), fields deliberately not in
// alphabetical order.
func shardRec(id string, pkgs ...string) string {
	aff := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		eco, name, _ := strings.Cut(p, "/")
		aff = append(aff, fmt.Sprintf(`
    {"package": {"ecosystem": %q, "name": %q},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]}`, eco, name))
	}
	return fmt.Sprintf(`{
  "schema_version": "1.6.0",
  "id": %q,
  "modified": "2026-11-01T00:00:00Z",
  "summary": "issue in <%s> & co",
  "affected": [%s
  ]
}
`, id, id, strings.Join(aff, ","))
}

// npmShardRecords is a small npm export: a package with two advisories, a
// mixed-case spelling of it, a record naming many packages (and one PyPI
// entry, which no npm shard may carry), a record with no affected and one
// whose only entry has no name.
func npmShardRecords() map[string]string {
	many := []string{"npm/left-pad", "PyPI/requests"}
	for i := 0; i < 12; i++ {
		many = append(many, fmt.Sprintf("npm/pkg-%02d", i))
	}
	return map[string]string{
		"GHSA-0001.json": shardRec("GHSA-0001", "npm/lodash"),
		"GHSA-0002.json": shardRec("GHSA-0002", "npm/lodash", "npm/lodash.merge"),
		"GHSA-0003.json": shardRec("GHSA-0003", "npm/LoDash"),
		"GHSA-0004.json": shardRec("GHSA-0004", many...),
		"GHSA-0005.json": `{"id":"GHSA-0005","withdrawn":"2026-01-01T00:00:00Z"}`,
		"GHSA-0006.json": `{"id":"GHSA-0006","affected":[{"package":{"ecosystem":"npm","name":""}}]}`,
		"README.txt":     "not a record",
	}
}

// shardFixture is one osvshards publisher's directories.
type shardFixture struct {
	osvFixture
	lang, osIn, objects string
}

func newShardFixture(t *testing.T) shardFixture {
	t.Helper()
	f := newOSVFixture(t)
	root := filepath.Dir(f.in)
	return shardFixture{osvFixture: f, lang: f.in, osIn: filepath.Join(root, "os"), objects: filepath.Join(root, "objects")}
}

func (f shardFixture) opts(now time.Time) osvShardsOptions {
	return osvShardsOptions{Key: f.priv, Lang: f.lang, OS: f.osIn, State: f.state, Objects: f.objects, Out: f.out, Reissue: 20 * time.Hour, Now: now}
}

func (f shardFixture) kindDir() string { return filepath.Join(f.out, string(content.OSVShards)) }

// writeShardInputs lays out a language input (npm, PyPI, GitHub Actions)
// and an OS input (Debian-12).
func writeShardInputs(t *testing.T, f shardFixture, npm map[string]string) {
	t.Helper()
	osvWriteEco(t, f.lang, "npm", osvZip(t, npm, osvT0), nil)
	osvWriteEco(t, f.lang, "PyPI", osvZip(t, map[string]string{
		"PYSEC-1.json": shardRec("PYSEC-1", "PyPI/Zope.Interface"),
	}, osvT0), nil)
	osvWriteEco(t, f.lang, "GitHub Actions", osvZip(t, map[string]string{
		"GHSA-gha1.json": shardRec("GHSA-gha1", "GitHub Actions/Azure/setup-kubectl"),
	}, osvT0), nil)
	if err := os.MkdirAll(f.osIn, 0o755); err != nil {
		t.Fatal(err)
	}
	deb := osvZip(t, map[string]string{
		"DSA-1.json": shardRec("DSA-1", "Debian:12/linux", "Debian:12/openssl"),
		"DSA-2.json": shardRec("DSA-2", "Debian:12/openssl"),
	}, osvT0)
	if err := os.WriteFile(filepath.Join(f.osIn, "Debian-12.zip"), deb, 0o600); err != nil {
		t.Fatal(err)
	}
}

// shardNode is the node's half of the walk, built only from the published
// bytes: the verified manifest, then per package its set's descriptor, the
// index file of its first key byte and the shard of its prefix, each
// checked against the digest that names it.
type shardNode struct {
	t       *testing.T
	f       shardFixture
	sets    map[string]osvshardkey.SetDescriptor
	fetched map[string]bool
}

func newShardNode(t *testing.T, f shardFixture, now time.Time) shardNode {
	t.Helper()
	env := mustRead(t, filepath.Join(f.kindDir(), "manifest.json"))
	res, err := content.Verify(content.VerifyInput{Envelope: env, Kind: content.OSVShards, FeedKeys: []ed25519.PublicKey{f.pub}, Now: now})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, err := content.Verify(content.VerifyInput{Envelope: env, Kind: content.OSVExport, FeedKeys: []ed25519.PublicKey{f.pub}, Now: now}); err == nil {
		t.Error("a shard manifest must not verify as security.osv_export")
	}
	n := shardNode{t: t, f: f, sets: map[string]osvshardkey.SetDescriptor{}, fetched: map[string]bool{}}
	for _, e := range res.Manifest.Entries {
		data := mustRead(t, filepath.Join(f.kindDir(), e.Name))
		if err := content.CheckArtifact(e, data); err != nil {
			t.Fatal(err)
		}
		d, err := osvshardkey.DecodeSet(data)
		if err != nil {
			t.Fatal(err)
		}
		if e.Name != osvshardkey.SetFile(d.Set) {
			t.Fatalf("entry %s holds set %s", e.Name, d.Set)
		}
		n.sets[d.Set] = d
	}
	return n
}

// object reads one object from the store and checks its digest and size.
func (n shardNode) object(rel, digest string, size int64) []byte {
	n.t.Helper()
	data := mustRead(n.t, filepath.Join(n.f.objects, filepath.FromSlash(rel)))
	if int64(len(data)) != size || content.HashBytes(data) != digest {
		n.t.Fatalf("%s does not match its reference", rel)
	}
	n.fetched[rel] = true
	return data
}

// lookup returns the records the node assembles for one package of a set:
// every record of every shard it fetches, merged by id (union of affected).
func (n shardNode) lookup(set string, names ...string) map[string]map[string]any {
	n.t.Helper()
	d, ok := n.sets[set]
	if !ok {
		n.t.Fatalf("no set %s", set)
	}
	out := map[string]map[string]any{}
	for _, p := range osvshardkey.Prefixes(d.Base, d.Bits, names...) {
		b := osvshardkey.FirstByte(p, d.Bits)
		ref, ok := d.IndexFor(b)
		if !ok {
			continue
		}
		raw := n.object(osvshardkey.IndexPath(set, ref.Object), ref.Object, ref.Size)
		idx, err := osvshardkey.DecodeIndex(raw, d, b)
		if err != nil {
			n.t.Fatal(err)
		}
		s, ok := idx.ShardFor(p)
		if !ok {
			continue
		}
		gz := n.object(osvshardkey.ShardPath(set, s.Object), s.Object, s.Size)
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			n.t.Fatal(err)
		}
		body, err := io.ReadAll(zr)
		if err != nil {
			n.t.Fatal(err)
		}
		var recs []map[string]any
		if err := json.Unmarshal(body, &recs); err != nil {
			n.t.Fatalf("shard is not a JSON array: %v", err)
		}
		if len(recs) != s.Records {
			n.t.Fatalf("shard holds %d records, its index says %d", len(recs), s.Records)
		}
		for _, r := range recs {
			// Strip mode: every entry a shard carries hashes into its prefix.
			for _, a := range r["affected"].([]any) {
				pkg := a.(map[string]any)["package"].(map[string]any)
				if osvshardkey.PrefixOf(d.Base, pkg["name"].(string), d.Bits) != p {
					n.t.Errorf("shard %d carries %v, which hashes elsewhere", p, pkg)
				}
				if osvshardkey.Base(pkg["ecosystem"].(string)) != d.Base {
					n.t.Errorf("shard of %s carries an entry of %v", d.Base, pkg["ecosystem"])
				}
			}
			id := r["id"].(string)
			if prev, ok := out[id]; ok {
				prev["affected"] = append(prev["affected"].([]any), r["affected"].([]any)...)
				continue
			}
			out[id] = r
		}
	}
	return out
}

// matches is what osvlocal (byte equality on name and ecosystem base) finds
// for name among assembled records.
func matches(recs map[string]map[string]any, base, name string) []string {
	var ids []string
	for id, r := range recs {
		for _, a := range r["affected"].([]any) {
			pkg := a.(map[string]any)["package"].(map[string]any)
			if pkg["name"] == name && osvshardkey.Base(pkg["ecosystem"].(string)) == base {
				ids = append(ids, id)
				break
			}
		}
	}
	sort.Strings(ids)
	return ids
}

func TestOSVShardsNodeFindsExactlyTheWholeExportsAdvisories(t *testing.T) {
	f := newShardFixture(t)
	writeShardInputs(t, f, npmShardRecords())
	res, err := buildOSVShards(f.opts(osvT0))
	if err != nil {
		t.Fatal(err)
	}
	if res.Unchanged || res.ManifestVersion != 1 || res.Epoch != 1 {
		t.Fatalf("first publish: %+v", res)
	}
	n := newShardNode(t, f, osvT0.Add(time.Hour))
	if got := len(n.sets); got != 4 {
		t.Fatalf("%d sets, want npm, PyPI, GitHub-Actions and Debian-12", got)
	}
	d := n.sets["npm"]
	if d.Bits != 13 || d.Base != "npm" || d.Ecosystem != "npm" || d.Epoch != 1 || d.Mode != osvshardkey.ModeStrip || d.Records != 4 {
		t.Fatalf("npm descriptor: %+v", d)
	}
	if deb := n.sets["Debian-12"]; deb.Base != "Debian" || deb.Ecosystem != "Debian:12" || deb.Bits != 9 {
		t.Fatalf("Debian-12 descriptor: %+v", deb)
	}

	for _, tc := range []struct {
		set, base string
		names     []string
		match     string
		want      []string
	}{
		{"npm", "npm", []string{"lodash"}, "lodash", []string{"GHSA-0001", "GHSA-0002"}},
		{"npm", "npm", []string{"lodash.merge"}, "lodash.merge", []string{"GHSA-0002"}},
		// The mixed-case record shares lodash's shard, as Canon promises.
		{"npm", "npm", []string{"lodash"}, "LoDash", []string{"GHSA-0003"}},
		{"npm", "npm", []string{"pkg-07"}, "pkg-07", []string{"GHSA-0004"}},
		{"npm", "npm", []string{"left-pad"}, "left-pad", []string{"GHSA-0004"}},
		{"npm", "npm", []string{"requests"}, "requests", nil},
		{"npm", "npm", []string{"no-such-package"}, "no-such-package", nil},
		// PEP 503: the node's normalized name reaches the record's spelling.
		{"PyPI", "PyPI", []string{"zope-interface"}, "Zope.Interface", []string{"PYSEC-1"}},
		// GitHub Actions: the lower-cased owner/repo reaches the record's.
		{"GitHub-Actions", "GitHub Actions", []string{"azure/setup-kubectl"}, "Azure/setup-kubectl", []string{"GHSA-gha1"}},
		{"Debian-12", "Debian", []string{"openssl"}, "openssl", []string{"DSA-1", "DSA-2"}},
		{"Debian-12", "Debian", []string{"linux"}, "linux", []string{"DSA-1"}},
	} {
		got := matches(n.lookup(tc.set, tc.names...), tc.base, tc.match)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s %v -> %s: %v, want %v", tc.set, tc.names, tc.match, got, tc.want)
		}
	}

	// A record naming many packages is published once per prefix, each copy
	// stripped; merging the copies a node fetched restores every entry.
	all := make([]string, 0, 13)
	all = append(all, "left-pad")
	for i := 0; i < 12; i++ {
		all = append(all, fmt.Sprintf("pkg-%02d", i))
	}
	merged := n.lookup("npm", all...)
	if got := len(merged["GHSA-0004"]["affected"].([]any)); got != 13 {
		t.Errorf("merged GHSA-0004 holds %d entries, want the 13 npm ones", got)
	}
	// Every other field survives the strip as written.
	if merged["GHSA-0004"]["summary"] != "issue in <GHSA-0004> & co" {
		t.Errorf("summary: %v", merged["GHSA-0004"]["summary"])
	}

	// objects.txt names exactly the store's objects, which are exactly what
	// the descriptors reach.
	listed := strings.Fields(string(mustRead(t, filepath.Join(f.objects, osvShardsObjectsList))))
	if !sort.StringsAreSorted(listed) || len(listed) != res.Objects {
		t.Fatalf("objects.txt: %d paths, sorted %v; result says %d", len(listed), sort.StringsAreSorted(listed), res.Objects)
	}
	if got := storeObjects(t, f.objects); !reflect.DeepEqual(got, listed) {
		t.Fatalf("store holds\n%v\nobjects.txt names\n%v", got, listed)
	}
}

// TestOSVShardsNewEcosystems: the six ecosystems mirrored since 2026-11-06
// (Pub, SwiftURL, Hex, Hackage, Julia, CRAN) publish one set each at their
// NameRules bits, named by the ecosystem as the bucket spells it; the node's
// name, which may differ in case from the record's, reaches the record; and
// an entry of another ecosystem in the same record stays out of the set's
// shards (shardNode.lookup fails on one).
func TestOSVShardsNewEcosystems(t *testing.T) {
	f := newShardFixture(t)
	writeShardInputs(t, f, npmShardRecords())
	rows := []struct {
		eco, id, record, node string
	}{
		{"Pub", "GHSA-pub1", "dio", "dio"},
		{"SwiftURL", "GHSA-swf1", "github.com/Alamofire/Alamofire", "github.com/alamofire/alamofire"},
		{"Hex", "GHSA-hex1", "plug", "plug"},
		{"Hackage", "HSEC-2026-0001", "aeson", "aeson"},
		{"Julia", "JLSEC-2026-1", "ImageMagick_jll", "imagemagick_jll"},
		{"CRAN", "RSEC-2026-1", "readxl", "readxl"},
	}
	for _, r := range rows {
		osvWriteEco(t, f.lang, r.eco, osvZip(t, map[string]string{
			r.id + ".json": shardRec(r.id, r.eco+"/"+r.record, "npm/"+r.record),
		}, osvT0), nil)
	}
	if _, err := buildOSVShards(f.opts(osvT0)); err != nil {
		t.Fatal(err)
	}
	n := newShardNode(t, f, osvT0.Add(time.Hour))
	if got := len(n.sets); got != 4+len(rows) {
		t.Fatalf("%d sets, want the four of writeShardInputs and the six", got)
	}
	for _, r := range rows {
		d, ok := n.sets[r.eco]
		if !ok {
			t.Errorf("no %s set", r.eco)
			continue
		}
		rule, _ := osvshardkey.RuleFor(r.eco)
		if d.Bits != 8 || d.Bits != rule.DefaultBits || d.Base != r.eco || d.Ecosystem != r.eco || d.Records != 1 || d.Mode != osvshardkey.ModeStrip {
			t.Errorf("%s descriptor: %+v", r.eco, d)
		}
		if got := matches(n.lookup(r.eco, r.node), r.eco, r.record); !reflect.DeepEqual(got, []string{r.id}) {
			t.Errorf("%s %q -> %q: %v, want [%s]", r.eco, r.node, r.record, got, r.id)
		}
	}
}

// storeObjects lists the object store's object files, sorted.
func storeObjects(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if rel != osvShardsObjectsList {
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// storeDigests maps every object file to its bytes' digest.
func storeDigests(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, rel := range storeObjects(t, dir) {
		out[rel] = content.HashBytes(mustRead(t, filepath.Join(dir, filepath.FromSlash(rel))))
	}
	return out
}

func TestOSVShardsDeterministicAndContentAddressed(t *testing.T) {
	a, b := newShardFixture(t), newShardFixture(t)
	writeShardInputs(t, a, npmShardRecords())
	writeShardInputs(t, b, npmShardRecords())
	if _, err := buildOSVShards(a.opts(osvT0)); err != nil {
		t.Fatal(err)
	}
	if _, err := buildOSVShards(b.opts(osvT0.Add(3 * time.Hour))); err != nil {
		t.Fatal(err)
	}
	da, db := storeDigests(t, a.objects), storeDigests(t, b.objects)
	if !reflect.DeepEqual(da, db) {
		t.Fatal("two builds of the same input wrote different objects")
	}
	for rel, sum := range da {
		if !strings.Contains(rel, "/"+sum+".") {
			t.Errorf("%s is not named by its digest %s", rel, sum)
		}
	}
	for _, set := range []string{"npm", "PyPI", "GitHub-Actions", "Debian-12"} {
		name := osvshardkey.SetFile(set)
		if !bytes.Equal(mustRead(t, filepath.Join(a.kindDir(), name)), mustRead(t, filepath.Join(b.kindDir(), name))) {
			t.Errorf("%s differs between two builds of the same input", name)
		}
	}
	// A shard is a deterministic gzip: a zero header (no name, no time).
	for rel := range da {
		if !strings.HasSuffix(rel, ".json.gz") {
			continue
		}
		zr, err := gzip.NewReader(bytes.NewReader(mustRead(t, filepath.Join(a.objects, filepath.FromSlash(rel)))))
		if err != nil {
			t.Fatal(err)
		}
		if zr.Name != "" || !zr.ModTime.IsZero() {
			t.Errorf("%s: gzip header name %q time %v", rel, zr.Name, zr.ModTime)
		}
	}

	// The same input again on the same state: every set reused, nothing
	// published, the store and objects.txt untouched.
	before := mustRead(t, filepath.Join(a.objects, osvShardsObjectsList))
	res, err := buildOSVShards(a.opts(osvT0.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Unchanged {
		t.Fatalf("an unchanged input published: %+v", res)
	}
	for _, s := range res.Sets {
		if !s.reused {
			t.Errorf("%s was rebuilt for an unchanged input", s.in.set)
		}
	}
	if !bytes.Equal(before, mustRead(t, filepath.Join(a.objects, osvShardsObjectsList))) || !reflect.DeepEqual(da, storeDigests(t, a.objects)) {
		t.Fatal("an unchanged run changed the store")
	}

	// Past the reissue interval it re-signs with the same epoch and objects.
	res, err = buildOSVShards(a.opts(osvT0.Add(21 * time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Unchanged || res.ManifestVersion != 2 || res.Epoch != 1 {
		t.Fatalf("reissue: %+v", res)
	}
	if !reflect.DeepEqual(da, storeDigests(t, a.objects)) {
		t.Fatal("a reissue changed the store")
	}

	// A lost object makes the set rebuild, which writes the same bytes back.
	var victim string
	for rel := range da {
		if strings.HasPrefix(rel, "npm/obj/") {
			victim = rel
			break
		}
	}
	if err := os.Remove(filepath.Join(a.objects, filepath.FromSlash(victim))); err != nil {
		t.Fatal(err)
	}
	res, err = buildOSVShards(a.opts(osvT0.Add(22 * time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Unchanged {
		t.Fatalf("a rebuild of the same input published: %+v", res)
	}
	if !reflect.DeepEqual(da, storeDigests(t, a.objects)) {
		t.Fatal("the rebuild did not restore the lost object byte for byte")
	}
}

func TestOSVShardsChangedExportRewritesOnlyItsShards(t *testing.T) {
	f := newShardFixture(t)
	writeShardInputs(t, f, npmShardRecords())
	if _, err := buildOSVShards(f.opts(osvT0)); err != nil {
		t.Fatal(err)
	}
	before := storeDigests(t, f.objects)
	n1 := newShardNode(t, f, osvT0)
	sets1 := n1.sets

	// One npm record changes (a new fixed version); nothing else does.
	recs := npmShardRecords()
	recs["GHSA-0001.json"] = strings.Replace(recs["GHSA-0001.json"], "9.9.9", "9.9.10", 1)
	osvWriteEco(t, f.lang, "npm", osvZip(t, recs, osvT0), nil)
	res, err := buildOSVShards(f.opts(osvT0.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Unchanged || res.ManifestVersion != 2 || res.Epoch != 2 {
		t.Fatalf("changed publish: %+v", res)
	}
	after := storeDigests(t, f.objects)
	var added, removed []string
	for rel := range after {
		if _, ok := before[rel]; !ok {
			added = append(added, rel)
		}
	}
	for rel := range before {
		if _, ok := after[rel]; !ok {
			removed = append(removed, rel)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	// lodash's shard and the index file listing it: one new shard, one new
	// index file, the old two pruned, every other object kept as it was.
	if len(added) != 2 || len(removed) != 2 {
		t.Fatalf("added %v, removed %v; want one shard and one index file each", added, removed)
	}
	for _, rel := range added {
		if !strings.HasPrefix(rel, "npm/") {
			t.Errorf("a set that did not change gained %s", rel)
		}
	}
	n2 := newShardNode(t, f, osvT0.Add(time.Hour))
	if n2.sets["npm"].Epoch != 2 {
		t.Errorf("npm epoch %d, want 2", n2.sets["npm"].Epoch)
	}
	for _, s := range []string{"PyPI", "GitHub-Actions", "Debian-12"} {
		if !reflect.DeepEqual(n2.sets[s], sets1[s]) {
			t.Errorf("%s changed though its input did not", s)
		}
	}
	got := n2.lookup("npm", "lodash")
	if !strings.Contains(fmt.Sprint(got["GHSA-0001"]), "9.9.10") {
		t.Errorf("the changed record is not the one published: %v", got["GHSA-0001"])
	}
	listed := strings.Fields(string(mustRead(t, filepath.Join(f.objects, osvShardsObjectsList))))
	if !reflect.DeepEqual(storeObjects(t, f.objects), listed) {
		t.Fatal("the store was not pruned to objects.txt")
	}
}

func TestOSVShardsRefusals(t *testing.T) {
	cases := map[string]func(t *testing.T, f shardFixture){
		"a checksum mismatch": func(t *testing.T, f shardFixture) {
			osvWriteEco(t, f.lang, "npm", osvZip(t, npmShardRecords(), osvT0), func(s *osvSource) { s.MD5 = "AAAAAAAAAAAAAAAAAAAAAA==" })
		},
		// opam, not Hex: Hex has a row since the 2026-11-06 ecosystems
		// joined; opam is an OSV ecosystem the mirror does not carry.
		"an ecosystem with no bits row": func(t *testing.T, f shardFixture) {
			osvWriteEco(t, f.lang, "opam", osvZip(t, map[string]string{"A.json": shardRec("A", "opam/x")}, osvT0), nil)
		},
		"an unknown OS file": func(t *testing.T, f shardFixture) {
			if err := os.WriteFile(filepath.Join(f.osIn, "Fedora-40.zip"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a record that is not JSON": func(t *testing.T, f shardFixture) {
			recs := npmShardRecords()
			recs["BAD.json"] = "{not json"
			osvWriteEco(t, f.lang, "npm", osvZip(t, recs, osvT0), nil)
		},
		"a shard over the cap": func(t *testing.T, f shardFixture) {
			prev := osvShardMaxBytes
			osvShardMaxBytes = 64
			t.Cleanup(func() { osvShardMaxBytes = prev })
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			f := newShardFixture(t)
			writeShardInputs(t, f, npmShardRecords())
			if _, err := buildOSVShards(f.opts(osvT0)); err != nil {
				t.Fatal(err)
			}
			manifest := mustRead(t, filepath.Join(f.kindDir(), "manifest.json"))
			list := mustRead(t, filepath.Join(f.objects, osvShardsObjectsList))
			state := mustRead(t, filepath.Join(f.state, osvStateFile))
			mut(t, f)
			if _, err := buildOSVShards(f.opts(osvT0.Add(30 * time.Hour))); err == nil {
				t.Fatal("the build was not refused")
			}
			// A refused build publishes nothing: the last output, its object
			// list and the state stay as they were.
			if !bytes.Equal(manifest, mustRead(t, filepath.Join(f.kindDir(), "manifest.json"))) ||
				!bytes.Equal(list, mustRead(t, filepath.Join(f.objects, osvShardsObjectsList))) ||
				!bytes.Equal(state, mustRead(t, filepath.Join(f.state, osvStateFile))) {
				t.Fatal("a refused build changed the output or the state")
			}
			for _, rel := range strings.Fields(string(list)) {
				if _, err := os.Stat(filepath.Join(f.objects, filepath.FromSlash(rel))); err != nil {
					t.Fatalf("a refused build removed a published object: %v", err)
				}
			}
		})
	}
}

func TestOSVShardsStateIsItsOwn(t *testing.T) {
	f := newShardFixture(t)
	writeShardInputs(t, f, npmShardRecords())
	if err := claimFeedState(f.state, "osvexport", content.OSVExport); err != nil {
		t.Fatal(err)
	}
	if _, err := buildOSVShards(f.opts(osvT0)); err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Fatalf("another kind's state must be refused: %v", err)
	}
}

func TestOSVShardsOSOnlyAndLanguageOnly(t *testing.T) {
	f := newShardFixture(t)
	writeShardInputs(t, f, npmShardRecords())
	o := f.opts(osvT0)
	o.Lang = ""
	if _, err := buildOSVShards(o); err != nil {
		t.Fatal(err)
	}
	if n := newShardNode(t, f, osvT0); len(n.sets) != 1 || n.sets["Debian-12"].Set == "" {
		t.Fatalf("OS only: %v", n.sets)
	}
	o = f.opts(osvT0.Add(time.Hour))
	o.OS = ""
	if _, err := buildOSVShards(o); err != nil {
		t.Fatal(err)
	}
	if n := newShardNode(t, f, osvT0.Add(time.Hour)); len(n.sets) != 3 {
		t.Fatalf("language only: %d sets", len(n.sets))
	}
	o.Lang = ""
	if _, err := buildOSVShards(o); err == nil {
		t.Fatal("a build with no input was accepted")
	}
}

func TestOSVShardsVerb(t *testing.T) {
	root := t.TempDir()
	_, keyPath, err := generateKeypairNamed(filepath.Join(root, "key"), contentFeedKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	f := newShardFixture(t)
	writeShardInputs(t, f, npmShardRecords())
	stdout, err := os.Create(filepath.Join(root, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdout.Close() }()
	args := []string{"osvshards", "-key", keyPath, "-lang", f.lang, "-os", f.osIn, "-state", f.state, "-objects", f.objects, "-out", f.out}
	if err := run(args, stdout); err == nil || !strings.Contains(err.Error(), "not among the content-feed keys") {
		t.Fatalf("an unpinned key must be refused: %v", err)
	}
	if err := run([]string{"osvshards", "-key", keyPath, "-state", f.state, "-objects", f.objects, "-out", f.out}, stdout); err == nil {
		t.Fatal("no input was accepted")
	}
	if err := run(append(args, "-allow-unpinned-key"), stdout); err != nil {
		t.Fatal(err)
	}
	printed := string(mustRead(t, stdout.Name()))
	for _, want := range []string{"npm: built, 13 bits,", "Debian-12: built, 9 bits,", "osvshards: manifest_version 1, epoch 1"} {
		if !strings.Contains(printed, want) {
			t.Errorf("summary lacks %q:\n%s", want, printed)
		}
	}
}
