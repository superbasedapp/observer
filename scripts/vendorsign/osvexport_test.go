package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/md5" //nolint:gosec // the bucket's checksum spelling, in a test
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

var osvT0 = time.Date(2026, 11, 3, 6, 0, 0, 0, time.UTC)

// osvZip builds an export zip of name -> body, entries in name order,
// stamped with mod.
func osvZip(t *testing.T, records map[string]string, mod time.Time) []byte {
	t.Helper()
	names := make([]string, 0, len(records))
	for n := range records {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, n := range names {
		f, err := w.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Deflate, Modified: mod})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(records[n])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// osvWriteEco writes <in>/<eco>/all.zip and a source.json with its true
// checksums; mut may falsify them.
func osvWriteEco(t *testing.T, in, eco string, data []byte, mut func(*osvSource)) {
	t.Helper()
	dir := filepath.Join(in, eco)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, osvExportFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	var crc [4]byte
	binary.BigEndian.PutUint32(crc[:], crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)))
	sum := md5.Sum(data) //nolint:gosec // test
	src := osvSource{
		Object:       "https://storage.googleapis.com/osv-vulnerabilities/" + eco + "/all.zip",
		LastModified: "Mon, 02 Nov 2026 10:00:00 GMT",
		CRC32C:       base64.StdEncoding.EncodeToString(crc[:]),
		MD5:          base64.StdEncoding.EncodeToString(sum[:]),
		Generation:   "1762077600000000",
	}
	if mut != nil {
		mut(&src)
	}
	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, osvSourceFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// osvFixture is one publisher's directories and key.
type osvFixture struct {
	in, state, out string
	pub            ed25519.PublicKey
	priv           ed25519.PrivateKey
}

func newOSVFixture(t *testing.T) osvFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	return osvFixture{
		in: filepath.Join(root, "in"), state: filepath.Join(root, "state"), out: filepath.Join(root, "out"),
		pub: pub, priv: priv,
	}
}

func (f osvFixture) opts(now time.Time, ratio float64) osvExportOptions {
	return osvExportOptions{
		Key: f.priv, In: f.in, State: f.state, Out: f.out,
		RebaseAge: 7 * 24 * time.Hour, RebaseRatio: ratio, Reissue: 20 * time.Hour, Now: now,
	}
}

func (f osvFixture) kindDir() string { return filepath.Join(f.out, string(content.OSVExport)) }

// verify checks the published envelope with the content channel, as a node
// would, and every artifact against its entry.
func (f osvFixture) verify(t *testing.T, now time.Time, accepted *content.Accepted) content.Result {
	t.Helper()
	env, err := os.ReadFile(filepath.Join(f.kindDir(), "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := content.Verify(content.VerifyInput{
		Envelope: env, Kind: content.OSVExport, FeedKeys: []ed25519.PublicKey{f.pub}, Accepted: accepted, Now: now,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for _, e := range res.Manifest.Entries {
		data, err := os.ReadFile(filepath.Join(f.kindDir(), e.Name))
		if err != nil {
			t.Fatal(err)
		}
		if err := content.CheckArtifact(e, data); err != nil {
			t.Errorf("%s: %v", e.Name, err)
		}
		if e.Upstream.Method != content.UpstreamGCSObjectHash || e.License != osvLicense {
			t.Errorf("%s: upstream %+v license %q", e.Name, e.Upstream, e.License)
		}
	}
	if _, err := content.Verify(content.VerifyInput{
		Envelope: env, Kind: content.OSVExport, VendorKeys: []ed25519.PublicKey{f.pub}, Now: now,
	}); content.ReasonOf(err) != content.ContentReasonNoKey {
		t.Errorf("a feed-signed manifest must not verify against vendor keys alone: %v", err)
	}
	return res
}

func entryNamed(t *testing.T, m content.Manifest, name string) content.Entry {
	t.Helper()
	for _, e := range m.Entries {
		if e.Name == name {
			return e
		}
	}
	t.Fatalf("no entry %s", name)
	return content.Entry{}
}

// readZip returns name -> body.
func readZip(t *testing.T, data []byte) map[string]string {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name] = string(b)
	}
	return out
}

// applyDelta is the node-side merge in its simplest form: the base minus
// Drop, overlaid with the delta's records.
func applyDelta(t *testing.T, f osvFixture, m content.Manifest, eco string) map[string]string {
	t.Helper()
	d := entryNamed(t, m, eco+".delta.zip")
	if d.Delta == nil || d.Delta.Base != eco+".zip" {
		t.Fatalf("%s carries no delta over %s.zip: %+v", d.Name, eco, d.Delta)
	}
	base, err := os.ReadFile(filepath.Join(f.kindDir(), eco+".zip"))
	if err != nil {
		t.Fatal(err)
	}
	if content.HashBytes(base) != d.Delta.BaseSHA256 {
		t.Fatal("delta's base digest is not the published base")
	}
	delta, err := os.ReadFile(filepath.Join(f.kindDir(), d.Name))
	if err != nil {
		t.Fatal(err)
	}
	merged := readZip(t, base)
	for _, n := range d.Delta.Drop {
		delete(merged, n)
	}
	for n, b := range readZip(t, delta) {
		merged[n] = b
	}
	if len(merged) != d.Delta.Records {
		t.Errorf("%s: merged %d records, the entry says %d", eco, len(merged), d.Delta.Records)
	}
	return merged
}

func TestOSVExportBaseDeltaAndReissue(t *testing.T) {
	f := newOSVFixture(t)
	npm1 := map[string]string{"A.json": `{"id":"A"}`, "B.json": `{"id":"B"}`, "C.json": `{"id":"C"}`}
	pypi := map[string]string{"X.json": `{"id":"X"}`}
	osvWriteEco(t, f.in, "npm", osvZip(t, npm1, osvT0), nil)
	osvWriteEco(t, f.in, "PyPI", osvZip(t, pypi, osvT0), nil)

	// First run: a base per ecosystem and empty deltas.
	r1, err := buildOSVExport(f.opts(osvT0, 1))
	if err != nil {
		t.Fatal(err)
	}
	if r1.ManifestVersion != 1 || r1.Epoch != 1 || len(r1.Ecosystems) != 2 {
		t.Fatalf("first run: %+v", r1)
	}
	for _, e := range r1.Ecosystems {
		if !e.Rebased || e.Reason != "new" || e.DeltaEntries != 0 || e.Dropped != 0 {
			t.Errorf("first run %s: %+v", e.Eco, e)
		}
	}
	res1 := f.verify(t, osvT0, nil)
	if got := applyDelta(t, f, res1.Manifest, "npm"); !reflect.DeepEqual(got, npm1) {
		t.Errorf("first run npm merge = %v", got)
	}
	if d := entryNamed(t, res1.Manifest, "npm.delta.zip"); len(readZip(t, mustRead(t, filepath.Join(f.kindDir(), d.Name)))) != 0 {
		t.Error("the first delta must be empty")
	}
	firstBase := entryNamed(t, res1.Manifest, "npm.zip")

	// A changed, an added and a removed record.
	npm2 := map[string]string{"A.json": `{"id":"A"}`, "B.json": `{"id":"B","modified":"2"}`, "D.json": `{"id":"D"}`}
	osvWriteEco(t, f.in, "npm", osvZip(t, npm2, osvT0.Add(time.Hour)), nil)
	t1 := osvT0.Add(time.Hour)
	r2, err := buildOSVExport(f.opts(t1, 1))
	if err != nil {
		t.Fatal(err)
	}
	if r2.ManifestVersion != 2 || r2.Epoch != 2 {
		t.Fatalf("second run counters: %+v", r2)
	}
	acc1 := &content.Accepted{ManifestVersion: res1.Manifest.ManifestVersion, Epoch: res1.Manifest.Epoch, ManifestHash: res1.Hash}
	res2 := f.verify(t, t1, acc1)
	npmBase := entryNamed(t, res2.Manifest, "npm.zip")
	if npmBase.SHA256 != firstBase.SHA256 {
		t.Error("the npm base must be kept")
	}
	d := entryNamed(t, res2.Manifest, "npm.delta.zip")
	if !reflect.DeepEqual(d.Delta.Drop, []string{"C.json"}) || d.Delta.Records != 3 {
		t.Errorf("npm delta: %+v", d.Delta)
	}
	deltaRecs := readZip(t, mustRead(t, filepath.Join(f.kindDir(), d.Name)))
	if len(deltaRecs) != 2 || deltaRecs["B.json"] != npm2["B.json"] || deltaRecs["D.json"] != npm2["D.json"] {
		t.Errorf("npm delta records: %v", deltaRecs)
	}
	if got := applyDelta(t, f, res2.Manifest, "npm"); !reflect.DeepEqual(got, npm2) {
		t.Errorf("npm merge = %v, want %v", got, npm2)
	}
	if got := applyDelta(t, f, res2.Manifest, "PyPI"); !reflect.DeepEqual(got, pypi) {
		t.Errorf("PyPI merge = %v", got)
	}
	var npmRes osvEcoResult
	for _, e := range r2.Ecosystems {
		if e.Eco == "npm" {
			npmRes = e
		}
	}
	if npmRes.Rebased || npmRes.DeltaEntries != 2 || npmRes.Dropped != 1 {
		t.Errorf("npm result: %+v", npmRes)
	}

	// Unchanged inside the reissue window: nothing written.
	before := mustRead(t, filepath.Join(f.kindDir(), "manifest.json"))
	t2 := t1.Add(2 * time.Hour)
	r3, err := buildOSVExport(f.opts(t2, 1))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	printOSVExport(&out, r3)
	if !r3.Unchanged || out.String() != "unchanged\n" {
		t.Fatalf("unchanged run: %+v %q", r3, out.String())
	}
	if !bytes.Equal(before, mustRead(t, filepath.Join(f.kindDir(), "manifest.json"))) {
		t.Error("an unchanged run rewrote the manifest")
	}

	// Past the reissue interval: a new version, the same epoch.
	t3 := t1.Add(21 * time.Hour)
	r4, err := buildOSVExport(f.opts(t3, 1))
	if err != nil {
		t.Fatal(err)
	}
	if r4.Unchanged || r4.ManifestVersion != 3 || r4.Epoch != 2 {
		t.Fatalf("reissue: %+v", r4)
	}
	acc2 := &content.Accepted{ManifestVersion: res2.Manifest.ManifestVersion, Epoch: res2.Manifest.Epoch, ManifestHash: res2.Hash}
	res4 := f.verify(t, t3, acc2)
	if entryNamed(t, res4.Manifest, "npm.delta.zip").SHA256 != d.SHA256 {
		t.Error("a reissue must carry the same artifacts")
	}

	// An explicit version not above the last is refused.
	osvWriteEco(t, f.in, "npm", osvZip(t, npm1, osvT0), nil)
	o := f.opts(t3.Add(time.Hour), 1)
	o.ManifestVersion = 3
	if _, err := buildOSVExport(o); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Errorf("a version at the last published one must be refused: %v", err)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOSVExportRebase(t *testing.T) {
	recs := map[string]string{}
	for _, n := range []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J"} {
		recs[n+".json"] = `{"id":"` + n + `"}`
	}
	cases := []struct {
		name   string
		after  time.Duration
		change []string
		want   string // "" kept
	}{
		{name: "small change kept", after: time.Hour, change: []string{"A"}},
		{name: "past the ratio", after: time.Hour, change: []string{"A", "B"}, want: "ratio"},
		{name: "past the age", after: 7 * 24 * time.Hour, change: []string{"A"}, want: "age"},
		{name: "unchanged but old", after: 8 * 24 * time.Hour, want: "age"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newOSVFixture(t)
			osvWriteEco(t, f.in, "npm", osvZip(t, recs, osvT0), nil)
			if _, err := buildOSVExport(f.opts(osvT0, 0.10)); err != nil {
				t.Fatal(err)
			}
			next := map[string]string{}
			for k, v := range recs {
				next[k] = v
			}
			for _, n := range tc.change {
				next[n+".json"] = `{"id":"` + n + `","v":2}`
			}
			osvWriteEco(t, f.in, "npm", osvZip(t, next, osvT0), nil)
			now := osvT0.Add(tc.after)
			r, err := buildOSVExport(f.opts(now, 0.10))
			if err != nil {
				t.Fatal(err)
			}
			if r.Unchanged {
				t.Fatalf("unexpected unchanged: %+v", r)
			}
			e := r.Ecosystems[0]
			if e.Rebased != (tc.want != "") || e.Reason != tc.want {
				t.Fatalf("result %+v, want reason %q", e, tc.want)
			}
			res := f.verify(t, now, nil)
			d := entryNamed(t, res.Manifest, "npm.delta.zip")
			if tc.want != "" && (len(readZip(t, mustRead(t, filepath.Join(f.kindDir(), d.Name)))) != 0 || len(d.Delta.Drop) != 0) {
				t.Error("a rebased ecosystem must publish an empty delta")
			}
			if got := applyDelta(t, f, res.Manifest, "npm"); !reflect.DeepEqual(got, next) {
				t.Errorf("merge = %v", got)
			}
		})
	}
}

func TestOSVExportRefusesChecksumMismatch(t *testing.T) {
	data := func(t *testing.T) []byte { return osvZip(t, map[string]string{"A.json": "{}"}, osvT0) }
	other := base64.StdEncoding.EncodeToString([]byte{9, 9, 9, 9})
	cases := []struct {
		name string
		mut  func(*osvSource)
		want string
	}{
		{"crc32c mismatch", func(s *osvSource) { s.CRC32C = other }, "crc32c"},
		{"md5 mismatch", func(s *osvSource) { s.MD5 = base64.StdEncoding.EncodeToString(make([]byte, 16)) }, "md5"},
		{"no checksum", func(s *osvSource) { s.CRC32C, s.MD5 = "", "" }, "crc32c or md5"},
		{"http object", func(s *osvSource) { s.Object = "http://storage.googleapis.com/x/all.zip" }, "https"},
		{"bad last_modified", func(s *osvSource) { s.LastModified = "yesterday" }, "last_modified"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newOSVFixture(t)
			osvWriteEco(t, f.in, "npm", data(t), tc.mut)
			_, err := buildOSVExport(f.opts(osvT0, 1))
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "npm") {
				t.Fatalf("err = %v, want one naming npm and %q", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(f.state, osvStateFile)); !os.IsNotExist(err) {
				t.Error("a refused run must not write state")
			}
			if _, err := os.Stat(f.kindDir()); !os.IsNotExist(err) {
				t.Error("a refused run must not write output")
			}
		})
	}
	// Only one checksum present, and it matches: accepted.
	f := newOSVFixture(t)
	osvWriteEco(t, f.in, "npm", data(t), func(s *osvSource) { s.MD5 = "" })
	if _, err := buildOSVExport(f.opts(osvT0, 1)); err != nil {
		t.Fatalf("crc32c alone: %v", err)
	}
	// Not a zip at all.
	g := newOSVFixture(t)
	osvWriteEco(t, g.in, "npm", []byte("not a zip"), nil)
	if _, err := buildOSVExport(g.opts(osvT0, 1)); err == nil || !strings.Contains(err.Error(), "zip") {
		t.Fatalf("a non-zip export: %v", err)
	}
}

// TestOSVDeltaIsDeterministic: the same records cut from exports stamped
// at different times give byte-identical deltas, and the entries are the
// raw input bytes.
func TestOSVDeltaIsDeterministic(t *testing.T) {
	recs := map[string]string{"B.json": `{"id":"B"}`, "A.json": strings.Repeat(`{"id":"A"}`, 50)}
	cut := func(mod time.Time) []byte {
		data := osvZip(t, recs, mod)
		r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		d, err := writeOSVDelta(r, []string{"A.json", "B.json"})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	a, b := cut(osvT0), cut(osvT0.Add(400*24*time.Hour))
	if !bytes.Equal(a, b) {
		t.Fatal("the same records gave different delta bytes")
	}
	r, err := zip.NewReader(bytes.NewReader(a), int64(len(a)))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.File) != 2 || r.File[0].Name != "A.json" || r.File[1].Name != "B.json" {
		t.Fatalf("delta entries not sorted: %v", r.File)
	}
	for _, zf := range r.File {
		if !zf.Modified.Equal(osvDeltaModTime) || zf.Method != zip.Deflate {
			t.Errorf("%s: modified %v method %d", zf.Name, zf.Modified, zf.Method)
		}
	}
	if got := readZip(t, a); !reflect.DeepEqual(got, recs) {
		t.Errorf("delta records = %v", got)
	}
	empty, err := writeOSVDelta(r, nil)
	if err != nil || len(empty) == 0 || len(readZip(t, empty)) != 0 {
		t.Errorf("an empty delta must be a valid empty zip: %d bytes, %v", len(empty), err)
	}
}

func TestOSVExportKeyChecks(t *testing.T) {
	_, feedPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	feedPub := feedPriv.Public().(ed25519.PublicKey)
	_, relPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	relPub := relPriv.Public().(ed25519.PublicKey)
	restoreV, restoreF := acceptedVendorKeys, acceptedFeedKeys
	t.Cleanup(func() { acceptedVendorKeys, acceptedFeedKeys = restoreV, restoreF })
	acceptedVendorKeys = func() []ed25519.PublicKey { return []ed25519.PublicKey{relPub} }

	acceptedFeedKeys = func() []ed25519.PublicKey { return nil }
	if warn, err := checkFeedKeyIsPinned(feedPriv, false); err != nil || !strings.Contains(warn, "NO content-feed public key") {
		t.Errorf("no compiled feed key: warn %q err %v", warn, err)
	}
	if _, err := checkFeedKeyIsPinned(relPriv, true); err == nil || !strings.Contains(err.Error(), "RELEASE") {
		t.Errorf("the release key must never sign the feed: %v", err)
	}
	acceptedFeedKeys = func() []ed25519.PublicKey { return []ed25519.PublicKey{feedPub} }
	if warn, err := checkFeedKeyIsPinned(feedPriv, false); err != nil || warn != "" {
		t.Errorf("pinned feed key: warn %q err %v", warn, err)
	}
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	if _, err := checkFeedKeyIsPinned(otherPriv, false); err == nil {
		t.Error("an unpinned key must be refused")
	}
	if warn, err := checkFeedKeyIsPinned(otherPriv, true); err != nil || warn == "" {
		t.Errorf("-allow-unpinned-key: warn %q err %v", warn, err)
	}
}

func TestKeygenFeedWritesTheFeedKeyFile(t *testing.T) {
	dir := t.TempDir()
	outFile, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"keygen", "-feed", "-out", dir}, outFile); err != nil {
		t.Fatal(err)
	}
	_ = outFile.Close()
	printed := string(mustRead(t, outFile.Name()))
	priv, err := loadPrivateKey(filepath.Join(dir, contentFeedKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if !strings.Contains(printed, pubB64) || !strings.Contains(printed, keyID(priv.Public().(ed25519.PublicKey))) || !strings.Contains(printed, "contentfeedkey.go") {
		t.Errorf("keygen -feed output: %s", printed)
	}
	if _, err := os.Stat(filepath.Join(dir, vendorKeyFile)); !os.IsNotExist(err) {
		t.Error("keygen -feed must not write the vendor key file")
	}
	if _, _, err := generateKeypairNamed(dir, contentFeedKeyFile); err == nil {
		t.Error("a second keygen -feed overwrote the feed key")
	}
}

// TestOSVExportGitHubActionsArtifactNames: the GitHub Actions ecosystem's
// input directory keeps the bucket's spelling (with its space); its
// artifacts are named by osvdb's one rule (GitHub-Actions.zip, a name the
// feed host serves), the delta names that base, a second run keeps the base
// from the state, and a node reads them by the same rule.
func TestOSVExportGitHubActionsArtifactNames(t *testing.T) {
	f := newOSVFixture(t)
	gha1 := map[string]string{"GHSA-mrrh-fwg8-r2c3.json": `{"id":"GHSA-mrrh-fwg8-r2c3"}`}
	osvWriteEco(t, f.in, "GitHub Actions", osvZip(t, gha1, osvT0), nil)
	osvWriteEco(t, f.in, "npm", osvZip(t, map[string]string{"A.json": `{"id":"A"}`}, osvT0), nil)
	if _, err := buildOSVExport(f.opts(osvT0, 1)); err != nil {
		t.Fatal(err)
	}
	res1 := f.verify(t, osvT0, nil)
	base := osvdb.ExportArtifact("GitHub Actions")
	if base != "GitHub-Actions.zip" || osvdb.DeltaArtifact("GitHub Actions") != "GitHub-Actions.delta.zip" {
		t.Fatalf("artifact names %q", base)
	}
	for _, e := range res1.Manifest.Entries {
		if strings.Contains(e.Name, " ") {
			t.Fatalf("an artifact name with a space: %q", e.Name)
		}
	}
	first := entryNamed(t, res1.Manifest, base)
	gha2 := map[string]string{"GHSA-mrrh-fwg8-r2c3.json": `{"id":"GHSA-mrrh-fwg8-r2c3"}`, "GHSA-p756-rfxh-x63h.json": `{"id":"GHSA-p756-rfxh-x63h"}`}
	osvWriteEco(t, f.in, "GitHub Actions", osvZip(t, gha2, osvT0.Add(time.Hour)), nil)
	t1 := osvT0.Add(time.Hour)
	if _, err := buildOSVExport(f.opts(t1, 1)); err != nil {
		t.Fatal(err)
	}
	res2 := f.verify(t, t1, &content.Accepted{ManifestVersion: res1.Manifest.ManifestVersion, Epoch: res1.Manifest.Epoch, ManifestHash: res1.Hash})
	if b := entryNamed(t, res2.Manifest, base); b.SHA256 != first.SHA256 {
		t.Fatal("the GitHub Actions base must be kept from the state")
	}
	d := entryNamed(t, res2.Manifest, osvdb.DeltaArtifact("GitHub Actions"))
	if d.Delta == nil || d.Delta.Base != base || d.Delta.Records != 2 {
		t.Fatalf("delta %+v", d.Delta)
	}
	if recs := readZip(t, mustRead(t, filepath.Join(f.kindDir(), d.Name))); len(recs) != 1 || recs["GHSA-p756-rfxh-x63h.json"] == "" {
		t.Fatalf("delta records %v", recs)
	}
	if _, err := os.Stat(filepath.Join(f.state, "base", base)); err != nil {
		t.Fatalf("the state base is not under the artifact name: %v", err)
	}
}

// TestOSVExportRefusesUnnamableEcosystem: an input directory whose name has
// no artifact name is refused before anything is signed.
func TestOSVExportRefusesUnnamableEcosystem(t *testing.T) {
	f := newOSVFixture(t)
	osvWriteEco(t, f.in, "GitHub  Actions", osvZip(t, map[string]string{"A.json": `{"id":"A"}`}, osvT0), nil)
	if _, err := buildOSVExport(f.opts(osvT0, 1)); err == nil || !strings.Contains(err.Error(), "artifact") {
		t.Fatalf("want a refusal, got %v", err)
	}
	if _, err := os.Stat(f.kindDir()); err == nil {
		t.Fatal("nothing may be written for a refused input")
	}
}
