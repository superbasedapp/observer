package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
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

// osRecSummary carries characters a careless re-encoder would escape
// (HTML) or reorder, so the strip is checked to keep them as written.
const osRecSummary = "heap overflow in <libfoo> & café"

// osRec is a pretty-printed OSV record with one affected entry per
// ecosystem, fields deliberately not in alphabetical order.
func osRec(id string, ecos ...string) string {
	aff := make([]string, 0, len(ecos))
	for _, e := range ecos {
		aff = append(aff, fmt.Sprintf(`
    {
      "package": {"ecosystem": %q, "name": "libfoo"},
      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2-1"}]}],
      "versions": ["1.0-1", "1.1-1"]
    }`, e))
	}
	return fmt.Sprintf(`{
  "schema_version": "1.6.0",
  "id": %q,
  "modified": "2026-11-01T00:00:00Z",
  "summary": %q,
  "affected": [%s
  ],
  "references": [{"type": "WEB", "url": "https://example.test/%s"}]
}
`, id, osRecSummary, strings.Join(aff, ","), id)
}

// compactJSON is the bytes the strip writes for a record that keeps every
// entry it lists.
func compactJSON(t *testing.T, s string) string {
	t.Helper()
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(s)); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// osvZipOrdered builds an export zip with its entries in the given order
// (the bucket's order is not alphabetical), stamped with mod.
func osvZipOrdered(t *testing.T, records map[string]string, order []string, mod time.Time) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, n := range order {
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

func (f osvFixture) osKindDir() string { return filepath.Join(f.out, string(content.OSVOSExport)) }

// verifyOS checks the published envelope as a node would and every
// artifact against its entry.
func (f osvFixture) verifyOS(t *testing.T, now time.Time) content.Manifest {
	t.Helper()
	env, err := os.ReadFile(filepath.Join(f.osKindDir(), "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := content.Verify(content.VerifyInput{Envelope: env, Kind: content.OSVOSExport, FeedKeys: []ed25519.PublicKey{f.pub}, Now: now})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, err := content.Verify(content.VerifyInput{Envelope: env, Kind: content.OSVExport, FeedKeys: []ed25519.PublicKey{f.pub}, Now: now}); err == nil {
		t.Error("an OS manifest must not verify as security.osv_export")
	}
	for _, e := range res.Manifest.Entries {
		data, err := os.ReadFile(filepath.Join(f.osKindDir(), e.Name))
		if err != nil {
			t.Fatal(err)
		}
		if err := content.CheckArtifact(e, data); err != nil {
			t.Errorf("%s: %v", e.Name, err)
		}
	}
	return res.Manifest
}

// mergedOS is the node's view of one release: base plus delta through
// osvdb.MergeExportZip, as name -> record.
func mergedOS(t *testing.T, f osvFixture, m content.Manifest, art string) map[string]string {
	t.Helper()
	d := entryNamed(t, m, art+".delta.zip")
	if d.Delta == nil || d.Delta.Base != art+".zip" {
		t.Fatalf("%s carries no delta over %s.zip: %+v", d.Name, art, d.Delta)
	}
	open := func(name string) *zip.Reader {
		data, err := os.ReadFile(filepath.Join(f.osKindDir(), name))
		if err != nil {
			t.Fatal(err)
		}
		r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	drop := map[string]bool{}
	for _, n := range d.Delta.Drop {
		drop[n] = true
	}
	var out bytes.Buffer
	st, err := osvdb.MergeExportZip(open(art+".zip"), open(d.Name), drop, &out)
	if err != nil {
		t.Fatal(err)
	}
	if st.Total != d.Delta.Records {
		t.Errorf("%s: merged %d records, the entry says %d", art, st.Total, d.Delta.Records)
	}
	return readZip(t, out.Bytes())
}

// osDebian and osRedHat are the first day's two whole exports: two Debian
// releases sharing a record, a record no release keeps, and a Red Hat
// record spanning several streams and majors.
func osDebian() map[string]string {
	return map[string]string{
		"DEBIAN-CVE-1.json": osRec("DEBIAN-CVE-1", "Debian:11", "Debian:12"),
		"DEBIAN-CVE-2.json": osRec("DEBIAN-CVE-2", "Debian:12"),
		"DEBIAN-CVE-3.json": osRec("DEBIAN-CVE-3", "Debian:10"),
		"DEBIAN-CVE-5.json": osRec("DEBIAN-CVE-5", "Debian:11"),
		"DEBIAN-CVE-6.json": osRec("DEBIAN-CVE-6", "Debian:11"),
		"DEBIAN-CVE-7.json": osRec("DEBIAN-CVE-7", "Debian:11"),
	}
}

func osRedHat() map[string]string {
	return map[string]string{
		"RHSA-1.json": osRec("RHSA-1", "Red Hat:enterprise_linux:9::baseos", "Red Hat:enterprise_linux:8::appstream",
			"Red Hat:enterprise_linux:9::appstream", "Red Hat:rhel_eus:9.2::baseos", "Red Hat:enterprise_linux:90::x"),
		"RHSA-2.json": osRec("RHSA-2", "Red Hat:enterprise_linux:10.0::baseos", "Red Hat:enterprise_linux:100::x"),
	}
}

func writeOSInputs(t *testing.T, in string, debian, redhat map[string]string) {
	t.Helper()
	osvWriteEco(t, in, "Debian", osvZip(t, debian, osvT0), func(s *osvSource) {
		s.Object = "https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip"
	})
	osvWriteEco(t, in, "Red Hat", osvZip(t, redhat, osvT0), func(s *osvSource) {
		s.Object = "https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/all.zip"
	})
}

func TestOSVOSExportStripsPerRelease(t *testing.T) {
	f := newOSVFixture(t)
	writeOSInputs(t, f.in, osDebian(), osRedHat())
	r1, err := buildOSVOSExport(f.opts(osvT0, 1))
	if err != nil {
		t.Fatal(err)
	}
	if r1.Unchanged || r1.ManifestVersion != 1 || r1.Epoch != 1 || r1.Verb != "osvosexport" {
		t.Fatalf("first run: %+v", r1)
	}
	if !reflect.DeepEqual(r1.Omitted, []string{"Debian-13"}) {
		t.Errorf("omitted = %v, want the release with no record", r1.Omitted)
	}
	m := f.verifyOS(t, osvT0)

	// Golden manifest shape: two entries per release with a record, in the
	// channel's order, each base the stripped file and each delta over it.
	if m.Kind != content.OSVOSExport || m.ManifestVersion != 1 || m.Epoch != 1 {
		t.Fatalf("manifest %s v%d e%d", m.Kind, m.ManifestVersion, m.Epoch)
	}
	var names []string
	for _, e := range m.Entries {
		names = append(names, e.Name)
	}
	want := []string{
		"Debian-11.delta.zip", "Debian-11.zip", "Debian-12.delta.zip", "Debian-12.zip",
		"Red-Hat-EL10.delta.zip", "Red-Hat-EL10.zip", "Red-Hat-EL8.delta.zip", "Red-Hat-EL8.zip",
		"Red-Hat-EL9.delta.zip", "Red-Hat-EL9.zip",
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	if !reflect.DeepEqual(sorted, want) {
		t.Fatalf("entries %v, want %v", names, want)
	}
	records := map[string]int{"Debian-11": 4, "Debian-12": 2, "Red-Hat-EL8": 1, "Red-Hat-EL9": 1, "Red-Hat-EL10": 1}
	for art, n := range records {
		r, _ := osvdb.ReleaseByArtifact(art)
		b := entryNamed(t, m, r.ExportArtifact())
		d := entryNamed(t, m, r.DeltaArtifact())
		if b.Delta != nil || d.Delta == nil || d.Delta.Base != b.Name || d.Delta.BaseSHA256 != b.SHA256 || d.Delta.Records != n || len(d.Delta.Drop) != 0 {
			t.Errorf("%s: base %+v delta %+v", art, b, d.Delta)
		}
		for _, e := range []content.Entry{b, d} {
			if e.Source != osvOSSourceLabel || e.License != osvOSLicense || e.Upstream.Method != content.UpstreamGCSObjectHash ||
				!strings.HasPrefix(e.Upstream.Object, "https://osv-vulnerabilities.storage.googleapis.com/") || !strings.HasSuffix(e.Upstream.Object, "/all.zip") ||
				e.Version != "2026-11-02T10:00:00Z" {
				t.Errorf("%s: %+v", e.Name, e)
			}
		}
	}

	// What each release holds: only its own entries, every other field and
	// the field order as written.
	wantFiles := map[string]map[string]string{
		"Debian-11": {
			"DEBIAN-CVE-1.json": compactJSON(t, osRec("DEBIAN-CVE-1", "Debian:11")),
			"DEBIAN-CVE-5.json": compactJSON(t, osRec("DEBIAN-CVE-5", "Debian:11")),
			"DEBIAN-CVE-6.json": compactJSON(t, osRec("DEBIAN-CVE-6", "Debian:11")),
			"DEBIAN-CVE-7.json": compactJSON(t, osRec("DEBIAN-CVE-7", "Debian:11")),
		},
		"Debian-12": {
			"DEBIAN-CVE-1.json": compactJSON(t, osRec("DEBIAN-CVE-1", "Debian:12")),
			"DEBIAN-CVE-2.json": compactJSON(t, osRec("DEBIAN-CVE-2", "Debian:12")),
		},
		"Red-Hat-EL8":  {"RHSA-1.json": compactJSON(t, osRec("RHSA-1", "Red Hat:enterprise_linux:8::appstream"))},
		"Red-Hat-EL9":  {"RHSA-1.json": compactJSON(t, osRec("RHSA-1", "Red Hat:enterprise_linux:9::baseos", "Red Hat:enterprise_linux:9::appstream"))},
		"Red-Hat-EL10": {"RHSA-2.json": compactJSON(t, osRec("RHSA-2", "Red Hat:enterprise_linux:10.0::baseos"))},
	}
	for art, wantRecs := range wantFiles {
		if got := mergedOS(t, f, m, art); !reflect.DeepEqual(got, wantRecs) {
			t.Errorf("%s holds %v\nwant %v", art, got, wantRecs)
		}
	}
	if got := mergedOS(t, f, m, "Debian-12")["DEBIAN-CVE-2.json"]; !strings.Contains(got, `"summary":"heap overflow in <libfoo> & café"`) ||
		!strings.HasPrefix(got, `{"schema_version":"1.6.0","id":"DEBIAN-CVE-2",`) {
		t.Errorf("a stripped record must keep its fields, order and characters as written: %s", got)
	}
	if _, err := os.Stat(filepath.Join(f.state, osvOSStrippedDir, "Debian-13.zip")); !os.IsNotExist(err) {
		t.Errorf("an empty release must leave no stripped file: %v", err)
	}
	if raw, err := os.ReadFile(filepath.Join(f.state, osvKindFile)); err != nil || strings.TrimSpace(string(raw)) != string(content.OSVOSExport) {
		t.Errorf("state kind mark = %q, %v", raw, err)
	}

	// The summary names the omitted release and the verb.
	var out bytes.Buffer
	printOSVExport(&out, r1)
	if !strings.Contains(out.String(), "Debian-13: no record, left out of the manifest") || !strings.Contains(out.String(), "osvosexport: manifest_version 1, epoch 1") {
		t.Errorf("summary:\n%s", out.String())
	}
}

func TestOSVOSExportDeltaAndUnchanged(t *testing.T) {
	f := newOSVFixture(t)
	writeOSInputs(t, f.in, osDebian(), osRedHat())
	if _, err := buildOSVOSExport(f.opts(osvT0, 1)); err != nil {
		t.Fatal(err)
	}
	m1 := f.verifyOS(t, osvT0)

	// Day two: DEBIAN-CVE-1 loses its Debian 11 entry (its Debian 12
	// stripped record is byte-identical), DEBIAN-CVE-2 changes, DEBIAN-CVE-4
	// is new for Debian 11; Red Hat's export is unchanged.
	deb := osDebian()
	deb["DEBIAN-CVE-1.json"] = osRec("DEBIAN-CVE-1", "Debian:12")
	deb["DEBIAN-CVE-2.json"] = strings.Replace(osRec("DEBIAN-CVE-2", "Debian:12"), `"1.2-1"`, `"1.3-1"`, 1)
	deb["DEBIAN-CVE-4.json"] = osRec("DEBIAN-CVE-4", "Debian:11")
	osvWriteEco(t, f.in, "Debian", osvZip(t, deb, osvT0.Add(time.Hour)), nil)
	t1 := osvT0.Add(24 * time.Hour)
	r2, err := buildOSVOSExport(f.opts(t1, 1))
	if err != nil {
		t.Fatal(err)
	}
	if r2.Unchanged || r2.ManifestVersion != 2 || r2.Epoch != 2 {
		t.Fatalf("second run: %+v", r2)
	}
	for _, e := range r2.Ecosystems {
		if e.Rebased {
			t.Errorf("%s rebased (%s) on a small change", e.Eco, e.Reason)
		}
	}
	m2 := f.verifyOS(t, t1)
	d11 := entryNamed(t, m2, "Debian-11.delta.zip")
	if !reflect.DeepEqual(d11.Delta.Drop, []string{"DEBIAN-CVE-1.json"}) {
		t.Errorf("Debian-11 drop = %v", d11.Delta.Drop)
	}
	delta11, _ := os.ReadFile(filepath.Join(f.osKindDir(), "Debian-11.delta.zip"))
	if got := readZip(t, delta11); len(got) != 1 || got["DEBIAN-CVE-4.json"] == "" {
		t.Errorf("Debian-11 delta = %v", got)
	}
	delta12, _ := os.ReadFile(filepath.Join(f.osKindDir(), "Debian-12.delta.zip"))
	if got := readZip(t, delta12); len(got) != 1 || !strings.Contains(got["DEBIAN-CVE-2.json"], "1.3-1") {
		t.Errorf("Debian-12 delta must hold only the changed record: %v", got)
	}
	if got := mergedOS(t, f, m2, "Debian-12"); got["DEBIAN-CVE-1.json"] != compactJSON(t, osRec("DEBIAN-CVE-1", "Debian:12")) || len(got) != 2 {
		t.Errorf("Debian-12 merge = %v", got)
	}
	if got := mergedOS(t, f, m2, "Debian-11"); len(got) != 4 || got["DEBIAN-CVE-1.json"] != "" || got["DEBIAN-CVE-4.json"] == "" {
		t.Errorf("Debian-11 merge = %v", got)
	}
	for _, name := range []string{"Red-Hat-EL9.zip", "Red-Hat-EL9.delta.zip", "Debian-12.zip"} {
		if a, b := entryNamed(t, m1, name), entryNamed(t, m2, name); a.SHA256 != b.SHA256 {
			t.Errorf("%s changed though its records did not", name)
		}
	}

	// Day two again, an hour later: nothing changed, nothing is written.
	r3, err := buildOSVOSExport(f.opts(t1.Add(time.Hour), 1))
	if err != nil {
		t.Fatal(err)
	}
	if !r3.Unchanged {
		t.Fatalf("an unchanged input must print unchanged: %+v", r3)
	}
	// Past the reissue interval the same artifacts are re-signed.
	r4, err := buildOSVOSExport(f.opts(t1.Add(21*time.Hour), 1))
	if err != nil || r4.Unchanged || r4.ManifestVersion != 3 || r4.Epoch != 2 {
		t.Fatalf("reissue: %+v %v", r4, err)
	}
}

// TestOSVOSExportDeterministic: the same exports, whatever the order of
// their entries, give byte-identical output.
func TestOSVOSExportDeterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	pub, _ := priv.Public().(ed25519.PublicKey)
	run := func(reverse bool) map[string][]byte {
		root := t.TempDir()
		f := osvFixture{in: filepath.Join(root, "in"), state: filepath.Join(root, "state"), out: filepath.Join(root, "out"), pub: pub, priv: priv}
		for _, d := range []struct {
			base string
			recs map[string]string
		}{{"Debian", osDebian()}, {"Red Hat", osRedHat()}} {
			order := make([]string, 0, len(d.recs))
			for n := range d.recs {
				order = append(order, n)
			}
			sort.Strings(order)
			if reverse {
				sort.Sort(sort.Reverse(sort.StringSlice(order)))
			}
			osvWriteEco(t, f.in, d.base, osvZipOrdered(t, d.recs, order, osvT0), nil)
		}
		if _, err := buildOSVOSExport(f.opts(osvT0, 1)); err != nil {
			t.Fatal(err)
		}
		files := map[string][]byte{}
		ents, err := os.ReadDir(f.osKindDir())
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			b, err := os.ReadFile(filepath.Join(f.osKindDir(), e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			files[e.Name()] = b
		}
		return files
	}
	a, b, c := run(false), run(false), run(true)
	if len(a) != 11 || len(c) != 11 {
		t.Fatalf("%d and %d files, want 10 artifacts and the manifest", len(a), len(c))
	}
	for name, data := range a {
		if !bytes.Equal(data, b[name]) {
			t.Errorf("%s differs between two runs over the same exports", name)
		}
		// Reordered exports are other upstream bytes, so the manifest's
		// upstream checksums differ; every artifact must not.
		if name != "manifest.json" && !bytes.Equal(data, c[name]) {
			t.Errorf("%s depends on the order of the export's entries", name)
		}
	}
}

func TestOSVOSExportRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f osvFixture)
		want  string
	}{
		{"unknown distribution directory", func(t *testing.T, f osvFixture) {
			writeOSInputs(t, f.in, osDebian(), osRedHat())
			osvWriteEco(t, f.in, "Fedora", osvZip(t, map[string]string{"F.json": `{"id":"F"}`}, osvT0), nil)
		}, `"Fedora" is not a distribution`},
		{"no distribution directory", func(t *testing.T, f osvFixture) {
			if err := os.MkdirAll(f.in, 0o755); err != nil {
				t.Fatal(err)
			}
		}, "no distribution directory"},
		{"a whole export with no record", func(t *testing.T, f osvFixture) {
			osvWriteEco(t, f.in, "Debian", osvZip(t, map[string]string{}, osvT0), nil)
		}, "holds no record"},
		{"every release empty", func(t *testing.T, f osvFixture) {
			osvWriteEco(t, f.in, "Debian", osvZip(t, map[string]string{"DEBIAN-CVE-3.json": osRec("DEBIAN-CVE-3", "Debian:10")}, osvT0), nil)
		}, "no release of Debian holds a record"},
		{"a record that is not an object", func(t *testing.T, f osvFixture) {
			osvWriteEco(t, f.in, "Debian", osvZip(t, map[string]string{"X.json": `["Debian:12"]`}, osvT0), nil)
		}, "not a JSON object"},
		{"a record with a repeated field", func(t *testing.T, f osvFixture) {
			osvWriteEco(t, f.in, "Debian", osvZip(t, map[string]string{"X.json": `{"id":"X","affected":[],"affected":[{"package":{"ecosystem":"Debian:12"}}]}`}, osvT0), nil)
		}, "repeats"},
		{"a nested entry", func(t *testing.T, f osvFixture) {
			osvWriteEco(t, f.in, "Debian", osvZip(t, map[string]string{"a/X.json": osRec("X", "Debian:12")}, osvT0), nil)
		}, "flat"},
		{"a checksum mismatch", func(t *testing.T, f osvFixture) {
			osvWriteEco(t, f.in, "Debian", osvZip(t, osDebian(), osvT0), func(s *osvSource) { s.CRC32C = "AAAAAA==" })
		}, "crc32c"},
		{"the language kind's state", func(t *testing.T, f osvFixture) {
			writeOSInputs(t, f.in, osDebian(), osRedHat())
			if err := os.MkdirAll(f.state, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(f.state, osvKindFile), []byte("security.osv_export\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "belongs to security.osv_export"},
		{"an unmarked state", func(t *testing.T, f osvFixture) {
			writeOSInputs(t, f.in, osDebian(), osRedHat())
			if err := os.MkdirAll(f.state, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(f.state, osvStateFile), []byte(`{"manifest_version":3,"epoch":2}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "unmarked state.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newOSVFixture(t)
			tc.setup(t, f)
			_, err := buildOSVOSExport(f.opts(osvT0, 1))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one containing %q", err, tc.want)
			}
			if _, err := os.Stat(f.osKindDir()); !os.IsNotExist(err) {
				t.Errorf("a refused run must write no output: %v", err)
			}
		})
	}
}

// TestOSVExportRefusesTheOSState: the language verb never runs on the OS
// kind's state.
func TestOSVExportRefusesTheOSState(t *testing.T) {
	f := newOSVFixture(t)
	writeOSInputs(t, f.in, osDebian(), osRedHat())
	if _, err := buildOSVOSExport(f.opts(osvT0, 1)); err != nil {
		t.Fatal(err)
	}
	g := newOSVFixture(t)
	osvWriteEco(t, g.in, "npm", osvZip(t, map[string]string{"A.json": `{"id":"A"}`}, osvT0), nil)
	g.state = f.state
	if _, err := buildOSVExport(g.opts(osvT0, 1)); err == nil || !strings.Contains(err.Error(), "belongs to security.osv_os_export") {
		t.Fatalf("err = %v", err)
	}
}

// TestOSVOSExportVerb runs the verb end to end through run(), with a key
// file the tree does not pin.
func TestOSVOSExportVerb(t *testing.T) {
	root := t.TempDir()
	_, keyPath, err := generateKeypairNamed(filepath.Join(root, "key"), contentFeedKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	in, state, outDir := filepath.Join(root, "in"), filepath.Join(root, "state"), filepath.Join(root, "out")
	writeOSInputs(t, in, osDebian(), osRedHat())
	stdout, err := os.Create(filepath.Join(root, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdout.Close() }()
	args := []string{"osvosexport", "-key", keyPath, "-in", in, "-state", state, "-out", outDir}
	if err := run(args, stdout); err == nil || !strings.Contains(err.Error(), "not among the content-feed keys") {
		t.Fatalf("an unpinned key must be refused: %v", err)
	}
	if err := run(append(args, "-allow-unpinned-key"), stdout); err != nil {
		t.Fatal(err)
	}
	printed, _ := os.ReadFile(stdout.Name())
	if !strings.Contains(string(printed), "Debian-12: base rebased (new), delta 0 entries, 0 dropped, 2 records") {
		t.Errorf("summary:\n%s", printed)
	}
	if _, err := os.Stat(filepath.Join(outDir, string(content.OSVOSExport), "manifest.json")); err != nil {
		t.Fatal(err)
	}
}

// TestOSVOSSetNamesEveryRelease: every row of the release table has the
// artifact names the node reads, and only those.
func TestOSVOSSetNamesEveryRelease(t *testing.T) {
	for _, r := range osvdb.OSReleases {
		if osvOSSet.baseName(r.Artifact) != r.ExportArtifact() || osvOSSet.deltaName(r.Artifact) != r.DeltaArtifact() {
			t.Errorf("%s: %q %q", r.Artifact, osvOSSet.baseName(r.Artifact), osvOSSet.deltaName(r.Artifact))
		}
	}
	if osvOSSet.baseName("npm") != "" {
		t.Error("a key outside the release table must have no artifact name")
	}
}
