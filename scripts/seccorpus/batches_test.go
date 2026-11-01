package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/seccorpus"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
)

// packetsFixture writes a corpus with 5 results of go.sql-string-concat
// and 3 of js.shell-interpolation, then runs packets with a cap of 2,
// go.sql-string-concat in full and batches of 2: 7 findings, 4 batches.
func packetsFixture(t *testing.T) (p paths, pk string) {
	t.Helper()
	dir := t.TempDir()
	p = paths{corpus: filepath.Join(dir, "corpus"), pack: filepath.Join(dir, "pack")}
	for _, d := range []string{p.corpus, p.pack} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	floor, err := secrulepack.Floor()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.pack, secrulepack.ManifestFile), floor.Files()[secrulepack.ManifestFile], 0o600); err != nil {
		t.Fatal(err)
	}
	copyCommitted(t, p, labellersFile)
	copyCommitted(t, p, "repos.tsv")
	var cands []seccorpus.Finding
	for rule, n := range map[string]int{"go.sql-string-concat": 5, "js.shell-interpolation": 3} {
		for i := 1; i <= n; i++ {
			cands = append(cands, seccorpus.Finding{Repo: "https://github.com/o/r", Commit: strings.Repeat("c", 40), Path: "src/" + rule, Line: i, Rule: rule})
		}
	}
	if err := writeJSONL(p.file("candidates.jsonl"), cands); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.file("counts.tsv"), []byte("rule\tresults\texcluded\trepositories\ngo.sql-string-concat\t5\t0\t1\njs.shell-interpolation\t3\t0\t1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pk = filepath.Join(dir, "packets")
	if err := writePackets(p, filepath.Join(dir, "clones"), pk, 2, 1, 2, []string{"go.sql-string-concat"}); err != nil {
		t.Fatal(err)
	}
	return p, pk
}

// fillManifest fills the skeleton: reviewer ids per side and one run agent
// per batch per side.
func fillManifest(t *testing.T, p paths, edit func(row batchRow) batchRow) {
	t.Helper()
	rows, err := readBatches(p)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString(batchesHeader + "\n")
	for _, r := range rows {
		r.Reviewer = "agent:sec-g4-reviewer-" + r.Side
		r.RunAgent = "agent:run-" + r.Batch + "-" + r.Side
		if edit != nil {
			r = edit(r)
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n", r.Batch, r.Side, r.Reviewer, r.RunAgent, r.Packets, r.IDsSHA, r.Isolation)
	}
	if err := os.WriteFile(p.file(batchesFile), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeLabels writes one reviewer's per-batch label files, every finding
// labelled true.
func writeLabels(t *testing.T, pk string) string {
	t.Helper()
	in := filepath.Join(t.TempDir(), "labels")
	if err := os.MkdirAll(in, 0o700); err != nil {
		t.Fatal(err)
	}
	batches, err := packetBatches(pk)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range batches {
		ids, err := packetIDs(pk, b)
		if err != nil {
			t.Fatal(err)
		}
		var rows []reviewerLabel
		for _, id := range ids {
			rows = append(rows, reviewerLabel{ID: id, Verdict: seccorpus.TruePositive, Reason: "input_reaches_sink"})
		}
		if err := writeJSONL(filepath.Join(in, b+".jsonl"), rows); err != nil {
			t.Fatal(err)
		}
	}
	return in
}

// TestPacketsLabelsInFull is milestone 2 of lane SEC-G4 (P-077): -full
// labels a rule's every result, the others keep the cap, the labelset
// records the list, and packets writes the manifest's skeleton.
func TestPacketsLabelsInFull(t *testing.T) {
	p, pk := packetsFixture(t)
	h, cands, err := readLabelset(p.file("labelset.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	per := map[string]int{}
	for _, f := range cands {
		per[f.Rule]++
	}
	if h.Labelset != labelsetSchema || h.Cap != 2 || h.LabelSeed != 1 || strings.Join(h.Full, ",") != "go.sql-string-concat" {
		t.Fatalf("labelset header %+v", h)
	}
	if per["go.sql-string-concat"] != 5 || per["js.shell-interpolation"] != 2 {
		t.Fatalf("labelled %v, want all 5 and 2 of 3", per)
	}
	rows, err := readBatches(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 8 {
		t.Fatalf("%d manifest rows, want 4 batches by 2 sides", len(rows))
	}
	for _, r := range rows {
		if r.Reviewer != unset || r.RunAgent != unset {
			t.Fatalf("the skeleton row %+v is filled", r)
		}
		ids, err := packetIDs(pk, r.Batch)
		if err != nil || len(ids) != r.Packets || idsDigest(ids) != r.IDsSHA {
			t.Fatalf("row %+v does not state its packets (%v)", r, err)
		}
	}
	b, _ := os.ReadFile(p.file(batchesFile))
	if strings.Contains(string(b), "src/") || strings.Contains(string(b), "github.com") {
		t.Fatal("the manifest carries content")
	}
	// A legacy labelset (lane SEC-G3's, no header) reads with no rule in full.
	legacy := filepath.Join(t.TempDir(), "labelset.jsonl")
	if err := writeJSONL(legacy, cands); err != nil {
		t.Fatal(err)
	}
	if h, c, err := readLabelset(legacy); err != nil || len(h.Full) != 0 || len(c) != len(cands) {
		t.Fatalf("legacy labelset: %+v %d %v", h, len(c), err)
	}
	for _, c := range []struct {
		name string
		cap  int
		full []string
	}{{"an unknown rule in full", 2, []string{"go.nope"}}, {"cap 0", 0, nil}} {
		if err := writePackets(p, t.TempDir(), filepath.Join(t.TempDir(), "x"), 2, 1, c.cap, c.full); err == nil {
			t.Errorf("packets accepted %s", c.name)
		}
	}
}

// TestLabelsNeedTheManifest: a label file is imported only for a batch the
// manifest lists for its side, filled in, with the stated packet ids.
func TestLabelsNeedTheManifest(t *testing.T) {
	type tc struct {
		name  string
		edit  func(batchRow) batchRow
		files func(t *testing.T, in string)
		in    func(in string) string
		want  string
	}
	extra := func(t *testing.T, in string) {
		if err := os.WriteFile(filepath.Join(in, "batch-009.jsonl"), []byte(`{"id":"p00001","verdict":"true_positive","reason":"input_reaches_sink"}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	missing := func(t *testing.T, in string) { _ = os.Remove(filepath.Join(in, "batch-002.jsonl")) }
	cases := []tc{
		{name: "the filled manifest", want: ""},
		{name: "the skeleton, unfilled", edit: func(r batchRow) batchRow { r.Reviewer, r.RunAgent = unset, unset; return r }, want: "is prepared but not filled in"},
		{name: "side b prepared, side a filled (lane SEC-G5)", edit: func(r batchRow) batchRow {
			if r.Side == "b" {
				r.Reviewer, r.RunAgent = unset, unset
			}
			return r
		}, want: ""},
		{name: "a half-filled row", edit: func(r batchRow) batchRow {
			if r.Side == "b" {
				r.RunAgent = unset
			}
			return r
		}, want: "no reviewer or run agent"},
		{name: "a label file whose batch is not in the manifest", files: extra, want: "is not in batches.tsv"},
		{name: "a batch with no label file", files: missing, want: "has no label file"},
		{name: "a stated digest that is not the packets'", edit: func(r batchRow) batchRow {
			if r.Batch == "batch-001" {
				r.IDsSHA = strings.Repeat("0", 64)
			}
			return r
		}, want: "the manifest states"},
		{name: "one run agent for two batches", edit: func(r batchRow) batchRow { r.RunAgent = "agent:run-shared-" + r.Side; return r }, want: "one fresh agent per batch per side"},
		{name: "a run agent that is a labeller", edit: func(r batchRow) batchRow {
			if r.Batch == "batch-001" && r.Side == "a" {
				r.RunAgent = "agent:sec-g3-reviewer-b"
			}
			return r
		}, want: "run agent"},
		{name: "a reviewer not in labellers.tsv", edit: func(r batchRow) batchRow { r.Reviewer = "agent:someone-" + r.Side; return r }, want: "is not in labellers.tsv"},
		{name: "one reviewer on both sides", edit: func(r batchRow) batchRow { r.Reviewer = "agent:sec-g4-reviewer-a"; return r }, want: "both sides"},
		{name: "a single file for -in", in: func(in string) string { return filepath.Join(in, "batch-001.jsonl") }, want: "directory"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, pk := packetsFixture(t)
			fillManifest(t, p, c.edit)
			in := writeLabels(t, pk)
			if c.files != nil {
				c.files(t, in)
			}
			arg := in
			if c.in != nil {
				arg = c.in(in)
			}
			err := importLabels(p, pk, "a", arg)
			if c.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				l, err := readJSONL[seccorpus.LabelRecord](p.file("labels-a.jsonl"))
				if err != nil || len(l) != 7 {
					t.Fatalf("labels-a.jsonl: %d rows, %v", len(l), err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("importLabels = %v, want an error naming %q", err, c.want)
			}
		})
	}
}

// TestMeasureRefusesAPartialFullRule: a rule the labelset names in full
// must have every result labelled, or measure refuses (P-077).
func TestMeasureRefusesAPartialFullRule(t *testing.T) {
	p, pk := packetsFixture(t)
	fillManifest(t, p, nil)
	for _, side := range []string{"a", "b"} {
		if err := importLabels(p, pk, side, writeLabels(t, pk)); err != nil {
			t.Fatal(err)
		}
	}
	if err := measure(p); err != nil {
		t.Fatal(err)
	}
	if r := rule(manifest(t, p), "go.sql-string-concat"); r.Precision == nil || !r.Precision.FullyLabelled() {
		t.Fatalf("go.sql-string-concat in full: %+v", r.Precision)
	}
	if r := rule(manifest(t, p), "js.shell-interpolation"); r.Precision == nil || r.Precision.FullyLabelled() {
		t.Fatalf("js.shell-interpolation capped: %+v", r.Precision)
	}
	// counts.tsv now says go.sql-string-concat had 6 results: 5 labelled.
	if err := os.WriteFile(p.file("counts.tsv"), []byte("rule\tresults\texcluded\trepositories\ngo.sql-string-concat\t6\t0\t1\njs.shell-interpolation\t3\t0\t1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := measure(p); err == nil || !strings.Contains(err.Error(), "labelled in full") {
		t.Fatalf("measure = %v, want a refusal of the partial full rule", err)
	}
}

// TestBatchesIsolation: the isolation column (lane SEC-G4 audit finding 1)
// is unset or "attested"; the legacy column line reads as unset; only a
// manifest whose every second-pass row is attested marks the second pass
// attested isolated.
func TestBatchesIsolation(t *testing.T) {
	p, _ := packetsFixture(t)
	write := func(header string, rows ...string) {
		t.Helper()
		if err := os.WriteFile(p.file(batchesFile), []byte(header+"\n"+strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sha := strings.Repeat("a", 64)
	row := func(side, isolation string) string {
		return "batch-001\t" + side + "\tagent:r-" + side + "\tagent:run-" + side + "\t1\t" + sha + "\t" + isolation
	}
	cases := []struct {
		name     string
		header   string
		rows     []string
		attested bool
		err      string
	}{
		{"unset on both sides", batchesHeader, []string{row("a", "-"), row("b", "-")}, false, ""},
		{"the second pass attested", batchesHeader, []string{row("a", "-"), row("b", "attested")}, true, ""},
		{"only the first pass attested", batchesHeader, []string{row("a", "attested"), row("b", "-")}, false, ""},
		{"no second-pass row", batchesHeader, []string{row("a", "attested")}, false, ""},
		{"a value the harness never writes", batchesHeader, []string{row("a", "-"), row("b", "yes")}, false, "isolation"},
		{"six columns under the new header", batchesHeader, []string{"batch-001\tb\tagent:r\tagent:run\t1\t" + sha}, false, "7 columns"},
		{"the legacy column line reads as unset", batchesHeaderV1, []string{"batch-001\tb\tagent:r\tagent:run\t1\t" + sha}, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			write(c.header, c.rows...)
			rows, err := readBatches(p)
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("readBatches = %v, want an error naming %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := secondPassAttested(rows); got != c.attested {
				t.Fatalf("secondPassAttested = %v, want %v", got, c.attested)
			}
		})
	}
	// The committed manifest attests nothing.
	rows, err := readBatches(paths{corpus: "corpus"})
	if err != nil || len(rows) == 0 || secondPassAttested(rows) {
		t.Fatalf("committed batches.tsv: %d rows, attested %v, %v", len(rows), secondPassAttested(rows), err)
	}
}
