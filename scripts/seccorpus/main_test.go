package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/seccorpus"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
)

func TestOutside(t *testing.T) {
	root := t.TempDir()
	cases := map[string]bool{
		filepath.Join(root, "x"):       false,
		root:                           false,
		filepath.Join(root, "..", "y"): true,
		filepath.Dir(root):             true,
	}
	for dir, want := range cases {
		if got, err := outside(dir, root); err != nil || got != want {
			t.Errorf("outside(%s) = %v %v, want %v", dir, got, err, want)
		}
	}
}

func TestReadRepos(t *testing.T) {
	p := filepath.Join(t.TempDir(), "repos.tsv")
	c := strings.Repeat("a", 40)
	if err := os.WriteFile(p, []byte("# c\nhttps://github.com/o/r\t"+c+"\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := readRepos(p)
	if err != nil || len(rs) != 1 || rs[0].dir() != "o__r" {
		t.Fatalf("readRepos = %v %v", rs, err)
	}
	for _, bad := range []string{"https://github.com/o/r\tabc\n", "git@github.com:o/r\t" + c + "\n", "https://github.com/o/r " + c + "\n"} {
		_ = os.WriteFile(p, []byte(bad), 0o600)
		if _, err := readRepos(p); err == nil {
			t.Errorf("readRepos accepted %q", bad)
		}
	}
	// The committed corpus list reads, and holds this repository.
	committed, err := readRepos(filepath.Join("corpus", "repos.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	self := false
	for _, r := range committed {
		self = self || r.URL == selfURL
	}
	if len(committed) != 61 || !self {
		t.Fatalf("corpus/repos.tsv: %d repositories, this one listed %v (want 50 JSP-7, 10 Java and C# from SEC-G5, plus this one)", len(committed), self)
	}
}

func TestExcerptIsBounded(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 100; i++ {
		if i == 50 {
			b.WriteString(strings.Repeat("x", 1000) + "\n")
			continue
		}
		b.WriteString("line\n")
	}
	p := filepath.Join(t.TempDir(), "f.py")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	ex, err := excerpt(p, 50)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(ex, "\n"), "\n")
	if len(lines) != excerptBefore+excerptAfter+1 || !strings.HasPrefix(lines[excerptBefore], ">>   50| ") || !strings.HasSuffix(lines[excerptBefore], "[cut]") {
		t.Fatalf("excerpt of %d lines: %q", len(lines), lines[excerptBefore])
	}
}

// corpusFixture is a temporary corpus and pack: three rules, labelled so
// that only go.sql-string-concat clears the bar.
func corpusFixture(t *testing.T) paths {
	t.Helper()
	dir := t.TempDir()
	p := paths{corpus: filepath.Join(dir, "corpus"), pack: filepath.Join(dir, "pack")}
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
	var cands []seccorpus.Finding
	var labels = map[string][]seccorpus.LabelRecord{}
	add := func(rule string, n, disagree int) {
		for i := 1; i <= n; i++ {
			f := seccorpus.Finding{Repo: "https://github.com/o/r", Commit: strings.Repeat("b", 40), Path: "src/" + rule, Line: i, Rule: rule}
			cands = append(cands, f)
			vb := seccorpus.TruePositive
			reason := seccorpus.Reason("input_reaches_sink")
			if i <= disagree {
				vb, reason = seccorpus.FalsePositive, "constant_or_internal"
			}
			labels["a"] = append(labels["a"], seccorpus.LabelRecord{Finding: f, Reviewer: "a", Verdict: seccorpus.TruePositive, Reason: "input_reaches_sink"})
			labels["b"] = append(labels["b"], seccorpus.LabelRecord{Finding: f, Reviewer: "b", Verdict: vb, Reason: reason})
		}
	}
	add("go.sql-string-concat", 20, 0)   // 20 of 20, every result: lower 0.839
	add("go.shell-interpolation", 20, 1) // 19 of 20: lower 0.764
	add("js.sql-string-concat", 5, 0)    // 5 of 5: lower 0.566
	add("js.shell-interpolation", 20, 0) // 20 of 20 but 90 results (capped): never blocks
	if err := writeLabelset(p.file("labelset.jsonl"), labelsetHeader{Cap: 20, LabelSeed: 1, Full: []string{"go.sql-string-concat"}}, cands); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.file("counts.tsv"), []byte("rule\tresults\texcluded\trepositories\ngo.sql-string-concat\t20\t0\t1\ngo.shell-interpolation\t90\t0\t1\njs.sql-string-concat\t5\t0\t1\njs.shell-interpolation\t90\t0\t1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	copyCommitted(t, p, labellersFile)
	if err := os.WriteFile(p.file(batchesFile), []byte(batchesHeader+"\nbatch-001\ta\tagent:sec-g4-reviewer-a\tagent:run-a1\t1\t"+idsDigest([]string{"p00001"})+"\t-\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for r, l := range labels {
		if err := writeJSONL(p.file("labels-"+r+".jsonl"), l); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// copyCommitted copies a committed corpus file into the fixture.
func copyCommitted(t *testing.T, p paths, name string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("corpus", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.file(name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func manifest(t *testing.T, p paths) secrulepack.Manifest {
	t.Helper()
	var m secrulepack.Manifest
	if err := readJSON(filepath.Join(p.pack, secrulepack.ManifestFile), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func rule(m secrulepack.Manifest, id string) secrulepack.Rule {
	for _, r := range m.Rules {
		if r.ID == id {
			return r
		}
	}
	return secrulepack.Rule{}
}

// answer fills the sample's operator column.
func answer(t *testing.T, p paths, fill func(line string) string) {
	t.Helper()
	b, err := os.ReadFile(p.file("operator-sample.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	ls := strings.Split(string(b), "\n")
	for i, l := range ls {
		if l != "" && !strings.HasPrefix(l, "#") && l != sampleHeader {
			ls[i] = l + fill(l)
		}
	}
	if err := os.WriteFile(p.file("operator-sample.tsv"), []byte(strings.Join(ls, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestMeasureSampleRecord is milestone 5's bar end to end: measure records
// figures with blocking off; the sample covers only the rule that cleared
// 0.8; record turns blocking on for exactly that rule after a clean
// spot-check, and for none after an overturned true positive.
func TestMeasureSampleRecord(t *testing.T) {
	for _, overturn := range []bool{false, true} {
		p := corpusFixture(t)
		if err := measure(p); err != nil {
			t.Fatal(err)
		}
		m := manifest(t, p)
		for _, r := range m.Rules {
			if r.Blocking || r.OperatorSpotcheck != nil {
				t.Fatalf("%s blocks after measure", r.ID)
			}
		}
		if r := rule(m, "go.sql-string-concat"); r.Precision == nil || r.Precision.Denominator != 20 || !(r.Precision.WilsonLower >= 0.8) {
			t.Fatalf("go.sql-string-concat figure %+v", r.Precision)
		}
		if r := rule(m, "go.shell-interpolation"); r.Precision == nil || r.Precision.ReviewerDisagreements != 1 || r.Precision.WilsonLower >= 0.8 || r.Precision.Results != 90 || r.Precision.Denominator != 20 {
			t.Fatalf("go.shell-interpolation figure %+v", r.Precision)
		}
		if err := record(p, "2026-10-22", independent); err == nil {
			t.Fatal("record ran before a sample existed")
		}
		if err := drawSample(p, 1, 5, 150, "auto"); err != nil {
			t.Fatal(err)
		}
		if err := record(p, "2026-10-22", independent); err == nil {
			t.Fatal("record accepted an unanswered sample")
		}
		first := true
		answer(t, p, func(string) string {
			if overturn && first {
				first = false
				return "overturn"
			}
			return "agree"
		})
		if err := record(p, "2026-10-22", independent); err != nil {
			t.Fatal(err)
		}
		m = manifest(t, p)
		sql := rule(m, "go.sql-string-concat")
		// 20 both-true results: half of them (10), which is also the
		// minimum a blocking rule needs.
		if s := sql.OperatorSpotcheck; s == nil || s.SampleSize != 10 || s.Reviewer != independent ||
			s.FiguresDigest != secrulepack.PrecisionDigest(*sql.Precision) || sql.Blocking == overturn {
			t.Fatalf("overturn=%v: go.sql-string-concat spot-check %+v blocking %v", overturn, sql.OperatorSpotcheck, sql.Blocking)
		}
		for _, id := range []string{"go.shell-interpolation", "js.sql-string-concat"} {
			if r := rule(m, id); r.Blocking || r.OperatorSpotcheck != nil {
				t.Fatalf("%s: blocking %v, spot-check %+v (under the bar)", id, r.Blocking, r.OperatorSpotcheck)
			}
		}
		// P-077: 20 of 20 clears the bound, but 20 labelled of 90 results is
		// a capped figure: spot-checked, never blocking.
		if r := rule(m, "js.shell-interpolation"); r.Blocking || r.OperatorSpotcheck == nil || r.Precision.FullyLabelled() || r.Precision.RecomputedLower() < secrulepack.BlockingLowerBound {
			t.Fatalf("js.shell-interpolation: blocking %v, spot-check %+v, figure %+v (capped, must not block)", r.Blocking, r.OperatorSpotcheck, r.Precision)
		}
		floor, _ := secrulepack.Floor()
		v := secrulepack.ParseVersion(floor.Version())
		if want := fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]+1); m.Version != want {
			t.Fatalf("version %s after record, want %s (the floor's patch raised)", m.Version, want)
		}
	}
}

func TestRecordRefusesAnEditedSample(t *testing.T) {
	p := corpusFixture(t)
	if err := measure(p); err != nil {
		t.Fatal(err)
	}
	if err := drawSample(p, 1, 5, 150, "auto"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p.file("operator-sample.tsv"))
	// Flip one reviewer's label in the sample file: record must refuse.
	edited := strings.Replace(string(b), "\ttrue_positive\ttrue_positive\ttrue_positive\t", "\tfalse_positive\ttrue_positive\tfalse_positive\t", 1)
	_ = os.WriteFile(p.file("operator-sample.tsv"), []byte(edited), 0o600)
	answer(t, p, func(string) string { return "agree" })
	before, _ := os.ReadFile(filepath.Join(p.pack, secrulepack.ManifestFile))
	if err := record(p, "2026-10-22", independent); err == nil || !strings.Contains(err.Error(), "differs from the seeded draw") {
		t.Fatalf("record = %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(p.pack, secrulepack.ManifestFile))
	if string(before) != string(after) {
		t.Fatal("a refused record changed pack.json")
	}
}

// independent is a spot-checker that labelled none of the corpus.
const independent = "agent:spotcheck-independent-1"

// TestRecordRefusesASampleThatIsNotTheDraw is audit finding 1: record
// re-draws the sample from the seed in the file's header and refuses a
// deleted, an added, a swapped row or an edited draw line, so a rule cannot
// be spot-checked on hand-picked rows.
func TestRecordRefusesASampleThatIsNotTheDraw(t *testing.T) {
	// unsampled renders a labelset row of go.sql-string-concat that the
	// draw did not pick, in the sample's own row format.
	unsampled := func(t *testing.T, p paths, text string) string {
		t.Helper()
		_, cands, _ := readLabelset(p.file("labelset.jsonl"))
		for _, f := range cands {
			l := strings.Join([]string{f.Rule, f.Repo, f.Commit, f.Path, strconv.Itoa(f.Line), "true_positive", "true_positive", "true_positive"}, "\t") + "\t"
			if f.Rule == "go.sql-string-concat" && !strings.Contains(text, l) {
				return l + "agree"
			}
		}
		t.Fatal("every go.sql-string-concat row was sampled")
		return ""
	}
	cases := []struct {
		name string
		edit func(t *testing.T, p paths, lines []string) []string
	}{
		{"a deleted row", func(t *testing.T, p paths, ls []string) []string {
			return append(append([]string(nil), ls[:len(ls)-2]...), ls[len(ls)-1])
		}},
		{"an added row", func(t *testing.T, p paths, ls []string) []string {
			return append(ls[:len(ls)-1:len(ls)-1], unsampled(t, p, strings.Join(ls, "\n")), ls[len(ls)-1])
		}},
		{"a swapped row", func(t *testing.T, p paths, ls []string) []string {
			out := append([]string(nil), ls...)
			out[len(out)-2] = unsampled(t, p, strings.Join(ls, "\n"))
			return out
		}},
		{"an edited draw line", func(t *testing.T, p paths, ls []string) []string {
			out := append([]string(nil), ls...)
			for i, l := range out {
				if strings.HasPrefix(l, "# draw: ") {
					out[i] = strings.Replace(l, "per 5", "per 4", 1)
				}
			}
			return out
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := corpusFixture(t)
			if err := measure(p); err != nil {
				t.Fatal(err)
			}
			if err := drawSample(p, 1, 5, 150, "auto"); err != nil {
				t.Fatal(err)
			}
			answer(t, p, func(string) string { return "agree" })
			b, _ := os.ReadFile(p.file("operator-sample.tsv"))
			// The file ends in a newline, so the last element is "".
			ls := c.edit(t, p, strings.Split(string(b), "\n"))
			_ = os.WriteFile(p.file("operator-sample.tsv"), []byte(strings.Join(ls, "\n")), 0o600)
			before, _ := os.ReadFile(filepath.Join(p.pack, secrulepack.ManifestFile))
			if err := record(p, "2026-10-22", independent); err == nil || !strings.Contains(err.Error(), "differs from the seeded draw") {
				t.Fatalf("record = %v", err)
			}
			after, _ := os.ReadFile(filepath.Join(p.pack, secrulepack.ManifestFile))
			if string(before) != string(after) {
				t.Fatal("a refused record changed pack.json")
			}
		})
	}
}

// TestRecordSpotchecker is ruling P-064: the spot-check is answered by an
// independent AI reviewer or by the operator, never by a labeller.
func TestRecordSpotchecker(t *testing.T) {
	labellers, err := readLabellers(paths{corpus: "corpus"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"agent:sec-g3-reviewer-a", "agent:sec-g3-reviewer-b", "agent:sec-g4-reviewer-a", "agent:sec-g4-reviewer-b", "agent:sec-g5-reviewer-a"} {
		if !strings.Contains(strings.Join(labellers, ","), want) {
			t.Errorf("corpus/labellers.tsv does not list %s", want)
		}
	}
	type tc struct {
		reviewer string
		ok       bool
	}
	cases := []tc{
		{"agent:" + strings.ToUpper(strings.TrimPrefix(labellers[1], "agent:")), false},
		// A run agent of the batch manifest labelled a batch.
		{"agent:run-a1", false},
		{"", false},
		{"agent:", false},
		{"someone", false},
		{"agent:has space", false},
		{independent, true},
		{secrulepack.SpotcheckerOperator, true},
	}
	for _, l := range labellers {
		cases = append(cases, tc{l, false})
	}
	for _, c := range cases {
		p := corpusFixture(t)
		if err := measure(p); err != nil {
			t.Fatal(err)
		}
		if err := drawSample(p, 1, 5, 150, "auto"); err != nil {
			t.Fatal(err)
		}
		answer(t, p, func(string) string { return "agree" })
		err := record(p, "2026-10-22", c.reviewer)
		if (err == nil) != c.ok {
			t.Fatalf("record -reviewer %q = %v, want ok %v", c.reviewer, err, c.ok)
		}
		if c.ok {
			if s := rule(manifest(t, p), "go.sql-string-concat").OperatorSpotcheck; s == nil || s.Reviewer != c.reviewer {
				t.Fatalf("-reviewer %q stored %+v", c.reviewer, s)
			}
		}
	}
	b, _ := os.ReadFile(filepath.Join("corpus", "operator-sample.tsv"))
	for _, l := range labellers {
		if !strings.Contains(string(b), l) {
			t.Errorf("the committed sample's header does not name the labeller %s", l)
		}
	}
}

// TestRecordRefusesATooSmallSpotcheck: a rule's spot-check under
// Precision.MinSpotcheck (10, or every true positive when fewer) is refused.
func TestRecordRefusesATooSmallSpotcheck(t *testing.T) {
	cleared := secrulepack.Rule{ID: "go.x", Precision: &secrulepack.Precision{Figure: 1, WilsonLower: secrulepack.WilsonLower(20, 20), Denominator: 20}}
	few := secrulepack.Rule{ID: "go.y", Precision: &secrulepack.Precision{Figure: 0.1, WilsonLower: secrulepack.WilsonLower(3, 30), Denominator: 30}}
	for _, c := range []struct {
		r    secrulepack.Rule
		size int
		ok   bool
	}{
		{cleared, 5, false}, {cleared, 9, false}, {cleared, 10, true},
		{few, 2, false}, {few, 3, true},
		{secrulepack.Rule{ID: "go.z"}, 10, false},
	} {
		err := checkSpotcheckSize(c.r, seccorpus.Tally{Rule: c.r.ID, SampleSize: c.size})
		if (err == nil) != c.ok {
			t.Errorf("%s with %d answers: %v, want ok %v", c.r.ID, c.size, err, c.ok)
		}
	}
}

// TestCommittedSampleIsItsDraw pins the committed sample to its draw line:
// re-drawing from the committed labels with the header's parameters gives
// the file byte for byte (its operator column empty).
func TestCommittedSampleIsItsDraw(t *testing.T) {
	p := paths{corpus: "corpus", pack: filepath.Join("..", "..", "internal", "secrulepack", "floor", "observer-code")}
	b, err := os.ReadFile(p.file("operator-sample.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	if samplePending(b) {
		// The second pass is pending (lane SEC-G5): no sample, and the
		// committed labels measure only with -second-pass-pending.
		if _, _, _, err := loadMeasurement(p); err == nil {
			t.Fatal("the sample says the second pass is pending, but the committed labels are complete")
		}
		if _, _, _, err := loadMeasurementWith(p, seccorpus.MeasureOptions{SecondPassPending: true}); err != nil {
			t.Fatalf("the pending measurement does not load: %v", err)
		}
		return
	}
	seed, per, max, scope, err := readDraw(string(b))
	if err != nil {
		t.Fatal(err)
	}
	want, _, err := renderSample(p, seed, per, max, scope)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != want {
		t.Fatal("corpus/operator-sample.tsv is not its seeded draw: run go run ./scripts/seccorpus sample")
	}
	rows, err := readSample(p)
	if err != nil {
		t.Fatal(err)
	}
	// Every reviewer disagreement and at least half the both-true findings
	// of every sampled rule are in the sample (audit finding 4).
	_, cands, labels, err := loadMeasurement(p)
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]bool{}
	sampled := map[string]bool{}
	for _, r := range rows {
		in[r.Key()] = true
		sampled[r.Rule] = true
	}
	va, vb := map[string]seccorpus.Verdict{}, map[string]seccorpus.Verdict{}
	for _, l := range labels {
		if l.Reviewer == seccorpus.ReviewerA {
			va[l.Key()] = l.Verdict
		} else {
			vb[l.Key()] = l.Verdict
		}
	}
	bothTrue, bothTrueIn := map[string]int{}, map[string]int{}
	for _, f := range cands {
		if !sampled[f.Rule] {
			continue
		}
		k := f.Key()
		if va[k] != vb[k] && !in[k] {
			t.Errorf("disagreement %s is not in the sample", k)
		}
		if va[k] == seccorpus.TruePositive && vb[k] == seccorpus.TruePositive {
			bothTrue[f.Rule]++
			if in[k] {
				bothTrueIn[f.Rule]++
			}
		}
	}
	for r, n := range bothTrue {
		if 2*bothTrueIn[r] < n {
			t.Errorf("%s: %d of %d both-true findings sampled (want at least half)", r, bothTrueIn[r], n)
		}
	}
}

func TestMeasureRefusesIncompleteLabels(t *testing.T) {
	p := corpusFixture(t)
	l, _ := readJSONL[seccorpus.LabelRecord](p.file("labels-b.jsonl"))
	_ = writeJSONL(p.file("labels-b.jsonl"), l[1:])
	before, _ := os.ReadFile(filepath.Join(p.pack, secrulepack.ManifestFile))
	if err := measure(p); err == nil {
		t.Fatal("measure accepted a missing label")
	}
	after, _ := os.ReadFile(filepath.Join(p.pack, secrulepack.ManifestFile))
	if string(before) != string(after) {
		t.Fatal("a refused measure changed pack.json")
	}
}

func TestSamePrecision(t *testing.T) {
	k1, k2 := 0.5, 0.5
	a := &secrulepack.Precision{Figure: 1, Denominator: 3, Kappa: &k1}
	b := &secrulepack.Precision{Figure: 1, Denominator: 3, Kappa: &k2}
	if !samePrecision(a, b) || samePrecision(a, nil) || samePrecision(a, &secrulepack.Precision{Figure: 1, Denominator: 3}) {
		t.Fatal("samePrecision")
	}
}

// TestPrecisionDocTableIsCurrent is the drift gate of the generated table
// in docs/code-rules-precision.md (regenerate: go run ./scripts/seccorpus
// table, from the repository root).
func TestPrecisionDocTableIsCurrent(t *testing.T) {
	p := paths{corpus: "corpus", pack: filepath.Join("..", "..", "internal", "secrulepack", "floor", "observer-code")}
	var man secrulepack.Manifest
	if err := readJSON(filepath.Join(p.pack, secrulepack.ManifestFile), &man); err != nil {
		t.Fatal(err)
	}
	c, err := counts(p)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join("..", "..", docPath))
	if os.IsNotExist(err) {
		t.Skip("docs/ is private-only; the public repository has no precision doc")
	}
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), renderTable(man, c)) {
		t.Fatal("docs/code-rules-precision.md's table is stale: run go run ./scripts/seccorpus table")
	}
}

func TestPrivateOnlyPaths(t *testing.T) {
	got, err := privateOnlyPaths(filepath.Join("..", ".."))
	if os.IsNotExist(err) {
		t.Skip("scripts/release.sh is private-only")
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"docs", "marketing", "website", "model-pricing", "harness-gateway", "internal/orgserver"} {
		if !underAny(want+"/x", got) {
			t.Errorf("%s is not in PRIVATE_ONLY_PATHS as read: %v", want, got)
		}
	}
	if underAny("internal/secrulepack/pack.go", got) || underAny("docsx/a", got) {
		t.Error("a public path reads as private-only")
	}
}

func TestSampleScope(t *testing.T) {
	m := seccorpus.Measurement{Rules: []seccorpus.RuleFigures{{Rule: "a", WilsonLower: 0.85}, {Rule: "b", WilsonLower: 0.2}}}
	for _, c := range []struct {
		scope string
		want  []string
	}{{"auto", []string{"a"}}, {"cleared", []string{"a"}}, {"all", []string{"a", "b"}}} {
		got, _, err := sampleScope(m, c.scope)
		if err != nil || strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: %v %v", c.scope, got, err)
		}
	}
	none := seccorpus.Measurement{Rules: []seccorpus.RuleFigures{{Rule: "b", WilsonLower: 0.2}}}
	if got, _, _ := sampleScope(none, "auto"); len(got) != 1 {
		t.Errorf("auto with nothing cleared = %v, want every measured rule", got)
	}
	if got, _, _ := sampleScope(none, "cleared"); len(got) != 0 {
		t.Errorf("cleared with nothing cleared = %v", got)
	}
	if _, _, err := sampleScope(m, "x"); err == nil {
		t.Error("an unknown scope was accepted")
	}
}

// TestRecordOnTheCommittedCorpus runs the record step over a copy of the
// committed corpus and pack with every sample row answered agree: on this
// measurement no rule clears 0.8, so every sampled rule gets its
// spot-check record and none starts blocking.
func TestRecordOnTheCommittedCorpus(t *testing.T) {
	dir := t.TempDir()
	p := paths{corpus: filepath.Join(dir, "corpus"), pack: filepath.Join(dir, "pack")}
	for _, d := range []string{p.corpus, p.pack} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"labelset.jsonl", "labels-a.jsonl", "labels-b.jsonl", "counts.tsv", "operator-sample.tsv", labellersFile, batchesFile} {
		b, err := os.ReadFile(filepath.Join("corpus", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p.file(f), b, 0o600); err != nil {
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
	// The copy's pack takes its figures from the committed labels first, as
	// measure writes them (the committed pack.json may be between a rule
	// rewrite and its re-measurement).
	if b, _ := os.ReadFile(p.file("operator-sample.tsv")); samplePending(b) {
		// The second pass is pending (lane SEC-G5): a full measurement and
		// a record are refused; the pending measurement lets nothing block.
		if err := measure(p); err == nil {
			t.Fatal("measure accepted the committed labels with the second pass pending")
		}
		if err := measureWith(p, true); err != nil {
			t.Fatal(err)
		}
		if err := record(p, "2026-10-23", independent); err == nil {
			t.Fatal("record ran on a pending measurement")
		}
		for _, r := range manifest(t, p).Rules {
			if r.Blocking || r.MayBlock() || (r.Precision != nil && !r.Precision.OneEffectivePass()) {
				t.Fatalf("%s: a pending measurement may block (%+v)", r.ID, r.Precision)
			}
		}
		return
	}
	if err := measure(p); err != nil {
		t.Fatal(err)
	}
	answer(t, p, func(string) string { return "agree" })
	if err := record(p, "2026-10-22", independent); err != nil {
		t.Fatal(err)
	}
	// On this measurement no rule's lower bound clears 0.8, so the sample
	// covers every measured rule: each gets its spot-check record and none
	// starts blocking.
	m := manifest(t, p)
	checked, measured := 0, 0
	for _, r := range m.Rules {
		if r.Blocking {
			t.Errorf("%s blocks (lower bound %v)", r.ID, r.Precision.WilsonLower)
		}
		if r.Precision != nil {
			measured++
			if r.Precision.RecomputedLower() >= secrulepack.BlockingLowerBound {
				t.Errorf("%s clears the bound on the committed measurement; this test assumes none does", r.ID)
			}
		}
		if r.OperatorSpotcheck != nil {
			checked++
		}
	}
	if checked == 0 || checked != measured {
		t.Errorf("%d rules got a spot-check record, want the %d measured", checked, measured)
	}
}

// TestOneEffectivePassNeverBlocks is lane SEC-G4 audit finding 1 end to end:
// when the two passes agree on every verdict and reason code over 20 or
// more results, measure records them as one effective pass (no kappa, the
// one-pass method) and record leaves blocking off for a rule that clears
// the bar; only a second pass the manifest marks attested isolated lets
// it block.
func TestOneEffectivePassNeverBlocks(t *testing.T) {
	for _, attested := range []bool{false, true} {
		p := corpusFixture(t)
		// Side b now agrees with side a on every verdict and reason code.
		a, err := readJSONL[seccorpus.LabelRecord](p.file("labels-a.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		for i := range a {
			a[i].Reviewer = seccorpus.ReviewerB
		}
		if err := writeJSONL(p.file("labels-b.jsonl"), a); err != nil {
			t.Fatal(err)
		}
		isolation := "-"
		if attested {
			isolation = "attested"
		}
		manifestRows := batchesHeader + "\nbatch-001\ta\tagent:sec-g4-reviewer-a\tagent:run-a1\t1\t" + idsDigest([]string{"p00001"}) + "\t-\n" +
			"batch-001\tb\tagent:sec-g4-reviewer-b\tagent:run-b1\t1\t" + idsDigest([]string{"p00001"}) + "\t" + isolation + "\n"
		if err := os.WriteFile(p.file(batchesFile), []byte(manifestRows), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := measure(p); err != nil {
			t.Fatal(err)
		}
		sql := rule(manifest(t, p), "go.sql-string-concat")
		if sql.Precision == nil || sql.Precision.Passes == nil || sql.Precision.Passes.Results != 65 || sql.Precision.OneEffectivePass() == attested {
			t.Fatalf("attested=%v: go.sql-string-concat figure %+v", attested, sql.Precision)
		}
		if !attested && (sql.Precision.Kappa != nil || sql.Precision.Method != MethodOnePass) {
			t.Fatalf("one effective pass recorded a kappa or the two-pass method: %+v", sql.Precision)
		}
		if err := drawSample(p, 1, 5, 150, "auto"); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(p.file("operator-sample.tsv"))
		if !strings.Contains(string(b), "reason codes") || !strings.Contains(string(b), "ONE effective") {
			t.Fatal("the sample does not tell the spot-checker to check the reason codes of one effective pass")
		}
		answer(t, p, func(string) string { return "agree" })
		if err := record(p, "2026-10-22", independent); err != nil {
			t.Fatal(err)
		}
		if sql = rule(manifest(t, p), "go.sql-string-concat"); sql.Blocking != attested {
			t.Fatalf("attested=%v: go.sql-string-concat blocking %v", attested, sql.Blocking)
		}
	}
}

// TestRecordRefusesAFigureWithoutItsPasses: a figure stripped of its pass
// agreement (or carrying another) is refused by record, so removing
// "passes" from pack.json cannot let one effective pass block.
func TestRecordRefusesAFigureWithoutItsPasses(t *testing.T) {
	p := corpusFixture(t)
	if err := measure(p); err != nil {
		t.Fatal(err)
	}
	if err := drawSample(p, 1, 5, 150, "auto"); err != nil {
		t.Fatal(err)
	}
	answer(t, p, func(string) string { return "agree" })
	if err := editManifest(p, func(man *secrulepack.Manifest) error {
		for i := range man.Rules {
			if man.Rules[i].ID == "go.sql-string-concat" {
				man.Rules[i].Precision.Passes = nil
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := record(p, "2026-10-22", independent); err == nil || !strings.Contains(err.Error(), "passes") {
		t.Fatalf("record = %v, want a refusal naming the passes", err)
	}
}
