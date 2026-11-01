package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/seccorpus"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
)

// reviewerLabel is one line a reviewer writes: a packet id, a verdict and a
// reason code. Nothing else is accepted (no notes, so no source text).
type reviewerLabel struct {
	ID      string            `json:"id"`
	Verdict seccorpus.Verdict `json:"verdict"`
	Reason  seccorpus.Reason  `json:"reason"`
}

// importLabels turns one reviewer's labels into corpus/labels-<r>.jsonl.
// in is a directory of per-batch label files, batch-NNN.jsonl. Every
// label file's batch must be in the batch manifest (corpus/batches.tsv) for
// this side, with its reviewer and run agent filled in, and must label
// exactly that batch's packet ids, whose count and digest the manifest
// states; every batch of the packets directory must be labelled. A label
// file whose batch is not in the manifest is refused (lane SEC-G3 audit
// finding 6).
func importLabels(p paths, pk, reviewer, in string) error {
	if reviewer != seccorpus.ReviewerA && reviewer != seccorpus.ReviewerB {
		return fmt.Errorf("labels: -reviewer must be a or b")
	}
	if st, err := os.Stat(in); err != nil || !st.IsDir() {
		return fmt.Errorf("labels: -in must be a directory of per-batch label files (batch-NNN.jsonl)")
	}
	labellers, err := readLabellers(p)
	if err != nil {
		return err
	}
	rows, err := readBatches(p)
	if err != nil {
		return err
	}
	if err := checkBatches(rows, labellers); err != nil {
		return fmt.Errorf("labels: %w", err)
	}
	manifest := map[string]batchRow{}
	for _, r := range rows {
		if r.Side == reviewer {
			if prepared(r) {
				return fmt.Errorf("labels: %s side %s is prepared but not filled in (reviewer and run agent): fill it before importing", r.Batch, r.Side)
			}
			manifest[r.Batch] = r
		}
	}
	index, err := readJSONL[indexRow](filepath.Join(pk, "index.jsonl"))
	if err != nil {
		return err
	}
	byID := map[string]seccorpus.Finding{}
	for _, r := range index {
		byID[r.ID] = r.Finding
	}
	files, err := filepath.Glob(filepath.Join(in, "*.jsonl"))
	if err != nil {
		return err
	}
	inBatch := map[string]bool{}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".jsonl")
		if _, ok := manifest[name]; !ok {
			return fmt.Errorf("labels: %s: batch %s side %s is not in %s", f, name, reviewer, batchesFile)
		}
		inBatch[name] = true
	}
	batches, err := packetBatches(pk)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var out []seccorpus.LabelRecord
	for _, b := range batches {
		row, ok := manifest[b]
		switch {
		case !ok:
			return fmt.Errorf("labels: packet batch %s side %s is not in %s", b, reviewer, batchesFile)
		case !inBatch[b]:
			return fmt.Errorf("labels: packet batch %s has no label file %s.jsonl in %s", b, b, in)
		}
		ids, err := packetIDs(pk, b)
		if err != nil {
			return err
		}
		if len(ids) != row.Packets || idsDigest(ids) != row.IDsSHA {
			return fmt.Errorf("labels: batch %s: the packets hold %d ids (digest %s), the manifest states %d (%s)", b, len(ids), idsDigest(ids), row.Packets, row.IDsSHA)
		}
		want := map[string]bool{}
		for _, id := range ids {
			want[id] = true
		}
		raw, err := readJSONL[reviewerLabel](filepath.Join(in, b+".jsonl"))
		if err != nil {
			return err
		}
		got := 0
		for _, l := range raw {
			f, ok := byID[l.ID]
			switch {
			case !ok || !want[l.ID]:
				return fmt.Errorf("labels: %s: %s is not a packet id of the batch", b, l.ID)
			case seen[l.ID]:
				return fmt.Errorf("labels: %s is labelled twice", l.ID)
			}
			seen[l.ID] = true
			got++
			rec := seccorpus.LabelRecord{Finding: f, Reviewer: reviewer, Verdict: l.Verdict, Reason: l.Reason}
			if err := rec.Validate(); err != nil {
				return fmt.Errorf("labels: %s: %w", l.ID, err)
			}
			out = append(out, rec)
		}
		if got != len(ids) {
			return fmt.Errorf("labels: %s: %d of %d packet ids labelled", b, got, len(ids))
		}
	}
	if len(seen) != len(index) {
		return fmt.Errorf("labels: %d of %d packet ids labelled", len(seen), len(index))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return writeJSONL(p.file("labels-"+reviewer+".jsonl"), out)
}

// Corpus and Method are the strings every recorded figure carries.
const (
	CorpusName = "jsp7-50 + 10 Java and C# web applications (SEC-G5) + this repository at 1909234af (scripts/seccorpus/corpus/repos.tsv)"
	MethodName = "two independent agents (labellers.tsv, batches.tsv) label every selected result (all when at most 60, else a seeded sample of 60, and all of a rule in the labelset's full list; P-047, P-077, JSP-8); true only when both agree; ecosystem exclusions per internal/seccorpus"
	// MethodOnePass replaces MethodName when the two passes agree on every
	// verdict and reason code and the second is not attested isolated
	// (secrulepack.Passes.OneEffectivePass, lane SEC-G4 audit finding 1).
	// MethodPending replaces both while side-b labels are pending (measure
	// -second-pass-pending, lane SEC-G5).
	MethodPending = "ONE labelling pass so far: side a labelled every selected result (labellers.tsv, batches.tsv); the side-b batches are prepared in batches.tsv and await their attested relabel, so no rule may block; all results when at most 60, else a seeded sample of 60 (P-047, P-077, JSP-8); ecosystem exclusions per internal/seccorpus"
	MethodOnePass = "ONE effective labelling pass: two agent passes (labellers.tsv, batches.tsv) agreed on every verdict and reason code and were not shown independent, so no inter-rater agreement is claimed; every selected result labelled (P-047, P-077, JSP-8); ecosystem exclusions per internal/seccorpus"
)

// loadMeasurement measures the committed candidates and labels; every
// candidate needs both sides.
func loadMeasurement(p paths) (seccorpus.Measurement, []seccorpus.Finding, []seccorpus.LabelRecord, error) {
	return loadMeasurementWith(p, seccorpus.MeasureOptions{})
}

// loadMeasurementWith is loadMeasurement with options (measure
// -second-pass-pending).
func loadMeasurementWith(p paths, o seccorpus.MeasureOptions) (seccorpus.Measurement, []seccorpus.Finding, []seccorpus.LabelRecord, error) {
	_, cands, err := readLabelset(p.file("labelset.jsonl"))
	if err != nil {
		return seccorpus.Measurement{}, nil, nil, err
	}
	var labels []seccorpus.LabelRecord
	for _, r := range []string{seccorpus.ReviewerA, seccorpus.ReviewerB} {
		l, err := readJSONL[seccorpus.LabelRecord](p.file("labels-" + r + ".jsonl"))
		if err != nil {
			return seccorpus.Measurement{}, nil, nil, err
		}
		for _, x := range l {
			if x.Reviewer != r {
				return seccorpus.Measurement{}, nil, nil, fmt.Errorf("labels-%s.jsonl carries reviewer %q", r, x.Reviewer)
			}
		}
		labels = append(labels, l...)
	}
	m, err := seccorpus.MeasureWith(cands, labels, o)
	return m, cands, labels, err
}

func round(x float64, places int) float64 {
	s := math.Pow(10, float64(places))
	return math.Round(x*s) / s
}

// measure records each measured rule's figures in pack.json (blocking
// stays as it is: off until record) and the whole measurement in
// corpus/figures.json.
func measure(p paths) error { return measureWith(p, false) }

// measureWith is measure; secondPassPending accepts findings labelled by
// side a only while the side-b batches await their relabel (lane SEC-G5):
// the figures are then one pass (MethodPending) and no rule may block.
func measureWith(p paths, secondPassPending bool) error {
	m, _, _, err := loadMeasurementWith(p, seccorpus.MeasureOptions{SecondPassPending: secondPassPending})
	if err != nil {
		return err
	}
	figs := map[string]seccorpus.RuleFigures{}
	for _, r := range m.Rules {
		figs[r.Rule] = r
	}
	all, err := counts(p)
	if err != nil {
		return err
	}
	if err := checkFull(p, figs, all); err != nil {
		return err
	}
	passes, err := measurementPasses(p, m)
	if err != nil {
		return err
	}
	m.OneEffectivePass = passes.OneEffectivePass()
	method := MethodName
	switch {
	case m.Passes.SecondPassPending > 0:
		method = MethodPending
	case m.OneEffectivePass:
		method = MethodOnePass
	}
	err = editManifest(p, func(man *secrulepack.Manifest) error {
		for i := range man.Rules {
			r := &man.Rules[i]
			f, ok := figs[r.ID]
			if !ok {
				r.Precision = nil
				continue
			}
			prec := &secrulepack.Precision{
				Figure: round(f.Figure, 6), WilsonLower: round(f.WilsonLower, 6), Denominator: f.Labelled,
				Results: max(all[r.ID][0], f.Labelled), ReviewerDisagreements: f.Agreement.Disagreements(), Corpus: CorpusName, Method: method,
			}
			ps := passes
			prec.Passes = &ps
			// One effective pass: a kappa would present the agreement of two
			// passes not shown independent as inter-rater agreement.
			if f.KappaDefined && !m.OneEffectivePass {
				k := round(f.Kappa, 4)
				prec.Kappa = &k
			}
			if !samePrecision(r.Precision, prec) {
				// A new measurement invalidates an earlier spot-check.
				r.OperatorSpotcheck, r.Blocking = nil, false
			}
			r.Precision = prec
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := writeJSON(p.file("figures.json"), m); err != nil {
		return err
	}
	if m.Passes.SecondPassPending > 0 {
		fmt.Printf("%d labelled results have no side-b label yet: ONE pass, no rule may block on it\n", m.Passes.SecondPassPending)
		// The spot-check audits two passes; until side b runs there is no
		// sample to draw, and an older sample checked other figures.
		if err := writePendingSample(p, m.Passes.SecondPassPending); err != nil {
			return err
		}
	} else if m.OneEffectivePass {
		fmt.Printf("the two passes agree on every verdict and reason code (%d of %d) and the second pass is not attested isolated: ONE effective pass, no rule may block on it\n", passes.ReasonAgreements, passes.Results)
	}
	for _, r := range m.Rules {
		fmt.Printf("%-40s %4d labelled  %4d true  precision %.3f  lower %.3f  disagreements %d\n",
			r.Rule, r.Labelled, r.TruePositives, r.Figure, r.WilsonLower, r.Agreement.Disagreements())
	}
	return nil
}

// measurementPasses is the pass agreement a figure of measurement m
// records: m's counts and whether the batch manifest marks the second pass
// attested isolated.
func measurementPasses(p paths, m seccorpus.Measurement) (secrulepack.Passes, error) {
	rows, err := readBatches(p)
	if err != nil {
		return secrulepack.Passes{}, err
	}
	return secrulepack.Passes{
		Results: m.Passes.Results, VerdictAgreements: m.Passes.VerdictAgreements, ReasonAgreements: m.Passes.ReasonAgreements,
		SecondPassAttestedIsolated: secondPassAttested(rows), SecondPassPending: m.Passes.SecondPassPending,
	}, nil
}

// checkFull refuses a measurement in which a rule the labelset names in
// full has fewer labelled findings than results on the corpus (counts.tsv):
// a full figure must cover every result, or it could not block (P-077).
func checkFull(p paths, figs map[string]seccorpus.RuleFigures, all map[string][3]int) error {
	h, _, err := readLabelset(p.file("labelset.jsonl"))
	if err != nil {
		return err
	}
	for _, r := range h.Full {
		c, ok := all[r]
		if !ok {
			return fmt.Errorf("measure: %s is labelled in full but has no row in counts.tsv", r)
		}
		if got := figs[r].Labelled; got != c[0] {
			return fmt.Errorf("measure: %s is labelled in full, but %d of its %d results are labelled", r, got, c[0])
		}
	}
	return nil
}

// editManifest reads pack.json, applies edit, validates the whole pack and
// writes pack.json back; a pack the validator refuses is never written.
func editManifest(p paths, edit func(*secrulepack.Manifest) error) error {
	floor, err := secrulepack.Floor()
	if err != nil {
		return err
	}
	files := floor.Files()
	var man secrulepack.Manifest
	if err := readJSON(filepath.Join(p.pack, secrulepack.ManifestFile), &man); err != nil {
		return err
	}
	if err := edit(&man); err != nil {
		return err
	}
	b, err := jsonIndent(man)
	if err != nil {
		return err
	}
	files[secrulepack.ManifestFile] = b
	if _, err := secrulepack.Parse(files); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(p.pack, secrulepack.ManifestFile), b, 0o644)
}

// sampleHeader is the spot-check sample file's header line.
const sampleHeader = "rule\trepo\tcommit\tpath\tline\treviewer_a\treviewer_b\tjoint\treason_a\treason_b\toperator"

// drawLine is the sample file's machine-read header line: the parameters
// record re-draws the sample from.
const drawLine = "# draw: seed %d per %d max %d scope %s"

// sampleScope picks the rules the operator's sample covers: "cleared"
// is the rules whose Wilson lower bound clears the bar (the candidates for
// blocking), "all" every measured rule, and "auto" the cleared rules, or
// every measured rule when none cleared (so the spot-check still audits
// the reviewers' labels behind a "noisy" verdict).
func sampleScope(m seccorpus.Measurement, scope string) ([]string, string, error) {
	var cleared, all []string
	for _, r := range m.Rules {
		all = append(all, r.Rule)
		if r.WilsonLower >= secrulepack.BlockingLowerBound {
			cleared = append(cleared, r.Rule)
		}
	}
	switch {
	case scope == "cleared" || (scope == "auto" && len(cleared) > 0):
		return cleared, "the rules whose Wilson lower bound clears 0.8", nil
	case scope == "all" || scope == "auto":
		return all, "every measured rule (no rule cleared 0.8, so the sample audits the labels behind each noisy verdict)", nil
	}
	return nil, "", fmt.Errorf("sample: -scope %q (want auto, cleared or all)", scope)
}

// pendingSampleMarker starts the line of a sample file written while the
// second pass is pending: it holds no rows and no draw line, so record
// cannot run on it.
const pendingSampleMarker = "# pending: "

// writePendingSample replaces the sample with a header-only file naming
// why there is no sample yet and every labeller (lane SEC-G5).
func writePendingSample(p paths, pending int) error {
	labellers, err := readLabellers(p)
	if err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# The independent spot-check (P-047, P-064): NOT DRAWN.\n")
	fmt.Fprintf(&b, "%sthe second labelling pass (side b) is prepared in %s and has not run: %d labelled results carry side a only, so no rule may block and there is nothing to spot-check yet. Draw the sample with `seccorpus sample` once side b is labelled.\n", pendingSampleMarker, batchesFile, pending)
	fmt.Fprintf(&b, "# Labellers (never the spot-checker), every one in %s: %s.\n", labellersFile, strings.Join(labellers, ", "))
	return os.WriteFile(p.file("operator-sample.tsv"), []byte(b.String()), 0o644)
}

// samplePending reports whether the sample file is the pending placeholder.
func samplePending(b []byte) bool {
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, pendingSampleMarker) {
			return true
		}
	}
	return false
}

// renderSample draws the sample from the committed labels and renders the
// sample file with an empty operator column. record renders it again from
// the file's draw line and requires the answered file to match it.
func renderSample(p paths, seed uint64, per, max int, scope string) (string, int, error) {
	if per < 1 || max < 1 {
		return "", 0, fmt.Errorf("sample: -per and -max must be at least 1")
	}
	m, cands, labels, err := loadMeasurement(p)
	if err != nil {
		return "", 0, err
	}
	rules, words, err := sampleScope(m, scope)
	if err != nil {
		return "", 0, err
	}
	labellers, err := readLabellers(p)
	if err != nil {
		return "", 0, err
	}
	va, vb := map[string]seccorpus.Verdict{}, map[string]seccorpus.Verdict{}
	ra, rb := map[string]seccorpus.Reason{}, map[string]seccorpus.Reason{}
	for _, l := range labels {
		if l.Reviewer == seccorpus.ReviewerA {
			va[l.Key()], ra[l.Key()] = l.Verdict, l.Reason
		} else {
			vb[l.Key()], rb[l.Key()] = l.Verdict, l.Reason
		}
	}
	unanimous := secrulepack.Passes{Results: m.Passes.Results, VerdictAgreements: m.Passes.VerdictAgreements, ReasonAgreements: m.Passes.ReasonAgreements}.Unanimous()
	var rows []seccorpus.SampleRow
	for _, f := range cands {
		rows = append(rows, seccorpus.SampleRow{Finding: f, ReviewerA: va[f.Key()], ReviewerB: vb[f.Key()], Joint: seccorpus.Joint(va[f.Key()], vb[f.Key()])})
	}
	var sample []seccorpus.SampleRow
	if len(rules) > 0 {
		if sample, err = seccorpus.DrawSample(rows, rules, seed, per, max); err != nil {
			return "", 0, err
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# The independent spot-check (P-047, P-064): %d rows over %d rules, %s.\n", len(sample), len(rules), words)
	fmt.Fprintf(&b, "# Stratified per rule with one seed: every reviewer disagreement, at least half the both-true findings, at least %d rows\n", seccorpus.MinSpotcheckSample)
	fmt.Fprintf(&b, "# (or every both-true finding when fewer), then seeded rows up to %d per rule (%d in all before the required rows).\n", seccorpus.PerRule(len(rules), per, max), max)
	fmt.Fprintf(&b, drawLine+"\n", seed, per, max, scope)
	fmt.Fprintf(&b, "# Labellers (never the spot-checker), every one in %s: %s.\n", labellersFile, strings.Join(labellers, ", "))
	if unanimous {
		fmt.Fprintf(&b, "# The two labelling passes agree on every verdict and reason code (%d of %d): they count as ONE effective\n", m.Passes.ReasonAgreements, m.Passes.Results)
		b.WriteString("# pass, so check the reason codes as closely as the verdicts.\n")
	}
	b.WriteString("# The spot-checker (an independent AI reviewer or the operator) checks the joint verdict AND both reviewers'\n")
	b.WriteString("# reason codes, fills the operator column with agree, or overturn when the joint verdict is wrong or either\n")
	b.WriteString("# reason code does not fit the finding (counted like a wrong verdict), and changes nothing else, then runs:\n")
	b.WriteString("# go run ./scripts/seccorpus record -date YYYY-MM-DD -reviewer agent:<id> (or -reviewer operator)\n")
	b.WriteString(sampleHeader + "\n")
	for _, r := range sample {
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t\n", r.Rule, r.Repo, r.Commit, r.Path, r.Line, r.ReviewerA, r.ReviewerB, r.Joint, ra[r.Key()], rb[r.Key()])
	}
	return b.String(), len(rules), nil
}

// drawSample writes corpus/operator-sample.tsv over the rules sampleScope
// picks.
func drawSample(p paths, seed uint64, per, max int, scope string) error {
	text, rules, err := renderSample(p, seed, per, max, scope)
	if err != nil {
		return err
	}
	fmt.Printf("%d rows over %d rules\n", strings.Count(text, "\n")-strings.Count(text, "\n#")-2, rules)
	return os.WriteFile(p.file("operator-sample.tsv"), []byte(text), 0o644)
}

// readDraw reads the draw line of a sample file.
func readDraw(text string) (seed uint64, per, max int, scope string, err error) {
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimRight(l, "\r")
		if !strings.HasPrefix(l, "# draw: ") {
			continue
		}
		if _, err = fmt.Sscanf(l, drawLine, &seed, &per, &max, &scope); err != nil {
			return 0, 0, 0, "", fmt.Errorf("the draw line %q: %w", l, err)
		}
		return seed, per, max, scope, nil
	}
	return 0, 0, 0, "", fmt.Errorf("the sample file has no draw line")
}

// readSample reads an answered sample file and refuses it unless it is
// exactly the seeded draw its draw line names, with only the operator
// column filled: a deleted, added, swapped or edited row, or an edited
// header, is refused.
func readSample(p paths) ([]seccorpus.SampleRow, error) {
	path := p.file("operator-sample.tsv")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := strings.ReplaceAll(string(b), "\r\n", "\n")
	seed, per, max, scope, err := readDraw(text)
	if err != nil {
		return nil, fmt.Errorf("record: %s: %w", path, err)
	}
	want, _, err := renderSample(p, seed, per, max, scope)
	if err != nil {
		return nil, err
	}
	got := strings.Split(strings.TrimRight(text, "\n"), "\n")
	exp := strings.Split(strings.TrimRight(want, "\n"), "\n")
	differs := func(line int) error {
		return fmt.Errorf("record: %s:%d differs from the seeded draw (seed %d, per %d, max %d, scope %s): a row was deleted, added, swapped or edited; draw it again with go run ./scripts/seccorpus sample", path, line, seed, per, max, scope)
	}
	var out []seccorpus.SampleRow
	header := false
	for i, e := range exp {
		if i >= len(got) {
			return nil, differs(i + 1)
		}
		l := got[i]
		if strings.HasPrefix(e, "#") || !header {
			if l != e {
				return nil, differs(i + 1)
			}
			header = header || e == sampleHeader
			continue
		}
		// A data row: everything up to the operator column must match.
		cut := strings.LastIndex(l, "\t")
		if cut < 0 || l[:cut+1] != e {
			return nil, differs(i + 1)
		}
		f := strings.Split(e, "\t")
		line, err := strconv.Atoi(f[4])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: line %q", path, i+1, f[4])
		}
		out = append(out, seccorpus.SampleRow{
			Finding:   seccorpus.Finding{Rule: f[0], Repo: f[1], Commit: f[2], Path: f[3], Line: line},
			ReviewerA: seccorpus.Verdict(f[5]), ReviewerB: seccorpus.Verdict(f[6]), Joint: seccorpus.Verdict(f[7]),
			Operator: strings.ToLower(strings.TrimSpace(l[cut+1:])),
		})
	}
	if len(got) != len(exp) {
		return nil, differs(len(exp) + 1)
	}
	return out, nil
}

// checkSpotchecker refuses a spot-checker that is not "operator" or
// "agent:<id>", an agent that is one of the corpus's labellers (every id in
// corpus/labellers.tsv, lane SEC-G3's and every later lane's), and an agent
// that ran a labelling batch (a run agent of corpus/batches.tsv).
func checkSpotchecker(p paths, reviewer string) error {
	if !secrulepack.ValidSpotchecker(reviewer) {
		return fmt.Errorf("record: -reviewer %q (want agent:<id> of an independent AI reviewer, or operator)", reviewer)
	}
	labellers, err := readLabellers(p)
	if err != nil {
		return fmt.Errorf("record: %w", err)
	}
	batches, err := readBatches(p)
	if err != nil {
		return fmt.Errorf("record: %w", err)
	}
	refused := append([]string(nil), labellers...)
	for _, b := range batches {
		refused = append(refused, b.Reviewer, b.RunAgent)
	}
	for _, l := range refused {
		if strings.EqualFold(reviewer, l) {
			return fmt.Errorf("record: -reviewer %s labelled this corpus; the spot-check must be independent of every labeller (P-064)", reviewer)
		}
	}
	return nil
}

// checkSpotcheckSize refuses a rule's spot-check that is smaller than the
// bar needs (secrulepack.Precision.MinSpotcheck).
func checkSpotcheckSize(r secrulepack.Rule, t seccorpus.Tally) error {
	if r.Precision == nil {
		return fmt.Errorf("record: %s was sampled but has no precision figure", r.ID)
	}
	if need := r.Precision.MinSpotcheck(); t.SampleSize < need {
		return fmt.Errorf("record: %s: %d answered rows, the spot-check needs at least %d", r.ID, t.SampleSize, need)
	}
	return nil
}

// record is the one-command step after the spot-checker's answers: it
// checks the answered sample is exactly its seeded draw, writes each
// sampled rule's operator_spotcheck (who answered, the digest of the
// figures checked, the tally), turns blocking on for exactly the rules that
// clear the bar, raises the pack's patch version and validates the pack.
func record(p paths, date, reviewer string) error {
	if _, err := time.Parse("2006-01-02", date); err != nil {
		return fmt.Errorf("record: -date YYYY-MM-DD is required")
	}
	if err := checkSpotchecker(p, reviewer); err != nil {
		return err
	}
	rows, err := readSample(p)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return fmt.Errorf("record: the sample is empty (no rule cleared the bar)")
	}
	tallies, err := seccorpus.TallySample(rows)
	if err != nil {
		return err
	}
	// A figure must carry the committed measurement's pass agreement: one
	// with none, or another, was not written by measure from these labels
	// and this manifest (so a figure stripped of its passes cannot block).
	m, _, _, err := loadMeasurement(p)
	if err != nil {
		return err
	}
	want, err := measurementPasses(p, m)
	if err != nil {
		return err
	}
	by := map[string]seccorpus.Tally{}
	for _, t := range tallies {
		by[t.Rule] = t
	}
	var blocking []string
	err = editManifest(p, func(man *secrulepack.Manifest) error {
		for i := range man.Rules {
			r := &man.Rules[i]
			t, ok := by[r.ID]
			if !ok {
				continue
			}
			if err := checkSpotcheckSize(*r, t); err != nil {
				return err
			}
			if r.Precision.Passes == nil || *r.Precision.Passes != want {
				return fmt.Errorf("record: %s: the figure's passes are not the committed measurement's (%+v); run go run ./scripts/seccorpus measure", r.ID, want)
			}
			r.OperatorSpotcheck = &secrulepack.Spotcheck{
				Date: date, Reviewer: reviewer, FiguresDigest: secrulepack.PrecisionDigest(*r.Precision),
				SampleSize: t.SampleSize, Disagreements: t.Disagreements, OverturnedTrue: t.OverturnedTrue,
			}
			r.Blocking = r.MayBlock()
			if r.Blocking {
				blocking = append(blocking, r.ID)
			} else if !r.Precision.FullyLabelled() && r.Precision.RecomputedLower() >= secrulepack.BlockingLowerBound {
				fmt.Printf("%s clears the bound on a capped figure (%d labelled of %d results): it stays flag only until every result is labelled (P-077)\n", r.ID, r.Precision.Denominator, r.Precision.Results)
			}
		}
		v := secrulepack.ParseVersion(man.Version)
		if v == nil {
			return fmt.Errorf("record: pack version %q", man.Version)
		}
		man.Version = fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]+1)
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("spot-check by %s recorded for %d rules; blocking on for %d: %s\n", reviewer, len(tallies), len(blocking), strings.Join(blocking, ", "))
	return nil
}

// samePrecision reports whether two recorded figures are the same
// measurement (Kappa and Passes compared by value).
func samePrecision(a, b *secrulepack.Precision) bool {
	if a == nil || b == nil {
		return a == b
	}
	ka, kb := a.Kappa, b.Kappa
	pa, pb := a.Passes, b.Passes
	x, y := *a, *b
	x.Kappa, y.Kappa, x.Passes, y.Passes = nil, nil, nil, nil
	if x != y || (ka == nil) != (kb == nil) || (pa == nil) != (pb == nil) {
		return false
	}
	if pa != nil && *pa != *pb {
		return false
	}
	return ka == nil || *ka == *kb
}
