package cvss4

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"testing"
)

// The oracle: scores that did not come from FIRST's calculator or from the
// tables this package was generated from.
//
//   - oracle_gocvss_*.tsv and the space digest come from running
//     github.com/pandatix/go-cvss v0.6.4 (MIT), a separate implementation with
//     its own tables, once (tools/cvss4gen/oracle).
//   - oracle_cve.tsv holds the scores real CVE records publish.
//
// testdata/README.md says how each was produced and what the five known
// disagreements are.

func score1(t *testing.T, s string) float64 {
	t.Helper()
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		t.Fatalf("bad score %q: %v", s, err)
	}
	return f
}

// isRoundingTie reports whether a raw (unrounded) score sits on an exact x.x5
// boundary, within float noise: the situation in which one implementation
// rounds the tenth up and another down.
func isRoundingTie(raw float64) bool {
	tenths := raw * 10
	return math.Abs(tenths-math.Floor(tenths)-0.5) < 1e-6
}

// divergences loads the 72 base vectors on which go-cvss and FIRST differ.
func divergences(t *testing.T) map[string][2]float64 {
	t.Helper()
	out := map[string][2]float64{}
	for _, r := range readTSV(t, "oracle_base_divergence.tsv") {
		if len(r) != 3 {
			t.Fatalf("divergence row %v", r)
		}
		out[r[0]] = [2]float64{score1(t, r[1]), score1(t, r[2])}
	}
	return out
}

func TestOracleBaseDivergencesAreOneRoundingTie(t *testing.T) {
	div := divergences(t)
	if len(div) != 72 {
		t.Fatalf("%d divergences, want 72", len(div))
	}
	for v, pair := range div {
		b, err := Parse(v)
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		raw, _, err := unroundedScore(b.selection())
		if err != nil {
			t.Fatal(err)
		}
		if raw != 4.9499999999999993 {
			t.Errorf("%s: unrounded %.17g, want the 4.95 tie 4.9499999999999993", v, raw)
		}
		first, goc := pair[0], pair[1]
		got := mustScore(t, v).Score
		if got != first {
			t.Errorf("%s: scores %v, FIRST's calculator says %v", v, got, first)
		}
		if math.Round((goc-first)*10) != 1 {
			t.Errorf("%s: go-cvss %v is not one tenth above FIRST's %v", v, goc, first)
		}
		if RatingOf(first) != RatingOf(goc) {
			t.Errorf("%s: the tie crosses a rating boundary (%v vs %v)", v, first, goc)
		}
	}
}

func TestOracleGoCVSSBaseSample(t *testing.T) {
	rows := readTSV(t, "oracle_gocvss_base.tsv")
	if len(rows) < 800 {
		t.Fatalf("%d base oracle rows, want at least 800", len(rows))
	}
	div := divergences(t)
	perMacro := map[string]int{}
	disagreed := 0
	for _, r := range rows {
		vector, want := r[0], score1(t, r[1])
		res := mustScore(t, vector)
		perMacro[res.MacroVector]++
		if res.Score == want {
			continue
		}
		disagreed++
		if pair, ok := div[vector]; !ok || pair[1] != want || pair[0] != res.Score {
			t.Errorf("%s: scores %v, go-cvss says %v and the pair is not a listed divergence", vector, res.Score, want)
		}
	}
	if disagreed != 1 {
		t.Errorf("%d sample rows disagree with go-cvss, want exactly the one tie", disagreed)
	}
	if len(perMacro) != 36 {
		t.Errorf("the sample reaches %d MacroVectors, want all 36 a base vector can reach", len(perMacro))
	}
	for mv, n := range perMacro {
		if n < 3 {
			t.Errorf("MacroVector %s has only %d sample rows", mv, n)
		}
	}
}

func TestOracleGoCVSSFullVectorsCoverAll270MacroVectors(t *testing.T) {
	rows := readTSV(t, "oracle_gocvss_full.tsv")
	perMacro := map[string]int{}
	ties := 0
	for _, r := range rows {
		vector, want := r[0], score1(t, r[1])
		sel := selectionOf(t, vector)
		eq := sel.macroLevels()
		perMacro[macroKey(eq)]++
		// A maximal vector must exist for every vector the oracle holds: the
		// calculator's fallback to the last candidate is not relied on.
		if _, qualified, err := sel.referenceDistances(eq); err != nil || !qualified {
			t.Errorf("%s: no maximal vector qualifies (err %v)", vector, err)
		}
		got, _, err := scoreSelection(sel)
		if err != nil {
			t.Fatalf("%s: %v", vector, err)
		}
		if got == want {
			continue
		}
		// The only allowed disagreement is the rounding tie.
		raw, _, _ := unroundedScore(sel)
		if !isRoundingTie(raw) || math.Abs(math.Round((want-got)*10)) != 1 {
			t.Errorf("%s: scores %v, go-cvss says %v (unrounded %.17g)", vector, got, want, raw)
			continue
		}
		ties++
	}
	if len(perMacro) != 270 {
		t.Errorf("the full-vector oracle reaches %d MacroVectors, want all 270", len(perMacro))
	}
	for mv, n := range perMacro {
		if _, ok := macroScores[mv]; !ok {
			t.Errorf("oracle row derives MacroVector %s, which the table does not have", mv)
		}
		if n < 2 {
			t.Errorf("MacroVector %s has only %d oracle rows", mv, n)
		}
	}
	if ties != 1 {
		t.Errorf("%d rounding ties in the full-vector oracle, want the 1 recorded in testdata/README.md", ties)
	}
}

func TestOracleWholeBaseSpaceAgreesWithGoCVSSExceptTheTie(t *testing.T) {
	var wantSum string
	var wantCount int
	for _, r := range readTSV(t, "oracle_gocvss_space.txt") {
		fields := strings.Fields(r[0])
		if len(fields) != 2 {
			t.Fatalf("space row %q", r[0])
		}
		wantSum = fields[0]
		n, err := strconv.Atoi(fields[1])
		if err != nil {
			t.Fatal(err)
		}
		wantCount = n
	}
	div := divergences(t)
	h := sha256.New()
	count, replaced := 0, 0
	walkBase(func(v string) {
		count++
		score := mustScore(t, v).Score
		if pair, ok := div[v]; ok {
			// go-cvss's line for a listed divergence carries go-cvss's score.
			if pair[0] != score {
				t.Fatalf("%s: scores %v, the divergence list says FIRST gives %v", v, score, pair[0])
			}
			score = pair[1]
			replaced++
		}
		h.Write([]byte(v + "\t" + FormatScore(score) + "\n"))
	})
	if count != wantCount || count != 104976 {
		t.Fatalf("walked %d vectors, digest file says %d, want 104,976", count, wantCount)
	}
	if replaced != len(div) {
		t.Errorf("%d of %d listed divergences were met in the walk", replaced, len(div))
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSum {
		t.Errorf("digest of the scorer's output over the whole base space = %s, go-cvss's = %s", got, wantSum)
	}
}

func TestOracleRealCVERecords(t *testing.T) {
	rows := readTSV(t, "oracle_cve.tsv")
	disputed := map[string][]string{}
	for _, r := range readTSV(t, "oracle_cve_disputed.tsv") {
		if len(r) != 6 {
			t.Fatalf("disputed row %v", r)
		}
		disputed[r[0]+"\t"+r[1]] = r
	}
	if len(disputed) != 4 {
		t.Fatalf("%d disputed rows, want 4", len(disputed))
	}
	vectors := map[string]bool{}
	agreed, seenDisputed := 0, 0
	for _, r := range rows {
		vector, published, severity := r[0], score1(t, r[1]), r[2]
		vectors[vector] = true
		res := mustScore(t, vector)

		// The published severity is the rating of the published score, in
		// every record: the record's own consistency, nothing of ours.
		if string(RatingOf(published)) != severity {
			t.Errorf("%s: published score %v is rated %q by the record, %q by the specification", vector, published, severity, RatingOf(published))
		}
		d, isDisputed := disputed[vector+"\t"+r[1]]
		if !isDisputed {
			if res.Score != published {
				t.Errorf("%s: scores %v, the record publishes %v (%s)", vector, res.Score, published, r[3])
			}
			agreed++
			continue
		}
		seenDisputed++
		// A disputed row is pinned: ours is FIRST's calculator's value, and
		// go-cvss either agrees with ours (the CNA erred) or with the record
		// (the rounding tie, the same one as the divergence list).
		first, goc := score1(t, d[2]), score1(t, d[3])
		if res.Score != first {
			t.Errorf("%s: scores %v, the disputed list pins %v", vector, res.Score, first)
		}
		if goc != first && goc != published {
			t.Errorf("%s: go-cvss %v agrees with neither ours %v nor the record %v", vector, goc, first, published)
		}
		if goc != first {
			if _, ok := divergences(t)[vector]; !ok {
				t.Errorf("%s: go-cvss differs from ours but the vector is not in the divergence list", vector)
			}
		}
	}
	if len(vectors) < 100 {
		t.Errorf("%d distinct real vectors, want at least 100", len(vectors))
	}
	if seenDisputed != len(disputed) {
		t.Errorf("%d of %d disputed rows appear in oracle_cve.tsv", seenDisputed, len(disputed))
	}
	if agreed < 250 {
		t.Errorf("only %d published rows agree with the scorer", agreed)
	}
}
