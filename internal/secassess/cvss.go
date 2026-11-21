package secassess

import (
	"errors"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secassess/cvss4"
)

// CVSS 4.0 base scores on penetration test findings (depth plan W7.1, decision
// D30). The agent may add a base vector to a finding; Observer parses it with
// the strict cvss4 grammar, scores it from tables generated out of FIRST's
// calculator, and keeps its own score and band beside the agent's vector. A
// score, a band or a rating the agent wrote is never read. The vector is the
// weakness as it behaved in the in-box copy: a base score has no threat
// intelligence and no deployment behind it, which is what CVSSNote says wherever
// a CVSS line is shown. The finding's stored severity does not change with it:
// the likelihood-times-impact band still decides what an import carries (and the
// import caps it).

// CVSSNote is the sentence shown beside every CVSS line, in the web
// (CVSS_NOTE in secAssessModel.ts, pinned by a test) and in the exports.
const CVSSNote = "Base score of the weakness as logged in an in-box copy, not a production risk."

// CVSSApart is the sentence that says the base score and the finding's band are
// two readings made from different inputs, so a "medium" band beside a critical
// base score does not read as Observer disagreeing with itself (N-1, N-16). The
// web prints it once in an opened finding (CVSS_APART, which says "in the
// table" where the web has one); the Markdown export carries it on the CVSS
// bullet, where the band is the Rating bullet above. Both say that the band is
// the agent's likelihood times impact and that neither changes the other; a test
// pins the tail they share.
const CVSSApart = "This is a separate reading from the band in the rating above, which is the agent's likelihood times impact. Neither changes the other."

// cvssRefusal says, in Observer's words, why a vector was left out, one phrase
// per refusal code of cvss4.Parse. The phrases never repeat the agent's text.
var cvssRefusal = map[cvss4.ErrorCode]string{
	cvss4.CodeEmpty:         "is empty",
	cvss4.CodeTooLong:       "is too long to be a base vector",
	cvss4.CodeBadPrefix:     "does not start with CVSS:4.0/ (only CVSS 4.0 is read)",
	cvss4.CodeBadSyntax:     "has a part that is not METRIC:VALUE",
	cvss4.CodeNotBase:       "carries a threat, environmental or supplemental metric (only the 11 base metrics are read)",
	cvss4.CodeBadMetric:     "has a metric that is unknown, repeated or out of order (the order is AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA)",
	cvss4.CodeMissingMetric: "stops before all 11 base metrics",
	cvss4.CodeBadValue:      "has a value its metric does not take",
}

// cvssBandOf maps the rating of a CVSS score to a band. A score of 0.0 is
// rated none, which has no band: the empty Band.
func cvssBandOf(r cvss4.Rating) Band {
	switch r {
	case cvss4.RatingLow:
		return BandLow
	case cvss4.RatingMedium:
		return BandMedium
	case cvss4.RatingHigh:
		return BandHigh
	case cvss4.RatingCritical:
		return BandCritical
	}
	return ""
}

// ScoreCVSS scores a CVSS 4.0 base vector: its base score and the band of
// that score ("" for 0.0). The error is a *cvss4.ParseError for a vector that
// is not a base vector.
func ScoreCVSS(vector string) (score float64, band Band, err error) {
	res, err := cvss4.Compute(vector)
	if err != nil {
		return 0, "", fmt.Errorf("secassess.ScoreCVSS: %w", err)
	}
	return res.Score, cvssBandOf(res.Rating), nil
}

// FormatCVSSScore renders a base score with one decimal ("9.3", "0.0").
func FormatCVSSScore(score float64) string { return cvss4.FormatScore(score) }

// cvssReading is the score of a finding's vector as Observer reads it now, from
// the vector alone: the stored score is never used, so an export says what the
// vector scores whatever a stored copy holds. ok is false for a finding with no
// vector or one that is not a base vector.
func cvssReading(f PTFinding) (score float64, band Band, ok bool) {
	if f.CVSS == "" {
		return 0, "", false
	}
	s, b, err := ScoreCVSS(f.CVSS)
	if err != nil {
		return 0, "", false
	}
	return s, b, true
}

// cvssVector is the part of row V5 that reads a finding's optional vector. A
// vector that is not a CVSS 4.0 base vector is left out, with one issue that
// says why; the finding itself is kept with its rating and its band.
func (v *validator) cvssVector(path string, f *PTFinding) {
	f.CVSS = strings.TrimSpace(f.CVSS)
	if f.CVSS == "" {
		return
	}
	_, err := cvss4.Parse(f.CVSS)
	if err == nil {
		return
	}
	why, at := "is not a CVSS 4.0 base vector", ""
	var pe *cvss4.ParseError
	if errors.As(err, &pe) {
		if w, ok := cvssRefusal[pe.Code]; ok {
			why = w
		}
		if pe.Metric != "" {
			at = " (at " + pe.Metric + ")"
		}
	}
	// The finding is named by its id (row V4 has accepted it: a closed alphabet),
	// so the list under How checked says which finding lost its vector, and the
	// issue's Item lets the view say so on the finding's own row. The vector
	// itself is never repeated.
	v.issueItem("V5", "bad_cvss_dropped", SevDropped, path, f.ID,
		fmt.Sprintf("The CVSS vector of %s %s%s, so it was left out. The finding keeps its likelihood and impact rating.", findingWords(f.ID), why, at))
	f.CVSS = ""
}

// findingWords names a finding in an issue: by its id, which row V4 has already
// accepted (letters, digits, dot, underscore, hyphen), so the sentence is
// Observer's own and never carries free text of the agent's. A finding whose id
// is not one of those reads as "this finding".
func findingWords(id string) string {
	if ValidItemID(id) {
		return "finding " + id
	}
	return "this finding"
}

// applyCVSS sets the computed score and band of a finding from its vector, and
// clears them for a finding without one. An error means the vector, which row V5
// already vetted, did not score; the caller drops the vector.
func applyCVSS(f *PTFinding) error {
	f.CVSSScore, f.CVSSBand = nil, ""
	if f.CVSS == "" {
		return nil
	}
	score, band, err := ScoreCVSS(f.CVSS)
	if err != nil {
		return err
	}
	f.CVSSScore, f.CVSSBand = &score, band
	return nil
}
