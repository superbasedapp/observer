package secassess

import (
	"fmt"
	"strings"
)

// The clean-reading rule (plan section 13, limit 3: a clean result is not a
// clearance). A result with nothing in it never reads as "clean", "secure" or
// "no vulnerabilities". CleanReading says what the empty result does and does
// not mean, and CoverageLine says what the agent covered; both are built from
// the validator's coverage reports, in Observer's own words, and neither says
// more than the report holds. A result with nothing SHOWN is not always a result
// the agent left empty: when the agent wrote items and the check refused or left
// out every one of them, the reading says that, and never "none was reported".
// The web's coverageCountsLine mirrors coverageCounts; both sides pin the same
// example.

// The sentences of the clean reading and the coverage line.
const (
	// ReadingNotStartedHead opens the reading of a pen test whose target did
	// not start; ReadingNotStartedAll or ReadingNotStartedOne follows it when
	// the coverage report has rows, then ReadingNotStartedTail.
	ReadingNotStartedHead = "The target was not started, so nothing was tested in a running application"
	// ReadingNotStartedAll is the clause for two or more categories (the %d is
	// the number of coverage rows).
	ReadingNotStartedAll = ": all %d categories read as skipped"
	// ReadingNotStartedOne is the clause for exactly one category.
	ReadingNotStartedOne = ": the 1 category reads as skipped"
	// ReadingNotStartedTail closes the reading of a target that did not start.
	ReadingNotStartedTail = ". No weakness was reported; this is not proof that none exists."
	// ReadingNotStartedStop closes the reading of a target that did not start
	// when the agent's findings were refused (the first sentence says so).
	ReadingNotStartedStop = "."
	// ReadingPenTestStarted is the reading of a pen test with no findings whose
	// target started (the %s is the counts line).
	ReadingPenTestStarted = "No weakness was reported in what was tested (%s); this is not proof that none exists."
	// ReadingThreatModel is the reading of a threat model with no threats (the
	// first %s is the waived pairs with their noun, the %d the empty cells).
	ReadingThreatModel = "No threat was recorded (%s waived with a reason, %d with neither). " +
		"A threat model is read from code and documents only, so this is not proof that none exists."
	// ReadingRefused is the reading of a result whose items the check refused or
	// left out, all of them: the first %s is what the agent wrote ("2 findings"),
	// the second what became of them ("the check refused 2"), the third the kind
	// of thing that is not shown ("weakness", "threat").
	ReadingRefused = "The agent wrote %s, and none is shown here: %s. This says nothing about whether a %s exists; the issues say why."
	// CoverageLinePenTest is the coverage line of a pen test (the %s is the
	// counts line).
	CoverageLinePenTest = "Covered by the agent: %s."
	// CoverageLineThreatModel is the coverage line of a threat model (the first
	// %s is the analysed pairs with their noun, the two %d the waived and the
	// empty cells).
	CoverageLineThreatModel = "Covered by the agent: %s analysed, %d waived with a reason and %d with neither."
)

// coverageCountsHead is the first half of the counts line: how many of the
// categories the agent claimed, and how many of those a logged request backs.
const coverageCountsHead = "%d of %d categories claimed, %d with a logged request"

// coverageCountParts are the parts of the counts line that follow the head,
// in order; a part is written only when its count is above zero.
var coverageCountParts = []struct{ key, format string }{
	{CovSkipped, ", %d skipped"},
	{CovNotStarted, ", %d skipped (target not started)"},
	{CovNotApplicable, ", %d not applicable"},
	{CovToolUnavailable, ", %d with a tool unavailable"},
	{CovMissing, ", %d with no row"},
}

// coverageCounts is the pen test coverage in one phrase, for example "5 of 8
// categories claimed, 0 with a logged request, 1 skipped, 1 not applicable, 1
// with a tool unavailable". A category counts as claimed when the agent says it
// tested it, whether or not a logged request backs the claim; it counts as
// logged only with a logged request.
func coverageCounts(pt *PTCoverage) string {
	logged := pt.Counts[CovTestedLogged]
	s := fmt.Sprintf(coverageCountsHead, pt.Counts[CovTestedClaimed]+logged, len(pt.Rows), logged)
	for _, p := range coverageCountParts {
		if n := pt.Counts[p.key]; n > 0 {
			s += fmt.Sprintf(p.format, n)
		}
	}
	return s
}

// counted writes n with its noun in the right number ("1 finding", "2
// findings").
func counted(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// pairs is a count of element and category pairs with its noun.
func pairs(n int) string {
	return counted(n, "element and category pair", "element and category pairs")
}

// itemsCount returns how the validation counted the collection and how many
// items it kept. A checked model that is present is the authority on what was
// kept (a stored copy that did not fit keeps the report and not the model, and
// the report's kept count stands in for it); the report is the authority on
// what was read, refused and left out. ok is false when the result names no
// such collection and holds no model for it.
func itemsCount(res Result, coll string, kept func() (int, bool)) (c Count, k int, ok bool) {
	c, named := res.Report.Counts[coll]
	k, hasModel := kept()
	if !hasModel {
		k, ok = c.Kept, named
		return c, k, ok
	}
	return c, k, true
}

// refusedClause says what became of the items that are not shown, from the
// counts: "the check refused 2", "the check left out 1" or both.
func refusedClause(c Count) string {
	var parts []string
	if c.Refused > 0 {
		parts = append(parts, fmt.Sprintf("refused %d", c.Refused))
	}
	if c.LeftOut > 0 {
		parts = append(parts, fmt.Sprintf("left out %d", c.LeftOut))
	}
	return "the check " + strings.Join(parts, " and ")
}

// refusedAll reports whether the agent wrote items and none is kept: the
// reading must say so instead of "none was reported".
func refusedAll(c Count, kept int) bool { return c.Read > 0 && kept == 0 }

// CleanReading says what a result with nothing in it does and does not mean.
// It returns "" when the result holds something to read (a finding or a
// threat), when the file was refused, and when the result carries no coverage
// report to say what was covered. A result whose items were all refused or left
// out by the check reads as exactly that, not as "none was reported".
func CleanReading(res Result) string {
	if res.Report.State == ValidationInvalid {
		return ""
	}
	if pt := res.Report.PT; pt != nil {
		c, n, ok := itemsCount(res, "findings", func() (int, bool) {
			if res.PT == nil {
				return 0, false
			}
			return len(res.PT.Findings), true
		})
		if !ok || n > 0 {
			return ""
		}
		if refusedAll(c, n) {
			s := fmt.Sprintf(ReadingRefused, counted(c.Read, "finding", "findings"), refusedClause(c), "weakness")
			if !pt.Started {
				s += " " + ReadingNotStartedHead + ReadingNotStartedStop
			}
			return s
		}
		if !pt.Started {
			s := ReadingNotStartedHead
			switch rows := len(pt.Rows); {
			case rows == 1:
				s += ReadingNotStartedOne
			case rows > 1:
				s += fmt.Sprintf(ReadingNotStartedAll, rows)
			}
			return s + ReadingNotStartedTail
		}
		return fmt.Sprintf(ReadingPenTestStarted, coverageCounts(pt))
	}
	if tm := res.Report.TM; tm != nil {
		c, n, ok := itemsCount(res, "threats", func() (int, bool) {
			if res.TM == nil {
				return 0, false
			}
			return len(res.TM.Threats), true
		})
		if !ok || n > 0 {
			return ""
		}
		if refusedAll(c, n) {
			return fmt.Sprintf(ReadingRefused, counted(c.Read, "threat", "threats"), refusedClause(c), "threat")
		}
		return fmt.Sprintf(ReadingThreatModel, pairs(tm.Waived), tm.Empty)
	}
	return ""
}

// CoverageLine says what the agent covered, in one sentence. It returns ""
// when the result carries no coverage report (a refused file, an old run).
func CoverageLine(res Result) string {
	switch {
	case res.Report.PT != nil:
		return fmt.Sprintf(CoverageLinePenTest, coverageCounts(res.Report.PT))
	case res.Report.TM != nil:
		tm := res.Report.TM
		return fmt.Sprintf(CoverageLineThreatModel, pairs(tm.Analysed), tm.Waived, tm.Empty)
	}
	return ""
}
