package codequality

import (
	"path"
	"sort"
	"strings"
	"time"
)

// ProblemKind is why a report that exists was not used. Closed vocabulary.
type ProblemKind string

// The closed ProblemKind vocabulary.
const (
	ProblemTooLarge     ProblemKind = "too_large"    // over MaxReportBytes
	ProblemSymlink      ProblemKind = "symlink"      // the path or a parent is a symbolic link
	ProblemUnreadable   ProblemKind = "unreadable"   // permission or I/O error
	ProblemUnrecognized ProblemKind = "unrecognized" // not one of the four formats
	ProblemParse        ProblemKind = "parse_error"  // the format's parser failed
	ProblemNoLines      ProblemKind = "no_lines"     // parsed, no instrumented line
	ProblemCapped       ProblemKind = "capped"       // past MaxReports
)

// Problem is one report that exists but was not used.
type Problem struct {
	RelPath string      `json:"path"`
	Kind    ProblemKind `json:"kind"`
}

// Found is one report read and parsed.
type Found struct {
	RelPath string
	ModTime time.Time
	Report  Report
}

// ReportUse says how a found report entered the project figure.
type ReportUse string

// The closed ReportUse vocabulary.
const (
	// UseCounted: its lines are in the project figure.
	UseCounted ReportUse = "counted"
	// UseSameRun: a second format of a counted report's test run (same
	// directory, mostly the same files), so not counted twice.
	UseSameRun ReportUse = "same_run"
)

// ReportSummary is one found report as the page lists it.
type ReportSummary struct {
	RelPath    string    `json:"path"`
	Format     Format    `json:"format"`
	ModTime    time.Time `json:"modified_at"`
	Lines      int       `json:"lines"`
	Covered    int       `json:"covered"`
	Files      int       `json:"files"`
	TotalsOnly bool      `json:"totals_only,omitempty"`
	Skipped    int       `json:"skipped_records,omitempty"`
	Use        ReportUse `json:"use"`
	// SameRunAs names the counted report this one duplicates (UseSameRun).
	SameRunAs string `json:"same_run_as,omitempty"`
}

// FileLine is one file of the least-covered list.
type FileLine struct {
	Path    string   `json:"path"`
	Report  string   `json:"report"`
	Lines   int      `json:"lines"`
	Covered int      `json:"covered"`
	Percent *float64 `json:"percent,omitempty"`
}

// CoverageFigure is the project's combined coverage numbers.
type CoverageFigure struct {
	Lines   int
	Covered int
	// Percent is Covered / Lines * 100; nil when Lines is 0.
	Percent *float64
	Reports []ReportSummary
	// LeastCovered lists up to LeastCoveredLimit counted files with at
	// least LeastCoveredMinLines instrumented lines, lowest percent first.
	LeastCovered []FileLine
	// NewestReport is the newest modification time among counted reports.
	NewestReport time.Time
	// OldestReport is the oldest modification time among counted reports.
	OldestReport time.Time
}

// Least-covered list bounds.
const (
	LeastCoveredLimit    = 10
	LeastCoveredMinLines = 10
)

// formatPriority orders formats for the same-run rule: when two reports
// are one run, the one ranked first is counted. lcov and Cobertura keep
// per-line records for every writer; JaCoCo and Go profiles follow.
var formatPriority = map[Format]int{FormatLCOV: 0, FormatCobertura: 1, FormatJaCoCo: 2, FormatGoCover: 3}

// sameRunOverlap is the share of the smaller report's file basenames that
// must also be in the other report for the two to read as one test run.
const sameRunOverlap = 0.5

// sameRun reports whether a and b are two formats of one test run: the
// same directory, and either one carries no per-file records or their
// file basename sets overlap by at least sameRunOverlap of the smaller.
// Different languages in one directory (a Go profile beside a JS lcov)
// share no basenames and are both counted.
func sameRun(a, b Found) bool {
	if path.Dir(a.RelPath) != path.Dir(b.RelPath) {
		return false
	}
	if a.Report.TotalsOnly || b.Report.TotalsOnly {
		return true
	}
	small, large := a.Report.Files, b.Report.Files
	if len(small) > len(large) {
		small, large = large, small
	}
	if len(small) == 0 {
		return true
	}
	names := make(map[string]bool, len(large))
	for _, f := range large {
		names[baseName(f.Path)] = true
	}
	var hit int
	for _, f := range small {
		if names[baseName(f.Path)] {
			hit++
		}
	}
	return float64(hit) >= sameRunOverlap*float64(len(small))
}

// baseName is the last element of a slash- or backslash-separated path.
func baseName(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	return path.Base(p)
}

// Combine folds the reports found into one project figure. Reports are
// considered in priority order (format, then path); a report that is the
// same run as an already-counted one is listed as UseSameRun and not
// counted; every other report is counted and summed. Reports in different
// directories are separate runs (a monorepo's packages) and are summed.
func Combine(found []Found) CoverageFigure {
	ordered := append([]Found(nil), found...)
	sort.SliceStable(ordered, func(i, j int) bool {
		pi, pj := formatPriority[ordered[i].Report.Format], formatPriority[ordered[j].Report.Format]
		if pi != pj {
			return pi < pj
		}
		return ordered[i].RelPath < ordered[j].RelPath
	})
	var fig CoverageFigure
	var counted []Found
	var files []FileLine
	for _, f := range ordered {
		sum := ReportSummary{
			RelPath: f.RelPath, Format: f.Report.Format, ModTime: f.ModTime,
			Lines: f.Report.Lines, Covered: f.Report.Covered, Files: len(f.Report.Files),
			TotalsOnly: f.Report.TotalsOnly, Skipped: f.Report.Skipped, Use: UseCounted,
		}
		for _, c := range counted {
			if sameRun(c, f) {
				sum.Use, sum.SameRunAs = UseSameRun, c.RelPath
				break
			}
		}
		fig.Reports = append(fig.Reports, sum)
		if sum.Use != UseCounted {
			continue
		}
		counted = append(counted, f)
		fig.Lines += f.Report.Lines
		fig.Covered += f.Report.Covered
		if fig.NewestReport.IsZero() || f.ModTime.After(fig.NewestReport) {
			fig.NewestReport = f.ModTime
		}
		if fig.OldestReport.IsZero() || f.ModTime.Before(fig.OldestReport) {
			fig.OldestReport = f.ModTime
		}
		for _, fc := range f.Report.Files {
			if fc.Lines >= LeastCoveredMinLines {
				files = append(files, FileLine{Path: fc.Path, Report: f.RelPath, Lines: fc.Lines, Covered: fc.Covered, Percent: Percent(fc.Covered, fc.Lines)})
			}
		}
	}
	sort.SliceStable(fig.Reports, func(i, j int) bool { return fig.Reports[i].RelPath < fig.Reports[j].RelPath })
	fig.Percent = Percent(fig.Covered, fig.Lines)
	sort.SliceStable(files, func(i, j int) bool {
		pi, pj := *files[i].Percent, *files[j].Percent
		if pi != pj {
			return pi < pj
		}
		if files[i].Lines != files[j].Lines {
			return files[i].Lines > files[j].Lines
		}
		return files[i].Path < files[j].Path
	})
	if len(files) > LeastCoveredLimit {
		files = files[:LeastCoveredLimit]
	}
	fig.LeastCovered = files
	return fig
}

// Percent is n / d * 100, nil when d is 0.
func Percent(n, d int) *float64 {
	if d <= 0 {
		return nil
	}
	p := float64(n) / float64(d) * 100
	return &p
}
