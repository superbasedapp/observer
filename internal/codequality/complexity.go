package codequality

import (
	"math"
	"sort"
)

// Complexity roll-up rules. A function is "over" when its cyclomatic
// complexity (decision points + 1, counted by code intelligence) is above
// ComplexityThreshold, McCabe's original limit.
const (
	ComplexityThreshold = 10
	// TopComplexLimit bounds the most-complex list the page shows.
	TopComplexLimit = 10
)

// ComplexityFiles is one group of a project's indexed files, as the store
// classifies them.
type ComplexityFiles struct {
	Lang string
	// Counter: the files were parsed by an exact-span backend that counts
	// complexity for their language (go/ast, tree-sitter with a rule
	// table). A heuristic-fallback file, or a language without a table,
	// never gets a figure.
	Counter bool
	// Current: the files were indexed with complexity counting on
	// (codeintel_files.extract_version at the complexity version).
	Current bool
	Files   int
}

// FuncValue is one counted function's figure.
type FuncValue struct {
	Lang       string
	Complexity int
}

// ComplexFunction is one function of the most-complex list.
type ComplexFunction struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Lang       string `json:"lang"`
	File       string `json:"file"`
	StartLine  int    `json:"start_line"`
	EndLine    int    `json:"end_line"`
	Complexity int    `json:"complexity"`
}

// ComplexityInput is the store's answer for one project.
type ComplexityInput struct {
	Index IndexFacts
	Files []ComplexityFiles
	// Values holds every counted function's figure (capped at MaxSymbols;
	// Index.Truncated says so).
	Values []FuncValue
	// Top is the most complex functions, highest first (up to
	// TopComplexLimit).
	Top []ComplexFunction
}

// LangComplexity is one language's part of the figure.
type LangComplexity struct {
	Lang      string `json:"lang"`
	Functions int    `json:"functions"`
	Over      int    `json:"over"`
	P90       int    `json:"p90"`
	Max       int    `json:"max"`
}

// ComplexityFigure is the project's complexity numbers.
type ComplexityFigure struct {
	Functions int
	Over      int
	Sum       int
	// OverShare is Over / Functions * 100; Mean is Sum / Functions; both
	// nil when no function was counted.
	OverShare   *float64
	Mean        *float64
	P50         int
	P90         int
	Max         int
	PerLanguage []LangComplexity
	Top         []ComplexFunction
	// CountedFiles have a counter and were indexed with counting on;
	// PendingFiles have a counter but were indexed before counting was on
	// (the next index pass counts them); UncountedFiles never get a figure
	// (heuristic parser or no counter for the language), UncountedLangs
	// names their languages.
	CountedFiles   int
	PendingFiles   int
	UncountedFiles int
	UncountedLangs []string
}

// ComplexityResult is one project's complexity answer.
type ComplexityResult struct {
	State  State
	Reason string
	ComplexityFigure
	Index IndexFacts
	// Stale: measured from an index left from when code intelligence was
	// on; it is no longer refreshed.
	Stale bool
}

// ComplexityFacts are the inputs of the complexity state rules.
type ComplexityFacts struct {
	Enabled      bool
	CodeIntelOn  bool
	NotInBuild   bool
	Archived     bool
	IndexedFiles int
	CounterFiles int // indexed files with a counter, counted or pending
	CountedFiles int // of them, indexed with counting on
	Functions    int
}

// complexityRules is walked top-down; the last row always matches. Like
// duplication, an index that exists is read even when code intelligence is
// now off (the figure is then flagged stale).
var complexityRules = []stateRule[ComplexityFacts]{
	{StateOff, func(f ComplexityFacts) bool { return !f.Enabled }, "Quality metrics are off ([projects].quality_metrics = false)."},
	{StateNotInBuild, func(f ComplexityFacts) bool { return f.NotInBuild }, "This build of Observer has no code intelligence, which complexity needs."},
	{StateArchived, func(f ComplexityFacts) bool { return f.Archived && f.IndexedFiles == 0 }, "The project's code intelligence index was moved to the archive; rehydrate it to measure complexity."},
	{StateCodeIntelOff, func(f ComplexityFacts) bool { return f.IndexedFiles == 0 && !f.CodeIntelOn }, "Not measured: code intelligence is off. Turn it on in Settings > Intelligence > Code intelligence to measure complexity."},
	{StateNotIndexed, func(f ComplexityFacts) bool { return f.IndexedFiles == 0 }, "Not measured yet: code intelligence has not indexed this project."},
	{StateNoSupportedFiles, func(f ComplexityFacts) bool { return f.CounterFiles == 0 }, "No indexed file is in a language complexity is counted for with exact spans. Files on the heuristic parser get no figure."},
	{StateCodeIntelOff, func(f ComplexityFacts) bool { return f.CountedFiles == 0 && !f.CodeIntelOn }, "Not measured: code intelligence is off, and the index it left predates complexity counting."},
	{StateCountPending, func(f ComplexityFacts) bool { return f.CountedFiles == 0 }, "Not counted yet: the index was built before complexity counting was on. The next index pass counts it (the daemon's start pass, or observer index <path>)."},
	{StateNoFunctions, func(f ComplexityFacts) bool { return f.Functions == 0 }, "The counted files hold no function or method."},
	{StateMeasured, func(ComplexityFacts) bool { return true }, "Cyclomatic complexity (decision points + 1) of each function and method, counted by code intelligence from exact parse spans."},
}

// ComplexityState decides the complexity state and its reason.
func ComplexityState(f ComplexityFacts) (State, string) { return walk(complexityRules, f) }

// MeasureComplexity composes the complexity answer from the store's index
// read, through the complexity state table.
func MeasureComplexity(enabled, codeIntelOn bool, in ComplexityInput) ComplexityResult {
	res := ComplexityResult{Index: in.Index}
	var counter, counted int
	if enabled && !in.Index.NotInBuild {
		res.ComplexityFigure = rollComplexity(in)
		counter, counted = res.CountedFiles+res.PendingFiles, res.CountedFiles
	}
	res.State, res.Reason = ComplexityState(ComplexityFacts{
		Enabled: enabled, CodeIntelOn: codeIntelOn, NotInBuild: in.Index.NotInBuild,
		Archived: in.Index.Archived, IndexedFiles: in.Index.IndexedFiles,
		CounterFiles: counter, CountedFiles: counted, Functions: res.Functions,
	})
	if res.State != StateMeasured {
		// Keep the file classification (it explains no_supported_files and
		// count_pending) but no number a reader could take for a figure.
		res.ComplexityFigure = ComplexityFigure{
			CountedFiles: res.CountedFiles, PendingFiles: res.PendingFiles,
			UncountedFiles: res.UncountedFiles, UncountedLangs: res.UncountedLangs,
		}
		return res
	}
	res.Stale = !codeIntelOn
	return res
}

// rollComplexity folds the store's rows into the figure.
func rollComplexity(in ComplexityInput) ComplexityFigure {
	var fig ComplexityFigure
	uncounted := map[string]bool{}
	for _, f := range in.Files {
		switch {
		case !f.Counter:
			fig.UncountedFiles += f.Files
			if f.Lang != "" {
				uncounted[f.Lang] = true
			}
		case f.Current:
			fig.CountedFiles += f.Files
		default:
			fig.PendingFiles += f.Files
		}
	}
	for l := range uncounted {
		fig.UncountedLangs = append(fig.UncountedLangs, l)
	}
	sort.Strings(fig.UncountedLangs)

	all := make([]int, 0, len(in.Values))
	byLang := map[string][]int{}
	for _, v := range in.Values {
		if v.Complexity < 1 {
			continue // not a figure (the store reads only counted rows)
		}
		all = append(all, v.Complexity)
		byLang[v.Lang] = append(byLang[v.Lang], v.Complexity)
	}
	fig.Functions = len(all)
	if fig.Functions == 0 {
		return fig
	}
	for _, c := range all {
		fig.Sum += c
		if c > ComplexityThreshold {
			fig.Over++
		}
	}
	sort.Ints(all)
	fig.P50, fig.P90, fig.Max = percentile(all, 50), percentile(all, 90), all[len(all)-1]
	fig.OverShare = Percent(fig.Over, fig.Functions)
	mean := float64(fig.Sum) / float64(fig.Functions)
	fig.Mean = &mean
	for lang, vals := range byLang {
		sort.Ints(vals)
		lc := LangComplexity{Lang: lang, Functions: len(vals), P90: percentile(vals, 90), Max: vals[len(vals)-1]}
		for _, c := range vals {
			if c > ComplexityThreshold {
				lc.Over++
			}
		}
		fig.PerLanguage = append(fig.PerLanguage, lc)
	}
	sort.Slice(fig.PerLanguage, func(i, j int) bool {
		a, b := fig.PerLanguage[i], fig.PerLanguage[j]
		if a.Functions != b.Functions {
			return a.Functions > b.Functions
		}
		return a.Lang < b.Lang
	})
	fig.Top = append([]ComplexFunction(nil), in.Top...)
	sort.SliceStable(fig.Top, func(i, j int) bool {
		a, b := fig.Top[i], fig.Top[j]
		if a.Complexity != b.Complexity {
			return a.Complexity > b.Complexity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.StartLine < b.StartLine
	})
	if len(fig.Top) > TopComplexLimit {
		fig.Top = fig.Top[:TopComplexLimit]
	}
	return fig
}

// percentile is the nearest-rank p-th percentile of sorted (ascending,
// non-empty) values.
func percentile(sorted []int, p float64) int {
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}
