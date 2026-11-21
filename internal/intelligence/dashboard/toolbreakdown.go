package dashboard

import (
	"sort"

	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// SurfaceUnresolved is the by_surface bucket for action rows whose native
// tool name did not resolve to a taxonomy row — an empty raw_tool_name
// (the adapter never captured one), or a native name tooltax has no entry
// for. It is deliberately NOT one of tooltax.Surfaces(): "we don't know
// where this tool lives" is a different statement from "it lives in the
// harness", and collapsing the two would turn a capture gap into a claim.
//
// It is ALSO where the capped native-name pass parks its remainder (see
// breakdownNativeGroupCap): an action whose native name never reached the
// fold is, by definition, an action whose surface we did not resolve.
const SurfaceUnresolved = "unresolved"

// breakdownNativeGroupCap bounds the number of (tool, raw_tool_name)
// groups the surface pass will read.
//
// The live corpus holds ~300 distinct native tool names across all 30
// adapters (measured 2026-07-31, 321,675 action rows), so this cap is
// ~65× the real world and cannot trip on it. It exists because
// raw_tool_name is UNRESTRICTED free text written by whatever produced
// the log: a corpus where every action carries a unique native name
// would otherwise make the group count — in SQLite and in this process —
// O(actions) rather than O(vocabulary). The observation "~300 names" is
// not a bound, so this is the bound.
//
// The pass orders by COUNT(*) DESC, so if the cap ever bites, what
// survives is the mass of the corpus and what is dropped is the long
// tail of one-off names — which lands in SurfaceUnresolved via the
// remainder, keeping sum(by_surface) == total true and honest.
//
// A var rather than a const ONLY so a test can shrink it and exercise
// the over-cap path against the real handler instead of simulating it;
// nothing in production writes it.
var breakdownNativeGroupCap = 20000

// breakdownCoverage is the plan §4 "coverage-depth honesty" block: how
// many canonical categories this adapter's declared vocabulary can even
// EXPRESS, next to how many were actually observed in the window. Without
// it a shallow-capture adapter (12 of the 30 adapters emit only 2-5
// action types) reads as "doesn't use tools" rather than "we can't see
// what it does".
//
// ObservedCategories and ExpressibleCategories are NOT a numerator and a
// denominator. They are two independent facts about the same tool, and
// observed CAN exceed expressible — legitimately, not as a bug:
// tooltax's tool-less fallback rows and the global `mcp__*` glob resolve
// for every adapter, and failure/meta events are emitted by the harness
// rather than by any declared native tool. claude-code's declared
// vocabulary spans 8 categories while a window routinely observes 9.
// Rendering them as a ratio produces "9 of 8", which is why the client
// states them separately (see web/src/lib/actions.ts::coverageCaption).
type breakdownCoverage struct {
	// ObservedCategories is how many distinct canonical categories this
	// tool produced rows in, inside the window. Never truncated to the
	// declared vocabulary: a category that was really observed is a
	// fact, and hiding it would be the opposite of honest.
	ObservedCategories int `json:"observed_categories"`
	// ExpressibleCategories is how many canonical categories the tool's
	// declared native vocabulary covers (tooltax.CoverageDepth). Zero
	// when the tool has no declared vocabulary at all — see
	// VocabularyDeclared, which is what tells the two zeros apart.
	ExpressibleCategories int `json:"expressible_categories"`
	// ObservedBeyondDeclared is how many of the observed categories fall
	// OUTSIDE the declared vocabulary. It is what makes
	// ObservedCategories > ExpressibleCategories explicable rather than
	// impossible-looking, and it is why the two numbers must never be
	// formatted as one ratio.
	ObservedBeyondDeclared int `json:"observed_beyond_declared"`
	// CanonicalCategories is the size of the canonical category set, so
	// a client can render "8 of 10" without hard-coding 10.
	CanonicalCategories int `json:"canonical_categories"`
	// VocabularyDeclared reports whether tooltax carries any
	// tool-specific rows for this tool. False means the denominator is
	// unknown, NOT that the tool expresses nothing — an honest zero.
	VocabularyDeclared bool `json:"vocabulary_declared"`
}

// toolBreakdown is one row of /api/tools/breakdown's `tools` array. The
// tool/total/by_type keys are the pre-WP-T5 shape and are unchanged;
// by_category, by_surface and coverage are additive.
type toolBreakdown struct {
	Tool  string `json:"tool"`
	Total int    `json:"total"`
	// ByType is the raw per-action_type histogram (unchanged contract).
	ByType map[string]int `json:"by_type"`
	// ByCategory folds ByType through tooltax.CategoryForActionType —
	// the canonical like-to-like dimension. Computed at query time, never
	// stored, so a taxonomy fix applies to history immediately.
	ByCategory map[string]int `json:"by_category"`
	// BySurface counts by WHERE the native tool lives (builtin / mcp /
	// orchestration / meta), plus SurfaceUnresolved. Orthogonal to
	// category on purpose: cowork's `mcp__workspace__bash` is surface mcp
	// but category cmd. Always sums to Total.
	BySurface map[string]int `json:"by_surface"`
	// Coverage is the capture-depth honesty block.
	Coverage breakdownCoverage `json:"coverage"`
}

// breakdownAccumulator folds the two /api/tools/breakdown scans into the
// response rows, adding the canonical category + surface dimensions
// through tooltax.
//
// It is an ACCUMULATOR rather than a func([]group) on purpose: the
// handler streams rows into it and retains nothing, so this process's
// memory is O(tools × action types) + O(tools × surfaces) — bounded by
// the taxonomy — no matter how many groups the database returns.
type breakdownAccumulator struct {
	idx   map[string]*breakdownAcc
	order []string
}

type breakdownAcc struct {
	row *toolBreakdown
	// categories is the observed-category set behind
	// Coverage.ObservedCategories.
	categories map[string]struct{}
	// surfaceAttributed is how many actions the native-name pass placed
	// into a surface bucket. Total minus this is the remainder that goes
	// to SurfaceUnresolved, which is what keeps sum(by_surface) == total
	// even when the capped pass did not see every name.
	surfaceAttributed int
	// ordered records that this tool already took its place in the
	// output order (assigned by the totals pass only).
	ordered bool
}

func newBreakdownAccumulator() *breakdownAccumulator {
	return &breakdownAccumulator{idx: map[string]*breakdownAcc{}}
}

// ensure returns the accumulator row for a tool, creating it if needed.
// `counted` says whether the caller is the totals pass — only that pass
// contributes to the output ORDER, so the ordering contract does not
// depend on which pass ran first.
func (b *breakdownAccumulator) ensure(tool string, counted bool) *breakdownAcc {
	a, ok := b.idx[tool]
	if !ok {
		depth := tooltax.CoverageDepth(tool)
		a = &breakdownAcc{
			row: &toolBreakdown{
				Tool:       tool,
				ByType:     map[string]int{},
				ByCategory: map[string]int{},
				BySurface:  map[string]int{},
				Coverage: breakdownCoverage{
					ExpressibleCategories: depth,
					CanonicalCategories:   len(tooltax.Categories()),
					VocabularyDeclared:    depth > 0,
				},
			},
			categories: map[string]struct{}{},
		}
		b.idx[tool] = a
	}
	if counted && !a.ordered {
		a.ordered = true
		b.order = append(b.order, tool)
	}
	return a
}

// AddActionTypeCount folds one (tool, action_type) group — the exact,
// uncapped pass that owns Total, ByType and ByCategory.
func (b *breakdownAccumulator) AddActionTypeCount(tool, actionType string, n int) {
	a := b.ensure(tool, true)
	a.row.Total += n
	a.row.ByType[actionType] += n
	category := tooltax.CategoryForActionType(actionType)
	a.row.ByCategory[category] += n
	a.categories[category] = struct{}{}
}

// AddNativeCount folds one (tool, raw_tool_name) group — the capped pass
// that owns BySurface. Anything it never sees becomes the remainder that
// Rows() parks in SurfaceUnresolved. The native name is resolved under the
// tool's own vocabulary; AddNativeCountIn is the form for a group whose
// names belong to another tool's vocabulary.
func (b *breakdownAccumulator) AddNativeCount(tool, rawToolName string, n int) {
	b.AddNativeCountIn(tool, tool, rawToolName, n)
}

// AddNativeCountIn folds one (tool, raw_tool_name) group whose native name
// is classified under vocabulary rather than under tool: a cloud-agent
// connector whose sessions land under one tool while its tool calls carry
// another tool's names (Cline Cloud lands under cline, its calls carry
// cline-cli's names; cloudagents.VocabularyForSource). The counts still go
// to tool's row.
func (b *breakdownAccumulator) AddNativeCountIn(tool, vocabulary, rawToolName string, n int) {
	a := b.ensure(tool, false)
	a.row.BySurface[surfaceFor(vocabulary, rawToolName)] += n
	a.surfaceAttributed += n
}

// Rows finishes the fold: it resolves the coverage block, settles the
// surface remainder and applies the ordering contract (unchanged from
// pre-WP-T5: densest tool first, ties broken by first appearance in the
// totals query's own `ORDER BY tool` order).
//
// A tool seen ONLY by the native-name pass (Total == 0) is dropped: it
// contributes no counted action, and emitting a zero-total row would put
// a phantom adapter on the chart.
func (b *breakdownAccumulator) Rows() []toolBreakdown {
	out := make([]toolBreakdown, 0, len(b.order))
	for _, tool := range b.order {
		a := b.idx[tool]
		if a.row.Total <= 0 {
			continue
		}
		a.row.Coverage.ObservedCategories = len(a.categories)
		a.row.Coverage.ObservedBeyondDeclared = countBeyondDeclared(tool, a.categories)

		// sum(by_surface) == total is a pinned invariant. The surface
		// pass is capped and runs first (see handleToolsBreakdown), so
		// the remainder is normally >= 0; clamp anyway rather than
		// subtract into a negative bucket, because retention pruning
		// between the two scans could in principle shrink the totals.
		if remainder := a.row.Total - a.surfaceAttributed; remainder > 0 {
			a.row.BySurface[SurfaceUnresolved] += remainder
		}
		out = append(out, *a.row)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Total > out[j].Total })
	return out
}

// countBeyondDeclared counts observed categories that the tool's declared
// vocabulary does not cover. For an undeclared tool every observed
// category is beyond it — which is exactly why the client renders that
// case as "capture depth not mapped" instead of any comparison.
func countBeyondDeclared(tool string, observed map[string]struct{}) int {
	declared := make(map[string]struct{})
	for _, c := range tooltax.CategoriesForTool(tool) {
		declared[c] = struct{}{}
	}
	n := 0
	for c := range observed {
		if _, ok := declared[c]; !ok {
			n++
		}
	}
	return n
}

// surfaceFor resolves where a native tool lives, falling back to
// SurfaceUnresolved rather than guessing. vocabulary is the tool id whose
// native names rawToolName belongs to (normally the row's own tool).
func surfaceFor(vocabulary, rawToolName string) string {
	if rawToolName == "" {
		return SurfaceUnresolved
	}
	e, ok := tooltax.Resolve(vocabulary, rawToolName)
	if !ok || e.Surface == "" {
		return SurfaceUnresolved
	}
	return string(e.Surface)
}

// breakdownSurfaceKeys returns the by_surface key space in display order:
// the canonical surfaces, then the unresolved bucket. Emitted alongside
// the rows so a client renders the dimension in one fixed order instead
// of inventing its own.
func breakdownSurfaceKeys() []string {
	surfaces := tooltax.Surfaces()
	out := make([]string, 0, len(surfaces)+1)
	for _, s := range surfaces {
		out = append(out, string(s))
	}
	return append(out, SurfaceUnresolved)
}
