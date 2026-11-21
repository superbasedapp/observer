package codequality

import (
	"sort"
	"time"
)

// Symbol is one codeintel function or method the duplication roll-up
// considers: its node id, file, name, kind and line span.
type Symbol struct {
	ID        int64
	File      string
	Name      string
	Kind      string
	StartLine int
	EndLine   int
}

// Lines is the symbol's inclusive line span, 0 when the span is unknown
// (codeintel's heuristic parser stores end_line 0 for an approximate span).
func (s Symbol) Lines() int {
	if s.StartLine <= 0 || s.EndLine < s.StartLine {
		return 0
	}
	return s.EndLine - s.StartLine + 1
}

// Bucket is one codeintel_minhash row: a node's hash for one LSH band.
type Bucket struct {
	NodeID int64
	Band   int
	Hash   int64
}

// IndexFacts is what the store knows about a project's codeintel index.
type IndexFacts struct {
	// Key is the codeintel project key the rows were read under ("" when
	// none matched).
	Key string
	// IndexedFiles counts the project's files with status 'indexed'.
	IndexedFiles int
	// LastIndexedAt is the newest indexed_at among them.
	LastIndexedAt time.Time
	// Archived: the project's index was moved to the cold archive.
	Archived bool
	// NotInBuild: this binary was built without the codeintel component
	// (-tags sbo_omit_codeintel), so the index cannot be read.
	NotInBuild bool
	// Truncated: the symbol read hit MaxSymbols.
	Truncated bool
}

// DuplicationInput is the store's answer for one project.
type DuplicationInput struct {
	Index   IndexFacts
	Symbols []Symbol
	Buckets []Bucket
}

// Duplication roll-up rules. EligibleKinds and MinSymbolLines decide which
// symbols count; MinSharedBands is the near-clone threshold (codeintel
// writes 12 bands of 4 rows, internal/codeintel/semantic, so two bodies
// with shingle Jaccard similarity s share 12*s^4 bands on average: 6 shared
// bands is about s >= 0.84); a bucket with more than MaxBucketMembers
// symbols is boilerplate every body shares and is skipped, counted in
// SkippedBuckets.
var EligibleKinds = []string{"function", "method"}

// Duplication thresholds and bounds.
const (
	MinSymbolLines   = 6
	MinSharedBands   = 6
	TotalBands       = 12
	MaxBucketMembers = 64
	// MaxSymbols bounds the symbol read in the store seam.
	MaxSymbols = 200_000
	// TopGroups / MembersPerGroup bound the groups the page lists.
	TopGroups       = 5
	MembersPerGroup = 6
)

// CloneMember is one symbol of a clone group as the page lists it.
type CloneMember struct {
	Name      string `json:"name"`
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

// CloneGroup is one group of near-clone symbols.
type CloneGroup struct {
	Size    int           `json:"size"`
	Lines   int           `json:"lines"`
	Members []CloneMember `json:"members"`
}

// DuplicationFigure is the project's duplication numbers.
type DuplicationFigure struct {
	EligibleSymbols int
	ClonedSymbols   int
	// EligibleLines / ClonedLines are line UNIONS per file (a nested
	// function's lines are counted once).
	EligibleLines int
	ClonedLines   int
	Groups        int
	// SymbolShare / LineShare are ClonedX / EligibleX * 100; nil when the
	// denominator is 0.
	SymbolShare    *float64
	LineShare      *float64
	TopGroups      []CloneGroup
	SkippedBuckets int
}

// eligible reports whether s counts for the roll-up.
func eligible(s Symbol) bool {
	if s.Lines() < MinSymbolLines {
		return false
	}
	for _, k := range EligibleKinds {
		if s.Kind == k {
			return true
		}
	}
	return false
}

// overlapping reports whether a and b are the same file and their spans
// intersect (one nested in the other): such a pair is not a clone pair.
func overlapping(a, b Symbol) bool {
	return a.File == b.File && a.StartLine <= b.EndLine && b.StartLine <= a.EndLine
}

type bucketKey struct {
	band int
	hash int64
}

type pairKey struct{ a, b int64 }

// Duplicate computes the duplication figure from a project's symbols and
// their LSH band buckets: two eligible symbols that share at least
// MinSharedBands band buckets (and do not overlap in one file) are a
// near-clone pair; pairs are joined into groups (union-find). Every member
// of a group counts as cloned, the "original" included (the convention of
// Sonar's duplicated lines). The result is approximate by construction:
// MinHash estimates similarity, it does not compare bodies.
func Duplicate(symbols []Symbol, buckets []Bucket) DuplicationFigure {
	byID := make(map[int64]Symbol, len(symbols))
	for _, s := range symbols {
		if eligible(s) {
			byID[s.ID] = s
		}
	}
	var fig DuplicationFigure
	fig.EligibleSymbols = len(byID)
	if len(byID) == 0 {
		return fig
	}
	members := map[bucketKey][]int64{}
	seen := map[bucketKey]map[int64]bool{}
	for _, b := range buckets {
		if _, ok := byID[b.NodeID]; !ok {
			continue
		}
		k := bucketKey{b.Band, b.Hash}
		if seen[k] == nil {
			seen[k] = map[int64]bool{}
		}
		if seen[k][b.NodeID] {
			continue
		}
		seen[k][b.NodeID] = true
		members[k] = append(members[k], b.NodeID)
	}
	shared := map[pairKey]int{}
	for _, ids := range members {
		if len(ids) < 2 {
			continue
		}
		if len(ids) > MaxBucketMembers {
			fig.SkippedBuckets++
			continue
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for i := 0; i < len(ids); i++ {
			for j := i + 1; j < len(ids); j++ {
				shared[pairKey{ids[i], ids[j]}]++
			}
		}
	}
	uf := newUnionFind()
	for p, n := range shared {
		if n >= MinSharedBands && !overlapping(byID[p.a], byID[p.b]) {
			uf.union(p.a, p.b)
		}
	}
	groups := map[int64][]Symbol{}
	for id := range uf.parent {
		root := uf.find(id)
		groups[root] = append(groups[root], byID[id])
	}

	var all, cloned []Symbol
	for _, s := range byID {
		all = append(all, s)
	}
	var list []CloneGroup
	for _, g := range groups {
		if len(g) < 2 {
			continue
		}
		sort.Slice(g, func(i, j int) bool {
			if g[i].File != g[j].File {
				return g[i].File < g[j].File
			}
			return g[i].StartLine < g[j].StartLine
		})
		cloned = append(cloned, g...)
		cg := CloneGroup{Size: len(g), Lines: unionLines(g)}
		for i, s := range g {
			if i == MembersPerGroup {
				break
			}
			cg.Members = append(cg.Members, CloneMember{Name: s.Name, File: s.File, StartLine: s.StartLine, EndLine: s.EndLine})
		}
		list = append(list, cg)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Lines != list[j].Lines {
			return list[i].Lines > list[j].Lines
		}
		if list[i].Size != list[j].Size {
			return list[i].Size > list[j].Size
		}
		a, b := list[i].Members[0], list[j].Members[0]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.StartLine < b.StartLine
	})
	fig.Groups = len(list)
	if len(list) > TopGroups {
		list = list[:TopGroups]
	}
	fig.TopGroups = list
	fig.ClonedSymbols = len(cloned)
	fig.EligibleLines = unionLines(all)
	fig.ClonedLines = unionLines(cloned)
	fig.SymbolShare = Percent(fig.ClonedSymbols, fig.EligibleSymbols)
	fig.LineShare = Percent(fig.ClonedLines, fig.EligibleLines)
	return fig
}

// unionLines counts the distinct lines the symbols span, per file.
func unionLines(ss []Symbol) int {
	byFile := map[string][][2]int{}
	for _, s := range ss {
		if s.Lines() == 0 {
			continue
		}
		byFile[s.File] = append(byFile[s.File], [2]int{s.StartLine, s.EndLine})
	}
	var total int
	for _, spans := range byFile {
		sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
		curS, curE := spans[0][0], spans[0][1]
		for _, sp := range spans[1:] {
			if sp[0] <= curE+1 {
				if sp[1] > curE {
					curE = sp[1]
				}
				continue
			}
			total += curE - curS + 1
			curS, curE = sp[0], sp[1]
		}
		total += curE - curS + 1
	}
	return total
}

// unionFind is a plain disjoint-set over node ids.
type unionFind struct{ parent map[int64]int64 }

func newUnionFind() *unionFind { return &unionFind{parent: map[int64]int64{}} }

func (u *unionFind) find(x int64) int64 {
	if _, ok := u.parent[x]; !ok {
		u.parent[x] = x
	}
	for u.parent[x] != x {
		u.parent[x] = u.parent[u.parent[x]]
		x = u.parent[x]
	}
	return x
}

func (u *unionFind) union(a, b int64) {
	ra, rb := u.find(a), u.find(b)
	if ra == rb {
		return
	}
	if ra < rb {
		u.parent[rb] = ra
	} else {
		u.parent[ra] = rb
	}
}
