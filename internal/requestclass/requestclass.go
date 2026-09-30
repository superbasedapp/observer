package requestclass

import (
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Values is the closed vocabulary in its canonical display order: the main
// conversation first, then the agentic classes, then the housekeeping ones.
// Summarize emits its per-class buckets in this order. Adding a class the
// vendor documents is a row here (and a models constant), nothing else.
var Values = []string{
	models.APIRequestClassMain,       // a turn of the main conversation
	models.APIRequestClassSubagent,   // a turn of a subagent
	models.APIRequestClassWorkflow,   // an agent running inside a workflow
	models.APIRequestClassCompaction, // the summarization request that compacts a conversation
	models.APIRequestClassAuxiliary,  // side requests: session titles, classifiers, summaries
}

// rank maps a vocabulary value to its position in Values.
var rank = func() map[string]int {
	m := make(map[string]int, len(Values))
	for i, v := range Values {
		m[v] = i
	}
	return m
}()

// Valid reports whether v is exactly one of the closed vocabulary's values.
func Valid(v string) bool {
	_, ok := rank[v]
	return ok
}

// Normalize returns v when it is a vocabulary value, else "" (stored as
// NULL). Matching is exact after trimming surrounding whitespace: the
// documented values are lowercase ASCII and a near-miss ("Main", "sub-agent")
// is never guessed at.
func Normalize(v string) string {
	v = strings.TrimSpace(v)
	if Valid(v) {
		return v
	}
	return ""
}

// Row is one COUNTED proxy turn of a session (a row the one session rule,
// sessionmsg.DeriveVerdicts, keeps), as the split reads it. Class is the
// stored request_class ("" for NULL); it is re-normalized here, so a caller
// may pass the raw column.
type Row struct {
	Class               string
	InputTokens         int64
	OutputTokens        int64
	CacheReadTokens     int64
	CacheCreationTokens int64
	// CostUSD is the turn's recorded proxy cost.
	CostUSD float64
}

// Bucket is one class's share of a session's counted proxy turns.
type Bucket struct {
	// Class is the vocabulary value; "" on the Unclassified bucket.
	Class               string  `json:"class"`
	Turns               int64   `json:"turns"`
	InputTokens         int64   `json:"input_tokens"`
	OutputTokens        int64   `json:"output_tokens"`
	CacheReadTokens     int64   `json:"cache_read_tokens"`
	CacheCreationTokens int64   `json:"cache_creation_tokens"`
	CostUSD             float64 `json:"cost_usd"`
}

// Split is a session's counted proxy turns split by request class.
//
// Classified is the honesty flag: false means NO counted turn carried a
// class (a client that never sends the hint header, or a node too old to
// ship it), and a surface then renders nothing - never "100% unclassified",
// which would read as a finding about the session rather than an absence of
// the signal.
type Split struct {
	Classified bool `json:"classified"`
	// Classes holds one bucket per class with at least one turn, in Values
	// order. Empty (never null) when Classified is false.
	Classes []Bucket `json:"classes"`
	// Unclassified aggregates the counted turns with no (or an unknown)
	// class; its Class is "".
	Unclassified Bucket `json:"unclassified"`
	// TotalTurns is every counted proxy turn, classified or not.
	TotalTurns int64 `json:"total_turns"`
}

// Summarize splits rows by request class. It returns nil when rows is empty
// (the session has no counted proxy turn, so there is nothing to split).
//
// Order-independent by construction, including the float cost sums: each
// bucket's rows are summed in a canonical order (cost, then the token
// counts), so two engines that load the same rows in different orders get
// bit-identical figures.
func Summarize(rows []Row) *Split {
	if len(rows) == 0 {
		return nil
	}
	sorted := make([]Row, len(rows))
	for i, r := range rows {
		r.Class = Normalize(r.Class)
		sorted[i] = r
	}
	sort.SliceStable(sorted, func(i, j int) bool { return lessRow(sorted[i], sorted[j]) })

	byClass := make([]Bucket, len(Values))
	for i, v := range Values {
		byClass[i].Class = v
	}
	out := &Split{Classes: []Bucket{}}
	for _, r := range sorted {
		out.TotalTurns++
		b := &out.Unclassified
		if i, ok := rank[r.Class]; ok {
			b = &byClass[i]
			out.Classified = true
		}
		b.Turns++
		b.InputTokens += r.InputTokens
		b.OutputTokens += r.OutputTokens
		b.CacheReadTokens += r.CacheReadTokens
		b.CacheCreationTokens += r.CacheCreationTokens
		b.CostUSD += r.CostUSD
	}
	for _, b := range byClass {
		if b.Turns > 0 {
			out.Classes = append(out.Classes, b)
		}
	}
	return out
}

// lessRow is the canonical summation order (see Summarize).
func lessRow(a, b Row) bool {
	switch {
	case a.Class != b.Class:
		return a.Class < b.Class
	case a.CostUSD != b.CostUSD:
		return a.CostUSD < b.CostUSD
	case a.InputTokens != b.InputTokens:
		return a.InputTokens < b.InputTokens
	case a.OutputTokens != b.OutputTokens:
		return a.OutputTokens < b.OutputTokens
	case a.CacheReadTokens != b.CacheReadTokens:
		return a.CacheReadTokens < b.CacheReadTokens
	default:
		return a.CacheCreationTokens < b.CacheCreationTokens
	}
}
