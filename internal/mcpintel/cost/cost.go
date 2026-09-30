// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package cost

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
)

// TokenizerVersion names the estimator every number in this package comes
// from: ceil(bytes/4) over canonical (compact) JSON, the
// internal/cachetrack.EstimateTokens text heuristic. It is persisted beside
// every estimate (mcp_audit.tokenizer_version) so a later estimator change
// never silently re-denominates stored rows.
const TokenizerVersion = "sbo-bytes4-v1" //nolint:gosec // G101 false positive: tokenizer version label, not a credential

// tokenizerKind is the cachetrack block kind the estimate is asked for: a
// text-scaled kind (tool descriptors and results are JSON text).
const tokenizerKind = "text"

// Attribution methods (the mcp_audit.attribution_method CHECK, R11.9).
const (
	// MethodDirect: the estimate belongs to exactly this call (its own tool
	// descriptor, its own result).
	MethodDirect = "direct"
	// MethodAllocated: a shared cost split across several tools by weight
	// (a catalogue listing's result, allocated across the tools it lists).
	MethodAllocated = "allocated"
	// MethodInferred: no per-tool descriptor was available; the schema share
	// is a stand-in (the server's average descriptor) or absent.
	MethodInferred = "inferred"
)

// Attribution confidences (the mcp_audit.attribution_confidence CHECK - the
// same exact | inferred | none vocabulary correlation uses).
const (
	ConfidenceExact    = "exact"
	ConfidenceInferred = "inferred"
	ConfidenceNone     = "none"
)

// Methods and Confidences are the closed vocabularies, in CHECK order.
var (
	Methods     = []string{MethodDirect, MethodAllocated, MethodInferred}
	Confidences = []string{ConfidenceExact, ConfidenceInferred, ConfidenceNone}
)

// EstimateTokens is the token estimate of canonical bytes b (0 for none).
func EstimateTokens(b []byte) int64 {
	return int64(cachetrack.EstimateTokens(tokenizerKind, b))
}

// TokensForBytes is EstimateTokens for a byte COUNT (the content-free
// result_size_bytes a completion record carries at every capture level):
// ceil(n/4), 0 for n <= 0. Pinned equal to EstimateTokens by a test, so the
// two can never disagree about the same bytes.
func TokensForBytes(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return (n + 3) / 4
}

// Catalog is one approved snapshot's schema overhead: native tool name ->
// the estimated tokens of that tool's model-facing descriptor.
type Catalog map[string]int64

// Total is the whole catalogue's schema overhead.
func (c Catalog) Total() int64 {
	var t int64
	for _, v := range c {
		t += v
	}
	return t
}

// descriptor is the model-facing projection of one MCP tool descriptor: the
// fields an MCP client puts in a model's tools[] definition. annotations /
// outputSchema / title are client-side metadata and are not counted.
type descriptor struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// CatalogFromToolsJSON estimates every descriptor of a canonical tools_json
// array (mcp_server_snapshot.tools_json). An empty input is an empty
// catalogue; a malformed one is an error (the caller then attributes with
// no catalogue - honestly 'none', never a guess).
func CatalogFromToolsJSON(raw []byte) (Catalog, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return Catalog{}, nil
	}
	var tools []descriptor
	if err := json.Unmarshal(raw, &tools); err != nil {
		return nil, fmt.Errorf("cost.CatalogFromToolsJSON: %w", err)
	}
	out := make(Catalog, len(tools))
	for _, t := range tools {
		if t.Name == "" {
			continue
		}
		if len(t.InputSchema) > 0 {
			var buf bytes.Buffer
			if json.Compact(&buf, t.InputSchema) == nil {
				t.InputSchema = buf.Bytes()
			}
		}
		b, err := json.Marshal(t)
		if err != nil {
			return nil, fmt.Errorf("cost.CatalogFromToolsJSON: %s: %w", t.Name, err)
		}
		out[t.Name] = EstimateTokens(b)
	}
	return out, nil
}

// CallKind is the shape of the governed call, resolved by the caller from
// its method table at the boundary (never a method-name switch here).
type CallKind string

// Call kinds.
const (
	// KindToolCall is a call that invokes ONE tool (tools/call).
	KindToolCall CallKind = "tool_call"
	// KindCatalogue is a tool catalogue listing (tools/list): its result is
	// the schema overhead of every tool it lists.
	KindCatalogue CallKind = "catalogue"
	// KindOther is every other governed call (resources/read, prompts/get,
	// completion, tasks, the non-tool catalogues): its result belongs to it
	// and it carries no tool schema.
	KindOther CallKind = "other"
)

// AttributeInput is one call, as the PDP resolved it.
type AttributeInput struct {
	Kind CallKind
	// Tool is the called tool's weight key (tools/call), in the same key
	// space as Weights.
	Tool string
	// Weights is the per-tool schema catalogue the call can see, keyed by the
	// caller's tool key (the MCP gateway keys it "<server id>/<native tool>",
	// the mcp_tool budget scope ref). nil / empty = no approved snapshot.
	Weights map[string]int64
}

// Attribution is the pre-result half of an estimate: how the call's cost is
// attributed and what its quota reservation holds before the result exists.
type Attribution struct {
	Method     string
	Confidence string
	// SchemaTokens is the schema-overhead estimate charged to this call.
	SchemaTokens int64
	// ReserveTokens is what a quota reservation holds before the result is
	// known: the schema share, or for a catalogue listing the catalogue
	// total (a listing is its catalogue).
	ReserveTokens int64
	// Weights is carried for an ALLOCATED attribution only: the weights its
	// result is split by at settlement.
	Weights map[string]int64
	// TokenizerVersion names the estimator.
	TokenizerVersion string
}

// Zero reports an attribution nothing stamped (no method).
func (a Attribution) Zero() bool { return a.Method == "" }

// attributionRule is one row of the attribution table.
type attributionRule struct {
	name  string
	match func(in AttributeInput) bool
	apply func(in AttributeInput) Attribution
}

// attributionRules is walked top-down; the first matching row wins and the
// last row matches everything (the table is total).
var attributionRules = []attributionRule{
	{
		// The call's own descriptor is in the approved snapshot: its schema
		// overhead is exactly that descriptor's estimate.
		name:  "tool_call_described",
		match: func(in AttributeInput) bool { _, ok := in.Weights[in.Tool]; return in.Kind == KindToolCall && ok },
		apply: func(in AttributeInput) Attribution {
			w := in.Weights[in.Tool]
			return Attribution{Method: MethodDirect, Confidence: ConfidenceExact, SchemaTokens: w, ReserveTokens: w}
		},
	},
	{
		// A catalogue listing with a known catalogue: its result is the
		// listed tools' schema overhead, ALLOCATED across them by weight. The
		// schema column stays 0 so the listing is never counted twice (its
		// result already is the schemas).
		name:  "catalogue_allocated",
		match: func(in AttributeInput) bool { return in.Kind == KindCatalogue && total(in.Weights) > 0 },
		apply: func(in AttributeInput) Attribution {
			return Attribution{
				Method: MethodAllocated, Confidence: ConfidenceInferred,
				ReserveTokens: total(in.Weights), Weights: copyWeights(in.Weights),
			}
		},
	},
	{
		// A tool call whose own descriptor is absent from a known catalogue:
		// the server's AVERAGE descriptor stands in.
		name:  "tool_call_undescribed",
		match: func(in AttributeInput) bool { return in.Kind == KindToolCall && len(in.Weights) > 0 },
		apply: func(in AttributeInput) Attribution {
			avg := ceilDiv(total(in.Weights), int64(len(in.Weights)))
			return Attribution{Method: MethodInferred, Confidence: ConfidenceInferred, SchemaTokens: avg, ReserveTokens: avg}
		},
	},
	{
		// A tool call with no approved snapshot at all: nothing to attribute
		// the schema from - honestly none, never a guessed figure.
		name:  "tool_call_no_catalogue",
		match: func(in AttributeInput) bool { return in.Kind == KindToolCall },
		apply: func(AttributeInput) Attribution {
			return Attribution{Method: MethodInferred, Confidence: ConfidenceNone}
		},
	},
	{
		// Every other call (and a catalogue with no catalogue): its result is
		// its own and it carries no tool schema.
		name:  "own_result",
		match: func(AttributeInput) bool { return true },
		apply: func(AttributeInput) Attribution {
			return Attribution{Method: MethodDirect, Confidence: ConfidenceExact}
		},
	},
}

// Attribute walks the attribution table and stamps TokenizerVersion.
func Attribute(in AttributeInput) Attribution {
	a, _ := attribute(in)
	return a
}

// attribute also returns the matching row's name (tests).
func attribute(in AttributeInput) (Attribution, string) {
	for _, r := range attributionRules {
		if r.match(in) {
			a := r.apply(in)
			a.TokenizerVersion = TokenizerVersion
			return a, r.name
		}
	}
	return Attribution{Method: MethodDirect, Confidence: ConfidenceExact, TokenizerVersion: TokenizerVersion}, "unreachable"
}

// Estimate is a settled estimate: the attribution plus the result half.
type Estimate struct {
	Attribution
	// ResultBytes is the content-free result size; ResultTokens its estimate.
	ResultBytes  int64
	ResultTokens int64
	// TotalTokens = SchemaTokens + ResultTokens: what the call is charged.
	TotalTokens int64
	// Shares is the per-tool split of TotalTokens for an ALLOCATED call (sums
	// exactly to TotalTokens); nil otherwise.
	Shares map[string]int64
	// Estimated is always true: nothing here is metered.
	Estimated bool
}

// Settle completes an attribution with the call's result size.
func Settle(a Attribution, resultBytes int64) Estimate {
	if resultBytes < 0 {
		resultBytes = 0
	}
	e := Estimate{Attribution: a, ResultBytes: resultBytes, ResultTokens: TokensForBytes(resultBytes), Estimated: true}
	if e.TokenizerVersion == "" {
		e.TokenizerVersion = TokenizerVersion
	}
	e.TotalTokens = e.SchemaTokens + e.ResultTokens
	if a.Method == MethodAllocated && len(a.Weights) > 0 {
		e.Shares = Allocate(e.TotalTokens, a.Weights)
	}
	return e
}

// Allocate splits total across the weighted keys in proportion to their
// weights by the largest-remainder method: every share is floor(total *
// w / W) and the remaining units go, one each, to the largest fractional
// remainders (ties broken by key, so the split is deterministic). The shares
// always sum to exactly total. Zero or negative weights take nothing unless
// every weight is zero, in which case the split is even.
func Allocate(total int64, weights map[string]int64) map[string]int64 {
	if len(weights) == 0 {
		return nil
	}
	keys := make([]string, 0, len(weights))
	var sum int64
	for k, w := range weights {
		keys = append(keys, k)
		if w > 0 {
			sum += w
		}
	}
	sort.Strings(keys)
	out := make(map[string]int64, len(keys))
	if total <= 0 {
		for _, k := range keys {
			out[k] = 0
		}
		return out
	}
	eff := func(k string) int64 {
		if sum == 0 {
			return 1
		}
		if w := weights[k]; w > 0 {
			return w
		}
		return 0
	}
	denom := sum
	if denom == 0 {
		denom = int64(len(keys))
	}
	type rem struct {
		key string
		r   int64
	}
	rems := make([]rem, 0, len(keys))
	var given int64
	for _, k := range keys {
		num := total * eff(k)
		share := num / denom
		out[k] = share
		given += share
		rems = append(rems, rem{k, num % denom})
	}
	sort.SliceStable(rems, func(i, j int) bool {
		if rems[i].r != rems[j].r {
			return rems[i].r > rems[j].r
		}
		return rems[i].key < rems[j].key
	})
	for i := int64(0); i < total-given; i++ {
		out[rems[i%int64(len(rems))].key]++
	}
	return out
}

func total(w map[string]int64) int64 {
	var t int64
	for _, v := range w {
		if v > 0 {
			t += v
		}
	}
	return t
}

func copyWeights(w map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(w))
	for k, v := range w {
		out[k] = v
	}
	return out
}

func ceilDiv(a, b int64) int64 {
	if b <= 0 {
		return 0
	}
	return (a + b - 1) / b
}
