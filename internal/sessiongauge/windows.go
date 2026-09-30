package sessiongauge

import (
	"regexp"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
)

// Windows is a model-id -> context-window table built from a pricing
// catalog's economics (ModelWindows). The zero value is an empty table: every
// lookup is unknown.
type Windows map[string]int64

// ModelWindows builds the table from per-model economics keyed by model id
// (the node's feed rows or the org's stored economics map). A model whose
// economics carries no positive context_window_tokens is left out, so it
// reads as unknown rather than 0.
func ModelWindows(econ map[string]*pricingfeed.Economics) Windows {
	out := Windows{}
	for model, e := range econ {
		if e == nil || e.ContextWindowTokens == nil || *e.ContextWindowTokens <= 0 {
			continue
		}
		key := normalizeModel(model)
		if key == "" {
			continue
		}
		out[key] = *e.ContextWindowTokens
	}
	return out
}

// DocWindows builds the table from the org's pricing document's context
// windows (orgcontract.PricingPolicyDoc.ContextWindows, an unsigned display
// sibling of the signed body): the windows an ENROLLED node receives from its
// org, which the org took from the same feed economics its own session drawer
// reads (PolicyWindowList). An entry with no model or a non-positive window
// is left out (unknown, never 0).
func DocWindows(list []orgcontract.ModelContextWindow) Windows {
	out := Windows{}
	for _, e := range list {
		if e.Tokens <= 0 {
			continue
		}
		key := normalizeModel(e.Model)
		if key == "" {
			continue
		}
		out[key] = e.Tokens
	}
	return out
}

// PolicyWindowList is the SERVER half of DocWindows: it renders the org's
// WHOLE window table (every model its feed economics names, not only the
// price book's rows) as the document's context_windows list, sorted by model
// so the bytes, and therefore the document ETag, are stable. Non-positive
// windows and empty models are left out. DocWindows(PolicyWindowList(w))
// answers every WindowFor lookup exactly as w does.
func PolicyWindowList(w Windows) []orgcontract.ModelContextWindow {
	out := make([]orgcontract.ModelContextWindow, 0, len(w))
	for k, v := range w {
		key := normalizeModel(k)
		if v <= 0 || key == "" {
			continue
		}
		out = append(out, orgcontract.ModelContextWindow{Model: key, Tokens: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Model != out[j].Model {
			return out[i].Model < out[j].Model
		}
		return out[i].Tokens < out[j].Tokens
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

// MergeWindows composes window tables in PRECEDENCE order, the highest first
// (the node passes its org's policy windows, then its own feed's). The
// precedence is per LOOKUP, not per key: a lower layer's key is kept only
// when no higher layer already resolves that id through the WindowFor
// ladder, so for every model id
//
//	MergeWindows(a, b).WindowFor(m) == first non-zero of a.WindowFor(m), b.WindowFor(m)
//
// (pinned by TestMergeWindowsIsLayeredLookup). A plain key union would let a
// lower layer's exact dated key outrank a higher layer's undated one.
func MergeWindows(layers ...Windows) Windows {
	out := Windows{}
	for _, layer := range layers {
		above := make(Windows, len(out))
		for k, v := range out {
			above[k] = v
		}
		for k, v := range layer {
			if v <= 0 || above.WindowFor(k) > 0 {
				continue
			}
			out[k] = v
		}
	}
	return out
}

// windowKeyRules is the ordered model-id ladder WindowFor walks: the exact
// (normalized) id, then the id without a vendor route prefix
// ("anthropic/claude-x" -> "claude-x"), then without a trailing release date
// ("claude-x-20250929" -> "claude-x"). No family guessing past that: an id
// the catalog does not name reads as unknown.
var windowKeyRules = []func(string) string{
	func(m string) string { return m },
	stripVendorPrefix,
	func(m string) string { return stripDateSuffix(stripVendorPrefix(m)) },
}

// WindowFor returns the model's context window in tokens, 0 when the table
// does not name it.
func (w Windows) WindowFor(model string) int64 {
	m := normalizeModel(model)
	if m == "" || len(w) == 0 {
		return 0
	}
	for _, rule := range windowKeyRules {
		if v, ok := w[rule(m)]; ok && v > 0 {
			return v
		}
	}
	return 0
}

// normalizeModel is the catalog's key normalization (trim + lowercase, the
// org pricing package's NormalizeModel).
func normalizeModel(m string) string {
	return strings.ToLower(strings.TrimSpace(m))
}

// stripVendorPrefix drops a leading "vendor/" route prefix.
func stripVendorPrefix(m string) string {
	if i := strings.LastIndex(m, "/"); i >= 0 {
		return m[i+1:]
	}
	return m
}

// dateSuffix matches a trailing release date: -YYYYMMDD or -YYYY-MM-DD.
var dateSuffix = regexp.MustCompile(`-(\d{8}|\d{4}-\d{2}-\d{2})$`)

// stripDateSuffix drops a trailing release date.
func stripDateSuffix(m string) string {
	return dateSuffix.ReplaceAllString(m, "")
}
