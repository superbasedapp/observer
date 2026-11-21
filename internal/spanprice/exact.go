package spanprice

// exact.go - the exact-cost precedence (plan W4-2, contract
// docs/plans/plane-a-sdk-buildout/contracts/cost-source.md). D24 (Rules)
// decides between computed and reported; an EXACT observation (the org AI
// gateway's or the machine proxy's tokens on the provider's own response)
// beats both (principle 7). Nothing is thrown away: the losing numbers and
// the deltas stay in ExactDetail.

// The exact sources.
const (
	// SourceGatewayExact: the org AI gateway served the call.
	SourceGatewayExact Source = "gateway_exact"
	// SourceProxyExact: the machine's proxy served the call.
	SourceProxyExact Source = "proxy_exact"
)

// Sources lists every cost_source value in display order, the unpriced ""
// last (contract section 1).
var Sources = []Source{SourceGatewayExact, SourceProxyExact, SourceComputed, SourceReported, SourceNone}

// IsExact reports whether s is one of the exact sources.
func IsExact(s Source) bool { return s == SourceGatewayExact || s == SourceProxyExact }

// Label is the display label of a cost source (contract section 1).
func Label(s Source) string {
	switch s {
	case SourceGatewayExact:
		return "Gateway exact"
	case SourceProxyExact:
		return "Proxy exact"
	case SourceComputed:
		return "Computed"
	case SourceReported:
		return "Reported"
	default:
		return "Unpriced"
	}
}

// Exact is one exact observation joined to a span.
type Exact struct {
	// Source is SourceGatewayExact or SourceProxyExact.
	Source Source
	// USD is the exact cost (the sum when several requests joined one span):
	// for the gateway, the org price book pricing the gateway's exact tokens
	// (ruling D27), never the gateway rate card's estimate.
	USD float64
	// Unpriced is set when the price book does not price the observation (or
	// one of several summed requests): no exact cost exists, so D24 decides
	// and the observation's facts are only recorded (ruling D27).
	Unpriced bool
	// Tokens are the exact tokens as observed (the sum over the requests).
	Tokens *ExactTokens
	// RateCardUSD is the gateway rate card's estimate, kept for reference
	// only (D27); nil when the card had no rate.
	RateCardUSD *float64
	// RequestIDs are the gateway request ids (at most MaxRequestIDs kept);
	// Requests is their full count.
	RequestIDs      []string
	Requests        int
	RateCardVersion string
	// JoinRule is the join rule that matched (gwcostjoin.Rules).
	JoinRule string
}

// ExactTokens are the token counts an exact source observed on the
// provider's response, as the provider reported them.
type ExactTokens struct {
	Input      int64 `json:"input"`
	Output     int64 `json:"output"`
	CacheRead  int64 `json:"cache_read"`
	CacheWrite int64 `json:"cache_write"`
}

// MaxRequestIDs bounds ExactDetail.GatewayRequestIDs.
const MaxRequestIDs = 16

// ExactDetail is cost_detail with the exact fields (contract section 3). The
// embedded Detail keeps D24's numbers under their existing JSON names.
type ExactDetail struct {
	Detail
	GatewayExact      *float64 `json:"gateway_exact,omitempty"`
	ProxyExact        *float64 `json:"proxy_exact,omitempty"`
	BaseSource        *Source  `json:"base_source,omitempty"`
	DeltaReported     *float64 `json:"delta_reported,omitempty"`
	DeltaComputed     *float64 `json:"delta_computed,omitempty"`
	GatewayRequestIDs []string `json:"gateway_request_ids,omitempty"`
	GatewayRequests   int      `json:"gateway_requests,omitempty"`
	RateCardVersion   string   `json:"rate_card_version,omitempty"`
	JoinRule          string   `json:"join_rule,omitempty"`
	// D27: the gateway's exact tokens, its rate card estimate (reference
	// only, never the cost) and whether the price book left it unpriced.
	GatewayTokens      *ExactTokens `json:"gateway_tokens,omitempty"`
	GatewayRateCardUSD *float64     `json:"gateway_rate_card_usd,omitempty"`
	GatewayUnpriced    bool         `json:"gateway_unpriced,omitempty"`
}

// ExactResult is a span's recorded cost after the exact rule.
type ExactResult struct {
	CostUSD *float64
	Source  Source
	// DeltaUSD is exact minus reported (cost_delta_usd); nil unless the
	// source is exact and a reported cost exists.
	DeltaUSD *float64
	Detail   ExactDetail
}

// ExactRule is one row of the exact precedence table.
type ExactRule struct {
	Name string
	When func(e *Exact) bool
}

// ExactRules is contract section 2 row 1, walked before D24: the first row
// that matches decides. Rows 2-4 are Rules (D24).
var ExactRules = []ExactRule{
	{Name: "a priced exact observation wins", When: func(e *Exact) bool { return e != nil && IsExact(e.Source) && !e.Unpriced }},
	{Name: "an unpriced exact observation: D24 decides, its facts are kept", When: func(e *Exact) bool { return e != nil && IsExact(e.Source) }},
	{Name: "no exact observation: D24 decides", When: func(*Exact) bool { return true }},
}

// exactRule returns the index of the first ExactRules row matching e.
func exactRule(e *Exact) int {
	for i, r := range ExactRules {
		if r.When(e) {
			return i
		}
	}
	return len(ExactRules) - 1
}

// WithExact applies the exact rule on top of a D24 result. A nil exact (or
// one with a non-exact source) keeps base; an unpriced one keeps base's cost
// and records its facts (D27: never $0, never the rate card's estimate). The
// deltas are never computed against a number that is not there.
func WithExact(base Result, e *Exact) ExactResult {
	out := ExactResult{CostUSD: base.CostUSD, Source: base.Source, Detail: ExactDetail{Detail: base.Detail}}
	rule := exactRule(e)
	if rule == 2 {
		return out
	}
	bs := base.Source
	out.Detail.BaseSource = &bs
	out.Detail.JoinRule = e.JoinRule
	if e.Source == SourceGatewayExact {
		out.Detail.GatewayRequests = e.Requests
		ids := e.RequestIDs
		if len(ids) > MaxRequestIDs {
			ids = ids[:MaxRequestIDs]
		}
		out.Detail.GatewayRequestIDs = append([]string(nil), ids...)
		out.Detail.RateCardVersion = e.RateCardVersion
		out.Detail.GatewayTokens = e.Tokens
		out.Detail.GatewayRateCardUSD = e.RateCardUSD
	}
	if rule == 1 {
		out.Detail.GatewayUnpriced = e.Source == SourceGatewayExact
		return out
	}
	usd := e.USD
	out.CostUSD = &usd
	out.Source = e.Source
	if e.Source == SourceGatewayExact {
		out.Detail.GatewayExact = &usd
	} else {
		out.Detail.ProxyExact = &usd
	}
	if r := base.Detail.Reported; r != nil {
		d := usd - *r
		out.DeltaUSD = &d
		out.Detail.DeltaReported = &d
	}
	if c := base.Detail.Computed; c != nil {
		d := usd - *c
		out.Detail.DeltaComputed = &d
	}
	return out
}

// BaseFromStored rebuilds the D24 result of a span from what is stored: its
// cost_source, cost_usd and the D24 fields of its cost_detail. A stored
// exact source falls back to the detail's base (a re-join of a span that
// was joined before). It is how a joiner that never saw the span's tokens
// still keeps every number.
func BaseFromStored(source Source, costUSD *float64, d Detail, base *Source) Result {
	res := Result{Source: source, Detail: d}
	if IsExact(source) {
		res.Source = SourceNone
		if base != nil {
			res.Source = *base
		}
	}
	switch res.Source {
	case SourceComputed:
		if res.Detail.Computed == nil && costUSD != nil && !IsExact(source) {
			v := *costUSD
			res.Detail.Computed = &v
		}
		res.CostUSD = res.Detail.Computed
	case SourceReported:
		if res.Detail.Reported == nil && costUSD != nil && !IsExact(source) {
			v := *costUSD
			res.Detail.Reported = &v
		}
		res.CostUSD = res.Detail.Reported
	default:
		res.Source = SourceNone
		res.CostUSD = nil
	}
	return res
}

// Provenance summarizes the cost sources of a trace's cost-bearing spans
// (contract section 5).
type Provenance struct {
	Label    string         `json:"label"`
	Complete bool           `json:"complete"`
	Sources  map[string]int `json:"sources"`
	// modelSpans counts the ModelSpan spans (AddModelSpan); with no
	// cost-bearing span either, Finish labels the trace no_model_calls.
	modelSpans int
}

// UnpricedKey is the Provenance.Sources key of the unpriced spans.
const UnpricedKey = "unpriced"

// NewProvenance returns an empty provenance with every source key present.
func NewProvenance() Provenance {
	p := Provenance{Sources: map[string]int{}}
	for _, s := range Sources {
		p.Sources[sourceKey(s)] = 0
	}
	return p
}

// Add counts one cost-bearing span of source s.
func (p *Provenance) Add(s Source) {
	if p.Sources == nil {
		*p = NewProvenance()
	}
	p.Sources[sourceKey(s)]++
}

// AddModelSpan counts one span that names a model on a model-call kind
// (ModelSpan), whether or not it is cost-bearing.
func (p *Provenance) AddModelSpan() {
	if p.Sources == nil {
		*p = NewProvenance()
	}
	p.modelSpans++
}

// Finish sets Label and Complete from the counts. A trace with no
// cost-bearing span and no model span made no model call: it is labelled
// ProvenanceNoModelCalls (and complete), never "unpriced" (L-21).
func (p *Provenance) Finish() {
	if p.Sources == nil {
		*p = NewProvenance()
	}
	p.Label = ProvenanceLabel(p.Sources)
	p.Complete = p.Sources[UnpricedKey] == 0
	if p.modelSpans == 0 && p.bearing() == 0 {
		p.Label = ProvenanceNoModelCalls
	}
}

// bearing is the number of cost-bearing spans counted.
func (p *Provenance) bearing() int {
	n := 0
	for _, c := range p.Sources {
		n += c
	}
	return n
}

func sourceKey(s Source) string {
	if s == SourceNone {
		return UnpricedKey
	}
	return string(s)
}

// Provenance labels.
const (
	ProvenanceUnpriced = "unpriced"
	ProvenanceMixed    = "mixed"
	// ProvenanceNoModelCalls labels a trace that made no model call (no
	// cost-bearing span and no span naming a model): there is nothing to
	// price, which is not the same as a call the price book could not price
	// (L-21). Its cost_usd is null and it is complete.
	ProvenanceNoModelCalls = "no_model_calls"
)

// ProvenanceRule is one row of the trace label table.
type ProvenanceRule struct {
	Name  string
	When  func(priced map[string]int) bool
	Label func(priced map[string]int) string
}

// ProvenanceRules is contract section 5's label table, walked top-down over
// the PRICED counts (the unpriced key removed).
var ProvenanceRules = []ProvenanceRule{
	{
		Name:  "no priced span",
		When:  func(p map[string]int) bool { return len(p) == 0 },
		Label: func(map[string]int) string { return ProvenanceUnpriced },
	},
	{
		Name: "every priced span one source",
		When: func(p map[string]int) bool { return len(p) == 1 },
		Label: func(p map[string]int) string {
			for k := range p {
				return k
			}
			return ProvenanceUnpriced
		},
	},
	{
		Name:  "several sources",
		When:  func(map[string]int) bool { return true },
		Label: func(map[string]int) string { return ProvenanceMixed },
	},
}

// ProvenanceLabel walks ProvenanceRules over counts.
func ProvenanceLabel(counts map[string]int) string {
	priced := map[string]int{}
	for k, n := range counts {
		if k != UnpricedKey && n > 0 {
			priced[k] = n
		}
	}
	for _, r := range ProvenanceRules {
		if r.When(priced) {
			return r.Label(priced)
		}
	}
	return ProvenanceMixed
}

// CostBearing reports whether a span carries cost facts (contract section
// 5): a model-call kind (CostKind) with token counts or a cost. A chain,
// agent or HTTP span is not, even when it restates its children's usage
// (L-03); nor is a model-call span that names a model but reports no usage
// and no cost (L-07: LlamaIndex records _prepare_chat_with_tools and the
// predict wrapper as LLM spans that call nothing). Such a span still counts
// as a ModelSpan, so a trace whose calls all went unreported reads
// "unpriced", not "no_model_calls".
func CostBearing(kind string, tokens int64, costUSD *float64, source Source) bool {
	if !CostKind(kind) {
		return false
	}
	return tokens > 0 || source != SourceNone || (costUSD != nil && *costUSD != 0)
}
