package anthropic

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceClaudeCodeUsage is the catalog id of the surface.
const SurfaceClaudeCodeUsage vs.SurfaceID = "anthropic.console.claude_code_usage"

// Claude Code Analytics vocabulary.
const (
	ClaudeCodeContract = "anthropic.console.claude_code_usage/v1 admin-api 2023-06-01 (2026-10-07)"

	// LegacyClaudeCodeKey is the ownership key of the legacy ccanalytics
	// poller's admin (Console) surface, which reads the same report. The
	// Enterprise kind reads another API and is not replaced here.
	LegacyClaudeCodeKey = "ccanalytics.admin"

	// ClaudeCodePageLimit is the documented maximum records per page.
	ClaudeCodePageLimit = 1000
	// ClaudeCodeMaxWindow: the report returns one UTC day per request.
	ClaudeCodeMaxWindow = day
)

// ClaudeCodeUsage returns the driver of anthropic.console.claude_code_usage.
//
// Contract (Claude Code Analytics API guide: "returns metrics for this
// single day only", limit up to 1000, an opaque page cursor, data older than
// one hour): GET /v1/organizations/usage_report/claude_code with starting_at
// as a UTC date. Each record is one actor's day: a user_actor with
// email_address or an api_actor with api_key_name, is_remote, core_metrics
// (sessions, lines added and removed, commits, pull requests), tool_actions
// keyed by tool name (accepted, rejected) and model_breakdown (tokens and an
// estimated cost in cents of USD). One record per actor per day per
// is_remote: a repeat is schema drift.
//
// The run's window picks the day: the UTC date of the window start moved
// back by settleLag, so the last hours of a day are read again after they
// settle and the restatement replaces the provisional facts.
func ClaudeCodeUsage() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:       SurfaceClaudeCodeUsage,
		Build:         buildClaudeCode,
		ParseResponse: parseClaudeCode,
		Canary:        canaryClaudeCode,
		Auth:          adminAuth,
		Headers:       headers(),
		ContentTypes:  []string{"application/json"},
		Supplies: []vs.DataClass{
			vs.ClassUsage, vs.ClassCost, vs.ClassLOC, vs.ClassCommits, vs.ClassSessions, vs.ClassAdoption,
		},
		LegacyPoller:    LegacyClaudeCodeKey,
		ContractVersion: ClaudeCodeContract,
		Tool:            Tool,
		MaxWindow:       ClaudeCodeMaxWindow,
		KnownPaths:      claudeCodeKnownPaths,
	}
}

func buildClaudeCode(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if w.From.IsZero() || !w.To.After(w.From) {
		return vendorapi.Request{}, fmt.Errorf("%s: a non-empty window is required", SurfaceClaudeCodeUsage)
	}
	q := map[string][]string{
		"starting_at": {w.From.UTC().Add(-settleLag).Format(time.DateOnly)},
		"limit":       {strconv.Itoa(ClaudeCodePageLimit)},
	}
	if err := pageQuery(SurfaceClaudeCodeUsage, q, cursor); err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: "/v1/organizations/usage_report/claude_code", Query: q}, nil
}

type ccNumberPair struct {
	Accepted *json.Number `json:"accepted"`
	Rejected *json.Number `json:"rejected"`
}

type ccRecord struct {
	Date  *string `json:"date"`
	Actor *struct {
		Type       *string `json:"type"`
		Email      *string `json:"email_address"`
		APIKeyName *string `json:"api_key_name"`
	} `json:"actor"`
	IsRemote    *bool `json:"is_remote"`
	CoreMetrics *struct {
		Sessions *json.Number `json:"num_sessions"`
		LOC      *struct {
			Added   *json.Number `json:"added"`
			Removed *json.Number `json:"removed"`
		} `json:"lines_of_code"`
		Commits *json.Number `json:"commits_by_claude_code"`
		PRs     *json.Number `json:"pull_requests_by_claude_code"`
	} `json:"core_metrics"`
	ModelBreakdown *[]ccModel              `json:"model_breakdown"`
	ToolActions    map[string]ccNumberPair `json:"tool_actions"`
}

type ccModel struct {
	Model  *string `json:"model"`
	Tokens *struct {
		Input         *json.Number `json:"input"`
		Output        *json.Number `json:"output"`
		CacheRead     *json.Number `json:"cache_read"`
		CacheCreation *json.Number `json:"cache_creation"`
	} `json:"tokens"`
	EstimatedCost *struct {
		Amount   *json.Number `json:"amount"`
		Currency *string      `json:"currency"`
	} `json:"estimated_cost"`
}

// toolNameRE bounds a tool_actions key before it becomes a fact dimension.
// A key outside it is never stored raw (plan 12A.7): its counts land under
// the feature tool:other, like an unknown enum value (plan 12A.5), and the
// canary reports the unknown key.
var toolNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// otherTool is the feature an unknown tool_actions key lands under.
const otherTool = "tool:other"

// ccActor resolves the record's identity: a user by e-mail (lower-cased) or an
// API key by its name. Any other actor shape is an identity change.
func ccActor(r ccRecord) (string, string, bool) {
	if r.Actor == nil || r.Actor.Type == nil {
		return "", "", false
	}
	switch *r.Actor.Type {
	case "user_actor":
		if e := vendorapi.FoldEmail(vendorapi.Str(r.Actor.Email)); e != "" {
			return "email", e, true
		}
	case "api_actor":
		if n := strings.TrimSpace(vendorapi.Str(r.Actor.APIKeyName)); n != "" {
			return "api_key_name", n, true
		}
	}
	return "", "", false
}

// ccFact is one metric of one record in micro-units.
type ccFact struct {
	metric, unit, model, feature string
	micros                       int64
}

// ccMetric is one row of the record metric table: a metric, its unit and
// where it is read from. Every row is required by the documented record.
type ccMetric struct {
	metric, unit string
	get          func(ccRecord) *json.Number
}

var ccCoreMetrics = []ccMetric{
	{"sessions", "count", func(r ccRecord) *json.Number { return r.CoreMetrics.Sessions }},
	{"lines_added", "lines", func(r ccRecord) *json.Number {
		if r.CoreMetrics.LOC == nil {
			return nil
		}
		return r.CoreMetrics.LOC.Added
	}},
	{"lines_removed", "lines", func(r ccRecord) *json.Number {
		if r.CoreMetrics.LOC == nil {
			return nil
		}
		return r.CoreMetrics.LOC.Removed
	}},
	{"commits", "count", func(r ccRecord) *json.Number { return r.CoreMetrics.Commits }},
	{"pull_requests", "count", func(r ccRecord) *json.Number { return r.CoreMetrics.PRs }},
}

// ccModelFacts reads one model_breakdown entry: four token counts and the
// estimated cost (an integer number of cents of USD).
func ccModelFacts(m ccModel) ([]ccFact, bool) {
	t, c := m.Tokens, m.EstimatedCost
	if m.Model == nil || *m.Model == "" || t == nil || c == nil || c.Amount == nil || c.Currency == nil ||
		!strings.EqualFold(*c.Currency, "USD") {
		return nil, false
	}
	var out []ccFact
	for _, x := range []struct {
		metric string
		n      *json.Number
	}{{"input_tokens", t.Input}, {"output_tokens", t.Output}, {"cache_read_tokens", t.CacheRead}, {"cache_write_tokens", t.CacheCreation}} {
		v, ok := count(x.n)
		if !ok {
			return nil, false
		}
		out = append(out, ccFact{metric: x.metric, unit: "tokens", model: *m.Model, micros: v})
	}
	cost, ok := vendorapi.DecimalMicros(c.Amount.String(), 2)
	if !ok {
		return nil, false
	}
	return append(out, ccFact{metric: "estimated_cost", unit: "usd", model: *m.Model, micros: cost}), true
}

// ccToolFacts reads tool_actions: accepted and rejected per documented tool
// name, every other key summed under tool:other.
func ccToolFacts(actions map[string]ccNumberPair) ([]ccFact, bool) {
	names := make([]string, 0, len(actions))
	for k := range actions {
		names = append(names, k)
	}
	sort.Strings(names)
	var out []ccFact
	var otherAcc, otherRej int64
	other := false
	for _, k := range names {
		a := actions[k]
		acc, ok1 := count(a.Accepted)
		rej, ok2 := count(a.Rejected)
		if !ok1 || !ok2 {
			return nil, false
		}
		if !toolNameRE.MatchString(k) || "tool:"+k == otherTool {
			other = true
			if otherAcc > math.MaxInt64-acc || otherRej > math.MaxInt64-rej {
				return nil, false
			}
			otherAcc, otherRej = otherAcc+acc, otherRej+rej
			continue
		}
		out = append(out,
			ccFact{metric: "tool_accepted", unit: "count", feature: "tool:" + k, micros: acc},
			ccFact{metric: "tool_rejected", unit: "count", feature: "tool:" + k, micros: rej},
		)
	}
	if other {
		out = append(out,
			ccFact{metric: "tool_accepted", unit: "count", feature: otherTool, micros: otherAcc},
			ccFact{metric: "tool_rejected", unit: "count", feature: otherTool, micros: otherRej},
		)
	}
	return out, true
}

// ccRecordFacts reads every metric of one record; false is schema drift.
func ccRecordFacts(r ccRecord) ([]ccFact, bool) {
	if r.CoreMetrics == nil || r.ModelBreakdown == nil {
		return nil, false
	}
	var out []ccFact
	for _, m := range ccCoreMetrics {
		v, ok := count(m.get(r))
		if !ok {
			return nil, false
		}
		out = append(out, ccFact{metric: m.metric, unit: m.unit, micros: v})
	}
	seen := map[string]bool{}
	for _, m := range *r.ModelBreakdown {
		facts, ok := ccModelFacts(m)
		if !ok || seen[*m.Model] {
			return nil, false
		}
		seen[*m.Model] = true
		out = append(out, facts...)
	}
	tools, ok := ccToolFacts(r.ToolActions)
	if !ok {
		return nil, false
	}
	return append(out, tools...), true
}

func parseClaudeCode(r vendorapi.Response) (vendorapi.Page, error) {
	var doc reportDoc[ccRecord]
	next, err := envelope(SurfaceClaudeCodeUsage, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{NextCursor: next, SourceRecords: len(*doc.Data)}
	seen := map[string]bool{}
	for i, rec := range *doc.Data {
		if rec.Date == nil {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceClaudeCodeUsage, "data[%d].date is missing", i)
		}
		at, err := time.Parse(time.RFC3339Nano, *rec.Date)
		if err != nil || !at.UTC().Equal(at.UTC().Truncate(day)) {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceClaudeCodeUsage, "data[%d].date is not a UTC day", i)
		}
		start := at.UTC()
		kind, id, ok := ccActor(rec)
		if !ok {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceClaudeCodeUsage, "data[%d].actor is not a documented actor", i)
		}
		segment := ""
		if rec.IsRemote != nil {
			segment = "local"
			if *rec.IsRemote {
				segment = "remote"
			}
		}
		key := start.Format(time.DateOnly) + "\x00" + kind + "\x00" + id + "\x00" + segment
		if seen[key] {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceClaudeCodeUsage, "data[%d] repeats an actor day and segment", i)
		}
		seen[key] = true
		facts, ok := ccRecordFacts(rec)
		if !ok {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceClaudeCodeUsage, "data[%d] misses or mistypes a documented metric", i)
		}
		for _, f := range facts {
			page.Facts = append(page.Facts, vendorapi.FactRow{
				IntervalStart: start, IntervalEnd: start.Add(day), SourceTZ: "UTC", CoverageDomain: "anthropic.console.claude_code",
				IdentityKind: kind, Identity: id, ModelRaw: f.model, Feature: f.feature, TrafficSegment: segment,
				Metric: f.metric, Unit: f.unit, ValueMicros: f.micros,
			})
		}
	}
	return page, nil
}

// canaryClaudeCode reports drift that does not fail the page: a tool_actions
// key outside the documented name shape (landed as tool:other).
func canaryClaudeCode(p vendorapi.Page) []vendorapi.DriftSignal {
	for _, f := range p.Facts {
		if f.Feature == otherTool {
			return []vendorapi.DriftSignal{{Path: "data[].tool_actions.*", Kind: "unknown_key"}}
		}
	}
	return nil
}

// claudeCodeKnownPaths are the documented response paths (the corpus field
// ledgers of the Claude Code report).
var claudeCodeKnownPaths = []string{
	"data", "data[]", "data[].actor", "data[].actor.api_key_name", "data[].actor.email_address", "data[].actor.type",
	"data[].core_metrics", "data[].core_metrics.commits_by_claude_code", "data[].core_metrics.lines_of_code",
	"data[].core_metrics.lines_of_code.added", "data[].core_metrics.lines_of_code.removed",
	"data[].core_metrics.num_sessions", "data[].core_metrics.pull_requests_by_claude_code",
	"data[].customer_type", "data[].date", "data[].is_remote", "data[].model_breakdown",
	"data[].model_breakdown[]", "data[].model_breakdown[].estimated_cost",
	"data[].model_breakdown[].estimated_cost.amount", "data[].model_breakdown[].estimated_cost.currency",
	"data[].model_breakdown[].model", "data[].model_breakdown[].tokens",
	"data[].model_breakdown[].tokens.cache_creation", "data[].model_breakdown[].tokens.cache_read",
	"data[].model_breakdown[].tokens.input", "data[].model_breakdown[].tokens.output",
	"data[].organization_id", "data[].subscription_type", "data[].terminal_type", "data[].tool_actions",
	"has_more", "next_page",
}
