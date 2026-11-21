package warp

import (
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// Harness usage surface.
const (
	SurfaceHarnessUsage vs.SurfaceID = "warp.agent_api.run_harness_usage"

	HarnessUsageContract = "warp.agent_api.run_harness_usage/v1 " + contract
)

// Harness usage vocabulary.
const (
	// HarnessUsageClass is the snapshot class of one run's harness usage
	// read (available or not); its subject is the run id.
	HarnessUsageClass = "warp.run_harness_usage"
	// HarnessUsageNamespace keys the run's native counters: one row per run,
	// re-landed with a higher revision (the capture sequence) as it runs.
	HarnessUsageNamespace = "warp.run.harness"
	// The envelope harness values (HarnessUsageEnvelope discriminator).
	EnvelopeClaudeCode = "CLAUDE_CODE"
	EnvelopeCodex      = "CODEX"
	// Flags on the usage row.
	FlagHarness         = "harness"
	FlagCoverage        = "coverage_status"
	FlagInputBasis      = "input_basis"
	FlagOutputBasis     = "output_basis"
	FlagCache1h         = "cache_creation_1h"
	FlagCaptureSequence = "capture_sequence"
	FlagAbsent          = "absent"
	// Input and output bases: Claude Code's input_tokens excludes the cache
	// counters ("cache counters are not added to input_tokens") and its
	// output has no reasoning split; Codex's input_tokens includes
	// cached_input_tokens and output_tokens includes reasoning_output_tokens
	// (the OpenAI convention; the schema says the categories "may overlap").
	// The driver reports the native counters as given; netting is the
	// consumer's.
	BasisNetOfCache        = "net_of_cache"
	BasisIncludesCached    = "includes_cached"
	BasisNoReasoningSplit  = "no_reasoning_split"
	BasisIncludesReasoning = "includes_reasoning"
	// CoverageUnavailable is the tokenStatus of a snapshot with no measured
	// token counts.
	CoverageUnavailable = "unavailable"
)

// RunHarnessUsage returns the driver of warp.agent_api.run_harness_usage.
//
// Contract (OpenAPI getRunHarnessUsage): GET
// /api/v1/agent/runs/{runId}/harness-usage, {run_id, conversation_id,
// available, age_seconds, usage}, usage being the CLAUDE_CODE or CODEX
// envelope {metricsVersion, harness, executionId, captureSequence,
// capturedAt, snapshot{coverage{tokenStatus, toolStatus}, payload{usage,
// attribution, toolCalls}}}. Every read lands one warp.run_harness_usage
// snapshot (available, harness, coverage); a measured snapshot also lands
// one usage row of native cumulative counters keyed by the run id, revision
// the capture sequence, model the single attributed model (none when the
// attribution names several or none). A null counter is unmeasured, never
// zero: it is named in the "absent" flag and its field stays 0.
func RunHarnessUsage() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceHarnessUsage,
		Build:           buildHarnessUsage,
		ParseResponse:   parseHarnessUsage,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassUsage},
		ClosedDTO:       true,
		ContractVersion: HarnessUsageContract,
		KnownPaths:      harnessUsageKnownPaths,
	}
}

func buildHarnessUsage(p vendorapi.Params, _ vendorapi.Window, _ string) (vendorapi.Request, error) {
	path, err := runPath(SurfaceHarnessUsage, p, "/harness-usage")
	if err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: path}, nil
}

// tokenUsage is the union of ClaudeTokenUsage and CodexTokenUsage.
type tokenUsage struct {
	InputTokens              *num `json:"input_tokens"`
	OutputTokens             *num `json:"output_tokens"`
	CacheReadInputTokens     *num `json:"cache_read_input_tokens"`
	CacheCreationInputTokens *num `json:"cache_creation_input_tokens"`
	CacheCreation            *struct {
		Ephemeral1h *num `json:"ephemeral_1h_input_tokens"`
	} `json:"cache_creation"`
	CachedInputTokens     *num `json:"cached_input_tokens"`
	CacheWriteInputTokens *num `json:"cache_write_input_tokens"`
	ReasoningOutputTokens *num `json:"reasoning_output_tokens"`
}

type harnessDoc struct {
	RunID     *string `json:"run_id"`
	Available *bool   `json:"available"`
	Usage     *struct {
		Harness         *string `json:"harness"`
		CaptureSequence *num    `json:"captureSequence"`
		CapturedAt      *string `json:"capturedAt"`
		Snapshot        *struct {
			Coverage *struct {
				TokenStatus *string `json:"tokenStatus"`
			} `json:"coverage"`
			Payload *struct {
				Usage       *tokenUsage           `json:"usage"`
				Attribution *[]harnessAttribution `json:"attribution"`
			} `json:"payload"`
		} `json:"snapshot"`
	} `json:"usage"`
}

// harnessAttribution is one entry of a snapshot payload's attribution.
type harnessAttribution struct {
	Model *string `json:"model"`
}

// harnessBases is the input and output basis of each envelope.
var harnessBases = map[string][2]string{
	EnvelopeClaudeCode: {BasisNetOfCache, BasisNoReasoningSplit},
	EnvelopeCodex:      {BasisIncludesCached, BasisIncludesReasoning},
}

func parseHarnessUsage(r vendorapi.Response) (vendorapi.Page, error) {
	if err := status200(SurfaceHarnessUsage, r); err != nil {
		return vendorapi.Page{}, err
	}
	var doc harnessDoc
	if err := decode(r.Body, &doc); err != nil {
		return vendorapi.Page{}, drift(SurfaceHarnessUsage, "body does not decode as the documented GetRunHarnessUsageResponse")
	}
	id := str(doc.RunID)
	if !idRE.MatchString(id) {
		return vendorapi.Page{}, drift(SurfaceHarnessUsage, "required field run_id is missing or not an id")
	}
	if want := r.Params[ParamRunID]; want != "" && want != id {
		return vendorapi.Page{}, drift(SurfaceHarnessUsage, "run_id is not the run the request asked for")
	}
	if doc.Available == nil {
		return vendorapi.Page{}, drift(SurfaceHarnessUsage, "required field available is missing")
	}
	snap := vendorapi.VendorSnapshot{Class: HarnessUsageClass, Subject: id, Body: map[string]string{"available": strconv.FormatBool(*doc.Available)}}
	out := vendorapi.Page{SourceRecords: 1}
	u := doc.Usage
	if !*doc.Available || u == nil {
		out.Snapshots = append(out.Snapshots, snap)
		return out, nil
	}
	harness := str(u.Harness)
	bases, ok := harnessBases[harness]
	if !ok {
		return vendorapi.Page{}, drift(SurfaceHarnessUsage, "usage.harness is not a documented envelope")
	}
	at, ok := rfc3339(u.CapturedAt)
	if !ok {
		return vendorapi.Page{}, drift(SurfaceHarnessUsage, "usage.capturedAt is not an RFC 3339 timestamp")
	}
	seq, present, ok := counter(u.CaptureSequence)
	if !present || !ok {
		return vendorapi.Page{}, drift(SurfaceHarnessUsage, "usage.captureSequence is not a sequence number")
	}
	if u.Snapshot == nil || u.Snapshot.Coverage == nil || u.Snapshot.Payload == nil {
		return vendorapi.Page{}, drift(SurfaceHarnessUsage, "usage.snapshot is missing its coverage or payload")
	}
	status := strings.ToLower(str(u.Snapshot.Coverage.TokenStatus))
	if !tokenRE.MatchString(status) {
		return vendorapi.Page{}, drift(SurfaceHarnessUsage, "usage.snapshot.coverage.tokenStatus is missing")
	}
	snap.Body["harness"], snap.Body["coverage_status"] = strings.ToLower(harness), status
	snap.Body["captured_at"] = at.Format(time.RFC3339)
	out.Snapshots = append(out.Snapshots, snap)
	tu := u.Snapshot.Payload.Usage
	if status == CoverageUnavailable || tu == nil {
		return out, nil
	}
	row := vendorapi.UsageRow{
		JoinKind: UsageJoinKind, JoinNamespace: HarnessUsageNamespace, JoinValue: id, At: at, SessionRef: id,
		Revision: seq, IdentityKind: IdentityCaller, Identity: IdentityCallerValue,
		Flags: map[string]string{
			FlagHarness: strings.ToLower(harness), FlagCoverage: status, FlagInputBasis: bases[0], FlagOutputBasis: bases[1],
			FlagCaptureSequence: strconv.FormatInt(seq, 10),
		},
	}
	measured, err := harnessCounters(harness, tu, &row)
	if err != nil {
		return vendorapi.Page{}, err
	}
	if measured == 0 {
		return out, nil // nothing measured: absent, never zero
	}
	if err := harnessCache1h(harness, tu, &row); err != nil {
		return vendorapi.Page{}, err
	}
	row.Model = harnessModel(u.Snapshot.Payload.Attribution)
	out.Usage = append(out.Usage, row)
	return out, nil
}

// harnessCounters lands the envelope's native counters on row and names
// every unmeasured one in the absent flag. It returns how many counters
// were measured.
func harnessCounters(harness string, tu *tokenUsage, row *vendorapi.UsageRow) (int, error) {
	cacheWrite := tu.CacheCreationInputTokens
	cacheRead := tu.CacheReadInputTokens
	if harness == EnvelopeCodex {
		cacheWrite, cacheRead = tu.CacheWriteInputTokens, tu.CachedInputTokens
	}
	var absent []string
	measured := 0
	for _, c := range []struct {
		name string
		v    *num
		dst  *int64
	}{
		{"input", tu.InputTokens, &row.InputTokens},
		{"output", tu.OutputTokens, &row.OutputTokens},
		{"cache_read", cacheRead, &row.CacheReadTokens},
		{"cache_write", cacheWrite, &row.CacheWriteTokens},
		{"reasoning", tu.ReasoningOutputTokens, &row.ReasoningTokens},
	} {
		v, present, ok := counter(c.v)
		if !ok {
			return 0, drift(SurfaceHarnessUsage, "usage counter %s is not a whole non-negative count", c.name)
		}
		if !present {
			if c.name != "reasoning" || harness == EnvelopeCodex {
				absent = append(absent, c.name)
			}
			continue
		}
		measured++
		*c.dst = v
	}
	if measured > 0 && len(absent) > 0 {
		row.Flags[FlagAbsent] = strings.Join(absent, ",")
	}
	return measured, nil
}

// harnessCache1h flags a Claude Code envelope's one-hour cache-write count.
func harnessCache1h(harness string, tu *tokenUsage, row *vendorapi.UsageRow) error {
	cc := tu.CacheCreation
	if cc == nil || harness != EnvelopeClaudeCode {
		return nil
	}
	v, present, ok := counter(cc.Ephemeral1h)
	if !ok {
		return drift(SurfaceHarnessUsage, "usage counter cache_creation.ephemeral_1h_input_tokens is not a count")
	}
	if present {
		row.Flags[FlagCache1h] = strconv.FormatInt(v, 10)
	}
	return nil
}

// harnessModel returns the single attributed model, or "" when the
// attribution names several or none (or the one it names is too long).
func harnessModel(a *[]harnessAttribution) string {
	if a == nil {
		return ""
	}
	models := map[string]bool{}
	for _, e := range *a {
		if m := str(e.Model); m != "" {
			models[m] = true
		}
	}
	if len(models) != 1 {
		return ""
	}
	for m := range models {
		if len(m) <= vendorapi.MaxIDLen {
			return m
		}
	}
	return ""
}
