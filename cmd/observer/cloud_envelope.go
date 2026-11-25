//go:build !sbo_omit_cloud_intelligence

package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudevidence"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// --- shared evidence build -------------------------------------------------

// cloudEnvelopeResult (the build output) lives in the core file
// cloudenvelope_core.go, so the org intel rail compiles without this file.

// buildCloudEnvelope is THE one build path preview, consent, and the sync
// rebuild closure all funnel through, so preview bytes == the bytes consent
// binds == the bytes sync uploads (plan §7 invariant 4). It refuses org /
// unknown / missing sessions with honest copy before building.
//
// DETERMINISM. Every input is read from the DB and every derivation is a pure
// function of those rows; nothing here consults the clock. Two builds of an
// unchanged session therefore produce byte-identical bytes and equal digests,
// which is what makes the rebuild-and-compare check at send time meaningful.
//
// pricer may be nil. When it is non-nil and the session recorded no per-turn
// cost (the common case: only a couple of adapters write estimated_cost_usd),
// it prices the summed token bundle so the envelope carries an honest cost
// figure instead of a misleading 0.
func buildCloudEnvelope(ctx context.Context, st *store.Store, sessionID string, purpose cloudcontract.Purpose, pricer *cost.Engine) (cloudEnvelopeResult, error) {
	return buildCloudEnvelopeConfigured(ctx, st, sessionID, purpose, pricer, 0)
}

// buildCloudEnvelopeFor is buildCloudEnvelope with the RECEIPT's field classes
// made explicit. The classes decide one thing: whether a structural build
// carries the single first-prompt excerpt (the "Title only" level's own
// disclosure - see perUploadFieldClasses and cloudevidence.BuildOptions.
// GrantedFieldClasses). The send-time rebuild passes the classes the outbox
// item's receipt actually bound, so a receipt minted before the class existed
// rebuilds byte-identically to what the developer previewed - the digest
// re-check would refuse the send otherwise, and rightly so.
func buildCloudEnvelopeFor(ctx context.Context, st *store.Store, sessionID string, purpose cloudcontract.Purpose, fieldClasses []string, pricer *cost.Engine) (cloudEnvelopeResult, error) {
	return buildCloudEnvelopeWithSettings(ctx, st, sessionID, purpose, fieldClasses, pricer, nil)
}

func buildCloudEnvelopeWithSettings(ctx context.Context, st *store.Store, sessionID string, purpose cloudcontract.Purpose, fieldClasses []string, pricer *cost.Engine, settings *store.CloudEvidenceSettings) (cloudEnvelopeResult, error) {
	return buildPlaneEnvelope(ctx, st, envelopePlane{plane: cloudcontract.PlanePersonal}, sessionID, purpose, fieldClasses, pricer, settings)
}

// envelopePlane names the plane an envelope is built for. The org plane
// (Cloud Intelligence parity phase 2, the B1 rail) carries the org id so the
// project pseudonym it mints is SCOPED to that org: a project with both
// personal and org sessions never sends the same pseudonym to both planes.
type envelopePlane struct {
	plane cloudcontract.Plane
	orgID string
}

// eligible applies the plane's authority rule (INV-1) before anything is read.
func (p envelopePlane) eligible(sessionID string, auth dataauthority.Classification) error {
	if p.plane == cloudcontract.PlaneOrg {
		if !auth.EligibleForOrgEnrichment() {
			return fmt.Errorf("session %q is classified %q, not org - only sessions captured while enrolled go to the organization (plane separation)", sessionID, auth.Authority)
		}
		return nil
	}
	if !auth.EligibleForPersonalEnrichment() {
		return fmt.Errorf("session %q is classified %q, not personal - org and unknown sessions are never sent to the personal cloud (plane separation)", sessionID, auth.Authority)
	}
	return nil
}

// projectKey is the local key the project pseudonym is minted under.
func (p envelopePlane) projectKey(projectID int64) string {
	if p.plane == cloudcontract.PlaneOrg {
		return "org:" + p.orgID + ":" + strconv.FormatInt(projectID, 10)
	}
	return strconv.FormatInt(projectID, 10)
}

// buildPlaneEnvelope is THE one build path for both planes (preview ==
// consent == upload bytes on each).
func buildPlaneEnvelope(ctx context.Context, st *store.Store, ep envelopePlane, sessionID string, purpose cloudcontract.Purpose, fieldClasses []string, pricer *cost.Engine, settings *store.CloudEvidenceSettings) (cloudEnvelopeResult, error) {
	settings, settingsJSON, settingsErr := cloudSettingsForPurpose(settings, purpose)
	if settingsErr != nil {
		return cloudEnvelopeResult{}, settingsErr
	}

	purposeSet, err := cloudPurposeSet(purpose)
	if err != nil {
		return cloudEnvelopeResult{}, err
	}
	classes := make([]cloudcontract.FieldClass, 0, len(fieldClasses))
	for _, c := range fieldClasses {
		classes = append(classes, cloudcontract.FieldClass(c))
	}
	auth, ok, err := st.SessionAuthority(ctx, sessionID)
	if err != nil {
		return cloudEnvelopeResult{}, fmt.Errorf("read session authority: %w", err)
	}
	if !ok {
		return cloudEnvelopeResult{}, fmt.Errorf("session %q not found, or its data-authority is unknown - unknown-authority sessions are never eligible for cloud enrichment", sessionID)
	}
	if err := ep.eligible(sessionID, auth); err != nil {
		return cloudEnvelopeResult{}, err
	}

	// CONTENT GATE. The text substrate is READ AT ALL only under the
	// bounded-context-enrichment purpose, so a structural build cannot leak an
	// excerpt even if a later refactor mis-wires the builder: there is nothing
	// in the input to leak. The builder applies the same gate again (belt and
	// braces) and scrubs everything it does include.
	//
	// The one narrower read: a STRUCTURAL build whose receipt binds the
	// first_user_prompt_excerpt class reads the prompt rows only - no assistant
	// text, no failure messages - so the "Title only" level can carry the
	// first prompt its consent screen has always named (2026-09-16).
	wantText := purpose == cloudcontract.PurposeContextEnrichment
	wantFirstPrompt := !wantText && purpose == cloudcontract.PurposeStructuralInsights &&
		cloudClassesInclude(classes, cloudcontract.FieldClassFirstUserPrompt)

	// The two WHOLE-SESSION populations are STREAMED, not loaded: the store hands
	// each row to a pure accumulator inside the snapshot and keeps nothing (A5,
	// A8). `outcomes` sees every run_command row of the session — so the last
	// build is the true last one however deep the session is — and `failures`
	// every recorded failure, so the error classes describe the session rather
	// than a window of it.
	//
	// `harness` sees the opening of every user_prompt row, so the activity mix
	// counts a harness-written message (a background task notification, another
	// agent's hand-back, a system reminder) as what it is, never as the
	// developer's prompt (T-966).
	var (
		outcomes cloudevidence.OutcomeTally
		failures cloudevidence.ErrorClassTally
		harness  cloudevidence.HarnessPromptTally
	)
	req := store.CloudEvidenceRequest{
		MaxActions:         cloudcontract.MaxActions,
		EvidenceSettings:   settings,
		IncludeTexts:       wantText,
		IncludeFirstPrompt: wantFirstPrompt,
		Commands:           outcomes.AddCommand,
		PromptHeads:        harness.Add,
	}
	if settings != nil {
		req.MaxActions = max(1, settings.ActionSummaries)
		if !settings.Outcomes {
			req.Commands = nil
		}
	}
	if wantText && (settings == nil || settings.FailureClasses > 0) {
		req.Failures = failures.Add
	}
	// The store does the striding: it selects an even sample across the session's
	// WHOLE ordered action population in SQL and reports the true population
	// separately (facts.ActionCount), so MaxActions is the SAMPLE SIZE, not a scan
	// bound. Milestones do not come from this sample at all — they come from the
	// kind-bounded population below; outcomes come from the stream above.
	//
	// ONE SNAPSHOT covers all of it, texts included, so a concurrent write cannot
	// make two rebuilds of the same session disagree (A7).
	bundle, ok, err := st.LoadCloudEvidenceBundle(ctx, sessionID, req)
	if err != nil {
		return cloudEnvelopeResult{}, fmt.Errorf("load session facts: %w", err)
	}
	if !ok {
		return cloudEnvelopeResult{}, fmt.Errorf("session %q not found", sessionID)
	}
	facts := bundle.Facts

	cloudSession, err := st.GetOrCreateCloudSessionPseudonym(ctx, sessionID)
	if err != nil {
		return cloudEnvelopeResult{}, fmt.Errorf("session pseudonym: %w", err)
	}
	cloudProject, err := st.GetOrCreateCloudProjectPseudonym(ctx, ep.projectKey(facts.ProjectID))
	if err != nil {
		return cloudEnvelopeResult{}, fmt.Errorf("project pseudonym: %w", err)
	}

	start := cloudSessionStart(facts)
	// TWO populations, deliberately. `sampled` is the bounded action list the
	// envelope carries; `milestoneRows` is the kind-bounded population the
	// FIRST-OCCURRENCE milestones are read from. Deriving milestones from the
	// sample would report what the SAMPLE contained rather than what the session
	// did. The outcome COUNTS come from neither — they come from the streamed
	// run_command population, which has no window at all.
	sampled := cloudRawActions(facts.Actions, start)
	milestoneRows := cloudRawActions(facts.OutcomeActions, start)

	input := cloudevidence.SessionInput{
		CloudSessionID:  cloudSession,
		CloudProjectID:  cloudProject,
		Tool:            facts.Tool,
		ModelFamily:     facts.Model,
		StartedAtBucket: cloudStartedBucket(start),
		DurationSeconds: cloudDurationSeconds(facts),
		Metrics:         cloudMetrics(facts, pricer),
		Actions:         cloudActions(sampled),
		ActionsTotal:    facts.ActionCount,
		Milestones:      cloudevidence.DeriveMilestones(milestoneRows),
		Outcomes:        outcomes.Outcomes(),
		ActivityMix:     harness.Reclassify(cloudActivityMix(facts.ActivityMix)),
		Authority:       auth,
	}

	cloudApplyEvidenceSettings(&input, settings)
	switch {
	case settings != nil && (wantText || wantFirstPrompt):
		input.Excerpts = cloudevidence.SelectExcerptsWithSettings(cloudevidence.SessionTexts{
			UserPrompts:       bundle.Texts.UserPrompts,
			AssistantMessages: bundle.Texts.AssistantMessages,
			ErrorTally:        &failures,
		}, cloudevidence.ExcerptSelection{
			UserMessages: settings.UserMessages, AssistantMessages: settings.AssistantMessages,
			FailureClasses: settings.FailureClasses, Bytes: settings.ExcerptBytes,
		})
	case wantText:
		texts := bundle.Texts
		input.Excerpts = cloudevidence.SelectExcerpts(cloudevidence.SessionTexts{
			UserPrompts:           texts.UserPrompts,
			FinalAssistantMessage: texts.FinalAssistantMessage,
			// The failure population was classified as it streamed, so the
			// classes describe every failure the session recorded — not the
			// head+tail window a materialized list would have been.
			ErrorTally: &failures,
		}, false)
	case wantFirstPrompt:
		// The title-only lane (ruling R8): exactly the set the narrowed
		// first_user_prompt_excerpt class authorizes - the first REAL prompt,
		// harness injections skipped. The hosted gate admits that one excerpt
		// under the structural purpose alone
		// (cloudcontract.Envelope.ContextIsFirstPromptOnly); the job still runs
		// as a full enrichment server-side, which is fine - the disclosure is
		// what narrows, not the result.
		input.Excerpts = cloudevidence.SelectExcerpts(cloudevidence.SessionTexts{
			UserPrompts: bundle.Texts.UserPrompts,
		}, true)
	}

	env, err := cloudevidence.BuildEnvelope(input, ep.plane, cloudevidence.BuildOptions{
		Scrubber:            scrub.New(),
		ScrubberVersion:     cloudScrubberVersion,
		GrantedPurposes:     purposeSet,
		GrantedFieldClasses: classes,
	})
	if err != nil {
		return cloudEnvelopeResult{}, fmt.Errorf("build envelope: %w", err)
	}
	bytesOut, digests, err := cloudevidence.Serialize(env)
	if err != nil {
		return cloudEnvelopeResult{}, fmt.Errorf("serialize envelope: %w", err)
	}
	return cloudEnvelopeResult{
		EvidenceSettingsJSON: settingsJSON,
		Bytes:                bytesOut,
		Digests:              digests,
		CloudSession:         cloudSession,
		Actions:              len(env.Actions),
		Excerpts:             len(env.Context),
		Purpose:              purpose,
		Envelope:             env,
	}, nil
}

// cloudSessionStart resolves the session's start instant: the sessions row's
// own started_at when it has one, else the earliest observed action. A session
// row without a start is common on adapters that only stamp it at end.
func cloudSessionStart(f store.CloudSessionFacts) time.Time {
	if !f.StartedAt.IsZero() {
		return f.StartedAt
	}
	return f.FirstActionAt
}

// cloudRawActions maps store action facts into the pure layer's RawAction,
// stamping each one's elapsed seconds from the session start (clamped at 0 —
// an action can be recorded microseconds BEFORE the session row's start).
func cloudRawActions(in []store.CloudActionFact, start time.Time) []cloudevidence.RawAction {
	out := make([]cloudevidence.RawAction, 0, len(in))
	for _, a := range in {
		elapsed := 0
		if !start.IsZero() && !a.Timestamp.IsZero() && a.Timestamp.After(start) {
			elapsed = int(a.Timestamp.Sub(start).Seconds())
		}
		kind := a.Kind
		if kind == "" {
			kind = "action"
		}
		// A harness-written "user prompt" is sampled as what it is (T-966).
		kind = cloudevidence.ReclassifyPromptKind(kind, a.Target)
		out = append(out, cloudevidence.RawAction{
			Ref:            a.Ref,
			Kind:           kind,
			Success:        a.Success,
			Target:         a.Target,
			RawToolName:    a.RawToolName,
			ElapsedSeconds: elapsed,
		})
	}
	return out
}

// cloudMetrics maps the store's numeric substrate onto the envelope's metric
// block, clamping every ratio into the contract's range rather than letting a
// stray stored value fail the whole build.
//
// COST HONESTY. estimated_cost_usd is 0 for most adapters (only a couple record
// a provider-reported per-turn cost), so a summed 0 would claim "this session
// was free". When a pricer is available and nothing was recorded, the session is
// priced PER TOKEN ROW — each row on its own model, at its own timestamp — and
// the money is summed. The recorded figure still wins whenever it is non-zero.
//
// PER ROW, NOT PER SESSION. Pricing the summed bundle as one turn was wrong in
// two ways at once (F5): several models price input in LONG-CONTEXT BANDS, so a
// session of 3 × 150k-token turns crossed a 272k threshold it never actually
// crossed and was billed the surcharge; and a session that used two models — or
// that straddled a rate change — was priced entirely on one model's current rate
// card. The engine's own contract says it: "never hand it tokens aggregated
// across a rate boundary; aggregate AFTER pricing, not before."
func cloudMetrics(f store.CloudSessionFacts, pricer *cost.Engine) cloudevidence.MetricsInput {
	m := f.Metrics
	out := cloudevidence.MetricsInput{
		TokensIn:           m.TokensIn,
		TokensOut:          m.TokensOut,
		CacheReadTokens:    m.CacheReadTokens,
		CostUSD:            m.CostUSD,
		DeterministicScore: clampFloat(m.QualityScore, 0, 100),
		RedundancyRatio:    clampFloat(m.RedundancyRatio, 0, 1),
		ErrorRate:          clampFloat(m.ErrorRate, 0, 1),
		Usage:              cloudUsagePresence(m),
	}
	if out.ErrorRate == 0 && f.ActionCount > 0 {
		out.ErrorRate = clampFloat(float64(f.FailedActions)/float64(f.ActionCount), 0, 1)
	}
	if pricer != nil {
		if priced, ok := cloudPricedCost(f, pricer); ok {
			out.CostUSD = priced
		}
	}
	return out
}

// cloudUsagePresence states whether ANY counted token row fed the metrics
// (D-866). A session captured by hooks alone (no watcher, no proxy) has actions
// but no token rows, and its zeros must upload as "not measured", not as a free
// session. Presence is read from the rows, never from the sums being zero: a
// measured session can total zero. Non-zero sums can only come from rows, so
// they count as captured too (a defensive guard for a caller that filled the
// sums without the row count).
func cloudUsagePresence(m store.CloudSessionMetrics) cloudevidence.UsagePresence {
	if m.RecordedRows > 0 || len(m.Turns) > 0 || len(m.ProxyTurns) > 0 ||
		m.TokensIn > 0 || m.TokensOut > 0 || m.CacheReadTokens > 0 || m.CostUSD > 0 {
		return cloudevidence.UsageCaptured
	}
	return cloudevidence.UsageNotCaptured
}

// cloudPricedCost prices the session PER TOKEN ROW and sums the money. Rows are
// already in a stable order from the store, and float addition in a fixed order
// is deterministic, so two rebuilds of an unchanged session produce the same
// cost — which the two-digest protocol requires. ok=false means the session
// carried no per-row substrate at all, so the caller keeps whatever aggregate it
// already had.
//
// PER ROW, NOT PER SESSION (F5). Pricing the summed bundle as one turn was wrong
// in two ways at once: several models price input in LONG-CONTEXT BANDS, so a
// session of 3 × 150k-token turns crossed a 272k threshold it never actually
// crossed; and a session that used two models — or that straddled a rate change
// — was priced entirely on one model's current rate card.
//
// RECORDED-OR-ESTIMATED, ALSO PER ROW (A6). The decision used to be made for the
// whole session from an aggregate: any non-zero recorded total suppressed pricing
// for EVERY row, so one adapter-recorded turn in a session made the other forty
// free. A row carries its own recorded cost or it does not, and that is the level
// the choice belongs at.
//
// The bundle handed to the engine is COMPLETE — fast tier, 1h cache-creation
// tier, and web-search requests included. Dropping them priced a fast-mode Opus
// turn at half its real cost, which is not a rounding difference.
//
// A row with no recorded model falls back to the session's model, and a row with
// no usable timestamp to the session start; a row whose model has no pricing
// entry and no recorded cost contributes nothing (an under-estimate, which is the
// honest direction — it never invents a rate).
func cloudPricedCost(f store.CloudSessionFacts, pricer *cost.Engine) (float64, bool) {
	turns := f.Metrics.Turns
	if len(turns) == 0 {
		turns = f.Metrics.ProxyTurns
	}
	if len(turns) == 0 {
		return 0, false
	}
	start := cloudSessionStart(f)
	total := 0.0
	for _, t := range turns {
		if t.RecordedCostUSD > 0 {
			total += t.RecordedCostUSD
			continue
		}
		model := t.Model
		if strings.TrimSpace(model) == "" {
			model = f.Model
		}
		at := t.Timestamp
		if at.IsZero() {
			at = start
		}
		b, ok := pricer.ComputeBreakdownAt(model, cost.TokenBundle{
			Input:             int64(t.Input),
			Output:            int64(t.Output),
			CacheRead:         int64(t.CacheRead),
			CacheCreation:     int64(t.CacheCreation),
			CacheCreation1h:   int64(t.CacheCreation1h),
			Reasoning:         int64(t.Reasoning),
			WebSearchRequests: int64(t.WebSearchRequests),
			Fast:              t.Fast,
		}, at)
		if !ok {
			continue
		}
		total += b.Total
	}
	return total, true
}

func clampFloat(v, lo, hi float64) float64 {
	if v != v || v < lo { // NaN or under
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// cloudActivityMix maps the store's whole-session kind histogram into the
// builder's input shape; the builder normalizes, merges, sorts and bounds it.
func cloudActivityMix(in []store.CloudKindCount) []cloudevidence.ActivityMixInput {
	out := make([]cloudevidence.ActivityMixInput, 0, len(in))
	for _, kc := range in {
		out = append(out, cloudevidence.ActivityMixInput{Kind: kc.Kind, Count: kc.Count})
	}
	return out
}

// cloudStartedBucket buckets a start time to the hour (RFC3339). A zero start
// falls back to the Unix epoch bucket so the envelope stays valid and
// deterministic across rebuilds.
func cloudStartedBucket(t time.Time) string {
	if t.IsZero() {
		return time.Unix(0, 0).UTC().Format(time.RFC3339)
	}
	return t.UTC().Truncate(time.Hour).Format(time.RFC3339)
}

// cloudDurationSeconds is the session's wall duration. It prefers the sessions
// row's own start→end span and FALLS BACK to the observed action span, because
// ended_at is empty on most live/unfinished sessions — and reporting a 39-hour
// session as "0 seconds" is not a small inaccuracy, it erases the one signal
// that says how long the work took.
func cloudDurationSeconds(f store.CloudSessionFacts) int {
	if !f.StartedAt.IsZero() && !f.EndedAt.IsZero() && f.EndedAt.After(f.StartedAt) {
		return int(f.EndedAt.Sub(f.StartedAt).Seconds())
	}
	if !f.FirstActionAt.IsZero() && !f.LastActionAt.IsZero() && f.LastActionAt.After(f.FirstActionAt) {
		return int(f.LastActionAt.Sub(f.FirstActionAt).Seconds())
	}
	return 0
}

// cloudActions maps the pure layer's RawAction to builder inputs, resolving
// each action's closed-vocabulary category. The RAW TARGET is handed on as a
// Path ONLY when it really is a path: a shell command must never ride the
// path-correlation grant's hash, and a prose target is not a path at all.
func cloudActions(in []cloudevidence.RawAction) []cloudevidence.ActionInput {
	out := make([]cloudevidence.ActionInput, 0, len(in))
	for _, a := range in {
		status := "ok"
		if !a.Success {
			status = "error"
		}
		category, pathIsSafe := cloudevidence.ActionCategory(a)
		path := ""
		if pathIsSafe {
			path = a.Target
		}
		out = append(out, cloudevidence.ActionInput{
			Ref:      a.Ref,
			Kind:     a.Kind,
			Status:   status,
			Path:     path,
			Category: category,
		})
	}
	return out
}
