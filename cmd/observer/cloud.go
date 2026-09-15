package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudevidence"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/tagtaxonomy"
)

// cloud.go is the `observer cloud` command family (CI-P2 Lane E — cloud-
// intelligence Azure Foundry plan of record §6 "CI-P2" CLI bullet). It is
// integration wiring only: it COMPOSES the already-landed pure packages
// (cloudcontract / cloudevidence), the node-local store seam (cloudlocal.go +
// dataauthority), and the CONSENT-GATED EGRESS SEAM (internal/cloudgateway). It
// invents no protocol.
//
// EGRESS POSTURE (divergence-remediation plan rev 4.1 §2 R2 + its F11
// disposition). This file no longer holds the network client, the credential
// store, or any direct import of internal/cloudclient / cloudcred / cloudpop.
// Every outbound call goes through internal/cloudgateway, which resolves live
// consent (fail-closed) before touching the network and keeps a distinguished
// BOOTSTRAP lane for the sign-in action itself. That is what the narrowed
// tests/invariant/cloud_egress_test.go allow-list now pins: the gateway is the
// one importer of the network lane, and cmd/observer reaches it only through
// that seam.
//
// Every subcommand still runs and exits — no goroutine, ticker, watcher hook, or
// daemon wiring lives here. What changed under R2 is the PRINCIPLE ("no egress
// without prior explicit consent", replacing "only typed CLI commands may touch
// the network"), which is why the gateway, not this file's shape, is now the
// enforcement point.

const (
	// cloudScrubberVersion is the scrubber-version label this lane binds into
	// every consent receipt and envelope. It is a stable node-side convention
	// (the scrub package exposes no version constant); the same value MUST be
	// used at preview, consent, and rebuild so the two-digest coherence check
	// holds.
	cloudScrubberVersion = "scrub.v1"
	// cloudRetentionPolicyVersion labels the retention policy a receipt is
	// bound under (recorded, node-local; the enforceable retention lives
	// server-side per plan §2.8).
	cloudRetentionPolicyVersion = "retention.v1-candidate"
	// cloudFeatureSessionEnrichment is the one enrichment feature this arc
	// ships (plan §5 in-scope: Signed-in Free session enrichment).
	cloudFeatureSessionEnrichment = "session_enrichment"
	// cloudBaseURLEnv is the environment fallback for the cloud base URL.
	// Resolution order (D15): --base-url flag > this env var > [cloud].base_url
	// in config.toml > defaultCloudBaseURL (the hosted service). A shipped build
	// therefore signs in out of the box; env/config override only for staging or
	// self-hosting.
	cloudBaseURLEnv = "SBO_CLOUD_BASE_URL"
	// defaultCloudBaseURL is the hosted Cloud Intelligence service — the built-in
	// final fallback so `observer cloud login` (and the dashboard Sign in button
	// that spawns it) work without the operator hand-setting [cloud].base_url.
	// The Advanced settings field advertises this same URL as its placeholder.
	// Overridable for staging / self-hosting via --base-url, the env var, or
	// [cloud].base_url.
	defaultCloudBaseURL = "https://cloud.superbased.app"
	// cloudLoginPortEnv is the environment fallback for the WorkOS PKCE
	// callback listener port. There is no --flag for this value, so
	// resolution (D15) is: this env var > [cloud].login_port in config.toml
	// > the command's built-in default (9797).
	cloudLoginPortEnv = "SBO_CLOUD_LOGIN_PORT"
	// cloudSendingLeaseTTL is how long an outbox item may sit in `sending`
	// before `observer cloud sync` reclaims it as stranded (FD4). Since sync is
	// manual and single-shot, any `sending` row older than this is from a prior
	// interrupted run; the window is generous so a genuinely in-flight upload on
	// a slow link is never reclaimed out from under itself.
	cloudSendingLeaseTTL = 15 * time.Minute
)

// newCloudCmd assembles the `observer cloud` command family.
func newCloudCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cloud",
		Short: "Signed-in personal cloud intelligence (manual-only)",
		Long: "Personal cloud-intelligence commands (Signed-in Free spine).\n\n" +
			"MANUAL-ONLY: these commands are the sole outbound trigger — nothing runs\n" +
			"on a schedule and the observer/watcher make no cloud calls. The cloud base\n" +
			"URL is taken from --base-url, else the " + cloudBaseURLEnv + " environment\n" +
			"variable, else [cloud].base_url in config.toml, else the built-in default\n" +
			"(" + defaultCloudBaseURL + "). The WorkOS login callback port is taken from\n" +
			cloudLoginPortEnv + ", else [cloud].login_port.",
	}
	cmd.AddCommand(
		newCloudStatusCmd(),
		newCloudLoginCmd(),
		newCloudPreviewCmd(),
		newCloudConsentCmd(),
		newCloudEnableCmd(),
		newCloudDisableCmd(),
		newCloudSyncCmd(),
		newCloudLogoutCmd(),
		newCloudDeleteAccountCmd(),
	)
	return cmd
}

// resolveCloudBaseURL applies the D15 flag > env > [cloud].base_url resolution,
// falling back to defaultCloudBaseURL (the hosted service) when none is set — so
// a fresh install signs in out of the box. It never returns "".
func resolveCloudBaseURL(flagVal string, cfg config.Config) string {
	if strings.TrimSpace(flagVal) != "" {
		return strings.TrimSpace(flagVal)
	}
	if v := strings.TrimSpace(os.Getenv(cloudBaseURLEnv)); v != "" {
		return v
	}
	if v := strings.TrimSpace(cfg.Cloud.BaseURL); v != "" {
		return v
	}
	return defaultCloudBaseURL
}

// cloudBaseURLSource names which D15 precedence layer resolveCloudBaseURL
// actually used, for status output — "built-in default" when nothing is set and
// the compiled default applies.
func cloudBaseURLSource(flagVal string, cfg config.Config) string {
	switch {
	case strings.TrimSpace(flagVal) != "":
		return "--base-url"
	case strings.TrimSpace(os.Getenv(cloudBaseURLEnv)) != "":
		return "$" + cloudBaseURLEnv
	case strings.TrimSpace(cfg.Cloud.BaseURL) != "":
		return "[cloud].base_url"
	default:
		return "built-in default"
	}
}

// cloudCredDir resolves the credential-store fallback directory (~/.observer),
// derived from the configured DB path so it tracks a custom --config.
func cloudCredDir(cfg config.Config) string {
	return filepath.Dir(cfg.Observer.DBPath)
}

// openCloudGateway builds the consent-gated egress seam. grants is the consent
// source: pass the store for anything that may touch the FEATURE lane, or nil
// for the bootstrap-only commands (`status`, `logout`, `delete-account`) that
// never send session- or window-derived data — a nil source makes every feature
// send fail closed rather than silently permissive.
//
// An empty baseURL is tolerated: the gateway still answers credential questions
// and can clear local state, and every network method refuses with
// ErrNoBaseURL. Commands that REQUIRE an endpoint call requireCloudBaseURL
// first, so the "pass --base-url" copy stays where the user can act on it.
//
// onTokenHealed (optional) is told when an expired API token was transparently
// re-exchanged through the persisted sign-in, so a command can say so.
func openCloudGateway(cfg config.Config, baseURL, devToken string, grants cloudgateway.GrantStore, onTokenHealed func()) (*cloudgateway.Gateway, error) {
	gw, err := cloudgateway.Open(cloudgateway.Options{
		Grants:         grants,
		CredDir:        cloudCredDir(cfg),
		BaseURL:        baseURL,
		DevToken:       strings.TrimSpace(devToken),
		WorkOSClientID: resolveWorkOSClientID(cfg),
		OnTokenHealed:  onTokenHealed,
	})
	if err != nil {
		return nil, fmt.Errorf("build cloud gateway: %w", err)
	}
	return gw, nil
}

// cloudHostKey reduces a resolved base URL to the lowercase host the node's
// results-pull cursor is keyed by (see store.LoadCloudResultCursor): the
// hosted results sequence is per estate, so staging's cursor must never be
// replayed against production. An unparsable value is used verbatim.
func cloudHostKey(resolved string) string {
	u, err := url.Parse(strings.TrimSpace(resolved))
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimSpace(resolved))
	}
	return strings.ToLower(u.Host)
}

// requireCloudBaseURL returns the resolved base URL or the honest "how to set
// it" error. It is the one place that copy lives.
func requireCloudBaseURL(resolved string) error {
	if resolved == "" {
		return fmt.Errorf("no cloud base URL — pass --base-url, set %s, or set [cloud].base_url in config.toml", cloudBaseURLEnv)
	}
	return nil
}

// --- shared evidence build -------------------------------------------------

// cloudEnvelopeResult is the output of buildCloudEnvelope — the exact bytes a
// node previews AND uploads, their two digests, and a content-free summary.
type cloudEnvelopeResult struct {
	EvidenceSettingsJSON string
	Bytes                []byte
	Digests              cloudcontract.Digests
	CloudSession         string
	Actions              int
	Excerpts             int
	Purpose              cloudcontract.Purpose
	// Envelope is the built envelope these bytes were serialized from, so a
	// surface can summarize it without re-parsing the bytes. It is node-local
	// and is never a second serialization: Bytes above stays the one truth.
	Envelope *cloudcontract.Envelope
}

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
		return cloudEnvelopeResult{}, fmt.Errorf("session %q not found, or its data-authority is unknown — unknown-authority sessions are never eligible for personal cloud enrichment", sessionID)
	}
	if !auth.EligibleForPersonalEnrichment() {
		return cloudEnvelopeResult{}, fmt.Errorf("session %q is classified %q, not personal — org and unknown sessions are never sent to the personal cloud (plane separation)", sessionID, auth.Authority)
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
	var (
		outcomes cloudevidence.OutcomeTally
		failures cloudevidence.ErrorClassTally
	)
	req := store.CloudEvidenceRequest{
		MaxActions:         cloudcontract.MaxActions,
		EvidenceSettings:   settings,
		IncludeTexts:       wantText,
		IncludeFirstPrompt: wantFirstPrompt,
		Commands:           outcomes.AddCommand,
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
	cloudProject, err := st.GetOrCreateCloudProjectPseudonym(ctx, strconv.FormatInt(facts.ProjectID, 10))
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
		ActivityMix:     cloudActivityMix(facts.ActivityMix),
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

	env, err := cloudevidence.BuildEnvelope(input, cloudcontract.PlanePersonal, cloudevidence.BuildOptions{
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

// --- status ----------------------------------------------------------------

func newCloudStatusCmd() *cobra.Command {
	var (
		configPath string
		baseURL    string
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show device key, credential backend, base URL, and outbox summary",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			resolved := resolveCloudBaseURL(baseURL, cfg)
			gw, err := openCloudGateway(cfg, resolved, "", nil, nil)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()

			fmt.Fprintln(w, "SuperBased cloud (Signed-in Free) — status")
			if resolved == "" {
				fmt.Fprintf(w, "  base URL:            (unset — pass --base-url, set %s, or set [cloud].base_url in config.toml)\n", cloudBaseURLEnv)
			} else {
				fmt.Fprintf(w, "  base URL:            %s (from %s)\n", resolved, cloudBaseURLSource(baseURL, cfg))
			}
			if cfg.Cloud.AutoSync {
				fmt.Fprintf(w, "  auto-sync:           on ([cloud].auto_sync=true) — while `observer start` is running it spawns `observer cloud sync` every %d min (consent-gated: nothing is sent without a live grant). Still runs manually here.\n",
					cfg.Cloud.ResolvedCloudAutoSyncMinutes())
			} else {
				fmt.Fprintln(w, "  auto-sync:           off ([cloud].auto_sync=false) — sync only when you run `observer cloud sync`")
			}
			// SUPERSEDED by the enrichment policy below (value-upgrade plan
			// §W3, 2026-09-15): [cloud].auto_enrich is still parsed (an
			// existing config.toml with it set must not fail to load) but
			// nothing reads it anymore — background enrichment is governed
			// entirely by `observer cloud enable`'s Background flag.
			fmt.Fprintln(w, "  auto-enrich:         governed by the enrichment policy below ([cloud].auto_enrich is superseded and ignored)")
			// The developer's own `observer cloud enable`/`disable` choice
			// (migration 115) plus the last `observer cloud sync` outcome
			// (migration 117). A short-lived second DB open, degrading to the
			// honest "not set"/"never" lines on any error — the main
			// outbox-summary DB open below is unaffected.
			if _, policyDB, policyCleanup, perr := loadConfigAndDB(cmd.Context(), configPath); perr == nil {
				policySt := store.New(policyDB)
				cloudPrintEnrichPolicyLine(cmd.Context(), policySt, w)
				cloudPrintLastSyncLine(cmd.Context(), policySt, w)
				cloudPrintPlanLine(cmd.Context(), policySt, w)
				policyCleanup()
			} else {
				fmt.Fprintln(w, "  enrichment policy:   not set (run observer cloud enable)")
				fmt.Fprintln(w, "  last sync:           never")
				fmt.Fprintln(w, "  plan:                unknown until the next sync")
			}
			// D16: the node never learns its server-side allowance in this arc —
			// there is no wire field for it — so status says so honestly rather
			// than printing a fabricated number (mirrors the dashboard's
			// honest-unknown allowance card).
			fmt.Fprintln(w, "  allowance:           unknown (server-reported at sync; not disclosed to the node in this release)")
			fmt.Fprintf(w, "  credential backend:  %s\n", gw.CredentialBackend())
			if diag := gw.CredentialDiagnostic(); diag != "" {
				fmt.Fprintf(w, "  security:            DEGRADED — %s\n", diag)
			} else {
				fmt.Fprintln(w, "  security:            OS-backed")
			}
			fmt.Fprintf(w, "  device key:          %s\n", presentOrNot(gw.DeviceKeyPresent()))
			fmt.Fprintf(w, "  API token:           %s\n", presentOrNot(gw.APITokenPresent()))
			// The API token is short-lived (server TTL); the persisted WorkOS
			// sign-in is what an expired token is re-exchanged through. Whether
			// that self-heal is POSSIBLE is knowable locally; whether the token
			// is expired right now is not (it carries no expiry) — status never
			// makes a network call to find out, so it says exactly that much.
			fmt.Fprintf(w, "  sign-in (WorkOS):    %s\n", cloudSignInLine(gw))

			// Content-free outbox summary: how many items are awaiting a send.
			_, database, cleanup, dberr := loadConfigAndDB(cmd.Context(), configPath)
			if dberr != nil {
				fmt.Fprintf(w, "  outbox:              (unavailable: %v)\n", dberr)
				return nil
			}
			defer cleanup()
			st := store.New(database)
			items, lerr := st.ListSendableCloudOutbox(cmd.Context())
			if lerr != nil {
				fmt.Fprintf(w, "  outbox:              (unavailable: %v)\n", lerr)
				return nil
			}
			cursor, _ := st.LoadCloudResultCursor(cmd.Context(), cloudHostKey(resolved))
			fmt.Fprintf(w, "  outbox (sendable):   %d item(s)\n", len(items))
			cloudPrintGrantSummary(cmd.Context(), st, w)
			if cursor == "" {
				fmt.Fprintln(w, "  results cursor:      (none pulled yet)")
			} else {
				fmt.Fprintf(w, "  results cursor:      %s\n", cursor)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Cloud base URL (else $"+cloudBaseURLEnv+", else [cloud].base_url)")
	return cmd
}

// cloudPrintEnrichPolicyLine prints `observer cloud status`'s "enrichment
// policy:" line: the developer's own `observer cloud enable`/`disable`
// choice (migration 115), or the honest "not set" line for a pre-115 schema
// or a schema with no row yet — the same degrade-to-empty-state convention
// every other line in this command follows.
func cloudPrintEnrichPolicyLine(ctx context.Context, st *store.Store, w io.Writer) {
	policy, ok, err := st.GetCloudEnrichPolicy(ctx)
	if err != nil || !ok {
		fmt.Fprintln(w, "  enrichment policy:   not set (run observer cloud enable)")
		return
	}
	bg := "off"
	if policy.Background {
		bg = "on"
	}
	fmt.Fprintf(w, "  enrichment policy:   %s (background %s, set %s via %s)\n",
		policy.Level, bg, cloudDisplayDay(policy.UpdatedAt), policy.Source)
}

// cloudPrintLastSyncLine prints `observer cloud status`'s "last sync:" line:
// the outcome of the most recent `observer cloud sync` run (migration 117's
// cloud_sync_last singleton, dashboard-spawned/auto-sync/manual all write the
// same row), or the honest "never" line when it has never run.
func cloudPrintLastSyncLine(ctx context.Context, st *store.Store, w io.Writer) {
	last, ok, err := st.GetCloudSyncLast(ctx)
	if err != nil || !ok {
		fmt.Fprintln(w, "  last sync:           never")
		return
	}
	state := "failed"
	if last.OK {
		state = "ok"
	}
	if last.WaitingProvider > 0 {
		fmt.Fprintf(w, "  last sync:           %s %s - %d sent, %d waiting on provider, %d results\n",
			last.FinishedAt.Local().Format("2006-01-02 15:04"), state, last.Sent, last.WaitingProvider, last.Results)
		return
	}
	fmt.Fprintf(w, "  last sync:           %s %s - %d sent, %d results\n",
		last.FinishedAt.Local().Format("2006-01-02 15:04"), state, last.Sent, last.Results)
}

// cloudPrintPlanLine prints `observer cloud status`'s "plan:" line — the
// account plan the most recent `observer cloud sync` observed via GET
// /v1/usage (migration 118's cloud_sync_last plan columns), or the honest
// "unknown until the next sync" line when no sync has ever reported one
// (including a sync whose usage fetch failed on every run so far).
func cloudPrintPlanLine(ctx context.Context, st *store.Store, w io.Writer) {
	last, ok, err := st.GetCloudSyncLast(ctx)
	if err != nil || !ok || last.PlanName == "" {
		fmt.Fprintln(w, "  plan:                unknown until the next sync")
		return
	}
	label := last.PlanLabel
	if label == "" {
		label = last.PlanName
	}
	daily := "unknown"
	if last.DailyCap != nil {
		daily = strconv.Itoa(*last.DailyCap)
	}
	monthly := "unknown"
	if last.MonthlyCap != nil {
		monthly = strconv.Itoa(*last.MonthlyCap)
	}
	digestWeekly := "unknown"
	if last.DigestWeekly != nil {
		if *last.DigestWeekly != 0 {
			digestWeekly = "included"
		} else {
			digestWeekly = "not in plan"
		}
	}
	retention := "unknown"
	if last.ResultsRetentionDays != nil {
		retention = fmt.Sprintf("%d days", *last.ResultsRetentionDays)
	}
	fmt.Fprintf(w, "  plan:                %s (%s/day, %s/month; weekly digests %s; results kept %s)\n",
		label, daily, monthly, digestWeekly, retention)
}

func presentOrNot(present bool) string {
	if present {
		return "present"
	}
	return "not present"
}

// cloudSignInExpiredHint is the one user-facing recovery line for an expired
// sign-in: the API token was rejected and the self-heal could not refresh it.
const cloudSignInExpiredHint = "sign-in expired — run `observer cloud login`"

// cloudSignInLine states, without a network call, whether an expired API token
// can self-heal on this device.
func cloudSignInLine(gw *cloudgateway.Gateway) string {
	switch {
	case gw.WorkOSSignInPresent():
		return "present — an expired API token is re-exchanged automatically on the next `observer cloud` call"
	case gw.APITokenPresent():
		return "not present (a --dev-token session stores none) — when the API token expires, run `observer cloud login`"
	default:
		return "not present — run `observer cloud login`"
	}
}

// --- login -----------------------------------------------------------------

func newCloudLoginCmd() *cobra.Command {
	var (
		configPath string
		baseURL    string
		devToken   string
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in with WorkOS (PKCE) and exchange for a device-bound API token",
		Long: "Signs in with WorkOS AuthKit via a browser (PKCE loopback flow) and\n" +
			"exchanges the result for a short-lived, device-bound SuperBased API token.\n" +
			"Set " + cloudWorkOSClientIDEnv + " to the WorkOS client id. For local testing\n" +
			"without WorkOS, pass --dev-token (in-memory only, never stored).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			// Dev path: exchange a supplied WorkOS access token via the stub broker.
			if strings.TrimSpace(devToken) != "" {
				resolved := resolveCloudBaseURL(baseURL, cfg)
				if err := requireCloudBaseURL(resolved); err != nil {
					return err
				}
				gw, err := openCloudGateway(cfg, resolved, devToken, nil, nil)
				if err != nil {
					return err
				}
				// BOOTSTRAP lane: the device exchange IS the sign-in action, so it
				// carries no consent grant (R2 disposition F10).
				if err := gw.BootstrapExchange(cmd.Context()); err != nil {
					return fmt.Errorf("exchange: %w", err)
				}
				fmt.Fprintln(w, "Signed in — device-bound API token stored. (dev token was not persisted)")
				return nil
			}
			// Production: WorkOS PKCE loopback sign-in.
			clientID := resolveWorkOSClientID(cfg)
			if clientID == "" {
				fmt.Fprintf(w, "%s\n", cloudWorkOSClientIDMissingHint)
				return nil
			}
			return runWorkOSLogin(cmd.Context(), w, cfg, baseURL, clientID)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Cloud base URL (else $"+cloudBaseURLEnv+", else [cloud].base_url)")
	cmd.Flags().StringVar(&devToken, "dev-token", "", "Dev WorkOS access token for the stub broker (never stored)")
	return cmd
}

// cloudWorkOSClientIDEnv names the WorkOS client id used for the node PKCE flow.
// It is PUBLIC (safe on the node); the WorkOS API key is server-side only and is
// never read here.
const cloudWorkOSClientIDEnv = "WORKOS_CLIENT_ID"

// cloudWorkOSClientIDMissingHint is the ONE user-facing line for "no client id
// is configured" — printed by `observer cloud login` and surfaced verbatim by
// the dashboard's Cloud account card, so both name the same two knobs.
const cloudWorkOSClientIDMissingHint = "Set [cloud].workos_client_id in config.toml or the " + cloudWorkOSClientIDEnv +
	" environment variable to sign in with WorkOS (or pass --dev-token to `observer cloud login` for local testing)."

// resolveWorkOSClientID applies the env > [cloud].workos_client_id precedence
// (the same ladder as the base URL, minus a flag: there is no --client-id).
// "" means unconfigured. Both `observer cloud login` and the gateway's refresh
// broker resolve through here, so a config-file id and an env id behave
// identically everywhere — including inside the subprocess the dashboard's
// Sign-in button spawns, which inherits the daemon's environment and reads the
// same config file.
func resolveWorkOSClientID(cfg config.Config) string {
	if v := strings.TrimSpace(os.Getenv(cloudWorkOSClientIDEnv)); v != "" {
		return v
	}
	return strings.TrimSpace(cfg.Cloud.WorkOSClientID)
}

// runWorkOSLogin runs the WorkOS AuthKit PKCE loopback sign-in: it starts a
// 127.0.0.1 callback listener, opens the browser to the AuthKit authorize URL,
// receives the authorization code, exchanges it (with the code verifier, NO
// client secret) for tokens — persisting the refresh token — and then exchanges
// a fresh WorkOS access token for the device-bound SuperBased API token.
func runWorkOSLogin(ctx context.Context, w io.Writer, cfg config.Config, baseURL, clientID string) error {
	// The whole flow is BOOTSTRAP-lane egress: the OAuth leg plus the device
	// exchange, both authorized by the user having typed `observer cloud login`.
	// It is composed through the gateway so cmd/observer holds no direct handle
	// on the network lane or the credential store.
	resolved := resolveCloudBaseURL(baseURL, cfg)
	// Fail before the browser opens rather than after: a sign-in that cannot
	// reach an endpoint would otherwise persist WorkOS refresh material and then
	// stop, leaving the user signed in to nothing.
	if err := requireCloudBaseURL(resolved); err != nil {
		return err
	}
	gw, err := openCloudGateway(cfg, resolved, "", nil, nil)
	if err != nil {
		return err
	}
	pkce, err := gw.GeneratePKCE()
	if err != nil {
		return err
	}
	state, err := gw.RandomState()
	if err != nil {
		return err
	}

	// Loopback callback on a FIXED port. WorkOS matches redirect URIs exactly,
	// including the port, so a dynamic port would never match the registered
	// URI — the operator registers http://127.0.0.1:<port>/callback in the
	// WorkOS dashboard and we must listen on that exact port. Override the
	// default with SBO_CLOUD_LOGIN_PORT, else [cloud].login_port in config.toml
	// (register the matching URI too). Bind 127.0.0.1 explicitly (not
	// "localhost") so the browser's redirect and our listener agree even when
	// localhost resolves to IPv6.
	loginPort := "9797"
	if p := strings.TrimSpace(os.Getenv(cloudLoginPortEnv)); p != "" {
		loginPort = p
	} else if cfg.Cloud.LoginPort != 0 {
		loginPort = strconv.Itoa(cfg.Cloud.LoginPort)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", loginPort))
	if err != nil {
		return fmt.Errorf("start loopback listener on 127.0.0.1:%s (port busy? set %s or [cloud].login_port, and register the matching WorkOS redirect URI): %w", loginPort, cloudLoginPortEnv, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	authURL, err := gw.AuthorizeURL(clientID, redirectURI, pkce.Challenge, state)
	if err != nil {
		_ = ln.Close()
		return err
	}

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(rw http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != state {
			writeCloudLoginPage(rw, cloudLoginPageStateMismatch)
			errCh <- fmt.Errorf("state mismatch (possible CSRF) — sign-in aborted")
			return
		}
		if e := q.Get("error"); e != "" {
			writeCloudLoginPage(rw, cloudLoginPageAuthError)
			errCh <- fmt.Errorf("authorization error: %s (%s)", e, q.Get("error_description"))
			return
		}
		code := q.Get("code")
		if code == "" {
			writeCloudLoginPage(rw, cloudLoginPageNoCode)
			errCh <- fmt.Errorf("callback carried no authorization code")
			return
		}
		writeCloudLoginPage(rw, cloudLoginPageSuccess)
		codeCh <- code
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	fmt.Fprintln(w, "Opening your browser to sign in with WorkOS...")
	fmt.Fprintf(w, "If it does not open, visit this URL:\n\n  %s\n\n", authURL)
	openBrowser(authURL) // best-effort + silent; the URL above is the manual fallback

	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Minute):
		return fmt.Errorf("sign-in timed out after 5 minutes")
	}

	if err := gw.BootstrapExchangeWorkOSCode(ctx, clientID, code, pkce.Verifier); err != nil {
		return err
	}

	// Exchange a fresh WorkOS access token (via the persisted refresh) for the
	// device-bound SuperBased API token. The gateway resolved the production
	// WorkOS broker at Open time from WORKOS_CLIENT_ID, which is the same id the
	// authorize URL above was built with.
	if err := gw.BootstrapExchange(ctx); err != nil {
		return fmt.Errorf("exchange: %w", err)
	}
	fmt.Fprintln(w, "Signed in — device-bound API token stored.")
	return nil
}

// --- preview ---------------------------------------------------------------

func newCloudPreviewCmd() *cobra.Command {
	var (
		configPath string
		receiptID  string
		sessionID  string
		purpose    string
	)
	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Show the LITERAL bytes and digests that would upload for a session",
		Long: "Builds the evidence envelope for a session and prints the exact bytes\n" +
			"that would upload (what you see is what uploads), both digests, and a\n" +
			"content-free summary. No network. Refuses org / unknown sessions.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if sessionID == "" {
				return errors.New("--session is required")
			}
			p, err := parseCloudPurpose(purpose)
			if err != nil {
				return err
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			var res cloudEnvelopeResult
			pricer := acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default())
			if receiptID != "" {
				res, err = cloudReceiptPreview(cmd.Context(), st, receiptID, sessionID, p, pricer)
			} else {
				res, err = buildCloudEnvelope(cmd.Context(), st, sessionID, p, pricer)
			}
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%s\n", res.Bytes)
			fmt.Fprintln(w, "----")
			fmt.Fprintf(w, "purpose:                %s\n", res.Purpose)
			fmt.Fprintf(w, "evidence-content digest: %s\n", res.Digests.EvidenceContent)
			fmt.Fprintf(w, "upload digest:           %s\n", res.Digests.Upload)
			fmt.Fprintf(w, "actions:                 %d\n", res.Actions)
			fmt.Fprintf(w, "context excerpts:        %d\n", res.Excerpts)
			fmt.Fprintf(w, "upload size:             %d bytes\n", len(res.Bytes))
			cloudPrintEnvelopeSummary(w, res)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&receiptID, "receipt-id", "", "Use the selection settings frozen on this receipt")
	cmd.Flags().StringVar(&sessionID, "session", "", "Local session id to preview")
	cmd.Flags().StringVar(&purpose, "purpose", string(cloudcontract.PurposeStructuralInsights), "Consent purpose to build under")
	return cmd
}

// cloudPrintEnvelopeSummary prints the human-readable digest of what the bytes
// above actually contain: the structural signal, and — the part that matters
// most — EVERY excerpt verbatim, so a developer reads the exact post-scrub text
// that would leave the machine rather than having to find it inside the JSON.
func cloudPrintEnvelopeSummary(w io.Writer, res cloudEnvelopeResult) {
	if res.EvidenceSettingsJSON != "" {
		fmt.Fprintf(w, "evidence settings: %s\n", res.EvidenceSettingsJSON)
	}
	env := res.Envelope
	if env == nil {
		return
	}
	fmt.Fprintln(w, "----")
	fmt.Fprintf(w, "duration:                %d s\n", env.DurationSeconds)
	fmt.Fprintf(w, "metrics:                 tokens in %d / out %d, cache read %d, cost $%.4f, error rate %.3f\n",
		env.Metrics.TokensIn, env.Metrics.TokensOut, env.Metrics.CacheReadTokens,
		env.Metrics.CostUSD, env.Metrics.ErrorRate)
	if len(env.ActivityMix) > 0 {
		parts := make([]string, 0, len(env.ActivityMix))
		for _, e := range env.ActivityMix {
			parts = append(parts, fmt.Sprintf("%s=%d", e.Key, e.Count))
		}
		fmt.Fprintf(w, "activity mix:            %s\n", strings.Join(parts, " "))
	}
	if len(env.Milestones) > 0 {
		parts := make([]string, 0, len(env.Milestones))
		for _, m := range env.Milestones {
			parts = append(parts, fmt.Sprintf("%s@%ds", m.Kind, m.ElapsedSeconds))
		}
		fmt.Fprintf(w, "milestones:              %s\n", strings.Join(parts, " "))
	}
	build := env.Outcomes.Build
	if build == "" {
		build = "(none observed)"
	}
	// The unknown counts are shown WITH the knowable ones, never folded into
	// them: a session whose suites all ran behind `|| true` reports "0/0 passed,
	// 4 runs unknowable", which is the truth, rather than a clean-looking zero.
	unknown := ""
	if env.Outcomes.TestsUnknown > 0 || env.Outcomes.BuildsUnknown > 0 {
		unknown = fmt.Sprintf(" (%d test / %d build run(s) had an unknowable outcome — the recorded exit status belonged to another segment of the same command line)",
			env.Outcomes.TestsUnknown, env.Outcomes.BuildsUnknown)
	}
	fmt.Fprintf(w, "outcomes:                tests %d/%d passed, build %s%s\n",
		env.Outcomes.TestsPassed, env.Outcomes.TestsRun, build, unknown)
	if env.Overflow != nil && env.Overflow.ActionsOmitted > 0 {
		fmt.Fprintf(w, "actions sampled:         %d kept, %d omitted (even stride across the whole session)\n",
			len(env.Actions), env.Overflow.ActionsOmitted)
	}
	if len(env.Context) == 0 {
		fmt.Fprintln(w, "excerpts:                none - this purpose uploads NO session content")
		return
	}
	fmt.Fprintf(w, "excerpts:                %d (post-scrub, exactly as they would upload)\n", len(env.Context))
	for i, c := range env.Context {
		fmt.Fprintf(w, "  [%d] %s (%d bytes, cap %d)\n", i+1, c.Source, len(c.Text), c.LengthCapBytes)
		for _, line := range strings.Split(c.Text, "\n") {
			fmt.Fprintf(w, "      %s\n", line)
		}
	}
}

// --- consent ---------------------------------------------------------------

func newCloudConsentCmd() *cobra.Command {
	var (
		configPath           string
		baseURL              string
		sessionID            string
		purpose              string
		yes                  bool
		backgroundGeneration int64
		expectedUploadDigest string
	)
	cmd := &cobra.Command{
		Use:   "consent",
		Short: "Confirm a preview, record a consent receipt, and enqueue for sync",
		Long: "Per-session consent: builds the envelope for one session, shows its digests,\n" +
			"records a receipt binding those exact bytes, and enqueues it.\n\n" +
			"Standing grants — which authorize a SCHEMA rather than one upload — are managed\n" +
			"by the subcommands: `grant`, `revoke`, and `list`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if sessionID == "" {
				return errors.New("--session is required")
			}
			p, err := parseCloudPurpose(purpose)
			if err != nil {
				return err
			}
			// The same table the egress seam gates on decides this, so the CLI
			// can never record a receipt whose upload the gateway would refuse:
			// the refusal happens HERE, with honest copy, instead of at the far
			// end of a sync the developer thought they had authorized.
			if ok, reason := cloudgateway.EvidenceUploadable(p); !ok {
				return fmt.Errorf("%q cannot authorize a session upload: %s", string(p), reason)
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			if cmd.Flags().Changed("background-generation") {
				if err := st.CheckCloudBackgroundPolicy(cmd.Context(), backgroundGeneration, string(p)); err != nil {
					return err
				}
			}

			resolved := resolveCloudBaseURL(baseURL, cfg)
			if resolved == "" {
				return fmt.Errorf("no cloud base URL — pass --base-url, set %s, or set [cloud].base_url in config.toml (the receipt binds the upload endpoint)", cloudBaseURLEnv)
			}

			// Device thumbprint is the node-local account pseudonym bound on the
			// receipt (no cloud account exists until exchange). No network call.
			gw, err := openCloudGateway(cfg, resolved, "", st, nil)
			if err != nil {
				return err
			}
			thumbprint, err := gw.DeviceThumbprint()
			if err != nil {
				return err
			}

			res, err := buildCloudEnvelopeConfigured(cmd.Context(), st, sessionID, p, acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default()), backgroundGeneration)
			if err != nil {
				return err
			}
			if expectedUploadDigest != "" && expectedUploadDigest != res.Digests.Upload {
				return errors.New("the evidence or settings changed since preview; preview again before confirming")
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Session %s — purpose %s\n", sessionID, p)
			fmt.Fprintf(w, "  evidence-content digest: %s\n", res.Digests.EvidenceContent)
			fmt.Fprintf(w, "  upload digest:           %s\n", res.Digests.Upload)
			fmt.Fprintf(w, "  upload size:             %d bytes (%d actions)\n", len(res.Bytes), res.Actions)
			// Consent is the moment the developer authorizes these exact bytes,
			// so it shows the same excerpt-by-excerpt disclosure preview does.
			cloudPrintEnvelopeSummary(w, res)

			// Idempotency (review 2026-09-15): the auto-enrich sweep and a
			// manual "Enrich now" can both reach here for one session. If these
			// exact bytes are already in flight, report that job and mint
			// nothing - one enrichment must never cost two quota units or show
			// twice on the ledger.
			if existing, found, ferr := st.FindLiveCloudOutboxForUpload(cmd.Context(), sessionID, res.Digests.Upload); ferr != nil {
				return ferr
			} else if found {
				fmt.Fprintf(w, "Already queued as job %s (identical bytes, state %s); nothing new recorded. Run `observer cloud sync` to send.\n", existing.ID, existing.State)
				return nil
			}

			if !yes {
				ok, cerr := cloudConfirm(cmd.InOrStdin(), w, "Record consent and enqueue this session for sync?")
				if cerr != nil {
					return cerr
				}
				if !ok {
					fmt.Fprintln(w, "Aborted — nothing recorded.")
					return nil
				}
			}

			receiptID, err := st.InsertCloudConsentReceipt(cmd.Context(), store.CloudConsentReceipt{
				AccountPseudonym:       thumbprint,
				BackgroundGeneration:   backgroundGeneration,
				DeviceLabelRef:         thumbprint,
				Purpose:                string(p),
				FieldClassesJSON:       cloudFieldClassesJSON(p),
				EvidenceSettingsJSON:   res.EvidenceSettingsJSON,
				EnvelopeSchemaVersion:  cloudcontract.EnvelopeSchemaVersion,
				ScrubberVersion:        cloudScrubberVersion,
				Endpoint:               resolved + "/v1/jobs",
				RetentionPolicyVersion: cloudRetentionPolicyVersion,
				UploadDigest:           res.Digests.Upload,
			})
			if err != nil {
				return fmt.Errorf("record consent receipt: %w", err)
			}
			jobID, err := st.EnqueueCloudOutbox(cmd.Context(), store.CloudOutboxItem{
				SessionID:             sessionID,
				FeatureSetJSON:        cloudFeatureSetJSON(),
				EvidenceContentDigest: res.Digests.EvidenceContent,
				UploadDigest:          res.Digests.Upload,
				ReceiptID:             receiptID,
			})
			if errors.Is(err, store.ErrCloudOutboxDuplicate) {
				// Lost the race to a concurrent consent for the same bytes:
				// the receipt just minted binds nothing, so retire it and
				// point at the job that carries the upload.
				if ierr := st.InvalidateCloudConsentReceipt(cmd.Context(), receiptID); ierr != nil {
					return fmt.Errorf("enqueue: %w (and retiring the unused receipt failed: %w)", err, ierr)
				}
				if existing, found, ferr := st.FindLiveCloudOutboxForUpload(cmd.Context(), sessionID, res.Digests.Upload); ferr == nil && found {
					fmt.Fprintf(w, "Already queued as job %s (identical bytes, state %s); nothing new recorded. Run `observer cloud sync` to send.\n", existing.ID, existing.State)
					return nil
				}
				fmt.Fprintln(w, "Already queued (identical bytes); nothing new recorded. Run `observer cloud sync` to send.")
				return nil
			}
			if err != nil {
				return fmt.Errorf("enqueue: %w", err)
			}
			fmt.Fprintf(w, "Recorded receipt %s and enqueued job %s. Run `observer cloud sync` to send.\n", receiptID, jobID)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Cloud base URL (else $"+cloudBaseURLEnv+", else [cloud].base_url)")
	cmd.Flags().StringVar(&sessionID, "session", "", "Local session id to consent")
	cmd.Flags().StringVar(&purpose, "purpose", "", "Consent purpose (required)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip the interactive confirmation")
	cmd.Flags().StringVar(&expectedUploadDigest, "expected-upload-digest", "", "Refuse if these bytes differ from the displayed preview")
	cmd.Flags().Int64Var(&backgroundGeneration, "background-generation", 0, "Expected policy generation for daemon-scheduled consent")
	_ = cmd.Flags().MarkHidden("background-generation")
	// Standing-grant management lives alongside the per-session flow above: the
	// parent's own RunE still handles `consent --session ...` unchanged.
	cmd.AddCommand(
		newCloudConsentGrantCmd(),
		newCloudConsentRevokeCmd(),
		newCloudConsentListCmd(),
	)
	return cmd
}

// --- sync ------------------------------------------------------------------

func newCloudSyncCmd() *cobra.Command {
	var (
		configPath string
		baseURL    string
		devToken   string
		sessionID  string
	)
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Drain the outbox (upload) and pull enrichment results by cursor",
		Long: "Manually drains the outbox: each sendable job is rebuilt once and its\n" +
			"digests re-checked against the consent receipt before upload (a mismatch\n" +
			"moves it to reconfirmation_required, never auto-sent). Under a standing\n" +
			"structural grant it first captures any completed day windows that have not\n" +
			"been snapshotted yet, then drains them in revision order. Finally it pulls\n" +
			"results by cursor.\n\n" +
			"EVERY outbound call goes through the consent-gated egress seam: with no live\n" +
			"grant, nothing is sent and nothing is fetched.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			if cmd.Flags().Changed("session") && strings.TrimSpace(sessionID) == "" {
				return errors.New("--session must name a session")
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			// W3 (value-upgrade plan §4, 2026-09-15): record the outcome of
			// THIS run into cloud_sync_last — content-free counts and a
			// closed error class only — so `observer cloud status` and the
			// dashboard's GET /api/cloud/status can say "did the last sync
			// work" without re-running one. Written on BOTH the success and
			// failure paths via this defer, which reads the counters below by
			// reference: they are declared here, before any return in the
			// function body, precisely so the defer sees their final values
			// no matter which return statement fires (a named return `err`
			// is what lets `return someErr` still populate the value this
			// defer reads).
			syncStarted := time.Now().UTC()
			var sent, reconf, waiting, failed, associated, unassociated, digests int
			var signInExpired bool
			// W5 (value-upgrade plan §4, 2026-09-15): the account plan GET
			// /v1/usage reported on this run, if the fetch succeeded. Stays at
			// its zero value ("" / nil) when it did not — RecordCloudSyncLast
			// then correctly writes "unknown" rather than repeating a stale
			// number from a prior run.
			var planName, planLabel string
			var planDigestWeekly, planRetentionDays, planDailyCap, planMonthlyCap *int
			defer func() {
				err = cloudScopedSyncError(sessionID, err, failed, reconf)
				errClass := ""
				if err != nil {
					errClass = cloudErrClass(err)
				}
				_ = st.RecordCloudSyncLast(cmd.Context(), store.CloudSyncLast{
					StartedAt: syncStarted, FinishedAt: time.Now().UTC(), OK: err == nil,
					Sent: sent, WaitingProvider: waiting, Reconfirm: reconf, Failed: failed,
					Results: associated, SignInExpired: signInExpired, ErrorClass: errClass,
					PlanName: planName, PlanLabel: planLabel,
					DigestWeekly: planDigestWeekly, ResultsRetentionDays: planRetentionDays,
					DailyCap: planDailyCap, MonthlyCap: planMonthlyCap,
				})
			}()

			// The same pricer preview and consent used, so a rebuild at send
			// time reproduces the exact bytes the receipt bound.
			pricer := acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default())
			resolved := resolveCloudBaseURL(baseURL, cfg)
			if err := requireCloudBaseURL(resolved); err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			gw, err := openCloudGateway(cfg, resolved, devToken, st, func() {
				fmt.Fprintln(w, "Note: the API token had expired; it was re-exchanged through the persisted sign-in.")
			})
			if err != nil {
				return err
			}
			// signInExpired records that the token self-heal failed somewhere in
			// this run. The network client latches that state, so once any rail
			// hits it every later authenticated call (the results pull included)
			// fails fast with the same error — which is how a failure on the
			// structural/community rails (reported inline, never fatal) still
			// reaches this flag through the results pull below.

			// FD4: reclaim outbox items stranded in `sending` by a prior crash/
			// kill (a sync that transitioned to sending but never marked the
			// outcome) so they retry. The idempotency key makes an ambiguous
			// prior delivery safe.
			if n, rerr := st.ReclaimStaleCloudSending(cmd.Context(), time.Now().Add(-cloudSendingLeaseTTL)); rerr != nil {
				return fmt.Errorf("reclaim stale sending: %w", rerr)
			} else if n > 0 {
				fmt.Fprintf(w, "Reclaimed %d stranded 'sending' item(s) from a prior interrupted sync.\n", n)
			}

			// Structural-insights rail: capture then drain, both under the
			// standing grant. Reported separately and never fatal — a structural
			// problem must not cost the developer their session-evidence sync.
			if sessionID == "" {
				cloudSyncStructural(cmd.Context(), st, gw, time.Now(), w)

				// Community cohort-benchmarking rail: compute the current month's own
				// value and upload it under the standing grant. Also separate + never
				// fatal, and a no-op unless the developer granted the purpose.
				cloudSyncCommunity(cmd.Context(), st, gw, time.Now(), w)
			}

			items, err := st.ListSendableCloudOutbox(cmd.Context())
			if err != nil {
				return fmt.Errorf("list outbox: %w", err)
			}
			items = cloudScopeSyncItems(items, sessionID, w)
			for _, it := range items {
				if err := cloudDrainOneGated(cmd.Context(), st, gw, it, w, pricer); err != nil {
					signInExpired = signInExpired || errors.Is(err, cloudgateway.ErrSignInExpired)
					switch {
					case errors.Is(err, errCloudProviderNotReady):
						waiting++
					case errors.Is(err, store.ErrCloudReconfirmationRequired),
						errors.Is(err, store.ErrCloudEndpointMismatch),
						errors.Is(err, store.ErrCloudSendUnauthorized),
						errors.Is(err, cloudgateway.ErrNoLiveGrant),
						errors.Is(err, cloudgateway.ErrGrantRevoked):
						reconf++
					default:
						failed++
					}
					continue
				}
				sent++
			}
			if waiting > 0 {
				fmt.Fprintf(w, "Outbox: %d sent, %d waiting on provider, %d need reconfirmation, %d failed (of %d sendable).\n", sent, waiting, reconf, failed, len(items))
			} else {
				fmt.Fprintf(w, "Outbox: %d sent, %d need reconfirmation, %d failed (of %d sendable).\n", sent, reconf, failed, len(items))
			}

			// Pull results by cursor and associate each back to its local
			// session via the reverse pseudonym lookup (CI-P5b), or its local
			// project via the project pseudonym for a weekly digest (W5). It is
			// a FEATURE fetch: with no live grant at all there is nothing on the
			// service that belongs to this device, and no request is made.
			err = gw.FeatureFetch(cmd.Context(), func(sess cloudgateway.ReadSession) error {
				var perr error
				associated, unassociated, digests, perr = cloudPullResultsAndDigests(cmd.Context(), st, cloudHostKey(resolved), sess, w)
				return perr
			})
			if errors.Is(err, cloudgateway.ErrNoLiveGrant) {
				fmt.Fprintln(w, "Results: skipped — no live consent grant, so nothing was fetched.")
				return nil
			}
			if err != nil {
				fmt.Fprintf(w, "Results: pull incomplete: %v\n", err)
				if signInExpired || errors.Is(err, cloudgateway.ErrSignInExpired) {
					// Exit non-zero so the R2a auto-sync subprocess surfaces the
					// state in the daemon log instead of silently failing forever.
					return errors.New(cloudSignInExpiredHint + " (the persisted sign-in could not be refreshed; nothing syncs until then)")
				}
				return nil
			}
			if signInExpired {
				return errors.New(cloudSignInExpiredHint + " (the persisted sign-in could not be refreshed; nothing syncs until then)")
			}
			resultsLine := fmt.Sprintf("Results: %d associated", associated)
			if unassociated > 0 {
				resultsLine += fmt.Sprintf(", %d for sessions not on this device", unassociated)
			}
			if digests > 0 {
				resultsLine += fmt.Sprintf(", %d digest(s)", digests)
			}
			fmt.Fprintln(w, resultsLine+".")

			// W5: read the account's resolved plan through the SAME
			// consent-gated read lane, straight after the results pull — no new
			// egress path. A failed usage fetch is a WARN, never a sync
			// failure: the sync already did its job (outbox drained, results
			// pulled), and the plan fields simply stay unknown.
			var usage cloudgateway.UsageView
			switch uerr := gw.FeatureFetch(cmd.Context(), func(sess cloudgateway.ReadSession) error {
				var perr error
				usage, perr = sess.Usage(cmd.Context())
				return perr
			}); {
			case uerr == nil:
				planName, planLabel = usage.Plan, usage.PlanLabel
				dailyCap, monthlyCap := usage.DailyCap, usage.MonthlyCap
				planDailyCap, planMonthlyCap = &dailyCap, &monthlyCap
				if usage.DigestWeekly != nil {
					v := 0
					if *usage.DigestWeekly {
						v = 1
					}
					planDigestWeekly = &v
				}
				if usage.ResultsRetentionDays != nil {
					v := *usage.ResultsRetentionDays
					planRetentionDays = &v
				}
			case errors.Is(uerr, cloudgateway.ErrNoLiveGrant):
				// Routine: no live grant at all, same as the results pull above;
				// the plan simply stays unknown, silently.
			default:
				fmt.Fprintf(w, "Warning: could not read the account plan from the hosted service: %v\n", uerr)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Cloud base URL (else $"+cloudBaseURLEnv+", else [cloud].base_url)")
	cmd.Flags().StringVar(&devToken, "dev-token", "", "Dev WorkOS access token for the stub broker (never stored)")
	cmd.Flags().StringVar(&sessionID, "session", "", "Upload only this session; skip structural/community uploads and still pull available results")
	return cmd
}

// cloudDrainOneGated is the CONSENT GATE around one session-evidence item: it
// resolves the item's bound purpose and routes the actual drain through the
// gateway's feature lane, so the network client is only reachable once a live
// grant for that purpose has been confirmed.
//
// It is deliberately a BELT over machinery that already works: the per-item
// receipt binding, digest re-check, endpoint binding (FD1) and pre-dispatch
// re-verification (FD3) inside cloudDrainOne are untouched. What the gate adds
// is that a node with no live consent at all makes NO network attempt, rather
// than relying on every per-item path to refuse.
func cloudDrainOneGated(ctx context.Context, st *store.Store, gw *cloudgateway.Gateway, it store.CloudOutboxItem, w io.Writer, pricer *cost.Engine) error {
	rcpt, ok, err := st.GetCloudConsentReceipt(ctx, it.ReceiptID)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintf(w, "  job %s: NEEDS RECONFIRMATION — its consent receipt no longer exists; not sent\n", it.ID)
		return fmt.Errorf("job %s: %w", it.ID, store.ErrCloudReceiptNotFound)
	}
	purpose, perr := parseCloudPurpose(rcpt.Purpose)
	if perr != nil {
		fmt.Fprintf(w, "  job %s: NEEDS RECONFIRMATION — its receipt names an unknown purpose %q; not sent\n", it.ID, rcpt.Purpose)
		return perr
	}
	// A bounded upload needs BOTH purposes to actually authorize an evidence
	// body — the structural purpose it implies, not just the one the developer
	// typed — before the single receipt-bound purpose below gates the live
	// grant + dispatches. cloudPurposeSet is the same table buildCloudEnvelope
	// uses to decide what the envelope discloses under, so this check can never
	// drift from what is about to be sent.
	set, serr := cloudPurposeSet(purpose)
	if serr != nil {
		fmt.Fprintf(w, "  job %s: NEEDS RECONFIRMATION — its receipt names a purpose this build no longer supports (%v); not sent\n", it.ID, serr)
		return serr
	}
	if uerr := cloudPurposeSetUploadable(set); uerr != nil {
		fmt.Fprintf(w, "  job %s: NOT SENT — %v\n", it.ID, uerr)
		return uerr
	}
	err = gw.FeatureSend(ctx, purpose, func(sess cloudgateway.UploadSession) error {
		return cloudDrainOne(ctx, st, sess, it, w, pricer)
	})
	switch {
	case errors.Is(err, cloudgateway.ErrNoLiveGrant), errors.Is(err, cloudgateway.ErrGrantRevoked):
		fmt.Fprintf(w, "  job %s: NOT SENT — no live consent grant for purpose %q; nothing left this machine\n", it.ID, purpose)
	case errors.Is(err, cloudgateway.ErrPurposeNotUploadable):
		fmt.Fprintf(w, "  job %s: NOT SENT — purpose %q does not authorize an evidence upload (%v)\n", it.ID, purpose, err)
	}
	return err
}

// cloudDrainOne prepares (rebuild + digest re-check), uploads, and marks one
// outbox item. Its error is returned so the caller can bucket the outcome. It
// is only ever reached from inside an authorized gateway send — the Session it
// takes cannot be obtained any other way.
// errCloudProviderNotReady is a node-local sentinel: the hosted enrichment
// provider returned provider_policy_unverified (it is not accepting jobs yet —
// a server-side credential/attestation gate, nothing the developer did). The
// outbox item stays retryable; a later sync sends it once the provider is
// enabled. The sync summary counts it as "waiting on provider", not "failed".
var errCloudProviderNotReady = errors.New("cloud: hosted enrichment provider is not accepting jobs yet")

func cloudDrainOne(ctx context.Context, st *store.Store, sess cloudgateway.UploadSession, it store.CloudOutboxItem, w io.Writer, pricer *cost.Engine) error {
	rebuild := func(ctx context.Context) ([]byte, string, string, error) {
		rcpt, ok, err := st.GetCloudConsentReceipt(ctx, it.ReceiptID)
		if err != nil {
			return nil, "", "", err
		}
		if !ok {
			return nil, "", "", store.ErrCloudReceiptNotFound
		}
		p, perr := parseCloudPurpose(rcpt.Purpose)
		if perr != nil {
			return nil, "", "", perr
		}
		// The receipt's OWN classes, not today's table: an item consented
		// before the first-prompt class existed must rebuild to the bytes the
		// developer saw.
		settings, serr := store.ParseCloudEvidenceSettings(rcpt.EvidenceSettingsJSON)
		if serr != nil {
			return nil, "", "", serr
		}
		res, berr := buildCloudEnvelopeWithSettings(ctx, st, it.SessionID, p, cloudReceiptFieldClasses(rcpt.FieldClassesJSON), pricer, settings)
		if berr != nil {
			return nil, "", "", berr
		}
		return res.Bytes, res.Digests.EvidenceContent, res.Digests.Upload, nil
	}

	// FD1: bind the send target to the receipt's approved endpoint. The store
	// refuses the send (reconfirmation) if the client's immutable upload URL is
	// not the origin+path the developer consented to.
	bytesOut, lease, err := st.PrepareCloudOutboxSend(ctx, it.ID, sess.UploadEndpoint(), rebuild)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrCloudEndpointMismatch):
			fmt.Fprintf(w, "  job %s: NEEDS RECONFIRMATION — the sync endpoint does not match the one you consented to\n", it.ID)
			fmt.Fprintf(w, "    (%v). Re-run `observer cloud consent --session %s --base-url <approved>` to confirm.\n", err, it.SessionID)
		case errors.Is(err, store.ErrCloudReconfirmationRequired):
			fmt.Fprintf(w, "  job %s: NEEDS RECONFIRMATION — the rebuilt envelope no longer matches the receipt\n", it.ID)
			fmt.Fprintf(w, "    (a local edit, scrubber upgrade, schema bump, or an authorization change). Re-preview and\n")
			fmt.Fprintf(w, "    re-run `observer cloud consent --session %s` to confirm the new bytes.\n", it.SessionID)
		}
		return err
	}

	// FD3: cheap pre-flight — if the receipt was already invalidated or the
	// session upgraded to org before we even mint a pseudonym, abort here (moving
	// the item to reconfirmation_required) before doing any further work.
	if verr := st.VerifyCloudSendAuthorization(ctx, lease); verr != nil {
		fmt.Fprintf(w, "  job %s: NEEDS RECONFIRMATION — authorization changed before dispatch; not sent (%v)\n", it.ID, verr)
		return verr
	}

	cloudSession, err := st.GetOrCreateCloudSessionPseudonym(ctx, it.SessionID)
	if err != nil {
		_ = st.MarkCloudOutboxRetryable(ctx, it.ID, "pseudonym_error")
		return err
	}

	// Two-digest preview truth: register the exact (upload, content) digests
	// these bytes carry BEFORE the upload, or the server refuses the upload with
	// reconfirmation_required. The receipt supplies the disclosure metadata; the
	// outbox row carries the digests of the bytes about to be sent.
	if pcErr := cloudPreviewConfirm(ctx, st, sess, it); pcErr != nil {
		_ = st.MarkCloudOutboxRetryable(ctx, it.ID, cloudErrClass(pcErr))
		fmt.Fprintf(w, "  job %s: failed (retryable): preview-confirmation: %v\n", it.ID, pcErr)
		return pcErr
	}

	receipt, found, rerr := st.GetCloudConsentReceipt(ctx, it.ReceiptID)
	if rerr != nil || !found {
		return fmt.Errorf("cloudDrainOne: %w", store.ErrCloudReceiptNotFound)
	}
	resp, upErr := sess.Upload(ctx, cloudgateway.UploadRequest{
		CloudSessionID: cloudSession,
		Feature:        cloudFeatureSessionEnrichment,
		Envelope:       bytesOut,
		UploadDigest:   it.UploadDigest,
		SchemaVersion:  cloudcontract.EnvelopeSchemaVersion,
		// FD3: re-verify authorization inside the client, immediately before each
		// physical POST (after the pseudonym mint above, and before every retry).
		// This closes the prepare→dispatch window (a revocation during the
		// pseudonym mint) and the retry window (a revocation between attempts) —
		// the confirmed body never leaves once the receipt is gone or the session
		// has flipped to org authority.
		PreAttempt:    func() error { return st.VerifyCloudSendAuthorization(ctx, lease) },
		DispatchLease: cloudDispatchLeaseForMode(st, receipt.ID, cloudcontract.Purpose(receipt.Purpose), receipt.ConsentGeneration, store.CloudGrantPerUpload),
	})
	if upErr != nil {
		// A server 409 reconfirmation_required means the exact bytes were not
		// preview-confirmed (two-digest preview truth). That is a re-preview/
		// re-consent situation, NOT a terminal failure: park the item in
		// reconfirmation_required and surface the store sentinel so the sync loop
		// counts it as reconfirmation rather than a burned failure.
		if d, ok := cloudgateway.HTTPError(upErr); ok && d.StatusCode == http.StatusConflict && d.Code == "reconfirmation_required" {
			_ = st.MarkCloudOutboxReconfirmation(ctx, it.ID, "reconfirmation_required")
			fmt.Fprintf(w, "  job %s: NEEDS RECONFIRMATION — the server did not accept these exact bytes; re-preview and re-run `observer cloud consent --session %s`\n", it.ID, it.SessionID)
			return fmt.Errorf("cloudDrainOne: %w", store.ErrCloudReconfirmationRequired)
		}
		// The hosted enrichment provider is not accepting jobs yet
		// (provider_policy_unverified — the provider credential/attestation gate
		// on the server, not anything the developer did). Keep the item retryable
		// and say so honestly: nothing to do, a later sync sends it once the
		// provider is enabled — never a scary "failed".
		if d, ok := cloudgateway.HTTPError(upErr); ok && d.Code == "provider_policy_unverified" {
			_ = st.MarkCloudOutboxRetryable(ctx, it.ID, "provider_policy_unverified")
			fmt.Fprintf(w, "  job %s: QUEUED — the hosted enrichment provider is not accepting jobs yet; your job is kept and will send automatically on a later `observer cloud sync` (nothing to do)\n", it.ID)
			return fmt.Errorf("cloudDrainOne: %w", errCloudProviderNotReady)
		}
		if cloudUploadTerminal(upErr) {
			_ = st.MarkCloudOutboxTerminal(ctx, it.ID, cloudErrClass(upErr))
			fmt.Fprintf(w, "  job %s: FAILED (terminal): %v\n", it.ID, upErr)
			// A 422 digest_mismatch stays TERMINAL — the server recomputed a
			// different digest over these exact bytes, and no retry of the same
			// bytes can change that. But the most likely CAUSE is not a corrupt
			// node: the envelope is versioned additively (`activity_mix` was
			// added under an unchanged schema version), so a server that predates
			// this node DROPS the unknown field and digests something else. That
			// is a deployment-order problem — servers roll before nodes — and the
			// operator can only act on it if we say so.
			if d, ok := cloudgateway.HTTPError(upErr); ok && d.Code == cloudErrCodeDigestMismatch {
				fmt.Fprintf(w, "    %s\n", cloudDigestMismatchHint)
			}
			// A 403 out_of_purpose means the server needed a purpose this receipt
			// did not disclose under. Name the missing purpose (the server's
			// message embeds it) and the exact command that grants it, instead of
			// leaving the operator to grep an error code.
			if d, ok := cloudgateway.HTTPError(upErr); ok && d.Code == cloudErrCodeOutOfPurpose {
				fmt.Fprintf(w, "    %s\n", cloudOutOfPurposeHint(d.Message, it.SessionID))
			}
		} else {
			_ = st.MarkCloudOutboxRetryable(ctx, it.ID, cloudErrClass(upErr))
			fmt.Fprintf(w, "  job %s: failed (retryable): %v\n", it.ID, upErr)
		}
		return upErr
	}
	if err := st.MarkCloudOutboxSent(ctx, it.ID); err != nil {
		return err
	}
	fmt.Fprintf(w, "  job %s: sent (cloud job %s)\n", it.ID, resp.JobID)
	return nil
}

// cloudPreviewConfirm registers the two digests of the exact bytes the following
// upload will carry (the outbox row's EvidenceContentDigest + UploadDigest) with
// the disclosure metadata bound on the receipt, so the server admits the upload
// instead of refusing it with reconfirmation_required. It runs immediately
// before the upload — the receipt binds (account, upload_digest), and those are
// the bytes about to be POSTed.
func cloudPreviewConfirm(ctx context.Context, st *store.Store, sess cloudgateway.UploadSession, it store.CloudOutboxItem) error {
	rcpt, ok, err := st.GetCloudConsentReceipt(ctx, it.ReceiptID)
	if err != nil {
		return err
	}
	if !ok {
		return store.ErrCloudReceiptNotFound
	}
	// The receipt names the ONE purpose the developer typed at consent time,
	// but the server's out-of-purpose check requires the FULL disclosure set a
	// bounded envelope carries (structural_activity_insights is the base every
	// session-evidence upload rides on; bounded_context_enrichment is additive
	// on top of it). cloudPurposeSet is the same table buildCloudEnvelope used
	// to decide the envelope's own DisclosurePurposes, so the two can never
	// disagree about what this upload discloses under.
	purpose, perr := parseCloudPurpose(rcpt.Purpose)
	if perr != nil {
		return fmt.Errorf("cloudPreviewConfirm: %w", perr)
	}
	purposeSet, serr := cloudPurposeSet(purpose)
	if serr != nil {
		return fmt.Errorf("cloudPreviewConfirm: %w", serr)
	}
	var fieldClasses []string
	if strings.TrimSpace(rcpt.FieldClassesJSON) != "" {
		if jerr := json.Unmarshal([]byte(rcpt.FieldClassesJSON), &fieldClasses); jerr != nil {
			return fmt.Errorf("cloudPreviewConfirm: decode field classes: %w", jerr)
		}
	}
	endpoint := rcpt.Endpoint
	if endpoint == "" {
		endpoint = sess.UploadEndpoint()
	}
	return sess.PreviewConfirm(ctx, cloudgateway.PreviewConfirmRequest{
		Purposes:        cloudPurposeStrings(purposeSet),
		FieldClasses:    fieldClasses,
		EvidenceSchema:  rcpt.EnvelopeSchemaVersion,
		ScrubberVersion: rcpt.ScrubberVersion,
		RetentionPolicy: rcpt.RetentionPolicyVersion,
		Endpoint:        endpoint,
		UploadDigest:    it.UploadDigest,
		ContentDigest:   it.EvidenceContentDigest,
	})
}

// cloudPullResults pulls result pages until the cursor stops advancing,
// persisting the cursor after each page. It returns (associated,
// unassociated) counts, exactly as before the W5 value-upgrade wave added
// project digests — a thin wrapper over cloudPullResultsAndDigests that
// discards the digest count, kept so existing call sites need not know
// about digests.
func cloudPullResults(ctx context.Context, st *store.Store, host string, sess cloudgateway.ReadSession, w io.Writer) (associated, unassociated int, err error) {
	associated, unassociated, _, err = cloudPullResultsAndDigests(ctx, st, host, sess, w)
	return associated, unassociated, err
}

// cloudPullResultsAndDigests pulls result pages until the cursor stops
// advancing, persisting the cursor after each page. Bounded to avoid an
// unbounded loop. It returns (associated, unassociated, digests) counts:
// associated session-enrichment results landed a local cloud_results row;
// unassociated ones carried a cloud_session_id this device never minted
// (e.g. a result for a session enrolled elsewhere) — that is routine,
// honestly reported, and never an error; digests is every project-digest
// record stored (whether or not its project pseudonym resolved locally — a
// digest is stored regardless, see cloudAssociateDigestResult).
func cloudPullResultsAndDigests(ctx context.Context, st *store.Store, host string, sess cloudgateway.ReadSession, w io.Writer) (associated, unassociated, digests int, err error) {
	cursor, err := st.LoadCloudResultCursor(ctx, host)
	if err != nil {
		return 0, 0, 0, err
	}
	for page := 0; page < 100; page++ {
		res, err := sess.Results(ctx, cursor)
		if err != nil {
			return associated, unassociated, digests, err
		}
		for _, rec := range res.Results {
			// FE6: a deletion tombstone (or any schema-invalid record) is NOT a
			// valid enrichment. Skip it — never persist it, and never let a
			// title-less zero-value record supersede a real local result.
			if cloudResultIsTombstone(rec) {
				fmt.Fprintf(w, "  result %s: tombstone/invalid record — skipped (not stored)\n", rec.ResultID)
				continue
			}
			switch rec.Kind {
			case cloudcontract.ResultKindProjectDigest:
				ok, aerr := cloudAssociateDigestResultFromHost(ctx, st, rec, host)
				if aerr != nil {
					return associated, unassociated, digests, aerr
				}
				digests++
				if !ok {
					fmt.Fprintf(w, "  digest %s: stored, but its project is not on this device (cloud_project_id %s)\n", rec.ResultID, rec.CloudProjectID)
				}
			case "", cloudcontract.ResultKindSessionEnrichment:
				ok, aerr := cloudAssociateResult(ctx, st, rec)
				if aerr != nil {
					return associated, unassociated, digests, aerr
				}
				if ok {
					associated++
				} else {
					unassociated++
					fmt.Fprintf(w, "  result %s: no local session for this device (cloud_session_id %s)\n", rec.ResultID, rec.CloudSessionID)
				}
			default:
				// W5: a forward-compat kind this build does not understand.
				// Store nothing; a bounded, honest log line rather than
				// silently dropping it or misclassifying it as a tombstone.
				fmt.Fprintf(w, "  result %s: unknown kind %q — skipped (not stored)\n", rec.ResultID, rec.Kind)
			}
		}
		if res.NextCursor == "" || res.NextCursor == cursor {
			break
		}
		cursor = res.NextCursor
		if err := st.SaveCloudResultCursor(ctx, host, cursor); err != nil {
			return associated, unassociated, digests, err
		}
		if len(res.Results) == 0 {
			break
		}
	}
	return associated, unassociated, digests, nil
}

// cloudResultProvenanceExt carries the wire ResultProvenance fields that have
// no dedicated cloud_results column (route/prompt version, price snapshot
// version, retry count — the store keeps only model_route/prompt_hash/tokens/
// cost_usd). Per the CI-P5 mapping, these ride inside CloudResult.ResultJSON
// — the one JSON blob the store already persists per result (documented
// "allowed content, node-local") — under a reserved key, rather than adding a
// migration. cloudcontract.Result is embedded verbatim in
// cloudStoredResult so every existing consumer (the dashboard's
// json.RawMessage passthrough) still sees the unchanged product fields
// (title/taxonomy_tags/description/...) at the top level.
type cloudResultProvenanceExt struct {
	RouteVersion  int64  `json:"route_version,omitempty"`
	PromptVersion int64  `json:"prompt_version,omitempty"`
	PriceVersion  string `json:"price_version,omitempty"`
	RetryCount    int    `json:"retry_count,omitempty"`
}

// cloudStoredResult is the shape persisted in CloudResult.ResultJSON.
type cloudStoredResult struct {
	cloudcontract.Result
	CloudProvenanceExt cloudResultProvenanceExt `json:"cloud_provenance_ext"`
}

// cloudResultIsTombstone reports whether a pulled ResultRecord is a deletion
// tombstone or otherwise not a valid enrichment (FE6). The server may emit
// `{"tombstoned":true}` for a deleted result, which decodes into a zero-value
// ResultRecord (no ResultID, empty Result). A record with no server result id,
// or whose body fails its kind's cloudcontract schema Validate, must never be
// persisted or supersede a real local result. Validate is the same boundary
// the server applies before storage, so a real result always passes it.
//
// Kind-dispatched (W5, value-upgrade plan §4): a project-digest record's
// payload lives in DigestResult, not Result, so it is validated against
// DigestResult.Validate — checking Result on a digest record would always
// fail (an empty session-enrichment body) and misclassify every digest as a
// tombstone. An UNKNOWN kind is deliberately NOT a tombstone: it is a
// forward-compat record this build does not understand yet, and
// cloudPullResultsAndDigests logs and skips it explicitly (a distinct
// "unknown kind" line) rather than folding it into this bucket.
func cloudResultIsTombstone(rec cloudcontract.ResultRecord) bool {
	// FE6: the typed tombstone flag is authoritative and checked FIRST, before
	// any body inspection. A server that emits `{"tombstoned":true}` — even with
	// a nonempty ResultID and a schema-valid but stale residual `result` body —
	// must never resurrect a deleted enrichment as a live local result.
	if rec.Tombstoned {
		return true
	}
	if strings.TrimSpace(rec.ResultID) == "" {
		return true
	}
	switch rec.Kind {
	case cloudcontract.ResultKindProjectDigest:
		if rec.DigestResult == nil {
			return true
		}
		return rec.DigestResult.Validate() != nil
	case "", cloudcontract.ResultKindSessionEnrichment:
		return rec.Result.Validate() != nil
	default:
		return false
	}
}

// cloudAssociateResult dispatches a pulled ResultRecord on its Kind (W5,
// value-upgrade plan §4): "" / "session_enrichment" through the existing
// session-result path unchanged; "project_digest" through the digest path.
// Any other kind stores nothing and reports unassociated — the caller
// (cloudPullResultsAndDigests) filters an unknown kind out before ever
// reaching here in practice (it logs a distinct bounded line instead), but
// this dispatch stays complete so a direct call is never silently wrong.
func cloudAssociateResult(ctx context.Context, st *store.Store, rec cloudcontract.ResultRecord) (bool, error) {
	switch rec.Kind {
	case cloudcontract.ResultKindProjectDigest:
		return cloudAssociateDigestResult(ctx, st, rec)
	case "", cloudcontract.ResultKindSessionEnrichment:
		return cloudAssociateSessionResult(ctx, st, rec)
	default:
		return false, nil
	}
}

// cloudAssociateDigestResult resolves the local project a pulled project-
// digest record's cloud_project_id maps to, if any, and stores the digest
// regardless — a digest is small and worth keeping even when the project
// pseudonym is not (yet) recognized on this device (e.g. resolvable later
// after an identity merge). ok reports whether the local project resolved;
// it is never an error when it did not.
func cloudAssociateDigestResult(ctx context.Context, st *store.Store, rec cloudcontract.ResultRecord) (bool, error) {
	return cloudAssociateDigestResultFromHost(ctx, st, rec, "")
}

func cloudAssociateDigestResultFromHost(ctx context.Context, st *store.Store, rec cloudcontract.ResultRecord, host string) (bool, error) {
	if rec.DigestResult == nil {
		return false, fmt.Errorf("cloudAssociateResult: digest result %s carries no digest body", rec.ResultID)
	}
	if err := rec.DigestResult.Validate(); err != nil {
		return false, fmt.Errorf("cloudAssociateResult: %w", err)
	}
	localProjectID, ok, err := st.LookupLocalProjectByCloudPseudonym(ctx, rec.CloudProjectID)
	if err != nil {
		return false, fmt.Errorf("cloudAssociateResult: %w", err)
	}
	resultJSON, err := json.Marshal(rec.DigestResult)
	if err != nil {
		return false, fmt.Errorf("cloudAssociateResult: marshal digest: %w", err)
	}
	// The global result cursor is monotonic across accounts within one estate.
	// AccountCursor is deliberately not used: its values are incomparable
	// across accounts. Empty host (legacy direct callers) uses server time.
	stream := ""
	if host != "" {
		stream = strings.ToLower(host) + "/global-v1"
	}
	if uerr := st.UpsertCloudDigest(ctx, store.CloudDigest{
		ID:             rec.ResultID,
		ServerSequence: rec.Cursor,
		ServerStream:   stream,
		CloudProjectID: rec.CloudProjectID,
		LocalProjectID: localProjectID,
		PeriodStart:    rec.PeriodStart,
		PeriodEnd:      rec.PeriodEnd,
		SchemaVersion:  rec.SchemaVersion,
		ResultJSON:     string(resultJSON),
		ReceivedAt:     rec.ReceivedAt,
	}); uerr != nil {
		return false, fmt.Errorf("cloudAssociateResult: %w", uerr)
	}
	return ok, nil
}

// cloudAssociateSessionResult reverse-looks-up the local session a pulled
// ResultRecord's cloud_session_id maps to and, on a hit, upserts it as a
// local CloudResult. It uses the wire's ResultID as the stored row's id so a
// re-pull of the same result (the cursor didn't advance past it, or a retry)
// updates the same row in place rather than opening a new supersede chain.
// ok=false (a pseudonym this device never minted) is routine and not an
// error; the caller counts and reports it.
func cloudAssociateSessionResult(ctx context.Context, st *store.Store, rec cloudcontract.ResultRecord) (bool, error) {
	localSessionID, ok, err := st.LookupLocalSessionByCloudPseudonym(ctx, rec.CloudSessionID)
	if err != nil {
		return false, fmt.Errorf("cloudAssociateResult: %w", err)
	}
	if !ok {
		return false, nil
	}

	stored := cloudStoredResult{
		Result: rec.Result,
		CloudProvenanceExt: cloudResultProvenanceExt{
			RouteVersion:  rec.Provenance.RouteVersion,
			PromptVersion: rec.Provenance.PromptVersion,
			PriceVersion:  rec.Provenance.PriceVersion,
			RetryCount:    rec.Provenance.RetryCount,
		},
	}
	resultJSON, err := json.Marshal(stored)
	if err != nil {
		return false, fmt.Errorf("cloudAssociateResult: marshal result: %w", err)
	}

	if _, err := st.UpsertCloudResult(ctx, store.CloudResult{
		ID:            rec.ResultID,
		SessionID:     localSessionID,
		SchemaVersion: rec.SchemaVersion,
		ResultJSON:    string(resultJSON),
		Provenance: store.CloudResultProvenance{
			ModelRoute: rec.Provenance.ModelRouteID,
			PromptHash: rec.Provenance.PromptHash,
			Tokens:     int(rec.Provenance.TokensIn + rec.Provenance.TokensOut),
			CostUSD:    rec.Provenance.CostUSD,
		},
		ReceivedAt: rec.ReceivedAt,
	}); err != nil {
		return false, fmt.Errorf("cloudAssociateResult: %w", err)
	}

	// Best-effort auto-merge of the enrichment's controlled-vocabulary
	// taxonomy tags into the session's own user-facing tag set
	// (session_tags, migration 075). This is a convenience layer over
	// user-owned classification data, not part of result association: a
	// merge failure must never fail this call (which would incorrectly
	// report the pulled result as unassociated) or abort the wider pull.
	// store.ErrTooManyTags (the session already carries a full tag set) is
	// the routine, expected rejection; any other MutateSessionTags error is
	// equally non-fatal here — both are swallowed rather than propagated.
	//
	// Only STANDARD slugs merge. taxonomy_tags is constrained server-side by a
	// strict json_schema enum built from tagtaxonomy.Slugs(), but a wire value
	// is still untrusted input on this side of the boundary: an older server, a
	// vocabulary that has since shrunk, or a schema bypass could hand us a slug
	// that is not in the curated set, and quietly writing it into the user's own
	// session_tags would corrupt their tag space with an unexplained label. Off
	// vocabulary slugs are DROPPED here — they remain visible on the result
	// itself, which is where an un-vocabularized suggestion belongs.
	if merged := cloudStandardTaxonomyTags(rec.Result.TaxonomyTags); len(merged) > 0 {
		if mErr := st.MutateSessionTags(ctx, localSessionID, merged, nil); mErr != nil {
			_ = mErr // best-effort: see comment above.
		}
	}
	return true, nil
}

// cloudStandardTaxonomyTags filters a pulled result's taxonomy tags down to the
// curated vocabulary, preserving order and dropping duplicates. It is separated
// from cloudAssociateResult so the rule is unit-testable without a database.
func cloudStandardTaxonomyTags(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, tag := range in {
		slug := strings.TrimSpace(tag)
		if slug == "" || seen[slug] || !tagtaxonomy.IsStandard(slug) {
			continue
		}
		seen[slug] = true
		out = append(out, slug)
	}
	return out
}

// cloudUploadTerminal classifies a client error as terminal (a 4xx client
// error other than 429) vs retryable (transport / 5xx / 429). An expired
// sign-in is a CREDENTIAL state, not a rejection of the item — it wraps the
// 401 that revealed it, but the item must stay queued for the sync after the
// user's next `observer cloud login`.
func cloudUploadTerminal(err error) bool {
	if errors.Is(err, cloudgateway.ErrSignInExpired) {
		return false
	}
	if status, ok := cloudgateway.HTTPStatus(err); ok {
		return status >= 400 && status < 500 && status != http.StatusTooManyRequests
	}
	return false
}

// cloudErrClass returns a content-free error class for the outbox row.
func cloudErrClass(err error) string {
	if errors.Is(err, cloudgateway.ErrSignInExpired) {
		return cloudErrClassSignInExpired
	}
	if status, ok := cloudgateway.HTTPStatus(err); ok {
		return fmt.Sprintf("http_%d", status)
	}
	return "transport"
}

// cloudErrClassSignInExpired is the content-free outbox error class for a send
// that failed because the sign-in expired (retryable after `observer cloud
// login`).
const cloudErrClassSignInExpired = "sign_in_expired"

// cloudErrCodeDigestMismatch is the server's error code when it recomputes a
// different digest over the uploaded bytes (HTTP 422).
const cloudErrCodeDigestMismatch = "digest_mismatch"

// cloudDigestMismatchHint is the ONE user-facing explanation for a 422
// digest_mismatch. It is a hint, not a state change: the item stays terminal
// (re-sending identical bytes to the same server cannot succeed), but the
// operator is told the likeliest cause and what to do about it.
const cloudDigestMismatchHint = "the server computed a different digest over these exact bytes — most often it PREDATES this " +
	"node's envelope version (fields are added additively, and a server that does not know a field drops it and " +
	"digests something else). The hosted service rolls BEFORE nodes: update it, then re-run `observer cloud preview` " +
	"and `observer cloud consent` for this session."

// cloudErrCodeOutOfPurpose is the server's error code (HTTP 403) when the
// envelope's disclosure needs a consent purpose the confirmed receipt did not
// grant (internal/cloudserver/api/jobs.go's requiredPurposes /
// DisclosurePurposes checks).
const cloudErrCodeOutOfPurpose = "out_of_purpose"

// The two message prefixes internal/cloudserver/api/jobs.go embeds the
// missing purpose after. Matched literally so cloudOutOfPurposeHint can name
// the exact purpose in its own remedy instead of repeating the server's raw
// message.
const (
	cloudOutOfPurposeRequiredPrefix = "required purpose not granted: "
	cloudOutOfPurposeDeclaredPrefix = "declared disclosure purpose not granted: "
)

// cloudOutOfPurposeHint turns a 403 out_of_purpose body into an actionable
// remedy: which purpose is missing, and the exact command that grants it. A
// bounded_context_enrichment consent grants BOTH purposes a session-evidence
// upload needs (cloudPurposeSet), so re-consenting under it is always the fix
// once this node carries that behavior - this is the live-bug remedy itself,
// not just documentation of it.
func cloudOutOfPurposeHint(serverMessage, sessionID string) string {
	missing := strings.TrimPrefix(serverMessage, cloudOutOfPurposeRequiredPrefix)
	if missing == serverMessage {
		missing = strings.TrimPrefix(serverMessage, cloudOutOfPurposeDeclaredPrefix)
	}
	if missing == serverMessage {
		missing = ""
	}
	if missing == "" {
		return fmt.Sprintf(
			"the server rejected this upload because a required consent purpose was not granted (%s). "+
				"Re-run `observer cloud consent --session %s --purpose %s` (it grants the structural purpose "+
				"too) then retry `observer cloud sync`.",
			serverMessage, sessionID, string(cloudcontract.PurposeContextEnrichment),
		)
	}
	return fmt.Sprintf(
		"the server needs purpose %q granted for this upload and it is not on the confirmed receipt. "+
			"Re-run `observer cloud consent --session %s --purpose %s` (bounded_context_enrichment grants both "+
			"the structural and bounded purposes together) then retry `observer cloud sync`.",
		missing, sessionID, string(cloudcontract.PurposeContextEnrichment),
	)
}

// --- logout ----------------------------------------------------------------

func newCloudLogoutCmd() *cobra.Command {
	var (
		configPath string
		baseURL    string
		allHosts   bool
	)
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Revoke this device's server token and clear stored credentials",
		Long: "Signs this device out. It first asks the hosted service to revoke this\n" +
			"device's API token (D17) so a copy of the bearer stops working, then clears\n" +
			"the local credentials. The server call is BEST-EFFORT: if the base URL is\n" +
			"unset, no credential is stored, or the request fails, the local credentials\n" +
			"are still cleared and the command still succeeds. Local enrichment results\n" +
			"are always kept.\n\n" +
			"Credentials are stored per cloud host (the API token and the sign-in\n" +
			"material; one device key is shared): a plain logout signs out of the host\n" +
			"the base URL resolves to, and --all-hosts wipes every host's credentials\n" +
			"on this device (the device key included, so every host needs a fresh sign-in).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			gw, err := openCloudGateway(cfg, resolveCloudBaseURL(baseURL, cfg), "", nil, nil)
			if err != nil {
				return err
			}
			cloudLogoutBestEffort(cmd, gw)
			if allHosts {
				// The host-less gateway opens the legacy-shaped store, whose Clear is
				// the full local wipe (cloudcred: every host's scoped records, the
				// legacy records and the device key).
				all, aerr := openCloudGateway(cfg, "", "", nil, nil)
				if aerr != nil {
					return aerr
				}
				if err := all.ClearCredentials(); err != nil {
					return fmt.Errorf("clear credentials (all hosts): %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Logged out — credentials for every cloud host cleared. Local enrichment results are kept.")
				return nil
			}
			if err := gw.ClearCredentials(); err != nil {
				return fmt.Errorf("clear credentials: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Logged out — credentials cleared. Local enrichment results are kept.")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Cloud base URL for the server-side token revocation (else $"+cloudBaseURLEnv+", else [cloud].base_url)")
	cmd.Flags().BoolVar(&allHosts, "all-hosts", false, "Also clear the credentials stored for every OTHER cloud host on this device (full local wipe)")
	return cmd
}

// cloudLogoutBestEffort attempts the server-side token revocation for `observer
// cloud logout` (D17). It NEVER returns an error and never blocks: signing out
// of your own machine must work offline, on a decommissioned endpoint, and after
// the token has already expired. Every outcome that isn't a clean revocation
// prints exactly one line and the caller proceeds to clear local state.
//
// Two preconditions decide whether a request is attempted at all — a resolvable
// base URL and a stored API token — so a node that was never signed in makes no
// network call (the manual-only/zero-egress posture: nothing outbound without
// something to revoke).
func cloudLogoutBestEffort(cmd *cobra.Command, gw *cloudgateway.Gateway) {
	w := cmd.OutOrStdout()
	if !gw.Configured() {
		return // never signed in against a known endpoint; nothing to revoke
	}
	if !gw.APITokenPresent() {
		return // no stored token ⇒ nothing to revoke, and no request to make
	}
	// BOOTSTRAP lane: revoking your own device token is an account/device
	// operation, authorized by the same sign-in action that minted it.
	if err := gw.BootstrapLogout(cmd.Context()); err != nil {
		fmt.Fprintf(w, "Warning: server-side token revocation failed (%v). Clearing local credentials anyway; the token expires on its own.\n", err)
		return
	}
	fmt.Fprintln(w, "Server-side device token revoked.")
}

// --- delete-account --------------------------------------------------------

func newCloudDeleteAccountCmd() *cobra.Command {
	var (
		configPath string
		baseURL    string
		localOnly  bool
		yes        bool
	)
	cmd := &cobra.Command{
		Use:   "delete-account",
		Short: "Request hosted account deletion (or --local-only to clear just this device)",
		Long: "Requests server-side deletion of the signed-in account via the hosted\n" +
			"deletion endpoint (authenticated by the stored device token — run\n" +
			"`observer cloud login` first). Requires explicit confirmation unless\n" +
			"--yes. Use --local-only to skip the server and only clear this device's\n" +
			"local credentials.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			if localOnly {
				gw, gerr := openCloudGateway(cfg, "", "", nil, nil)
				if gerr != nil {
					return gerr
				}
				if err := gw.ClearCredentials(); err != nil {
					return fmt.Errorf("clear credentials: %w", err)
				}
				fmt.Fprintln(w, "Local credentials cleared. No server request was made (--local-only).")
				return nil
			}

			resolved := resolveCloudBaseURL(baseURL, cfg)
			if resolved == "" {
				return fmt.Errorf("no cloud base URL — pass --base-url, set %s, or set [cloud].base_url in config.toml (or --local-only to clear just this device)", cloudBaseURLEnv)
			}
			if !yes {
				ok, cerr := cloudConfirm(cmd.InOrStdin(), w,
					"Request PERMANENT server-side deletion of your cloud account and all its evidence/results?")
				if cerr != nil {
					return cerr
				}
				if !ok {
					fmt.Fprintln(w, "Aborted — no deletion requested.")
					return nil
				}
			}
			gw, err := openCloudGateway(cfg, resolved, "", nil, nil)
			if err != nil {
				return err
			}
			// BOOTSTRAP lane: deleting the account you signed into is an
			// account/device operation and sends no session-derived data.
			resp, err := gw.BootstrapRequestDeletion(cmd.Context())
			if err != nil {
				return fmt.Errorf("request account deletion: %w", err)
			}
			fmt.Fprintf(w, "Server-side deletion requested (request %s, state %q).\n", resp.ID, resp.State)
			fmt.Fprintln(w, "Run `observer cloud delete-account --local-only` to also clear this device's credentials.")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Cloud base URL (else $"+cloudBaseURLEnv+", else [cloud].base_url)")
	cmd.Flags().BoolVar(&localOnly, "local-only", false, "Clear only this device's local credentials (no server call)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip the interactive confirmation")
	return cmd
}

// --- helpers ---------------------------------------------------------------

func parseCloudPurpose(p string) (cloudcontract.Purpose, error) {
	if strings.TrimSpace(p) == "" {
		return "", errors.New("--purpose is required (one of: " + cloudPurposeList() + ")")
	}
	purpose := cloudcontract.Purpose(strings.TrimSpace(p))
	if !purpose.Valid() {
		return "", fmt.Errorf("unknown purpose %q (one of: %s)", p, cloudPurposeList())
	}
	return purpose, nil
}

func cloudPurposeList() string {
	all := cloudcontract.AllPurposes()
	parts := make([]string, len(all))
	for i, p := range all {
		parts[i] = string(p)
	}
	return strings.Join(parts, ", ")
}

// cloudPurposeSet is the single table-driven source of truth for which
// consent purposes a session-evidence build under `purpose` discloses under
// AND must be granted for. structural_activity_insights is the BASE every
// session-evidence upload rides on (identity, structural metrics, paths —
// fields every envelope carries regardless of purpose); bounded_context_
// enrichment is ADDITIVE on top of it, unlocking the `context` excerpts, never
// a replacement for it.
//
// Every call site that used to pass a single literal purpose through to
// GrantedPurposes / a receipt's disclosed-purposes list / a pre-send grant
// check now goes through here instead, so the three can never drift apart
// again the way they did in the live bug this closes: `observer cloud consent
// --purpose bounded_context_enrichment` recorded (and disclosed under) ONLY
// bounded_context_enrichment, so `observer cloud sync` reached the server with
// an envelope carrying structural fields it had never declared a purpose for
// — a 403 out_of_purpose naming the missing structural_activity_insights,
// parking the outbox item terminal.
//
// An unsupported purpose (anything outside the two below) is rejected with an
// honest error rather than silently building an under-declared envelope —
// exactly the failure mode this function exists to close off.
func cloudPurposeSet(purpose cloudcontract.Purpose) ([]cloudcontract.Purpose, error) {
	switch purpose {
	case cloudcontract.PurposeStructuralInsights:
		return []cloudcontract.Purpose{cloudcontract.PurposeStructuralInsights}, nil
	case cloudcontract.PurposeContextEnrichment:
		return []cloudcontract.Purpose{
			cloudcontract.PurposeStructuralInsights,
			cloudcontract.PurposeContextEnrichment,
		}, nil
	default:
		return nil, fmt.Errorf(
			"purpose %q cannot build a session-evidence envelope - supported purposes are %q (structural only) "+
				"and %q (structural plus bounded excerpts, which implies and always includes the structural purpose)",
			string(purpose), string(cloudcontract.PurposeStructuralInsights), string(cloudcontract.PurposeContextEnrichment),
		)
	}
}

// cloudPurposeSetUploadable verifies every purpose in a disclosure set is one
// whose rule row actually permits a session-evidence upload
// (cloudgateway.EvidenceUploadable). FeatureSend already makes this check for
// the ONE purpose it dispatches under; a bounded upload's set carries a SECOND
// purpose (structural_activity_insights) that never went through that gate on
// its own, so this closes the same gap for every purpose cloudPurposeSet adds
// — a live grant is necessary but not sufficient if the implied purpose itself
// cannot authorize an evidence body.
func cloudPurposeSetUploadable(set []cloudcontract.Purpose) error {
	for _, p := range set {
		if ok, reason := cloudgateway.EvidenceUploadable(p); !ok {
			return fmt.Errorf("purpose %q (implied by this upload) does not authorize a session-evidence upload: %s", string(p), reason)
		}
	}
	return nil
}

// cloudPurposeStrings renders a purpose set as plain strings, in the order
// cloudPurposeSet produced them, for a wire payload that wants []string.
func cloudPurposeStrings(set []cloudcontract.Purpose) []string {
	out := make([]string, len(set))
	for i, p := range set {
		out[i] = string(p)
	}
	return out
}

// perUploadFieldClasses is the closed purpose → field-class table for a
// PER-UPLOAD receipt: exactly which preview groupings a session-evidence
// envelope built under that purpose actually contains.
//
// It fixes the same defect the standing path already fixed (see
// cloudStandingFieldClassesJSON): this used to record the PURPOSE NAME in the
// field-class slot, which is not a member of cloudcontract's closed FieldClass
// vocabulary at all — so a receipt claimed a class that does not exist and the
// consent surface could not say what the upload contained.
//
// Structural envelopes carry identity, structural metrics, per-action
// path-derived categories AND (since 2026-09-16) the narrowed first-user-prompt
// class - the single first_user_prompt excerpt every "Title only" consent
// screen names ("a structural summary and your first prompt, nothing else").
// A bounded-context envelope additionally carries the post-scrub excerpt set.
// Nothing here binds user feedback (not built on this path).
var perUploadFieldClasses = map[cloudcontract.Purpose][]string{
	cloudcontract.PurposeStructuralInsights: {
		string(cloudcontract.FieldClassIdentityLinkage),
		string(cloudcontract.FieldClassStructuralMetrics),
		string(cloudcontract.FieldClassPaths),
		string(cloudcontract.FieldClassFirstUserPrompt),
	},
	cloudcontract.PurposeContextEnrichment: {
		string(cloudcontract.FieldClassIdentityLinkage),
		string(cloudcontract.FieldClassStructuralMetrics),
		string(cloudcontract.FieldClassPaths),
		string(cloudcontract.FieldClassFirstUserPrompt),
		string(cloudcontract.FieldClassContentExcerpts),
	},
}

// cloudFieldClasses returns the field classes a per-upload receipt binds for
// a purpose (a copy of the table row; nil for a purpose with no row).
func cloudFieldClasses(p cloudcontract.Purpose) []string {
	return append([]string(nil), perUploadFieldClasses[p]...)
}

// cloudFieldClassesJSON records the field classes a per-upload receipt binds.
// A purpose with no row returns "[]" — saying nothing beats fabricating a class
// or reusing another purpose's.
func cloudFieldClassesJSON(p cloudcontract.Purpose) string {
	classes, ok := perUploadFieldClasses[p]
	if !ok {
		return "[]"
	}
	b, _ := json.Marshal(classes)
	return string(b)
}

// cloudReceiptFieldClasses decodes a receipt's field_classes_json column. A
// column that is not a JSON array (a pre-vocabulary receipt) decodes to nil,
// which every consumer reads as "no class granted" - the fail-closed reading.
func cloudReceiptFieldClasses(raw string) []string {
	var classes []string
	if err := json.Unmarshal([]byte(raw), &classes); err != nil {
		return nil
	}
	return classes
}

// cloudClassesInclude reports whether c is among the granted classes.
func cloudClassesInclude(classes []cloudcontract.FieldClass, c cloudcontract.FieldClass) bool {
	for _, g := range classes {
		if g == c {
			return true
		}
	}
	return false
}

func cloudFeatureSetJSON() string {
	b, _ := json.Marshal([]string{cloudFeatureSessionEnrichment})
	return string(b)
}

// cloudConfirm reads a y/N line from r.
func cloudConfirm(r io.Reader, w io.Writer, prompt string) (bool, error) {
	fmt.Fprintf(w, "%s [y/N]: ", prompt)
	sc := bufio.NewScanner(r)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return false, err
		}
		return false, nil
	}
	ans := strings.ToLower(strings.TrimSpace(sc.Text()))
	return ans == "y" || ans == "yes", nil
}
