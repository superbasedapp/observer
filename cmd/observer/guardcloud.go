package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guard/notify"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Guard cloud tier composition (guard spec §15, G15; operator
// decision D1 — everything below is explicit-opt-in). The dispatcher
// is DAEMON-RESIDENT and decoupled from every hot path: instead of
// hooking the per-verdict alert sites, it SWEEPS the guard_events
// tail through a schema_meta cursor on a fixed cadence, so verdicts
// recorded by ANY process (hook, watcher, proxy) reach the cloud
// features uniformly and a cloud outage can never add a microsecond
// to an enforcement decision (§15 fail-soft). Delivery is
// best-effort: the cursor advances at dispatch time, there is no
// redelivery queue — alerting is a convenience surface, the audit
// chain is the record.
//
// All network I/O routes through the single notify.Egress worker:
// endpoint allowlist derived from CONFIG-DECLARED destinations only,
// payload_max_bytes cap, scrub-redaction before send (§15.1), every
// settled call logged.

const (
	// cloudSweepInterval is the guard_events tail-poll cadence.
	cloudSweepInterval = 30 * time.Second
	// cloudSweepBatch bounds one sweep's row read.
	cloudSweepBatch = 200
	// judgeApprovalTTL bounds a judge-granted session approval
	// (§15.2 ask resolution) — short by design; a human grant via
	// `observer guard approve` is the durable path. One owner with the
	// dashboard consent card's disclosure (notify.JudgeApprovalTTL).
	judgeApprovalTTL = notify.JudgeApprovalTTL
	// judgeSource is the guard_events source attribution for
	// judge-recorded rows (§15.2).
	judgeSource = "llm_judge"
)

// cloudDispatcher fans qualifying guard events out to the configured
// cloud features.
type cloudDispatcher struct {
	cfg    config.GuardCloudConfig
	st     *store.Store
	logger *slog.Logger
	egress *notify.Egress

	judgeKey string

	// pending correlates in-flight judge submissions (Request.Tag =
	// the reviewed event's id) with their originating rows.
	mu      sync.Mutex
	pending map[string]store.GuardEventRow
}

// cloudAllowlist derives the §15 endpoint allowlist from the
// config-declared destinations — an endpoint that is not configured
// cannot be reached, even by a coding error.
func cloudAllowlist(cfg config.GuardCloudConfig) []string {
	var allow []string
	for _, w := range cfg.Webhooks {
		if w.URL != "" {
			allow = append(allow, w.URL)
		}
	}
	if cfg.LLMJudge.Enabled && cfg.LLMJudge.Endpoint != "" {
		allow = append(allow, cfg.LLMJudge.Endpoint)
	}
	if cfg.Reputation.Enabled {
		allow = append(allow, notify.NPMRegistryBase)
	}
	return allow
}

// newCloudDispatcher assembles the dispatcher. doer overrides the
// egress HTTP transport (tests); nil = production client.
func newCloudDispatcher(cfg config.GuardCloudConfig, st *store.Store, logger *slog.Logger, doer notify.Doer) *cloudDispatcher {
	d := &cloudDispatcher{
		cfg: cfg, st: st, logger: logger,
		pending: map[string]store.GuardEventRow{},
	}
	if cfg.LLMJudge.Enabled && cfg.LLMJudge.APIKeyEnv != "" {
		d.judgeKey = os.Getenv(cfg.LLMJudge.APIKeyEnv)
	}
	scrubber := scrub.New()
	d.egress = notify.NewEgress(notify.EgressOptions{
		Allow:        cloudAllowlist(cfg),
		MaxBodyBytes: cfg.PayloadMaxBytes,
		// §15.1 redaction-before-send: the JSON-aware scrub pass —
		// we will not be the tool that leaks secrets to its own
		// security service.
		Redact:   func(b []byte) []byte { return []byte(scrubber.RawJSON(b)) },
		OnResult: d.onResult,
		Doer:     doer,
	})
	return d
}

// hasEventFeatures reports whether any sweep-fed feature is
// configured (reputation is the on-demand CLI surface and does not
// justify a sweep loop on its own).
func (d *cloudDispatcher) hasEventFeatures() bool {
	if d.cfg.LLMJudge.Enabled && d.cfg.LLMJudge.Endpoint != "" {
		return true
	}
	for _, w := range d.cfg.Webhooks {
		if w.URL != "" {
			return true
		}
	}
	return false
}

// run is the daemon loop: anchor the cursor, then sweep on the
// cadence until ctx cancels. Always drains the egress worker on exit.
func (d *cloudDispatcher) run(ctx context.Context) {
	defer d.egress.Close()
	if err := d.anchorCursor(ctx); err != nil {
		d.logger.Warn("guard cloud: cursor anchor failed; dispatcher inert", "err", err)
		return
	}
	ticker := time.NewTicker(cloudSweepInterval)
	defer ticker.Stop()
	for {
		d.sweep(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// anchorCursor initialises the cursor at the CURRENT tail on first
// enable, so pre-existing history never alert-storms the operator's
// channels the day they turn the feature on.
func (d *cloudDispatcher) anchorCursor(ctx context.Context) error {
	cur, err := d.st.LoadGuardCloudCursor(ctx)
	if err != nil {
		return err
	}
	if cur != 0 {
		return nil
	}
	maxIDs, err := d.st.CurrentMaxIDs(ctx)
	if err != nil {
		return err
	}
	return d.st.SaveGuardCloudCursor(ctx, maxIDs.GuardEvents)
}

// sweep dispatches the new guard_events tail and advances the cursor.
func (d *cloudDispatcher) sweep(ctx context.Context) {
	cur, err := d.st.LoadGuardCloudCursor(ctx)
	if err != nil {
		d.logger.Warn("guard cloud: cursor load failed", "err", err)
		return
	}
	rows, err := d.st.GuardEventsAfter(ctx, cur, cloudSweepBatch)
	if err != nil {
		d.logger.Warn("guard cloud: tail read failed", "err", err)
		return
	}
	for _, ev := range rows {
		d.dispatch(ev)
		cur = ev.ID
	}
	if len(rows) > 0 {
		if err := d.st.SaveGuardCloudCursor(ctx, cur); err != nil {
			d.logger.Warn("guard cloud: cursor save failed", "err", err)
		}
	}
}

// dispatch fans one event out. Judge-sourced rows are never
// re-reviewed (loop prevention) and webhook only on a deny verdict —
// the §15.2 flag-UPGRADE case; their allow/flag outcomes reach the
// operator through the recorded event and the approval effect.
func (d *cloudDispatcher) dispatch(ev store.GuardEventRow) {
	if ev.RuleID == "" {
		return
	}
	fromJudge := ev.Source == judgeSource
	if !fromJudge || ev.Decision == "deny" {
		d.fanoutWebhooks(ev)
	}
	if fromJudge {
		return
	}
	// §15.2: ask/flag-class ambiguity only — never clear denies and
	// never the Q2 failure wrapper's own rows.
	if d.cfg.LLMJudge.Enabled && d.cfg.LLMJudge.Endpoint != "" &&
		(ev.Decision == "ask" || ev.Decision == "flag") && ev.RuleID != guard.GuardErrorRuleID {
		d.submitJudge(ev)
	}
}

// fanoutWebhooks submits the event to every webhook whose
// min_severity admits it.
func (d *cloudDispatcher) fanoutWebhooks(ev store.GuardEventRow) {
	sev := severityRank(ev.Severity)
	alert := notify.WebhookAlert{
		RuleID: ev.RuleID, Category: ev.Category, Severity: ev.Severity,
		Decision: ev.Decision, Tool: ev.Tool, Enforced: ev.Enforced,
		Reason: ev.Reason, Timestamp: ev.TS.UTC().Format(time.RFC3339), Source: ev.Source,
	}
	for _, w := range d.cfg.Webhooks {
		if w.URL == "" || sev < severityRank(defaultSeverity(w.MinSeverity)) {
			continue
		}
		body, err := notify.BuildWebhook(w.Kind, w.RoutingKey, alert)
		if err != nil {
			d.logger.Warn("guard cloud: webhook build failed", "kind", w.Kind, "err", err)
			continue
		}
		d.egress.Submit(notify.Request{Feature: "webhook", Endpoint: w.URL, Body: body})
	}
}

// defaultSeverity applies the [guard.alerts]-style default ("high")
// to an empty per-webhook min_severity.
func defaultSeverity(s string) string {
	if s == "" {
		return "high"
	}
	return s
}

// severityRank orders severities via the policy enum; unknown
// strings rank lowest (a typo'd min_severity alerts MORE, not less —
// fail toward visibility).
func severityRank(s string) int {
	sev, err := policy.ParseSeverity(s)
	if err != nil {
		return -1
	}
	return int(sev)
}

// submitJudge ships one bounded event context for review.
func (d *cloudDispatcher) submitJudge(ev store.GuardEventRow) {
	tag := strconv.FormatInt(ev.ID, 10)
	d.mu.Lock()
	if _, dup := d.pending[tag]; dup {
		d.mu.Unlock()
		return
	}
	d.pending[tag] = ev
	d.mu.Unlock()

	req, err := notify.BuildJudgeRequest(d.cfg.LLMJudge.Endpoint, d.cfg.LLMJudge.Model, d.judgeKey, notify.JudgeContext{
		RuleID: ev.RuleID, Category: ev.Category, Severity: ev.Severity,
		Decision: ev.Decision, EventKind: ev.EventKind, Tool: ev.Tool,
		Reason: ev.Reason, TargetExcerpt: ev.TargetExcerpt, TaintOrigin: ev.TaintOrigin,
	})
	if err != nil {
		d.logger.Warn("guard cloud: judge build failed", "event", ev.ID, "err", err)
		d.clearPending(tag)
		return
	}
	req.Tag = tag
	if !d.egress.Submit(req) {
		d.clearPending(tag)
	}
}

func (d *cloudDispatcher) clearPending(tag string) (store.GuardEventRow, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ev, ok := d.pending[tag]
	delete(d.pending, tag)
	return ev, ok
}

// onResult runs on the egress worker goroutine: log every settled
// call (§15 "every call logged"), then complete the judge flow for
// correlated responses.
func (d *cloudDispatcher) onResult(res notify.Result) {
	switch {
	case res.Refused:
		d.logger.Warn("guard cloud: egress refused", "feature", res.Request.Feature, "endpoint", res.Request.Endpoint, "reason", res.Err)
	case res.Err != "":
		d.logger.Warn("guard cloud: egress failed", "feature", res.Request.Feature, "endpoint", res.Request.Endpoint, "err", res.Err)
	default:
		d.logger.Debug("guard cloud: delivered", "feature", res.Request.Feature, "endpoint", res.Request.Endpoint, "status", res.Status)
	}
	if res.Request.Feature != "llm_judge" {
		return
	}
	ev, ok := d.clearPending(res.Request.Tag)
	if !ok {
		return
	}
	if res.Refused || res.Err != "" || res.Status != 200 {
		return // already logged; fail-soft — the deterministic verdict stands
	}
	verdict, err := notify.ParseJudgeResponse(res.Body)
	if err != nil {
		d.logger.Warn("guard cloud: judge response unusable", "event", ev.ID, "err", err)
		return
	}
	d.recordJudge(ev, verdict)
}

// recordJudge persists the review as a guard event (source =
// llm_judge, advisory — never enforced) and, for a HIGH-CONFIDENCE
// allow on an ask-class verdict, writes a short-lived session
// approval: the §15.2 "resolve an ask" semantics realized through the
// EXISTING approval machinery — the next identical blocking verdict
// in the session downgrades to approved; an already-replied prompt
// cannot be retracted, and the judge can never mint a deny on its own
// (F6 — it only ever reviews events that already carry a rule
// verdict).
func (d *cloudDispatcher) recordJudge(ev store.GuardEventRow, v notify.JudgeVerdict) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now().UTC()
	row := store.GuardEventRow{
		TS: now, SessionID: ev.SessionID, Tool: ev.Tool, EventKind: ev.EventKind,
		RuleID: ev.RuleID, Category: ev.Category, Severity: ev.Severity,
		Decision: v.Verdict, Enforced: false, Source: judgeSource,
		Reason: fmt.Sprintf("LLM judge review of event #%d (%s %s): %s (confidence %.2f)",
			ev.ID, ev.RuleID, ev.Decision, v.Rationale, v.Confidence),
		TargetHash: ev.TargetHash, TargetExcerpt: ev.TargetExcerpt, TaintOrigin: ev.TaintOrigin,
	}
	if _, err := d.st.InsertGuardEvents(ctx, []store.GuardEventRow{row}); err != nil {
		d.logger.Warn("guard cloud: judge event persist failed", "event", ev.ID, "err", err)
	}
	if v.Verdict == "allow" && v.Confidence >= notify.JudgeConfidenceFloor &&
		ev.Decision == "ask" && ev.SessionID != "" {
		if _, err := d.st.InsertGuardApproval(ctx, store.GuardApprovalRow{
			TS: now, RuleID: ev.RuleID, Scope: "session", SessionID: ev.SessionID,
			GrantedBy: judgeSource, ExpiresAt: now.Add(judgeApprovalTTL), Channel: "judge",
		}); err != nil {
			d.logger.Warn("guard cloud: judge approval write failed", "event", ev.ID, "err", err)
		} else {
			d.logger.Info("guard cloud: judge resolved ask to session approval",
				"rule", ev.RuleID, "session", ev.SessionID, "confidence", v.Confidence)
		}
	}
}

// newGuardMCPReputationCmd is the §15.3 on-demand reputation surface:
// npm-registry metadata for an MCP server package, fetched through
// the SAME egress worker (allowlist + redaction + logging) as every
// other cloud call. On-demand only — nothing in the daemon queries a
// registry on its own, and the command refuses to run without the D1
// double opt-in ([guard.cloud].enabled + [guard.cloud.reputation]).
func newGuardMCPReputationCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "reputation <npm-package>",
		Short: "Registry reputation for an MCP server package (cloud opt-in, §15.3)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			// The ONE lookup (notify.LookupNPMReputation): the D1 opt-in
			// gate, one request through the egress worker, the parse. The
			// dashboard's Security > MCP control calls the same function.
			info, err := notify.LookupNPMReputation(args[0], notify.ReputationLookupOptions{
				CloudEnabled:      cfg.Guard.Cloud.Enabled,
				ReputationEnabled: cfg.Guard.Cloud.Reputation.Enabled,
				MaxBodyBytes:      cfg.Guard.Cloud.PayloadMaxBytes,
				Doer:              reputationDoer,
			})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, line := range notify.FormatNPMInfo(info) {
				fmt.Fprintln(out, line)
			}
			if info.Young() {
				fmt.Fprintln(out, "warning:     "+notify.YoungPackageWarning)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

// reputationDoer is the CLI lookup transport; a var so tests can stub
// the registry.
var reputationDoer notify.Doer
