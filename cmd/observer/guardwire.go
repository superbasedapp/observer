package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guard/notify"
	"github.com/marmutapp/superbased-observer/internal/orgbudget"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Daemon-wide guard sharing (guard spec §8 / G9). `observer start`
// assembles the proxy and the watcher through separate build
// functions, each with its own Store handle over the same SQLite
// file — but the guard layer's TAINT STATE must be daemon-wide: the
// proxy's §8.4 injection heuristics mark Imperative taint that the
// watcher ingest seam's T-501 consumes. processGuards therefore keys
// ONE Guard per (process, observer.db): the first composition site to
// ask constructs it (with its store backing the approval lookup and
// the policy-state log — equivalent through either handle, same DB),
// and every later site receives the same instance. The cachetrack
// single-engine precedent, adapted for the two-store assembly.
//
// Hook processes remain separate Guards by design (short-lived
// subprocesses — documented in internal/guard/hook.go).
var processGuards = struct {
	mu sync.Mutex
	m  map[string]*guard.Guard
}{m: map[string]*guard.Guard{}}

// acquireProcessGuard returns the per-(process, db-path) shared Guard,
// constructing it on first call. Returns nil when the guard is
// disabled/off or construction failed (WARN-and-continue — the
// daemon never refuses to run over a guard problem). Failed
// constructions are not cached, so a later caller retries.
func acquireProcessGuard(ctx context.Context, cfg config.Config, st *store.Store, logger *slog.Logger) *guard.Guard {
	if !cfg.Guard.Enabled || cfg.Guard.Mode == "off" {
		return nil
	}
	key := cfg.Observer.DBPath
	processGuards.mu.Lock()
	defer processGuards.mu.Unlock()
	if g, ok := processGuards.m[key]; ok {
		return g
	}
	g := buildGuardForStore(ctx, cfg, st, logger)
	if g != nil {
		processGuards.m[key] = g
	}
	return g
}

// budgetWindowStarts computes both units over the calendars sealed into the
// same immutable guard snapshot as the numeric cap.
func budgetWindowStarts(now time.Time, calendars guard.BudgetCalendars) (dayStart, weekStart, monthStart time.Time) {
	return orgbudget.CalendarWindowStarts(now, orgbudget.Zone(calendars.DailyTimezone), orgbudget.Zone(calendars.MonthlyTimezone))
}

// lookupProcessGuard returns the already-constructed per-(process, db-path)
// Guard WITHOUT building one, or nil when none exists (the guard is off, or
// no composition site has asked yet).
//
// It exists so a later wiring step — the org budget boundary, which runs after
// buildProxy has already composed the shared Guard — can reach that ONE
// instance without opening a second Store handle just to satisfy
// acquireProcessGuard's constructor. Constructing here instead would create
// exactly the second guard the processGuards map exists to prevent.
func lookupProcessGuard(dbPath string) *guard.Guard {
	processGuards.mu.Lock()
	defer processGuards.mu.Unlock()
	return processGuards.m[dbPath]
}

// buildGuardForStore constructs the guard composition layer wired to
// one store handle: policy layers via guard.New, the §14.4
// policy-change log callback, and the §6.3 approval lookup. Every
// failure path is WARN-and-continue (the Q2 fail-open philosophy
// applied at composition).
func buildGuardForStore(ctx context.Context, cfg config.Config, st *store.Store, logger *slog.Logger) *guard.Guard {
	home, err := os.UserHomeDir()
	if err != nil {
		logger.Warn("guard: home dir unavailable; ~-anchored policy paths degrade", "err", err)
	}
	roots, err := st.ProjectRoots(ctx)
	if err != nil {
		logger.Warn("guard: project roots unavailable; cross-project rule R-151 inert this run", "err", err)
	}
	// §14.2 org policy key pin: the daemon path supplies the enrolment
	// pin so the org bundle loader requires the cached envelope's key
	// to match it (hook processes skip the pin read — §6.4 latency;
	// they still verify the envelope's own signature). One indexed
	// read at construction; a read failure degrades to the
	// self-contained check, never blocks the daemon.
	var orgKeyPin string
	if states, serr := st.LatestGuardPolicyStates(ctx); serr == nil {
		for _, ps := range states {
			if ps.Layer == "org" && strings.HasSuffix(ps.Path, orgclient.PolicyKeyPinSuffix) {
				orgKeyPin = ps.ContentHash
			}
		}
	} else {
		logger.Warn("guard: org policy key pin unavailable; bundle loads with self-contained verification only", "err", serr)
	}
	g, err := guard.New(guard.Options{
		Config:            cfg.Guard,
		Home:              home,
		KnownProjectRoots: roots,
		Notifier:          notify.NewDesktop(),
		OrgKeyPinHash:     orgKeyPin,
		OnPolicyState: func(ps guard.PolicyState) {
			// Project layers load lazily mid-run; use a fresh
			// short-lived context rather than the (possibly long-gone)
			// composition ctx.
			recCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, rerr := st.RecordGuardPolicyState(recCtx, store.GuardPolicyStateRow{
				Layer: ps.Layer, Path: ps.Path, Version: ps.Version,
				ContentHash: ps.ContentHash,
				LoadedAt:    time.Now().UTC(),
			}); rerr != nil {
				logger.Warn("guard: policy-state record failed", "layer", ps.Layer, "path", ps.Path, "err", rerr)
			}
		},
	})
	if err != nil {
		logger.Warn("guard: construction failed; daemon runs unguarded", "err", err)
		return nil
	}
	for _, issue := range g.LoadIssues() {
		logger.Warn("guard: policy load issue", "issue", issue)
	}
	// §6.3 approvals: blocking verdicts consult the grant register.
	// The daemon's store handle is long-lived, so the lookup is one
	// indexed read; errors report false (fail-safe to enforcement).
	g.SetApprovalLookup(func(ruleID, sessionID, rootHash string) bool {
		lctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return st.ApprovalActiveFor(lctx, ruleID, sessionID, rootHash, time.Now().UTC())
	})
	// ONE SUBJECT IDENTITY for the org's per-tool / per-model caps (bundle
	// BUD-N, adversarial review P1-3). The cap's id, the accounting key and the
	// stamped event are all folded through THIS function, so an org cap on
	// `claude-sonnet-5` matches a node that captured `claude-sonnet-5-20260501`
	// instead of silently governing nothing.
	//
	// It resolves the price table LAZILY, per call, for the same reason the
	// budget lookup below does: the process cost engine is composed by
	// buildProxy, which runs AFTER this guard is assembled, and constructing one
	// here would create a second pricing truth.
	resolveSubject := budgetSubjectResolver(cfg.Observer.DBPath)
	g.SetBudgetSubjectResolver(resolveSubject)
	// §12.1 budget lookup: spend-so-far for the B-601/B-602 rows and
	// the §4.4 cost matchers. Guard caches per session (30s TTL), so
	// this SUM query runs at most ~2/min/session; errors report
	// ok=false (rules fail toward silence, never a spurious breach).
	// Wired whenever the guard runs — user cost-matcher rules work
	// even with no [guard.budget] thresholds set.
	g.SetBudgetAccountingLookup(func(sessionID string, accounting guard.BudgetAccountingContext) (guard.BudgetSnapshot, bool) {
		lctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		now := time.Now().UTC()
		// Calendar day / calendar month in the ORG BUDGET's own timezone when
		// one governs those windows, UTC otherwise; rolling 7 days for the
		// weekly window (§1.3), which has no calendar and therefore no zone.
		// The boundaries are caller-supplied precisely so the day-boundary
		// policy can vary (store/guard.go), and the node must bucket the same
		// calendar day the dashboard percentage and the alert ladder do.
		dayStart, weekStart, monthStart := budgetWindowStarts(now, accounting.Calendars)
		// The process engine is composed by buildProxy before this guard is
		// assembled. Look it up without acquiring or constructing one here:
		// acquireProcessGuard holds processGuards.mu while composing the guard,
		// and a nested engine construction would create a second pricing truth.
		engine := lookupProcessCostEngine(cfg.Observer.DBPath)
		table := engine.Table()
		pricer := guardBudgetTablePricer(table)
		if accounting.Managed {
			identity, active, err := orgclient.CurrentBudgetIdentity(lctx, st)
			if err != nil || !active || accounting.BudgetBinding == "" || identity.Binding != accounting.BudgetBinding {
				return guard.BudgetSnapshot{}, false
			}
			pricer = managedBudgetTablePricer(table, accounting.BudgetBinding)
		}
		spend, err := st.GuardBudgetSpendPriced(
			lctx, sessionID, dayStart, weekStart, monthStart, pricer,
			store.GuardBudgetReadOptions{Managed: accounting.Managed, ResolveSubject: resolveSubject},
		)
		if err != nil {
			logger.Warn("guard: budget spend lookup failed", "err", err)
			return guard.BudgetSnapshot{}, false
		}
		if spend.UnpricedRows > 0 {
			logger.Debug("guard: budget spend has unpriced usage",
				"rows", spend.UnpricedRows, "tokens", spend.UnpricedTokens,
				"unpriced_windows", spend.UnpricedWindows,
				"unpriced_tools", spend.UnpricedTools,
				"fallback_models", spend.FallbackModels,
				"unpriced_models", spend.UnpricedModels,
				"pricing_sources", spend.PricingSources)
		}
		if accounting.Managed {
			// Report, never deny (ruling A3): the coverage this read observed
			// is what the node's budget posture carries to the org and what
			// `observer guard status` prints. Recorded here because this is
			// the one read that priced the cap's own windows - computing it a
			// second time elsewhere would be a second accounting truth.
			recordBudgetPricingCoverage(cfg.Observer.DBPath, budgetPricingCoverageOf(spend))
		}
		snap := guard.BudgetSnapshot{
			WeeklyUSDExpiresAt: spend.WeeklyExpiresAt,
			SessionUSD:         spend.SessionUSD,
			DailyUSD:           spend.DailyUSD,
			WeeklyUSD:          spend.WeeklyUSD,
			MonthlyUSD:         spend.MonthlyUSD,
			// The PER-SUBJECT slice of the very same read (bundle BUD-N): the
			// organization's per-tool / per-model caps compare against these,
			// and because they came out of one query over one set of window
			// stamps they can never disagree with the node-wide numbers above
			// about which turns they counted. SessionTool lets the proxy
			// admission lane — which holds a session id and no tool — scope a
			// per-tool cap at all.
			ByTool:       subjectWindowsOf(spend.ByTool),
			ByModel:      subjectWindowsOf(spend.ByModel),
			SessionTool:  spend.SessionTool,
			SessionModel: spend.SessionModel,
			// UNPRICED ROWS NO LONGER CLOSE A WINDOW (ruling A2, 2026-09-15).
			// They are priced by the fallback ladder and counted; what is left
			// unavailable here is only what the price table itself could not
			// establish, set below when the witness or the enrollment binding
			// fails.
		}
		priceWitness := table.PricingDocumentWitness()
		snap.PricingDocumentWitness = guard.BudgetDocumentWitness{
			Known: priceWitness.Known, Present: priceWitness.Present, SHA256: priceWitness.SHA256,
		}
		if accounting.Managed && (!priceWitness.Valid() || table.EnrollmentBinding() != accounting.BudgetBinding) {
			// An unverified cold-start table cannot establish measured org spend.
			// Even an explicit-empty document must belong to this enrollment.
			// Classify that as unavailable accounting here so the hard policy can
			// refuse work; a measured denial with no durable witness would only
			// fail the later signal fence and leave the process running.
			snap.USDUnavailable = policy.BudgetUnavailableWindows{
				Session: true, Daily: true, Weekly: true, Monthly: true,
			}
		}
		if engine != nil && table != nil {
			snap.AccountingEvidence = &guard.BudgetAccountingEvidence{Fence: func(ctx context.Context, action func() error) error {
				return engine.WithPricingTable(ctx, table, action)
			}}
		}
		// TOKEN windows for the B-621..B-624 rows (org-budget plan §3.3c).
		// Read in the SAME lookup, over the SAME window boundaries, so a
		// token budget and a dollar budget can never disagree about which
		// turns they counted. A token read error marks those windows unavailable
		// so a configured hard token cap cannot admit on a fabricated zero.
		if tok, terr := st.GuardBudgetTokens(lctx, sessionID, dayStart, weekStart, monthStart, store.GuardBudgetReadOptions{Managed: accounting.Managed}); terr != nil {
			logger.Warn("guard: budget token lookup failed", "err", terr)
			snap.TokensUnavailable = policy.BudgetUnavailableWindows{
				Session: true,
				Daily:   true,
				Weekly:  true,
				Monthly: true,
			}
		} else {
			snap.TokensUnavailable = policy.BudgetUnavailableWindows{
				Session: tok.Unavailable.Session,
				Daily:   tok.Unavailable.Daily,
				Weekly:  tok.Unavailable.Weekly,
				Monthly: tok.Unavailable.Monthly,
			}
			snap.SessionTokens = tok.SessionTokens
			snap.DailyTokens = tok.DailyTokens
			snap.WeeklyTokens = tok.WeeklyTokens
			snap.WeeklyTokensExpiresAt = tok.WeeklyExpiresAt
			snap.MonthlyTokens = tok.MonthlyTokens
		}
		// Provider usage-window utilization (B-610..B-613). Advisory-
		// grade and node-wide; a missing window leaves the fields 0
		// (limit rules treat 0 as no-match). A read error is
		// non-fatal — the $ windows still stamp.
		if u5, u7, ok, uerr := st.LatestLimitWindows(lctx); uerr != nil {
			logger.Warn("guard: limit-window lookup failed", "err", uerr)
		} else if ok {
			snap.Util5h, snap.Util7d = u5, u7
		}
		return snap, true
	})
	// §9.2 pin lookup: pinned-and-approved MCP servers stop marking
	// mcp_unpinned taint. One indexed read, only on MCP-result paths;
	// errors report false (fail toward "unpinned", never toward
	// silently trusting a server).
	g.SetMCPPinLookup(func(server string) bool {
		lctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ok, err := st.GuardMCPServerApproved(lctx, server)
		return err == nil && ok
	})
	// Prompt-submit reconsider-once persistence (Group 3, phase-3a
	// review — the proxy-lane follow-up docs/guard-prompt.md's "Two
	// follow-ups" section names). Mirrors cmd/observer/hook.go:836's
	// wiring almost verbatim, except this Guard is daemon-shared and
	// already holds a long-lived `st *store.Store` handle (unlike the
	// hook process's short-lived per-call db.Open/Close), so it calls
	// st directly — the same simplification SetApprovalLookup and
	// SetBudgetLookup above already make. Until this was wired, every
	// proxy-lane ask-once/redact finding hit
	// !g.promptReconsiderWired() and degraded to an unconditional
	// block (DegradedFrom:"store_unwired") — safe (nothing forwards
	// unconfirmed), but not the designed "block once, then allow an
	// identical resend" UX, and not the cross-lane confirm
	// (docs/guard-prompt.md "Cross-lane confirm") either, since there
	// was no shared store state to confirm against.
	g.SetPromptReconsiderStore(guard.PromptReconsiderFuncs{
		Lookup: func(fp string, now time.Time) (time.Time, bool, error) {
			lctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			row, ok, err := st.LookupPromptReconsider(lctx, fp, now)
			return row.WarnedAt, ok, err
		},
		Record: func(fp, sessionID, tool, detectors string, warnedAt, expiresAt time.Time) error {
			rctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			return st.RecordPromptWarned(rctx, store.PromptReconsiderRow{
				Fingerprint: fp, SessionID: sessionID, Tool: tool, Detectors: detectors,
				WarnedAt: warnedAt, ExpiresAt: expiresAt,
			})
		},
		Confirm: func(fp string, now time.Time) (bool, error) {
			cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			return st.ConfirmPromptReconsider(cctx, fp, now)
		},
	})
	// §9.2 config-change re-scan: a watcher-ingested write to a
	// locate-table MCP registry file re-runs the config scan
	// (debounced — editor save bursts coalesce to one pass).
	if r := newMCPSecRunner(configGuardMCP{
		Pinning:             cfg.Guard.MCP.Pinning,
		PoisoningHeuristics: cfg.Guard.MCP.PoisoningHeuristics,
	}, st, g, logger); r != nil {
		g.SetMCPRescan(debouncedMCPRescan(r, 5*time.Second))
	}
	// §13.2 dialect drift re-check: a watcher-ingested write to a
	// compiled native config (settings.json, opencode.json) re-checks
	// drift against policy — the same config-watch trigger the MCP
	// re-scan rides, second consumer (one mechanism, two consumers).
	if dr := newDialectRunner(configGuardDialects{
		Compile: cfg.Guard.Dialects.Compile,
		Targets: cfg.Guard.Dialects.Targets,
	}, st, g, logger); dr != nil {
		g.SetDialectRescan(dr.watchPaths(), debouncedDialectRescan(dr, 5*time.Second))
	}
	return g
}

// budgetSubjectResolver builds the ONE identity rule a per-tool / per-model
// budget cap is compared under.
//
//   - a TOOL id has no alias ladder anywhere in the product — an adapter id is
//     a fixed vocabulary — so it resolves to the plain normalisation.
//   - a MODEL id resolves through the PRICE TABLE's own ladder
//     (cost.Table.ResolveModelKey: exact -> :free -> date-stripped -> family ->
//     router-prefix retry), which is the only component that already knows two
//     model strings can name one model. A model the table has never seen keeps
//     its own id, which is the honest fallback: the cap still matches an
//     identically-spelled row and still misses a differently-spelled one, and
//     the node reports that miss through BudgetPostureRow.OrgSubjectUnmatched
//     rather than hiding it.
//
// The engine is looked up per call rather than captured, because the process
// cost engine is composed by buildProxy AFTER the guard is assembled, and a
// nil engine simply degrades to the normalisation.
func budgetSubjectResolver(dbPath string) func(kind, id string) string {
	return func(kind, id string) string {
		norm := guard.NormalizeBudgetSubjectID(id)
		if norm == "" || kind != policy.BudgetSubjectKindModel {
			return norm
		}
		engine := lookupProcessCostEngine(dbPath)
		if engine == nil {
			return norm
		}
		table := engine.Table()
		if table == nil {
			return norm
		}
		if key, ok := table.ResolveModelKey(norm); ok {
			return guard.NormalizeBudgetSubjectID(key)
		}
		return norm
	}
}

// subjectWindowsOf converts the store's per-subject window totals into the
// guard's shape. Two plain types across one seam, converted at the boundary —
// the same one-seam-per-integration-point rule every other type on this path
// follows (CLAUDE.md #2): internal/store must not import internal/policy and
// internal/guard must not learn a store type.
func subjectWindowsOf(in map[string]store.GuardBudgetSubjectWindows) map[string]policy.BudgetWindowAmounts {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]policy.BudgetWindowAmounts, len(in))
	for id, w := range in {
		out[id] = policy.BudgetWindowAmounts{
			SessionUSD: w.SessionUSD, DailyUSD: w.DailyUSD,
			WeeklyUSD: w.WeeklyUSD, MonthlyUSD: w.MonthlyUSD,
			SessionTokens: w.SessionTokens, DailyTokens: w.DailyTokens,
			WeeklyTokens: w.WeeklyTokens, MonthlyTokens: w.MonthlyTokens,
		}
	}
	return out
}

// guardScannerAdapter bridges the daemon's shared *guard.Guard +
// *store.Store behind proxy.GuardScanner — the pipelineAdapter /
// costEngineAdapter pattern: the proxy package holds only its own
// plain types; persistence and alerting live here, behind the seam.
// mcp, when non-nil, receives the §9.2 MCP tool-declaration
// observations the request scan surfaces.
type guardScannerAdapter struct {
	g      *guard.Guard
	st     *store.Store
	logger *slog.Logger
	mcp    *mcpsecRunner
}

// ScanRequest implements proxy.GuardScanner (§8.2 + §8.4). Verdicts
// persist synchronously through the one-owner store seam before the
// decision returns — rare (only verdict-bearing requests pay it), and
// an enforced deny/mask should be on the audit chain before the
// synthetic response leaves. Persistence failure is log-and-continue
// (§17.4): it never blocks the request decision.
//
// MCP declaration observations (§9.2) run DETACHED: the pin diff
// reads + writes the DB, and the request must not wait on it — the
// declarations describe config state, not this request's content.
func (a guardScannerAdapter) ScanRequest(_ context.Context, provider string, body []byte, sessionID string) proxy.GuardRequestResult {
	return a.finishScan(a.g.ScanProxyRequest(provider, body, sessionID, time.Now().UTC()))
}

// ScanPrompt / ScanRequestAfterPrompt implement proxy.PromptPhaseScanner
// (LIVE CORRECTION 2026-09-07): the proxy runs the prompt lane on the
// pre-compression body and the remaining scans on the final body -- see
// the interface's doc comment for why one post-compression scan cannot
// see a pasted secret (the pipeline forward-scrubs it first).
func (a guardScannerAdapter) ScanPrompt(_ context.Context, provider string, body []byte, sessionID string) proxy.GuardRequestResult {
	return a.finishScan(a.g.ScanProxyPrompt(provider, body, sessionID, time.Now().UTC()))
}

func (a guardScannerAdapter) ScanRequestAfterPrompt(_ context.Context, provider string, body []byte, sessionID string) proxy.GuardRequestResult {
	return a.finishScan(a.g.ScanProxyRequestAfterPrompt(provider, body, sessionID, time.Now().UTC()))
}

// finishScan persists/alerts the verdicts, hands MCP declarations to
// the off-path runner, and maps the guard result onto the proxy's
// action vocabulary -- shared by all three scan entry points.
func (a guardScannerAdapter) finishScan(res guard.ProxyRequestResult) proxy.GuardRequestResult {
	a.persistAndAlert(res.Verdicts)
	if len(res.MCPDecls) > 0 && a.mcp != nil {
		decls := res.MCPDecls
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			a.mcp.ObserveDecls(ctx, decls)
		}()
	}
	var out proxy.GuardRequestResult
	switch {
	// Group 3 (phase-3a review, docs/guard-prompt.md "Two follow-ups"
	// item 2): a prompt-lane block sets PromptDeny/PromptStatus/
	// PromptRuleID/PromptReason ALONGSIDE the generic Deny/DenyRuleID/
	// DenyReason fields (scanPrompt never sets Deny alone for a
	// prompt-lane block — see ProxyRequestResult's own doc comment),
	// so this case MUST be checked before the plain res.Deny case
	// below or a prompt-submit interrupt would render through the
	// wrong (egress-worded, always-403) body builder. Switches a
	// proxy-lane deny to the intended 400-for-ask-once/403-for-block
	// developer-facing wording (guardPromptDenyBody).
	case res.PromptDeny:
		out.Action = "prompt_deny"
		out.RuleID = res.PromptRuleID
		out.Reason = res.PromptReason
		out.Status = res.PromptStatus
	case res.Deny:
		out.Action = "deny"
		out.RuleID = res.DenyRuleID
		out.Reason = res.DenyReason
	case res.MaskedBody != nil:
		out.Action = "mask"
		out.Body = res.MaskedBody
	}
	return out
}

// InspectResponse implements proxy.GuardScanner (§8.3): flag/alert
// only — the proxy already delivered the response. apiTurnID anchors
// each persisted verdict to the api_turn this response was captured as
// (0 when the turn was dropped) so the obs trajectory enrichment can
// surface the verdict on the span.
func (a guardScannerAdapter) InspectResponse(_ context.Context, sessionID string, apiTurnID int64, tools []proxy.GuardToolUse) {
	in := make([]guard.ProxyToolUse, 0, len(tools))
	for _, t := range tools {
		in = append(in, guard.ProxyToolUse{Name: t.Name, Input: t.Input})
	}
	verdicts := a.g.InspectProxyResponse(sessionID, in, time.Now().UTC())
	if apiTurnID != 0 {
		for i := range verdicts {
			verdicts[i].Input.APITurnID = apiTurnID
		}
	}
	a.persistAndAlert(verdicts)
}

// persistAndAlert writes record-worthy verdicts through the one-owner
// guard store seam (detached context — the request context may die
// the moment the client has its bytes) and fires desktop alerts
// post-persist (the MaybeAlert call-site contract).
func (a guardScannerAdapter) persistAndAlert(verdicts []guard.ActionVerdict) {
	if len(verdicts) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := a.st.PersistGuardVerdicts(ctx, verdicts); err != nil {
		a.logger.Warn("guard: proxy verdict persist failed", "err", err)
	}
	for i := range verdicts {
		a.g.MaybeAlert(verdicts[i])
	}
}
