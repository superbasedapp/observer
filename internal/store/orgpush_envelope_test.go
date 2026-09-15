// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/processobs"
)

// This file is the COMPOSED-ENVELOPE sentinel for the 2026-08-26 host-crash
// incident (docs/plans/post-incident-task-queue-2026-08-26.md, Task 7 H1).
//
// The incident: the session-network-events wire composed a full 7-day
// request/response body snapshot with no envelope budget (233–253 MB against a
// 1 MiB configured maximum). The server verified the Ed25519 signature over its
// 32 MiB truncated read, so every push failed as an AUTH error; the retry
// backoff re-materialised the identical snapshot each cycle; the daemon reached
// 6.7 GB RSS / 90% CPU and amplified an independent host fault into three
// Hyper-V freezes.
//
// The commit that fixed it bounded exactly ONE wire. This file pins the general
// property instead — every wire family in PushBatch composes under the same
// budget spine — and, critically, makes a NEW unbudgeted wire fail loudly by
// name (TestPushBatchWireFamiliesAllBudgeted) rather than silently reintroduce
// the defect.

// envelopeWireFamilies names every slice field of PushBatch, mapped to a note
// recording where its rows come from and what a budget truncation DROPS. Every
// entry is seeded by seedEveryWireFamily, so a family listed here but not
// actually produced fails TestSelectUnpushedSince_ComposedEnvelopeRespectsBudget
// at the generous budget.
//
// Truncation semantics, by family shape:
//
//   - CURSOR wires (sessions, actions, api_turns, token_usage, guard_events,
//     otel_content) are id-ordered ASC and truncation drops the HIGHEST ids —
//     the cursor stays on the last row actually appended, so nothing is skipped;
//     the tail simply ships on the next tick. These keep the pre-existing
//     forward-progress exception: a single oversized row still ships when the
//     batch is otherwise empty.
//   - WINDOWED snapshot wires whose SQL orders most-recent-first (network
//     events, terminal runs, remote audit, benchmark runs) drop their OLDEST
//     rows first.
//   - GROUPED aggregate wires (day/model/session/project buckets) are key-
//     ordered, so truncation drops the LAST buckets in key order — arbitrary
//     with respect to value, but never lossy: each is a whole-window recompute
//     the server upserts by natural key, so the dropped buckets are recomposed
//     on the next push.
var envelopeWireFamilies = map[string]string{
	// --- cursor wires (bounded by the fits() guard, id-ordered ASC) ---
	"Sessions":    "sessions JOIN projects; truncation defers the highest rowids",
	"Actions":     "actions; truncation defers the highest ids",
	"APITurns":    "api_turns; truncation defers the highest ids",
	"TokenUsage":  "token_usage; truncation defers the highest ids",
	"GuardEvents": "guard_events; truncation defers the highest ids",
	"OTelContent": "otel_content bodies; truncation defers the highest ids",

	// --- teams-tier aggregates (fitRows, key-ordered buckets) ---
	"RoutingSummaries":     "SelectRoutingSummaries; drops trailing (day,tier,reason,mode) buckets",
	"CacheSummaries":       "SelectCacheSummaries; drops trailing (day,model,kind) buckets",
	"CodeintelSummaries":   "SelectCodeintelSummaries; drops trailing (project,lang) buckets",
	"ProcessSummaries":     "SelectProcessSummaries; drops trailing (day,tool) buckets",
	"TerminalSummaries":    "SelectTerminalSummaries; drops trailing (day,tool,kind) buckets",
	"RemoteAuditSummaries": "SelectRemoteAuditSummaries; drops trailing buckets",
	"RoutingDetails":       "SelectRoutingDetail; drops trailing (day,model,turn_kind) buckets",
	"LimitGauges":          "SelectLimitGauges; drops trailing (day,provider) buckets",

	// --- session-scoped enterprise wires (fitRows) ---
	"SessionVerbositySummaries": "SelectSessionVerbositySummaries; drops trailing sessions in id order",
	"SessionCacheSummaries":     "SelectSessionCacheSummaries; drops trailing (session,model,kind) buckets",
	"SessionCacheEvents":        "SelectSessionCacheEvents; per-session capped at 500 most-recent in SQL, then chronological — fitRows drops the trailing (session,timestamp) events",
	"SessionProcesses":          "SelectSessionProcessRows; per-session most-recent-first, drops oldest runs",
	"SessionNetworkEvents":      "SelectSessionNetworkEventsBounded; per-session most-recent-first, drops oldest events",

	// --- node session-detail trickle-up (fitSnapshot; each under its OWN
	// tier flag, with a SECOND shipsRawContent() gate on the content columns
	// INSIDE the row rather than on the family) ---
	"SessionTaskItems":       "SelectSessionTaskItems; key-ordered per session, drops trailing items",
	"SessionTaskTransitions": "SelectSessionTaskTransitions; chronological per session, drops trailing transitions",
	"SessionToolAccounts":    "SelectSessionToolAccounts; chronological per session, drops trailing observations",

	// --- Lines-of-Code aggregates (fitSnapshot; DEFAULT posture, not
	// shipsRawContent-gated) ---
	"SessionLOC": "SelectSessionLOCSummaries; drops trailing (session,project root) rows in session-id order",
	"LOCDays":    "SelectLOCDaySummaries; drops trailing (day,project root) buckets in day order",

	// --- wave-3 per-developer enterprise wires (fitRows) ---
	"AdvisorSuggestions": "advisor provider snapshot; drops trailing suggestions",
	"ProjectPatterns":    "SelectProjectPatternRows; drops trailing (project,kind) rows",
	"BenchmarkRuns":      "SelectBenchmarkOrgRows; started_at DESC, drops oldest runs",
	"BenchmarkAttempts":  "SelectBenchmarkOrgRows; drops trailing attempts of the oldest kept runs",
	"CompressionStats":   "SelectCompressionStatRows; drops trailing (day,mechanism) buckets",
	"RoutingDevRows":     "SelectRoutingDevRows; drops trailing (day,model,turn_kind,mode) buckets",
	"CodeintelDevRows":   "SelectCodeintelDevRows; drops trailing (project,lang) buckets",
	"TerminalRuns":       "SelectTerminalRunRows; launched_at DESC, drops oldest runs",
	"TerminalCommands":   "SelectTerminalCommandRows; per-run turn_seq DESC, drops oldest commands",
	"RemoteAudit":        "SelectRemoteAuditRows; id DESC, drops oldest events",
	"GuardPins":          "SelectGuardPinRows; drops trailing pins",
	"GuardApprovals":     "SelectGuardApprovalRows; drops trailing approvals",

	// --- obs provider tiers (fitRows, all windowed-recompute) ---
	"ObsSummaries":         "obs T1 provider; drops trailing (day,model) buckets",
	"ObsTraces":            "obs T2 provider; drops trailing traces",
	"ObsSpans":             "obs T2 provider; drops trailing spans (their trace may already be truncated — the server upsert reconciles on the next window)",
	"ObsSpanEvents":        "obs T2 provider; drops trailing span events",
	"ObsContent":           "obs T3 provider; drops trailing content bodies",
	"ObsEvalRuns":          "obs T4 provider; drops trailing eval-run summaries",
	"ObsEndUserSpend":      "obs T5 provider; drops trailing (day,end_user) buckets",
	"ObsAdmissionEvents":   "obs T6 provider; drops trailing verdict events",
	"ObsAdmissionPolicies": "obs T6 provider; drops trailing policy snapshots",
	"ObsEvalItems":         "obs T7 provider; drops trailing per-item scores",
	"ObsEgressDecisions":   "obs T8 provider; drops trailing egress decisions",
}

// TestPushBatchWireFamiliesAllBudgeted is the structural half of the sentinel:
// it walks PushBatch by reflection and fails, BY NAME, on any slice field that
// is not registered in envelopeWireFamilies. A new wire added to the push
// envelope therefore cannot merge without its author consciously deciding how it
// composes under the budget and seeding it into the composed-envelope test
// below — which is exactly the review step the 2026-08-26 defect skipped.
func TestPushBatchWireFamiliesAllBudgeted(t *testing.T) {
	t.Parallel()
	bt := reflect.TypeOf(PushBatch{})
	for i := 0; i < bt.NumField(); i++ {
		f := bt.Field(i)
		if f.Type.Kind() != reflect.Slice {
			continue
		}
		if _, ok := envelopeWireFamilies[f.Name]; !ok {
			t.Errorf("PushBatch.%s (%s) is a wire family with NO envelope-budget coverage.\n"+
				"Every slice field on the push envelope must (a) compose through fitRows(budget, …) in "+
				"internal/store/orgpush.go — the six cursor wires use the fits() guard instead — and "+
				"(b) be registered in envelopeWireFamilies here with a note on what truncation drops, plus "+
				"seeded by seedEveryWireFamily.\n"+
				"An unbudgeted wire is the 2026-08-26 host-crash defect: a snapshot that outgrows "+
				"[org_client].max_push_bytes parks the push loop in silent 1h ErrBatchTooLarge cycles "+
				"instead of degrading by truncation.", f.Name, f.Type)
		}
	}
	for name := range envelopeWireFamilies {
		if _, ok := bt.FieldByName(name); !ok {
			t.Errorf("envelopeWireFamilies names %q but PushBatch has no such field — "+
				"remove the stale registry entry (and its seeding)", name)
		}
	}
}

// envelopeShareOptions turns every content/detail/obs tier ON, so a single
// compose exercises every wire family at once. This is the widest posture the
// node can be in (admin-managed enterprise), which is precisely the posture the
// incident happened under.
func envelopeShareOptions() ShareOptions {
	return ShareOptions{
		AdminManaged:    true,
		FullToolBodies:  true,
		RoutingSummary:  true,
		CacheDetail:     true,
		RoutingDetail:   true,
		LimitGauge:      true,
		CodeintelDetail: true,
		ProcessDetail:   true,
		TerminalDetail:  true,
		ObsSummary:      true,
		ObsTraces:       true,
		ObsContent:      true,
		ObsEvalSummary:  true,
		ObsAdmission:    true,
		ObsEvalItems:    true,
		ObsEgress:       true,
		// Node session-detail trickle-up W2/W3 — their own tiers, on for the
		// same reason every other tier is: this fixture is the WIDEST posture
		// a node can be in.
		TaskDetail:        true,
		ToolAccountDetail: true,
	}
}

// envelopePad returns n bytes of filler, used to make each seeded family large
// enough that the composed envelope genuinely exceeds a 1 MiB budget.
func envelopePad(n int) string { return strings.Repeat("p", n) }

// stubEnvelopeObsProviders wires all eight obs tiers with padded rows so the
// provider-seam families are as budget-hungry as the SQL-backed ones.
func stubEnvelopeObsProviders() ObsOrgProviders {
	body := envelopePad(4 << 10)
	return ObsOrgProviders{
		Summaries: func(context.Context, int) ([]orgcontract.ObsSummaryRow, error) {
			out := make([]orgcontract.ObsSummaryRow, 0, 20)
			for i := 0; i < 20; i++ {
				out = append(out, orgcontract.ObsSummaryRow{
					Day: "2026-08-2" + fmt.Sprint(i%10), Model: "gpt-4o-" + body, Traces: int64(i),
				})
			}
			return out, nil
		},
		Spans: func(context.Context, orgcontract.ObsCursor, int) (orgcontract.ObsSpanBatch, error) {
			var b orgcontract.ObsSpanBatch
			for i := 0; i < 20; i++ {
				id := fmt.Sprintf("t-%d", i)
				b.Traces = append(b.Traces, orgcontract.ObsTraceRow{
					TraceID: id, Source: body, ProjectRoot: "/repo/obs", SpanCount: 1,
				})
				b.Spans = append(b.Spans, orgcontract.ObsSpanRow{
					TraceID: id, SpanID: id + "-s", Name: body, Model: "gpt-4o",
				})
				b.Events = append(b.Events, orgcontract.ObsSpanEventRow{
					TraceID: id, SpanID: id + "-s", Name: body, Time: "2026-08-25T00:00:00Z",
				})
			}
			return b, nil
		},
		Content: func(context.Context, orgcontract.ObsCursor, int) ([]orgcontract.ObsContentRow, error) {
			out := make([]orgcontract.ObsContentRow, 0, 20)
			for i := 0; i < 20; i++ {
				out = append(out, orgcontract.ObsContentRow{
					TraceID: fmt.Sprintf("t-%d", i), SpanID: fmt.Sprintf("t-%d-s", i),
					Kind: "prompt", ContentHash: "h", Content: body,
				})
			}
			return out, nil
		},
		EvalRuns: func(context.Context, int) ([]orgcontract.ObsEvalRow, error) {
			out := make([]orgcontract.ObsEvalRow, 0, 20)
			for i := 0; i < 20; i++ {
				out = append(out, orgcontract.ObsEvalRow{
					Day: "2026-08-25", DatasetName: body, RunName: fmt.Sprintf("run-%d", i), Total: 3,
				})
			}
			return out, nil
		},
		EndUserSpend: func(context.Context, int) ([]orgcontract.ObsEndUserSpendRow, error) {
			out := make([]orgcontract.ObsEndUserSpendRow, 0, 20)
			for i := 0; i < 20; i++ {
				out = append(out, orgcontract.ObsEndUserSpendRow{
					Day: "2026-08-25", EndUser: fmt.Sprintf("cust-%d-%s", i, body), CostUSD: 1,
				})
			}
			return out, nil
		},
		Admission: func(context.Context, orgcontract.ObsCursor, int) (orgcontract.ObsAdmissionBatch, error) {
			var b orgcontract.ObsAdmissionBatch
			for i := 0; i < 20; i++ {
				b.Events = append(b.Events, orgcontract.ObsAdmissionRow{
					TS: "2026-08-25T00:00:00Z", Mode: "enforce", Decision: "allow",
					Tenant: "acme", EndUser: "u", ReasonExcerpt: body,
				})
				b.Policies = append(b.Policies, orgcontract.ObsAdmissionPolicyRow{
					PolicyHash: fmt.Sprintf("ph-%d", i), CreatedAt: "2026-08-25T00:00:00Z",
					Mode: "enforce", Scope: "org", Body: body,
				})
			}
			return b, nil
		},
		EvalItems: func(context.Context, orgcontract.ObsCursor, int) (orgcontract.ObsEvalItemBatch, error) {
			var b orgcontract.ObsEvalItemBatch
			for i := 0; i < 20; i++ {
				b.Items = append(b.Items, orgcontract.ObsEvalItemRow{
					RunID: int64(i), RunName: fmt.Sprintf("run-%d", i), DatasetName: body,
				})
			}
			return b, nil
		},
		Egress: func(context.Context, orgcontract.ObsCursor, int) (orgcontract.ObsEgressBatch, error) {
			var b orgcontract.ObsEgressBatch
			for i := 0; i < 20; i++ {
				b.Events = append(b.Events, orgcontract.ObsEgressRow{
					TS: "2026-08-25T00:00:00Z", Mode: "enforce", RuleName: body,
					Action: "deny", ReasonCode: "policy", RowHash: fmt.Sprintf("rh-%d", i),
					Tenant: "acme", User: "u",
				})
			}
			return b, nil
		},
	}
}

// seedEveryWireFamily populates EVERY content-bearing wire family at once, with
// enough bulk that the composed envelope is several megabytes — i.e. the shape
// of the enterprise node the incident happened on, not a toy fixture.
//
// It is deliberately a flat, linear seed script — one independent stanza per
// wire family — so a NEW family is appended rather than woven in.
//
//nolint:gocyclo // see above: length is the point, not branchiness.
func seedEveryWireFamily(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	pad := envelopePad(4 << 10)

	// Cursor wires: sessions / actions / api_turns / token_usage.
	pid := seedPushData(t, s, s.db)
	sessionID := "s1"

	// Extra actions so the actions wire is not a two-row toy.
	extra := make([]models.Action, 0, 40)
	for i := 0; i < 40; i++ {
		extra = append(extra, models.Action{
			SessionID: sessionID, ProjectID: pid, Timestamp: now,
			ActionType: models.ActionReadFile, Target: fmt.Sprintf("/repo/f%d.go", i), Success: true,
			Tool: models.ToolClaudeCode, RawToolOutput: pad, ContentBytes: 4096,
			SourceFile: "f.jsonl", SourceEventID: fmt.Sprintf("ex-%d", i),
		})
	}
	if _, err := s.InsertActions(ctx, extra); err != nil {
		t.Fatalf("seed extra actions: %v", err)
	}

	// guard_events (cursor wire).
	events := make([]GuardEventRow, 0, 20)
	for i := 0; i < 20; i++ {
		events = append(events, GuardEventRow{
			TS: now, SessionID: sessionID, Tool: "claude-code", EventKind: "policy_check",
			RuleID: "dangerous-command", Category: "shell", Severity: "high", Decision: "allow",
			Source: "hook", TargetHash: "th", Reason: pad[:1024], TargetExcerpt: "rm -rf /tmp/x",
		})
	}
	if _, err := s.InsertGuardEvents(ctx, events); err != nil {
		t.Fatalf("seed guard events: %v", err)
	}

	// otel_content (cursor wire) — real bodies, the biggest cursor-side rows.
	content := make([]models.OTelContent, 0, 20)
	for i := 0; i < 20; i++ {
		content = append(content, models.OTelContent{
			RequestID: fmt.Sprintf("req-%d", i), SessionID: sessionID, Kind: "prompt",
			Content: envelopePad(16 << 10), ContentHash: fmt.Sprintf("h-%d", i),
			Timestamp: now, Source: "cc_otel",
		})
	}
	if _, err := s.InsertOTelContent(ctx, content); err != nil {
		t.Fatalf("seed otel_content: %v", err)
	}

	// router_decisions → RoutingSummaries + RoutingDevRows + RoutingDetails.
	decisions := make([]RouterDecisionRow, 0, 30)
	for i := 0; i < 30; i++ {
		decisions = append(decisions, RouterDecisionRow{
			SessionID: sessionID, Timestamp: now.Add(-time.Duration(i) * time.Minute),
			Mode: "advise", Channel: "B",
			OriginalModel: "claude-opus-4-8", SelectedModel: fmt.Sprintf("claude-haiku-4-5-%d", i),
			TurnKind: "read_only", PolicyHash: "h1", ReasonCodes: []string{"cheap_turn"},
			EstSavingsUSD: 0.4, CacheForfeitUSD: 0.01, Applied: true,
		})
	}
	if err := s.InsertRouterDecisions(ctx, decisions); err != nil {
		t.Fatalf("seed router decisions: %v", err)
	}

	// cache_events → CacheSummaries + SessionCacheSummaries.
	cacheEvents := make([]CacheEventRow, 0, 30)
	for i := 0; i < 30; i++ {
		cacheEvents = append(cacheEvents, CacheEventRow{
			SessionID: sessionID, Tier: "proxy", Timestamp: now.Add(-time.Duration(i) * time.Minute),
			Model: fmt.Sprintf("claude-opus-4-7-%d", i), Kind: "hit", Cause: "suffix_growth",
			TokensRead: 9000,
		})
	}
	if _, err := s.InsertCacheEvents(ctx, cacheEvents); err != nil {
		t.Fatalf("seed cache events: %v", err)
	}

	// process_runs / process_events → SessionProcesses + ProcessSummaries.
	for i := 0; i < 10; i++ {
		runID := seedProcessRun(t, s, fmt.Sprintf("proc-%d", i), sessionID, 200+i,
			now.Add(-time.Duration(i)*time.Minute), true)
		seedProcessEvents(t, s, runID, fmt.Sprintf("proc-%d", i), sessionID, 2)
	}

	// network events with bodies → SessionNetworkEvents (the incident wire).
	body := envelopePad(32 << 10)
	for i := 0; i < 20; i++ {
		seedNetworkEvent(t, s, sessionID, "proxy:env", now.Add(-time.Duration(i)*time.Second),
			map[string]any{"capture_source": "proxy", "method": "POST"},
			&processobs.NetworkBodyCapture{CaptureSource: "proxy", RequestBody: body, ResponseBody: body})
	}

	// project_patterns → ProjectPatterns.
	for i := 0; i < 20; i++ {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO project_patterns (project_id, pattern_type, pattern_data, confidence,
			   last_reinforced_at, observation_count, source_tools)
			 VALUES (?, 'hot_file', ?, 0.9, ?, 5, 'claude-code')`,
			pid, fmt.Sprintf(`{"file_path":"/repo/f%d.go","pad":%q}`, i, pad), timestamp(now)); err != nil {
			t.Fatalf("seed project_patterns: %v", err)
		}
	}

	// benchmarks → BenchmarkRuns + BenchmarkAttempts.
	seedBenchmarkOrgRun(t, s, "bench-env", now.Add(-time.Hour))

	// compression_events → CompressionStats.
	for i := 0; i < 10; i++ {
		seedCompressionEvent(t, s, now.Add(-time.Duration(i)*time.Hour), fmt.Sprintf("shell-%d", i), 10000, 4000)
	}

	// codeintel_* → CodeintelDevRows + CodeintelSummaries.
	seedCodeintelFanout(t, s)

	// terminal_runs / terminal_commands → TerminalRuns + TerminalCommands +
	// TerminalSummaries.
	for i := 0; i < 10; i++ {
		runKey := fmt.Sprintf("run-env-%d", i)
		if err := s.InsertTerminalRun(ctx, TerminalRun{
			RunID: runKey, Tool: "claude-code", Kind: "attach",
			LaunchedAt: now.Add(-time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatalf("seed terminal run: %v", err)
		}
		if err := s.UpsertCorrelation(ctx, TerminalCorrelation{
			RunID: runKey, SessionID: sessionID, Confidence: 0.9, Source: "oob",
		}); err != nil {
			t.Fatalf("seed terminal correlation: %v", err)
		}
		for seq := 1; seq <= 3; seq++ {
			if err := s.InsertTerminalCommand(ctx, TerminalCommand{
				RunID: runKey, TurnSeq: seq, StartedAt: now, Trust: "oob",
				CmdHash: fmt.Sprintf("cmd-%d-%d", i, seq),
			}); err != nil {
				t.Fatalf("seed terminal command: %v", err)
			}
		}
	}

	// remote_audit → RemoteAudit + RemoteAuditSummaries.
	for i := 0; i < 20; i++ {
		if err := s.InsertRemoteAudit(ctx, RemoteAuditEvent{
			TS: now.Add(-time.Duration(i) * time.Minute), Kind: "http_request",
			SessionID: sessionID, Principal: "view", RemoteAddr: "127.0.0.1",
			Route: fmt.Sprintf("/api/x/%d", i), Decision: "allow", Detail: "ok",
		}); err != nil {
			t.Fatalf("seed remote audit: %v", err)
		}
	}

	// guard_pins / guard_approvals → GuardPins + GuardApprovals.
	for i := 0; i < 10; i++ {
		if err := s.UpsertGuardPin(ctx, GuardPinRow{
			Kind: "mcp_server", Name: fmt.Sprintf("observer-%d", i), Client: "claude-code",
			PinHash: "deadbeef", FirstSeen: now.Add(-48 * time.Hour), LastVerified: now, Status: "pinned",
		}); err != nil {
			t.Fatalf("seed guard pin: %v", err)
		}
		if _, err := s.InsertGuardApproval(ctx, GuardApprovalRow{
			TS: now, RuleID: fmt.Sprintf("rule-%d", i), Scope: "session",
			SessionID: sessionID, GrantedBy: "alice@example.com",
			ExpiresAt: now.Add(24 * time.Hour),
		}); err != nil {
			t.Fatalf("seed guard approval: %v", err)
		}
	}

	// file_changes → SessionLOC + LOCDays. Two actors and two categories so
	// the fold exercises more than one bucket per session.
	locRows := make([]FileChangeRow, 0, 40)
	for i := 0; i < 20; i++ {
		locRows = append(locRows,
			FileChangeRow{
				SessionID: sessionID, ProjectID: pid,
				FilePathHash: fmt.Sprintf("fh-ai-%d", i), InputDigest: fmt.Sprintf("dg-ai-%d", i),
				Language: "go", Category: "code",
				Actor: LOCActorAI, Confidence: "high", Source: LOCSourceEdit,
				Stats:   loc.Stats{AddedCode: 40 + i, ModifiedCode: 3, DeletedCode: 2, AddedComment: 1},
				Version: loc.Version, SavedAt: now.Add(-time.Duration(i) * time.Hour),
			},
			FileChangeRow{
				SessionID: sessionID, ProjectID: pid,
				FilePathHash: fmt.Sprintf("fh-hu-%d", i),
				Language:     "go", Category: "code",
				Actor: LOCActorHuman, Confidence: "high", Source: LOCSourceEditor,
				Stats:   loc.Stats{AddedCode: 5, ModifiedCode: 1},
				Version: loc.Version, SavedAt: now.Add(-time.Duration(i) * time.Hour),
			})
	}
	if _, err := s.InsertFileChanges(ctx, locRows); err != nil {
		t.Fatalf("seed file_changes: %v", err)
	}

	// task_items + task_transitions → SessionTaskItems + SessionTaskTransitions.
	// Written directly rather than through applyTaskEvents so the seed does not
	// depend on the taskflow decoder's own tool vocabulary; the wire Select
	// reads these columns either way.
	for i := 0; i < 20; i++ {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO task_items
			   (session_id, tool, key, key_kind, content, active_form, owner,
			    raw_status, status, order_index, first_seen_at, last_seen_at, unmatched)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0)`,
			sessionID, "claude-code", fmt.Sprintf("task-%d", i), "native_id",
			pad, pad, "alice@example.com", "in_progress", "in_progress", i,
			timestamp(now), timestamp(now)); err != nil {
			t.Fatalf("seed task_items: %v", err)
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO task_transitions
			   (session_id, key, from_status, to_status, ts, action_id, source_event_id)
			 VALUES (?,?,?,?,?,?,?)`,
			sessionID, fmt.Sprintf("task-%d", i), "pending", "in_progress",
			timestamp(now), int64(i), fmt.Sprintf("evt-task-%d", i)); err != nil {
			t.Fatalf("seed task_transitions: %v", err)
		}
	}

	// tool_account_observations → SessionToolAccounts.
	for i := 0; i < 20; i++ {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO tool_account_observations
			   (session_id, tool, binding_kind, binding_id, role, account_key,
			    email, name, account_id, source, scope, stage, observed_at)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			sessionID, "claude-code", "message", fmt.Sprintf("msg-%d", i), "assistant",
			fmt.Sprintf("acct-%d-%s", i, pad), "dev@acme.example", "Dev "+pad, "acct-id",
			"hook", "session", "start", timestamp(now)); err != nil {
			t.Fatalf("seed tool_account_observations: %v", err)
		}
	}

	// limit_snapshots → LimitGauges.
	util := 0.42
	for i := 0; i < 10; i++ {
		if err := s.InsertLimitSnapshot(ctx, models.LimitSnapshot{
			ScopeHash: "default", Provider: fmt.Sprintf("anthropic-%d", i), SessionID: sessionID,
			ObservedAt:   now.Add(-time.Duration(i) * time.Hour),
			Window5hUtil: &util, Window7dUtil: &util, Status: "ok",
		}); err != nil {
			t.Fatalf("seed limit snapshot: %v", err)
		}
	}

	// advisor provider → AdvisorSuggestions.
	s.SetAdvisorOrgProvider(func(context.Context) ([]orgcontract.AdvisorSuggestionRow, error) {
		out := make([]orgcontract.AdvisorSuggestionRow, 0, 20)
		for i := 0; i < 20; i++ {
			out = append(out, orgcontract.AdvisorSuggestionRow{
				SuggestionKey: fmt.Sprintf("k-%d", i), Detector: "context_balloon",
				Category: "cost", Scope: "session", ScopeID: sessionID,
				Severity: "advice", Title: pad, Nudge: pad,
			})
		}
		return out, nil
	})

	// obs provider seam → the eight Obs* tiers.
	s.SetObsOrgProviders(stubEnvelopeObsProviders())
}

// TestSelectUnpushedSince_ComposedEnvelopeRespectsBudget is the behavioural half
// of the sentinel: with EVERY content-bearing wire family seeded large and every
// tier opted in, the COMPOSED batch must respect maxBytes — not merely each wire
// in isolation. It also proves the bound is a TRUNCATION, not a drop: at a
// generous budget every registered family is present.
func TestSelectUnpushedSince_ComposedEnvelopeRespectsBudget(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedEveryWireFamily(t, s)
	share := envelopeShareOptions()

	// Generous budget: every family composes in full. This is also what proves
	// the seeding actually produced each family — a registry entry with no
	// seeding fails HERE with the family named.
	const wide = 64 << 20
	full, err := s.SelectUnpushedSince(ctx, PushCursor{}, wide, "org-1", "dev@acme.example", share, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (wide): %v", err)
	}
	fv := reflect.ValueOf(full)
	for name, note := range envelopeWireFamilies {
		f := fv.FieldByName(name)
		if !f.IsValid() {
			t.Fatalf("PushBatch has no field %q", name)
		}
		if f.Len() == 0 {
			t.Errorf("wire family %s is EMPTY at a %d-byte budget — seedEveryWireFamily must populate "+
				"every family registered in envelopeWireFamilies, otherwise the small-budget assertion "+
				"below is vacuous for it (%s)", name, wide, note)
		}
	}
	if full.EstBytes < 1<<20 {
		t.Fatalf("seeded envelope is only %d bytes — the fixture must exceed the 1 MiB budget "+
			"for the truncation assertion to mean anything", full.EstBytes)
	}

	// Production budget: the default [org_client].max_push_bytes. The composed
	// envelope must fit. Before the spine, the network wire alone shipped
	// 233–253 MB here.
	const maxBytes = 1 << 20
	batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, maxBytes, "org-1", "dev@acme.example", share, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if batch.EstBytes > maxBytes {
		t.Fatalf("composed EstBytes = %d exceeds maxBytes = %d — some wire family composes "+
			"outside the envelope budget spine", batch.EstBytes, maxBytes)
	}
	if batch.Empty() {
		t.Fatal("a budgeted batch must still carry forward progress, not degrade to empty")
	}
	// Truncation, not collapse: the cursor wires still made progress.
	if batch.Cursor.Sessions == 0 {
		t.Errorf("cursor did not advance for the sessions wire: %+v", batch.Cursor)
	}
}

// TestSelectUnpushedSince_BudgetedCursorsNeverSkipRows proves the spine did not
// disturb cursor semantics: a truncated batch leaves the cursor on the last row
// it actually shipped, so draining across successive pushes yields every row
// exactly once with no gap. This is the property that makes truncation safe —
// snapshot wires are idempotent recomputes, cursor wires are not.
// TestSelectUnpushedSince_SerializedSizeNeverExceedsBudget pins the invariant
// the 2026-08-27 live pause proved EstBytes alone does not: the batch's ACTUAL
// serialized JSON must fit maxBytes. Per-row jsonSize excludes the inter-row
// commas and the envelope's top-level keys, so before pushEnvelopeCursorSlack a
// many-small-rows backlog composed est just under the cap and serialized OVER
// it (693 bytes over on a 1,371-row drain), tripping orgclient's exact-size
// check and pausing the push loop. Asserted across every drain tick at a small
// budget so the comma error dominates — this is the mutation-sensitive shape.
func TestSelectUnpushedSince_SerializedSizeNeverExceedsBudget(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedEveryWireFamily(t, s)
	share := envelopeShareOptions()

	const maxBytes = 96 << 10
	cur := PushCursor{}
	for i := 0; i < 300; i++ {
		batch, err := s.SelectUnpushedSince(ctx, cur, maxBytes, "org-1", "dev@acme.example", share, ScopeOptions{})
		if err != nil {
			t.Fatalf("SelectUnpushedSince (tick %d): %v", i, err)
		}
		if batch.RowCount() == 0 {
			break
		}
		raw, err := json.Marshal(batch)
		if err != nil {
			t.Fatalf("marshal (tick %d): %v", i, err)
		}
		// The forward-progress exception legitimately ships ONE oversized
		// row; only multi-row batches must fit exactly.
		if batch.RowCount() > 1 && int64(len(raw)) > maxBytes {
			t.Fatalf("tick %d: serialized batch = %d bytes exceeds maxBytes = %d "+
				"(rows=%d, est=%d) — the cursor fill left no room for inter-row "+
				"commas / envelope keys, the exact defect that paused live pushes "+
				"on 2026-08-27", i, len(raw), maxBytes, batch.RowCount(), batch.EstBytes)
		}
		cur = batch.Cursor
	}
}

// TestSessionProcessAndActionWireFieldsCompatBothDirections pins the CLAUDE.md
// compat invariant for the W-A additions (SessionProcessRow.{MessageID,
// WorkingSetBytes,ThreadCount,MetricSamplesJSON} and ActionRow.StopReason):
//
//   - new node -> old server: the fields serialize under their json keys, and
//     an older server simply ignores unknown keys on decode.
//   - a row that captured none of them serializes the pre-feature shape
//     (omitempty keeps the keys OUT), so nothing changes for an old reader.
//   - old node -> new server: an envelope that predates the fields decodes with
//     them at their zero values — no error, no phantom data.
func TestSessionProcessAndActionWireFieldsCompatBothDirections(t *testing.T) {
	t.Parallel()

	// --- SessionProcessRow ---
	full, err := json.Marshal(orgcontract.SessionProcessRow{
		SessionID: "s1", RunKey: "r1", StartedAt: "2026-08-24T10:00:00Z",
		MessageID: "msg_1", WorkingSetBytes: 4096, ThreadCount: 9,
		MetricSamplesJSON: `[{"t":"x","cpu_ms":1}]`,
	})
	if err != nil {
		t.Fatalf("marshal full process row: %v", err)
	}
	for _, key := range []string{`"message_id"`, `"working_set_bytes"`, `"thread_count"`, `"metric_samples_json"`} {
		if !strings.Contains(string(full), key) {
			t.Errorf("populated process row is missing wire key %s: %s", key, full)
		}
	}

	bare, err := json.Marshal(orgcontract.SessionProcessRow{SessionID: "s1", RunKey: "r1", StartedAt: "t"})
	if err != nil {
		t.Fatalf("marshal bare process row: %v", err)
	}
	for _, key := range []string{"message_id", "working_set_bytes", "thread_count", "metric_samples_json"} {
		if strings.Contains(string(bare), key) {
			t.Errorf("zero-value process row carries %q key; it must be omitempty so an old reader sees the pre-feature shape: %s", key, bare)
		}
	}

	var decodedProc orgcontract.SessionProcessRow
	if err := json.Unmarshal([]byte(`{"session_id":"s1","run_key":"r1","started_at":"t","pid":3}`), &decodedProc); err != nil {
		t.Fatalf("decode pre-feature process row: %v", err)
	}
	if decodedProc.MessageID != "" || decodedProc.WorkingSetBytes != 0 || decodedProc.ThreadCount != 0 || decodedProc.MetricSamplesJSON != "" {
		t.Errorf("pre-feature process row decoded with phantom metrics: %+v", decodedProc)
	}

	// --- ActionRow.StopReason + ActionRow.MessageID ---
	fullAction, err := json.Marshal(orgcontract.ActionRow{SessionID: "s1", ActionType: "assistant_turn", StopReason: "end_turn", MessageID: "msg_1"})
	if err != nil {
		t.Fatalf("marshal action with stop reason: %v", err)
	}
	for _, key := range []string{`"stop_reason"`, `"message_id"`} {
		if !strings.Contains(string(fullAction), key) {
			t.Errorf("populated action is missing key %s: %s", key, fullAction)
		}
	}
	bareAction, err := json.Marshal(orgcontract.ActionRow{SessionID: "s1", ActionType: "read_file"})
	if err != nil {
		t.Fatalf("marshal action without stop reason: %v", err)
	}
	for _, key := range []string{"stop_reason", "message_id"} {
		if strings.Contains(string(bareAction), key) {
			t.Errorf("zero %s must be omitempty: %s", key, bareAction)
		}
	}
	var decodedAction orgcontract.ActionRow
	if err := json.Unmarshal([]byte(`{"session_id":"s1","action_type":"read_file"}`), &decodedAction); err != nil {
		t.Fatalf("decode pre-feature action row: %v", err)
	}
	if decodedAction.StopReason != "" || decodedAction.MessageID != "" {
		t.Errorf("pre-feature action decoded with phantom stop_reason %q / message_id %q", decodedAction.StopReason, decodedAction.MessageID)
	}

	// --- TokenUsageRow.MessageID ---
	fullTU, err := json.Marshal(orgcontract.TokenUsageRow{SessionID: "s1", MessageID: "msg_1"})
	if err != nil {
		t.Fatalf("marshal token usage with message id: %v", err)
	}
	if !strings.Contains(string(fullTU), `"message_id"`) {
		t.Errorf("populated token usage is missing message_id key: %s", fullTU)
	}
	bareTU, err := json.Marshal(orgcontract.TokenUsageRow{SessionID: "s1"})
	if err != nil {
		t.Fatalf("marshal token usage without message id: %v", err)
	}
	if strings.Contains(string(bareTU), "message_id") {
		t.Errorf("zero TokenUsageRow.MessageID must be omitempty: %s", bareTU)
	}
	var decodedTU orgcontract.TokenUsageRow
	if err := json.Unmarshal([]byte(`{"session_id":"s1","source_event_id":"e1"}`), &decodedTU); err != nil {
		t.Fatalf("decode pre-feature token usage row: %v", err)
	}
	if decodedTU.MessageID != "" {
		t.Errorf("pre-feature token usage decoded with phantom message_id %q", decodedTU.MessageID)
	}
}

func TestSelectUnpushedSince_BudgetedCursorsNeverSkipRows(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedEveryWireFamily(t, s)
	share := envelopeShareOptions()

	total, err := s.CurrentMaxIDs(ctx)
	if err != nil {
		t.Fatalf("CurrentMaxIDs: %v", err)
	}

	seen := map[string]int{}
	cur := PushCursor{}
	for i := 0; i < 200; i++ {
		batch, err := s.SelectUnpushedSince(ctx, cur, 1<<20, "org-1", "dev@acme.example", share, ScopeOptions{})
		if err != nil {
			t.Fatalf("SelectUnpushedSince (drain %d): %v", i, err)
		}
		if batch.RowCount() == 0 {
			break
		}
		for _, r := range batch.Actions {
			seen["action:"+r.SourceEventID]++
		}
		if batch.Cursor.Actions < cur.Actions {
			t.Fatalf("actions cursor moved BACKWARDS: %d -> %d", cur.Actions, batch.Cursor.Actions)
		}
		cur = batch.Cursor
	}
	if cur.Actions != total.Actions {
		t.Errorf("drain ended at actions cursor %d, want the high-water %d — a budgeted cursor wire "+
			"must never leave rows permanently unshipped", cur.Actions, total.Actions)
	}
	for key, n := range seen {
		if n != 1 {
			t.Errorf("%s shipped %d times across the drain, want exactly 1", key, n)
		}
	}
}
