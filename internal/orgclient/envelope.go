package orgclient

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// EnvelopeMeta carries the envelope-level fields a PushBatch does not own:
// what the pushing client knows about itself.
type EnvelopeMeta struct {
	// AgentVersion is the pushing binary's version.
	AgentVersion string
	// MachineIdentity is the managed-tenancy machine fingerprint, "" otherwise.
	MachineIdentity string
	// SourceNodeKey is the per-device agent-access source key, "" otherwise.
	SourceNodeKey string
	// PushInterval is the pusher's cadence, stamped onto the budget posture.
	PushInterval time.Duration
}

// EnvelopeFromBatch is the ONE mapping from a composed PushBatch to the wire
// PushEnvelope. PushOnce uses it, and so does `observer cloud-session flush`
// (Rail S, docs/cloud-sessions.md), which ships the same envelope from a
// daemonless sandbox node instead of inventing a second wire.
// TestPushEnvelopeMapsEveryBatchFamily pins that every batch family is
// mapped here. from is the cursor the batch was selected above.
func EnvelopeFromBatch(batch store.PushBatch, from store.PushCursor, meta EnvelopeMeta) orgcontract.PushEnvelope {
	env := orgcontract.PushEnvelope{
		AgentVersion:    meta.AgentVersion,
		MachineIdentity: meta.MachineIdentity,
		SourceNodeKey:   meta.SourceNodeKey,
		CursorFrom:      maxCursor(from),
		CursorTo:        maxCursor(batch.Cursor),
		Sessions:        batch.Sessions,
		Actions:         batch.Actions,
		APITurns:        batch.APITurns,
		TokenUsage:      batch.TokenUsage,
		// Tombstones + resync manifests (agent migration 141, R2-TOMB):
		// omitempty, so a node with nothing deleted pushes a byte-identical
		// envelope, and a pre-R2-TOMB server ignores both keys.
		Deletions:                 batch.Deletions,
		SessionManifests:          batch.SessionManifests,
		RoutingSummaries:          batch.RoutingSummaries,
		CacheSummaries:            batch.CacheSummaries,
		CodeintelSummaries:        batch.CodeintelSummaries,
		ProcessSummaries:          batch.ProcessSummaries,
		SessionVerbositySummaries: batch.SessionVerbositySummaries,
		SessionCacheSummaries:     batch.SessionCacheSummaries,
		// Trickle-up wires (W2/W3/item 6b, 2026-09-11). Composed by their own
		// store seams under their share tiers; nil/empty otherwise. Every
		// PushBatch slice family with a same-named PushEnvelope field MUST be
		// mapped here - TestPushEnvelopeMapsEveryBatchFamily fails by name when
		// one is composed but never mapped (the class that dropped the obs
		// slices once and these four a second time).
		SessionCacheEvents:     batch.SessionCacheEvents,
		SessionTaskItems:       batch.SessionTaskItems,
		SessionTaskTransitions: batch.SessionTaskTransitions,
		SessionToolAccounts:    batch.SessionToolAccounts,
		SessionHookActivity:    batch.SessionHookActivity,
		SessionProcesses:       batch.SessionProcesses,
		// The process capture budget's rollups + counters (layer O1);
		// omitempty, so an older server ignores both keys.
		SessionProcessRollups:      batch.SessionProcessRollups,
		SessionProcessCaptureStats: batch.SessionProcessCaptureStats,
		SessionNetworkEvents:       batch.SessionNetworkEvents,
		SessionLOC:                 batch.SessionLOC,
		LOCDays:                    batch.LOCDays,
		SessionQuality:             batch.SessionQuality,
		CommitOwnership:            batch.CommitOwnership,
		// Delivery (commit to PR to merge, D-689): day counts from every
		// node; PR identity rows only under shipsRawContent(), decided by
		// store/deliverysummary.go. omitempty, so an older server ignores
		// both keys and a node with no evaluated commit sends neither.
		DeliveryDays:         batch.DeliveryDays,
		PullRequests:         batch.PullRequests,
		AdvisorSuggestions:   batch.AdvisorSuggestions,
		ProjectPatterns:      batch.ProjectPatterns,
		BenchmarkRuns:        batch.BenchmarkRuns,
		BenchmarkAttempts:    batch.BenchmarkAttempts,
		CompressionStats:     batch.CompressionStats,
		RoutingDevRows:       batch.RoutingDevRows,
		CodeintelDevRows:     batch.CodeintelDevRows,
		TerminalRuns:         batch.TerminalRuns,
		TerminalCommands:     batch.TerminalCommands,
		RemoteAudit:          batch.RemoteAudit,
		GuardPins:            batch.GuardPins,
		GuardApprovals:       batch.GuardApprovals,
		TerminalSummaries:    batch.TerminalSummaries,
		RemoteAuditSummaries: batch.RemoteAuditSummaries,
		// The sandbox posture aggregate (sandbox plan v2 section 8.4):
		// composed only under terminal_detail while the sandbox module is
		// active; nil otherwise, so both omitempty keys are absent.
		SandboxPosture:    batch.SandboxPosture,
		SandboxCapability: batch.SandboxCapability,
		// Managed nodes only (audit CG-15, decision D-11).
		SandboxEgressRefusals: batch.SandboxEgressRefusals,
		// The security pillar wire (security plan 7.4): composed through the
		// SecurityOrgProviders seam only while the security module is active
		// and the share level allows; nil otherwise, so the keys are absent.
		SecurityPosture:  batch.SecurityPosture,
		SecurityFindings: batch.SecurityFindings,
		AIChangeRecords:  batch.AIChangeRecords,
		// Agent Access P4 W4e relay wires: the HMAC-only aggregate (individual
		// mcp_activity opt-in, or enrolled capture posture) and the per-record
		// L2 events (enrolled posture only). Both composed by
		// store/mcprelaysummary.go under those gates; nil/empty otherwise.
		MCPRelayActivity: batch.MCPRelayActivity,
		MCPRelayEvents:   batch.MCPRelayEvents,
		RoutingDetails:   batch.RoutingDetails,
		LimitGauges:      batch.LimitGauges,
		// Lane F-WIRE per-session rate-limit windows: the newest observation
		// per (session, provider), composed by store/limitgauge.go under the
		// limit_gauge opt-in or the enrolled full-capture posture; nil
		// otherwise, so the omitempty key is absent.
		SessionLimitSnapshots: batch.SessionLimitSnapshots,
		GuardEvents:           batch.GuardEvents,
		OTelContent:           batch.OTelContent,
		// Agent Access P11 (c) shadow-MCP discovery inventory: FULL under the
		// enrolled capture posture, REDUCED under the individual mcp_activity
		// opt-in (store/mcpinventory.go); nil/empty otherwise. Its
		// source_scope is stamped just below from this node's own key.
		MCPInventory: batch.MCPInventory,
		// Org-tier observability (obs-org-tier plan). Each slice is
		// composed by orgpush.go::composeObsTiers only under its own
		// [org_client.share] flag; nil/empty when the node hasn't opted
		// in, so this mapping is inert for non-obs-sharing nodes.
		ObsSummaries:  batch.ObsSummaries,
		ObsTraces:     batch.ObsTraces,
		ObsSpans:      batch.ObsSpans,
		ObsSpanEvents: batch.ObsSpanEvents,
		ObsContent:    batch.ObsContent,
		ObsEvalRuns:   batch.ObsEvalRuns,
		// T5 per-end-user spend: composed only under ObsSummary &&
		// shipsRawContent() (end-user PII); nil/empty otherwise.
		ObsEndUserSpend: batch.ObsEndUserSpend,
		// T6 input-admission verdicts + policy snapshots: composed only
		// under the [org_client.share.obs] admission opt-in; nil/empty
		// otherwise. Verdict PII/prose is gated by shipsRawContent() in
		// composeObsTiers; policy Body always ships.
		ObsAdmissionEvents:   batch.ObsAdmissionEvents,
		ObsAdmissionPolicies: batch.ObsAdmissionPolicies,
		// T7 per-item eval scores: composed only under the
		// [org_client.share.obs] eval_items opt-in; nil/empty otherwise. Item
		// content excerpts are gated by shipsRawContent() in composeObsTiers;
		// the score metadata + content_hash always ship.
		ObsEvalItems:       batch.ObsEvalItems,
		ObsEgressDecisions: batch.ObsEgressDecisions, // T8
		// The node's own enum-only update posture (enterprise-update-management
		// plan §3.5). nil until cmd/observer wires the posture environment, and
		// the field is omitempty, so an envelope from a node without the
		// feature stays byte-identical to the pre-feature shape.
		UpdatePosture: batch.UpdatePosture,
		// The node's own enum-only BUDGET posture (org-budget plan §3.3d):
		// enforcement point, guard mode, where the effective numbers came
		// from, the last fetch state, and the proxy-only coverage limit. No
		// cap value, no resolved scope. nil until cmd/observer wires the
		// provider, and omitempty, so a node without the feature pushes a
		// byte-identical envelope.
		BudgetPosture: batch.BudgetPosture,
		// The node's enum-only component posture (modular packaging plan
		// 6.4): metadata about the binary, every share mode. nil until
		// cmd/observer wires the provider; omitempty.
		ComponentPosture: batch.ComponentPosture,
		// A MANAGED node's applied state of the org AI tool policy (adapter
		// config P7): closed enums and value hashes, an observed value only
		// under raw content. nil on an individual node and omitempty, so
		// every other envelope stays byte-identical; an older server ignores
		// the unknown key.
		AgentConfigState: batch.AgentConfigState,
		// The managed node's AI tool configuration inventory (D-112,
		// T-427): nil unless it changed and the node ships raw content;
		// omitempty, and an older server ignores the unknown key.
		AgentConfigInventory: batch.AgentConfigInventory,
	}
	// The posture's freshness horizon on the server is a function of how often
	// this node reports, and the CLIENT is the one owner of that fact: the
	// store composes the posture but does not tick the loop, and the server
	// cannot derive a cadence from arrival gaps without mistaking one missed
	// push for a slow node (SF-19). Stamped here rather than plumbed into the
	// provider seam so "this node's cadence" keeps exactly one definition:
	// pushInterval(), the same resolver the loop itself uses.
	// The inventory rows' source_scope is the node-computed identity the
	// reduced shape must carry (R14.6): this node's own source key, which only
	// the client owns. The server re-binds it to the key it verified.
	for i := range env.MCPInventory {
		env.MCPInventory[i].SourceScope = env.SourceNodeKey
	}
	if env.BudgetPosture != nil {
		stamped := *env.BudgetPosture
		stamped.PushIntervalSeconds = int(meta.PushInterval / time.Second)
		env.BudgetPosture = &stamped
	}
	return env
}

// maxCursor flattens the per-table push cursor to a single representative
// scalar (the highest id across the four tables) for the envelope's
// cursor_from/cursor_to. The authoritative cursor is per-table and persisted
// locally; this scalar is a server-side progress hint only.
func maxCursor(c store.PushCursor) int64 {
	m := c.Sessions
	for _, v := range []int64{c.Actions, c.APITurns, c.TokenUsage, c.GuardEvents, c.OTelContent, c.MCPRelay, c.LimitSnapshots} {
		if v > m {
			m = v
		}
	}
	return m
}
