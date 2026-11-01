// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"reflect"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// orgsnapkeys.go is the snapshot paging identity table (orgsnapgate.go). Each
// gated wire row type maps to the Go fields that make up the ORG SERVER's
// conflict key for that family (the ON CONFLICT columns in
// internal/orgserver/ingest and internal/orgserver/secorg, less org_id and the
// pusher, which are constant for one node). Paging records, per natural key,
// the digest the server accepted, so a row that changes back to an earlier
// value inside one cycle is still re-sent.
//
// A key coarser than the server's would make two server rows share one entry;
// fitSnapshot detects a repeat within one compose and falls back to key plus
// digest, so a wrong row here can only cost a re-send, never a skipped row.
// TestSnapshotPagingKeysCoverEveryGatedWire pins that every gated row type has
// an entry and that the seeded fixture has no repeats.
var snapNaturalKeys = map[reflect.Type][]string{
	// The eight aggregates, ingest.go ingestAggregateSummaries.
	reflect.TypeFor[orgcontract.RoutingSummaryRow]():     {"Day", "Tier", "Reason", "Mode"},
	reflect.TypeFor[orgcontract.CacheSummaryRow]():       {"Day", "Model", "Kind"},
	reflect.TypeFor[orgcontract.CodeintelSummaryRow]():   {"ProjectHash", "Lang"},
	reflect.TypeFor[orgcontract.ProcessSummaryRow]():     {"Day", "Tool"},
	reflect.TypeFor[orgcontract.TerminalSummaryRow]():    {"Day", "Tool", "Kind"},
	reflect.TypeFor[orgcontract.RemoteAuditSummaryRow](): {"Day", "Kind", "Decision", "Principal"},
	reflect.TypeFor[orgcontract.RoutingDetailRow]():      {"Day", "OriginalModel", "SelectedModel", "TurnKind", "Mode"},
	reflect.TypeFor[orgcontract.LimitGaugeRow]():         {"Day", "Provider"},
	// Per-session wires.
	reflect.TypeFor[orgcontract.SessionVerbosityRow]():      {"SessionID"},
	reflect.TypeFor[orgcontract.SessionCacheRow]():          {"SessionID", "Model", "Tier", "Kind", "Cause", "ZeroUsage"},
	reflect.TypeFor[orgcontract.SessionCacheEventRow]():     {"NodeEventID"},
	reflect.TypeFor[orgcontract.SessionProcessRow]():        {"SessionID", "RunKey"},
	reflect.TypeFor[orgcontract.SessionNetworkEventRow]():   {"SessionID", "EventKey"},
	reflect.TypeFor[orgcontract.SessionTaskItemRow]():       {"SessionID", "Key"},
	reflect.TypeFor[orgcontract.SessionTaskTransitionRow](): {"SessionID", "Key", "SourceEventID"},
	reflect.TypeFor[orgcontract.SessionToolAccountRow]():    {"SessionID", "Tool", "BindingKind", "BindingID", "Role", "AccountKey", "Source", "Scope", "Stage"},
	reflect.TypeFor[orgcontract.HookActivitySessionRow]():   {"SessionID", "Tool", "Event"},
	reflect.TypeFor[orgcontract.SessionQualityRow]():        {"SessionID"},
	// Lines of code, loc.go.
	reflect.TypeFor[orgcontract.SessionLOCRow](): {"SessionID", "ProjectRootHash"},
	reflect.TypeFor[orgcontract.LOCDayRow]():     {"Day", "ProjectRootHash"},
	// Commits and delivery. The server hashes a raw commit SHA when the hash
	// is empty, so both fields are part of one commit's identity.
	reflect.TypeFor[orgcontract.CommitOwnershipRow](): {"ProjectRootHash", "CommitSHAHash", "CommitSHA"},
	reflect.TypeFor[orgcontract.DeliveryDayRow]():     {"ProjectRootHash", "Day"},
	reflect.TypeFor[orgcontract.PullRequestRow]():     {"Provider", "RepoSlugHash", "RepoSlug", "Number"},
	// Enterprise per-developer wires.
	reflect.TypeFor[orgcontract.ProjectPatternRow]():   {"ProjectRootHash", "Kind", "Value"},
	reflect.TypeFor[orgcontract.BenchmarkRunRow]():     {"RunKey"},
	reflect.TypeFor[orgcontract.BenchmarkAttemptRow](): {"RunKey", "AttemptKey"},
	reflect.TypeFor[orgcontract.CompressionStatRow]():  {"Day", "Mechanism"},
	reflect.TypeFor[orgcontract.RoutingDevRow]():       {"Day", "OriginalModel", "SelectedModel", "TurnKind", "Mode"},
	reflect.TypeFor[orgcontract.CodeintelDevRow]():     {"ProjectHash", "Language"},
	reflect.TypeFor[orgcontract.TerminalRunRow]():      {"RunID"},
	reflect.TypeFor[orgcontract.TerminalCommandRow]():  {"RunID", "TurnSeq"},
	reflect.TypeFor[orgcontract.RemoteAuditRow]():      {"EventKey"},
	reflect.TypeFor[orgcontract.GuardPinRow]():         {"PinKey"},
	reflect.TypeFor[orgcontract.GuardApprovalRow]():    {"ApprovalKey"},
	reflect.TypeFor[orgcontract.SandboxPostureRow]():   {"Day", "IsolationClass", "CaptureLevel", "CaptureOrigin", "Verification", "NativeSandboxState", "KeyCustody"},
	// Security pillar, secorg.go.
	reflect.TypeFor[orgcontract.SecurityPostureRow](): {"Day"},
	reflect.TypeFor[orgcontract.SecurityFindingRow](): {"FindingRef"},
	reflect.TypeFor[orgcontract.AIChangeRecordRow]():  {"CommitIdentityHash"},
	// Agent Access.
	reflect.TypeFor[orgcontract.MCPRelayActivityRow](): {"Day", "VirtualServer", "ToolRefHMAC", "Decision", "ClientAttestation"},
	reflect.TypeFor[orgcontract.MCPInventoryRow]():     {"LocatorFingerprint"},
}

// snapVolatileFields are fields a row carries that hold the COMPOSE time rather
// than source data. They are left out of the paging digest: otherwise every
// compose would see every row as changed and an over-budget family would
// re-ship its first page forever. They still ship on the wire, and each new
// cycle (a source change or the hourly freshness floor) sends current values.
var snapVolatileFields = map[reflect.Type][]string{
	// mcpinventory.go stamps the observation time on every compose, and a
	// server with no earlier pin also takes it as first_seen.
	reflect.TypeFor[orgcontract.MCPInventoryRow](): {"ObservedAt", "FirstSeen", "LastSeen"},
}
