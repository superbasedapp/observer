// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// mcprelaysummary.go composes the two MCP relay wire families (Agent Access
// P4 W4e, docs/plans/agent-access-implementation-plan-2026-09-23.md §9.5 /
// §11.7; rulings R8.30.a/b, R9.5, R10.6, R14.5). This file - NOT orgpush.go -
// is the one place the push path reaches the node-local relay chain, and it
// does so through internal/mcprelay/record, the table's one owner, exactly
// as routingsummary.go owns router_decisions: the mcp_relay_* names are in
// tests/invariant/privacy_test.go's forbiddenCacheTables and never appear in
// orgpush.go.
//
// Two families, two postures:
//
//   - MCPRelayActivityRow (SelectMCPRelayActivity) is the HMAC-only daily
//     aggregate: (day, virtual server, tool_ref_hmac, decision, client
//     attestation) counts over a recent window, no plain names, no payload,
//     no subject/device identifier (identity is envelope-derived on the
//     server). An INDIVIDUAL node ships it only under
//     [org_client.share].mcp_activity; an ENROLLED teams/enterprise node
//     ships it by capture posture (shipsRawContent()).
//   - MCPRelayEventRow (SelectMCPRelayEvents) is ONE wire record per chain
//     record - decision / completion / gap / gap_resolution, each keyed by
//     the node's own seq (R14.5) - carrying the plain names and the L2
//     payloads AS STORED (the node's own CHECKs already NULL every payload
//     below L2). It ships ONLY under shipsRawContent(), as a CURSOR wire
//     (PushCursor.MCPRelay) so a record is delivered exactly once and the
//     server de-dupes replays on (source_node_key, local_record_seq,
//     record_kind).

// mcpRelayActivityWindowDays bounds the aggregate to the recent window; the
// server REPLACES the (org, source_node_key, day, dims) snapshot, so a
// re-pushed window is idempotent.
const mcpRelayActivityWindowDays = 7

// mcpRelayEventsPerBatch caps the per-record rows one SelectUnpushedSince
// reads; the cursor carries the tail to the next tick.
const mcpRelayEventsPerBatch = 2000

// mcpRelayReader opens the read-only record seam (no node key: the composer
// reads the chain, it never appends to it).
func (s *Store) mcpRelayReader() *record.SQLStore {
	return record.NewSQLStore(s.db, "")
}

// SelectMCPRelayActivity aggregates the relay chain's decision rows into the
// HMAC-only wire rows.
func (s *Store) SelectMCPRelayActivity(ctx context.Context) ([]orgcontract.MCPRelayActivityRow, error) {
	since := time.Now().UTC().AddDate(0, 0, -mcpRelayActivityWindowDays).Unix()
	buckets, err := s.mcpRelayReader().DailyActivity(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("store.SelectMCPRelayActivity: %w", err)
	}
	out := make([]orgcontract.MCPRelayActivityRow, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, orgcontract.MCPRelayActivityRow{
			Day: b.Day, VirtualServer: b.VServer, ToolRefHMAC: b.ToolRefHMAC,
			Decision: string(b.Decision), ClientAttestation: attestationOrClaimed(string(b.ClientAttestation)),
			N: b.N,
		})
	}
	return out, nil
}

// SelectMCPRelayEvents reads up to limit chain records with seq > after,
// seq ascending, as wire rows. It never applies a content gate of its own:
// the caller (orgpush.go) composes this family ONLY under shipsRawContent(),
// and the node's own CHECKs guarantee a record below L2 carries no payload.
// The returned rows carry LocalRecordSeq, which the caller advances the
// cursor by.
func (s *Store) SelectMCPRelayEvents(ctx context.Context, after int64, limit int) ([]orgcontract.MCPRelayEventRow, error) {
	recs, err := s.mcpRelayReader().ReadAfter(ctx, after, limit)
	if err != nil {
		return nil, fmt.Errorf("store.SelectMCPRelayEvents: %w", err)
	}
	out := make([]orgcontract.MCPRelayEventRow, 0, len(recs))
	for i := range recs {
		out = append(out, mcpRelayEventRow(recs[i]))
	}
	return out, nil
}

// mcpRelayEventRow maps one chain record onto its wire row, column for
// column. A decision row's client_attestation / credential_assurance are
// REQUIRED NOT NULL on the server's mcp_node_decision_event but only
// nullable on the node chain, so an unstated value ships as the least-assured
// enum ("claimed") rather than failing the whole push - that IS the honest
// value for an attestation the relay did not make.
func mcpRelayEventRow(r record.Record) orgcontract.MCPRelayEventRow {
	row := orgcontract.MCPRelayEventRow{
		LocalRecordSeq: r.Seq, RecordKind: string(r.Kind), TS: r.TS,
		VirtualServer: r.VServer, Server: r.Server, Tool: r.Tool, Method: r.Method,
		CallID: r.CallID, TraceID: r.TraceID, CodingSessionID: r.CodingSessionID, TurnRef: r.TurnRef, ActionRef: r.ActionRef,
		CorrConfidence: string(r.CorrConfidence),
		Decision:       string(r.Decision), ReasonCode: r.ReasonCode,
		ClientAttestation: string(r.ClientAttestation), CredentialAssurance: r.CredentialAssurance,
		LatencyMS: r.LatencyMS, CaptureLevel: string(r.CaptureLevel),
		ArgsExcerpt: r.ArgsExcerpt, ArgsFull: r.ArgsFull, ArgsScrubStatus: string(r.ArgsScrubStatus),
		ResultFull: r.ResultFull, ResultScrubStatus: string(r.ResultScrubStatus),
		ErrorFull: r.ErrorFull, ErrorScrubStatus: string(r.ErrorScrubStatus),
		ElicitationFull: r.ElicitationFull, ElicitationScrubStatus: string(r.ElicitationScrubStatus),
		ResultSizeBytes: r.ResultSizeBytes, ResultStatus: r.ResultStatus,
		GapFrom: r.GapFrom, GapTo: r.GapTo, LostCount: r.LostCount, GapReason: r.GapReason,
		ResolvesSeq: r.ResolvesSeq, ResolvedRangeStart: r.ResolvedRangeStart, ResolvedRangeEnd: r.ResolvedRangeEnd,
		Resolution: string(r.Resolution),
	}
	if r.Kind == record.KindDecision {
		row.ClientAttestation = attestationOrClaimed(row.ClientAttestation)
		if row.CredentialAssurance == "" {
			row.CredentialAssurance = "claimed"
		}
	}
	return row
}

// attestationOrClaimed maps an unstated attestation to "claimed", the
// least-assured enum value and the only honest one for a relay that made no
// attestation.
func attestationOrClaimed(v string) string {
	if v == "" {
		return string(record.AttestClaimed)
	}
	return v
}

// mcpRelayHeadSeq is the chain tail's seq: the change probe for the activity
// family AND the high-water mark enrolment seeds the cursor from. The chain
// is append-only with an AUTOINCREMENT seq, so a new record always advances
// it; O(1) (an index-endpoint seek on the primary key).
func (s *Store) mcpRelayHeadSeq(ctx context.Context) (int64, error) {
	h, err := s.mcpRelayReader().Head(ctx)
	if err != nil {
		return 0, fmt.Errorf("store.mcpRelayHeadSeq: %w", err)
	}
	return h.Seq, nil
}

// probeMCPRelayRecords is the Track R2 change-detection probe for the
// activity family (see mcpRelayHeadSeq).
func (s *Store) probeMCPRelayRecords(ctx context.Context) (string, error) {
	seq, err := s.mcpRelayHeadSeq(ctx)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("mr%d", seq), nil
}
