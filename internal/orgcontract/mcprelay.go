// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package orgcontract

import (
	"crypto/sha256"
	"encoding/hex"
)

// MemberSourceNodeKeyPrefix prefixes the compat source key the server derives
// for a push that carries no SourceNodeKey: 'member:' || member_id (doc3
// §9.5, R8.28.g). A real per-device key is 64 lowercase hex characters and
// can never collide with it.
const MemberSourceNodeKeyPrefix = "member:"

// SourceNodeKeyFromThumbprint derives PushEnvelope.SourceNodeKey from the
// pushing device's agent-access public-key thumbprint (the RFC 7638 `jkt`
// the P1 registration rail records as agent_credential.key_thumbprint):
// lowercase hex SHA-256 of the thumbprint string. The node computes it from
// its keychain slot; the server recomputes it from every ACTIVE kind='node'
// credential of the authenticated member to bind the two (a mismatch is a
// 400). One definition, shared by both sides, so they can never disagree.
func SourceNodeKeyFromThumbprint(jkt string) string {
	sum := sha256.Sum256([]byte(jkt))
	return hex.EncodeToString(sum[:])
}

// MemberSourceNodeKey is the compat source key for a member whose push
// carried no SourceNodeKey (a pre-P4 agent).
func MemberSourceNodeKey(memberID string) string {
	return MemberSourceNodeKeyPrefix + memberID
}

// MCPRelayActivityRow is the HMAC-only daily aggregate of a node's MCP relay
// decisions (doc3 §9.5 mcp_node_activity_daily, R8.11 / R8.23.f): one row
// per UTC day x virtual server x keyed tool HMAC x decision x client
// attestation. It carries NO user_id / machine_fp - identity is envelope-
// derived on the server (SourceNodeKey + the authenticated member) - and no
// plain server/tool name in ANY tenancy.
//
// An INDIVIDUAL (non-org-enrolled) node emits it only under
// [org_client.share].mcp_activity (R8.30.b); an ENROLLED teams/enterprise
// node emits it by capture posture (shipsRawContent(), R9.5). The server
// REPLACES the (org, source_node_key, day, dims) snapshot on every push, so a
// re-pushed window is idempotent.
type MCPRelayActivityRow struct {
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD).
	Day string `json:"day"`
	// VirtualServer is the resolved virtual server name (a policy object, not
	// content); "" when the relay could not resolve one.
	VirtualServer string `json:"virtual_server"`
	// ToolRefHMAC is the keyed HMAC of the tool name.
	ToolRefHMAC string `json:"tool_ref_hmac"`
	// Decision is allow | deny | ask.
	Decision string `json:"decision"`
	// ClientAttestation is process_attested | ipc_bound | configured |
	// claimed.
	ClientAttestation string `json:"client_attestation"`
	// N is the decision count in the bucket.
	N int64 `json:"n"`
}

// MCPRelayEventRow is ONE node relay record on the wire (doc3 §9.5
// mcp_node_decision_event, R14.5): a decision, a completion, a gap or a
// gap_resolution, each a SEPARATE append-only record keyed by
// (source_node_key, local_record_seq, record_kind). The server upserts on
// that key with DO NOTHING, so a replay de-dupes and a completion never
// collides with its decision; presentation joins the pair by call_id.
//
// It ships ONLY under shipsRawContent() (an enrolled teams/enterprise node,
// R9.5 / R10.6): the decision record carries the PLAIN server/tool names and
// the L2 args; the completion record carries the L2 result / error /
// elicitation payloads. Payload columns are NULL below L2 by the node's own
// CHECKs. Nullable integers are pointers so a NULL survives the wire.
type MCPRelayEventRow struct {
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// LocalRecordSeq is the node's own mcp_relay_record.seq for THIS record -
	// its chain position - and RecordKind which of the four kinds it is.
	LocalRecordSeq int64  `json:"local_record_seq"`
	RecordKind     string `json:"record_kind"`
	// TS is unix seconds.
	TS int64 `json:"ts"`

	VirtualServer string `json:"virtual_server,omitempty"`
	Server        string `json:"server,omitempty"`
	Tool          string `json:"tool,omitempty"`
	// Method is the JSON-RPC method of a decision record (tools/call,
	// initialize, notifications/initialized, tools/list, ...): not content,
	// the protocol verb. Additive (server migration 181 / pg 0047): an older
	// server ignores the key, an older agent omits it and the column stays
	// NULL.
	Method string `json:"method,omitempty"`

	CallID          string `json:"call_id,omitempty"`
	TraceID         string `json:"trace_id,omitempty"`
	CodingSessionID string `json:"coding_session_id,omitempty"`
	TurnRef         string `json:"turn_ref,omitempty"`
	ActionRef       string `json:"action_ref,omitempty"`
	CorrConfidence  string `json:"corr_confidence,omitempty"`

	Decision            string `json:"decision,omitempty"`
	ReasonCode          string `json:"reason_code,omitempty"`
	ClientAttestation   string `json:"client_attestation,omitempty"`
	CredentialAssurance string `json:"credential_assurance,omitempty"`
	LatencyMS           *int64 `json:"latency_ms,omitempty"`
	CaptureLevel        string `json:"capture_level,omitempty"`

	ArgsExcerpt            string `json:"args_excerpt,omitempty"`
	ArgsFull               string `json:"args_full,omitempty"`
	ArgsScrubStatus        string `json:"args_scrub_status,omitempty"`
	ResultFull             string `json:"result_full,omitempty"`
	ResultScrubStatus      string `json:"result_scrub_status,omitempty"`
	ErrorFull              string `json:"error_full,omitempty"`
	ErrorScrubStatus       string `json:"error_scrub_status,omitempty"`
	ElicitationFull        string `json:"elicitation_full,omitempty"`
	ElicitationScrubStatus string `json:"elicitation_scrub_status,omitempty"`
	ResultSizeBytes        *int64 `json:"result_size_bytes,omitempty"`
	ResultStatus           string `json:"result_status,omitempty"`

	GapFrom   *int64 `json:"gap_from,omitempty"`
	GapTo     *int64 `json:"gap_to,omitempty"`
	LostCount *int64 `json:"lost_count,omitempty"`
	GapReason string `json:"gap_reason,omitempty"`

	ResolvesSeq        *int64 `json:"resolves_seq,omitempty"`
	ResolvedRangeStart *int64 `json:"resolved_range_start,omitempty"`
	ResolvedRangeEnd   *int64 `json:"resolved_range_end,omitempty"`
	Resolution         string `json:"resolution,omitempty"`
}
