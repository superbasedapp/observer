package orgcontract

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the wire golden file instead of comparing")

// TestWireEncodingGolden pins the JSON wire encoding of every contract
// type. A change to a json tag, a field, or a type fails this test until
// the golden is intentionally regenerated with:
//
//	go test ./internal/orgcontract -update
//
// This is the tripwire that catches an accidental agent↔server wire
// incompatibility at test time rather than in production.
func TestWireEncodingGolden(t *testing.T) {
	fixtures := map[string]any{
		"enroll_request": EnrollRequest{
			OneTimeToken: "tok_id123.ot_abc123", AgentPublicKey: "MCowBQYDK2VwAyEA...",
		},
		"enroll_response": EnrollResponse{
			Bearer: "eyJ...sig", BearerExpiresAt: "2026-08-23T00:00:00Z",
			OrgID: "org-acme", OrgName: "Acme", UserID: "scim-42", UserEmail: "dev@acme.example",
		},
		// A server with a configured policy signing key additionally
		// delivers the org policy public key for the agent to pin (guard
		// spec §14.2). The plain enroll_response fixture above stays
		// byte-identical — that absence IS the pre-G13 compat shape.
		"enroll_response_with_policy_key": EnrollResponse{
			Bearer: "eyJ...sig", BearerExpiresAt: "2026-08-23T00:00:00Z",
			OrgID: "org-acme", OrgName: "Acme", UserID: "scim-42", UserEmail: "dev@acme.example",
			OrgPolicyPublicKey: "cHViLWtleS1ieXRlcw",
		},
		"bearer_claims": BearerClaims{
			Iss: "https://org.acme.example", Sub: "scim-42", Aud: "org-acme",
			Exp: 1797206400, Iat: 1789430400, Jti: "jti-7f3a",
		},
		"push_response": PushResponse{AcceptedRows: 118, DedupedRows: 7, NextCursor: 90210},
		// A push response carrying a break-glass lease on the enrolment rail
		// (P6). The plain push_response fixture above stays byte-identical — that
		// absence IS the pre-P6 compat shape (omitempty slice).
		"push_response_with_break_glass": PushResponse{
			AcceptedRows: 118, DedupedRows: 7, NextCursor: 90210,
			BreakGlassLeases: []BreakGlassLease{{
				LeaseID: "bgl-1", RequestID: "bgr-1", OrgID: "org-acme",
				OrgServerURL: "https://org.acme.example", KeyPinSHA256: "sha256:pin-aaa",
				UserID: "scim-42", UpstreamID: "anthropic-prod", Rung: "break_glass",
				SealScheme: "opaque-v1", SealedCredential: "c2VhbGVkLWJ5dGVz",
				PublicKey: "cHViLWtleS1ieXRlcw", ApprovedBy: "super-admin-1",
				GrantedAt: "2026-08-30T10:00:00Z", ExpiresAt: "2026-08-30T11:00:00Z",
				Signature: "c2lnLWJ5dGVzLWhlcmU",
			}},
		},
		// The update nudge (Enterprise Update Management §3.5). The plain
		// push_response fixture above stays byte-identical — that absence IS
		// the pre-feature compat shape (omitempty map), and it is what makes
		// a new agent against a pre-feature server stay inert.
		"push_response_with_update_versions": PushResponse{
			AcceptedRows: 118, DedupedRows: 7, NextCursor: 90210,
			UpdateVersions: map[string]int64{"stable": 17, "lts": 12},
		},
		"policy_bundle": PolicyBundle{
			Version:     3,
			BundleTOML:  "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\n",
			Signature:   "c2lnLWJ5dGVzLWhlcmU",
			PublicKey:   "cHViLWtleS1ieXRlcw",
			SignedAt:    "2026-06-11T09:00:00Z",
			Description: "deny destructive git on every enrolled agent",
		},
		"push_envelope": PushEnvelope{
			AgentVersion: "1.6.30",
			CursorFrom:   90000,
			CursorTo:     90210,
			Sessions: []SessionRow{{
				ID: "sess-1",
				// Default (metadata-only) shape: only the *_hash columns ship;
				// the raw ProjectRoot/GitRemote fields are zero so json
				// omitempty drops them from the wire. Project Identity
				// Resolver v2 (§3.2): the four owner/root-commit/fingerprint
				// hashes plus WorkspaceHash/GitUpstreamRemoteHash/IsWorktree
				// ship in every posture; GitUpstreamRemote/Workspace stay zero
				// here the same way ProjectRoot/GitRemote do.
				ProjectRootHash: "sha256:proj-root-aaa",
				GitRemoteHash:   "sha256:git-remote-bbb",
				Tool:            "claude-code", Model: "claude-opus-4-7", GitBranch: "main",
				StartedAt: "2026-05-25T10:00:00Z", EndedAt: "2026-05-25T10:42:00Z",
				TotalActions: 37, OrgID: "org-acme", UserEmail: "dev@acme.example",
				GitUpstreamRemoteHash:  "sha256:git-upstream-remote-ccc",
				GitRemoteOwnerHash:     "sha256:git-remote-owner-ddd",
				GitUpstreamOwnerHash:   "sha256:git-upstream-owner-eee",
				RootCommitHash:         "sha256:root-commit-fff",
				ContentFingerprintHash: "sha256:content-fingerprint-ggg",
				WorkspaceHash:          "sha256:workspace-hhh",
				IsWorktree:             true,
				// Capture surface (W1): closed-vocabulary METADATA that ships
				// in the DEFAULT posture — which is exactly why it belongs on
				// this metadata-only fixture rather than a *_full_content one.
				Surface: "ide", SurfaceHost: "vscode",
				// Tool-version trickle-up (server migration 161 / pg 0027):
				// a bounded, non-prose, vendor-authored token, METADATA like
				// Surface/SurfaceHost above — ships in the DEFAULT posture.
				ToolVersion: "1.2.3",
				// Parent-thread-id trickle-up (server migration 162 / pg
				// 0028): an opaque vendor-minted session-lineage pointer,
				// METADATA like ToolVersion above — ships in the DEFAULT
				// posture. See docs/security.md ledger row LINEAGE-1.
				ParentThreadID: "sess-0",
			}},
			Actions: []ActionRow{{
				SessionID: "sess-1", SourceEventID: "evt-9",
				Timestamp: "2026-05-25T10:05:00Z", Tool: "claude-code", ActionType: "edit_file",
				TargetHash: "sha256:tgt-ccc", SourceFileHash: "sha256:src-ddd",
				TurnIndex: 4, Success: true, DurationMs: 1200,
				IsSidechain: false, OrgID: "org-acme", UserEmail: "dev@acme.example",
			}},
			APITurns: []APITurnRow{{
				SessionID:       "sess-1",
				ProjectRootHash: "sha256:proj-root-aaa",
				Timestamp:       "2026-05-25T10:05:01Z", Provider: "anthropic", Model: "claude-opus-4-7",
				RequestID: "req-1", InputTokens: 1200, OutputTokens: 800, CacheReadTokens: 4000,
				CacheCreationTokens: 256, CacheCreation1hTokens: 0, WebSearchRequests: 0,
				CostUSD: 0.0421, MessageCount: 6, ToolUseCount: 3,
				SystemPromptHash: "sha256:aaa", MessagePrefixHash: "sha256:bbb",
				TimeToFirstTokenMS: 410, TotalResponseMS: 5200, StopReason: "end_turn",
				HTTPStatus: 200, ErrorClass: "", OrgID: "org-acme", UserEmail: "dev@acme.example",
				// Plane B per-turn authority stamps (Sol S5 / Luna L15):
				// content-free routing metadata that always rides the wire.
				Route: "gateway", RoutingGeneration: 7, AuthoritySource: "gateway",
			}},
			TokenUsage: []TokenUsageRow{{
				SessionID:       "sess-1",
				ProjectRootHash: "sha256:proj-root-aaa",
				Timestamp:       "2026-05-25T10:05:01Z", Tool: "claude-code", Model: "claude-opus-4-7",
				InputTokens: 1200, OutputTokens: 800, CacheReadTokens: 4000, CacheCreationTokens: 256,
				CacheCreation1hTokens: 0, ReasoningTokens: 0, WebSearchRequests: 0,
				EstimatedCostUSD: 0.0421, Source: "proxy", Reliability: "reliable",
				SourceFileHash: "sha256:src-eee",
				SourceEventID:  "tok-9",
				// Sub-agent (Task) window flag (W1): METADATA, ships in the
				// DEFAULT posture alongside ActionRow.IsSidechain.
				IsSidechain: true,
				OrgID:       "org-acme", UserEmail: "dev@acme.example",
			}},
			GuardEvents: []GuardEventRow{{
				SessionID: "sess-1",
				Timestamp: "2026-05-25T10:05:02Z", Tool: "claude-code", EventKind: "shell_exec",
				RuleID: "R-110", Category: "destructive", Severity: "critical", Decision: "flag",
				Enforced: false, Source: "builtin",
				// Default (metadata-only) shape: only target_hash ships;
				// the content-bearing Reason/TargetExcerpt/TaintOrigin
				// fields are zero so json omitempty drops them.
				TargetHash: "sha256:tgt-fff",
				ChainPrev:  "", ChainHash: "sha256:chain-001",
				OrgID: "org-acme", UserEmail: "dev@acme.example",
			}},
		},
		// The client-declared request class (server migration 188 / pg 0054,
		// lane G-WIRE2): a closed enum, METADATA that ships in the DEFAULT
		// posture. The push_envelope fixture above carries none, so its bytes
		// stay identical to the pre-188 shape - that absence IS the compat
		// shape an older server sees.
		"api_turn_row_with_request_class": APITurnRow{
			SessionID: "sess-1", ProjectRootHash: "sha256:proj-root-aaa",
			Timestamp: "2026-05-25T10:05:01Z", Provider: "anthropic", Model: "claude-opus-4-7",
			RequestID: "req-2", InputTokens: 300, OutputTokens: 40, CostUSD: 0.0031,
			HTTPStatus: 200, OrgID: "org-acme", UserEmail: "dev@acme.example",
			RequestClass: "subagent",
		},
		// Lines-of-Code wire (W5). Two fixtures for the session row so the
		// gated field's ABSENCE is pinned as its own shape: the default
		// metadata-only row carries the counts with no language mix (the
		// posture almost every node ships under), and the *_full_content one
		// adds the mix. If the gate ever inverted, the default fixture would
		// stop being byte-identical here.
		"session_loc_row": SessionLOCRow{
			OrgID: "org-acme", UserEmail: "dev@acme.example",
			SessionID: "sess-1", ProjectRootHash: "sha256:proj-root-aaa",
			AIAddedCode: 412, AIModifiedCode: 37, AIDeletedCode: 91,
			AIAddedComment: 44, AIDeletedComment: 6,
			AIWhitespace: 210, AIBlank: 63, AIUnknown: 0,
			AISidechainAddedCode: 128, AISidechainModifiedCode: 9, AISidechainDeletedCode: 14,
			HumanAddedCode: 23, HumanModifiedCode: 5, HumanDeletedCode: 2,
			SystemAddedCode: 0, SystemModifiedCode: 18, SystemDeletedCode: 0,
			UnknownLines: 7, DocsLines: 96, ConfigLines: 12,
			Files: 21, LowConfidenceFiles: 2, OverwriteFiles: 1,
			HumanCapture: "vscode", ClassifierVersion: 1,
		},
		"session_loc_row_full_content": SessionLOCRow{
			OrgID: "org-acme", UserEmail: "dev@acme.example",
			SessionID: "sess-1", ProjectRootHash: "sha256:proj-root-aaa",
			AIAddedCode: 412, AIModifiedCode: 37, AIDeletedCode: 91,
			Files: 21, HumanCapture: "none", ClassifierVersion: 1,
			LanguageMixJSON: `[{"language":"go","category":"code","files":18,"lines":449}]`,
		},
		// BL2-ORG session quality score. Two fixtures: a fully recorded row,
		// and one scored by a node whose scorer left the optional columns NULL
		// (no cache events, no edit) - those keys must be ABSENT, never 0.
		"session_quality_row": SessionQualityRow{
			OrgID: "org-acme", UserEmail: "dev@acme.example", SessionID: "sess-1",
			QualityScore:    0.8125,
			RedundancyRatio: float64p(0.125), ErrorRate: float64p(0.05),
			ExplorationEfficiency: float64p(0.6), ContinuityScore: float64p(0.9179),
			OnboardingCost: int64p(18234), TurnsToFirstEdit: int64p(4), RetryCostTokens: int64p(912),
			StaleReadsWasteful: int64p(3), StaleReadsNecessary: int64p(1), RedundancyRatioWasteful: float64p(0.09),
			ScoredAt: "2026-09-27T10:15:00.123456789Z", ScoredActionCount: int64p(50),
			WeightRedundancy: 0.4, WeightError: 0.3, WeightExploration: 0.2, WeightContinuity: 0.1,
		},
		// Lane F-WIRE per-session rate-limit window. Two fixtures: a full
		// observation, and one whose provider sent no window headers - those
		// keys must be ABSENT (unknown on the org), never 0.
		"session_limit_snapshot_row": SessionLimitSnapshotRow{
			OrgID: "org-acme", UserEmail: "dev@acme.example",
			SessionID: "sess-1", Tool: "claude-code", Provider: "anthropic",
			LocalID: 4211, ObservedAt: 1790000000,
			Window5hUtil: float64p(0.42), Window7dUtil: float64p(0.17),
			Window5hReset: int64p(1790012000), Window7dReset: int64p(1790400000),
		},
		"session_limit_snapshot_row_sparse": SessionLimitSnapshotRow{
			SessionID: "sess-2", Tool: "codex", Provider: "openai",
			LocalID: 4212, ObservedAt: 1790000060,
		},
		"session_quality_row_sparse": SessionQualityRow{
			SessionID: "sess-2", QualityScore: 0.55,
			RedundancyRatio: float64p(0.3), ErrorRate: float64p(0.2),
			ExplorationEfficiency: float64p(0), ContinuityScore: float64p(0.39),
			OnboardingCost: int64p(0), RetryCostTokens: int64p(0),
			ScoredAt: "2026-09-27T10:16:00.000000000Z", ScoredActionCount: int64p(10),
			WeightRedundancy: 0.4, WeightError: 0.3, WeightExploration: 0.2, WeightContinuity: 0.1,
		},
		// Node session-detail trickle-up W2/W3. Two fixtures per row type so
		// the GATED half's absence is pinned as its own shape, the same way
		// session_loc_row / session_loc_row_full_content pin the language mix:
		// the plain fixture is the posture a task_detail-but-not-content node
		// ships (status only), and the *_full_content one adds the prose /
		// the raw account identity. If either gate ever inverted, the plain
		// fixture would stop being byte-identical here.
		"session_task_item_row": SessionTaskItemRow{
			OrgID: "org-acme", UserEmail: "dev@acme.example",
			SessionID: "sess-1", Tool: "claude-code",
			Key: "task-7", KeyKind: "native_id",
			RawStatus: "in_progress", Status: "in_progress", OrderIndex: 2,
			FirstSeenAt: "2026-09-10T10:00:00Z", LastSeenAt: "2026-09-10T10:42:00Z",
		},
		"session_task_item_row_full_content": SessionTaskItemRow{
			OrgID: "org-acme", UserEmail: "dev@acme.example",
			SessionID: "sess-1", Tool: "claude-code",
			Key: "task-7", KeyKind: "native_id",
			Content:    "Wire the W2 task rows into the org drawer",
			ActiveForm: "Wiring the W2 task rows into the org drawer",
			Owner:      "dev@acme.example",
			RawStatus:  "in_progress", Status: "in_progress", OrderIndex: 2,
			FirstSeenAt: "2026-09-10T10:00:00Z", LastSeenAt: "2026-09-10T10:42:00Z",
			Unmatched: true,
		},
		"session_task_transition_row": SessionTaskTransitionRow{
			OrgID: "org-acme", UserEmail: "dev@acme.example",
			SessionID: "sess-1", Key: "task-7",
			FromStatus: "pending", ToStatus: "in_progress",
			Ts: "2026-09-10T10:05:00Z", ActionID: 4211, SourceEventID: "toolu_01abc",
		},
		"session_tool_account_row": SessionToolAccountRow{
			OrgID: "org-acme", UserEmail: "dev@acme.example",
			SessionID: "sess-1", Tool: "claude-code",
			BindingKind: "message", BindingID: "msg_01xyz", Role: "assistant",
			AccountKey: "ak_9f3c", Source: "hook", Scope: "session", Stage: "start",
			ObservedAt: "2026-09-10T10:00:03Z",
		},
		"session_tool_account_row_full_content": SessionToolAccountRow{
			OrgID: "org-acme", UserEmail: "dev@acme.example",
			SessionID: "sess-1", Tool: "claude-code",
			BindingKind: "message", BindingID: "msg_01xyz", Role: "assistant",
			AccountKey: "ak_9f3c",
			Email:      "dev@acme.example", Name: "Dev Example", AccountID: "acct_4417",
			Source: "hook", Scope: "session", Stage: "start",
			ObservedAt: "2026-09-10T10:00:03Z",
		},
		"loc_day_row": LOCDayRow{
			OrgID: "org-acme", UserEmail: "dev@acme.example",
			Day: "2026-09-06", ProjectRootHash: "sha256:proj-root-aaa",
			AICodeLines: 449, HumanCodeLines: 28, SystemCodeLines: 18,
			Files: 21, HumanCapture: "vscode", ClassifierVersion: 1,
		},
		// Commit ownership (lane F-PROJ). Three fixtures: the DEFAULT
		// metadata-only owned row (no subject key), the same row under the
		// raw-content posture (subject added), and the identity-only
		// unreachable row. If the subject gate ever inverted, or an author /
		// path field were ever added, the first fixture would stop being
		// byte-identical here.
		"commit_ownership_row": CommitOwnershipRow{
			OrgID: "org-acme", UserEmail: "dev@acme.example",
			ProjectRootHash: "sha256:proj-root-aaa", CommitSHA: "0123abcd0123abcd0123abcd0123abcd0123abcd",
			CommittedAt: "2026-09-28T10:00:00Z", Reachable: true,
			FilesCount: 3, Added: 42, Deleted: 7, AIFiles: 2, AICodeLines: 30, AICommentLines: 4,
			OwnerSessionID: "sess-1", OwnerReason: "most_code_lines", ShareBasis: "code_lines",
			Contributors: []CommitContributorRow{
				{SessionID: "sess-1", Share: 0.75, CodeLines: 22, CommentLines: 3, Files: 1, Prompts: 2},
				{SessionID: "sess-2", Share: 0.25, CodeLines: 8, CommentLines: 1, Files: 1, Prompts: 1},
			},
			RuleVersion: 1,
		},
		"commit_ownership_row_full_content": CommitOwnershipRow{
			OrgID: "org-acme", UserEmail: "dev@acme.example",
			ProjectRootHash: "sha256:proj-root-aaa", CommitSHA: "0123abcd0123abcd0123abcd0123abcd0123abcd",
			CommittedAt: "2026-09-28T10:00:00Z", Reachable: true,
			FilesCount: 1, Added: 3, AIFiles: 1, AICodeLines: 3,
			OwnerSessionID: "sess-1", OwnerReason: "sole_contributor", ShareBasis: "code_lines",
			Contributors: []CommitContributorRow{{SessionID: "sess-1", Share: 1, CodeLines: 3, Files: 1, Prompts: 1}},
			Subject:      "feat: parser",
			RuleVersion:  1,
		},
		"commit_ownership_row_unreachable": CommitOwnershipRow{
			ProjectRootHash: "sha256:proj-root-aaa", CommitSHA: "fedc0000fedc0000fedc0000fedc0000fedc0000",
			CommittedAt: "2026-09-27T09:00:00Z", Reachable: false,
			OwnerReason: "unreachable", RuleVersion: 1,
		},
		// A push from a MANAGED node (Project Identity Resolver v2, W6
		// correction). Two fields exist only on this shape, and both are
		// omitempty — which is exactly why the plain push_envelope fixture
		// above stays byte-identical, the same way
		// push_response_with_break_glass leaves push_response alone:
		//
		//   - the envelope-level machine_identity, which ONLY a
		//     managed-tenancy node computes and sends (an individual/BYO node
		//     never does), and which the server stamps onto the sessions rows
		//     the push inserts;
		//   - codeintel_dev[].project_root_hash, the project-identity hash
		//     that rides alongside the domain-separated project_hash so a
		//     codeintel row can be joined to its project.
		"push_envelope_managed_node": PushEnvelope{
			AgentVersion:    "1.30.0",
			MachineIdentity: "3f2a1b0c9d8e7f60514233445566778899aabbccddeeff00112233445566778a",
			CursorFrom:      90210,
			CursorTo:        90477,
			CodeintelDevRows: []CodeintelDevRow{{
				OrgID: "org-acme", UserEmail: "dev@acme.example",
				ProjectHash:     "sha256:codeintel-proj-aaa",
				ProjectRoot:     "/home/dev/work/acme-api",
				ProjectRootHash: "sha256:proj-root-aaa",
				Language:        "go",
				Files:           412, Symbols: 9130, Edges: 21877,
				LastIndexed: 1789430400,
			}},
		},
		// A push from a node that has learned about updates (Enterprise
		// Update Management §3.5). The posture is ENVELOPE-level and
		// omitempty, which is exactly why the plain push_envelope fixture
		// above stays byte-identical — a v1.7-shaped agent that never sets it
		// keeps pushing precisely the bytes it pushes today.
		//
		// Note what is NOT here and never can be: a hostname, a username, a
		// path, a progress percentage, or an error MESSAGE. The failure is an
		// error CLASS, and the block is a closed reason.
		// Agent Access P4 W4e (doc3 §9.5 / §11.7, R8.30.a/b, R9.5, R14.5). An
		// INDIVIDUAL node that opted into [org_client.share].mcp_activity ships
		// the HMAC-only daily aggregate and the per-device SourceNodeKey.
		// NOTHING per-call rides along: no plain server/tool name, no payload,
		// no event rows. The plain push_envelope fixture above stays
		// byte-identical - both new keys are omitempty, which is the compat
		// invariant in both directions (a pre-P4 agent sends neither; a pre-P4
		// server ignores both).
		"push_envelope_mcp_relay_individual": PushEnvelope{
			AgentVersion:  "1.35.0",
			SourceNodeKey: "9d2f6b1c4e8a7f30d1c2b3a4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718",
			CursorFrom:    90477,
			CursorTo:      90480,
			MCPRelayActivity: []MCPRelayActivityRow{{
				OrgID: "org-acme", UserEmail: "dev@acme.example",
				Day: "2026-09-24", VirtualServer: "vs-github", ToolRefHMAC: "hmac-tool-aaa",
				Decision: "allow", ClientAttestation: "process_attested", N: 17,
			}},
		},
		// The ENROLLED teams/enterprise shape (shipsRawContent()): the same
		// aggregate PLUS one wire record per node chain record - decision and
		// completion are SEPARATE records keyed (source_node_key,
		// local_record_seq, record_kind), gap / gap_resolution ride the same
		// way (R14.5). The decision carries the PLAIN names + L2 args; the
		// completion carries the L2 result / error / elicitation with their
		// own scrub status (R12.9); nullable integers are pointers so a NULL
		// (a decision's latency, a gap's capture level) never becomes a zero.
		"push_envelope_mcp_relay_managed": PushEnvelope{
			AgentVersion:    "1.35.0",
			MachineIdentity: "3f2a1b0c9d8e7f60514233445566778899aabbccddeeff00112233445566778a",
			SourceNodeKey:   "9d2f6b1c4e8a7f30d1c2b3a4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718",
			CursorFrom:      90480,
			CursorTo:        90484,
			MCPRelayActivity: []MCPRelayActivityRow{{
				OrgID: "org-acme", UserEmail: "dev@acme.example",
				Day: "2026-09-24", VirtualServer: "vs-github", ToolRefHMAC: "hmac-tool-aaa",
				Decision: "allow", ClientAttestation: "process_attested", N: 1,
			}},
			MCPRelayEvents: []MCPRelayEventRow{
				{
					OrgID: "org-acme", UserEmail: "dev@acme.example",
					LocalRecordSeq: 41, RecordKind: "decision", TS: 1790000000,
					VirtualServer: "vs-github", Server: "github", Tool: "create_issue", Method: "tools/call",
					CallID: "call-7f3a", TraceID: "trace-0011", CodingSessionID: "sess-1", TurnRef: "turn-9", ActionRef: "act-12",
					CorrConfidence: "exact", Decision: "allow", ReasonCode: "grant:github-issues",
					ClientAttestation: "process_attested", CredentialAssurance: "node_enrolled",
					CaptureLevel: "L2", ArgsFull: `{"title":"Cursor re-enrol regression"}`, ArgsScrubStatus: "structured",
				},
				{
					OrgID: "org-acme", UserEmail: "dev@acme.example",
					LocalRecordSeq: 42, RecordKind: "completion", TS: 1790000001,
					CallID: "call-7f3a", CaptureLevel: "L2", LatencyMS: int64p(830), ResultSizeBytes: int64p(2048),
					ResultStatus: "ok", ResultFull: `{"number":118}`, ResultScrubStatus: "structured",
					ErrorFull: `{"code":0}`, ErrorScrubStatus: "redacted",
					ElicitationFull: `{}`, ElicitationScrubStatus: "truncated",
				},
				{
					OrgID: "org-acme", UserEmail: "dev@acme.example",
					LocalRecordSeq: 43, RecordKind: "gap", TS: 1790000002,
					GapFrom: int64p(1789999900), GapTo: int64p(1789999950), LostCount: int64p(2), GapReason: "local_append_failed",
				},
				{
					OrgID: "org-acme", UserEmail: "dev@acme.example",
					LocalRecordSeq: 44, RecordKind: "gap_resolution", TS: 1790000003,
					ResolvesSeq: int64p(43), ResolvedRangeStart: int64p(1789999900), ResolvedRangeEnd: int64p(1789999920), Resolution: "late_arrival",
				},
			},
		},
		// Agent Access P11 (c) shadow-MCP discovery inventory (R12.10 / R13.8 /
		// R14.6), FULL shape: an ENROLLED teams/enterprise node
		// (shipsRawContent()) ships the raw locator - client, server name, url
		// (userinfo stripped), command, SCRUBBED args, env KEY names only and
		// the config-path HASH - beside the always-present identity.
		"push_envelope_mcp_inventory_full": PushEnvelope{
			AgentVersion:  "1.36.0",
			SourceNodeKey: "9d2f6b1c4e8a7f30d1c2b3a4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718",
			CursorFrom:    90484,
			CursorTo:      90484,
			MCPInventory: []MCPInventoryRow{
				{
					OrgID: "org-acme", UserEmail: "dev@acme.example",
					SourceScope:        "9d2f6b1c4e8a7f30d1c2b3a4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718",
					LocatorFingerprint: "4f6c1d2e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5",
					ServerNameHash:     "hmac-sha256:v1:7a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",
					Transport:          "stdio", ObservedAt: 1790000100, FirstSeen: 1789740000, LastSeen: 1790000100,
					Client: "claude-code", ServerName: "files", Command: "npx",
					Args: []string{"-y", "@acme/files-mcp", "--token=[REDACTED]"}, EnvKeys: []string{"API_KEY", "FILES_ROOT"},
					ConfigPathHash: "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00",
				},
				{
					OrgID: "org-acme", UserEmail: "dev@acme.example",
					SourceScope:        "9d2f6b1c4e8a7f30d1c2b3a4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718",
					LocatorFingerprint: "8a9b0c1d2e3f405162738495a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f",
					ServerNameHash:     "hmac-sha256:v1:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
					Transport:          "http", ObservedAt: 1790000100, FirstSeen: 1790000100, LastSeen: 1790000100,
					Client: "cursor", ServerName: "linear", URL: "https://mcp.linear.app/sse",
				},
			},
		},
		// The REDUCED (share-off) shape of the same stdio server: an INDIVIDUAL
		// node under [org_client.share].mcp_activity. Identity + metadata only -
		// source_scope, locator_fingerprint, server_name_hash, transport,
		// observed_at and the first/last-seen counts - and NO raw locator key
		// (every raw field is omitempty), yet still ingestible (R14.6).
		"push_envelope_mcp_inventory_reduced": PushEnvelope{
			AgentVersion:  "1.36.0",
			SourceNodeKey: "9d2f6b1c4e8a7f30d1c2b3a4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718",
			CursorFrom:    90484,
			CursorTo:      90484,
			MCPInventory: []MCPInventoryRow{{
				OrgID: "org-acme", UserEmail: "dev@acme.example",
				SourceScope:        "9d2f6b1c4e8a7f30d1c2b3a4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718",
				LocatorFingerprint: "4f6c1d2e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5",
				ServerNameHash:     "hmac-sha256:v1:7a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",
				Transport:          "stdio", ObservedAt: 1790000100, FirstSeen: 1789740000, LastSeen: 1790000100,
			}},
		},
		"push_envelope_with_update_posture": PushEnvelope{
			AgentVersion: "1.30.0",
			CursorFrom:   90477,
			CursorTo:     90501,
			UpdatePosture: &UpdatePostureRow{
				Version: "v1.30.0", Channel: "stable",
				OS: "linux", Arch: "amd64",
				State: "blocked", Reason: "install_method",
				TargetVersion: "v1.33.0", ManifestVersion: 17,
				InstallMethod: "npm", AutoApply: false,
				ExtensionVersion: "1.30.0",
			},
		},
		// Org-served Cloud Intelligence result rail (org-served-cloud-
		// intelligence plan §1.3/§2.4, W3). A page of derived per-session
		// enrichment results coming BACK to the node over
		// GET /api/agent/intel/results, plus the pagination cursor. These
		// never travel on the node→server push wire (INV-3): they are the
		// org's own product, landing in the node-local org_intel_cache table.
		"intel_result_row": IntelResultRow{
			SessionID: "sess-abc123", JobID: "ij-0001",
			Title:         "Fix the push cursor re-enrol regression",
			TaxonomyTags:  []string{"bugfix", "org-server"},
			SuggestedTags: []string{"push-cursor", "cas"},
			Description:   "Diagnosed and fixed a blind cursor save that replayed pre-enrol history.",
			Confidence:    "high",
			Limitations:   []string{"no test run observed"},
			// The five NARRATIVE lists (server migration 156 / agent 124). They
			// are the prose half a developer reads; evidence_refs stay OFF this
			// wire because they are the server's own grounding tokens.
			WorkDone:         []string{"Traced the blind cursor save to the re-enrol path."},
			PlansImplemented: []string{"The cursor CAS landed; the backfill sweep was left."},
			IssuesFound:      []string{"A cached page could be attributed to the wrong enrolment."},
			Failures:         []string{"The regression test for the re-enrol race was not run."},
			NextSteps:        []string{"Run the enrolment race suite before the next roll."},
			SchemaVersion:    "session_enrichment.v2-candidate",
			GeneratedAt:      "2026-09-11T10:00:00Z",
		},
		// The response fixture deliberately carries NO narrative lists: it pins
		// the other half of the contract, that all five are `omitempty` and a
		// pre-156 server's row serializes exactly as it did before this wave.
		"intel_results_response": IntelResultsResponse{
			Results: []IntelResultRow{{
				SessionID: "sess-abc123", JobID: "ij-0001",
				Title:         "Fix the push cursor re-enrol regression",
				Confidence:    "high",
				SchemaVersion: "session_enrichment.v2-candidate",
				GeneratedAt:   "2026-09-11T10:00:00Z",
			}},
			NextCursor: "2026-09-11T10:00:00Z",
		},
	}

	got, err := json.MarshalIndent(fixtures, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixtures: %v", err)
	}
	got = append(got, '\n')

	golden := filepath.Join("testdata", "wire_golden.json")
	if *update {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden: %v (run `go test ./internal/orgcontract -update` to create it)", err)
	}
	if string(got) != string(want) {
		t.Errorf("wire encoding changed.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestSessionRowIdentityV2FieldsCompatOlderAgent pins the compat direction
// the Project Identity Resolver v2 wire fields (§3.2) depend on: an older
// agent's push envelope carries none of the new keys, and unmarshalling it
// into today's SessionRow must yield the ordinary zero values (empty
// strings, false) with no error — the server simply degrades to
// remote-only resolution, exactly as it does for a pre-v2 agent today.
func TestSessionRowIdentityV2FieldsCompatOlderAgent(t *testing.T) {
	olderAgentJSON := `{
		"id": "sess-old",
		"project_root_hash": "sha256:proj-root-aaa",
		"git_remote_hash": "sha256:git-remote-bbb",
		"tool": "claude-code",
		"started_at": "2026-05-25T10:00:00Z",
		"total_actions": 3,
		"org_id": "org-acme",
		"user_email": "dev@acme.example"
	}`

	var got SessionRow
	if err := json.Unmarshal([]byte(olderAgentJSON), &got); err != nil {
		t.Fatalf("unmarshal older-agent session row: %v", err)
	}

	want := SessionRow{
		ID: "sess-old", ProjectRootHash: "sha256:proj-root-aaa", GitRemoteHash: "sha256:git-remote-bbb",
		Tool: "claude-code", StartedAt: "2026-05-25T10:00:00Z", TotalActions: 3,
		OrgID: "org-acme", UserEmail: "dev@acme.example",
	}
	if got != want {
		t.Fatalf("older-agent row decoded to %+v, want %+v (resolver v2 fields must all be zero)", got, want)
	}
}

// TestLOCWireCompatBothDirections pins the two-way compatibility the
// Lines-of-Code wire must hold (plan §4 W5, and the standing compat invariant
// in CLAUDE.md's "Teams / org-server invariants"):
//
//   - OLD AGENT -> NEW SERVER. A push envelope from an agent that predates
//     W5 carries neither `session_loc` nor `loc_days`. Decoding it must yield
//     nil slices with no error, and the server's ingest loop simply writes
//     nothing — no LOC row is invented for a node that never measured any.
//   - NEW AGENT -> OLD SERVER. Both keys are `omitempty` slices, so an agent
//     with nothing to send produces an envelope byte-identical to the old
//     shape; an old server ignores the keys when they ARE present, which is
//     the ordinary encoding/json behaviour this test states explicitly so a
//     future change to a non-omitempty field is a deliberate decision.
func TestLOCWireCompatBothDirections(t *testing.T) {
	olderAgentJSON := `{"agent_version":"1.7.9","cursor_from":1,"cursor_to":2}`
	var env PushEnvelope
	if err := json.Unmarshal([]byte(olderAgentJSON), &env); err != nil {
		t.Fatalf("unmarshal older-agent envelope: %v", err)
	}
	if env.SessionLOC != nil || env.LOCDays != nil {
		t.Fatalf("older-agent envelope decoded LOC wires as %v / %v, want nil (absence must never become a zeroed row)",
			env.SessionLOC, env.LOCDays)
	}

	// An agent with no LOC rows must not add either key to the wire.
	empty, err := json.Marshal(PushEnvelope{AgentVersion: "1.9.0", CursorFrom: 1, CursorTo: 2})
	if err != nil {
		t.Fatalf("marshal empty envelope: %v", err)
	}
	for _, key := range []string{"session_loc", "loc_days"} {
		if bytes.Contains(empty, []byte(`"`+key+`"`)) {
			t.Errorf("an envelope with no LOC rows carries %q — the key must be omitempty so an old server sees the pre-W5 shape exactly", key)
		}
	}

	// An unknown future field on a LOC row must not break today's decoder.
	futureRow := `{"session_loc":[{"session_id":"s1","project_root_hash":"h","ai_added_code":5,"some_future_field":123}]}`
	var future PushEnvelope
	if err := json.Unmarshal([]byte(futureRow), &future); err != nil {
		t.Fatalf("unmarshal newer-agent envelope: %v", err)
	}
	if len(future.SessionLOC) != 1 || future.SessionLOC[0].AIAddedCode != 5 {
		t.Fatalf("newer-agent row decoded to %+v, want the known fields preserved", future.SessionLOC)
	}
}

// int64p is the golden fixture's nullable-integer helper.
func int64p(v int64) *int64 { return &v }

// float64p is the golden fixture's nullable-float helper.
func float64p(v float64) *float64 { return &v }

// TestSessionQualityWireCompatBothDirections pins the two-way compatibility
// of the BL2-ORG session quality wire (CLAUDE.md "Compat invariant"): an
// older agent's envelope carries no `session_quality` key and decodes to a nil
// slice (the server writes nothing, never a zeroed score), an agent with no
// scored sessions adds no key (an older server sees the pre-BL2-ORG shape
// exactly, and ignores the key when present), and an unknown future field on a
// row does not break today's decoder.
func TestSessionQualityWireCompatBothDirections(t *testing.T) {
	var env PushEnvelope
	if err := json.Unmarshal([]byte(`{"agent_version":"1.30.0","cursor_from":1,"cursor_to":2}`), &env); err != nil {
		t.Fatalf("unmarshal older-agent envelope: %v", err)
	}
	if env.SessionQuality != nil {
		t.Fatalf("older-agent envelope decoded session_quality as %v, want nil", env.SessionQuality)
	}

	empty, err := json.Marshal(PushEnvelope{AgentVersion: "1.36.0", CursorFrom: 1, CursorTo: 2})
	if err != nil {
		t.Fatalf("marshal empty envelope: %v", err)
	}
	if bytes.Contains(empty, []byte(`"session_quality"`)) {
		t.Error("an envelope with no scored sessions carries \"session_quality\" - the key must be omitempty")
	}

	future := `{"session_quality":[{"session_id":"s1","quality_score":0.7,"scored_at":"2026-09-27T10:00:00.000000000Z","some_future_field":1}]}`
	var got PushEnvelope
	if err := json.Unmarshal([]byte(future), &got); err != nil {
		t.Fatalf("unmarshal newer-agent envelope: %v", err)
	}
	if len(got.SessionQuality) != 1 || got.SessionQuality[0].QualityScore != 0.7 || got.SessionQuality[0].RedundancyRatio != nil {
		t.Fatalf("newer-agent row decoded to %+v, want the known fields kept and absent components nil", got.SessionQuality)
	}
}

// TestSessionLimitSnapshotWireCompatBothDirections pins the two-way
// compatibility of the lane F-WIRE per-session rate-limit window wire
// (CLAUDE.md "Compat invariant"): an older agent's envelope carries no
// `session_limit_snapshots` key and decodes to a nil slice (the server writes
// nothing, and the org gauge reads as not reported, never 0%), an agent with
// nothing to ship adds no key (an older server sees the pre-F-WIRE shape
// exactly, and ignores the key when present), an unknown future field on a row
// does not break today's decoder, and absent windows stay nil.
func TestSessionLimitSnapshotWireCompatBothDirections(t *testing.T) {
	var env PushEnvelope
	if err := json.Unmarshal([]byte(`{"agent_version":"1.30.0","cursor_from":1,"cursor_to":2}`), &env); err != nil {
		t.Fatalf("unmarshal older-agent envelope: %v", err)
	}
	if env.SessionLimitSnapshots != nil {
		t.Fatalf("older-agent envelope decoded session_limit_snapshots as %v, want nil", env.SessionLimitSnapshots)
	}

	empty, err := json.Marshal(PushEnvelope{AgentVersion: "1.36.0", CursorFrom: 1, CursorTo: 2})
	if err != nil {
		t.Fatalf("marshal empty envelope: %v", err)
	}
	if bytes.Contains(empty, []byte(`"session_limit_snapshots"`)) {
		t.Error("an envelope with no limit windows carries \"session_limit_snapshots\" - the key must be omitempty")
	}

	future := `{"session_limit_snapshots":[{"session_id":"s1","tool":"claude-code","provider":"anthropic","local_id":7,"observed_at":1790000000,"window_5h_util":0.5,"some_future_field":"x"}]}`
	var got PushEnvelope
	if err := json.Unmarshal([]byte(future), &got); err != nil {
		t.Fatalf("unmarshal newer-agent envelope: %v", err)
	}
	if len(got.SessionLimitSnapshots) != 1 {
		t.Fatalf("newer-agent envelope decoded %d rows, want 1", len(got.SessionLimitSnapshots))
	}
	r := got.SessionLimitSnapshots[0]
	if r.SessionID != "s1" || r.Tool != "claude-code" || r.Provider != "anthropic" || r.LocalID != 7 ||
		r.ObservedAt != 1790000000 || r.Window5hUtil == nil || *r.Window5hUtil != 0.5 {
		t.Fatalf("newer-agent row decoded to %+v, want the known fields kept", r)
	}
	if r.Window7dUtil != nil || r.Window5hReset != nil || r.Window7dReset != nil {
		t.Fatalf("absent windows decoded non-nil: %+v - an unreported window must stay unknown, never 0", r)
	}

	// A sparse row round-trips with its absent windows still absent.
	sparse, err := json.Marshal(SessionLimitSnapshotRow{SessionID: "s2", Tool: "codex", Provider: "openai", LocalID: 8, ObservedAt: 1})
	if err != nil {
		t.Fatalf("marshal sparse row: %v", err)
	}
	for _, k := range []string{"window_5h_util", "window_7d_util", "window_5h_reset", "window_7d_reset"} {
		if bytes.Contains(sparse, []byte(`"`+k+`"`)) {
			t.Errorf("sparse row carries %q: %s", k, sparse)
		}
	}
}

// TestAPITurnRequestClassWireCompatBothDirections pins the two-way
// compatibility of APITurnRow.RequestClass (server migration 188 / pg 0054,
// CLAUDE.md "Compat invariant"): an older agent's row carries no
// `request_class` key and decodes to "" (the org stores NULL, never a guessed
// class); a row with no class adds no key (an older server sees the pre-188
// shape exactly, and ignores the key when present); a classed row
// round-trips.
func TestAPITurnRequestClassWireCompatBothDirections(t *testing.T) {
	var old APITurnRow
	if err := json.Unmarshal([]byte(`{"session_id":"s1","timestamp":"2026-05-25T10:05:01Z","provider":"anthropic","input_tokens":5,"output_tokens":1,"cache_read_tokens":0,"cache_creation_tokens":0,"cache_creation_1h_tokens":0,"web_search_requests":0,"cost_usd":0,"message_count":0,"tool_use_count":0,"time_to_first_token_ms":0,"total_response_ms":0,"http_status":200,"org_id":"o","user_email":"e"}`), &old); err != nil {
		t.Fatalf("unmarshal older-agent row: %v", err)
	}
	if old.RequestClass != "" {
		t.Fatalf("older-agent row decoded request_class %q, want empty", old.RequestClass)
	}

	unclassed, err := json.Marshal(APITurnRow{SessionID: "s1", Provider: "anthropic"})
	if err != nil {
		t.Fatalf("marshal unclassed row: %v", err)
	}
	if bytes.Contains(unclassed, []byte(`"request_class"`)) {
		t.Errorf("a row with no class carries \"request_class\": %s - the key must be omitempty", unclassed)
	}

	classed, err := json.Marshal(APITurnRow{SessionID: "s1", Provider: "anthropic", RequestClass: "compaction"})
	if err != nil {
		t.Fatalf("marshal classed row: %v", err)
	}
	var back APITurnRow
	if err := json.Unmarshal(classed, &back); err != nil {
		t.Fatalf("unmarshal classed row: %v", err)
	}
	if back.RequestClass != "compaction" {
		t.Fatalf("classed row round-tripped to %q, want compaction", back.RequestClass)
	}

	// An older server's decoder is modelled by a struct without the field:
	// the unknown key must not break it.
	var older struct {
		SessionID string `json:"session_id"`
		Provider  string `json:"provider"`
	}
	if err := json.Unmarshal(classed, &older); err != nil || older.SessionID != "s1" {
		t.Fatalf("an older decoder rejected the classed row: %+v, %v", older, err)
	}
}
