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
			SchemaVersion: "session_enrichment.v2-candidate",
			GeneratedAt:   "2026-09-11T10:00:00Z",
		},
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
