-- 131_mcp_relay.sql — Agent Access P4 node wave (docs/plans/
-- agent-access-implementation-plan-2026-09-23.md §3.2 "Node migration",
-- §11.7 W4b/W4e; rulings R8.18, R8.27.a, R12.7, R13.4, R13.5, R14.2, R14.3,
-- R14.4, R15(a)). Three NODE-LOCAL tables owned by internal/mcprelay/record:
--
--   mcp_relay_state        the node's applied tools.mcp_access policy state
--                          plus the DURABLE pending-loss twin of the relay's
--                          in-memory failed-append counter (R13.5).
--   mcp_relay_launch_spec  the crash-safe journal of each AI client's ORIGINAL
--                          MCP server launch, written BEFORE the relay rewrites
--                          the client's config entry (R8.18 / finding-28).
--   mcp_relay_record       the ONE hash-chained, append-only relay record
--                          table: record_kind decision | completion | gap |
--                          gap_resolution over ONE AUTOINCREMENT seq and ONE
--                          chain_prev/chain_hash chain (R12.7 SUPERSEDES the
--                          two-table layout; R8.27.a: node MCP decisions do
--                          NOT reuse guard_events, which is failure-isolated
--                          and directly org-pushed).
--
-- Privacy posture. mcp_relay_state and mcp_relay_launch_spec NEVER reach the
-- org wire. mcp_relay_record is the SOURCE of two wire families
-- (orgcontract.MCPRelayActivityRow, the HMAC-only daily aggregate, and
-- orgcontract.MCPRelayEventRow, the per-record L2 row for enrolled
-- teams/enterprise nodes) composed by internal/store/mcprelaysummary.go
-- through a FUNCTION seam, exactly like routingsummary.go - the table NAME
-- stays out of internal/store/orgpush.go (all three names are in
-- tests/invariant/privacy_test.go's forbiddenCacheTables). No paired server
-- migration: the server side of this wire is 166/0032's mcp_node_activity_daily
-- + mcp_node_decision_event, already shipped by the P3 wave.
--
-- Chain construction (mirrors the gateway chain, internal/mcpgw/audit):
-- genesis = SHA-256("sbo-mcp-relay-genesis-v1" || node_key); chain_hash =
-- SHA-256(canonical(row) || chain_prev); verification walks seq ASC from
-- genesis across ALL record kinds (one id space). The table is append-only
-- and never pruned by this wave.
--
-- DDL deviation from §3.2, recorded: the plan's `idx_mcprelayrec_push ON
-- mcp_relay_record(seq)` is omitted - seq is the INTEGER PRIMARY KEY (the
-- rowid alias), so that index would be a redundant second copy of the key
-- paid on every append.

CREATE TABLE mcp_relay_state (
  family TEXT PRIMARY KEY,                       -- 'tools.mcp_access'
  running_version INTEGER, effective_hash TEXT, status TEXT, mode TEXT, last_applied INTEGER,
  -- R13.5: DURABLE pending-loss accounting. The NEXT successful append writes
  -- the record_kind='gap' row in the SAME transaction that ZEROES these.
  pending_loss_count    INTEGER NOT NULL DEFAULT 0,
  pending_loss_first_at INTEGER, pending_loss_last_at INTEGER,
  pending_loss_reason   TEXT,
  pending_loss_call_ids TEXT CHECK(pending_loss_call_ids IS NULL OR json_valid(pending_loss_call_ids)));

CREATE TABLE mcp_relay_launch_spec (            -- R8.18/finding-28: durable, crash-safe stdio launch journal
  client        TEXT NOT NULL,                  -- 'claude-code' | 'cursor' | ...
  config_path   TEXT NOT NULL,                  -- the AI client's MCP config file
  entry_key     TEXT NOT NULL,                  -- the mcpServers key we rewrote (e.g. 'github')
  orig_command  TEXT NOT NULL, orig_args TEXT,  -- the ORIGINAL server launch (JSON), restored on disable
  orig_cwd      TEXT,
  orig_env_refs TEXT,                           -- env as SECRET REFERENCES ONLY (never raw values)
  config_generation INTEGER NOT NULL,           -- CAS target: a concurrent rewrite bumps this
  backup_path   TEXT NOT NULL,                  -- R8.28.i: owner-only durable backup FILE holding the VERBATIM original bytes
  backup_sha256 TEXT NOT NULL,                  -- SHA-256 of those bytes; restore verifies then rewrites byte-identically
  applied_at    INTEGER NOT NULL,
  PRIMARY KEY (client, config_path, entry_key));

CREATE TABLE mcp_relay_record (
  seq           INTEGER PRIMARY KEY AUTOINCREMENT,  -- monotonic per node; the ONE chain position for every record kind
  record_kind   TEXT NOT NULL DEFAULT 'decision' CHECK(record_kind IN ('decision','completion','gap','gap_resolution')),  -- R12.7/R13.4
  ts            INTEGER NOT NULL,                -- unix seconds
  family        TEXT NOT NULL DEFAULT 'tools.mcp_access',
  decision_seq  INTEGER,                          -- a 'completion' row points at its 'decision' row's seq (same table); NULL on decision/gap
  vserver       TEXT,                            -- resolved virtual server
  server_ref_hmac TEXT,                          -- keyed HMAC of the upstream server name (aggregate dim; set on decision rows)
  tool_ref_hmac TEXT,                            -- keyed HMAC of the tool name (HMAC-only in every tenancy; set on decision rows)
  server        TEXT,                            -- R10.6: PLAIN server name; L2 enrolled teams/enterprise, NULL individual/L0
  tool          TEXT,                            -- PLAIN tool name; L2 teams/enterprise, NULL individual/L0
  call_id       TEXT,                            -- R11.8: stable per-call id; join key across the completion + org rows
  trace_id      TEXT,                            -- doc1-B9: OTLP trace id
  coding_session_id TEXT, turn_ref TEXT, action_ref TEXT,  -- R10.7/R11.8: correlation anchors
  corr_confidence TEXT CHECK(corr_confidence IS NULL OR corr_confidence IN ('exact','inferred','none')),  -- R10.7
  method        TEXT,
  event_kind    TEXT CHECK(event_kind IS NULL OR event_kind IN
     ('mcp_call','mcp_list','mcp_read','mcp_prompt','mcp_subscribe','mcp_task','mcp_deny')),  -- MCP node event enum (decision rows)
  decision      TEXT CHECK(decision IS NULL OR decision IN ('allow','deny','ask')),
  reason_code   TEXT,
  client_attestation   TEXT CHECK(client_attestation IS NULL OR client_attestation IN ('process_attested','ipc_bound','configured','claimed')),
  credential_assurance TEXT,
  capture_level TEXT CHECK(capture_level IS NULL OR capture_level IN ('L0','L1','L2')),  -- R14.2: required on decision/completion, NULL on gap/gap_resolution
  args_excerpt  TEXT,                            -- L1: scrub.CaptureJSON()'d + size-capped (R11.7)
  args_full     TEXT, args_scrub_status TEXT CHECK(args_scrub_status IS NULL OR args_scrub_status IN ('structured','text_fallback','redacted','truncated')),  -- R9.5/R12.9 L2 REQUEST args (decision row)
  result_full   TEXT, result_scrub_status TEXT CHECK(result_scrub_status IS NULL OR result_scrub_status IN ('structured','text_fallback','redacted','truncated')),  -- R9.5/R12.9 L2 result (completion row)
  error_full    TEXT, error_scrub_status TEXT CHECK(error_scrub_status IS NULL OR error_scrub_status IN ('structured','text_fallback','redacted','truncated')),  -- R12.9: node error payload + status
  elicitation_full TEXT, elicitation_scrub_status TEXT CHECK(elicitation_scrub_status IS NULL OR elicitation_scrub_status IN ('structured','text_fallback','redacted','truncated')),  -- R12.9: node elicitation payload + status
  result_size_bytes INTEGER,                     -- R11.9: content-free result size (present at L0 on a completion row)
  latency_ms    INTEGER, result_status TEXT,
  gap_from INTEGER, gap_to INTEGER, lost_count INTEGER, gap_reason TEXT,  -- R12.7: on a record_kind='gap' row (local append failures)
  resolves_seq INTEGER, resolved_range_start INTEGER, resolved_range_end INTEGER,  -- R13.4: on a record_kind='gap_resolution' row
  resolution TEXT CHECK(resolution IS NULL OR resolution IN ('late_arrival','confirmed_loss')),  -- R13.4: gap_resolution kind only
  chain_prev    BLOB NOT NULL,                   -- prior chain_hash (genesis for the first row)
  chain_hash    BLOB NOT NULL,                   -- SHA-256(canonical(row) || chain_prev)
  -- R13.6: the node L0 CHECK covers ALL FOUR payloads (args/result/error/elicitation).
  CHECK(capture_level <> 'L0' OR (args_excerpt IS NULL AND args_full IS NULL AND result_full IS NULL AND error_full IS NULL AND elicitation_full IS NULL)),
  CHECK(capture_level = 'L2' OR (args_full IS NULL AND result_full IS NULL AND error_full IS NULL AND elicitation_full IS NULL)),
  -- R13.4/R14.2: gap + gap_resolution rows carry NONE of the decision/capture/correlation columns.
  CHECK(record_kind <> 'gap' OR (gap_from IS NOT NULL AND gap_to IS NOT NULL AND lost_count IS NOT NULL AND gap_reason IS NOT NULL
        AND resolves_seq IS NULL AND resolved_range_start IS NULL AND resolved_range_end IS NULL AND resolution IS NULL
        AND capture_level IS NULL AND corr_confidence IS NULL
        AND decision_seq IS NULL AND vserver IS NULL AND server_ref_hmac IS NULL AND tool_ref_hmac IS NULL AND server IS NULL AND tool IS NULL
        AND call_id IS NULL AND trace_id IS NULL AND coding_session_id IS NULL AND turn_ref IS NULL AND action_ref IS NULL
        AND method IS NULL AND event_kind IS NULL AND decision IS NULL AND reason_code IS NULL AND client_attestation IS NULL
        AND credential_assurance IS NULL AND args_excerpt IS NULL AND args_full IS NULL AND args_scrub_status IS NULL
        AND result_full IS NULL AND result_scrub_status IS NULL AND error_full IS NULL AND error_scrub_status IS NULL
        AND elicitation_full IS NULL AND elicitation_scrub_status IS NULL AND result_size_bytes IS NULL AND latency_ms IS NULL AND result_status IS NULL)),
  -- R14.3: resolved_range_start <= resolved_range_end; the FK binds resolves_seq to the SAME chain; the store's append
  -- transaction REJECTS a non-gap parent + a range not contained in the parent gap; overlapping/duplicate resolutions
  -- are idempotent (effective loss = gap minus the UNION of resolutions).
  CHECK(record_kind <> 'gap_resolution' OR (resolves_seq IS NOT NULL AND resolved_range_start IS NOT NULL AND resolved_range_end IS NOT NULL AND resolution IS NOT NULL
        AND resolved_range_start <= resolved_range_end
        AND capture_level IS NULL AND corr_confidence IS NULL
        AND gap_from IS NULL AND gap_to IS NULL AND lost_count IS NULL AND gap_reason IS NULL
        AND decision_seq IS NULL AND vserver IS NULL AND server_ref_hmac IS NULL AND tool_ref_hmac IS NULL AND server IS NULL AND tool IS NULL
        AND call_id IS NULL AND trace_id IS NULL AND coding_session_id IS NULL AND turn_ref IS NULL AND action_ref IS NULL
        AND method IS NULL AND event_kind IS NULL AND decision IS NULL AND reason_code IS NULL AND client_attestation IS NULL
        AND credential_assurance IS NULL AND args_excerpt IS NULL AND args_full IS NULL AND args_scrub_status IS NULL
        AND result_full IS NULL AND result_scrub_status IS NULL AND error_full IS NULL AND error_scrub_status IS NULL
        AND elicitation_full IS NULL AND elicitation_scrub_status IS NULL AND result_size_bytes IS NULL AND latency_ms IS NULL AND result_status IS NULL)),
  -- R15(a): EXHAUSTIVE decision/completion shapes (mirrors the gateway chain).
  CHECK(record_kind <> 'decision' OR (
        capture_level IS NOT NULL AND corr_confidence IS NOT NULL AND call_id IS NOT NULL
        AND event_kind IS NOT NULL AND decision IS NOT NULL
        AND decision_seq IS NULL
        AND result_full IS NULL AND result_scrub_status IS NULL AND error_full IS NULL AND error_scrub_status IS NULL
        AND elicitation_full IS NULL AND elicitation_scrub_status IS NULL AND result_size_bytes IS NULL AND latency_ms IS NULL AND result_status IS NULL
        AND gap_from IS NULL AND gap_to IS NULL AND lost_count IS NULL AND gap_reason IS NULL
        AND resolves_seq IS NULL AND resolved_range_start IS NULL AND resolved_range_end IS NULL AND resolution IS NULL)),
  CHECK(record_kind <> 'completion' OR (
        capture_level IS NOT NULL AND call_id IS NOT NULL AND decision_seq IS NOT NULL AND result_status IS NOT NULL
        AND corr_confidence IS NULL AND vserver IS NULL AND server_ref_hmac IS NULL AND tool_ref_hmac IS NULL AND server IS NULL AND tool IS NULL
        AND method IS NULL AND event_kind IS NULL AND decision IS NULL AND reason_code IS NULL
        AND client_attestation IS NULL AND credential_assurance IS NULL
        AND coding_session_id IS NULL AND turn_ref IS NULL AND action_ref IS NULL
        AND args_excerpt IS NULL AND args_full IS NULL AND args_scrub_status IS NULL
        AND gap_from IS NULL AND gap_to IS NULL AND lost_count IS NULL AND gap_reason IS NULL
        AND resolves_seq IS NULL AND resolved_range_start IS NULL AND resolved_range_end IS NULL AND resolution IS NULL)),
  FOREIGN KEY (decision_seq) REFERENCES mcp_relay_record(seq),
  FOREIGN KEY (resolves_seq) REFERENCES mcp_relay_record(seq));   -- R14.3: gap_resolution.resolves_seq -> same chain
CREATE INDEX idx_mcprelayrec_ts   ON mcp_relay_record(ts);
CREATE INDEX idx_mcprelayrec_call ON mcp_relay_record(call_id) WHERE call_id IS NOT NULL;
CREATE INDEX idx_mcprelayrec_dec  ON mcp_relay_record(decision_seq) WHERE decision_seq IS NOT NULL;
