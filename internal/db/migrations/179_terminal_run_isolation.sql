-- 179_terminal_run_isolation.sql - the G19 isolation evidence of a terminal
-- run (sandbox plan v2 section 8.4, phase P1a; roadmap F0-13, the execution
-- evidence envelope's first consumer).
--
-- Every column is a closed enum from internal/sandboxvocab, written once at
-- launch by the terminal recorder (cmd/observer/terminal_launch.go) from
-- what the launch actually built. '' means "not recorded" (every row older
-- than this migration, and launch kinds that record nothing), never a
-- default value:
--   isolation_class      effective class built: none | process | container |
--                        userspace_kernel | hw_vm
--   stack                backend ids of the layers, outermost first, comma
--                        separated (bwrap today)
--   egress_tier          host | internet | proxy_only | none
--   capture_level        the COMPUTED level (internal/sandboxselect, table
--                        C1 to C8): full | proxy_and_transcripts |
--                        transcripts_only | none
--   capture_rule         the rule id that decided it (C1 to C8)
--   capture_origin       local | sandboxed | remote_sandbox
--   capture_degraded     1 when the run lost capture after launch
--   native_sandbox_state what Observer did with the agent's own sandbox
--   verification         live | doc | fixture | inferred on this host
--   key_custody          where the model credential sat
--   evidence_digest      execevidence.Envelope.Digest over the above and
--                        the producer inputs migration 181 stores, so a
--                        later record can name this evidence. The digest is
--                        unkeyed: it is not tamper evidence, because anyone
--                        who can edit the row can recompute it (ledger
--                        SHR-6)
--
-- terminal_run ships on the org wire only as TerminalRunRow under
-- ShareOptions.shipsRawContent() (managed nodes, or an individual node
-- whose operator set full_content); these columns ride with it and nothing
-- per-run is added under terminal_detail. Paired with server migration 240
-- and PostgreSQL 0107 (terminal_run_rows).

ALTER TABLE terminal_run ADD COLUMN isolation_class TEXT NOT NULL DEFAULT '';
ALTER TABLE terminal_run ADD COLUMN stack TEXT NOT NULL DEFAULT '';
ALTER TABLE terminal_run ADD COLUMN egress_tier TEXT NOT NULL DEFAULT '';
ALTER TABLE terminal_run ADD COLUMN capture_level TEXT NOT NULL DEFAULT '';
ALTER TABLE terminal_run ADD COLUMN capture_rule TEXT NOT NULL DEFAULT '';
ALTER TABLE terminal_run ADD COLUMN capture_origin TEXT NOT NULL DEFAULT '';
ALTER TABLE terminal_run ADD COLUMN capture_degraded INTEGER NOT NULL DEFAULT 0;
ALTER TABLE terminal_run ADD COLUMN native_sandbox_state TEXT NOT NULL DEFAULT '';
ALTER TABLE terminal_run ADD COLUMN verification TEXT NOT NULL DEFAULT '';
ALTER TABLE terminal_run ADD COLUMN key_custody TEXT NOT NULL DEFAULT '';
ALTER TABLE terminal_run ADD COLUMN evidence_digest TEXT NOT NULL DEFAULT '';
