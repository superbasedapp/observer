-- 195_terminal_run_seal.sql - the signed seal over a run's execution
-- evidence digest (component isolation.seal, ledger SHR-6, lane
-- GATES-SEC).
--
-- evidence_seal_key_id, evidence_seal_public_key and evidence_seal_sig are
-- the Ed25519 seal internal/execevidence.SignSeal makes over
-- evidence_digest and the key id (domain sbo-exec-evidence-seal-v1). ''
-- for every run sealed by nothing: the component off (the default), no
-- digest, or a row from before this migration, which reads `unsealed`.
-- One writer: internal/store/termrun_seal.go (the injected sealer the
-- terminal_run insert calls). The seal rides on TerminalRunRow only, so it
-- ships exactly when that row ships; it is never content (a key id, a
-- public key and a signature). Server pair: migration 260 / PostgreSQL
-- 0127 (terminal_run_rows seal and countersign columns).

ALTER TABLE terminal_run ADD COLUMN evidence_seal_key_id TEXT NOT NULL DEFAULT '';
ALTER TABLE terminal_run ADD COLUMN evidence_seal_public_key TEXT NOT NULL DEFAULT '';
ALTER TABLE terminal_run ADD COLUMN evidence_seal_sig TEXT NOT NULL DEFAULT '';
