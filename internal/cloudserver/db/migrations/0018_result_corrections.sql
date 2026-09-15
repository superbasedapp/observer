-- 0018_result_corrections.sql — immutable model result + append-only user
-- revisions, plus the regeneration supersede path (cloud-intelligence
-- divergence remediation plan rev 4.2, §3 "W6 → W6c"; operator ruling R6;
-- closes D4/D12/D21).
--
-- The correction model (R6, verbatim): the server keeps the immutable AI
-- ORIGINAL result and its provenance forever; a user edit is an APPEND-ONLY
-- revision (never an overwrite); the latest explicit user act wins; a
-- regeneration never displaces a user edit. This migration adds the two pieces
-- of durable state that model needs:
--
--   1. analysis_results gains
--        * correction_seq — a per-result monotonic counter, 0 for the pristine
--          AI original, bumped by 1 on every accepted correction. It IS the
--          result's ETag component: the correction route requires
--          If-Match: "<result_id>.<correction_seq>", so two concurrent editors
--          cannot both win a blind write (the second gets 412 and must re-read).
--          The AI original text in `result` is NEVER overwritten by a
--          correction — corrections live in result_revisions — so `result`
--          stays the immutable original + provenance the plan promises.
--        * superseded_by — the result id that regenerated over this one (D21).
--          The pre-existing `superseded` boolean (migration 0005) is the flag;
--          this adds the pointer. Set by the WORKER when a newer result for the
--          same cloud session lands (see the column-level grant below).
--
--   2. result_revisions — the append-only user-edit history, one row per
--      accepted correction, TENANT (RLS ENABLE + FORCE + the
--      sbci_current_account() policy every 0002/0012/0013 tenant table carries).
--      A revision is a PARTIAL correction (only the fields the user changed),
--      SafeText-validated at the API boundary before it reaches here.
--
-- Why a new table rather than more columns on analysis_results: a result has
-- ONE immutable AI original but MANY user revisions over time, and the plan's
-- audit requirement is the full history ("append-only RLS'd revision history").
-- One-to-many with its own monotonic seq is a child table (CLAUDE.md #4: one
-- owner per piece of state) — the same shape structural_snapshots uses for its
-- per-window revisions.

-- ---------------------------------------------------------------------------
-- analysis_results: the ETag counter + the regeneration pointer.
-- ---------------------------------------------------------------------------
ALTER TABLE analysis_results
    ADD COLUMN correction_seq bigint NOT NULL DEFAULT 0 CHECK (correction_seq >= 0),
    ADD COLUMN superseded_by  uuid;

-- superseded_by, when set, names another result of the SAME account. The
-- composite (account_id, superseded_by) FK keeps the pointer honest and
-- tenant-local; ON DELETE stays 0002's NO ACTION default (result removal is the
-- deletion pipeline's explicit decision, never a cascade).
ALTER TABLE analysis_results
    ADD CONSTRAINT analysis_results_superseded_by_fk
    FOREIGN KEY (account_id, superseded_by)
    REFERENCES analysis_results (account_id, id);

-- ---------------------------------------------------------------------------
-- result_revisions (TENANT) — the append-only user-edit history.
-- ---------------------------------------------------------------------------
CREATE TABLE result_revisions (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id     uuid NOT NULL REFERENCES accounts(account_id),
    -- The result this revision corrects. The composite FK ties the revision to
    -- an account-local result; RLS + this FK together mean a revision can only
    -- ever reference a result the same tenant owns.
    result_id      uuid NOT NULL,
    -- Per-result monotonic revision number (1, 2, 3 …). Allocation is serialized
    -- by taking FOR UPDATE on the parent analysis_results row inside the
    -- correction transaction (store.ApplyResultCorrection), so two concurrent
    -- corrections to the SAME result mint consecutive numbers rather than
    -- colliding; the UNIQUE below is the database-level backstop.
    revision_seq   int  NOT NULL CHECK (revision_seq >= 1),
    -- Who authored the edit. 'user' this arc (the developer, via portal or
    -- node); a reserved column for a future 'assistant'/'system' editor.
    editor         text NOT NULL DEFAULT 'user' CHECK (editor <> ''),
    -- Where the edit originated: the portal Sessions page, or a node override
    -- synced up (R6: "node override syncs up as a revision on next sync").
    source         text NOT NULL CHECK (source IN ('portal', 'node')),
    -- The corrected fields as a PARTIAL result object — only what the user
    -- changed, each field already run through cloudcontract.NormalizeText at the
    -- API boundary (SafeText: control/bidi-free, NFC-bounded). Bounded well
    -- under the result ceiling; a real correction is a title + maybe a
    -- description + a few tags.
    correction     jsonb NOT NULL CHECK (octet_length(correction::text) <= 16384),
    -- The client-supplied idempotency key for this correction. A retry of the
    -- same edit carries the same key and replays the same revision rather than
    -- appending a duplicate — enforced by the UNIQUE below, not application
    -- logic. Bounded so a hostile client cannot push an unbounded string.
    idempotency_key text NOT NULL CHECK (idempotency_key <> '' AND octet_length(idempotency_key) <= 200),
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    UNIQUE (account_id, id),
    -- One revision number per result: the app allocates it under the parent
    -- row lock, this is the backstop.
    UNIQUE (account_id, result_id, revision_seq),
    -- Idempotency as a DATABASE constraint: the same key can append at most one
    -- revision to a given result.
    UNIQUE (account_id, result_id, idempotency_key),
    FOREIGN KEY (account_id, result_id) REFERENCES analysis_results (account_id, id)
);

-- The correction route reads "the latest revision for this result" and the
-- Sessions detail reads a result's whole revision history newest-first.
CREATE INDEX result_revisions_result_seq
    ON result_revisions (account_id, result_id, revision_seq DESC);

ALTER TABLE result_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE result_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY result_revisions_tenant ON result_revisions
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

-- ---------------------------------------------------------------------------
-- Grants (E2 / W6rs role split).
-- ---------------------------------------------------------------------------
--
-- result_revisions:
--   * sbci_api INSERTs a new revision on PATCH /v1/results/{id}/correction and
--     on the portal Sessions edit, SELECTs for ETag + the Sessions detail, and
--     UPDATEs ONLY on account deletion (the body tombstone). A correction is
--     ALWAYS a fresh INSERT, never an UPDATE of an existing revision — the
--     append-only invariant is enforced in store.ApplyResultCorrection and
--     pinned by a test; the UPDATE grant exists solely for the deletion
--     tombstone, exactly as analysis_results' api UPDATE does.
--   * sbci_worker gets nothing: the worker never touches user revisions.
GRANT SELECT, INSERT, UPDATE ON result_revisions TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON result_revisions TO sbci_app;

-- analysis_results: the regeneration supersede path is a WORKER action — when
-- CompleteJobWithResult stores a newer result for a session, it marks the prior
-- current result superseded. The worker had NO UPDATE on analysis_results
-- (migration 0015: INSERT-only, so it can never rewrite a result body). Grant a
-- COLUMN-LEVEL UPDATE limited to exactly the two supersede columns, so the
-- worker can flip the flag + pointer but STILL cannot overwrite `result`,
-- `correction_seq`, or any provenance column. The negative test pins that a
-- worker UPDATE of `result` is denied.
GRANT UPDATE (superseded, superseded_by) ON analysis_results TO sbci_worker;
