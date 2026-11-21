-- 0056_signed_documents_grants.sql - grants on the signed-document tables
-- 0055 created (managed-SaaS M6.3; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.2, 4.5).
--
-- step: expand
--
-- Both tables are class S: no row-level security, so these grants ARE the
-- access control, and no policy step is needed.
--
--   sbci_worker  SELECT + INSERT: the worker builds a body, has the document
--                signer sign it, stores it and reads the latest back to
--                push it (design 4.5 "Process").
--   sbci_app     SELECT + INSERT: the operator paths and the dev/test
--                single-role fallback.
--
-- sbci_api and sbci_aggregator get nothing: no customer-session handler reads
-- a signed document. No role holds UPDATE or DELETE: the tables are
-- append-only.

SET LOCAL lock_timeout = '5s';

GRANT SELECT, INSERT ON org_entitlement_docs TO sbci_worker;
GRANT SELECT, INSERT ON availability_docs    TO sbci_worker;

GRANT SELECT, INSERT ON org_entitlement_docs TO sbci_app;
GRANT SELECT, INSERT ON availability_docs    TO sbci_app;
