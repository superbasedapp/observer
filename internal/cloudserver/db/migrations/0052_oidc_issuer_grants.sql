-- 0052_oidc_issuer_grants.sql - grants on the OIDC issuer tables 0051 created
-- (managed-SaaS M6.2; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.2, 4.4).
--
-- step: expand
--
-- The four tables are class S: no row-level security, so these grants ARE
-- the access control. No policy step is needed (there are no policies), and
-- the grants stand in a step of their own after the tables, the shape the
-- design's block asks for.
--
-- sbci_api is the serve process, which runs the issuer:
--
--   oidc_clients       SELECT (authorize), INSERT (the provisioning
--                      transaction, M6.5, adds the org's client in the same
--                      transaction as the org; a rename widens to UPDATE of
--                      redirect_uris in its own step).
--   oidc_codes         SELECT + INSERT + UPDATE (consumed_at) + DELETE: the
--                      conditional UPDATE ... RETURNING that spends a code
--                      reads it, and the sweep deletes spent and expired
--                      ones. Codes are stored by hash.
--   oidc_signing_keys  SELECT (JWKS, key selection) + INSERT (a signer's key
--                      registered as staged). Promotion and retirement are
--                      operator acts through sbci_app.
--   oidc_issued        INSERT only: append-only, and the serve process never
--                      reads back who signed in.
--
-- sbci_app (operator paths, the dev/test single-role fallback) holds the same
-- plus the operator's UPDATE on keys and clients. Nothing is granted on any of
-- them to sbci_worker or sbci_aggregator; no role holds UPDATE or DELETE on
-- oidc_issued.

SET LOCAL lock_timeout = '5s';

GRANT SELECT, INSERT                 ON oidc_clients      TO sbci_api;
GRANT SELECT, INSERT, DELETE         ON oidc_codes        TO sbci_api;
GRANT UPDATE (consumed_at)           ON oidc_codes        TO sbci_api;
GRANT SELECT, INSERT                 ON oidc_signing_keys TO sbci_api;
GRANT INSERT                         ON oidc_issued       TO sbci_api;

GRANT SELECT, INSERT, UPDATE         ON oidc_clients      TO sbci_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON oidc_codes        TO sbci_app;
GRANT SELECT, INSERT, UPDATE         ON oidc_signing_keys TO sbci_app;
GRANT SELECT, INSERT                 ON oidc_issued       TO sbci_app;
