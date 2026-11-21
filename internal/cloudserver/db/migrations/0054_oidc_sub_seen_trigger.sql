-- 0054_oidc_sub_seen_trigger.sql - every issued token records (org, sub) in
-- org_sub_seen (managed-SaaS M6.2; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.1, 4.4).
--
-- step: expand
--
-- org_sub_seen (0047) is the list M6.9 fans members/deactivate out to: every
-- (org, WorkOS sub) the issuer ever minted a token for. It is written here by
-- an AFTER INSERT trigger on oidc_issued, so it is maintained in the same
-- transaction as the issued row by construction, and the serve role
-- (sbci_api) needs no grant on org_sub_seen at all: it cannot read or write
-- the list of every org's subjects, only append a sign-in.
--
-- The trigger function is SECURITY DEFINER, owned by sbci_defs (which gets
-- SELECT, INSERT, UPDATE on org_sub_seen here), search_path pinned, every
-- relation schema-qualified (the 0022/0035/0047 hardening). A trigger function
-- cannot be called directly (it returns trigger), so its EXECUTE-to-PUBLIC
-- default grants nothing callable; migcheck classes a REVOKE as contract, so
-- none is attempted.
--
-- first_seen is the first sign-in's iat; last_seen moves forward only.

SET LOCAL lock_timeout = '5s';

CREATE FUNCTION sbci_oidc_note_sub_seen()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    INSERT INTO public.org_sub_seen AS s (org_id, sub, first_seen, last_seen)
    VALUES (NEW.org_id, NEW.sub, NEW.iat, NEW.iat)
    ON CONFLICT (org_id, sub) DO UPDATE
        SET last_seen = GREATEST(s.last_seen, EXCLUDED.last_seen);
    RETURN NEW;
END
$$;

ALTER FUNCTION sbci_oidc_note_sub_seen() OWNER TO sbci_defs;

GRANT SELECT, INSERT, UPDATE ON org_sub_seen TO sbci_defs;

CREATE TRIGGER oidc_issued_sub_seen
    AFTER INSERT ON oidc_issued
    FOR EACH ROW EXECUTE FUNCTION sbci_oidc_note_sub_seen();
