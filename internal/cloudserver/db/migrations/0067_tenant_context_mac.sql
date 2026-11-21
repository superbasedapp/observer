-- 0067_tenant_context_mac.sql - sbci_current_account() verifies a MAC'd
-- tenant context (managed-SaaS plan 07 M3b.2 and M6.1b; internal/tenantctx,
-- kind "account").
--
-- step: contract
--
-- Contract, because it changes what the running release relies on: from
-- this step, a bare account id in sbci.account_id is no context at all
-- (sbci_current_account() returns NULL, so every tenant policy matches no
-- row). A release older than this step's store (which sets a bare id) reads
-- and writes nothing in tenant tables once it lands, so the step ships with
-- the store change in one roll.
--
-- THE CONTEXT TOKEN. store.WithAccount (and store.SetAccountContext) set,
-- with set_config('sbci.account_id', $1, true), the token
--
--     <account>.<expiry>.<mac>
--
-- account: the account id, a lower-case canonical uuid (uuid::text); expiry:
-- unix seconds; mac: the lower-case hex HMAC-SHA256, under a live key of
-- sbci_tenant_context_keys (0066), of
--
--     'sbci-account-v1' || newline || '<account>.<expiry>'
--
-- The prefix is the account kind's MAC domain (tenantctx.KindAccount): the
-- org server's tokens are MAC'd with no prefix and no subject may contain a
-- newline, so an org token never verifies here, even under the same key.
-- Any session may SET the setting; the MAC is what a session without the key
-- cannot produce. A token is accepted while expiry is later than now(), the
-- transaction's start, so a context never lapses inside the transaction that
-- set it. The setting is per transaction (tenantctx's doc.go records why).
--
-- FUNCTIONS:
--
--   sbci_hmac_pads(key)        IMMUTABLE. The two HMAC pads of a key (RFC
--                              2104). EXECUTE: its owner only.
--   sbci_tenant_context_install(key, retire_others_after)
--                              Installs a key (32 to 1024 bytes, generated
--                              outside the database), or re-arms it when it
--                              is already installed, and returns its key id.
--                              With retire_others_after (0 to 24 hours) it
--                              caps every other live key at now() plus that
--                              overlap: a rotation. NULL retires nothing.
--                              Expired keys are deleted. SECURITY INVOKER and
--                              EXECUTE revoked from PUBLIC: only a role that
--                              may write sbci_tenant_context_keys (the
--                              migrating login, its owner) can install.
--   sbci_current_account()     STABLE SECURITY DEFINER, owner sbci_defs,
--                              search_path pinned. The account of a valid
--                              token, else NULL: no token, a malformed or
--                              overlong one, an expired one, a MAC no live
--                              key produces, or an empty key table. The
--                              token is fully shape-checked before any cast,
--                              so the function cannot raise. EXECUTE keeps
--                              its existing grants and PUBLIC (0004, 0015;
--                              it answers only for the caller's own token).
--
-- The MAC comparison hashes both sides first, so its running time does not
-- depend on how many leading bytes of a forged MAC are right.
--
-- Every tenant policy already calls sbci_current_account() and nothing else
-- reads the setting (m6.0 control-plane design 3.2), so this one body is the
-- whole cloud seam; no policy changes.

SET LOCAL lock_timeout = '5s';

CREATE FUNCTION sbci_hmac_pads(p_key bytea, OUT inner_key bytea, OUT outer_key bytea)
LANGUAGE plpgsql IMMUTABLE STRICT
SET search_path = pg_catalog, pg_temp
AS $f$
DECLARE
    kb bytea := p_key;
    i  int;
BEGIN
    IF length(kb) > 64 THEN
        kb := sha256(kb);
    END IF;
    kb := kb || decode(repeat('00', 64 - length(kb)), 'hex');
    inner_key := kb;
    outer_key := kb;
    FOR i IN 0..63 LOOP
        inner_key := set_byte(inner_key, i, get_byte(kb, i) # 54); -- 0x36
        outer_key := set_byte(outer_key, i, get_byte(kb, i) # 92); -- 0x5c
    END LOOP;
END
$f$;

REVOKE ALL ON FUNCTION sbci_hmac_pads(bytea) FROM PUBLIC;

CREATE FUNCTION sbci_tenant_context_install(p_key bytea, p_retire_others_after interval)
RETURNS text
LANGUAGE plpgsql VOLATILE
SET search_path = pg_catalog, pg_temp
AS $f$
DECLARE
    v_id text;
    pads record;
BEGIN
    IF p_key IS NULL OR length(p_key) < 32 OR length(p_key) > 1024 THEN
        RAISE EXCEPTION 'sbci_tenant_context_install: the key must be 32 to 1024 bytes' USING ERRCODE = '22023';
    END IF;
    IF p_retire_others_after IS NOT NULL
       AND (p_retire_others_after < interval '0' OR p_retire_others_after > interval '24 hours') THEN
        RAISE EXCEPTION 'sbci_tenant_context_install: the overlap must be between 0 and 24 hours' USING ERRCODE = '22023';
    END IF;
    v_id := encode(substring(sha256(convert_to('sbo-tenant-context-key-id-v1' || chr(10), 'UTF8') || p_key) FROM 1 FOR 8), 'hex');
    SELECT * INTO pads FROM public.sbci_hmac_pads(p_key);
    DELETE FROM public.sbci_tenant_context_keys
     WHERE not_after IS NOT NULL AND not_after <= now() AND key_id <> v_id;
    INSERT INTO public.sbci_tenant_context_keys (key_id, inner_key, outer_key)
    VALUES (v_id, pads.inner_key, pads.outer_key)
    ON CONFLICT (key_id) DO UPDATE SET not_after = NULL;
    IF p_retire_others_after IS NOT NULL THEN
        UPDATE public.sbci_tenant_context_keys SET not_after = now() + p_retire_others_after
         WHERE key_id <> v_id AND (not_after IS NULL OR not_after > now() + p_retire_others_after);
    END IF;
    RETURN v_id;
END
$f$;

REVOKE ALL ON FUNCTION sbci_tenant_context_install(bytea, interval) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sbci_current_account()
RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $f$
DECLARE
    tok   text := current_setting('sbci.account_id', true);
    parts text[];
    msg   bytea;
    want  bytea;
    k     record;
BEGIN
    IF tok IS NULL OR length(tok) > 512 THEN
        RETURN NULL;
    END IF;
    parts := regexp_match(tok, '^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.([0-9]{1,18})\.([0-9a-f]{64})$');
    IF parts IS NULL THEN
        RETURN NULL;
    END IF;
    IF parts[2]::bigint <= floor(extract(epoch FROM now()))::bigint THEN
        RETURN NULL;
    END IF;
    msg := convert_to('sbci-account-v1' || chr(10) || parts[1] || '.' || parts[2], 'UTF8');
    want := sha256(decode(parts[3], 'hex'));
    FOR k IN
        SELECT inner_key, outer_key FROM public.sbci_tenant_context_keys
         WHERE not_after IS NULL OR not_after > now()
    LOOP
        IF sha256(sha256(k.outer_key || sha256(k.inner_key || msg))) = want THEN
            RETURN parts[1]::uuid;
        END IF;
    END LOOP;
    RETURN NULL;
END
$f$;

ALTER FUNCTION sbci_current_account() OWNER TO sbci_defs;
