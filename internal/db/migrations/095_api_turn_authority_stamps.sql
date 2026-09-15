-- 095: Plane B per-turn authority stamps (Sol S5 / Luna L15).
--
-- docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md §2.4/§3.
-- Mixed-mode fleets (some nodes still routing direct, some via the org AI
-- Gateway) need per-turn facts so an org cost rollup can single-count a turn
-- and know which source owns its usage authority. These three columns carry
-- exactly that, and are CONTENT-FREE by construction — enum strings and an
-- integer generation id only, never any text drawn from a request/response
-- body. They ride the org push wire (orgcontract.APITurnRow) unconditionally
-- (metadata, not content), pinned by tests/invariant/privacy_test.go.
--
--   route              how the node proxy served the turn:
--                        'direct'   — straight to the fixed provider upstream
--                                     (Node Mode, or no org route installed)
--                        'gateway'  — via the org AI Gateway primary
--                        'fallback' — via an org AI Gateway fallback rung
--                      NULL/empty on pre-095 rows == 'direct' semantics.
--   routing_generation the immutable routing-snapshot generation (Sol S7) the
--                      turn was served under; 0 when no org route was live.
--   authority_source   which source is authoritative for this turn's org-level
--                      usage: 'node' (this proxy's observation stands) or
--                      'gateway' (the gateway's audit row wins; this row is the
--                      node-side shadow). NULL/empty == 'node' semantics.
ALTER TABLE api_turns ADD COLUMN route TEXT;
ALTER TABLE api_turns ADD COLUMN routing_generation INTEGER;
ALTER TABLE api_turns ADD COLUMN authority_source TEXT;
