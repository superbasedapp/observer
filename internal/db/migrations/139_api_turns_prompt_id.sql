-- 139_api_turns_prompt_id.sql - the client-supplied user-prompt grouping id
-- on a proxy-captured turn (post-Agent-Access backlog item 14, lane
-- R2-PROXYHDR, 2026-09-27).
--
-- WHY. Claude Code 2.1.283+ sends `x-claude-code-prompt-id` (a random UUID
-- shared by every request that serves one user prompt, including the turns
-- of the subagents that prompt started) when its gateway hint headers are on
-- (CLAUDE_CODE_GATEWAY_HINT_HEADERS=1; off by default for a custom base URL,
-- which `observer claude` now sets). Documented at
-- https://code.claude.com/docs/en/llm-gateway-protocol#gateway-hint-headers.
-- It is an EXACT user-message grouping key, so the Next-Message Cost
-- Predictor's turns-per-message ladder (internal/store/predict.go) prefers
-- it over bucketing turns between user_prompt action timestamps, which only
-- ~32% of sessions carry.
--
-- The proxy reads the value through a header-name table
-- (internal/proxy/prompthint.go), never a tool branch, and only accepts a
-- short printable-ASCII token; anything else stays NULL.
--
-- NODE-LOCAL: an opaque random id with no content, but it has no org
-- consumer yet, so internal/store/orgpush.go does not select it and there is
-- no paired server migration. Shipping it later is an additive wire field
-- (orgcontract.APITurnRow) plus a server migration.
ALTER TABLE api_turns ADD COLUMN prompt_id TEXT;

-- The predictor groups one session's turns by prompt id; a partial index
-- keeps it small because only hint-header turns carry a value.
CREATE INDEX IF NOT EXISTS idx_api_turns_session_prompt
    ON api_turns(session_id, prompt_id) WHERE prompt_id IS NOT NULL;
