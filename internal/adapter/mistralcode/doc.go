// Package mistralcode implements an adapter for Mistral Code, whose CLI
// binary is `vibe` (installed via `uv tool`). vibe >= 2.25 writes the
// "unified harness" store under ~/.vibe/logs/session/unified/<uuid>/ (see
// unified.go). Earlier versions (and sessions they left behind) use the
// LEGACY per-session directory under ~/.vibe/logs/session/:
//
//	session_<YYYYMMDD_HHMMSS>_<8hex>/
//	  meta.json       session metadata: working_directory, git branch,
//	                  the model config, and SESSION-CUMULATIVE token stats
//	                  (session_prompt_tokens / _completion_tokens /
//	                  _cached_tokens / session_cost) — verified live 2026-08-18.
//	  messages.jsonl  append-only transcript: one JSON object per line,
//	                  role user|assistant|tool. Assistant records carry
//	                  OpenAI-shaped tool_calls[] ({id,function:{name,arguments}})
//	                  and reasoning_content; tool records carry the result.
//
// Token tier is SESSION-LEVEL: the transcript has no per-message usage, so
// this adapter emits ONE TokenEvent per session from meta.json's cumulative
// stats (prompt tokens are GROSS, netted against cached). The event's
// SourceEventID is fixed per session so the store's MAX-upgrade keeps it
// monotonic as the session grows.
//
// Off-limits (never read): ~/.vibe/.env (holds MISTRAL_API_KEY, mode 0600 —
// confirmed live 2026-08-25), ~/.vibe/config.toml (mode 0600), ~/.vibe/vibehistory
// (raw prompt history, mode 0600), ~/.vibe/connector_bootstrap_cache.json, and
// any other vibe-home file — this adapter reads only meta.json + messages.jsonl
// under a legacy session directory, and only the store documents unified.go
// names under a unified session directory.
package mistralcode
