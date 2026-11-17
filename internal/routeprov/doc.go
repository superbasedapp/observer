// Package routeprov is the pure provenance model for the proxy routes
// Observer writes into AI clients' own config files (Claude Code's
// env.ANTHROPIC_BASE_URL, Codex's model_provider + base_url, ...).
//
// It answers one question for leaving an organization: did Observer's
// ENROLMENT write this route, and is it still exactly what enrolment wrote?
// Only then does Leave remove it. A route someone set themselves, or one
// `observer init` / Settings > Connected tools / a launcher wrote, is kept. The answer
// comes from a record made at write time (who wrote it, what value), never
// from guessing at the current value.
//
// The package holds the record types, the claim rule applied at write time
// (Note) and the ordered Leave decision table (Decide). It does no I/O: the
// one owner of the state file is internal/proxyroute, which writes the
// routes themselves.
package routeprov
