// Package grokbot implements an adapter for Grok Bot, the xAI DESKTOP agent
// app (Electron; productName "Grok Bot", internal package name "sand",
// author "SpaceXAI", built on Anysphere/Cursor's agent stack).
//
// DISTINCT from internal/adapter/grok (models.ToolGrok, "grok"), which parses
// the Grok CLI's ACP session bundles under ~/.grok/. Different product,
// different format, no path overlap.
//
// On-disk layout (Windows + macOS; Grok Bot is not distributed for Linux):
//
//	<electron userData>/sand-client-persistence/<base32(key)>.blob
//
// where <electron userData> is %APPDATA%\Grok Bot on Windows and
// ~/Library/Application Support/Grok Bot on macOS.
//
// Every .blob is PLAINTEXT JSON — no encryption, no DPAPI/OSCrypt, no
// protobuf, no SQLite, no LevelDB:
//
//	{"schemaVersion":<int>,"value":{...}}
//
// The filename is the persistence-slice key encoded with RFC 4648 base32 over
// a LOWERCASE alphabet ("abcdefghijklmnopqrstuvwxyz234567"), unpadded, plus a
// ".blob" suffix. See blobname.go, which reproduces the app's own
// encode/decode including all five of its validation rules.
//
// This adapter reads exactly ONE slice family:
//
//	sand.client.slice.account.<acct>.transcript.replicas.<agentId>
//
// one blob per conversation, holding the whole transcript as a single
// entries[] array rewritten in place. The agentId is the session id.
//
// # Deliberately not ingested
//
// The sibling `roster.last-roster` slice is a session index (agent names,
// createdAt/lastActivityAt, unread counts). It is NOT watched: every field it
// adds beyond what the transcript already carries — principally the
// user-chosen agent name — has nowhere to land, because models.Session has no
// title column and models.ToolEvent has no field that could carry one.
// Watching it would add a permanently zero-action cursor for no gain.
//
// Its `path` field ("/home/box/sand-data/agents/<id>/store.db") is the single
// most misleading value in this format: it looks exactly like a local project
// root and is a path INSIDE THE REMOTE SANDBOX VM. It must never be fed to
// git.Resolve — doing so would CWD-prefix the observer's own repo onto it (the
// foreign-path failure class). Nothing in this package resolves it.
//
// # THIN store: no tokens, no models, no cost, no cwd
//
// Grok Bot executes the agent in a remote sandbox ("the box"); the desktop app
// is a thin replicated client. There is no usage envelope, no model name, and
// no working directory anywhere in the local store, so this adapter emits
// sessions + actions ONLY and never a TokenEvent. Sessions land under the
// synthetic project root "[grokbot]" (the antigravity precedent).
//
// The strings "grok-4.5" / "grok-4.6" DO appear on disk, but only inside
// sand-statsig-bootstrap.json as feature-flag config (upgradeModelId,
// effort_first_compact_model_ids). That is flag configuration, not a record of
// what any session used, so Model is deliberately left empty rather than
// fabricated from it.
//
// # Off-limits (never read)
//
// sand-secrets.json (cursor-machine-id / cursor-accounts / local-exec-file-key),
// local-exec-daemon-credential.json and local-exec-daemon-connection.json (both
// sealed), "Local State" (Chromium DPAPI os_crypt key), Network/Cookies,
// Network/Trust Tokens, and the whole Partitions/sand-forever-box/ webview
// profile. The ~/.grokbot daemon-state directory is not read at all — it holds
// no conversation content and no usage data.
//
// The avoidance is STRUCTURAL, not conventional: IsSessionFile is an
// allow-list requiring the sand-client-persistence directory, a ".blob"
// extension, a clean base32 decode, and a transcript.replicas slice key.
// TestOffLimitsFilesNeverDispatched pins it against regression.
package grokbot
