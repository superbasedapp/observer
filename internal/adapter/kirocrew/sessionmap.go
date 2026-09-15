package kirocrew

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// sessionMapFile is the Crew Gateway's chat-slot → driven-agent-session
// index, at the Crew data root. GROUNDED 2026-09-03:
//
//	{"dashboard:chat-2-1700000002": {"sid": "99e0fd7c-…",
//	  "slack_thread_ts": null, "slack_channel_id": null,
//	  "provider": "acp", "cwd": "C:\\Users\\…\\antigravity"}, …}
//
// `sid` is the kiro-cli session id under `~/.kiro/sessions/cli/<sid>.
// {json,jsonl}` — the store internal/adapter/kirocli already captures.
// This file is the ONLY sidecar this adapter reads besides the chat
// transcript itself; everything else under the Crew root (config.json,
// memory.db, .env, audit.log, security_events.jsonl, …) is off-limits.
const sessionMapFile = "session_map.json"

// slackFieldsNeverRead documents, in code, that the two Slack-integration
// keys observed alongside `sid` in session_map.json are DELIBERATELY not
// decoded: `slack_thread_ts` and `slack_channel_id` are workspace
// identifiers, not capture data. sessionMapEntry types only `sid`.
type sessionMapEntry struct {
	SID string `json:"sid"`
}

// mapKeyForFile derives the session_map.json key for a Crew chat
// transcript path. GROUNDED: the transcript basename is the map key with
// the FIRST ':' rewritten as '_' (a path-safe filename), so the inverse
// is to rewrite the first '_' back:
//
//	sessions/dashboard_chat-2-1700000002.jsonl
//	  → map key "dashboard:chat-2-1700000002"
//
// A basename with no '_' has no derivable key and yields "".
func mapKeyForFile(path string) string {
	base := strings.TrimSuffix(filepath.Base(path), ".jsonl")
	i := strings.Index(base, "_")
	if i <= 0 || i == len(base)-1 {
		return ""
	}
	return base[:i] + ":" + base[i+1:]
}

// ownership is the resolved answer to "who owns this conversation's rows?"
// It is a closed vocabulary so the emit decision stays table-driven
// (CLAUDE.md #5) instead of an if/else ladder over file-read outcomes.
type ownership int

const (
	// ownedByKiroCLI means session_map.json resolves this chat slot to a
	// kiro-cli agent session id. That session's own store
	// (~/.kiro/sessions/cli/<sid>.{json,jsonl}) is the canonical record
	// and internal/adapter/kirocli already captures it — this adapter
	// must emit NO conversation rows for the chat, or the same
	// conversation lands twice under two tool identities.
	ownedByKiroCLI ownership = iota
	// ownedBySelf means the Crew data root HAS a session_map.json and it
	// does NOT resolve this chat slot: no kiro-cli twin exists, so the
	// Crew transcript is the only record of the conversation and this
	// adapter emits it in full.
	//
	// KNOWN LIMITATION (see docs/kiro-crew-adapter.md "The open-slot
	// caveat"). session_map.json is an OPEN-SLOT index, not a history:
	// its keys were byte-for-byte the keys of open_slots.json on the
	// grounding host, and a third live `agent_name == "kirocrew"`
	// kiro-cli session had no map entry at all. So a negative verdict is
	// only as durable as the slot: if Crew prunes a CLOSED slot from the
	// map while its transcript stays on disk, the next parse flips that
	// chat from ownedByKiroCLI to ownedBySelf and emits a duplicate of a
	// conversation kiro-cli already owns. Not observed (no chat was
	// closed during the grounding run) and not defended against here;
	// the fix is to make the positive verdict evidence-based rather than
	// index-based — look the transcript's first `tool_call_id` up in
	// ~/.kiro/sessions/cli/*.jsonl, where the ids are byte-identical, or
	// keep a sticky was-once-owned marker.
	ownedBySelf
	// ownershipUnresolved means the map could not be consulted at all
	// (absent, unreadable, malformed) or the transcript basename yields
	// no map key. Ownership is UNKNOWN, so the conservative answer is to
	// emit nothing: a missed session is recoverable by a later parse,
	// a duplicated one is not (the rows are keyed by a different
	// session id and never merge).
	ownershipUnresolved
)

// resolveOwnership decides who owns the conversation logged in a Crew
// chat transcript, per the table above.
//
// WHY THE MAP AND NOT THE TRANSCRIPT: the transcript carries no reference
// to its driven kiro-cli session; session_map.json is the only link. The
// read is race-free in practice — the Gateway writes the map entry when
// it creates the agent session, BEFORE the first turn is appended to the
// transcript (grounded on the step-in host: session_map.json mtime
// 15:11:17, sessions/dashboard_chat-2-….jsonl mtime 15:12:36) — so a
// transcript that exists always has its map entry already written.
func resolveOwnership(sessionFile string) (own ownership, twinSID string) {
	root := crewRootOf(sessionFile)
	if root == "" {
		return ownershipUnresolved, ""
	}
	key := mapKeyForFile(sessionFile)
	if key == "" {
		return ownershipUnresolved, ""
	}
	body, err := os.ReadFile(filepath.Join(root, sessionMapFile)) //nolint:gosec // root derives from a validated watch-root path
	if err != nil {
		return ownershipUnresolved, ""
	}
	var m map[string]sessionMapEntry
	if err := json.Unmarshal(body, &m); err != nil {
		return ownershipUnresolved, ""
	}
	entry, ok := m[key]
	if !ok {
		return ownedBySelf, ""
	}
	// An entry that EXISTS with a blank `sid` is the Gateway having
	// reserved the slot before minting the agent session. That is
	// UNRESOLVED, not "no twin": treating it as no-twin emits the whole
	// conversation now, and kiro-cli emits the same conversation again
	// the moment the sid lands — the unrecoverable direction this
	// package's ownership table exists to avoid.
	if sid := strings.TrimSpace(entry.SID); sid != "" {
		return ownedByKiroCLI, sid
	}
	return ownershipUnresolved, ""
}
