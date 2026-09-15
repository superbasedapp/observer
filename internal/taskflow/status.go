package taskflow

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// statusAliases maps every vendor status spelling seen in §R2.2's
// decoder table onto the normalized vocabulary. Hyphenated (copilot),
// underscored (everyone else), and dialect-specific (copilot-cli's
// "done") spellings all land here. An entry absent from this table
// normalizes to "" (unknown) — never guessed.
var statusAliases = map[string]string{
	"pending":     StatusPending,
	"not-started": StatusPending,
	"not_started": StatusPending,

	"in_progress":     StatusInProgress,
	"in-progress":     StatusInProgress,
	"inprogress":      StatusInProgress,
	"set_in_progress": StatusInProgress, // poolside verb

	"completed": StatusCompleted,
	"complete":  StatusCompleted, // poolside verb; kiro-cli command
	"done":      StatusCompleted, // copilot-cli dialect

	"cancelled": StatusCancelled,
	"canceled":  StatusCancelled,

	"blocked": StatusBlocked,

	"deleted": StatusDeleted,
}

// NormalizeStatus lowercases and trims a vendor status string and maps
// it onto the shared vocabulary. Returns "" for anything not in the
// table — an unrecognized dialect value is surfaced as "unknown", never
// coerced onto a guess.
func NormalizeStatus(raw string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	return statusAliases[key]
}

// ContentKey derives the deterministic content-hash identity used for
// every Snapshot item with no vendor id, and for poolside's
// content-addressed Delta items. Two calls carrying byte-identical
// (after TrimSpace) content always collide to the same key — that IS
// the v1 exact-match rule (§R2.3.4: fuzzy matching trades a countable
// loss for an unknown, silent mis-join). A short hex digest keeps the
// key compact; collisions are not a practical concern at per-session
// item-list scale.
func ContentKey(content string) string {
	trimmed := strings.TrimSpace(content)
	sum := sha256.Sum256([]byte(trimmed))
	return "c" + hex.EncodeToString(sum[:])[:16]
}

// NormalizedContentKey is ContentKey's "normalized" MatchMode sibling
// ([tasks].match_mode, FIX-4 / docs/task-tracking.md): case- and
// internal-whitespace-insensitive, so "Fix the bug" and "fix  the bug"
// collide onto the same item instead of tracking as two. Trades
// MatchMode's documented risk (an unknown, silent merge of two
// genuinely different items whose text happens to normalize the same)
// for tolerance of the cosmetic re-wording a vendor's own snapshot
// rewrite sometimes introduces between two consecutive calls.
func NormalizedContentKey(content string) string {
	fields := strings.Fields(strings.ToLower(content))
	normalized := strings.Join(fields, " ")
	sum := sha256.Sum256([]byte(normalized))
	return "n" + hex.EncodeToString(sum[:])[:16]
}

// contentKeyForMode picks ContentKey or NormalizedContentKey per
// [tasks].match_mode ("" and "exact" both mean the default). The "n"
// vs "c" prefix keeps the two modes' keys from ever colliding with
// each other if an operator flips the setting mid-session — a stale
// row under the old prefix simply shows up as a second, unmatched item
// rather than silently merging with a key computed under the new mode.
func contentKeyForMode(content, mode string) string {
	if mode == MatchModeNormalized {
		return NormalizedContentKey(content)
	}
	return ContentKey(content)
}

// applyMatchMode recomputes the Key of every content_hash item in
// place per mode, as a single seam AFTER a decoder returns rather than
// threading mode through every one of decoderTable's ~10 decode
// functions (CLAUDE.md #6, additive-not-invasive) — every content_hash
// item's Key is already ContentKey(item.Content) or a documented
// per-decoder equivalent (poolside's per-line trim, hermes' best-effort
// field), so recomputing from item.Content here is equivalent to the
// decoder having used the other mode from the start. KeyNative items
// (a real vendor id) are untouched — MatchMode only ever governs
// content-addressed identity.
func applyMatchMode(items []TaskItem, mode string) {
	if mode == "" || mode == MatchModeExact {
		return
	}
	for i := range items {
		if items[i].KeyKind == KeyContent {
			items[i].Key = contentKeyForMode(items[i].Content, mode)
		}
	}
}
