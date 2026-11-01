package statusline

import (
	"fmt"
	"strconv"
)

// DaemonTile is the small subset of the lean `GET /api/statusline`
// daemon response (plan §2.2) that this package needs to render the
// "today" segment. Every field is a pointer so an unreachable, timed-out,
// or never-started daemon (plan §2.3's fail-open ladder) is representable
// as a fully zero-value DaemonTile — every segment sourced from it simply
// omits itself, never renders a fabricated "$0.00" or "0%".
type DaemonTile struct {
	// TodayUSD is today's total observed spend across every captured
	// tool, priced through the cost engine (not a raw-column SUM — see
	// the plan's WP0 status block correction: the raw
	// estimated_cost_usd column is unpopulated for major sources).
	TodayUSD *float64
	// SessionUSD is the daemon's own view of the current session's
	// spend, when the caller supplied a session_id and the daemon found
	// a match. The "session" segment prefers Input.Cost.TotalCostUSD
	// (Claude Code's own figure, no lookup needed) when present, and
	// only falls back to this field otherwise.
	SessionUSD *float64
	// CacheReadShare is the fraction [0,1] of today's input-side tokens
	// served from prefix cache. Not rendered by any default segment
	// today; carried for a future segment kind without requiring a
	// DaemonTile shape change (CLAUDE.md #6, additive).
	CacheReadShare *float64
	// Budget is the node's org budget warning, already rendered short by
	// the caller from the daemon's budget-status file (e.g. "budget 96% of
	// $0.75/day"). nil = no org window at a warn rung, and the segment is
	// omitted (never a "0%").
	Budget *string
	// CostDisplay is the node's developer cost display, resolved by the
	// daemon from the org's signed display policy: CostDisplayTokens renders
	// the session/today segments as token usage (TodayTokens /
	// SessionTokens) and never a dollar figure, not even Claude Code's own
	// stdin cost. Anything else (including "", an older daemon) is dollars.
	CostDisplay string
	// TodayTokens / SessionTokens are the token usage behind TodayUSD /
	// SessionUSD (input + output + cache read + cache creation). nil =
	// unknown, and the segment is omitted in token mode.
	TodayTokens   *int64
	SessionTokens *int64
	// Grants is the org access grants in force on this node, already
	// rendered short by the caller (e.g. "1 exception, 3h left"). nil = none,
	// and the segment is omitted (request-grants design G6).
	Grants *string
	// MessagesUnread is how many messages from the org's admins wait unread
	// on this node (already filtered by the caller for the developer's
	// [messages] statusline and alerts_only choices). 0 = nothing unread,
	// and the segment is omitted. Only the count is ever rendered, never
	// message text (T-854).
	MessagesUnread int
	// Security is the current project's code security state, already
	// rendered short by the caller from the signed posture file (e.g.
	// "sec 2!" for two blocking findings, "sec *" for unscanned changes;
	// lane sec-c3). nil = the segment is off, the module is not active or
	// the project has no posture, and the segment is omitted.
	Security *string
}

// CostDisplayTokens is the token-usage developer cost display
// (orgcontract.DisplayCostTokens, restated: this package is pure).
const CostDisplayTokens = "tokens"

// tokenMode reports whether the tile asks for token usage instead of dollars.
func (t DaemonTile) tokenMode() bool { return t.CostDisplay == CostDisplayTokens }

// The segment-kind vocabulary accepted by RenderOptions.Segments and
// the [statusline].segments config key (plan §1.2, §6.3). Unknown
// strings in a Segments list are skipped silently — a typo in a config
// file degrades the line, it never panics or errors the command (plan
// §2.3's "never regress" fail-open discipline extended to config
// parsing).
const (
	// SegmentWordmark renders Wordmark. Unlike every other segment kind,
	// its datum (the constant itself) is never absent, AND (as of the F12
	// fix) Render forces it present exactly once at the front of every
	// composition regardless of whether, where, or how many times the
	// caller's Segments list mentions it — there is no way for a caller
	// to produce a wordmark-less or wordmark-reordered line. See
	// Render's doc comment / normalizeSegments for the enforcement.
	SegmentWordmark = "wordmark"
	// SegmentSession renders the current session's observed spend,
	// sourced from Input.Cost.TotalCostUSD (Claude Code's own figure)
	// when present, DaemonTile.SessionUSD otherwise.
	SegmentSession = "session"
	// SegmentToday renders DaemonTile.TodayUSD.
	SegmentToday = "today"
	// SegmentModel renders the current model's display name (falling
	// back to its raw id), sourced from Input.Model.
	SegmentModel = "model"
	// SegmentBudget renders DaemonTile.Budget: the node's org budget
	// warning while a warn rung is reached (2026-10-02 budget-latency arc).
	SegmentBudget = "budget"
	// SegmentGrants renders DaemonTile.Grants: the org exceptions in force
	// on this node and when the nearest one ends (request-grants G6).
	SegmentGrants = "grants"
	// SegmentMessages renders DaemonTile.MessagesUnread: how many messages
	// from the org's admins are unread (admin and developer messaging,
	// T-854). A count only, never message text.
	SegmentMessages = "messages"
	// SegmentSecurity renders DaemonTile.Security: the current project's
	// commit-gate state (security pillar plan section 6.1, lane sec-c3).
	// Not in DefaultSegments: the caller adds it when
	// [security.statusline].segment is on.
	SegmentSecurity = "security"
)

// DefaultSegments is the default ordered segment list (plan §1.2 "wordmark,
// session, today, model" / §4.1 / the WP0 status block's provisional
// decision lock for §9.2/§9.3: the full set including "today"). Render
// falls back to this list whenever RenderOptions.Segments is empty, so a
// caller need not repeat the default just to get it.
//
// SegmentBudget joined the default (2026-10-02): it renders only while an org
// budget window is at a warn rung, so a node with no org budget sees the
// exact pre-change line.
//
// SegmentGrants joined the default with the request-grants design: it renders
// only while an org exception is in force, so every other node sees the
// exact pre-change line.
//
// SegmentMessages joined the default with admin and developer messaging
// (T-854, D-688 ruling 1): it renders only while a message from the org's
// admins is unread, so every other node sees the exact pre-change line.
var DefaultSegments = []string{SegmentWordmark, SegmentSession, SegmentToday, SegmentModel, SegmentBudget, SegmentGrants, SegmentMessages}

// renderMessagesSegment renders the "messages" segment kind from the tile:
// "1 message from your admin" / "3 messages from your admins".
func renderMessagesSegment(tile DaemonTile) (string, bool) {
	switch {
	case tile.MessagesUnread <= 0:
		return "", false
	case tile.MessagesUnread == 1:
		return "1 message from your admin", true
	default:
		return strconv.Itoa(tile.MessagesUnread) + " messages from your admins", true
	}
}

// renderGrantsSegment renders the "grants" segment kind from the tile.
// renderSecuritySegment renders the "security" segment kind from the tile.
func renderSecuritySegment(tile DaemonTile) (string, bool) {
	if tile.Security == nil {
		return "", false
	}
	text := sanitizeControls(*tile.Security)
	if text == "" {
		return "", false
	}
	return text, true
}

func renderGrantsSegment(tile DaemonTile) (string, bool) {
	if tile.Grants == nil {
		return "", false
	}
	text := sanitizeControls(*tile.Grants)
	if text == "" {
		return "", false
	}
	return text, true
}

// renderBudgetSegment renders the "budget" segment kind from the tile.
func renderBudgetSegment(tile DaemonTile) (string, bool) {
	if tile.Budget == nil {
		return "", false
	}
	text := sanitizeControls(*tile.Budget)
	if text == "" {
		return "", false
	}
	return text, true
}

// maxModelWidth is the longest a model-name segment is allowed to display
// before truncation with an ellipsis — long enough for the model names
// this product actually prices (e.g. "claude-opus-4-5-20260101" at 24
// runes), short enough that one long id can't dominate a one-line status
// bar the way it's harmless to dominate a multi-row table column.
const maxModelWidth = 24

// segment is one already-rendered piece of the output line, plus whether
// it's the wordmark. joinSegments (render.go) special-cases the wordmark:
// it joins to its neighbor with a plain space instead of " · " only when
// Wordmark's own text already ends in the separator glyph (a capability
// check, not a hardcoded assumption about any one wordmark's shape).
type segment struct {
	text       string
	isWordmark bool
}

// renderSessionSegment renders the "session" segment kind: "<$X.XX>
// session". It prefers the stdin-JSON session cost (Claude Code already
// computed this figure server-side; no lookup, no honesty caveat beyond
// the product's existing list-price framing — plan §4.1) and falls back
// to the daemon's own session-scoped figure when stdin didn't supply one.
// Returns ok=false (segment omitted) when neither source has a value.
//
// In token mode (tile.CostDisplay) it renders the daemon's session token
// usage ("180k tok session") and never the stdin dollar figure; with no
// daemon figure the segment is omitted.
func renderSessionSegment(in Input, tile DaemonTile) (string, bool) {
	if tile.tokenMode() {
		if tile.SessionTokens == nil {
			return "", false
		}
		return formatTokens(*tile.SessionTokens) + " tok session", true
	}
	if in.Cost != nil && in.Cost.TotalCostUSD != nil {
		return formatUSD(*in.Cost.TotalCostUSD) + " session", true
	}
	if tile.SessionUSD != nil {
		return formatUSD(*tile.SessionUSD) + " session", true
	}
	return "", false
}

// renderTodaySegment renders the "today" segment kind: "<$X.XX> today",
// sourced from the daemon tile. Returns ok=false (segment omitted) when
// the daemon path never produced a figure (plan §2.3 cases 1/2/3/4).
func renderTodaySegment(tile DaemonTile) (string, bool) {
	if tile.tokenMode() {
		if tile.TodayTokens == nil {
			return "", false
		}
		return formatTokens(*tile.TodayTokens) + " tok today", true
	}
	if tile.TodayUSD == nil {
		return "", false
	}
	return formatUSD(*tile.TodayUSD) + " today", true
}

// renderModelSegment renders the "model" segment kind: the model's
// display name (preferred) or raw id, truncated per maxModelWidth.
// Returns ok=false (segment omitted) when no model information at all
// was supplied.
func renderModelSegment(in Input) (string, bool) {
	name := modelName(in)
	if name == "" {
		return "", false
	}
	return truncateModel(name), true
}

// modelName resolves the best available model label: DisplayName when
// present and non-empty (after sanitization — see below), ID otherwise,
// "" when neither is available.
//
// This is the ONE place externally-sourced text (Input.Model's fields,
// sourced from Claude Code's stdin JSON) enters this package's rendered
// output, so it is also the sanitization boundary (F1): both fields are
// passed through sanitizeControls before being considered, so a
// DisplayName of "safe\nERROR" resolves to the single-line "safe ERROR"
// rather than reaching the caller — and never with control characters
// still embedded — regardless of what a future caller does with the
// return value. A DisplayName that sanitizes down to the empty string
// (e.g. it was control characters only) falls through to ID exactly like
// an originally-empty DisplayName does.
func modelName(in Input) string {
	if in.Model == nil {
		return ""
	}
	if in.Model.DisplayName != nil {
		if name := sanitizeControls(*in.Model.DisplayName); name != "" {
			return name
		}
	}
	if in.Model.ID != nil {
		return sanitizeControls(*in.Model.ID)
	}
	return ""
}

// truncateModel shortens s to at most maxModelWidth runes, replacing the
// tail with a single "…" when it doesn't fit — matching the
// truncate-with-ellipsis convention internal/oneshot uses for its MODEL
// table column (a fresh, independent implementation per plan §6.2's
// "small independent copy is fine" call, not a shared import).
func truncateModel(s string) string {
	r := []rune(s)
	if len(r) <= maxModelWidth {
		return s
	}
	return string(r[:maxModelWidth-1]) + "…"
}

// formatUSD renders a dollar amount for the narrow statusline format:
// two decimal places below $100 ("$3.42" — cent-level precision where it
// matters most, the small figures a status bar shows most often), whole
// dollars at or above $100 ("$1235" — keeping the segment short once a
// session's or a day's spend grows large enough that cents stop being
// the interesting digit). Values are rounded to the nearest cent/dollar,
// never truncated (unlike internal/oneshot's token-count formatter — a
// dollar total is already a sum of rounded per-turn costs, not a place
// where truncation avoids a spurious unit-boundary crossing).
func formatUSD(v float64) string {
	abs := v
	if abs < 0 {
		abs = -abs
	}
	if abs < 100 {
		// no-bare-usd:allow (dollar view only; the token display renders the token figures)
		return "$" + strconv.FormatFloat(v, 'f', 2, 64)
	}
	return fmt.Sprintf("$%.0f", v)
}

// formatTokens renders a token count for the narrow statusline format, the
// token-mode counterpart of formatUSD: exact below 1,000 ("950"), thousands
// with one decimal below 10k ("1.2k") and whole thousands above ("180k"),
// millions with one decimal below 10M ("1.2M") and whole millions above
// ("42M"). Rounded, never negative.
func formatTokens(n int64) string {
	if n < 0 {
		n = 0
	}
	switch {
	case n < 1_000:
		return strconv.FormatInt(n, 10)
	case n < 9_950:
		return strconv.FormatFloat(float64(n)/1e3, 'f', 1, 64) + "k"
	case n < 999_500:
		return strconv.FormatFloat(float64(n)/1e3, 'f', 0, 64) + "k"
	case n < 9_950_000:
		return strconv.FormatFloat(float64(n)/1e6, 'f', 1, 64) + "M"
	default:
		return strconv.FormatFloat(float64(n)/1e6, 'f', 0, 64) + "M"
	}
}
