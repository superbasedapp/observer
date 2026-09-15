package store

import (
	"context"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// ContentCapture is the node's ADAPTER-SIDE message-content capture posture:
// the enterprise producer that feeds locally-parsed conversation text into
// otel_content, the table the org admin's audited message-content viewer reads
// (rollup.SessionMessages).
//
// Why this exists: otel_content had exactly one producer — the native-OTel
// receiver (cmd/observer/otlp_ingest.go::ingestOTelContent) — which only fires
// for a Claude Code install the admin pointed at the embedded OTLP listener.
// Every other tool (opencode, codex, cursor, …) parsed its message text in an
// adapter, handed it to Ingest on models.ToolEvent, and the text was stored on
// `actions` only. The admin's Messages panel was therefore empty for every
// tool. This is the missing PRODUCER; the wire (PushEnvelope.OTelContent) and
// the viewer already existed and are unchanged — the viewer remains a READ of
// data the node already shipped under its own opt-in.
//
// ShipsRawContent is the gate, evaluated per Ingest. It must be the node's own
// org-push content posture (store.ShareOptions.ShipsRawContent() —
// full_content || admin_managed) ANDed with the node's content-capture level
// ([ingest.otel].content_capture, shared with the native rail so one knob
// governs both producers). A nil func, or one returning false, means the
// producer writes NOTHING: a metadata-only node's local DB and org wire stay
// byte-identical to the pre-producer build.
//
// This is a NODE-SIDE posture only. There is no server-side force override —
// same invariant as every other content tier (CLAUDE.md "Teams / org-server
// invariants").
type ContentCapture struct {
	// ShipsRawContent reports whether this node captures message content.
	// nil == disabled.
	ShipsRawContent func() bool
	// MaxBytes bounds ONE stored row's content after scrubbing. <= 0 falls
	// back to defaultMessageContentMaxBytes.
	MaxBytes int
}

// defaultMessageContentMaxBytes mirrors config.DefaultIngestOTelContentMaxBytes
// (32 KiB) so an unwired MaxBytes behaves like the native rail's default. It is
// duplicated rather than imported because internal/store must not depend on
// internal/config.
const defaultMessageContentMaxBytes = 32 << 10

// otel_content `kind` vocabulary.
//
// The first three MIRROR the native rail (internal/adapter/ccotel: KindPrompt /
// KindToolInput / KindToolOutput) so the org viewer renders adapter-captured
// rows exactly like native-OTel ones.
//
// kindAssistant is an EXTENSION: Claude Code's OTel stream carries no
// assistant-text event, so the native vocabulary has no slot for the model's
// reply — and a transcript without replies is half a transcript, which the
// enterprise ruling ("everything from the dev node should be available for the
// admin dashboard") does not allow. The org viewer degrades gracefully on an
// unknown kind (web2/src/pages/Sessions.tsx: `kindLabel[m.kind] ?? m.kind`
// renders the raw string as the pill label), so no dashboard change is
// required; adding a friendly label there is a one-line follow-up.
const (
	kindPrompt     = "prompt"
	kindAssistant  = "assistant"
	kindToolInput  = "tool_input"
	kindToolOutput = "tool_output"
)

// messageContentSource is the provenance stamped on adapter-captured rows,
// distinguishing them from the native rail's ccotel.SourceTag ("cc_otel").
// Node-local: otel_content.source is not selected by the org-push seam.
const messageContentSource = "adapter"

// contentPart is one (kind, text) pair extractable from a ToolEvent. pick
// returns the FIRST non-empty candidate field, so an adapter that carries the
// body in a different column still feeds the same kind.
type contentPart struct {
	kind string
	pick func(models.ToolEvent) string
}

func rawInput(e models.ToolEvent) string   { return e.RawToolInput }
func toolOutput(e models.ToolEvent) string { return e.ToolOutput }

// promptText prefers the adapter-scrubbed full body and falls back to the
// preview columns for adapters that only carry a preview.
func promptText(e models.ToolEvent) string {
	return firstNonBlank(e.RawToolInput, e.Target, e.PrecedingReasoning)
}

// assistantText prefers the full reply body; adapters that only set the
// preview columns still yield their preview rather than nothing.
func assistantText(e models.ToolEvent) string {
	return firstNonBlank(e.ToolOutput, e.RawToolInput, e.Target)
}

// messageContentRules is the CAPABILITY table (CLAUDE.md #3 / #5): the rows are
// keyed by NORMALIZED action type — never by tool name — so every adapter that
// resolves its events into the shared vocabulary feeds content, and a new
// adapter needs no change here. An action type absent from the table falls
// through to defaultContentParts (a tool call: input + output).
var messageContentRules = map[string][]contentPart{
	models.ActionUserPrompt:       {{kindPrompt, promptText}},
	models.ActionAssistantMessage: {{kindAssistant, assistantText}},
	// A completion/answer row is the model speaking, not a tool call: some
	// adapters still land the final reply text here.
	models.ActionTaskComplete: {{kindAssistant, assistantText}},
	models.ActionAskUser:      {{kindAssistant, assistantText}},
}

// defaultContentParts covers every tool-call-shaped action.
var defaultContentParts = []contentPart{
	{kindToolInput, rawInput},
	{kindToolOutput, toolOutput},
}

// contentScrubber is the producer's secret-redaction pass. A Scrubber is
// immutable after construction (compiled patterns only), so one process-wide
// instance is safe for concurrent use and avoids recompiling the pattern set on
// every Ingest. Built lazily so a node that never captures content never
// compiles it. Default patterns, matching every other scrub.New() call site in
// cmd/observer — the adapters have already applied the config-aware pass, this
// is defence in depth.
var contentScrubber = sync.OnceValue(scrub.New)

// SetContentCapture installs the adapter-side message-content producer's
// posture. Mirrors SetCacheEngine/SetGuard: the cmd layer, which owns config,
// wires it once at Store construction; a Store that never gets one (hooks,
// tests, `observer scan` on a non-enterprise node) produces no content rows.
func (s *Store) SetContentCapture(cc ContentCapture) {
	s.contentCapture = cc
}

// capturesMessageContent evaluates the producer gate. This is THE check the
// enterprise posture turns on: with it removed a metadata-only node would start
// writing content rows it never wrote before.
func (s *Store) capturesMessageContent() bool {
	return s.contentCapture.ShipsRawContent != nil && s.contentCapture.ShipsRawContent()
}

// captureMessageContent is the adapter-side feeder for otel_content. It is the
// ONLY caller of InsertOTelContent on the ingest path; InsertOTelContent
// remains the table's sole writer (CLAUDE.md #4 — one owner, two feed paths:
// the native OTLP receiver and this).
//
// Contract details it must respect (see store.InsertOTelContent's doc comment):
//   - the body is scrubbed BEFORE it is bounded (redaction only shrinks text,
//     so scrub-then-cut can never re-expose truncated secret bytes), and
//   - ContentHash covers the FULL scrubbed body, never the truncated one —
//     hashing post-truncation would collide two long bodies sharing a prefix
//     and silently drop the second on ON CONFLICT DO NOTHING.
//
// Idempotency: (content_hash, kind, request_id, tool_use_id) is the UNIQUE key,
// and tool_use_id carries a SESSION-SCOPED event key (see eventContentKey), so
// re-parsing a transcript re-derives the identical key and inserts nothing.
// The scoping is load-bearing, not decoration: the UNIQUE key has no session
// column, so a bare per-event id (or an empty one) would make the same message
// text in two sessions collide and ON CONFLICT DO NOTHING would silently drop
// the second — real data loss, and not every adapter mints globally-unique
// event ids (some are per-file counters).
//
// Best-effort by design: it runs after the user-visible ingest work and its
// error is returned for the caller to log, never to fail the batch.
func (s *Store) captureMessageContent(ctx context.Context, events []models.ToolEvent) (int, error) {
	if !s.capturesMessageContent() || len(events) == 0 {
		return 0, nil
	}
	maxBytes := s.contentCapture.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMessageContentMaxBytes
	}
	rows := make([]models.OTelContent, 0, len(events))
	for _, e := range events {
		if e.SessionID == "" || e.ProjectRoot == "" {
			continue // skipped by Ingest too; never conjure a row for one
		}
		parts, ok := messageContentRules[e.ActionType]
		if !ok {
			parts = defaultContentParts
		}
		for _, p := range parts {
			body := strings.TrimSpace(p.pick(e))
			if body == "" {
				continue
			}
			// Defence in depth: adapters scrub these columns already, but the
			// producer must not depend on every one of ~36 adapters having
			// done so on every field it reads. Re-scrubbing redacted text is a
			// no-op.
			scrubbed := contentScrubber().String(body)
			rows = append(rows, models.OTelContent{
				RequestID:   e.MessageID, // turn join key, like the native rail's request_id
				SessionID:   e.SessionID,
				ToolUseID:   eventContentKey(e), // session-scoped event identity → idempotent re-parse
				Kind:        p.kind,
				Content:     scrub.TruncateN(scrubbed, maxBytes),
				ContentHash: HashOTelContent(scrubbed),
				Timestamp:   e.Timestamp,
				Source:      messageContentSource,
			})
		}
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return s.InsertOTelContent(ctx, rows)
}

// eventContentKey is the per-event component of the otel_content UNIQUE key.
// It is the event's own id SCOPED BY SESSION, because that key has no session
// column — see the idempotency note on captureMessageContent. An adapter that
// leaves SourceEventID empty still gets a session-distinct key (never a bare
// empty string shared by every such row), it just dedups on content alone
// within that session, which is the correct degradation.
func eventContentKey(e models.ToolEvent) string {
	return e.SessionID + "/" + e.SourceEventID
}

// firstNonBlank returns the first argument that is not empty after trimming.
func firstNonBlank(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
