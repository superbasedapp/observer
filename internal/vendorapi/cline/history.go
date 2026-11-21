package cline

import (
	"encoding/json"
	"math"
	"strconv"
	"time"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceSessionHistory is the catalog id of one cloud session's archived
// conversation.
const SurfaceSessionHistory vs.SurfaceID = "cline.cloud.session_history"

// History vocabulary.
const (
	SessionHistoryContract = "cline.cloud.session_history/v1 @cline/core 0.2.0 CloudSessionApi.history (undocumented)"

	// MessageNamespace is the namespace of the metadata-only tool-call rows
	// of a session's messages.
	MessageNamespace = "cline.cloud_message"
	// UsageNamespace and UsageJoinKind key a session's usage row: one row
	// per session, re-landed with a higher revision as the session runs.
	UsageNamespace = "cline.cloud_session"
	UsageJoinKind  = "session_id"
	// ChargedUnitUSD is the unit of the summed message metrics.cost (the
	// client's own figure; Cline credits are US dollars).
	ChargedUnitUSD = "usd"
	// IdentityCaller names the token owner: the archive belongs to the
	// caller's own session.
	IdentityCaller      = "caller"
	IdentityCallerValue = "self"
	// TokensFlag is set on a usage row when at least one message reported a
	// token count; a row without it carries a cost only.
	TokensFlag = "counts_reported"
	// InputBasisFlag records that InputTokens is the sum of the messages'
	// metrics.inputTokens as reported. The figure is GROSS: it includes
	// the cache reads (live check 2026-11-02, the per-message cost fits
	// sensible prices only that way), so the connector nets it against
	// CacheReadTokens (internal/cloudagents clineHistoryFigures). Whether
	// it includes cache writes is not observed.
	InputBasisFlag  = "input_basis"
	InputBasisValue = "input_tokens_as_reported"
	// ModelCountFlag is the number of distinct models the reporting
	// messages named (the row carries the latest one).
	ModelCountFlag = "model_count"
	// historyVersion is the only archive version the client accepts.
	historyVersion = "1"
	// maxMessageIDLen bounds a message id before it becomes an item id.
	maxMessageIDLen = 128
)

// messageRoles maps a message role to the content role of a message that
// carries human or assistant text. A role outside the table is drift.
var messageRoles = map[string]string{"user": "prompt", "assistant": "response"}

// textBlocks are the content block types that make a message a prompt or a
// response (a user message holding only tool_result blocks is the agent's
// tool output, not a prompt).
var textBlocks = map[string]bool{"text": true, "image": true, "file": true, "media": true}

// SessionHistory returns the driver of cline.cloud.session_history.
//
// Contract (observed in the vendor client, undocumented; @cline/core 0.2.0
// CloudSessionApi.history, "Raw archived snapshot; null distinguishes a
// missing archive from []"): GET /api/v1/session/{id}/history, Bearer
// account token. The body is {version: 1, messages: [MessageWithMetadata]}
// and is NOT wrapped in data; the client answers HTTP 404 with "no archive",
// which the node egress turns into the JSON literal null, landing nothing.
// A message (@cline/shared 0.2.0 dist/llms/messages.d.ts) carries role,
// content (a string or blocks), id?, modelInfo {id, provider}?, metrics
// {inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens, cost}? and
// ts? (epoch milliseconds). A timed user message with text is one prompt
// content item, a timed assistant message with text one response item; the
// text itself is never decoded (Text stays empty). Each tool_use block of a
// timed assistant message is one metadata row of action tool_call naming
// the tool; its input and every tool_result body are never decoded. The
// metrics of every message are summed into ONE usage row keyed by the
// session, and only when some message reported a figure: the token counts
// as reported, and the cost in US dollars (Cline credits are dollars). The
// live check of 2026-11-02 also saw updated_at and sessionId on the
// envelope and thinking blocks on assistant messages; neither is decoded.
func SessionHistory() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceSessionHistory,
		Build:           buildSessionHistory,
		ParseResponse:   parseSessionHistory,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassContent, vs.ClassAudit, vs.ClassUsage, vs.ClassCost},
		ClosedDTO:       true,
		ContractVersion: SessionHistoryContract,
		Tool:            Tool,
		KnownPaths:      historyKnownPaths,
	}
}

func buildSessionHistory(p vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	id := p[ParamSessionID]
	if !ValidID(id) || cursor != "" {
		return vendorapi.Request{}, drift(SurfaceSessionHistory, "a history read needs one session id and no cursor")
	}
	return vendorapi.Request{Method: "GET", Path: "/api/v1/session/" + id + "/history"}, nil
}

// historyDoc is the archive envelope.
type historyDoc struct {
	Version  *num       `json:"version"`
	Messages *[]message `json:"messages"`
}

// message is the closed DTO of one MessageWithMetadata: the text, the tool
// input and output, the thinking and the agent and metadata members are
// absent on purpose.
type message struct {
	Role      *string         `json:"role"`
	Content   json.RawMessage `json:"content"`
	ID        *string         `json:"id"`
	ModelInfo *struct {
		ID *string `json:"id"`
	} `json:"modelInfo"`
	Metrics *struct {
		InputTokens      *num `json:"inputTokens"`
		OutputTokens     *num `json:"outputTokens"`
		CacheReadTokens  *num `json:"cacheReadTokens"`
		CacheWriteTokens *num `json:"cacheWriteTokens"`
		Cost             *num `json:"cost"`
	} `json:"metrics"`
	Ts *num `json:"ts"`
}

// block is the closed DTO of one content block: its type, and for a
// tool_use block its id and tool name.
type block struct {
	Type *string `json:"type"`
	ID   *string `json:"id"`
	Name *string `json:"name"`
}

// sessionUsage accumulates the metrics of a session's messages.
type sessionUsage struct {
	tokens, cost           bool
	in, out, cRead, cWrite int64
	costMicros             int64
	at                     time.Time
	model                  string
	models                 map[string]bool
}

func parseSessionHistory(r vendorapi.Response) (vendorapi.Page, error) {
	if err := checkStatus(SurfaceSessionHistory, r); err != nil {
		return vendorapi.Page{}, err
	}
	if isNull(r.Body) {
		return vendorapi.Page{}, nil
	}
	sessionID := r.Params[ParamSessionID]
	if !ValidID(sessionID) {
		return vendorapi.Page{}, drift(SurfaceSessionHistory, "the response names no requested session")
	}
	var doc historyDoc
	if err := decode(r.Body, &doc); err != nil {
		return vendorapi.Page{}, drift(SurfaceSessionHistory, "body does not decode as the archive")
	}
	if doc.Version == nil || string(*doc.Version) != historyVersion {
		return vendorapi.Page{}, drift(SurfaceSessionHistory, "version is not the archive version 1")
	}
	if doc.Messages == nil {
		return vendorapi.Page{}, drift(SurfaceSessionHistory, "required field messages is missing")
	}
	msgs := *doc.Messages
	out := vendorapi.Page{SourceRecords: len(msgs)}
	u := sessionUsage{models: map[string]bool{}}
	seen := map[string]bool{}
	var newest time.Time
	for i, m := range msgs {
		role, ok := messageRoles[str(m.Role)]
		if !ok {
			return vendorapi.Page{}, drift(SurfaceSessionHistory, "messages[%d].role is not user or assistant", i)
		}
		itemID := "m" + strconv.Itoa(i)
		if m.ID != nil {
			if !plainID(*m.ID) {
				return vendorapi.Page{}, drift(SurfaceSessionHistory, "messages[%d].id is not a plain id", i)
			}
			itemID = *m.ID
		}
		if seen[itemID] {
			return vendorapi.Page{}, drift(SurfaceSessionHistory, "messages[%d] repeats a message id", i)
		}
		seen[itemID] = true
		at, ok := msTime(m.Ts)
		if !ok {
			return vendorapi.Page{}, drift(SurfaceSessionHistory, "messages[%d].ts is not epoch milliseconds", i)
		}
		if at.After(newest) {
			newest = at
		}
		blocks, text, err := contentBlocks(m.Content)
		if err != nil {
			return vendorapi.Page{}, drift(SurfaceSessionHistory, "messages[%d].content is not text or blocks", i)
		}
		if !at.IsZero() {
			if text {
				out.Content = append(out.Content, vendorapi.ContentItem{
					ItemID: itemID, At: at, SessionRef: sessionID, Role: role,
				})
			}
			for j, b := range blocks {
				if str(b.Type) != "tool_use" || role != "response" {
					continue
				}
				name := str(b.Name)
				if name == "" || len(name) > vendorapi.MaxTargetLen {
					return vendorapi.Page{}, drift(SurfaceSessionHistory, "messages[%d].content[%d] is a tool call with no usable name", i, j)
				}
				callID := "b" + strconv.Itoa(j)
				if b.ID != nil && plainID(*b.ID) {
					callID = *b.ID
				}
				out.Audit = append(out.Audit, vendorapi.AuditEvent{
					Namespace: MessageNamespace, EventID: itemID + "/" + callID, At: at, ActorIsAgent: true,
					AgentSessionID: sessionID, Action: "tool_call", Target: name,
					Detail: map[string]string{"message_id": itemID},
				})
			}
		}
		if err := u.add(m, at); err != nil {
			return vendorapi.Page{}, drift(SurfaceSessionHistory, "messages[%d].metrics: %v", i, err)
		}
	}
	if len(out.Content) > vendorapi.MaxContentItems {
		// Keep the newest items: earlier ones landed on earlier passes
		// (re-reads are deduplicated by item id).
		out.Content = out.Content[len(out.Content)-vendorapi.MaxContentItems:]
	}
	if row, ok := u.row(sessionID, newest); ok {
		out.Usage = append(out.Usage, row)
	}
	return out, nil
}

// add folds one message's metrics in. A message that reports no figure
// changes nothing; an untimed one still counts (the row is dated by the
// newest timed message).
func (u *sessionUsage) add(m message, at time.Time) error {
	mt := m.Metrics
	if mt == nil {
		return nil
	}
	reported := false
	for _, f := range []struct {
		n   *num
		dst *int64
	}{{mt.InputTokens, &u.in}, {mt.OutputTokens, &u.out}, {mt.CacheReadTokens, &u.cRead}, {mt.CacheWriteTokens, &u.cWrite}} {
		if f.n == nil {
			continue
		}
		v, ok := count(f.n)
		if !ok {
			return errNotCount
		}
		*f.dst += v
		u.tokens, reported = true, true
	}
	if mt.Cost != nil {
		micros, ok := usdMicros(*mt.Cost)
		if !ok {
			return errNotAmount
		}
		u.costMicros += micros
		u.cost, reported = true, true
	}
	if !reported {
		return nil
	}
	if !at.IsZero() && !at.Before(u.at) {
		u.at = at
		if m.ModelInfo != nil && str(m.ModelInfo.ID) != "" && len(*m.ModelInfo.ID) <= vendorapi.MaxIDLen {
			u.model = *m.ModelInfo.ID
		}
	}
	if m.ModelInfo != nil && str(m.ModelInfo.ID) != "" {
		u.models[*m.ModelInfo.ID] = true
	}
	return nil
}

// row returns the session's usage row, or false when no message reported a
// figure (absent, never zero) or no message carries a time to date it.
func (u *sessionUsage) row(sessionID string, newest time.Time) (vendorapi.UsageRow, bool) {
	if !u.tokens && !u.cost {
		return vendorapi.UsageRow{}, false
	}
	at := u.at
	if at.IsZero() {
		at = newest
	}
	if at.IsZero() {
		return vendorapi.UsageRow{}, false
	}
	row := vendorapi.UsageRow{
		JoinKind: UsageJoinKind, JoinNamespace: UsageNamespace, JoinValue: sessionID, SessionRef: sessionID,
		At: at, Model: u.model, Revision: at.Unix(), IdentityKind: IdentityCaller, Identity: IdentityCallerValue,
		Flags: map[string]string{ModelCountFlag: strconv.Itoa(len(u.models))},
	}
	if u.tokens {
		row.InputTokens, row.OutputTokens, row.CacheReadTokens, row.CacheWriteTokens = u.in, u.out, u.cRead, u.cWrite
		row.Flags[TokensFlag] = "true"
		row.Flags[InputBasisFlag] = InputBasisValue
	}
	if u.cost {
		row.ChargedUnit, row.ChargedMicros = ChargedUnitUSD, u.costMicros
	}
	return row, true
}

type parseError string

func (e parseError) Error() string { return string(e) }

const (
	errNotCount  parseError = "a token count is not a whole non-negative number"
	errNotAmount parseError = "cost is not a non-negative amount"
)

// usdMicros reads a JSON number of dollars (JavaScript may write a small
// cost in exponent form, 1e-7) as rounded micro-dollars.
func usdMicros(n num) (int64, bool) {
	if v, ok := vendorapi.DecimalMicros(string(n), 0); ok {
		return v, v >= 0
	}
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1e9 {
		return 0, false
	}
	return int64(math.Round(f * 1e6)), true
}

// msTime reads an optional epoch-milliseconds timestamp; absent or 0 is the
// zero time (an untimed message), anything else must be a whole positive
// number.
func msTime(n *num) (time.Time, bool) {
	if n == nil {
		return time.Time{}, true
	}
	v, err := strconv.ParseInt(string(*n), 10, 64)
	if err != nil || v < 0 {
		return time.Time{}, false
	}
	if v == 0 {
		return time.Time{}, true
	}
	return time.UnixMilli(v).UTC(), true
}

// contentBlocks reads a message's content: a string is one text part, an
// array is blocks; text reports whether the message carries any text part.
func contentBlocks(raw json.RawMessage) ([]block, bool, error) {
	if len(raw) == 0 || isNull(raw) {
		return nil, false, errNotContent
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, false, err
		}
		return nil, s != "", nil
	}
	var blocks []block
	if err := decode(raw, &blocks); err != nil {
		return nil, false, err
	}
	text := false
	for _, b := range blocks {
		if str(b.Type) == "" {
			return nil, false, errNotContent
		}
		text = text || textBlocks[*b.Type]
	}
	return blocks, text, nil
}

const errNotContent parseError = "content is not text or blocks"

// plainID reports whether a vendor message or tool-call id is a bounded
// printable token (it becomes part of an item id, never a path).
func plainID(s string) bool {
	if s == "" || len(s) > maxMessageIDLen {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) || r == '/' {
			return false
		}
	}
	return true
}

// historyKnownPaths are the response paths of the corpus field ledger of
// the archived history.
var historyKnownPaths = []string{
	"messages", "messages[]", "messages[].content", "messages[].content[]", "messages[].content[].content",
	"messages[].content[].id",
	"messages[].content[].input", "messages[].content[].is_error", "messages[].content[].name",
	"messages[].content[].text", "messages[].content[].tool_use_id", "messages[].content[].type",
	"messages[].id", "messages[].metrics", "messages[].metrics.cacheReadTokens",
	"messages[].metrics.cacheWriteTokens", "messages[].metrics.cost", "messages[].metrics.inputTokens",
	"messages[].metrics.outputTokens", "messages[].modelInfo", "messages[].modelInfo.id",
	"messages[].modelInfo.provider", "messages[].role", "messages[].ts", "version",
	// Seen live 2026-11-02, not in the type; never decoded.
	"messages[].content[].thinking", "sessionId", "updated_at",
}
