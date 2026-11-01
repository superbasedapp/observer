package opencode

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/transcriptutil"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// OpenCode 2.x storage (the v2 generation of storeSchema).
//
// A session is one `session_v2` row (directory, version, parent_id, and
// running token totals). Its conversation is the ordered
// `session_message` table: one row per message, `type` names the kind
// ("user", "assistant", "compaction", "synthetic", "system", "shell",
// "skill", "idle", "agent-switched", "model-switched",
// "location-switched") and `data` is the message JSON minus its id and
// type. An assistant message is ONE model step: its `content` array
// holds the step's reasoning / text / tool items in order, and its
// `tokens` + `cost` are that step's usage. A tool item carries both the
// call and its settled result (`state.status` completed / error).
// Grounded 2026-10-20 on the live database a 2.0 preview CLI wrote in a
// scratch home (see storeSchema), and on packages/schema/src/
// session-message.ts at tag v2.1.1. Tool names follow the 2.x set
// (shell, read, write, edit, patch, glob, grep, subagent, todo, skill,
// question, webfetch, websearch); 2.x tool inputs name the file `path`,
// not 1.x's `filePath`.
//
// Upgraded databases keep the 1.x tables beside the 2.x copy, and the
// 2.x copy reuses each 1.x message id. When both generations are present
// the 1.x reader owns every message whose id is still in `message`, so a
// migrated message is never ingested twice; the 2.x reader takes only
// the messages written after the upgrade.

// v2MessageRow is one session_message row joined to its session.
type v2MessageRow struct {
	ID         string
	SessionID  string
	Type       string
	Directory  string
	TimeCreate int64
	TimeUpdate int64
	Data       string
}

// v2Message is the decoded `data` of a session_message row. Numbers are
// decoded as float64 because the upstream schema declares them Finite,
// not integer.
type v2Message struct {
	Time struct {
		Created   float64 `json:"created"`
		Completed float64 `json:"completed"`
	} `json:"time"`
	Text  string `json:"text"`
	Agent string `json:"agent"`
	Model struct {
		ID         string `json:"id"`
		ProviderID string `json:"providerID"`
		Variant    string `json:"variant"`
	} `json:"model"`
	Content []v2Content `json:"content"`
	Finish  string      `json:"finish"`
	Status  string      `json:"status"`
	Cost    float64     `json:"cost"`
	Tokens  *v2Tokens   `json:"tokens"`
}

// v2Tokens is OpenCode 2.x TokenUsage.Info. `input` is already NET of
// the cache read (verified on the live database: session_v2.tokens_input
// is the plain sum of every step's input while the cache read is carried
// separately), the same convention as the 1.x message tokens.
type v2Tokens struct {
	Input     float64 `json:"input"`
	Output    float64 `json:"output"`
	Reasoning float64 `json:"reasoning"`
	Cache     struct {
		Read  float64 `json:"read"`
		Write float64 `json:"write"`
	} `json:"cache"`
}

func (t *v2Tokens) empty() bool {
	return t == nil || (t.Input == 0 && t.Output == 0 && t.Reasoning == 0 && t.Cache.Read == 0 && t.Cache.Write == 0)
}

// v2Content is one item of an assistant message's content array.
type v2Content struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	ID    string `json:"id"`
	Name  string `json:"name"`
	State struct {
		Status  string          `json:"status"`
		Input   json.RawMessage `json:"input"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Metadata struct {
			Exit *float64 `json:"exit"`
		} `json:"metadata"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	} `json:"state"`
	Time struct {
		Created   float64 `json:"created"`
		Ran       float64 `json:"ran"`
		Completed float64 `json:"completed"`
	} `json:"time"`
}

// v2ToolInput is the subset of 2.x tool inputs the mapping reads.
type v2ToolInput struct {
	Path        string `json:"path"`
	Description string `json:"description"`
}

// v2MessagesQuery / v2MessagesQueryBesideV1 select the session_message
// rows written since the cursor. The second form is used when the 1.x
// tables are present too and leaves out every message the 1.x reader
// owns (see the package comment above).
const (
	v2MessagesQuery = `
		SELECT sm.id, sm.session_id, sm.type, COALESCE(s.directory, ''), sm.time_created, sm.time_updated, sm.data
		  FROM session_message sm
		  LEFT JOIN session_v2 s ON s.id = sm.session_id
		 WHERE sm.time_updated > ?
		   AND sm.type IN ('user', 'assistant', 'compaction')
		 ORDER BY sm.time_updated ASC, sm.session_id ASC, sm.seq ASC`
	v2MessagesQueryBesideV1 = `
		SELECT sm.id, sm.session_id, sm.type, COALESCE(s.directory, ''), sm.time_created, sm.time_updated, sm.data
		  FROM session_message sm
		  LEFT JOIN session_v2 s ON s.id = sm.session_id
		 WHERE sm.time_updated > ?
		   AND sm.type IN ('user', 'assistant', 'compaction')
		   AND NOT EXISTS (SELECT 1 FROM message m WHERE m.id = sm.id)
		 ORDER BY sm.time_updated ASC, sm.session_id ASC, sm.seq ASC`
)

// parseV2 runs the OpenCode 2.x reader and appends its rows to res.
// besideV1 is true when the 1.x tables are present in the same file.
func (a *Adapter) parseV2(ctx context.Context, db *sql.DB, dbPath string, fromOffset int64, besideV1 bool, rootCache map[string]projectGitInfo, res *adapter.ParseResult) error {
	query := v2MessagesQuery
	if besideV1 {
		query = v2MessagesQueryBesideV1
	}
	rows, err := db.QueryContext(ctx, query, fromOffset)
	if err != nil {
		return fmt.Errorf("opencode.ParseSessionFile: v2 messages: %w", err)
	}
	var msgs []v2MessageRow
	for rows.Next() {
		var r v2MessageRow
		if err := rows.Scan(&r.ID, &r.SessionID, &r.Type, &r.Directory, &r.TimeCreate, &r.TimeUpdate, &r.Data); err != nil {
			_ = rows.Close()
			return fmt.Errorf("opencode.ParseSessionFile: v2 messages: %w", err)
		}
		msgs = append(msgs, r)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("opencode.ParseSessionFile: v2 messages: %w", err)
	}
	_ = rows.Close()

	for _, r := range msgs {
		var msg v2Message
		if err := json.Unmarshal([]byte(r.Data), &msg); err != nil {
			continue
		}
		project := a.resolveProjectRoot(r.Directory, rootCache)
		remote := a.resolveProjectRemote(r.Directory, rootCache)
		base := models.ToolEvent{
			SourceFile:  dbPath,
			SessionID:   r.SessionID,
			ProjectRoot: project,
			GitRemote:   remote,
			Tool:        models.ToolOpenCode,
		}
		switch r.Type {
		case "user":
			if ev, ok := a.v2UserPrompt(base, r, msg); ok {
				res.ToolEvents = append(res.ToolEvents, ev)
			}
		case "assistant":
			res.ToolEvents = append(res.ToolEvents, a.v2AssistantEvents(base, r, msg)...)
			if ev, ok := v2TokenEvent(base, r, msg); ok {
				res.TokenEvents = append(res.TokenEvents, ev)
			}
		case "compaction":
			// The compaction request is a real model call with its own
			// usage; the summary itself is not emitted as an action.
			if msg.Status == "completed" || msg.Status == "failed" {
				if ev, ok := v2TokenEvent(base, r, msg); ok {
					res.TokenEvents = append(res.TokenEvents, ev)
				}
			}
		}
	}

	lineages, err := loadSessionV2Lineages(ctx, db)
	if err != nil {
		return fmt.Errorf("opencode.ParseSessionFile: v2 session lineages: %w", err)
	}
	res.SessionLineages = append(res.SessionLineages, lineages...)

	// §14.3 Tier-2 cache observation for the 2.x store (T-925).
	cacheObservations, err := a.loadCacheObservationsV2(ctx, db, dbPath, fromOffset, besideV1)
	if err != nil {
		return fmt.Errorf("opencode.ParseSessionFile: v2 cache_observations: %w", err)
	}
	res.CacheObservations = append(res.CacheObservations, cacheObservations...)
	return nil
}

// v2UserPrompt emits the user_prompt row for a 2.x user message.
func (a *Adapter) v2UserPrompt(base models.ToolEvent, r v2MessageRow, msg v2Message) (models.ToolEvent, bool) {
	prompt := strings.TrimSpace(msg.Text)
	if prompt == "" {
		return models.ToolEvent{}, false
	}
	when := millisToTime(int64(msg.Time.Created))
	if when.IsZero() {
		when = millisToTime(r.TimeCreate)
	}
	ev := base
	ev.SourceEventID = "message:" + r.ID
	ev.Timestamp = chooseTime(when, time.Time{}, 0)
	ev.ActionType = models.ActionUserPrompt
	ev.Target = truncate(prompt, 200)
	ev.Success = true
	ev.PrecedingReasoning = truncate(prompt, 200)
	ev.RawToolName = "chat.message"
	ev.RawToolInput = a.scrubber.String(prompt)
	ev.MessageID = "user:" + r.ID
	return ev, true
}

// v2AssistantEvents emits the rows of one 2.x assistant step: one per
// settled tool item, one per text item once the step has completed, and
// the task_complete marker when the step finished with "stop". A
// reasoning item is never a row of its own: it is threaded onto the next
// tool or text item of the same step (consumed once, last wins), the
// same semantics loadReasoningIndex gives the 1.x parts. Items still
// streaming or running are skipped; the row is rewritten when they
// settle, which moves its time_updated past the cursor again.
func (a *Adapter) v2AssistantEvents(base models.ToolEvent, r v2MessageRow, msg v2Message) []models.ToolEvent {
	completed := msg.Time.Completed > 0
	model := msg.Model.ID
	meta := v2EffortMetadata(msg.Model.Variant)
	stepTime := millisToTime(int64(msg.Time.Created))
	if stepTime.IsZero() {
		stepTime = millisToTime(r.TimeCreate)
	}

	var out []models.ToolEvent
	pending := ""
	for i, item := range msg.Content {
		switch item.Type {
		case "reasoning":
			if body := strings.TrimSpace(item.Text); body != "" {
				pending = body
			}
		case "tool":
			reasoning := pending
			pending = ""
			if ev, ok := a.v2ToolEvent(base, r, item, model, meta, reasoning); ok {
				out = append(out, ev)
			}
		case "text":
			reasoning := pending
			pending = ""
			body := strings.TrimSpace(item.Text)
			if body == "" || !completed {
				continue
			}
			preview := a.scrubber.String(truncate(body, 200))
			preReason := preview
			if reasoning != "" {
				preReason = a.scrubber.String(truncate(reasoning, 200))
			}
			ev := base
			ev.SourceEventID = "asst:" + r.ID + ":" + strconv.Itoa(i)
			ev.Timestamp = chooseTime(stepTime, time.Time{}, 0)
			ev.Model = model
			ev.ActionType = models.ActionAssistantMessage
			ev.Target = preview
			ev.Success = true
			ev.PrecedingReasoning = preReason
			ev.RawToolName = "opencode.assistant_text"
			ev.ToolOutput = a.scrubber.String(contentcap.Cap(body, contentcap.DefaultMaxBytes))
			ev.MessageID = r.ID
			ev.Metadata = meta
			out = append(out, ev)
		}
	}

	if completed && msg.Finish == "stop" {
		ev := base
		ev.SourceEventID = "complete:" + r.ID
		ev.Timestamp = chooseTime(millisToTime(int64(msg.Time.Completed)), millisToTime(r.TimeUpdate), 0)
		ev.Model = model
		ev.ActionType = models.ActionTaskComplete
		ev.Target = msg.Finish
		ev.Success = true
		ev.RawToolName = "assistant.stop"
		ev.MessageID = r.ID
		ev.Metadata = withStopReason(v2EffortMetadata(msg.Model.Variant), msg.Finish)
		out = append(out, ev)
	}
	return out
}

// v2ToolEvent maps one settled 2.x tool item onto a ToolEvent through
// the same mapTool table the 1.x parts use.
func (a *Adapter) v2ToolEvent(base models.ToolEvent, r v2MessageRow, item v2Content, model string, meta *models.ActionMetadata, reasoning string) (models.ToolEvent, bool) {
	status := item.State.Status
	if status != "completed" && status != "error" {
		return models.ToolEvent{}, false
	}
	var in v2ToolInput
	_ = json.Unmarshal(item.State.Input, &in)

	var outParts []string
	for _, c := range item.State.Content {
		if c.Type == "text" && c.Text != "" {
			outParts = append(outParts, c.Text)
		}
	}
	output := strings.Join(outParts, "\n")

	// Reuse the 1.x mapping table: the 2.x `path` fills the slot the 1.x
	// metadata file path occupied, so read/write/edit targets resolve to
	// it, and the subagent description stands in for the 1.x part title.
	var part toolPartData
	part.Type = "tool"
	part.Tool = item.Name
	part.CallID = item.ID
	part.State.Status = status
	part.State.Input = item.State.Input
	part.State.Output = output
	part.State.Metadata.FilePath = in.Path
	part.State.Title = in.Description
	actionType, target, success, errMsg := mapTool(part)
	if item.State.Metadata.Exit != nil && *item.State.Metadata.Exit != 0 {
		success = false
		if errMsg == "" {
			errMsg = output
		}
	}
	if status == "error" {
		success = false
		errMsg = firstNonEmpty(item.State.Error.Message, errMsg, output)
	}

	start := millisToTime(int64(firstPositive(item.Time.Ran, item.Time.Created)))
	if start.IsZero() {
		start = millisToTime(r.TimeCreate)
	}
	var durationMs int64
	if s, e := int64(firstPositive(item.Time.Ran, item.Time.Created)), int64(item.Time.Completed); s > 0 && e > s {
		durationMs = e - s
	}

	rawInput := a.scrubber.RawJSON(item.State.Input)
	toolOutput := a.scrubber.String(contentcap.Cap(output, contentcap.DefaultMaxBytes))
	preReason := truncate(strings.TrimSpace(in.Description), 200)
	if reasoning != "" {
		preReason = a.scrubber.String(truncate(reasoning, 200))
	}

	ev := base
	ev.SourceEventID = "tool:" + r.ID + ":" + item.ID
	ev.Timestamp = chooseTime(start, time.Time{}, 0)
	ev.Model = model
	ev.ActionType = actionType
	ev.Target = truncate(target, 200)
	ev.Success = success
	ev.ErrorMessage = truncate(a.scrubber.String(errMsg), 500)
	ev.DurationMs = durationMs
	ev.PrecedingReasoning = preReason
	ev.RawToolName = item.Name
	ev.RawToolInput = rawInput
	ev.ToolOutput = toolOutput
	ev.MessageID = r.ID
	ev.Metadata = meta
	return ev, true
}

// v2TokenEvent emits the usage of one 2.x assistant step (or compaction
// request). Rows with no usage yet are skipped.
func v2TokenEvent(base models.ToolEvent, r v2MessageRow, msg v2Message) (models.TokenEvent, bool) {
	if msg.Tokens.empty() {
		return models.TokenEvent{}, false
	}
	when := millisToTime(int64(msg.Time.Completed))
	if when.IsZero() {
		when = millisToTime(r.TimeUpdate)
	}
	return models.TokenEvent{
		SourceFile:          base.SourceFile,
		SourceEventID:       "tokens:" + r.ID,
		SessionID:           r.SessionID,
		ProjectRoot:         base.ProjectRoot,
		GitRemote:           base.GitRemote,
		Timestamp:           when,
		Tool:                models.ToolOpenCode,
		Model:               msg.Model.ID,
		InputTokens:         int64(msg.Tokens.Input),
		OutputTokens:        int64(msg.Tokens.Output),
		CacheReadTokens:     int64(msg.Tokens.Cache.Read),
		CacheCreationTokens: int64(msg.Tokens.Cache.Write),
		ReasoningTokens:     int64(msg.Tokens.Reasoning),
		EstimatedCostUSD:    msg.Cost,
		Source:              models.TokenSourceJSONL,
		Reliability:         models.ReliabilityApproximate,
		MessageID:           r.ID,
	}, true
}

// v2EffortMetadata maps the 2.x model variant onto the effort column.
// "default" is the 2.x name for "no variant selected" (the 1.x to 2.x
// migration writes it for every message that had none), so it carries
// no effort level.
func v2EffortMetadata(variant string) *models.ActionMetadata {
	if strings.EqualFold(strings.TrimSpace(variant), "default") {
		return nil
	}
	return effortMetadata(variant)
}

func firstPositive(values ...float64) float64 {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}

// loadSessionV2Lineages reads session_v2.parent_id, the 2.x sub-agent
// child-session pointer, with the same semantics as loadSessionLineages.
func loadSessionV2Lineages(ctx context.Context, db *sql.DB) ([]models.SessionLineage, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, parent_id FROM session_v2 WHERE parent_id IS NOT NULL AND parent_id != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.SessionLineage
	for rows.Next() {
		var id, parent string
		if err := rows.Scan(&id, &parent); err != nil {
			return nil, err
		}
		out = append(out, models.SessionLineage{
			SessionID:      id,
			ParentThreadID: parent,
			ThreadSource:   "subagent",
		})
	}
	return out, rows.Err()
}

// loadSessionV2ToolVersions is loadSessionToolVersions over session_v2.
func loadSessionV2ToolVersions(ctx context.Context, db *sql.DB, touched map[string]bool) []models.SessionToolVersion {
	if len(touched) == 0 {
		return nil
	}
	rows, err := db.QueryContext(ctx, `SELECT id, COALESCE(version, '') FROM session_v2`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []models.SessionToolVersion
	for rows.Next() {
		var id, ver string
		if err := rows.Scan(&id, &ver); err != nil {
			return out
		}
		if ver == "" || !touched[id] {
			continue
		}
		out = append(out, models.SessionToolVersion{SessionID: id, Version: ver})
	}
	return out
}

// readSessionTranscriptV2 is readSessionTranscript over a 2.x session:
// user messages and the text and tool items of each assistant step, in
// session order. Reasoning is dropped, as in the 1.x reader.
func readSessionTranscriptV2(ctx context.Context, db *sql.DB, sessionID string) ([]models.TranscriptMessage, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT type, data
		  FROM session_message
		 WHERE session_id = ?
		   AND type IN ('user', 'assistant')
		 ORDER BY seq ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("opencode.ReadTranscript: v2 query: %w", err)
	}
	defer rows.Close()

	b := transcriptutil.New()
	for rows.Next() {
		var typ, raw string
		if err := rows.Scan(&typ, &raw); err != nil {
			return nil, err
		}
		var msg v2Message
		if err := json.Unmarshal([]byte(raw), &msg); err != nil {
			continue
		}
		ts := opencodeMillis(int64(msg.Time.Created))
		if typ == "user" {
			if strings.TrimSpace(msg.Text) != "" {
				b.User(msg.Text, ts)
			}
			continue
		}
		if c := opencodeMillis(int64(msg.Time.Completed)); !c.IsZero() {
			ts = c
		}
		for _, item := range msg.Content {
			switch item.Type {
			case "text":
				b.AssistantText(item.Text, msg.Model.ID, ts)
			case "tool":
				b.AssistantCall(item.ID, item.Name, string(item.State.Input), msg.Model.ID, ts)
				if item.State.Status == "completed" || item.State.Status == "error" {
					var parts []string
					for _, c := range item.State.Content {
						if c.Type == "text" {
							parts = append(parts, c.Text)
						}
					}
					out := strings.Join(parts, "\n")
					if out == "" {
						out = item.State.Error.Message
					}
					b.Resolve(item.ID, out, time.Time{})
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return b.Finish(), nil
}
