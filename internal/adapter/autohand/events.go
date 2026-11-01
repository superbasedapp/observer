package autohand

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// seedTurns replays the first limit bytes of the transcript through the same
// prompt rules handle/userPrompt apply, counting real user prompts so that
// TurnIndex indexes the whole session rather than restarting at 0 in every
// cursor window. It emits nothing. An unreadable or over-long line ends the
// replay with the count so far (TurnIndex is then a lower bound, never an
// error).
func (st *parseState) seedTurns(path string, limit int64) {
	f, err := os.Open(path) //nolint:gosec // watched session file
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, limit))
	sc.Buffer(make([]byte, 0, 1024*1024), maxLineBytes)
	for sc.Scan() {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var msg message
		if json.Unmarshal(raw, &msg) != nil || msg.Role != "user" || msg.Meta.injected() {
			continue
		}
		if st.inherited(st.stamp(msg)) {
			continue
		}
		if strings.TrimSpace(contentText(msg.Content)) == "" {
			continue
		}
		st.turn++
	}
}

// errorEvents turns the vendor's error.log records written during this
// session (same workspace, within the session's span) into api_error rows. A
// failed request leaves no transcript line at all (a quota-blocked session has
// an empty or absent conversation.jsonl), so the failure would otherwise be
// invisible. The row is keyed on the record's timestamp, so every re-parse
// upserts the same one.
func (a *Adapter) errorEvents(res *adapter.ParseResult, convPath, sessID, root, branch, remote string, m metadata) {
	if sessID == "" {
		return
	}
	for _, e := range entriesFor(a.errorLog(dataHomeFor(convPath)), m) {
		if e.ErrorLine == "" {
			continue
		}
		raw := e.ErrorName
		if raw == "" {
			raw = "api_error"
		}
		msg := a.scrubber.String(e.ErrorLine)
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile:    convPath,
			SourceEventID: "err:" + sessID + ":" + strconv.FormatInt(e.When.UnixMilli(), 10),
			SessionID:     sessID,
			ProjectRoot:   root,
			GitBranch:     branch,
			GitRemote:     remote,
			Timestamp:     e.When,
			Tool:          models.ToolAutohand,
			Model:         m.Model,
			ActionType:    models.ActionAPIError,
			RawToolName:   "autohand." + raw,
			Target:        truncate(a.scrubber.String(e.ErrorFirst), maxTargetLen),
			ErrorMessage:  msg,
			Success:       false,
		})
	}
}
