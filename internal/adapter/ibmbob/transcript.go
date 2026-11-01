package ibmbob

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter/transcriptutil"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// errNoStore is returned by ReadTranscript when no bob.db can be located.
var errNoStore = errors.New("ibmbob: no bob.db found for transcript read")

// ReadTranscript implements handoffsvc.TranscriptReader, the session-handoff
// transcript tier (docs/session-handoff.md). Bob has no proxy tier, so the
// conversation is re-read from its canonical store: the `messages` rows of
// the task whose id is sess.ID, in the same replay order the parser uses.
//
// User prompts and assistant narration become messages; each assistant tool
// call is paired with its tool-role result by call id. System prompts,
// `_meta.hide` replays and harness notices are dropped; the conversation
// summary Bob writes on a compaction is kept (it is what the model itself
// carries forward). Reasoning is not read.
func (a *Adapter) ReadTranscript(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	dbPath, err := a.storeDBPath(sourceHints)
	if err != nil {
		return nil, err
	}
	db, err := openReadOnlyDB(dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var envJSON string
	if tableExists(ctx, db, "tasks") {
		_ = db.QueryRowContext(ctx, `SELECT COALESCE(env, '') FROM tasks WHERE id = ?`, sess.ID).Scan(&envJSON)
	}
	model := modelID(decodeEnv(envJSON).Model)

	msgs, err := loadMessages(ctx, db, sess.ID)
	if err != nil {
		return nil, err
	}
	type decodedMsg struct {
		row messageRow
		msg bobMessage
	}
	decoded := make([]decodedMsg, 0, len(msgs))
	results := map[string]toolResult{}
	for _, m := range msgs {
		var bm bobMessage
		if err := json.Unmarshal([]byte(m.Data), &bm); err != nil {
			continue
		}
		decoded = append(decoded, decodedMsg{row: m, msg: bm})
		if strings.EqualFold(m.Role, "tool") && bm.ToolUsage != nil && bm.ToolUsage.Signature.ID != "" {
			results[bm.ToolUsage.Signature.ID] = resultFor(bm)
		}
	}

	b := transcriptutil.New()
	for _, dm := range decoded {
		ts := msToTime(dm.msg.Meta.Timestamp)
		if ts.IsZero() {
			ts = msToTime(dm.row.CreatedAt)
		}
		switch strings.ToLower(dm.row.Role) {
		case "user":
			if dm.msg.Meta.Hide {
				continue
			}
			b.SetNextID(dm.row.ID)
			b.User(a.scrub(contentText(dm.msg.Content)), ts)
		case "assistant":
			if dm.msg.Meta.NotAI && !dm.msg.Meta.Summary {
				continue
			}
			b.SetNextID(dm.row.ID)
			b.AssistantText(a.scrub(contentText(dm.msg.Content)), model, ts)
			for _, tc := range dm.msg.ToolCalls {
				b.AssistantCall(tc.ID, tc.Name, a.scrubRaw(tc.Arguments), model, ts)
				if res, ok := results[tc.ID]; ok {
					b.Resolve(tc.ID, a.scrub(res.Content), ts)
				}
			}
		}
	}
	return b.Finish(), nil
}

// storeDBPath resolves the bob.db to read: a usable hint first (the
// action's source_file), else the first watch root holding one.
func (a *Adapter) storeDBPath(hints []string) (string, error) {
	for _, h := range hints {
		p := resolveDBPath(h)
		if strings.EqualFold(filepath.Base(p), dbFile) && fileReadable(p) {
			return p, nil
		}
	}
	for _, root := range a.roots {
		p := filepath.Join(root, dbFile)
		if fileReadable(p) {
			return p, nil
		}
	}
	return "", errNoStore
}

func fileReadable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
