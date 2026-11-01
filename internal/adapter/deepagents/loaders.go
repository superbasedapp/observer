package deepagents

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// loadTouchedThreads returns the threads whose newest checkpoint in ANY
// namespace is later than cursor. A sub-agent's child namespace gains
// checkpoints while the root namespace is idle (the parent sits in its
// `tools` step until the child returns), so the touch test spans every
// namespace; LatestCheckpointID stays the root namespace's newest (the
// out-of-graph spend row is timestamped from it).
func loadTouchedThreads(ctx context.Context, db *sql.DB, cursor int64) ([]threadRow, error) {
	if !tableExists(ctx, db, "checkpoints") || !tableExists(ctx, db, "writes") {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT thread_id, MAX(checkpoint_id),
		       COALESCE(MAX(CASE WHEN checkpoint_ns = '' THEN checkpoint_id END), '')
		  FROM checkpoints
		 GROUP BY thread_id
		 ORDER BY MAX(checkpoint_id) ASC, thread_id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []threadRow
	for rows.Next() {
		var t threadRow
		var newest string
		if err := rows.Scan(&t.ID, &newest, &t.LatestCheckpointID); err != nil {
			return nil, err
		}
		if t.LatestCheckpointID == "" {
			// Only child-namespace checkpoints: no conversation of the
			// thread's own to anchor the sub-agent run to.
			continue
		}
		if cursorOf(newest) > cursor {
			out = append(out, t)
		}
	}
	return out, rows.Err()
}

// threadCheckpoints is a thread's checkpoint index across every namespace.
type threadCheckpoints struct {
	// byID is the decoded metadata of every checkpoint, keyed by checkpoint
	// id (a time-based UUIDv6, unique across namespaces).
	byID map[string]checkpointMeta
	// latest is the newest ROOT-namespace checkpoint's metadata.
	latest checkpointMeta
	// next maps a checkpoint id to the checkpoint LangGraph saved right after
	// it in the same namespace (its child via parent_checkpoint_id, else the
	// next id): the end of the step that ran from it.
	next map[string]string
	// spans is each child namespace's first and last checkpoint id.
	spans map[string][2]string
	// turnLast is the newest root-namespace checkpoint id of each turn_id.
	turnLast map[string]string
}

// loadCheckpoints indexes every checkpoint of a thread. Only the metadata
// column is read; the checkpoint blob is never selected.
func loadCheckpoints(ctx context.Context, db *sql.DB, threadID string) (threadCheckpoints, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT checkpoint_ns, checkpoint_id, COALESCE(parent_checkpoint_id, ''), metadata
		  FROM checkpoints
		 WHERE thread_id = ?
		 ORDER BY checkpoint_ns ASC, checkpoint_id ASC`, threadID)
	if err != nil {
		return threadCheckpoints{}, err
	}
	defer rows.Close()
	tc := threadCheckpoints{
		byID:     map[string]checkpointMeta{},
		next:     map[string]string{},
		spans:    map[string][2]string{},
		turnLast: map[string]string{},
	}
	childOf := map[string]string{}
	prevByNS := map[string]string{}
	for rows.Next() {
		var ns, id, parent string
		var raw []byte
		if err := rows.Scan(&ns, &id, &parent, &raw); err != nil {
			return threadCheckpoints{}, err
		}
		m := decodeMeta(raw)
		tc.byID[id] = m
		if ns == "" {
			tc.latest = m
			if m.TurnID != "" {
				tc.turnLast[m.TurnID] = id
			}
		} else {
			sp := tc.spans[ns]
			if sp[0] == "" {
				sp[0] = id
			}
			sp[1] = id
			tc.spans[ns] = sp
		}
		if _, dup := childOf[parent]; parent != "" && !dup {
			childOf[parent] = id
		}
		if prev := prevByNS[ns]; prev != "" {
			tc.next[prev] = id
		}
		prevByNS[ns] = id
	}
	if err := rows.Err(); err != nil {
		return threadCheckpoints{}, err
	}
	// A recorded parent link is authoritative over id adjacency.
	for parent, child := range childOf {
		tc.next[parent] = child
	}
	return tc, nil
}

// threadWorkspace is dcode's own per-thread workspace record
// (dcode_thread_workspaces): the directory the session ran in, the project
// root dcode resolved for it, and whether the run was the interactive TUI.
type threadWorkspace struct {
	Cwd         string
	ProjectRoot string
	// Interactive is workspace_config_json.interactive: true for the
	// Textual TUI, false for a headless `dcode -n` run; nil when absent.
	Interactive *bool
}

// loadThreadWorkspace reads dcode_thread_workspaces for a thread; absent
// table or row yields the zero value (the checkpoint metadata cwd is the
// fallback).
func loadThreadWorkspace(ctx context.Context, db *sql.DB, threadID string) threadWorkspace {
	if !tableExists(ctx, db, "dcode_thread_workspaces") {
		return threadWorkspace{}
	}
	var w threadWorkspace
	var root, cfg sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT cwd, project_root, workspace_config_json FROM dcode_thread_workspaces WHERE thread_id = ?`, threadID).
		Scan(&w.Cwd, &root, &cfg)
	if err != nil {
		return threadWorkspace{}
	}
	w.ProjectRoot = root.String
	var c struct {
		Interactive *bool `json:"interactive"`
	}
	if json.Unmarshal([]byte(cfg.String), &c) == nil {
		w.Interactive = c.Interactive
	}
	return w
}

// messageWrite is one `messages` channel write.
type messageWrite struct {
	// Namespace is the write's checkpoint_ns: "" for the thread's own graph,
	// `tools:<task id>` for a sub-agent run the `task` tool started.
	Namespace    string
	CheckpointID string
	TaskID       string
	Idx          int
	Type         string
	Value        []byte
}

// loadMessageWrites returns every `messages` channel write of a thread, in
// every namespace, ordered by namespace and then the way LangGraph replays
// them (checkpoint id, task id, idx — the vendor's own thread inspector's
// order). Only that channel is selected: the table also holds multi-megabyte
// `_quickjs_snapshot_payload` blobs the adapter must never read.
func loadMessageWrites(ctx context.Context, db *sql.DB, threadID string) ([]messageWrite, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT checkpoint_ns, checkpoint_id, task_id, idx, COALESCE(type, ''), value
		  FROM writes
		 WHERE thread_id = ? AND channel = 'messages'
		 ORDER BY checkpoint_ns ASC, checkpoint_id ASC, task_id ASC, idx ASC`, threadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []messageWrite
	for rows.Next() {
		var w messageWrite
		if err := rows.Scan(&w.Namespace, &w.CheckpointID, &w.TaskID, &w.Idx, &w.Type, &w.Value); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// writeKey identifies the task that produced a write: the checkpoint it ran
// from and its LangGraph task id.
func writeKey(checkpointID, taskID string) string { return checkpointID + "|" + taskID }

// loadRequestStarts reads the `_last_model_request_at` channel: dcode's
// model middleware records the ISO-8601 time it sent each model request
// (deepagents_code/configurable_model.py `request_started_at`) from the SAME
// task as the AI message the request produced. Keyed by writeKey. Grounded
// 2026-10-21: present for every root-namespace model call on both OSes,
// absent inside sub-agent namespaces.
func loadRequestStarts(ctx context.Context, db *sql.DB, threadID string) (map[string]time.Time, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT checkpoint_id, task_id, COALESCE(type, ''), value
		  FROM writes
		 WHERE thread_id = ? AND channel = '_last_model_request_at'`, threadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var cp, task, typ string
		var raw []byte
		if err := rows.Scan(&cp, &task, &typ, &raw); err != nil {
			return nil, err
		}
		if typ != "msgpack" || len(raw) == 0 {
			continue
		}
		v, err := decodeMsgpack(raw)
		if err != nil {
			continue
		}
		s, _ := v.(string)
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			out[writeKey(cp, task)] = t.UTC()
		}
	}
	return out, rows.Err()
}

// controlWrite is one `__interrupt__` or `__resume__` write: LangGraph's
// pause / answer record. Both halves of one pause share (namespace,
// checkpoint, task).
type controlWrite struct {
	Namespace    string
	CheckpointID string
	TaskID       string
	Channel      string
	Value        []byte
}

// loadControlWrites reads the `__interrupt__` / `__resume__` writes of a
// thread in every namespace.
func loadControlWrites(ctx context.Context, db *sql.DB, threadID string) ([]controlWrite, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT checkpoint_ns, checkpoint_id, task_id, channel, value
		  FROM writes
		 WHERE thread_id = ? AND channel IN ('__interrupt__', '__resume__') AND type = 'msgpack'
		 ORDER BY checkpoint_ns ASC, checkpoint_id ASC, task_id ASC, idx ASC`, threadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []controlWrite
	for rows.Next() {
		var w controlWrite
		if err := rows.Scan(&w.Namespace, &w.CheckpointID, &w.TaskID, &w.Channel, &w.Value); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// installVersion reads the install-level dcode version from
// `<state>/update_state.json` `seen_version` (the build dcode's update
// checker last recorded running as). It is the fallback for a thread whose
// checkpoints carry no lc_versions stamp; "" when absent or unreadable. The
// sibling latest_version.json names the newest RELEASE on the index, not
// the installed build, and is never used.
func installVersion(stateDir string) string {
	data, err := os.ReadFile(filepath.Join(stateDir, "update_state.json")) //nolint:gosec // fixed file name in the store's own directory
	if err != nil {
		return ""
	}
	var u struct {
		SeenVersion string `json:"seen_version"`
	}
	if json.Unmarshal(data, &u) != nil {
		return ""
	}
	return strings.TrimSpace(u.SeenVersion)
}
