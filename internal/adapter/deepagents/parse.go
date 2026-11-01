package deepagents

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// outcomeWindow bounds how many of a thread's most recent resolved tool
// calls are re-emitted as late OutcomeUpdates on an incremental parse. A call
// persisted optimistically (its result not yet written) is by construction
// among the newest calls of the thread; parallel tool calls and an approval
// pause never put more than a handful in flight.
const outcomeWindow = 64

// maxReasoningBytes caps the reasoning text carried on a row.
const maxReasoningBytes = 2000

// genTimingV is the generation-timing parser version stamped on token rows
// carrying GenMs (TokenEvent.GenTimingV).
const genTimingV = 1

// ParseSessionFile implements adapter.Adapter. It is a watermark read of the
// sessions.db at path: fromOffset is the Unix 100ns clock of the newest
// checkpoint already processed (UUIDv6 checkpoint ids embed it). When the
// store's newest checkpoint has not advanced nothing is read. Otherwise every
// thread that gained a checkpoint (in any namespace) is re-emitted in full —
// its messages are replayed from the `messages` channel writes — and
// downstream (source_file, source_event_id) dedup makes already-seen rows a
// no-op.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	dbPath := resolveDBPath(path)
	res := adapter.ParseResult{NewOffset: fromOffset}
	if _, err := os.Stat(dbPath); err != nil { //nolint:gosec // G703: the watcher-discovered sessions.db path, stat only
		// A -wal / -shm event for a store that is gone: nothing to read.
		return res, nil
	}

	db, err := openReadOnlyDB(dbPath)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("deepagents.ParseSessionFile: open: %w", err)
	}
	defer db.Close()

	cursor, err := latestCursor(ctx, db)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("deepagents.ParseSessionFile: cursor: %w", err)
	}
	if cursor <= fromOffset {
		return res, nil
	}
	res.NewOffset = cursor

	threads, err := loadTouchedThreads(ctx, db, fromOffset)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("deepagents.ParseSessionFile: threads: %w", err)
	}
	installVer := ""
	installRead := false
	identitiesByRoot := map[string]git.Identity{}
	for _, t := range threads {
		out, err := a.parseThread(ctx, db, dbPath, t, fromOffset)
		if err != nil {
			// One unreadable thread must not wedge the others (or the
			// cursor): warn and carry on.
			res.Warnings = append(res.Warnings, fmt.Sprintf("deepagents: thread %s: %v", t.ID, err))
			continue
		}
		res.ToolEvents = append(res.ToolEvents, out.tools...)
		res.TokenEvents = append(res.TokenEvents, out.tokens...)
		res.CacheObservations = append(res.CacheObservations, out.cache...)
		res.OutcomeUpdates = append(res.OutcomeUpdates, out.outcomes...)
		res.SessionSurfaces = append(res.SessionSurfaces, out.surfaces...)
		res.Warnings = append(res.Warnings, out.warnings...)
		if !out.emitted {
			continue
		}
		version := out.version
		if version == "" {
			// Ruling 2026-10-21: every session carries a version — the
			// install-level one when the thread recorded none.
			if !installRead {
				installVer, installRead = installVersion(filepath.Dir(dbPath)), true
			}
			version = installVer
		}
		if version != "" {
			res.SessionToolVersions = append(res.SessionToolVersions, models.SessionToolVersion{SessionID: t.ID, Version: version})
		}
		if out.root != "" {
			identitiesByRoot[out.root] = out.identity
		}
	}
	adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot)
	return res, nil
}

// threadOut is the events one thread produced.
type threadOut struct {
	tools    []models.ToolEvent
	tokens   []models.TokenEvent
	cache    []models.CacheTurnObservation
	outcomes []models.ActionOutcomeUpdate
	surfaces []models.SessionSurface
	warnings []string
	// version is the per-session dcode build ("" when no checkpoint
	// recorded one); emitted is false for a thread with no conversation.
	version  string
	emitted  bool
	root     string
	identity git.Identity
}

// resolveProjectRoot turns a thread's working directory into a stable project
// root. A foreign-OS path (a raw C:\… string from a Windows store read by a
// WSL observer) is translated and STAT-GATED before git resolution: a path
// that is not locally reachable is returned as-is, because git.Resolve's
// filepath.Abs would otherwise prefix the observer's own cwd onto it. An
// empty cwd falls back to a synthetic root.
func resolveProjectRoot(cwd string) (root, gitRemote string, id git.Identity) {
	wd := strings.TrimSpace(cwd)
	if wd == "" {
		return "[" + models.ToolDeepAgentsCode + "]", "", git.Identity{}
	}
	wd = crossmount.TranslateForeignPath(wd)
	if _, err := os.Stat(wd); err != nil {
		return wd, "", git.Identity{}
	}
	identity, err := git.ResolveIdentity(wd, git.IdentityOptions{})
	if err != nil {
		return wd, "", git.Identity{}
	}
	return identity.Root, identity.Remote, identity
}

// surfaceHosts maps workspace_config_json.interactive to the capture-surface
// host token: the Textual TUI, or a headless `dcode -n` run. Both are the
// CLI kind.
var surfaceHosts = map[bool]string{
	true:  "dcode",
	false: "dcode-headless",
}

// subagentNamespacePrefix is the checkpoint_ns prefix of a sub-agent run the
// `task` tool started: `tools:<LangGraph task id of the tools step>`.
const subagentNamespacePrefix = "tools:"

// agentIDOf returns the sub-agent identity of a child namespace: the task id
// of its innermost `tools:` segment (LangGraph joins nested namespaces with
// `|`).
func agentIDOf(ns string) string {
	last := ns
	if i := strings.LastIndex(ns, "|"); i >= 0 {
		last = ns[i+1:]
	}
	return strings.TrimPrefix(last, subagentNamespacePrefix)
}

// parseThread replays one thread's messages — its own namespace first, then
// every sub-agent namespace — and converts them to events.
func (a *Adapter) parseThread(ctx context.Context, db *sql.DB, dbPath string, t threadRow, fromOffset int64) (threadOut, error) {
	var out threadOut
	tc, err := loadCheckpoints(ctx, db, t.ID)
	if err != nil {
		return out, fmt.Errorf("checkpoint metadata: %w", err)
	}
	writes, err := loadMessageWrites(ctx, db, t.ID)
	if err != nil {
		return out, fmt.Errorf("message writes: %w", err)
	}
	byNS := map[string][]messageWrite{}
	for _, w := range writes {
		byNS[w.Namespace] = append(byNS[w.Namespace], w)
	}
	rootMsgs, rootCalls, warns := replayMessages(byNS[""])
	out.warnings = warns
	if len(rootMsgs) == 0 {
		return out, nil
	}
	starts, err := loadRequestStarts(ctx, db, t.ID)
	if err != nil {
		return out, fmt.Errorf("request starts: %w", err)
	}
	controls, err := loadControlWrites(ctx, db, t.ID)
	if err != nil {
		return out, fmt.Errorf("control writes: %w", err)
	}
	hitlByNS := map[string][]hitlRequest{}
	for _, r := range decodeHITL(controls) {
		hitlByNS[r.Namespace] = append(hitlByNS[r.Namespace], r)
	}

	ws := loadThreadWorkspace(ctx, db, t.ID)
	cwd := firstNonEmpty(ws.Cwd, tc.latest.Cwd, ws.ProjectRoot)
	root, remote, identity := resolveProjectRoot(cwd)
	out.root, out.identity, out.emitted = root, identity, true
	if ws.Interactive != nil {
		out.surfaces = []models.SessionSurface{{
			SessionID:   t.ID,
			Surface:     models.SurfaceCLI,
			SurfaceHost: surfaceHosts[*ws.Interactive],
		}}
	}
	out.version = tc.latest.version()

	// Sub-agent namespaces, oldest first. The `task` tool's result is the
	// ToolMessage written by the very task the namespace is named after, so
	// its tool_call_id links the parent's spawn row to the child run.
	var children []string
	for ns := range byNS {
		if ns != "" && strings.Contains(ns, subagentNamespacePrefix) {
			children = append(children, ns)
		}
	}
	sort.Slice(children, func(i, j int) bool {
		ci, cj := tc.spans[children[i]][0], tc.spans[children[j]][0]
		if ci != cj {
			return ci < cj
		}
		return children[i] < children[j]
	})
	agentByTask := map[string]string{}
	for _, ns := range children {
		agentByTask[agentIDOf(ns)] = ns
	}
	spawns := map[string]spawnLink{}
	for _, m := range rootMsgs {
		if m.Role != "tool" || m.ToolCallID == "" {
			continue
		}
		if ns, ok := agentByTask[m.TaskID]; ok {
			spawns[m.ToolCallID] = spawnLink{ns: ns, agentID: agentIDOf(ns), result: m}
		}
	}

	shared := &threadShared{
		a:       a,
		dbPath:  dbPath,
		session: t.ID,
		root:    root,
		remote:  remote,
		tc:      tc,
		starts:  starts,
	}
	b := newBuilder(shared, rootMsgs, rootCalls, hitlByNS[""])
	b.spawns = spawns
	b.run(rootMsgs)
	out.tools, out.tokens, out.cache = b.tools, b.tokens, b.cacheObs
	if sc, ok := loadSideCost(ctx, db, t.ID); ok {
		out.tokens = append(out.tokens, b.sideCostEvent(sc, t.LatestCheckpointID))
	}
	if fromOffset > 0 {
		out.outcomes = b.recentOutcomes()
	}

	// A sub-agent's first write re-states the parent conversation it was
	// forked from (`_deepagents_forked_context`), under the SAME message
	// ids; those copies were already counted above and are dropped, so only
	// the child's own messages (and their usage) are added.
	seen := map[string]bool{}
	for _, m := range rootMsgs {
		seen[m.ID] = true
	}
	for _, ns := range children {
		msgs, calls, w := replayMessages(byNS[ns])
		out.warnings = append(out.warnings, w...)
		var own []*rawMessage
		for _, m := range msgs {
			if !seen[m.ID] {
				own = append(own, m)
				seen[m.ID] = true
			}
		}
		if len(own) == 0 {
			continue
		}
		cb := newBuilder(shared, own, calls, hitlByNS[ns])
		cb.sidechain = true
		cb.agentID = agentIDOf(ns)
		cb.agentType = tc.byID[tc.spans[ns][0]].LCAgentName
		cb.run(own)
		if link, ok := b.spawnFor(cb.agentID); ok {
			cb.addSubagentStop(ns, link)
		}
		out.tools = append(out.tools, cb.tools...)
		out.tokens = append(out.tokens, cb.tokens...)
		if fromOffset > 0 {
			out.outcomes = append(out.outcomes, cb.recentOutcomes()...)
		}
	}
	return out, nil
}

// replayMessages decodes one namespace's `messages` writes in replay order
// and folds them by message id (LangGraph's add_messages reducer): the first
// sighting fixes a message's position, checkpoint and task, a later write
// with the same id replaces its content (a human-in-the-loop edit rewrites
// the tool call, and the after-model middleware re-writes an AI message
// verbatim). It also returns, per producing task (writeKey), the tool calls
// of the AI messages that task wrote — the approval pairing input. An
// undecodable write is skipped with a warning.
func replayMessages(writes []messageWrite) ([]*rawMessage, map[string][]rawToolCall, []string) {
	var (
		out   []*rawMessage
		byID  = map[string]*rawMessage{}
		calls = map[string][]rawToolCall{}
		warns []string
	)
	for _, w := range writes {
		if w.Type != "msgpack" || len(w.Value) == 0 {
			continue
		}
		v, err := decodeMsgpack(w.Value)
		if err != nil {
			warns = append(warns, fmt.Sprintf("deepagents: skipped undecodable write at checkpoint %s: %v", w.CheckpointID, err))
			continue
		}
		pos := 0
		key := writeKey(w.CheckpointID, w.TaskID)
		collectMessages(v, func(m rawMessage) {
			if m.ID == "" {
				m.ID = synthID(w.CheckpointID, w.TaskID, w.Idx, pos)
			}
			pos++
			if m.Role == "ai" && len(m.ToolCalls) > 0 {
				calls[key] = append(calls[key], m.ToolCalls...)
			}
			if prev, ok := byID[m.ID]; ok {
				// Keep the first sighting's position, checkpoint and task.
				m.CheckpointID, m.TaskID = prev.CheckpointID, prev.TaskID
				*prev = m
				return
			}
			m.CheckpointID, m.TaskID = w.CheckpointID, w.TaskID
			cp := m
			byID[cp.ID] = &cp
			out = append(out, &cp)
		})
	}
	return out, calls, warns
}

// newCache returns a fresh per-thread Tier-2 accumulator.
func newCache() *cacheobs.Accumulator { return cacheobs.New(MaxBlocksPerSession) }
