package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/handoff"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// handoffHookPayload returns the session-start context for a hook-armed
// session handoff targeted at tool (plan §10 inject_hook), or "" when
// nothing is armed / the feature is off / anything fails. It mirrors
// advisorSessionDigest: one config load + one best-effort point-read
// against the daemon's DB, and EVERY failure path degrades to "" so the
// hook's reply is never blocked (fail-open: a hook must never break the
// session; watchdog exits 0, not 2).
//
// The claim is one-shot and race-safe (store.ClaimArmedHandoffHook), so a
// handover fires for exactly the next matching session of the tool it was
// armed for and never again. The doc content itself lives only on disk
// (delivery_ref); we read it here (a cmd-layer os.ReadFile is allowed) and
// budget it to [handoff].hook_max_bytes via handoff.HookPayload before
// returning it (Phase 0 D-P0.2's 8KB cap).
func handoffHookPayload(ctx context.Context, tool, cwd, configPath string) string {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil || !cfg.Handoff.Enabled {
		return ""
	}
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		return ""
	}
	defer database.Close()

	// Best-effort project match: an armed handoff is claimed only for its
	// own project root. git.Resolve maps the session cwd to the working-tree
	// root (which is what the store recorded); a non-git cwd falls back to
	// the cwd itself.
	projectRoot := cwd
	if info, gerr := git.Resolve(cwd); gerr == nil {
		projectRoot = info.Root
	}

	docPath, ok, err := store.New(database).ClaimArmedHandoffHook(ctx, tool, projectRoot, time.Now())
	if err != nil || !ok || docPath == "" {
		return ""
	}
	body, err := os.ReadFile(docPath) //nolint:gosec // G703: reads the user's own local file with the user's own rights
	if err != nil {
		return ""
	}
	return handoff.HookPayload(string(body), docPath, hookMaxBytesOrDefault(cfg.Handoff.HookMaxBytes))
}

// composeSessionStartContext builds the additionalContext for a claude-code
// SessionStart. A hook-armed handoff (an explicit user action via
// `observer handoff --deliver hook`) takes precedence and consumes the whole
// hook budget — it is already budgeted to hook_max_bytes — so the advisor
// digest is skipped for that one session. Otherwise the advisor digest is
// returned as before. Both halves fail open to "".
func composeSessionStartContext(ctx context.Context, cwd string) string {
	if h := handoffHookPayload(ctx, models.ToolClaudeCode, cwd, ""); h != "" {
		return h
	}
	return advisorSessionDigest(ctx)
}

func hookMaxBytesOrDefault(v int) int {
	if v <= 0 {
		return 8192
	}
	return v
}

// sessionContextFields maps a context_inject binding's reply dialect onto
// the reply fields that carry session-start context to the MODEL (Lane F,
// hook-parity audit section 6). Data, keyed on the wire dialect, never on a
// tool: Claude Code keeps its own SessionStart builder
// (handleClaudeCodeSessionStart); these rows serve the other receivers,
// whose own reply is merged with the returned fields.
//
//   - codex: hookSpecificOutput.additionalContext on SessionStart
//     (learn.chatgpt.com/docs/hooks; the receiver otherwise replies {}).
//   - cursor: additional_context on sessionStart (cursor.com/docs/hooks).
var sessionContextFields = map[string]func(text string) map[string]any{
	"codex": func(text string) map[string]any {
		return map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName": "SessionStart", "additionalContext": text,
		}}
	},
	"cursor": func(text string) map[string]any {
		return map[string]any{"additional_context": text}
	},
}

// sessionContextBinding returns the start-phase context_inject binding that
// tool's native event provides, when its dialect has a sessionContextFields
// row AND the tool's handoff capability offers the hook lane. The handoff
// lane is the gate: HandoffCapability.Inject gains InjectHook for a tool
// only after a live check that its host renders the injected context, so an
// unverified host never pays for the claim (and never consumes one).
func sessionContextBinding(tool, event string) (integration.HookBinding, bool) {
	c, ok := integration.For(tool)
	if !ok || !hasInjectHook(c.Handoff) {
		return integration.HookBinding{}, false
	}
	for _, b := range c.Hook.Bindings {
		if b.NativeEvent != event || b.Cap != integration.HookCapContextInject || b.Phase != integration.HookPhaseStart {
			continue
		}
		if _, ok := sessionContextFields[b.Dialect]; ok {
			return b, true
		}
	}
	return integration.HookBinding{}, false
}

// hasInjectHook reports whether a handoff capability offers the hook lane.
func hasInjectHook(h integration.HandoffCapability) bool {
	for _, k := range h.Inject {
		if k == integration.InjectHook {
			return true
		}
	}
	return false
}

// wrapSessionStartContext returns w unchanged unless (tool, event) is a
// session-start context_inject binding with an armed handoff for the
// payload's cwd (claimed against configPath's database); then it returns a writer that merges the dialect's context
// fields into the first JSON object the receiver writes. Fail-open: any
// miss returns w.
func wrapSessionStartContext(ctx context.Context, w io.Writer, tool, event string, body []byte, configPath string) io.Writer {
	b, ok := sessionContextBinding(tool, event)
	if !ok {
		return w
	}
	p, ok := decodeObservePayload(body)
	if !ok || p.Cwd == "" {
		return w
	}
	text := handoffHookPayload(ctx, tool, p.Cwd, configPath)
	if text == "" {
		return w
	}
	return &jsonMergeWriter{w: w, fields: sessionContextFields[b.Dialect](text)}
}

// jsonMergeWriter merges fields into the first JSON object written through
// it; a key the reply already sets is never overwritten. A first write that
// is not a JSON object passes through untouched.
type jsonMergeWriter struct {
	w      io.Writer
	fields map[string]any
	done   bool
}

func (j *jsonMergeWriter) Write(p []byte) (int, error) {
	if j.done {
		return j.w.Write(p)
	}
	j.done = true
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(p), &m); err != nil || m == nil {
		return j.w.Write(p)
	}
	for k, v := range j.fields {
		if _, has := m[k]; !has {
			m[k] = v
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return j.w.Write(p)
	}
	out = append(out, '\n')
	if _, err := j.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}
