//go:build !sbo_omit_adapter_cursor && !sbo_omit_adapter_codex && !sbo_omit_adapter_open_interpreter && !sbo_omit_terminals_sandbox && !sbo_omit_isolation

package hook

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/codex"
	"github.com/marmutapp/superbased-observer/internal/adapter/cursor"
	"github.com/marmutapp/superbased-observer/internal/adapter/hermes"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/hooklifecycle"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/testsupport/jsoncompat"
)

// TestHookJSONGolden pins every hook payload decode entry point of this
// package, and the adapter hook parsers it calls, against the v1
// encoding/json decoder (Go 1.27 backs encoding/json with v2; plan
// docs/plans/security-pillar-plan-2026-10-19.md section 8.4, risk T17).
// The decoder list is read from the integration registry, so a new wired
// dialect joins the check (and needs the golden file regenerated). See
// internal/testsupport/jsoncompat for the procedure; the build line keeps
// the check to builds that compile every dialect it lists.
func TestHookJSONGolden(t *testing.T) {
	// cursor.BuildEvent claims a pending reasoning stash under
	// ~/.observer/cursor-reasoning; never the operator's real one.
	setTestHome(t, t.TempDir())
	root, err := jsoncompat.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	payloads, err := jsoncompat.Payloads(root)
	if err != nil {
		t.Fatal(err)
	}
	jsoncompat.Check(t, filepath.Join("testdata", "jsoncompat", "hook.golden"), hookJSONDecoders(), payloads)
}

// hookJSONDecoders lists the decode entry points: the fixed ones, then
// one per wired registry binding the dialect tables serve.
func hookJSONDecoders() []jsoncompat.Decoder {
	sc := scrub.New()
	at := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	noFile := func(string) ([]byte, error) { return nil, fs.ErrNotExist }
	noEnv := func(string) string { return "" }

	type pair struct {
		A, B any
	}
	type triple struct {
		A, B, C any
	}
	decs := []jsoncompat.Decoder{
		{Name: "BuildClaudeCodeEvent", Decode: func(b []byte) any {
			ev, ok := BuildClaudeCodeEvent(b)
			return pair{ev, ok}
		}},
		{Name: "ClassifyClaudeHookPayload", Decode: func(b []byte) any { return ClassifyClaudeHookPayload(b) }},
		{Name: "toolInputMap", Decode: func(b []byte) any { return toolInputMap(b) }},
		{Name: "toolGateSessionID", Decode: func(b []byte) any { return toolGateSessionID(b) }},
		{Name: "jsonHasAnyKey", Decode: func(b []byte) any { return jsonHasAnyKey(b, "prompt", "session_id") }},
		{Name: "jsonNestedHasKey", Decode: func(b []byte) any { return jsonNestedHasKey(b, "tool_info", "user_prompt") }},
		{Name: "hooklifecycle.Normalize", Decode: func(b []byte) any {
			p, ok := hooklifecycle.Normalize(b)
			return pair{p, ok}
		}},
		{Name: "cursor.BuildResponseTokenEvent", Decode: func(b []byte) any {
			tk, ok, err := cursor.BuildResponseTokenEvent(b)
			return triple{tk, ok, err}
		}},
	}
	for _, key := range []string{"session_id", "tool_name", "hook_event_name", "conversation_id", "cwd"} {
		key := key
		decs = append(decs, jsoncompat.Decoder{Name: "payloadFieldString/" + key, Decode: func(b []byte) any { return payloadFieldString(b, key) }})
	}
	for _, tool := range []string{models.ToolClaudeCode, models.ToolCodex} {
		for _, event := range []string{"PreToolUse", "PostToolUse", "Stop", "UserPromptSubmit"} {
			tool, event := tool, event
			decs = append(decs, jsoncompat.Decoder{Name: "localAccountObservations/" + tool + "/" + event, Decode: func(b []byte) any {
				return localAccountObservations(tool, event, b, noFile, noEnv, at)
			}})
		}
	}

	seen := map[string]bool{}
	add := func(name string, fn func([]byte) any) {
		if !seen[name] {
			seen[name] = true
			decs = append(decs, jsoncompat.Decoder{Name: name, Decode: fn})
		}
	}
	// Registry rows sorted by tool (on a copy), so the representative
	// binding chosen for each lifecycle shape never depends on row order.
	caps := append([]integration.Capability(nil), integration.Capabilities()...)
	sort.SliceStable(caps, func(i, j int) bool { return caps[i].Tool < caps[j].Tool })
	for _, c := range caps {
		for _, b := range c.Hook.Bindings {
			tool, b := c.Tool, b
			if b.Dialect != "" {
				if d, ok := toolGateDialects[b.Dialect]; ok {
					add("toolgate/"+b.Dialect+"/"+tool+"/"+b.NativeEvent, func(body []byte) any {
						evs, native, ok, _ := d.extract(ToolGateRequest{Tool: tool, Dialect: b.Dialect, NativeEvent: b.NativeEvent, Label: tool + ":" + b.NativeEvent, Body: body})
						return triple{evs, native, ok}
					})
				}
				if d, ok := promptDialects[b.Dialect]; ok {
					add("prompt/"+b.Dialect, func(body []byte) any {
						prompt, sid, ok, missing := d.extract(body)
						return []any{prompt, sid, ok, missing}
					})
				}
				if b.Dialect == PluginDialectToolGate {
					add("BuildPluginToolEvent/"+tool, func(body []byte) any {
						ev, ok := BuildPluginToolEvent(tool, body, PluginToolGateCaps(true))
						return pair{ev, ok}
					})
				}
			}
			// Decide's outcome depends on the binding's capability, phase
			// and process relation; one representative binding of each
			// shape keeps the corpus small.
			if hooklifecycle.Handled(b.Cap) {
				add(fmt.Sprintf("hooklifecycle.Decide/%s/%s/%v", b.Cap, b.Phase, b.ProcRel), func(body []byte) any {
					return hooklifecycle.Decide(tool, b, body, at)
				})
			}
			switch tool {
			case models.ToolCursor:
				// BuildCursorEvent answers false before decoding on an
				// event that is not pre-execution.
				if caps, known := guard.CapabilitiesFor(models.ToolCursor, "hook:"+b.NativeEvent); known && caps.PreExecution {
					add("BuildCursorEvent/"+b.NativeEvent, func(body []byte) any {
						ev, ok := BuildCursorEvent(b.NativeEvent, body, nil)
						return pair{ev, ok}
					})
				}
				// afterAgentThought stashes its preview on disk for the
				// next event to claim, so its result would depend on the
				// order of the calls; it decodes the same payload struct
				// as every other cursor event, which stay in the check.
				if b.NativeEvent != cursor.EventAfterAgentThought {
					add("cursor.BuildEvent/"+b.NativeEvent, func(body []byte) any {
						ev, ok, err := cursor.BuildEvent(b.NativeEvent, body, sc)
						return triple{ev, ok, err}
					})
				}
			case models.ToolCodex:
				add("codex.BuildHookEvent/"+b.NativeEvent, func(body []byte) any {
					ev, ok, err := codex.BuildHookEvent(b.NativeEvent, body, sc)
					return triple{ev, ok, err}
				})
			case models.ToolHermes:
				add("hermes.BuildToolEvent/"+b.NativeEvent, func(body []byte) any {
					ev, ok, err := hermes.BuildToolEvent(b.NativeEvent, body, sc)
					return triple{ev, ok, err}
				})
				add("hermes.BuildTokenEvent/"+b.NativeEvent, func(body []byte) any {
					ev, ok, err := hermes.BuildTokenEvent(b.NativeEvent, body)
					return triple{ev, ok, err}
				})
			}
		}
	}
	// Every dialect table row is covered even when no binding names it.
	for _, name := range sortedKeys(promptDialects) {
		d := promptDialects[name]
		add("prompt/"+name, func(body []byte) any {
			prompt, sid, ok, missing := d.extract(body)
			return []any{prompt, sid, ok, missing}
		})
	}
	for _, name := range sortedKeys(toolGateDialects) {
		d, name := toolGateDialects[name], name
		add("toolgate/"+name, func(body []byte) any {
			evs, native, ok, _ := d.extract(ToolGateRequest{Tool: models.ToolClaudeCode, Dialect: name, NativeEvent: "PreToolUse", Label: "claude-code:PreToolUse", Body: body})
			return triple{evs, native, ok}
		})
	}
	return decs
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
