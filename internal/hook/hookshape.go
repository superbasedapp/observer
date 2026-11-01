package hook

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
)

// Hook payload SHAPE log for live grounding (hook-parity audit section 6,
// "Live grounding"): when OBSERVER_HOOK_SHAPE_LOG names a file, every hook
// invocation that reaches a payload-shape seam appends one content-safe JSON
// line: the tool and event Observer was invoked as, the sorted set of
// top-level payload keys, and the values of short IDENTITY scalars only
// (session / conversation ids, event names, versions, source, reason, cwd,
// transcript path). Prompts, messages, tool inputs and tool output are never
// recorded. Off unless the variable is set (the operator sets it on the
// vendor CLI it launches for a probe); a write failure is silent.

// HookShapeLogEnv names the environment variable that enables the log.
const HookShapeLogEnv = "OBSERVER_HOOK_SHAPE_LOG"

// shapeScalarKeys are the only keys whose (short, scalar) values are kept.
var shapeScalarKeys = map[string]bool{
	"session_id": true, "sessionId": true, "conversation_id": true, "conversationId": true,
	"generation_id": true, "prompt_id": true, "turn_id": true, "thread_id": true,
	"hook_event_name": true, "hookEventName": true, "event": true, "eventName": true,
	"cursor_version": true, "version": true, "client_version": true,
	"source": true, "reason": true, "trigger": true, "model": true,
	"agent_id": true, "agent_type": true, "subagent_id": true,
	"cwd": true, "transcript_path": true, "transcriptPath": true, "permission_mode": true,
	"tool_name": true, "toolName": true, "stop_hook_active": true,
}

// shapeScalarMax bounds a kept scalar's length.
const shapeScalarMax = 200

type hookShape struct {
	Ts      string         `json:"ts"`
	Tool    string         `json:"tool"`
	Event   string         `json:"event"`
	Bytes   int            `json:"bytes"`
	Keys    []string       `json:"keys"`
	Scalars map[string]any `json:"scalars,omitempty"`
}

var hookShapeMu sync.Mutex

// DumpHookShape appends body's content-safe shape to the file named by
// OBSERVER_HOOK_SHAPE_LOG (a no-op when it is unset or body is not a JSON
// object).
func DumpHookShape(tool, event string, body []byte) {
	path := strings.TrimSpace(hookctx.Process().Getenv(HookShapeLogEnv))
	if path == "" {
		return
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return
	}
	s := hookShape{Ts: time.Now().UTC().Format(time.RFC3339Nano), Tool: tool, Event: event, Bytes: len(body)}
	for k, v := range m {
		s.Keys = append(s.Keys, k)
		if !shapeScalarKeys[k] {
			continue
		}
		switch x := v.(type) {
		case string:
			if len(x) > shapeScalarMax {
				x = x[:shapeScalarMax]
			}
			if s.Scalars == nil {
				s.Scalars = map[string]any{}
			}
			s.Scalars[k] = x
		case bool, float64:
			if s.Scalars == nil {
				s.Scalars = map[string]any{}
			}
			s.Scalars[k] = x
		}
	}
	sort.Strings(s.Keys)
	line, err := json.Marshal(s)
	if err != nil {
		return
	}
	hookShapeMu.Lock()
	defer hookShapeMu.Unlock()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) //nolint:gosec // G703: the daemon's own hook-shape log under the observer home
	if err != nil {
		return
	}
	_, _ = f.Write(append(line, '\n'))
	_ = f.Close()
}
