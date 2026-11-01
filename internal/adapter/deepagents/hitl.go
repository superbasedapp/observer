package deepagents

import (
	"encoding/json"
	"fmt"
	"strings"
)

// hitl.go decodes dcode's human-in-the-loop record. When a tool call needs
// approval, LangChain's HumanInTheLoopMiddleware pauses the graph: the
// `__interrupt__` write carries an `Interrupt` (ext 2, `langgraph.types`)
// whose value is `{"action_requests": [{name, args, description}],
// "review_configs": [...]}`, and the matching `__resume__` write from the
// SAME (namespace, checkpoint, task) carries `{"decisions": [{type,
// message?}]}` aligned with the requests (decision types approve / edit /
// reject / respond — langchain/agents/middleware/human_in_the_loop.py).
//
// The same two channels also carry dcode's own hook protocol
// (`{"type": "hook_invocation", ...}` interrupts answered by `{"decision":
// {...}}` resumes, one per fired hook — SubagentStart, PreToolUse, ...);
// those are not permission prompts and are skipped. Pairing is therefore by
// order among the HITL-shaped items only, never by raw list position (a
// hook resume list can hold more items than its interrupt list — grounded
// 2026-10-21, PostToolUse + SubagentStop answered together).

// hitlRequest is one approval request and, once answered, its decision.
type hitlRequest struct {
	Namespace    string
	CheckpointID string
	TaskID       string
	// InterruptID is the LangGraph interrupt id; Index the request's
	// position among that interrupt's action_requests.
	InterruptID string
	Index       int
	Name        string
	Args        map[string]any
	// Decision is "" while unanswered, else approve / edit / reject /
	// respond. Message is the reject / respond text, when given.
	Decision string
	Message  string
}

// decodeHITL pairs the HITL-shaped interrupts and resumes of a thread.
// Undecodable values are skipped (they carry no prompt to report).
func decodeHITL(writes []controlWrite) []hitlRequest {
	type group struct {
		requests  []hitlRequest
		decisions []map[string]any
	}
	var order []string
	groups := map[string]*group{}
	for _, w := range writes {
		key := w.Namespace + "\x00" + writeKey(w.CheckpointID, w.TaskID)
		g := groups[key]
		if g == nil {
			g = &group{}
			groups[key] = g
			order = append(order, key)
		}
		v, err := decodeMsgpack(w.Value)
		if err != nil {
			continue
		}
		items, _ := v.([]any)
		switch w.Channel {
		case "__interrupt__":
			for _, it := range items {
				g.requests = append(g.requests, interruptRequests(w, it)...)
			}
		case "__resume__":
			for _, it := range items {
				for _, d := range asSlice(asMap(it)["decisions"]) {
					if dm := asMap(d); dm != nil {
						g.decisions = append(g.decisions, dm)
					}
				}
			}
		}
	}
	var out []hitlRequest
	for _, key := range order {
		g := groups[key]
		for i := range g.requests {
			if i < len(g.decisions) {
				g.requests[i].Decision = strings.ToLower(firstString(g.decisions[i], "type"))
				g.requests[i].Message = firstString(g.decisions[i], "message")
			}
			out = append(out, g.requests[i])
		}
	}
	return out
}

// interruptRequests returns the approval requests of one Interrupt item, or
// nil when it is not a HITL pause.
func interruptRequests(w controlWrite, item any) []hitlRequest {
	ext, ok := item.(extValue)
	if !ok {
		return nil
	}
	_, class, payload, ok := ext.object()
	if !ok || class != "Interrupt" {
		return nil
	}
	p := asMap(payload)
	value := asMap(p["value"])
	reqs := asSlice(value["action_requests"])
	if len(reqs) == 0 {
		return nil
	}
	id := firstString(p, "id")
	var out []hitlRequest
	for i, r := range reqs {
		rm := asMap(r)
		if rm == nil {
			continue
		}
		out = append(out, hitlRequest{
			Namespace:    w.Namespace,
			CheckpointID: w.CheckpointID,
			TaskID:       w.TaskID,
			InterruptID:  id,
			Index:        i,
			Name:         firstString(rm, "name"),
			Args:         asMap(rm["args"]),
		})
	}
	return out
}

// matchCall finds the tool call an approval request is about among the
// AI-message tool calls written by the same task (the HITL middleware
// re-writes the AI message it paused on). An exact name + arguments match
// wins; otherwise the first unclaimed call of the same name (an `edit`
// decision changes the written arguments). claimed tracks calls already
// paired so two identical requests map to two calls.
func matchCall(r hitlRequest, calls []rawToolCall, claimed map[string]bool) string {
	want := jsonArgs(r.Args)
	for _, c := range calls {
		if c.ID != "" && !claimed[c.ID] && c.Name == r.Name && jsonArgs(c.Args) == want {
			claimed[c.ID] = true
			return c.ID
		}
	}
	for _, c := range calls {
		if c.ID != "" && !claimed[c.ID] && c.Name == r.Name {
			claimed[c.ID] = true
			return c.ID
		}
	}
	return ""
}

// permissionEventID is the stable source event id of an approval request.
func permissionEventID(r hitlRequest, callID string) string {
	if callID != "" {
		return "perm:" + callID
	}
	return fmt.Sprintf("perm:%s:%d", r.InterruptID, r.Index)
}

// argsJSON renders request arguments for RawToolInput.
func argsJSON(args map[string]any) []byte {
	if len(args) == 0 {
		return nil
	}
	b, err := json.Marshal(args)
	if err != nil {
		return nil
	}
	return b
}

// asSlice returns v as a list or nil.
func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}
