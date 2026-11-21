// Package promptturn is the ONE owner of "what is the developer's newest
// prompt in this request body" across the four LLM wire shapes the node
// proxy and the org AI gateway carry: Anthropic Messages, OpenAI Chat
// Completions, the OpenAI Responses API and Gemini generateContent.
//
// Three callers share it (P-228, docs/plans/discovery-admission-2026-11-03.md):
// the Plane-B prompt guard's proxy lane (internal/guard), the org AI
// gateway's planeb.admission gate (internal/orgserver/planebadmit) and the
// node proxy's coding-agent admission lane (cmd/observer). Before it existed
// each had its own extractor and they disagreed: the gateway re-judged the
// original prompt on every request of an OpenAI tool loop and handed EMPTY
// text to the judge on every Anthropic tool-loop request.
//
// Classify answers these things about one request body:
//
//   - Kind: user_prompt (the newest turn is something the developer typed),
//     continuation (the newest turn is a tool result the agent is feeding
//     back mid-loop, so the prompt that started the loop was already seen
//     when it was newest) or none (no user turn at all, or an unparseable
//     body);
//   - Text: the developer's text of a user_prompt turn (tool_result blocks
//     never count; the developer did not type a tool's output);
//   - Trailing: every new inbound item after the last assistant turn,
//     user text AND tool results, which is what an all_calls admission
//     scope judges;
//   - Generated: what the model or a tool produced in the newest exchange
//     (the newest assistant turn and the trailing tool results, never the
//     developer's text), which the prompt guard notes so a value the
//     conversation already carried is not judged as typed when a side
//     request re-sends it as user text.
//
// Branching is on WIRE SHAPE (a JSON schema), never on the client tool
// (CLAUDE.md rule 3). Parsing is tolerant: a shape mismatch yields a
// smaller answer, never an error or a panic.
//
// Pure package: no database/sql, net/http or fsnotify (imports_test.go).
package promptturn
