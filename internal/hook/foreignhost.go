package hook

import (
	"encoding/json"
	"strings"
)

// Another host can run the hook commands a user registered for Claude
// Code. cursor-agent does (grounded against the 2026.08.25 bundle, and the
// 2026.09.18 debug log's `cli.hook.executed` records with
// hookSource "claude-user"): it loads ~/.claude/settings.json (plus the
// project's .claude/settings*.json), maps each Claude event onto its own
// step (UserPromptSubmit -> beforeSubmitPrompt, PreToolUse -> preToolUse,
// PostToolUse -> postToolUse, Stop -> stop, SubagentStop -> subagentStop,
// SessionStart -> sessionStart, SessionEnd -> sessionEnd, PreCompact ->
// preCompact) and runs the command with the SAME stdin payload it gives its
// own hooks: Cursor's field set, `hook_event_name` set to the Cursor step
// name, and `cursor_version` always present. The hookSource label lives
// only in Cursor's own analytics log, never in the payload.
//
// Such a payload reaching the claude-code receiver is not a Claude Code
// event. Observer's cursor receiver already sees the same call through
// Cursor's own hooks.json, so handling it again would evaluate the guard
// twice, write pidbridge / compaction / account rows under the wrong tool,
// and count nothing Observer does not already have. So the receiver
// records nothing and evaluates nothing; it only answers.
//
// Hook-parity Lane C3 / T-034h (2026-10-03): the answer used to be an EMPTY
// stdout, which cursor-agent logs as a FAILED hook (errorClass empty_stdout,
// node 1 debug log 2026-10-03T09:00, every claude-user step). The reply is
// now the host's own neutral answer for the step (ForeignVerdict.Reply), so
// the replayed hook runs cleanly and still decides nothing.
//
// The ruling for every other host (audit section 5.3, Lane C3): a payload
// whose host is POSITIVELY identified by a signature row is answered as
// that row says (Action); a payload that is recognisably NOT Claude Code's
// but matches no row is a no-op (ForeignNoop: empty stdout, exit 0, nothing
// recorded, nothing evaluated).

// ForeignAction is what the claude-code receiver does with a payload another
// host sent.
type ForeignAction string

const (
	// ForeignNeutral: the host's own Observer hook already observes the
	// call; answer with the host's neutral reply, record nothing.
	ForeignNeutral ForeignAction = "neutral"
	// ForeignNoop: recognisably foreign, host not identified: empty
	// stdout, exit 0, nothing recorded, nothing evaluated.
	ForeignNoop ForeignAction = "noop"
	// ForeignDispatch: the host has no Observer hook of its own; the
	// payload is dispatched to the HOST's registry binding for its event
	// (ForeignVerdict.Tool + Step), and answered with the host's neutral
	// reply when that binding has no handler.
	ForeignDispatch ForeignAction = "dispatch"
	// ForeignReroute: the host runs Claude Code's hooks as ITS OWN hook
	// surface (Observer registers nothing of the host's own there), so the
	// payload is the host's call: it is served under the HOST's tool id by
	// the host's binding for the event (its tool gate, prompt gate or
	// lifecycle binding), and answered with the host's neutral reply when
	// that binding has no handler.
	ForeignReroute ForeignAction = "reroute"
)

// ForeignVerdict is the classification of one claude-code hook payload.
type ForeignVerdict struct {
	// Foreign is false for a genuine Claude Code payload (or one that does
	// not decode): the receiver proceeds exactly as before.
	Foreign bool
	// Host is the identified host ("" when unidentified).
	Host string
	// Tool is the registry tool id a ForeignDispatch verdict dispatches
	// to.
	Tool string
	// Action says how to answer.
	Action ForeignAction
	// Step is the host's own event name from the payload.
	Step string
	// Reply is the exact stdout bytes to write (nil: write nothing).
	Reply []byte
}

// hostProbe is the part of a hook payload the signature table reads.
type hostProbe struct {
	CursorVersion *string `json:"cursor_version"`
	HookEventName string  `json:"hook_event_name"`
	// HookEventCamel is Grok Build's own spelling of the event
	// (snake_case value, camelCase key), sent beside hook_event_name.
	HookEventCamel string `json:"hookEventName"`
	SessionID      string `json:"session_id"`
	SessionIDCamel string `json:"sessionId"`
	ConversationID string `json:"conversation_id"`
	// TranscriptPath is kept raw: Kimchi sends an explicit JSON null, which
	// Claude Code never does.
	TranscriptPath json.RawMessage `json:"transcript_path"`
	// kimchiEnv is true when the hook process carries KIMCHI_HOOK_EVENT
	// (set by the classifier from the environment, not the payload).
	kimchiEnv bool
	// copilotHookEnv is true when the hook process carries BOTH
	// COPILOT_CLI and COPILOT_HOOK_DIR, which the Copilot CLI runtime sets
	// on every hook it runs (live check 12). Only the names' presence is
	// read; no value is compared or kept.
	copilotHookEnv bool
}

// transcriptAbsent reports a payload with no transcript_path key at all.
// Claude Code sends the key on every event; the Copilot CLI runtime's
// Claude-compatible payload has none (live check 12).
func (p hostProbe) transcriptAbsent() bool {
	return p.TranscriptPath == nil
}

// transcriptNull reports an explicit "transcript_path": null.
func (p hostProbe) transcriptNull() bool {
	return string(p.TranscriptPath) == "null"
}

// transcriptEmpty reports an explicit empty-string "transcript_path": "",
// which DeepSeek Harness's Claude Code hook bridge always sends (its base()
// payload builder spells the literal). Claude Code always sends its
// transcript path, Kimchi sends null, and a host that omits the key leaves
// TranscriptPath nil, so none of them matches.
func (p hostProbe) transcriptEmpty() bool {
	return string(p.TranscriptPath) == `""`
}

// cortexTranscript reports Cortex Code's transcript shape:
// <data home>/conversations/<session_id>.json (either separator; the data
// home moves with CORTEX_HOME / SNOWFLAKE_HOME, so only the last two
// elements are matched). Claude Code's is projects/<slug>/<id>.jsonl.
func (p hostProbe) cortexTranscript() bool {
	var path string
	if json.Unmarshal(p.TranscriptPath, &path) != nil || path == "" || p.SessionID == "" {
		return false
	}
	return strings.HasSuffix(strings.ReplaceAll(path, `\`, "/"), "/conversations/"+p.SessionID+".json")
}

// uuidV7 reports a session id in the canonical UUID form with version 7
// (Kimchi's ids; Claude Code's are version 4).
func uuidV7(id string) bool {
	return len(id) == 36 && id[8] == '-' && id[13] == '-' && id[14] == '7' && id[18] == '-' && id[23] == '-'
}

// cursorSteps are the Cursor step names cursor-agent puts in
// hook_event_name when it runs a Claude Code hook (the targets of its
// Claude-event mapping). Claude Code itself spells every event in
// PascalCase, so none of these can come from Claude Code.
//
// They are spelled out here, not taken from internal/adapter/cursor: this
// classifier belongs to the claude-code receiver, which a build without
// adapter.cursor still has (lane MP-L1D, T-598).
// TestForeignCursorStepsMatchTheAdapter pins them to the adapter's own
// constants in every build that has the adapter.
var cursorSteps = map[string]bool{
	"beforeSubmitPrompt": true,
	"preToolUse":         true,
	"postToolUse":        true,
	"stop":               true,
	"subagentStop":       true,
	"sessionStart":       true,
	"sessionEnd":         true,
	"preCompact":         true,
}

// cursorNeutralReplies is cursor-agent's neutral answer per step: the bytes
// Observer's OWN cursor receiver writes when it has no opinion on that step
// (internal/hook/cursor.go: {"continue":true} on beforeSubmitPrompt, a reply
// without a permission field elsewhere). A step not listed answers {}.
var cursorNeutralReplies = map[string][]byte{
	"beforeSubmitPrompt": []byte(`{"continue":true}` + "\n"),
}

// neutralObject is the default neutral reply: an empty JSON object.
var neutralObject = []byte("{}\n")

func cursorNeutral(step string) []byte {
	if r, ok := cursorNeutralReplies[step]; ok {
		return r
	}
	return neutralObject
}

// foreignHostSignatures is the ordered signature table: the first row
// whose match holds names the host. Adding a host that runs Claude Code
// hooks is adding a row; a row may only DISPATCH or answer for a host once
// its signature is grounded on a live capture (audit section 5.3 ruling) or,
// since the surface-gap foreign-host lane (w5-foreign, 2026-10-26), on the
// vendor's own source naming the exact field value the row matches, with the
// live capture owed and recorded in the surface-gap pending tracker. A host
// whose payload carries no field that tells it from Claude Code gets no row
// (Devin CLI and VS Code Copilot below): an inferred signature could take a
// genuine Claude Code call off its gate.
//
// Live grounding (node 1, 2026-10-03, hook-parity Lane C):
//   - cursor-agent 2026.10.01-14929f9: cursor_version on every replayed
//     step; the neutral replies below log status "success" for every
//     claude-user step (sessionStart, preToolUse, postToolUse,
//     sessionEnd), and the shell tool still ran with and without --force.
//   - Grok Build 1.0.46 (`grok -p`): runs ~/.claude/settings.json hooks
//     with BOTH spellings: session_id + sessionId, hook_event_name
//     (PascalCase, e.g. "SessionEnd") + hookEventName (snake_case value,
//     "session_end"), plus workspaceRoot. Claude Code never sends
//     hookEventName. Its sessionId is the ~/.grok/sessions/<cwd>/<sid>/
//     bundle directory the grok adapter keys sessions on, so its lifecycle
//     events are DISPATCHED to the grok row's lifecycle bindings (grok has
//     no Observer hook of its own).
//   - Devin CLI 3000.11.3 (`devin -p`): ran NO Claude Code hook, so no row.
//
// Live grounding (2026-10-21 wave, docs/guard.md):
//   - Snowflake Cortex Code 1.2.18 reads ~/.claude/settings.json hooks as
//     its own and sends Claude's field set minus prompt_id; its
//     transcript_path is <data home>/conversations/<session_id>.json
//     (~/.snowflake/cortex by default, backslashes on Windows) and its
//     session_id is the cortex adapter's session id, so the call is
//     REROUTED to the cortex-code row. Its CORTEX_* environment does not
//     survive the wsl.exe bridge, so the row matches the payload only.
//   - Kimchi (claude-code-hook-adapter resource, default off) sends
//     "transcript_path": null, a UUIDv7 session_id (the kimchi adapter's
//     id) and sets KIMCHI_HOOK_EVENT in the hook's environment; Claude Code
//     never sends a null transcript_path. Rerouted to the kimchi row. A
//     Kimchi started inside Claude Code inherits CLAUDE_CODE_SESSION_ID, so
//     that variable is never a signal.
//
// Vendor-source grounding (surface-gap S-20, lane w5-foreign, 2026-10-26):
//   - DeepSeek Harness's experimental @deepseek-ai/dsh-hooks-claude-code
//     plugin (0.2.1-rc.3, lib/index.js) runs the hooks of the Claude Code
//     settings file its configPath names. Its base() payload is session_id
//     (the agent session header id), transcript_path: "" (always the empty
//     literal) and hook_event_name, plus cwd and the per-event fields;
//     PreToolUse carries tool_name verbatim from the harness (bash, pwsh,
//     edit), so its tool vocabulary is DeepSeek's. DeepSeek has no Observer
//     hook of its own placed (the plugin shim has no install location,
//     AP-016), so the call is REROUTED to the deepseek row's replay bindings.
//     Live capture owed (pending tracker LCX-4).
//
// No row, and why (surface-gap S-10, S-20, IDE-7):
//   - Devin CLI: the vendor documents read_config_from.claude (default on)
//     and a payload of hook_event_name, tool_name, tool_input, session_id and
//     prompt_id, all of which Claude Code also sends; lowercase tool names
//     (exec, edit) are shared with VS Code Copilot, and 3000.11.3 `devin -p`
//     ran none. Devin's own Observer hook in ~/.config/devin/config.json
//     already gates the call, so a replay is a double evaluation at worst.
//     Waits on a live capture (pending tracker LCX-3).
//   - Whether VS Code also runs ~/.claude/settings.json hooks
//     (chat.useClaudeHooks) is untested (live check 12b); the copilot-cli row
//     below covers any Claude-shaped payload the Copilot runtime sends.
//
// Live grounding (live check 12, 2026-10-26, surface-gap IDE-7 / S-20): VS
// Code 1.143.1 on Windows, Copilot Chat Agent mode with the local agent, a
// logging hook in ~/.copilot/hooks with both a PascalCase PreToolUse and a
// camelCase preToolUse entry. The local agent IS the Copilot CLI runtime
// (session in ~/.copilot/session-state, producer copilot-agent, copilotVersion
// 1.0.100-1) and both entries fired for one call: the camelCase one with the
// Copilot CLI shape (sessionId, toolName, toolArgs), the PascalCase one with a
// Claude-compatible shape: hook_event_name, session_id (the Copilot CLI
// session id), an ISO timestamp, cwd, tool_name mapped to Claude's
// vocabulary (Read for view) and tool_input, and NO transcript_path. The hook
// environment carried COPILOT_CLI and COPILOT_HOOK_DIR (and
// CLAUDE_PROJECT_DIR) and no VSCODE_* or TERM_PROGRAM variable, so the hook
// cannot tell VS Code from the standalone CLI (the ide/vscode stamp needs the
// agent-host.db pointer, a surfaceenrich follow-up). The review's assumed
// VS Code-storage transcript_path signature was wrong. So a Claude-shaped
// payload with no transcript_path whose process carries both variable NAMES
// is the Copilot CLI runtime's (a Claude Code started from a Copilot shell
// may inherit them, but Claude Code always sends transcript_path). Observer's
// own copilot-cli hook in ~/.copilot/hooks/superbased-observer.json sees the
// same call while it is registered, so the row answers NEUTRAL then (the
// cursor precedent). That holds only while the registration is in place
// (surface-gap Wave 5 audit finding 2, G2): with Observer's copilot-cli hook
// absent ([observer.hooks] auto_register off, the file removed), the replay
// is the only gate Observer has on the call, so the row's unregistered
// action REROUTES it to the copilot-cli row's Claude replay binding, the
// deepseek and kimchi way. Whether the registration is present is asked of
// the classifier's ForeignHostEnv.OwnGateRegistered (in production
// OwnGateRegistered: Observer's entries in the registry's own copilot-cli
// target, never a tool-name branch); an unknown answer is "absent", so the
// call is judged (a double evaluation at worst, never an unjudged call).
//
// The cursor rows follow the same rule (surface-gap FU-122, Mac round 4:
// Cursor IDE's Agents window runs both ~/.cursor/hooks.json and
// ~/.claude/settings.json, so every Cursor call reaches the claude-code
// registration too, with cursor_version, conversation_id and the Cursor step
// in hook_event_name). The replayed step IS the cursor step Observer's own
// cursor registration holds (preToolUse, beforeSubmitPrompt), so while that
// registration holds the step the replay answers Cursor's neutral reply and
// the cursor receiver judges the call once. With Observer's cursor hooks
// absent the replay is the only gate Observer has on the call, so it is
// rerouted to the cursor row's own binding for the step (its preToolUse tool
// gate or beforeSubmitPrompt prompt gate); a step with no such served binding
// (the lifecycle and observe steps) keeps the neutral reply and records
// nothing, so no Cursor event is captured twice either way.
//
// The cortex-code row is built for the day its own writer switches on
// (FU-141): Observer's writer for Cortex Code's hooks.json is built and
// switched off behind live check LC18 (register_cortex.go), and its entries
// run `observer hook cortex-code <event>`, so a call that file fires reaches
// the cortex-code receiver directly. While that registration holds the
// replayed gate (and only once its live gate is cleared: OwnGateRegistered
// answers false for a tool whose hook writer waits on a live check) the
// Claude settings replay of the same call answers neutral; otherwise, which
// is every node today, it is rerouted and judged as cortex-code as before.
var foreignHostSignatures = []struct {
	host   string
	tool   string
	match  func(hostProbe) bool
	action ForeignAction
	// unregistered, when non-empty, replaces action while the host's own
	// Observer gate for the replayed step is not registered on this node
	// (ForeignHostEnv.OwnGateRegistered): the row's action holds only
	// because that registration sees the same call.
	unregistered ForeignAction
	reply        func(step string) []byte
}{
	{host: "cursor", tool: "cursor", match: func(p hostProbe) bool { return p.CursorVersion != nil }, action: ForeignNeutral, unregistered: ForeignReroute, reply: cursorNeutral},
	{host: "cursor", tool: "cursor", match: func(p hostProbe) bool { return cursorSteps[p.HookEventName] }, action: ForeignNeutral, unregistered: ForeignReroute, reply: cursorNeutral},
	{host: "grok", tool: "grok", match: func(p hostProbe) bool { return p.HookEventCamel != "" }, action: ForeignDispatch, reply: func(string) []byte { return neutralObject }},
	{host: "cortex-code", tool: "cortex-code", match: hostProbe.cortexTranscript, action: ForeignNeutral, unregistered: ForeignReroute, reply: func(string) []byte { return neutralObject }},
	{host: "kimchi", tool: "kimchi", match: func(p hostProbe) bool { return p.transcriptNull() && (p.kimchiEnv || uuidV7(p.SessionID)) }, action: ForeignReroute, reply: func(string) []byte { return neutralObject }},
	{host: "copilot-cli", tool: "copilot-cli", match: func(p hostProbe) bool { return p.copilotHookEnv && p.transcriptAbsent() }, action: ForeignNeutral, unregistered: ForeignReroute, reply: func(string) []byte { return neutralObject }},
	{host: "deepseek", tool: "deepseek", match: hostProbe.transcriptEmpty, action: ForeignReroute, reply: func(string) []byte { return neutralObject }},
}

// ForeignHostTools returns the registry tool id of every host a signature row
// positively identifies, in table order without repeats (cursor, grok,
// cortex-code, kimchi, copilot-cli, deepseek). A row that names no tool of its own
// contributes its host. Pinned against hookdisable's replay-host list, so a
// host whose replay Observer recognises is also a host the Claude Code
// hook-off switches silence.
func ForeignHostTools() []string {
	seen := map[string]bool{}
	var out []string
	for _, row := range foreignHostSignatures {
		t := row.tool
		if t == "" {
			t = row.host
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// recognisablyForeign reports a payload Claude Code cannot have sent:
// Claude Code spells every hook_event_name in PascalCase and always sends
// session_id, so an event name that starts lower-case, or a session key
// spelled the way other hosts spell it (sessionId, conversation_id) with no
// session_id at all, came from another host. Deliberately narrow: a
// payload that merely LOOKS like Claude Code's is treated as Claude Code's
// (today's behaviour) until a live-grounded signature row says otherwise.
func recognisablyForeign(p hostProbe) bool {
	if n := p.HookEventName; n != "" && n[0] >= 'a' && n[0] <= 'z' {
		return true
	}
	if strings.TrimSpace(p.SessionID) == "" && (p.SessionIDCamel != "" || p.ConversationID != "") {
		return true
	}
	return false
}

// ClassifyClaudeHookPayload classifies a payload that reached a Claude Code
// hook command: genuine (Foreign false), from an identified host, or
// recognisably foreign but unidentified (ForeignNoop).
func ClassifyClaudeHookPayload(body []byte) ForeignVerdict {
	return ClassifyClaudeHookPayloadEnv(body, nil)
}

// ClassifyClaudeHookPayloadEnv is ClassifyClaudeHookPayload with the hook
// process's environment (getenv; nil reads none), for the hosts a signature
// row recognises partly by an environment variable they set. It asks no
// registration probe, so a row whose action depends on the host's own
// registration takes its unregistered action.
func ClassifyClaudeHookPayloadEnv(body []byte, getenv func(string) string) ForeignVerdict {
	return ClassifyClaudeHookPayloadHost(body, ForeignHostEnv{Getenv: getenv})
}

// ForeignHostEnv is what the classifier reads beyond the payload.
type ForeignHostEnv struct {
	// Getenv reads the hook process's environment (nil reads none).
	Getenv func(string) string
	// OwnGateRegistered reports whether Observer's own hook registration
	// for tool holds the gate a replayed Claude Code step maps to (see
	// OwnGateRegistered). nil, like a false answer, means not known to be
	// registered.
	OwnGateRegistered func(tool, step string) bool
}

// ClassifyClaudeHookPayloadHost is ClassifyClaudeHookPayloadEnv with the
// host's own registration probe, for the signature rows whose answer holds
// only while the host's own Observer hook is registered.
func ClassifyClaudeHookPayloadHost(body []byte, env ForeignHostEnv) ForeignVerdict {
	var p hostProbe
	if err := json.Unmarshal(body, &p); err != nil {
		return ForeignVerdict{}
	}
	if getenv := env.Getenv; getenv != nil {
		p.kimchiEnv = strings.TrimSpace(getenv("KIMCHI_HOOK_EVENT")) != ""
		p.copilotHookEnv = getenv("COPILOT_CLI") != "" && getenv("COPILOT_HOOK_DIR") != ""
	}
	for _, row := range foreignHostSignatures {
		if row.match(p) {
			action := row.action
			if row.unregistered != "" && (env.OwnGateRegistered == nil || !env.OwnGateRegistered(row.tool, p.HookEventName)) {
				action = row.unregistered
			}
			v := ForeignVerdict{Foreign: true, Host: row.host, Tool: row.tool, Action: action, Step: p.HookEventName}
			if row.reply != nil {
				v.Reply = row.reply(p.HookEventName)
			}
			return v
		}
	}
	if recognisablyForeign(p) {
		return ForeignVerdict{Foreign: true, Action: ForeignNoop, Step: p.HookEventName}
	}
	return ForeignVerdict{}
}

// ForeignClaudeHookHost reports the host that sent a payload to a Claude
// Code hook command when that host is NOT Claude Code ("" and false for a
// genuine Claude Code payload, or one that does not decode - the caller
// then proceeds exactly as before). An unidentified foreign payload reports
// host "unidentified".
func ForeignClaudeHookHost(body []byte) (string, bool) {
	v := ClassifyClaudeHookPayload(body)
	if !v.Foreign {
		return "", false
	}
	if v.Host == "" {
		return "unidentified", true
	}
	return v.Host, true
}

// A hook file Observer writes for ONE tool can be read by several surfaces
// of the same vendor. Antigravity's ~/.gemini/config/hooks.json is written by
// the antigravity-cli registration (`observer hook antigravity-cli <event>`),
// and the vendor documents that the Antigravity App and the Antigravity IDE
// read the same file (https://antigravity.google/docs/hooks?tab=ide, fetched
// 2026-10-26). Every agy hook payload carries transcriptPath, which the same
// page defines as <app_data_dir>/brain/<conversationId>/.system_generated/
// logs/transcript.jsonl, with app_data_dir ~/.gemini/antigravity (the App),
// ~/.gemini/antigravity-ide (the IDE) and ~/.gemini/antigravity-cli (the
// CLI). The antigravity adapter captures the desktop conversations from the
// first of those (internal/adapter/antigravity watch roots). So a payload
// whose transcript lies under the App or IDE data directory is that
// surface's call: its verdict belongs to the antigravity row, not the CLI's
// (surface-gap W-2c / IDE-10). The receiver serves it with the surface's own
// binding, which declares it rides the registered tool's file
// (HookBinding.ReplayedVia).
//
// The ancestor process the review suggested is not used: the hook runs
// through cmd /c on Windows and through the wsl.exe bridge when the daemon is
// in WSL, where no ancestry survives, while the payload field crosses both.

// hookSurfaceProbe is the part of a payload the surface table reads.
type hookSurfaceProbe struct {
	TranscriptPath string `json:"transcriptPath"`
}

// underAppDataDir reports a transcriptPath inside <app_data_dir>/brain/ for
// the product data directory named dir (either separator, case-insensitive
// for Windows paths). The vendor documents app_data_dir as a fixed
// directory under the user's gemini home (~/.gemini/<dir>); only the last
// two elements are compared, so the match holds wherever that home lives
// (the cortexTranscript precedent), while antigravity-cli and the other
// product directories never match another's whole element.
func (p hookSurfaceProbe) underAppDataDir(dir string) bool {
	path := strings.ToLower(strings.ReplaceAll(p.TranscriptPath, `\`, "/"))
	return path != "" && strings.Contains(path, "/"+dir+"/brain/")
}

// sharedHookFileSurfaces is the ordered table of surfaces that run a hook
// file another tool's registration wrote: registered is the tool id in the
// hook command, tool the surface's registry tool id. The first row whose
// registered tool and match hold names the surface; no row keeps the
// registered tool.
var sharedHookFileSurfaces = []struct {
	registered string
	tool       string
	match      func(hookSurfaceProbe) bool
}{
	{registered: "antigravity-cli", tool: "antigravity", match: func(p hookSurfaceProbe) bool { return p.underAppDataDir("antigravity") }},
	{registered: "antigravity-cli", tool: "antigravity", match: func(p hookSurfaceProbe) bool { return p.underAppDataDir("antigravity-ide") }},
}

// SurfaceTool reports the registry tool whose surface sent body through
// the hook command of registered, when that is another tool sharing the
// registered tool's hook file (sharedHookFileSurfaces). ok is false (and the
// tool is registered) for the registered tool's own payload, an undecodable
// one, or a tool no row names; a tool with no row costs no decode.
func SurfaceTool(registered string, body []byte) (string, bool) {
	var p hookSurfaceProbe
	decoded := false
	for _, row := range sharedHookFileSurfaces {
		if row.registered != registered {
			continue
		}
		if !decoded {
			if json.Unmarshal(body, &p) != nil {
				return registered, false
			}
			decoded = true
		}
		if row.match(p) {
			return row.tool, true
		}
	}
	return registered, false
}

// RecordForeignReplay appends the forensic hook-events.jsonl row for a
// foreign payload the claude-code receiver answered without recording.
func RecordForeignReplay(label string, v ForeignVerdict, bytes int) {
	host := v.Host
	if host == "" {
		host = "unidentified"
	}
	appendHookEventLog(hookEvent{Event: label, Bytes: bytes, Action: "foreign:" + host + ":" + string(v.Action)})
}
