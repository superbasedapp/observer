package otlpvendor

import "github.com/marmutapp/superbased-observer/internal/models"

// The mapping table. One row per AI tool whose OpenTelemetry export Observer
// maps; docs/plans/otlp-any-adapter-design-2026-10-06.md holds the
// per-adapter grounding (which tools export at all, from where, and why the
// rest are not here). Rows are walked in order: a resource is claimed by the
// first row naming its service.name; an unclaimed resource is read only by
// the rows that set ClaimByEventName.
//
// Every row's Evidence names how its shape was grounded. "live" rows were
// captured from the installed tool against a local mock model endpoint
// (testdata/otlp/<tool>/); "doc"/"source" rows come from the vendor's
// documentation or source and are pinned by a fixture built from it.

// SourceNativeOTel is the api_turns.source tag every non-Claude-Code
// vendor's turns persist with. The tool is on the session row; the tag only
// has to say "a tool's own native telemetry", which the store maps to the
// native-exact merge fidelity.
const SourceNativeOTel = "native_otel"

// sourceCCOTel mirrors store.SourceCCOTel (pinned by a cmd/observer test).
const sourceCCOTel = "cc_otel"

// GenAI semantic-convention keys (open-telemetry/semantic-conventions-genai,
// Development status). Both the current and the renamed-away spellings are
// listed so an exporter on either side of a rename maps the same way.
var (
	genAISession    = []string{"gen_ai.conversation.id", "session.id"}
	genAIRequest    = []string{"gen_ai.response.id"}
	genAIModel      = []string{"gen_ai.response.model", "gen_ai.request.model"}
	genAIProvider   = []string{"gen_ai.provider.name", "gen_ai.system"}
	genAIInput      = []string{"gen_ai.usage.input_tokens", "gen_ai.usage.prompt_tokens"}
	genAIOutput     = []string{"gen_ai.usage.output_tokens", "gen_ai.usage.completion_tokens"}
	genAICacheRead  = []string{"gen_ai.usage.cache_read.input_tokens", "gen_ai.usage.cache_read_input_tokens"}
	genAICacheWrite = []string{"gen_ai.usage.cache_write.input_tokens", "gen_ai.usage.cache_creation.input_tokens", "gen_ai.usage.cache_creation_input_tokens"}
	genAIReasoning  = []string{"gen_ai.usage.reasoning.output_tokens", "gen_ai.usage.reasoning_tokens"}
	genAIToolName   = []string{"gen_ai.tool.name"}
	genAIToolCallID = []string{"gen_ai.tool.call.id"}
	genAIToolArgs   = []string{"gen_ai.tool.call.arguments"}
	genAIToolResult = []string{"gen_ai.tool.call.result"}
	genAIError      = []string{"error.type"}
)

// genAIChatTurn is the GenAI-semconv inference span ("chat <model>") as a
// turn rule.
func genAIChatTurn() Rule {
	return Rule{
		Signal: SignalSpans, Names: []string{"chat "}, NamePrefix: true, Kind: KindTurn,
		Where: []Cond{{Key: "gen_ai.operation.name", Equals: "chat"}},
		F: Fields{
			Session: genAISession, Request: genAIRequest, Model: genAIModel, Provider: genAIProvider,
			Input: genAIInput, Output: genAIOutput, CacheRead: genAICacheRead,
			CacheWrite: genAICacheWrite, Reasoning: genAIReasoning,
		},
	}
}

// genAIToolSpan is the GenAI-semconv "execute_tool <name>" span as a tool
// call rule.
func genAIToolSpan() Rule {
	return Rule{
		Signal: SignalSpans, Names: []string{"execute_tool"}, NamePrefix: true, Kind: KindTool,
		Where: []Cond{{Key: "gen_ai.operation.name", Equals: "execute_tool"}},
		F:     Fields{Session: genAISession, ToolName: genAIToolName, CallID: genAIToolCallID, Failure: genAIError},
	}
}

// genAIToolContent captures the execute_tool span's arguments and result
// (present only when the tool's content capture is on).
func genAIToolContent() []Rule {
	base := Rule{
		Signal: SignalSpans, Names: []string{"execute_tool"}, NamePrefix: true, Kind: KindContent,
		Where: []Cond{{Key: "gen_ai.operation.name", Equals: "execute_tool"}},
	}
	in, out := base, base
	in.F = Fields{Session: genAISession, ToolUseID: genAIToolCallID, ContentKind: ContentToolInput, Content: genAIToolArgs}
	out.F = Fields{Session: genAISession, ToolUseID: genAIToolCallID, ContentKind: ContentToolOutput, Content: genAIToolResult}
	return []Rule{in, out}
}

// semconvNorm is the GenAI-semconv token convention: input_tokens SHOULD
// include cache reads and writes, output_tokens SHOULD include reasoning.
var semconvNorm = Normalize{InputIncludesCacheRead: true, InputIncludesCacheWrite: true}

// claudeCodeEvents lists a Claude Code event under both its current
// claude_code.-prefixed name and its legacy bare name.
func claudeCodeEvents(name string) []string { return []string{"claude_code." + name, name} }

var vendors = []Vendor{
	{
		// Claude Code: the original ccotel parser, moved onto the table with
		// its behaviour pinned by internal/adapter/ccotel's tests.
		Tool: "claude-code", ServiceNames: []string{"claude-code"}, ClaimByEventName: true,
		Provider: "anthropic", SourceTag: sourceCCOTel, Grain: GrainUser, NoSessionRows: true,
		// Input is already NET (Anthropic usage), output already gross. No
		// tool-call rule: Claude Code's actions are owned by its hooks and
		// transcript, and this export never wrote actions.
		// Its request_id is the Anthropic request id the proxy stores, so an
		// export turn merges into the proxied row (TokensMergeWithProxy).
		Owner:    Ownership{TokensWithTranscript: true, ContentWithTranscript: true, TokensMergeWithProxy: true},
		Evidence: "doc: code.claude.com/docs/en/monitoring-usage; shape pinned since native-console Phase 2b",
		Rules: []Rule{
			{
				Signal: SignalLogs, Names: claudeCodeEvents("api_request"), Kind: KindTurn, RequireRequest: true,
				F: Fields{
					Request: []string{"request_id", "request.id"}, Model: []string{"model"},
					Session: []string{"session.id", "session_id"},
					Input:   []string{"input_tokens"}, Output: []string{"output_tokens"},
					CacheRead: []string{"cache_read_tokens"}, CacheWrite: []string{"cache_creation_tokens"},
					Cost: []string{"cost_usd"}, Duration: []string{"duration_ms"},
				},
			},
			ccContent("user_prompt", ContentPrompt, "prompt", "user_prompt", "content"),
			ccContent("tool_result", ContentToolOutput, "tool_output", "output", "result", "content"),
			ccContent("tool_decision", ContentToolInput, "tool_input", "input"),
		},
	},
	{
		// Codex CLI ([otel] in $CODEX_HOME/config.toml). Live: codex 0.154.0.
		// service.name is the originator (codex_exec for `codex exec`,
		// codex_cli_rs for the TUI, codex_vscode for the IDE extension).
		Tool:         "codex",
		ServiceNames: []string{"codex_exec", "codex_cli_rs", "codex_vscode", "codex-cli", "codex_tui"},
		Provider:     "openai", SourceTag: SourceNativeOTel, Grain: GrainUser,
		// input_token_count is GROSS (non_cached = input - cached);
		// output_token_count already contains reasoning. The cache-write
		// count is left unmapped: it is counted inside input and the codex
		// rollout transcript does not carry it, so mapping it would break
		// the twin fold against the transcript row.
		Norm:        Normalize{InputIncludesCacheRead: true},
		Owner:       Ownership{TokensWithTranscript: true},
		ActionTypes: map[string]string{"shell": models.ActionRunCommand, "exec_command": models.ActionRunCommand, "apply_patch": models.ActionEditFile, "read_file": models.ActionReadFile},
		Evidence:    "live: codex-cli 0.154.0 against a mock Responses endpoint, 2026-10-06 (testdata/otlp/codex)",
		Rules: []Rule{
			{
				Signal: SignalLogs, Names: []string{"codex.sse_event"}, Kind: KindTurn,
				Where: []Cond{{Key: "event.kind", Equals: "response.completed"}, {Key: "input_token_count"}},
				F: Fields{
					Session: []string{"conversation.id"}, Model: []string{"model"},
					Input: []string{"input_token_count"}, Output: []string{"output_token_count"},
					CacheRead: []string{"cached_token_count"}, Reasoning: []string{"reasoning_token_count"},
				},
			},
			{
				Signal: SignalLogs, Names: []string{"codex.tool_result"}, Kind: KindTool,
				F: Fields{
					Session: []string{"conversation.id"}, ToolName: []string{"tool_name"},
					CallID: []string{"call_id"}, Success: []string{"success"}, Duration: []string{"duration_ms"},
				},
			},
			{
				Signal: SignalLogs, Names: []string{"codex.user_prompt"}, Kind: KindContent,
				F: Fields{Session: []string{"conversation.id"}, ContentKind: ContentPrompt, Content: []string{"prompt"}, ContentPlaceholders: []string{"[REDACTED]"}},
			},
			{
				Signal: SignalLogs, Names: []string{"codex.tool_result"}, Kind: KindContent,
				F: Fields{Session: []string{"conversation.id"}, ToolUseID: []string{"call_id"}, ContentKind: ContentToolInput, Content: []string{"arguments"}},
			},
			{
				Signal: SignalLogs, Names: []string{"codex.tool_result"}, Kind: KindContent,
				F: Fields{Session: []string{"conversation.id"}, ToolUseID: []string{"call_id"}, ContentKind: ContentToolOutput, Content: []string{"output"}},
			},
		},
	},
	{
		// Gemini CLI (telemetry block in ~/.gemini/settings.json). Live:
		// gemini-cli 0.53.1. Its "http" protocol is OTLP/HTTP JSON.
		Tool: "gemini-cli", ServiceNames: []string{"gemini-cli"},
		Provider: "google", SourceTag: SourceNativeOTel, Grain: GrainUser,
		// input_token_count = promptTokenCount (GROSS of cached content);
		// output_token_count = candidatesTokenCount, which EXCLUDES thoughts.
		Norm: Normalize{InputIncludesCacheRead: true, OutputExcludesReasoning: true, ReasoningByTotal: true},
		// NOT TokensWithTranscript: the gemini transcript adapter keys a
		// session by its chat FILE name ("session-<start>-<8 hex>") while
		// the export's session.id is the full uuid inside that file, so the
		// two captures of one call sit in different sessions and cannot
		// fold (proven by cmd/observer TestOTLPTurnsFoldAgainstTranscript).
		// With the gemini adapter enabled the transcript owns the tokens.
		ActionTypes: map[string]string{"run_shell_command": models.ActionRunCommand, "read_file": models.ActionReadFile, "write_file": models.ActionWriteFile, "replace": models.ActionEditFile, "list_directory": models.ActionSearchFiles, "glob": models.ActionSearchFiles, "search_file_content": models.ActionSearchText, "google_web_search": models.ActionWebSearch, "web_fetch": models.ActionWebFetch},
		Evidence:    "live: gemini-cli 0.53.1 against a mock Gemini API endpoint, 2026-10-06 (testdata/otlp/gemini-cli)",
		Rules: []Rule{
			{
				Signal: SignalLogs, Names: []string{"gemini_cli.api_response"}, Kind: KindTurn,
				Where: []Cond{{Key: "input_token_count"}},
				F: Fields{
					Session: []string{"session.id"}, Model: []string{"model"},
					Input: []string{"input_token_count"}, Output: []string{"output_token_count"},
					CacheRead: []string{"cached_content_token_count"}, Reasoning: []string{"thoughts_token_count"},
					Total: []string{"total_token_count"}, Duration: []string{"duration_ms"},
				},
			},
			{
				// No call id on the log record (only on trace spans); the
				// tool call id is synthesized from the record.
				Signal: SignalLogs, Names: []string{"gemini_cli.tool_call"}, Kind: KindTool,
				F: Fields{Session: []string{"session.id"}, ToolName: []string{"function_name"}, Success: []string{"success"}, Duration: []string{"duration_ms"}},
			},
			{
				Signal: SignalLogs, Names: []string{"gemini_cli.user_prompt"}, Kind: KindContent,
				F: Fields{Session: []string{"session.id"}, ContentKind: ContentPrompt, Content: []string{"prompt"}},
			},
			{
				Signal: SignalLogs, Names: []string{"gemini_cli.tool_call"}, Kind: KindContent,
				F: Fields{Session: []string{"session.id"}, ContentKind: ContentToolInput, Content: []string{"function_args"}},
			},
		},
	},
	{
		// Qwen Code (Gemini CLI fork; telemetry block in ~/.qwen/settings.json).
		// Live: qwen-code 0.21.0 against a mock OpenAI-compatible endpoint.
		Tool: "qwen-code", ServiceNames: []string{"qwen-code"},
		Provider: "openai", SourceTag: SourceNativeOTel, Grain: GrainUser,
		// Same event shape as Gemini CLI, but whether output_token_count
		// already contains thoughts depends on the content generator: the
		// OpenAI-compatible one (live capture: 1234 + 56 == total 1290 with
		// 16 thoughts inside the 56) includes them, the Gemini one does
		// not. The record's total decides (T-542); the qwen transcript
		// adapter applies the same rule, so the turn still folds.
		Norm:     Normalize{InputIncludesCacheRead: true, ReasoningByTotal: true},
		Owner:    Ownership{TokensWithTranscript: true},
		Evidence: "live: qwen-code 0.21.0 against a mock chat-completions endpoint, 2026-10-06 (testdata/otlp/qwen-code)",
		Rules: []Rule{
			{
				Signal: SignalLogs, Names: []string{"qwen-code.api_response"}, Kind: KindTurn,
				Where: []Cond{{Key: "input_token_count"}},
				F: Fields{
					Session: []string{"session.id"}, Request: []string{"response_id"}, Model: []string{"model"},
					Input: []string{"input_token_count"}, Output: []string{"output_token_count"},
					CacheRead: []string{"cached_content_token_count"}, Reasoning: []string{"thoughts_token_count"},
					Total: []string{"total_token_count"}, Duration: []string{"duration_ms"},
				},
			},
			{
				Signal: SignalLogs, Names: []string{"qwen-code.tool_call"}, Kind: KindTool,
				F: Fields{Session: []string{"session.id"}, ToolName: []string{"function_name"}, CallID: []string{"call_id"}, Success: []string{"success"}, Duration: []string{"duration_ms"}},
			},
			{
				Signal: SignalLogs, Names: []string{"qwen-code.user_prompt"}, Kind: KindContent,
				F: Fields{Session: []string{"session.id"}, ContentKind: ContentPrompt, Content: []string{"prompt"}},
			},
		},
	},
	{
		// GitHub Copilot CLI (COPILOT_OTEL_ENABLED / OTEL_EXPORTER_OTLP_*).
		// Live: @github/copilot 1.0.77 in BYOK offline mode against a mock.
		// Traces only, http/json by default; every chat span carries
		// gen_ai.conversation.id. invoke_agent spans carry per-message SUMS
		// of their chat spans and are deliberately NOT mapped.
		Tool: "copilot-cli", ServiceNames: []string{"github-copilot"},
		Provider: "github", SourceTag: SourceNativeOTel, Grain: GrainUser, Norm: semconvNorm,
		Evidence: "live: @github/copilot 1.0.77 (BYOK offline) against a mock chat-completions endpoint, 2026-10-06 (testdata/otlp/copilot-cli)",
		Rules:    append([]Rule{genAIChatTurn(), genAIToolSpan()}, genAIToolContent()...),
	},
	{
		// GitHub Copilot Chat in VS Code (github.copilot.chat.otel.*). Same
		// GenAI span family as the CLI per the vendor's monitoring doc.
		Tool: "copilot", ServiceNames: []string{"copilot-chat"},
		Provider: "github", SourceTag: SourceNativeOTel, Grain: GrainUser, Norm: semconvNorm,
		Evidence: "doc: code.visualstudio.com/docs/agents/guides/monitoring-agents + microsoft/vscode-copilot-chat docs/monitoring/agent_monitoring.md",
		Rules:    append([]Rule{genAIChatTurn(), genAIToolSpan()}, genAIToolContent()...),
	},
	{
		// Goose (OTEL_EXPORTER_OTLP_ENDPOINT). http/protobuf. The chat span
		// is goose's stream_response_from_provider; input is GROSS of cache
		// read and write per goose's own token_usage.rs.
		Tool: "goose", ServiceNames: []string{"goose"},
		SourceTag: SourceNativeOTel, Grain: GrainUser, Norm: semconvNorm,
		Evidence: "source: aaif-goose/goose crates/goose/src/agents/reply_parts.rs, ops_toolcalling.rs, token_usage.rs",
		Rules: append([]Rule{
			{
				Signal: SignalSpans, Names: []string{"stream_response_from_provider"}, Kind: KindTurn,
				F: Fields{
					Session: genAISession, Request: genAIRequest, Model: genAIModel, Provider: genAIProvider,
					Input: genAIInput, Output: genAIOutput, CacheRead: genAICacheRead, CacheWrite: genAICacheWrite,
				},
			},
			genAIToolSpan(),
		}, genAIToolContent()...),
	},
	{
		// OpenCode (OTEL_EXPORTER_OTLP_ENDPOINT plus experimental.openTelemetry
		// in opencode.json). Vercel AI SDK v6 spans; ai.streamText.doStream is
		// one provider call. Live opencode 1.15.6 exported logs only (no
		// ai.* spans), so this row is grounded on the AI SDK source.
		Tool: "opencode", ServiceNames: []string{"opencode"},
		SourceTag: SourceNativeOTel, Grain: GrainUser,
		Norm:     Normalize{InputIncludesCacheRead: true, InputIncludesCacheWrite: true},
		Evidence: "source: anomalyco/opencode packages/opencode/src/session/llm.ts + vercel/ai 6.0.168 stream-text.ts",
		Rules: []Rule{
			{
				Signal: SignalSpans, Names: []string{"ai.streamText.doStream", "ai.generateText.doGenerate"}, Kind: KindTurn,
				F: Fields{
					Session:    []string{"session.id", "ai.telemetry.metadata.sessionId"},
					Request:    []string{"ai.response.id", "gen_ai.response.id"},
					Model:      []string{"ai.response.model", "gen_ai.response.model", "ai.model.id"},
					Provider:   []string{"ai.model.provider"},
					Input:      []string{"ai.usage.inputTokens", "gen_ai.usage.input_tokens", "ai.usage.promptTokens"},
					Output:     []string{"ai.usage.outputTokens", "gen_ai.usage.output_tokens", "ai.usage.completionTokens"},
					CacheRead:  []string{"ai.usage.inputTokenDetails.cacheReadTokens", "ai.usage.cachedInputTokens"},
					CacheWrite: []string{"ai.usage.inputTokenDetails.cacheWriteTokens"},
					Reasoning:  []string{"ai.usage.outputTokenDetails.reasoningTokens", "ai.usage.reasoningTokens"},
				},
			},
			{
				Signal: SignalSpans, Names: []string{"ai.toolCall"}, Kind: KindTool,
				F: Fields{Session: []string{"session.id", "ai.telemetry.metadata.sessionId"}, ToolName: []string{"ai.toolCall.name"}, CallID: []string{"ai.toolCall.id"}},
			},
		},
	},
	{
		// xAI Grok Build CLI (GROK_EXTERNAL_OTEL=1 + OTEL_LOGS_EXPORTER=otlp,
		// or [telemetry] in ~/.grok/config.toml). Input is treated as GROSS
		// like the grok transcript adapter's prompt_tokens.
		Tool: "grok", ServiceNames: []string{"grok-cli"},
		Provider: "xai", SourceTag: SourceNativeOTel, Grain: GrainUser,
		Norm:     Normalize{InputIncludesCacheRead: true},
		Evidence: "doc: xai-org/grok-build crates/codegen/xai-grok-pager/docs/user-guide/24-monitoring-usage.md",
		Rules: []Rule{
			{
				Signal: SignalLogs, Names: []string{"grok_code.api_request"}, Kind: KindTurn,
				F: Fields{
					Session: []string{"session.id"}, Model: []string{"model"},
					Input: []string{"input_tokens"}, Output: []string{"output_tokens"},
					CacheRead: []string{"cache_read_tokens"}, Reasoning: []string{"reasoning_tokens"},
					Duration: []string{"duration_ms"},
				},
			},
			{
				Signal: SignalLogs, Names: []string{"grok_code.tool_result"}, Kind: KindTool,
				F: Fields{Session: []string{"session.id"}, ToolName: []string{"tool_name"}, CallID: []string{"tool_use_id"}, Success: []string{"success"}, Duration: []string{"duration_ms"}},
			},
			{
				Signal: SignalLogs, Names: []string{"grok_code.user_prompt"}, Kind: KindContent,
				F: Fields{Session: []string{"session.id"}, ContentKind: ContentPrompt, Content: []string{"prompt"}},
			},
		},
	},
	{
		// Z.AI ZCode CLI agent (OTEL_EXPORTER_OTLP_ENDPOINT). Vendor samples
		// traces at a hard-coded 10%, so this export alone undercounts; the
		// zcode SQLite adapter stays the token owner.
		Tool: "zcode", ServiceNames: []string{"zcode-cli-agent"},
		SourceTag: SourceNativeOTel, Grain: GrainUser,
		Norm:     Normalize{InputIncludesCacheRead: true},
		Evidence: "source: zai-org/ZCode apps/zcode-cli/packages/telemetry/src/agent-trace-runtime.ts (traces sampled at 0.1)",
		Rules: []Rule{
			{
				Signal: SignalSpans, Names: []string{"model_attempt"}, Kind: KindTurn,
				F: Fields{
					Session: []string{"zcode.execution.session_id"},
					Model:   []string{"zcode.model_attempt.response_model", "zcode.model_attempt.requested_model"},
					Input:   []string{"zcode.model_attempt.input_tokens"}, Output: []string{"zcode.model_attempt.output_tokens"},
					CacheRead: []string{"zcode.model_attempt.cache_read_tokens"}, CacheWrite: []string{"zcode.model_attempt.cache_write_tokens"},
					Reasoning: []string{"zcode.model_attempt.reasoning_tokens"},
				},
			},
			{
				Signal: SignalSpans, Names: []string{"tool_execution"}, Kind: KindTool,
				F: Fields{Session: []string{"zcode.execution.session_id"}, ToolName: []string{"zcode.tool_execution.tool_name"}, CallID: []string{"zcode.execution.tool_call_id"}, Failure: genAIError},
			},
		},
	},
	{
		// IBM Bob Shell (OTEL_EXPORTER_OTLP_ENDPOINT, or the OtelConfiguration
		// policy). Live: bobshell 2.0.6, 2026-10-22 (testdata/otlp/ibm-bob).
		// The external exporter passes only an attribute allow-list, which
		// carries NO token counts: the "LLM Generation" span has the Bob
		// tier alias (premium-ide), the call's cost in Bobcoins (not USD) and
		// its duration. There is therefore no turn rule (a zero-token turn
		// priced in Bobcoins would be wrong twice); the bob.db adapter owns
		// the session, and the export maps only its "Tool Used" spans, which
		// land when that adapter is disabled. gen_ai.conversation.id is the
		// bob.db task id, so a call lands in the adapter's own session.
		// No TranscriptTiming: the LLM Generation span's duration
		// (gen_ai.client.operation.duration) has nowhere to land, because
		// the ibm-bob adapter writes no token rows (AP-125), and the span
		// carries no per-call id a bob.db message could be matched on.
		Tool: "ibm-bob", ServiceNames: []string{"bob-shell"},
		SourceTag: SourceNativeOTel, Grain: GrainUser,
		ActionTypes: map[string]string{
			"execute_command": models.ActionRunCommand, "read_file": models.ActionReadFile, "office_read": models.ActionReadFile,
			"write_file": models.ActionWriteFile, "apply_diff": models.ActionEditFile, "insert_content": models.ActionEditFile,
			"search_and_replace": models.ActionEditFile, "office_edit": models.ActionEditFile, "list_files": models.ActionSearchFiles,
			"glob": models.ActionSearchFiles, "grep": models.ActionSearchText, "web_fetch": models.ActionWebFetch,
			"web_search": models.ActionWebSearch, "search_ibm_docs": models.ActionWebSearch,
		},
		Evidence: "live: bobshell 2.0.6 (signed-in account) exporting OTLP/HTTP JSON to a local sink, 2026-10-22 (testdata/otlp/ibm-bob)",
		Rules: []Rule{
			{
				// Every tool span is named after its tool; the event type
				// attribute is what marks it.
				Signal: SignalSpans, Names: []string{""}, NamePrefix: true, Kind: KindTool,
				Where: []Cond{{Key: "bob.event.type", Equals: "Tool Used"}},
				F: Fields{
					Session: []string{"gen_ai.conversation.id"}, ToolName: []string{"bob.tool.name"},
					Success: []string{"bob.operation.success"}, Duration: []string{"bob.tool.duration_ms"},
					SuccessFromStatus: true,
				},
			},
		},
	},
	{
		// Tencent CodeBuddy Code (CODEBUDDY_CODE_ENABLE_TELEMETRY=1 +
		// OTEL_TRACES_EXPORTER=otlp). Mock-model capture: codebuddy-code
		// 2.171.0, 2026-10-22 (testdata/otlp/codebuddy). service.name
		// carries the CLI version ("CodeBuddy-CLI-2.171.0"), so the claim is
		// a prefix. Token counts reach span ATTRIBUTES only with
		// OTEL_SEMCONV=agentlens (gen_ai.usage.* on the
		// codebuddy_code.model_stream span); the default semconv puts them
		// in span events. Either way the export reports the GROSS prompt and
		// GROSS completion with no cache-read or reasoning split, which the
		// transcript's rawUsage carries, so the transcript owns tokens while
		// the codebuddy adapter is enabled (the two shapes cannot fold).
		// request.id is the transcript's providerData.messageId.
		// Provider: the spans name no provider; CodeBuddy's gateway (and any
		// custom endpoint) speaks OpenAI chat-completions (the qwen-code
		// precedent).
		Tool: "codebuddy", ServiceNamePrefixes: []string{"CodeBuddy-CLI-"},
		Provider: "openai", SourceTag: SourceNativeOTel, Grain: GrainUser, Norm: semconvNorm,
		// request.id equals the transcript's providerData.messageId, which
		// the adapter stores as token_usage.message_id (proven against the
		// fixture transcript by cmd/observer TestOTLPGenTimingStampsTranscript).
		TranscriptTiming: TimingKeyMessageID,
		ActionTypes: map[string]string{
			"Read": models.ActionReadFile, "Write": models.ActionWriteFile, "Edit": models.ActionEditFile,
			"MultiEdit": models.ActionEditFile, "Bash": models.ActionRunCommand, "Grep": models.ActionSearchText,
			"Glob": models.ActionSearchFiles, "LS": models.ActionSearchFiles, "WebFetch": models.ActionWebFetch,
			"WebSearch": models.ActionWebSearch,
		},
		Evidence: "live (mock model): codebuddy-code 2.171.0 against a loopback chat-completions mock, OTEL_SEMCONV=agentlens and default, 2026-10-22 (testdata/otlp/codebuddy)",
		Rules: []Rule{
			{
				Signal: SignalSpans, Names: []string{"codebuddy_code.model_stream"}, Kind: KindTurn,
				Where: []Cond{{Key: "gen_ai.usage.input_tokens"}},
				F: Fields{
					Session: []string{"gen_ai.session.id", "codebuddy.session_id"}, Request: []string{"request.id"},
					Model: []string{"gen_ai.response.model", "gen_ai.request.model", "model.id"},
					Input: genAIInput, Output: genAIOutput, CacheRead: genAICacheRead, CacheWrite: genAICacheWrite,
					Reasoning: genAIReasoning, TTFT: []string{"gen_ai.response.time_to_first_token", "first_token_ms"},
				},
			},
			{
				// The same call's generation duration for the transcript's own
				// token row (gen_basis otel). model_stream opens when the
				// response starts: in the default-semconv capture it begins
				// right after the codebuddy_code.model_request span, and its
				// first_token_received event's time minus that event's ttft_ms
				// lands within 3 ms of the model_request start (126.289 vs
				// 129.000 ms on the first call, 435.109 vs 435.000 on the
				// second).
				// So the duration is rebuilt from the request start to the
				// stream end (time to first token included, like the
				// diagnostic log's agent.model_call.completed duration_ms the
				// adapter reads natively), never the stream-only span. The
				// session is required: the default semconv puts no session on
				// this span, and the only transcript proving request.id ==
				// messageId is the agentlens capture.
				Signal: SignalSpans, Names: []string{"codebuddy_code.model_stream"}, Kind: KindGenTiming,
				F: Fields{
					Session: []string{"gen_ai.session.id", "codebuddy.session_id"}, Request: []string{"request.id"},
					FirstTokenEvent: "first_token_received", TTFT: []string{"ttft_ms", "first_token_ms", "gen_ai.response.time_to_first_token"},
				},
			},
			{
				// The tool span (codebuddy_code.tool by default, named after
				// the tool under agentlens) has no session attribute; its
				// agent.tool.start_detail / success_detail events carry the
				// session as conversation_id.
				Signal: SignalSpans, Names: []string{"codebuddy_code.tool"}, Kind: KindTool,
				F: codebuddyToolFields,
			},
			{
				Signal: SignalSpans, Names: []string{""}, NamePrefix: true, Kind: KindTool,
				Where: []Cond{{Key: "gen_ai.span.kind", Equals: "TOOL"}},
				F:     codebuddyToolFields,
			},
		},
	},
	{
		// Kimchi (Cast AI). Redirected with telemetry.endpoint /
		// telemetry.metricsEndpoint in ~/.config/kimchi/config.json. Mock-model
		// capture: kimchi 1.17.0, 2026-10-22 (testdata/otlp/kimchi). Its log
		// events reuse Claude Code's bare names (api_request,
		// claude_code.tool_decision, tool_result), so this row must CLAIM
		// service.name "kimchi": unclaimed, the Claude Code row read them
		// and stored each tool_result / tool_decision body (the event name)
		// as otel_content. api_request is the same usage object the
		// transcript records: input NET of cache, output with reasoning
		// inside it and no reasoning count, no request id, and a bare model
		// id where the transcript says provider/model, so it cannot fold
		// against the transcript row and the transcript owns tokens while
		// the kimchi adapter is enabled. Metrics (cumulative claude_code.*
		// sums of the same usage) are not read.
		// No TranscriptTiming: api_request carries no per-call id (its
		// request.trace_id / span_id appear nowhere in the transcript, and
		// request_diagnostics' requestId is a different uuid). Its record
		// time equals the transcript entry's envelope timestamp in the
		// fixture, but that is an emission coincidence, not a key. And the
		// adapter already stamps a native duration from the same record's
		// two clock points, which an otel stamp could never replace.
		Tool: "kimchi", ServiceNames: []string{"kimchi"},
		SourceTag: SourceNativeOTel, Grain: GrainUser,
		ActionTypes: map[string]string{
			"read": models.ActionReadFile, "write": models.ActionWriteFile, "edit": models.ActionEditFile,
			"bash": models.ActionRunCommand, "powershell": models.ActionRunCommand, "grep": models.ActionSearchText,
			"find": models.ActionSearchFiles, "ls": models.ActionSearchFiles, "web_search": models.ActionWebSearch,
			"web_fetch": models.ActionWebFetch,
		},
		Evidence: "live (mock model): kimchi 1.17.0 against a loopback chat-completions mock, telemetry redirected in a throwaway config.json, 2026-10-22 (testdata/otlp/kimchi)",
		Rules: []Rule{
			{
				Signal: SignalLogs, Names: []string{"api_request"}, Kind: KindTurn,
				Where: []Cond{{Key: "input_tokens"}},
				F: Fields{
					Session: []string{"session.id", "pi_session_id"}, Model: []string{"model"}, Provider: []string{"provider"},
					Input: []string{"input_tokens"}, Output: []string{"output_tokens"},
					CacheRead: []string{"cache_read_tokens"}, CacheWrite: []string{"cache_creation_tokens"},
					Cost: []string{"cost_usd"}, Duration: []string{"duration_ms"},
				},
			},
			{
				// No call id on tool_result (only the decision event has
				// one); the call id is synthesized from the record.
				Signal: SignalLogs, Names: []string{"tool_result"}, Kind: KindTool,
				F: Fields{
					Session: []string{"session.id", "pi_session_id"}, ToolName: []string{"tool_name"},
					Success: []string{"success"}, Duration: []string{"duration_ms"},
				},
			},
		},
	},
	{
		// Cursor: Enterprise "OpenTelemetry Export" is sent SERVER-SIDE from
		// Cursor's cloud, once per team. Team grain: the node refuses it (the
		// org server is the destination). The row exists so the resource is
		// claimed (never mis-read by another row) and so the org side reuses
		// one mapping.
		Tool: "cursor", ServiceNames: []string{"cursor"},
		SourceTag: SourceNativeOTel, Grain: GrainTeam,
		// Member identity is on the RESOURCE (cursor.team.id, cursor.user.id,
		// optional cursor.user.account_id and cursor.user.email); runs started
		// with a team API key or service account carry none (vendor doc,
		// re-read 2026-10-06 for T-535). cursor.event.id is the dedupe key,
		// cursor.usage_event.id the request-grain billing key.
		Evidence: "doc: cursor.com/docs/enterprise/opentelemetry-export (+ /wire)",
		Rules: []Rule{
			{
				Signal: SignalLogs, Names: []string{"cursor.api.request", "api_request"}, Kind: KindTurn,
				F: Fields{
					Session: []string{"cursor.conversation.id"}, Request: []string{"cursor.event.id", "cursor.request.id"},
					MemberEmail: []string{"cursor.user.email"}, MemberUserID: []string{"cursor.user.id"},
					MemberAccountID: []string{"cursor.user.account_id"}, MemberTeamID: []string{"cursor.team.id"},
					BillingID: []string{"cursor.usage_event.id"},
					Model:     []string{"cursor.model.name"},
					Input:     []string{"cursor.api.request.input_tokens"}, Output: []string{"cursor.api.request.output_tokens"},
					CacheRead: []string{"cursor.api.request.cache_read_tokens"}, CacheWrite: []string{"cursor.api.request.cache_creation_tokens"},
				},
			},
		},
	},
	{
		// Claude Cowork: exported from inside the Cowork VM to an endpoint
		// set centrally in the org's admin settings, not on the device. Team
		// grain for the same reason as Cursor; claimed so its unprefixed
		// Claude-Code-shaped events are never read as Claude Code.
		Tool: "cowork", ServiceNames: []string{"cowork"},
		Provider: "anthropic", SourceTag: SourceNativeOTel, Grain: GrainTeam,
		Evidence: "doc: claude.com/docs/cowork/monitoring.md",
		Rules: []Rule{
			{
				Signal: SignalLogs, Names: claudeCodeEvents("api_request"), Kind: KindTurn,
				F: Fields{
					Session: []string{"session.id"}, Request: []string{"request_id"}, Model: []string{"model"},
					Input: []string{"input_tokens"}, Output: []string{"output_tokens"},
					CacheRead: []string{"cache_read_tokens"}, CacheWrite: []string{"cache_creation_tokens"},
					Cost: []string{"cost_usd"}, Duration: []string{"duration_ms"},
					// Claude Code's standard attributes (user.email,
					// user.account_uuid, organization.id); doc-grounded.
					MemberEmail: []string{"user.email"}, MemberAccountID: []string{"user.account_uuid"},
					MemberTeamID: []string{"organization.id"},
				},
			},
		},
	},
}

// codebuddyToolFields maps a CodeBuddy tool span under either semconv: the
// span names the tool and its call id, the span's agent.tool.* events carry
// the session (conversation_id) and the vendor-measured duration, and the
// span status carries the outcome.
var codebuddyToolFields = Fields{
	Session: []string{"gen_ai.session.id", "conversation_id"}, ToolName: []string{"tool.name", "tool_name"},
	CallID: []string{"tool.call_id", "call_id"}, Duration: []string{"duration_ms"},
	SuccessFromStatus: true, FromSpanEvents: true,
}

// ccContent is one Claude Code content-event rule.
func ccContent(event, kind string, contentKeys ...string) Rule {
	return Rule{
		Signal: SignalLogs, Names: claudeCodeEvents(event), Kind: KindContent,
		F: Fields{
			Request: []string{"request_id", "request.id"}, Session: []string{"session.id", "session_id"},
			ToolUseID: []string{"tool_use_id", "tool.use_id"}, ContentKind: kind,
			Content: contentKeys, ContentFromBody: true,
		},
	}
}

// Vendors returns a copy of the mapping table, in walk order.
func Vendors() []Vendor {
	out := make([]Vendor, len(vendors))
	copy(out, vendors)
	return out
}

// ForTool returns the mapping row for a registry tool id.
func ForTool(tool string) (Vendor, bool) {
	for _, v := range vendors {
		if v.Tool == tool {
			return v, true
		}
	}
	return Vendor{}, false
}
