# AI Apps examples

Small chatbots that send their traces to superbased's AI Apps, each run live
against OpenAI (`gpt-5-nano`) on 2026-11-20 and checked end to end on a
machine and an organization. Every example reads its OpenAI key from
`OPENAI_API_KEY` only, writes a `run.json` (its trace ids, identity and the
token counts OpenAI reported) and has a `verify.sh` that reads the machine's
(or the organization's) API and exits non-zero when spans, tokens or cost did
not arrive.

| Example | Language | Integration | Shows |
|---|---|---|---|
| [openai/python](openai/python) | Python | `instrument(["openai"])` | chat completions with a tool call, Responses API, streaming; optional AI gateway route (`gateway_exact` cost, app budgets) |
| [openai/typescript](openai/typescript) | TypeScript | `instrument(["openai"])` | the same, with `gatewayFetch()` for the AI gateway |
| [langgraph/python](langgraph/python) | Python | `instrument(["langgraph"])` | ReAct agent, one tool, checkpointer |
| [langgraph/typescript](langgraph/typescript) | TypeScript | `instrument(["langgraph"])` | `createReactAgent`, one tool, `MemorySaver` |
| [openai-agents/python](openai-agents/python) | Python | `instrument(["openai-agents"])` | function tool, session |
| [openai-agents/typescript](openai-agents/typescript) | TypeScript | `instrument(["openai-agents"])` | function tool, history |
| [llama-index/python](llama-index/python) | Python | `instrument(["llama-index"])` | `SimpleChatEngine` and a `FunctionAgent` with a tool |
| [pydantic-ai/python](pydantic-ai/python) | Python | `instrument(["pydantic-ai"])` | agent with one tool, message history |
| [vercel-ai/typescript](vercel-ai/typescript) | TypeScript | `instrument(["vercel-ai"])` | `generateText` with a tool; see its known issue |
| [sdk-direct/python](sdk-direct/python) | Python | none: the SDK's own spans | `admit()`, a registry prompt, manual LLM spans with usage, scores, feedback, `get_trace_cost()`, a dataset experiment with `fail_under` |
| [sdk-direct/java](sdk-direct/java) | Java | none: the SDK's own spans | the same as sdk-direct/python on the Java SDK (`Superbased.admit()`, `getPrompt`, `llmSpan` + `setUsage`, scores, feedback, `getTraceCost()`, `runExperiment` with `failUnder`). Not run live yet: it compiles against the SDK, and the SDK's suite runs the shared contract cases |
| [sdk-direct/go](sdk-direct/go) | Go | none: the SDK's own spans | the same as sdk-direct/python with the Go SDK: `Admit`, a registry prompt, manual LLM spans with usage, scores, feedback, `GetTraceCost`, a dataset experiment with `FailUnder` (not yet run live against OpenAI; see its README) |

## What every example needs

- superbased running on this machine with app observability on
  (`observer components add obs --yes`, `observer config set observability.enabled true`,
  `observer start`), or an organization's trace gateway and an SDK key
  (`SUPERBASED_DESTINATION=online`, `SUPERBASED_ORG_URL`, `SUPERBASED_API_KEY`).
- The SDK from a checkout of this repository, so each example tests the SDK
  beside it (in your own app: `pip install superbased-sdk` or
  `npm install @superbased/sdk`):
  Python `pip install "<repo>/sdk/python[<extra>]"`; TypeScript: `npm install` in
  the example (its `package.json` names the SDK folder; the first install also
  builds the SDK); Java: `mvn -q -f <repo>/sdk/java install -DskipTests`.
- `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.

`verify.py` (standard library only) is shared: `python3 verify.py run.json
--target machine|org [--llm-spans N]`. Against the machine it checks that each
trace has one root and no broken parent link, the end user, session, tenant and
service, every LLM span's model, tokens and cost source, that the trace's token
total equals its LLM spans (nothing counted twice), and that the LLM tokens equal
what OpenAI reported. Against the organization it reads
`/v1/sdk/traces/<id>/cost` with `SUPERBASED_API_KEY` (scope `sdk:read`): each
LLM span's model and cost source.

## gpt-5-nano

It is a reasoning model: pass a completion cap (`max_completion_tokens`,
Responses `max_output_tokens`, LangChain `max_completion_tokens` / JS `maxTokens`,
Pydantic AI `max_tokens`, Agents `ModelSettings(max_tokens=...)`) and a reasoning
effort (`minimal` keeps answers short and cheap), and leave `temperature`
unset. The price book shipped with superbased lists it at $0, so costs read $0
until you set a price (machine `[intelligence.pricing.models."gpt-5-nano"]`,
organization Settings > Pricing).

Findings from the live run that produced these examples:
`docs/plans/plane-a-sdk-buildout/reviews/live-chatbot-e2e-2026-11-20.md`.
