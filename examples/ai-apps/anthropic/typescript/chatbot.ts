// A small support chatbot on the Anthropic TypeScript SDK, traced with superbased.
//
// init() then instrument(["anthropic"]) (ESM: hand the module over),
// per-request identity with propagateAttributes, three turns (one with a tool
// call: tool_use / tool_result blocks), one call with summarized thinking, one
// streamed call, and a prompt-caching pair (the same long system prompt sent
// twice with cache_control: the first call writes the cache, the second reads
// it). Every call uses claude-haiku-5-5 at low effort (output_config.effort);
// no temperature, no thinking budget (Haiku 5.5 refuses both). Runs on Node 22
// as plain .ts (type stripping). With AI_GATEWAY_URL set, calls go through the
// org's AI gateway with gatewayFetch(), which sends the app identity headers
// and stamps the gateway's request id on the LLM span.
//
// Anthropic reports usage.input_tokens NET of the cache; run.json records the
// whole (gross) prompt, input_tokens + cache_creation + cache_read, which is
// what superbased stores as a span's input tokens.
import { writeFileSync } from "node:fs";
import {
  diagnostics, flush, gatewayFetch, getCurrentTraceId, init, instrument, Kind,
  propagateAttributes, shutdown, withSpan, withToolSpan, setToolResult,
} from "@superbased/sdk";

const SERVICE = process.env.SUPERBASED_SERVICE_NAME ?? "anthropic-chatbot-ts";
const RUN_ID = process.env.RUN_ID ?? String(Date.now());
const MODEL = "claude-haiku-5-5";
const EFFORT = { effort: "low" as const };
const USER = "user-ada";

init({ serviceName: SERVICE, release: "examples-1" });
const anthropicModule = await import("@anthropic-ai/sdk");
console.error("instrument:", instrument(["anthropic"], { modules: { anthropic: anthropicModule } }));
const Anthropic = anthropicModule.default;

const client = process.env.AI_GATEWAY_URL
  // The gateway root (the SDK adds /v1/messages); its key is a bearer token.
  ? new Anthropic({ baseURL: process.env.AI_GATEWAY_URL, apiKey: null, authToken: process.env.AI_GATEWAY_KEY, fetch: gatewayFetch() })
  : new Anthropic(); // ANTHROPIC_API_KEY from the environment

const orderTool = {
  name: "get_order_status",
  description: "Look up the shipping status of an order by its id.",
  input_schema: { type: "object" as const, properties: { order_id: { type: "string" } }, required: ["order_id"] },
};
const getOrderStatus = (orderId: string) => JSON.stringify({ order_id: orderId, status: "shipped", eta_days: 2 });

const SYSTEM = "You are a terse support bot. Answer in one sentence.";
// Long enough to cache on Haiku 5.5; the run id makes each run write its own entry.
const POLICY = `Policy set ${RUN_ID}.\n` + Array.from({ length: 89 }, (_, k) => {
  const i = k + 1;
  return `Policy ${i}: Orders placed on business day ${i} ship within ${(i % 3) + 1} business days; ` +
    `returns for those orders are accepted within 30 days with the original receipt, ` +
    `refunds go to the original payment method within ${(i % 5) + 3} days, and store credit ` +
    `is offered when the receipt is missing. Gift orders follow the same rule.`;
}).join("\n");

type Call = { kind: string; id: string; input: number; input_net: number; cache_write: number; cached: number; output: number; thinking_blocks: number };
const calls: Call[] = [];
const record = (kind: string, msg: any) => {
  const u = msg.usage;
  const write = u.cache_creation_input_tokens ?? 0, read = u.cache_read_input_tokens ?? 0;
  calls.push({ kind, id: msg.id, input: u.input_tokens + write + read, input_net: u.input_tokens,
    cache_write: write, cached: read, output: u.output_tokens,
    thinking_blocks: msg.content.filter((b: any) => b.type === "thinking").length });
};
const textOf = (msg: any) => msg.content.filter((b: any) => b.type === "text").map((b: any) => b.text).join("");

async function ask(messages: any[]) {
  const msg = await client.messages.create({
    model: MODEL, max_tokens: 2000, output_config: EFFORT, system: SYSTEM, tools: [orderTool], messages,
  });
  record("messages", msg);
  return msg;
}

const user = USER, session = `chat-ts-${RUN_ID}`, tenant = "acme";
const traceIds: string[] = [];

await propagateAttributes({ user, sessionId: session, tenant, tags: ["example"] }, async () => {
  const messages: any[] = [];
  const turns = ["Hi! What can you help me with?", "Where is my order A-1001?", "Thanks. Say goodbye in five words."];
  for (const [i, text] of turns.entries()) {
    await withSpan(`turn-${i + 1}`, Kind.AGENT, async () => {
      traceIds.push(getCurrentTraceId());
      messages.push({ role: "user", content: text });
      let msg = await ask(messages);
      while (msg.stop_reason === "tool_use") {
        // The whole assistant turn goes back unchanged (thinking blocks
        // included), then every tool_result in one user message.
        messages.push({ role: "assistant", content: msg.content });
        const results: any[] = [];
        for (const b of msg.content as any[]) {
          if (b.type !== "tool_use") continue;
          const result = await withToolSpan("get_order_status", { toolName: b.name, callId: b.id, arguments: b.input },
            async (span) => { const r = getOrderStatus(b.input.order_id); setToolResult(span, r); return r; });
          results.push({ type: "tool_result", tool_use_id: b.id, content: result });
        }
        messages.push({ role: "user", content: results });
        msg = await ask(messages);
      }
      messages.push({ role: "assistant", content: msg.content });
      console.log(`turn ${i + 1}: ${JSON.stringify(text)} -> ${JSON.stringify(textOf(msg))}`);
    });
  }
  await withSpan("thinking", Kind.AGENT, async () => {
    traceIds.push(getCurrentTraceId());
    const msg = await client.messages.create({
      model: MODEL, max_tokens: 4000, output_config: EFFORT, thinking: { type: "adaptive", display: "summarized" },
      messages: [{ role: "user", content: "Alice is older than Bob. Carol is younger than Dan but older than Alice. " +
        "Erin is older than Dan. Who is the second oldest? Check carefully, then answer with one name." }],
    });
    record("thinking", msg);
    console.log("thinking:", JSON.stringify(textOf(msg)), `(${calls.at(-1)!.thinking_blocks} thinking block(s))`);
  });
  await withSpan("streamed", Kind.AGENT, async () => {
    traceIds.push(getCurrentTraceId());
    const stream = client.messages.stream({
      model: MODEL, max_tokens: 2000, output_config: EFFORT,
      messages: [{ role: "user", content: "Count to three, digits only." }],
    });
    let text = "";
    stream.on("text", (t: string) => { text += t; });
    const final = await stream.finalMessage();
    record("stream", final);
    console.log("streamed:", JSON.stringify(text));
  });
  for (const n of [1, 2]) {
    await withSpan(`cached-${n}`, Kind.AGENT, async () => {
      traceIds.push(getCurrentTraceId());
      const msg = await client.messages.create({
        model: MODEL, max_tokens: 1000, output_config: EFFORT,
        system: [{ type: "text", text: `${SYSTEM}\n\n${POLICY}`, cache_control: { type: "ephemeral" } }],
        messages: [{ role: "user", content: `Question ${n}: how long do refunds take for orders from business day ${n + 10}?` }],
      });
      record(`cached-${n}`, msg);
      const c = calls.at(-1)!;
      console.log(`cached-${n}: cache write ${c.cache_write}, cache read ${c.cached}, uncached input ${c.input_net}: ${JSON.stringify(textOf(msg))}`);
    });
  }
});

const ok = await flush();
const d = diagnostics();
const out = {
  service: SERVICE, run_id: RUN_ID, user, session, tenant, trace_ids: traceIds, calls,
  diagnostics: { destination: d.destination, destinations: d.destinations, failedExports: d.failedExports, droppedSpans: d.droppedSpans },
};
writeFileSync(process.env.RUN_OUT ?? "run.json", JSON.stringify(out, null, 2));
console.error(JSON.stringify(out.diagnostics));
await shutdown();
process.exitCode = ok ? 0 : 1;
