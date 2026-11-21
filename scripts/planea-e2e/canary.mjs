// Dry-run canary for one TypeScript example: no provider call, ever.
//
// The runner copies this file next to a node_modules link to the example's
// own node_modules, so every import below resolves to the example's installed
// SDK and framework. It checks that init() resolves a destination, that
// instrument(<targets>, { modules }) answers "instrumented" for each target
// (the framework and its instrumentation are installed and load), and exports
// one synthetic trace (a root AGENT span and one manual LLM span with fixed
// usage) that verify.py then checks on the machine and/or the org.
//
// Argument: one JSON object
//   {"targets": [...], "modules": {"openai": "openai", "vercel-ai": {"ai": "ai", "otel": "@ai-sdk/otel"}},
//    "service": "...", "model": "...", "provider": "...", "out": "/path/run.json"}
// Provider keys are stripped from the environment by the runner.
import { writeFileSync } from "node:fs";

const INPUT = 1000, OUTPUT = 100;
const a = JSON.parse(process.argv[2]);
process.env.ANTHROPIC_OPEN_TELEMETRY ??= "false";

const sb = await import("@superbased/sdk");
const RUN_ID = process.env.RUN_ID ?? String(Date.now());
sb.init({ serviceName: a.service, release: "planea-e2e-canary" });

async function load(spec) {
  if (typeof spec === "string") return await import(spec);
  const out = {};
  for (const [k, v] of Object.entries(spec)) out[k] = await import(v);
  return out;
}
const modules = {};
for (const [k, v] of Object.entries(a.modules ?? {})) modules[k] = await load(v);
const status = a.targets.length ? sb.instrument(a.targets, { modules }) : {};
console.error("instrument:", status);

const user = "user-ada", session = `canary-${RUN_ID}`, tenant = "acme";
const traceIds = [];
await sb.propagateAttributes({ user, sessionId: session, tenant }, () =>
  sb.withSpan("canary-turn", sb.Kind.AGENT, () => {
    traceIds.push(sb.getCurrentTraceId());
    sb.withLlmSpan("canary-chat", { model: a.model, provider: a.provider }, (s) => {
      sb.setUsage(s, { inputTokens: INPUT, outputTokens: OUTPUT, responseModel: a.model });
    });
  }));
await sb.flush();
const d = sb.diagnostics();
writeFileSync(a.out, JSON.stringify({
  service: a.service, run_id: RUN_ID, user, session, tenant, trace_ids: traceIds,
  calls: [{ kind: "canary", input: INPUT, output: OUTPUT, cached: 0 }],
  instrument: status,
  diagnostics: Object.fromEntries(["destination", "destinationSource", "destinations", "signedIn", "credentialSource", "failedExports", "droppedSpans", "notes"]
    .map((k) => [k, d[k]])),
}, null, 2));
await sb.shutdown();
const bad = Object.entries(status).filter(([, v]) => v !== "instrumented" && v !== "already");
if (bad.length) {
  console.error("canary: not instrumented:", Object.fromEntries(bad));
  process.exit(3);
}
