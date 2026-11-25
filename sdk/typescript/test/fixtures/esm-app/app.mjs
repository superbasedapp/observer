// An ESM app with no superbased code: it is started with
// `node --import @superbased/sdk/register app.mjs` (plan 3.3). It imports
// openai statically, calls a loopback stub (STUB_URL), and prints what the
// SDK reports. The spans go wherever the environment says (the test points
// SUPERBASED_OTLP_ENDPOINT at the same stub).
import OpenAI from "openai";

const client = new OpenAI({ apiKey: "sk-fixture", baseURL: `${process.env.STUB_URL}/v1` });
await client.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: "Capital of France?" }] });

// Only to report back: the app itself needs none of this.
const sb = await import("@superbased/sdk");
const { registered } = await import("@superbased/sdk/register");
await sb.flush(5000);
const d = sb.diagnostics();
console.log(JSON.stringify({ registered: registered(), instrumented: sb.instrumented(), openai: d.instrumented.openai, mode: d.mode, service: d.serviceName }));
