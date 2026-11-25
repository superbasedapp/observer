// As app.mjs, with @google/genai: its instrumentation replaces the
// GoogleGenAI class export, which only works on a namespace the loader hook
// made writable (a plain ESM namespace is sealed).
import { GoogleGenAI } from "@google/genai";

const client = new GoogleGenAI({ apiKey: "fixture", httpOptions: { baseUrl: process.env.STUB_URL } });
const r = await client.models.generateContent({ model: "gemini-2.5-flash", contents: "Capital of France?" });

const sb = await import("@superbased/sdk");
await sb.flush(5000);
console.log(JSON.stringify({ text: r.text, instrumented: sb.instrumented(), gemini: sb.diagnostics().instrumented.gemini }));
