// A route handler that imports its model library statically, as a Next.js
// route module does. Next loads it after instrumentation.register().
import OpenAI from "openai";

export async function POST() {
  const client = new OpenAI({ apiKey: "sk-fixture", baseURL: `${process.env.STUB_URL}/v1` });
  const r = await client.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: "Capital of France?" }] });
  return { answer: r.choices[0].message.content };
}
