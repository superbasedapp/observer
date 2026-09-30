// Pins the tool-identity tables against the adapter registry: every tool id
// with a row in internal/integration/integration.go (the Go registry, the one
// owner of which tools exist) must have a real logo in the generated
// shared/lib/toolLogos.tsx TOOL_LOGOS table and a label/colour entry in
// shared/lib/tools.ts, and every tool token must be defined in BOTH theme
// blocks of shared/styles/tokens.css. A new adapter fails here until it gets
// its logo (design/brand-icons), TOOLS row and --tool-* tokens.
//
// toolLogos.tsx is JSX, which node's type stripping cannot load, so its keys
// are read from the source text (the generator writes one `"key": {` line
// per entry); tools.ts is plain TS and is imported for real.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { toolMeta } from "../../../shared/lib/tools.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const read = (rel: string) => readFileSync(path.join(root, rel), "utf8");

function registryToolIds(): string[] {
  const src = read("internal/integration/integration.go");
  const ids = [...src.matchAll(/^\s+Tool:\s+"([a-z0-9-]+)",/gm)].map((m) => m[1]);
  return [...new Set(ids)].sort();
}

function toolLogoKeys(): Set<string> {
  const src = read("shared/lib/toolLogos.tsx");
  const start = src.indexOf("export const TOOL_LOGOS");
  const end = src.indexOf("export const TOOL_PIPS");
  const body = src.slice(start, end);
  return new Set([...body.matchAll(/^\s+"([a-z0-9-]+)": \{/gm)].map((m) => m[1]));
}

test("the registry parse found the adapter rows", () => {
  const ids = registryToolIds();
  assert.ok(ids.length >= 45, `expected >= 45 registry tool ids, got ${ids.length}`);
  assert.ok(ids.includes("claude-code"));
});

test("every registry tool id has a TOOL_LOGOS entry", () => {
  const logos = toolLogoKeys();
  const missing = registryToolIds().filter((id) => !logos.has(id));
  assert.deepEqual(missing, [], `tools without a logo: ${missing.join(", ")}`);
});

// Product-family siblings share a token (gemini-cli -> --tool-gemini,
// antigravity-cli -> --tool-antigravity), so the check is "a --tool-* var
// that both themes define", not "--tool-<id>".
function colourToken(id: string): string {
  const m = toolMeta(id).colorVar.match(/^var\((--tool-[a-z0-9-]+)\)$/);
  assert.ok(m, `${id} colorVar is a --tool-* var`);
  return m[1];
}

test("every registry tool id has a TOOLS label (not the fallback)", () => {
  for (const id of registryToolIds()) {
    assert.equal(toolMeta(id).key, id, `${id} falls back to the "other" entry`);
    assert.notEqual(colourToken(id), "--tool-other", `${id} is grey`);
  }
});

test("every tool colour token is defined in both theme blocks", () => {
  const css = read("shared/styles/tokens.css");
  const lightAt = css.indexOf(':root[data-theme="light"]');
  assert.ok(lightAt > 0, "light theme block present");
  const dark = css.slice(0, lightAt);
  const light = css.slice(lightAt);
  for (const id of registryToolIds()) {
    const tok = colourToken(id);
    assert.ok(dark.includes(`${tok}:`), `${id} dark ${tok}`);
    assert.ok(light.includes(`${tok}:`), `${id} light ${tok}`);
  }
});
