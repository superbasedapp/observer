// sdkPrompt.ts is the ONE text of the agent prompt that adds the superbased
// SDK to an app (AI Apps SDK quickstart plan 3.9): four lines, then nothing.
// The node dashboard (web's AI apps first-run card) and the org dashboard
// (web2's first-run panel) both show sdkAgentPrompt(); the website shows the
// same four lines from website/pages-src/partials/prompt-sdk.html, which
// takes the commands from the same catalog fields through @@sdk.<id>.<field>@@
// tokens (a web test pins the two equal).
//
// The prompt runs the setup command and does what it prints. It never tells
// the agent to read, print, copy or move the SDK key or the file it is kept
// in (it says never to), and it never names the AI gateway.
//
// Pure: no React, no fetch, no app path aliases, so `node --test` loads it.

import { SDK_CATALOG, type SdkEntry } from "./sdkCatalog.ts";

/** The Python module that runs setup without uv (`python -m <module> setup`). */
export const PYTHON_SETUP_MODULE = "superbased_sdk";

/** Where the prompt sends the agent for the richer steps. */
export const SDK_DOCS_URL = "https://superbased.app/docs/sdk/overview";

/** The dashboard address setup looks for when nothing else is set. */
export const DEFAULT_NODE_URL = "http://127.0.0.1:8081";

function row(catalog: readonly SdkEntry[], id: string): SdkEntry {
  const r = catalog.find((s) => s.id === id);
  if (!r || !r.setup) throw new Error(`sdkPrompt: the catalog has no setup command for "${id}"`);
  return r;
}

/** sdkAgentPrompt is the four-line prompt. `nodeUrl`, when given and not
 *  the default dashboard address, is the machine's dashboard: the first line
 *  then says to set SUPERBASED_NODE_URL so setup and the app find it. */
export function sdkAgentPrompt(opts: { nodeUrl?: string } = {}, catalog: readonly SdkEntry[] = SDK_CATALOG): string {
  const node = row(catalog, "typescript");
  const py = row(catalog, "python");
  const url = (opts.nodeUrl ?? "").trim().replace(/\/+$/, "");
  const where =
    url && url !== DEFAULT_NODE_URL
      ? ` with SUPERBASED_NODE_URL=${url} set (this computer's superbased dashboard)`
      : "";
  return [
    `Add superbased tracing to this app: in the project root run \`${node.setup}\` (Node) or \`${py.setup}\` (Python; without uv: \`pip install ${py.package} && python -m ${PYTHON_SETUP_MODULE} setup\`)${where} and do what it prints.`,
    "If it asks me to approve in the browser or to answer y/N, tell me and wait. Never read, print, copy or move the SDK key or the file it is stored in.",
    "Add the one init line setup prints (for Node ESM, the start-script change it prints), run the app once, and give me the trace link.",
    `For more detail later (the request handler as an AGENT span, the end user as an opaque id), follow ${SDK_DOCS_URL}`,
  ].join("\n");
}

/** The setup command of each language that has one, in catalog order. */
export function setupCommands(catalog: readonly SdkEntry[] = SDK_CATALOG): { id: string; label: string; setup: string }[] {
  return catalog.filter((s) => s.setup).map((s) => ({ id: s.id, label: s.label, setup: s.setup }));
}
