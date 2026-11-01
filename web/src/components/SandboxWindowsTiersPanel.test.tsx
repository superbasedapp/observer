// Render tests of the extra Windows rows panel (lane GATES-SBX).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { SandboxWindowsTiersPanel, WINDOWS_TIER_ROWS } from "@/components/SandboxWindowsTiersPanel";

const view = (ids: string[]) => ({ configured: true, components: ids.map((id) => ({ id, state: "active" })) }) as never;

test("nothing renders while no row's component is selected", () => {
  assert.equal(renderToStaticMarkup(<SandboxWindowsTiersPanel wslc={undefined} hcs={undefined} view={view([])} />), "");
});

test("only the selected rows render, with the weaker tier labelled", () => {
  const html = renderToStaticMarkup(
    <SandboxWindowsTiersPanel wslc={{ path: "", image: "" }} hcs={{ utility_vm_image: "" }} view={view(["terminals.sandbox.mxc.appcontainer", "terminals.sandbox.hcs"])} />,
  );
  assert.match(html, /MXC AppContainer tier/);
  assert.match(html, /Weaker than ProcessContainer/);
  assert.match(html, /Hyper-V isolated containers/);
  assert.doesNotMatch(html, /WSL containers/);
  assert.doesNotMatch(html, /<input/);
  assert.equal(WINDOWS_TIER_ROWS.length, 3);
});
