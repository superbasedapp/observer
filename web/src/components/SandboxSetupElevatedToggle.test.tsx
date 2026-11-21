// Component test of the Sandbox isolation card's allow_elevated toggle
// ([terminal.sandbox.setup], decision P-250 default off; P-254): it shows
// the saved value, defaults to off when the daemon omits the block, says
// the organization can never turn it on, and its change handler writes
// draft.setup.allow_elevated.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { SandboxSetupElevatedToggle, type SandboxSetupConfig } from "@/components/SandboxSettingsCard";

function checkbox(html: string): string {
  const m = html.match(/<input[^>]*aria-label="Let a setup step ask for your password"[^>]*>/);
  assert.ok(m, "no allow_elevated checkbox");
  return m[0];
}

test("allow_elevated toggle: off when the daemon omits the setup block", () => {
  const html = renderToStaticMarkup(<SandboxSetupElevatedToggle value={undefined} disabled={false} onChange={() => {}} />);
  assert.doesNotMatch(checkbox(html), /checked/);
  assert.match(html, /Let a setup step ask for your password/);
  assert.match(html, /Off: a step that needs administrator rights shows its command for you to run yourself\./);
  assert.match(html, /On: it opens in a setup terminal where you type your password\./);
  assert.match(html, /Your organization can never turn this on\./);
});

test("allow_elevated toggle: shows the saved value and the read-only state", () => {
  const on = renderToStaticMarkup(<SandboxSetupElevatedToggle value={{ allow_elevated: true }} disabled={false} onChange={() => {}} />);
  assert.match(checkbox(on), /checked/);
  const ro = renderToStaticMarkup(<SandboxSetupElevatedToggle value={{ allow_elevated: true }} disabled={true} onChange={() => {}} />);
  assert.match(checkbox(ro), /disabled/);
});

test("allow_elevated toggle: its change handler writes draft.setup.allow_elevated", () => {
  let got: SandboxSetupConfig | null = null;
  const el = SandboxSetupElevatedToggle({ value: undefined, disabled: false, onChange: (v) => (got = v) }) as {
    props: { children: Array<{ props: { onChange?: (e: { target: { checked: boolean } }) => void } }> };
  };
  const input = el.props.children[0];
  assert.ok(input.props.onChange, "the checkbox has no change handler");
  input.props.onChange({ target: { checked: true } });
  assert.deepEqual(got, { allow_elevated: true });
  input.props.onChange({ target: { checked: false } });
  assert.deepEqual(got, { allow_elevated: false });
});
