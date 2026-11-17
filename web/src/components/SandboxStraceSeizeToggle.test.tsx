// Component test of the sandbox card's strace switch (lane ptrace, PT-96):
// off by default, says what it allows and the containment condition, shows
// each sandbox's ground or the reason strace stays blocked, is disabled
// while the status loads or the config is not writable, and its change
// handler reports the new value.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { SandboxStraceSeizeToggle, seizeRowText, type SandboxSeizeStatus } from "@/components/SandboxStraceSeizeToggle";

const rows = [
  { backend: "bwrap", label: "Bubblewrap", lifted: true, ground: "pid_namespace" },
  {
    backend: "process_lite",
    label: "Landlock only",
    lifted: false,
    reason: "strace stays blocked (PTRACE_SEIZE denied): this sandbox shares the host's process list and Yama ptrace_scope reads 0, so a seize could reach a process outside the sandbox",
  },
];

const off: SandboxSeizeStatus = { enabled: false, seccomp: true, yama_scope: 0, rows };

function checkbox(html: string): string {
  const m = html.match(/<input[^>]*aria-label="Allow strace in sandboxed terminals"[^>]*>/);
  assert.ok(m, "no strace switch checkbox");
  return m[0];
}

test("strace switch: off by default, says what it allows and when", () => {
  const html = renderToStaticMarkup(<SandboxStraceSeizeToggle status={off} disabled={false} busy={false} error={null} onChange={() => {}} />);
  assert.doesNotMatch(checkbox(html), /checked/);
  assert.doesNotMatch(checkbox(html), /disabled/);
  assert.match(html, /Off by default\./);
  assert.match(html, /strace -p\) stays blocked/);
  assert.match(html, /the sandbox has its own process list, or the kernel&#x27;s Yama setting limits tracing/);
  assert.match(html, /Observer never changes a kernel setting\./);
  assert.match(html, /not your organization, and not an AI agent\./);
  assert.match(html, /Bubblewrap<\/span>: strace allowed: the sandbox has its own process list/);
  assert.match(html, /Landlock only<\/span>: strace stays blocked \(PTRACE_SEIZE denied\)/);
  assert.doesNotMatch(html, /The syscall filter is off/);
});

test("strace switch: shows the saved value, the filter-off note and the error", () => {
  const on = renderToStaticMarkup(
    <SandboxStraceSeizeToggle status={{ ...off, enabled: true, seccomp: false }} disabled={false} busy={false} error="forbidden" onChange={() => {}} />,
  );
  assert.match(checkbox(on), /checked/);
  assert.match(on, /The syscall filter is off, so nothing is blocked now\./);
  assert.match(on, /role="alert"[^>]*>forbidden</);
});

test("strace switch: disabled while loading, saving or not writable", () => {
  for (const props of [
    { status: null, disabled: false, busy: false },
    { status: off, disabled: true, busy: false },
    { status: off, disabled: false, busy: true },
  ]) {
    const html = renderToStaticMarkup(<SandboxStraceSeizeToggle {...props} error={null} onChange={() => {}} />);
    assert.match(checkbox(html), /disabled/);
  }
});

test("strace switch: its change handler reports the new value", () => {
  const got: boolean[] = [];
  const el = SandboxStraceSeizeToggle({ status: off, disabled: false, busy: false, error: null, onChange: (v) => got.push(v) }) as {
    props: { children: Array<{ props: { children: Array<{ props: { onChange?: (e: { target: { checked: boolean } }) => void } }> } }> };
  };
  const input = el.props.children[0].props.children[0];
  assert.ok(input.props.onChange, "the checkbox has no change handler");
  input.props.onChange({ target: { checked: true } });
  input.props.onChange({ target: { checked: false } });
  assert.deepEqual(got, [true, false]);
});

test("seizeRowText: the ground's words, or the daemon's reason", () => {
  assert.equal(seizeRowText({ backend: "x", label: "X", lifted: true, ground: "yama" }), "strace allowed: the kernel's Yama setting limits tracing to the run's own child processes");
  assert.equal(seizeRowText({ backend: "x", label: "X", lifted: false, reason: "why" }), "why");
  assert.equal(seizeRowText({ backend: "x", label: "X", lifted: false }), "strace stays blocked");
});
