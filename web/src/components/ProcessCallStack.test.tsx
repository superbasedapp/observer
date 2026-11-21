// Component tests of the session-detail "Call stack" view
// (shared/components/sessiondetail: ProcessTree's stack view, ProcessFlame,
// ProcessSpawnStack), rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs). No DOM, so these pin the static layout: the
// chart at full width with the spawn stack below it, the slim empty line, the
// single merged notice line, bar labels only where they fit, and the zoom
// readout and overview strip.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { ProcessTree } from "@shared/components/sessiondetail/ProcessTree";
import { ProcessFlame } from "@shared/components/sessiondetail/ProcessFlame";
import { ProcessSpawnStack } from "@shared/components/sessiondetail/ProcessSpawnStack";
import { indexProcesses } from "@shared/lib/processLayout";
import type { ProcessNodeLike } from "@shared/lib/types";

const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

const T0 = Date.parse("2026-10-15T14:02:11Z");
const iso = (sec: number) => new Date(T0 + sec * 1000).toISOString();

function P(
  key: string,
  sec: number,
  durSec: number,
  extra: Partial<ProcessNodeLike> = {},
  children: ProcessNodeLike[] = [],
): ProcessNodeLike {
  return {
    process_key: key,
    pid: 100 + key.length,
    ppid: 1,
    exe: key,
    attribution_source: "inherited",
    attribution_confidence: "high",
    exited: true,
    exit_code: 0,
    duration_ms: durSec * 1000,
    started_at: iso(sec),
    children,
    ...extra,
  };
}

// A 100 s session: back-to-back 2 s commands (16 px at the 800 px server
// width, too narrow for a label), one 60 s command (labelled) and one 0.2 s
// command (a tick). Nothing is quiet, so Skip quiet squeezes nothing.
function smallSession(): ProcessNodeLike[] {
  const short = Array.from({ length: 50 }, (_, i) => P(`s${i}`, i * 2, 2, { exe: `short${i}` }));
  return [
    P("root", 0, 100, { exe: "claude", attribution_source: "bridge" }, [
      P("wide", 0, 60, { exe: "widecmd", argv_preview: "widecmd --run all" }),
      P("blip", 30, 0.2, { exe: "blipcmd" }),
      ...short,
    ]),
  ];
}

// 160 processes over about an hour, one of them only from the tool log and one
// never seen exiting: a large session with capture gaps.
function largeSession(): ProcessNodeLike[] {
  const kids = Array.from({ length: 158 }, (_, i) => P(`c${i}`, i * 25, 2, { exe: "node" }));
  kids.push(P("rg", 30, 0.1, { pid: 0, attribution_source: "action_correlation" }));
  kids.push(P("lost", 40, 0, { exited: false, last_seen_at: iso(41) }));
  return [P("root", 0, 4_000, { attribution_source: "bridge" }, kids)];
}
const NOW = T0 + 4_000_000;

function renderTree(roots: ProcessNodeLike[], selectedKey: string | null = null): string {
  return renderToStaticMarkup(
    <ProcessTree
      roots={roots}
      total={roots.length}
      initialView="stack"
      selectedKey={selectedKey}
      onSelectedKeyChange={() => {}}
      sessionLabel="Session abc"
      nowMs={NOW}
    />,
  );
}

test("the chart takes the full width and the spawn stack sits below it", () => {
  const html = renderTree(smallSession());
  const chart = html.indexOf('aria-label="Process call stack');
  const stack = html.indexOf('aria-label="Spawn stack"');
  assert.ok(chart > 0 && stack > chart, "spawn stack after the chart");
  assert.doesNotMatch(html, /xl:grid-cols-\[minmax\(0,1fr\)_320px\]/);
});

test("with nothing picked the spawn stack is one slim line", () => {
  const html = renderTree(smallSession());
  assert.match(html, /<aside[^>]*aria-label="Spawn stack"[^>]*>Click a bar to see which processes started it\.<\/aside>/);
  assert.doesNotMatch(html, /Click any bar to see the chain/);
});

test("a large session with gaps shows one merged notice line with Why?", () => {
  const html = renderTree(largeSession());
  const notes = html.match(/role="note"/g) ?? [];
  assert.equal(notes.length, 1, "exactly one notice");
  assert.match(html, /Partial capture:/);
  assert.match(html, /1 not seen exiting/);
  assert.match(html, /1 known only from the tool log/);
  assert.match(html, /identical processes share one bar/);
  assert.match(html, /aria-expanded="false"[^>]*>.*?Why\?<\/button>/);
  // The long explanation stays behind the disclosure.
  assert.doesNotMatch(html, /To keep the chart fast/);
});

test("a small complete session shows no notice", () => {
  const html = renderTree(smallSession());
  assert.doesNotMatch(html, /role="note"/);
});

test("labels only on bars wide enough to hold one", () => {
  const index = indexProcesses(smallSession(), NOW);
  const html = renderToStaticMarkup(
    <ProcessFlame index={index} selectedKey={null} onSelect={() => {}} sessionLabel="Session abc" nowMs={NOW} />,
  );
  // The 60 s bar carries its exe and short argv, truncated with an ellipsis.
  assert.match(html, /data-tier="label"[^>]*><span class="block truncate">.*?widecmd<\/span> <span[^>]*>widecmd --run all</);
  // The 2 s bars are bars with no text; the hover card and aria-label name them.
  const bare = html.match(/data-tier="bare"[^>]*><\/div>/g) ?? [];
  assert.ok(bare.length >= 40, `bare bars without text: ${bare.length}`);
  assert.doesNotMatch(html, />short1</);
  assert.match(html, /aria-label="short1, pid \d+, exit 0, started [^"]+, ran 2\.0s"/);
  // The 0.2 s command is a tick.
  assert.match(html, /aria-label="blipcmd[^"]*"[^>]*data-tier="tick"/);
});

test("the zoom readout and toolbar; the overview strip only when the window is narrower", () => {
  const small = indexProcesses(smallSession(), NOW);
  const s = renderToStaticMarkup(
    <ProcessFlame index={small} selectedKey={null} onSelect={() => {}} sessionLabel="Session abc" nowMs={NOW} />,
  );
  assert.match(s, /data-testid="flame-zoom"[^>]*>1× · all of 1m40s</);
  assert.match(s, /role="toolbar" aria-label="Zoom"/);
  assert.match(s, /disabled=""[^>]*aria-label="Zoom out"/);
  assert.match(s, /aria-label="Zoom in"/);
  assert.match(s, />Fit</);
  assert.match(s, />Zoom to selection</);
  assert.doesNotMatch(s, /role="slider"/);
  // The legend sits in the footer, after the plot.
  assert.ok(s.indexOf("tool log only") > s.indexOf('role="tree"'));
  // The plot is at least four rows tall even for a shallow session.
  const h = Number(/role="tree"[^>]*style="height:(\d+)px/.exec(s)?.[1]);
  assert.ok(h >= 134, `plot height ${h}`);

  const large = indexProcesses(largeSession(), NOW);
  const l = renderToStaticMarkup(
    <ProcessFlame index={large} selectedKey={null} onSelect={() => {}} sessionLabel="Session abc" nowMs={NOW} />,
  );
  assert.match(l, /data-testid="flame-zoom"[^>]*>\d+(\.\d)?× · \S+ of 1h0\dm</);
  assert.match(l, /role="slider"/);
  assert.match(l, /data-testid="overview-window"[^>]*>Window [^<]+ to [^<]+</);
});

test("with a pick the spawn stack uses the width and keeps the child chips", () => {
  const index = indexProcesses(
    [P("root", 0, 100, {}, [P("bash", 1, 50, {}, [P("git", 2, 1), P("npm", 3, 40)])])],
    NOW,
  );
  const html = renderToStaticMarkup(
    <ProcessSpawnStack index={index} selectedKey="bash" onSelect={() => {}} sessionLabel="Session abc" />,
  );
  assert.match(html, /Spawn stack · 2 deep/);
  assert.match(html, /lg:grid-cols-\[minmax\(0,3fr\)_minmax\(0,2fr\)\]/);
  assert.match(html, /Started 2 processes/);
  assert.match(html, />git(<!-- -->)? 103</);
});

test("the spawn stack links the message that started the picked process, inherited from its tool call", () => {
  const index = indexProcesses(
    [P("root", 0, 100, {}, [P("bash", 1, 50, { message_id: "msg_7", turn_index: 7 }, [P("git", 2, 1)])])],
    NOW,
  );
  const linked = renderToStaticMarkup(
    <ProcessSpawnStack index={index} selectedKey="git" onSelect={() => {}} onOpenMessage={() => {}} sessionLabel="Session abc" />,
  );
  assert.match(linked, />Open message</);
  assert.match(linked, /Open the message that started this process \(msg_7\)/);
  // Without a message handler the id is shown as plain text, never a dead link.
  const plain = renderToStaticMarkup(
    <ProcessSpawnStack index={index} selectedKey="git" onSelect={() => {}} sessionLabel="Session abc" />,
  );
  assert.doesNotMatch(plain, /Open message/);
  assert.match(plain, />msg_7</);
  // A process no tool call started has no message action.
  const none = renderToStaticMarkup(
    <ProcessSpawnStack index={indexProcesses([P("root", 0, 100, {}, [P("x", 1, 2)])], NOW)} selectedKey="x" onSelect={() => {}} onOpenMessage={() => {}} sessionLabel="Session abc" />,
  );
  assert.doesNotMatch(none, /Open message/);
});
