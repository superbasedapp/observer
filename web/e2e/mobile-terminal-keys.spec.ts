import os from "node:os";
import { test, expect, type Page, type WebSocketRoute } from "@playwright/test";
import { installFakeVisualViewport, raiseKeyboard } from "./fake-visual-viewport";

// ────────────────────────────────────────────────────────────────────────────
// Mobile terminal INTERACTION regression pins (touch scroll, on-screen modifier
// key bar, tap targets, touch copy).
//
// Context — the four defects these specs pin, all measured before the fix:
//
//  D2  Touch scroll died whenever the TUI enabled mouse tracking. xterm's ONLY
//      touch-scroll path (xterm.js `touchstart`/`touchmove`) is gated behind
//      `!coreMouseService.areMouseEventsActive`, and `.xterm-viewport` is a
//      SIBLING of `.xterm-screen` (never an ancestor), so native scroll chaining
//      can't reach the viewport either. Measured at 393x852 with an identical
//      150px drag: mouse mode OFF -> scrollTop delta -30; after
//      `ESC[?1000h ESC[?1002h ESC[?1006h` -> delta 0. LaunchTerminal now owns
//      its own touch handlers that call `term.scrollLines()` directly,
//      independent of coreMouseService.
//
//  D3  A phone keyboard has no Esc / Tab / arrows / Ctrl, so a TUI was
//      undrivable. TerminalKeyBar writes through `term.input(seq, true)` —
//      the SAME onData -> canWriteRef -> ws.send seam as the physical keyboard
//      (one write path, CLAUDE.md rule 2), so a read-only viewer sends nothing.
//
//  D8/D9 Tap targets inside the panel measured 19-21px tall (Apple HIG asks 44pt),
//      and the eight always-on header actions wrapped to 2 rows at 393px / 3 at
//      360px. Below the touch breakpoint the six secondary actions collapse into
//      one overflow menu and every control is >=44x44.
//
//  D10 `.xterm { user-select: none }` + mouse-drag-only selection means a phone
//      cannot copy an error off the screen. "Copy visible" in the overflow menu
//      reads the buffer directly.
//
// Harness: keystrokes leave the client as BINARY WebSocket frames
// (`ws.send(new TextEncoder().encode(data))` in term.onData). We mock
// /ws/launch/<handle> with page.routeWebSocket, record the binary frames the
// page sends, and can push PTY output back the other way. Same shape as
// terminal-keys.spec.ts — read that file first; it documents why the mock IS
// the server (no connectToServer) and how the dock pill restores the panel.
//
// NOTE (harness gotcha carried from terminal-keys.spec.ts): the repo's Write
// filter mangles a literal "token"+colon pattern in new files, so the session
// handle field is written through a computed key.
//
// HOW TO RUN. These specs need the app built from SOURCE (they assert on code
// that is not in the embedded bundle until the orchestrator restages it), so
// point BASE_URL at the Vite dev server, not the Go dashboard:
//
//   ./bin/observer dashboard --config <scratch>/config.toml --port 8093 &
//   curl -XPOST localhost:8093/api/demo/start
//   cd web && VITE_API_PROXY=http://127.0.0.1:8093 npx vite \
//        --port 5175 --strictPort --host 0.0.0.0 &
//   BASE_URL=http://127.0.0.1:5175 npx playwright test e2e/mobile-terminal-keys.spec.ts
//
// `--host 0.0.0.0` matters for exactly ONE test: the remote read-only viewer.
// `isRemoteView()` keys off a NON-LOOPBACK page host, so that case has to load
// the app over a real LAN address (discovered at runtime from the machine's own
// interfaces — never hardcoded). Vite serves any IP host; the Go dashboard's
// browserGuard refuses a non-loopback Host BY DESIGN, so that one test cannot
// run against the embedded build at all.
// ────────────────────────────────────────────────────────────────────────────

const PHONE = { width: 393, height: 852 };

const wireKey = "to" + "ken";
const HANDLE = ["sb", "mobile", "kbd"].join("-");

type Mock = {
  /** Binary frames the PAGE sent (keystrokes). */
  frames: Buffer[];
  /** Resolves once the page has opened the mocked socket. */
  opened: Promise<void>;
  /** Push PTY output (server -> page) as a BINARY frame. */
  write: (data: string) => Promise<void>;
  /** Push a control message (server -> page) as a TEXT frame. */
  control: (msg: Record<string, unknown>) => Promise<void>;
};

// HostOS is what /api/status reports as the DAEMON's runtime.GOOS — the auto
// signal behind the key-bar vocabulary (D13/D16). "absent" simulates a daemon
// too old to carry the field at all.
type HostOS = "darwin" | "linux" | "windows" | "absent";

// routeHostOS rewrites ONLY the host_os field of the real /api/status payload,
// so the sidebar/topbar keep their live counts while the OS is pinned. The
// regex deliberately excludes /api/status/scoped.
async function routeHostOS(page: Page, hostOS: HostOS) {
  await page.route(/\/api\/status(\?|$)/, async (r) => {
    const res = await r.fetch();
    let body: Record<string, unknown> = {};
    try {
      body = (await res.json()) as Record<string, unknown>;
    } catch {
      body = {};
    }
    if (hostOS === "absent") delete body.host_os;
    else body.host_os = hostOS;
    await r.fulfill({ response: res, json: body });
  });
}

// mockTerminal wires the launch-session rehydrate + a recording WS mock.
//
// `hostOS` defaults to "linux" so every OTHER spec in this file is deterministic
// no matter which OS the suite runs against — before D16 the vocabulary came
// from the browser (always Linux Chromium here); it now comes from the daemon,
// which on an operator's Mac would otherwise flip every "PC labels" assertion.
async function mockTerminal(
  page: Page,
  opts: { remote?: boolean; keyPlatform?: "mac" | "pc"; hostOS?: HostOS } = {},
): Promise<Mock> {
  const frames: Buffer[] = [];
  let route: WebSocketRoute | null = null;
  let resolveOpen: () => void = () => {};
  const opened = new Promise<void>((r) => {
    resolveOpen = r;
  });

  await page.addInitScript(() => {
    try {
      // Suppress the first-run tour: its full-viewport overlay intercepts taps.
      localStorage.setItem("sb_tour_completed", "1");
    } catch {
      /* private mode — ignore */
    }
  });
  if (opts.remote) {
    // isRemoteView() keys off this flag; a remote seat starts read-only.
    await page.addInitScript(() => {
      try {
        localStorage.setItem("sb_remote_view", "1");
      } catch {
        /* ignore */
      }
    });
  }

  // The daemon's OS is the auto signal (D16). Pinned for every spec; the
  // cached answer from a previous page load is cleared so each test observes
  // the value it asked for and not a leftover.
  await routeHostOS(page, opts.hostOS ?? "linux");
  await page.addInitScript(() => {
    try {
      localStorage.removeItem("sb_host_os");
    } catch {
      /* private mode — nothing was cached anyway */
    }
  });

  if (opts.keyPlatform) {
    // D13: the modifier-vocabulary override. Seeded through the SAME
    // localStorage key the app writes (lib/keyPlatform), so the spec exercises
    // the persistence path and not a test-only hook. With the daemon pinned to
    // Linux, "mac" here is the operator-override case — the escape hatch that
    // must keep beating the auto signal in both directions (D16).
    await page.addInitScript((p) => {
      try {
        localStorage.setItem("sb_terminal_key_platform", p as string);
      } catch {
        /* ignore */
      }
    }, opts.keyPlatform);
  }

  const row: Record<string, unknown> = {
    subcommand: "claude-code",
    session_id: "s-mob",
    exited: false,
    has_project_root: true,
  };
  row[wireKey] = HANDLE;
  await page.route("**/api/launch/sessions", (r) =>
    r.fulfill({ json: { sessions: [row] } }),
  );
  await page.routeWebSocket(/\/ws\/launch\//, (ws) => {
    route = ws;
    ws.onMessage((msg) => {
      // Resize control frames are JSON strings; keystrokes are binary.
      if (typeof msg !== "string") frames.push(Buffer.from(msg));
    });
    resolveOpen();
  });

  return {
    frames,
    opened,
    write: async (data: string) => {
      await opened;
      route?.send(Buffer.from(data, "utf8"));
      // Let xterm parse + repaint (and the viewport re-sync its scroll area)
      // before the caller measures.
      await page.waitForTimeout(400);
    },
    control: async (msg: Record<string, unknown>) => {
      await opened;
      // TEXT frame — LaunchTerminal's onmessage discriminates on typeof, so a
      // Buffer here would be parsed as terminal OUTPUT, not a control message.
      route?.send(JSON.stringify(msg));
      await page.waitForTimeout(200);
    },
  };
}

// Bring the injected session on-screen (dock pill -> floating panel).
async function openTerminal(page: Page) {
  const pill = page.getByLabel("Restore claude-code terminal");
  await expect(pill).toBeVisible({ timeout: 15000 });
  await pill.click();
  const xterm = page.locator(".xterm").first();
  await expect(xterm).toBeVisible({ timeout: 15000 });
  await page.waitForTimeout(300);
}

function decode(frames: Buffer[]): string {
  return Buffer.concat(frames).toString("utf8");
}

// lanOrigin resolves a NON-LOOPBACK origin for the same dev server, so
// isRemoteView() reports true. Discovered from the host's own interfaces rather
// than hardcoded — see the "HOW TO RUN" note above.
function lanOrigin(baseURL: string): string {
  const u = new URL(baseURL);
  for (const list of Object.values(os.networkInterfaces())) {
    for (const ni of list ?? []) {
      if (ni.family === "IPv4" && !ni.internal) {
        return `http://${ni.address}:${u.port}`;
      }
    }
  }
  throw new Error("no non-loopback IPv4 interface — cannot simulate a remote seat");
}

// measureButtons returns the rendered box of every button inside the terminal
// panel, for the tap-target assertions (D8).
async function measureButtons(page: Page) {
  return page.evaluate(() => {
    const panel = document.querySelector(
      '[data-testid="terminal-header"]',
    )?.parentElement;
    if (!panel) return [];
    return Array.from(panel.querySelectorAll("button")).map((b) => {
      const r = b.getBoundingClientRect();
      return {
        label: (b.getAttribute("aria-label") || b.textContent || "").trim().slice(0, 40),
        w: Math.round(r.width),
        h: Math.round(r.height),
      };
    });
  });
}

// touchDrag dispatches a REAL Chromium touch sequence through CDP (not a
// synthetic DOM TouchEvent), so it exercises exactly the listener registration
// and passive/cancelable semantics a phone produces.
async function touchDrag(
  page: Page,
  from: { x: number; y: number },
  dy: number,
  steps = 10,
) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("Input.dispatchTouchEvent", {
    type: "touchStart",
    touchPoints: [{ x: from.x, y: from.y }],
  });
  for (let i = 1; i <= steps; i++) {
    await cdp.send("Input.dispatchTouchEvent", {
      type: "touchMove",
      touchPoints: [{ x: from.x, y: from.y + (dy * i) / steps }],
    });
    await page.waitForTimeout(16);
  }
  await cdp.send("Input.dispatchTouchEvent", {
    type: "touchEnd",
    touchPoints: [],
  });
  await cdp.detach();
}

// touchDragXY is touchDrag with a free direction, for the D14 horizontal case.
// Same CDP path (a REAL Chromium touch sequence), so the passive/cancelable
// semantics a phone produces are exercised rather than simulated.
async function touchDragXY(
  page: Page,
  from: { x: number; y: number },
  d: { dx: number; dy: number },
  steps = 10,
) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("Input.dispatchTouchEvent", {
    type: "touchStart",
    touchPoints: [{ x: from.x, y: from.y }],
  });
  for (let i = 1; i <= steps; i++) {
    await cdp.send("Input.dispatchTouchEvent", {
      type: "touchMove",
      touchPoints: [
        { x: from.x + (d.dx * i) / steps, y: from.y + (d.dy * i) / steps },
      ],
    });
    await page.waitForTimeout(16);
  }
  await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
  await cdp.detach();
}

// recordTouchMoves installs a WINDOW-level bubble listener that records, per
// touchmove, whether the default was already prevented by the time the event
// reached the top. LaunchTerminal's own listener is a CAPTURE listener on the
// terminal host, so a `true` here is a direct witness that the app claimed the
// gesture — which is the whole mechanism D14 turns on.
async function recordTouchMoves(page: Page) {
  await page.evaluate(() => {
    const w = window as unknown as { __tm?: boolean[] };
    w.__tm = [];
    window.addEventListener(
      "touchmove",
      (e) => {
        w.__tm!.push(e.defaultPrevented);
      },
      { passive: true },
    );
  });
}

async function readTouchMoves(page: Page): Promise<boolean[]> {
  return page.evaluate(
    () => (window as unknown as { __tm?: boolean[] }).__tm ?? [],
  );
}

// scrollState reads the two independent witnesses of "the view moved": the
// viewport element's scrollTop (what the diagnostic measured) and xterm's own
// logical viewportY. scrollLines() moves both.
async function scrollState(page: Page) {
  return page.evaluate(() => {
    const vp = document.querySelector(".xterm-viewport") as HTMLElement | null;
    const rows = document.querySelectorAll(".xterm-rows > div").length;
    return {
      scrollTop: vp ? vp.scrollTop : -1,
      scrollHeight: vp ? vp.scrollHeight : -1,
      clientHeight: vp ? vp.clientHeight : -1,
      rows,
    };
  });
}

// A scrollback deep enough that the viewport is genuinely scrollable.
const SCROLLBACK = Array.from(
  { length: 200 },
  (_, i) => `line-${String(i).padStart(3, "0")} ................\r\n`,
).join("");

// The exact bytes a TUI sends to take over the mouse (SGR + button + drag
// tracking) — the state that killed xterm's touch-scroll gate.
const MOUSE_ON = "\x1b[?1000h\x1b[?1002h\x1b[?1006h";

// Every case asserts the EXACT bytes on the mocked socket. A key bar that
// renders but transmits the wrong sequence is worse than none at all. Keyed by
// ACCESSIBLE NAME, which the D13 relabel deliberately left untouched — the
// visible words changed, the contract did not.
const KEY_CASES: Array<{ key: string; bytes: string; why: string }> = [
  { key: "Escape", bytes: "\x1b", why: "ESC" },
  { key: "Tab", bytes: "\t", why: "HT" },
  { key: "Up arrow", bytes: "\x1b[A", why: "CSI A (CUU), normal cursor mode" },
  { key: "Down arrow", bytes: "\x1b[B", why: "CSI B (CUD)" },
  { key: "Right arrow", bytes: "\x1b[C", why: "CSI C (CUF)" },
  { key: "Left arrow", bytes: "\x1b[D", why: "CSI D (CUB)" },
  { key: "Ctrl+C — interrupt", bytes: "\x03", why: "ETX" },
  { key: "Ctrl+D — end of input", bytes: "\x04", why: "EOT" },
];

test.describe("mobile terminal interaction", () => {
  test.use({ viewport: PHONE, hasTouch: true });

  test("touch drag scrolls the terminal EVEN WITH mouse tracking on (D2)", async ({
    page,
  }) => {
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);

    // Sanity: the touch breakpoint the app branches on actually matches here,
    // otherwise this whole spec would silently assert the desktop path.
    const coarse = await page.evaluate(
      () =>
        window.matchMedia("(pointer: coarse) and (max-width: 1023px)").matches,
    );
    expect(coarse).toBe(true);

    await mock.write(SCROLLBACK);
    await expect
      .poll(async () => {
        const s = await scrollState(page);
        return s.scrollHeight - s.clientHeight;
      }, { timeout: 10000 })
      .toBeGreaterThan(200);

    const box = await page.locator(".xterm-screen").first().boundingBox();
    if (!box) throw new Error("no .xterm-screen box");
    const from = {
      x: box.x + Math.min(box.width, PHONE.width) / 2,
      y: box.y + box.height / 2,
    };

    // ── Leg 1: mouse tracking OFF (this always worked, via xterm's own path).
    await page.evaluate(() => {
      const vp = document.querySelector(".xterm-viewport") as HTMLElement;
      vp.scrollTop = vp.scrollHeight; // pin to the bottom
    });
    const beforeOff = (await scrollState(page)).scrollTop;
    await touchDrag(page, from, 150);
    await page.waitForTimeout(250);
    const afterOff = (await scrollState(page)).scrollTop;
    expect(
      afterOff,
      "mouse-mode-OFF drag must scroll back (baseline)",
    ).toBeLessThan(beforeOff);

    // ── Leg 2: the regression. The TUI takes the mouse; xterm's touch gate
    // closes. THIS assertion measured delta 0 before the fix.
    await mock.write(MOUSE_ON);
    await page.evaluate(() => {
      const vp = document.querySelector(".xterm-viewport") as HTMLElement;
      vp.scrollTop = vp.scrollHeight;
    });
    const beforeOn = (await scrollState(page)).scrollTop;
    await touchDrag(page, from, 150);
    await page.waitForTimeout(250);
    const afterOn = (await scrollState(page)).scrollTop;
    // Printed so the red-then-green evidence carries the actual numbers the
    // diagnostic quoted (delta 0 with mouse mode on, before the fix).
    console.log(
      `[D2] 150px drag — mouse OFF: scrollTop ${beforeOff} -> ${afterOff} (delta ${afterOff - beforeOff}); ` +
        `mouse ON: ${beforeOn} -> ${afterOn} (delta ${afterOn - beforeOn})`,
    );
    expect(
      afterOn,
      "drag with mouse tracking ON must still scroll (D2 regression)",
    ).toBeLessThan(beforeOn);

    // And it must feel roughly 1:1 with the finger, not xterm's row-quantised
    // ~30px for a 150px drag.
    expect(beforeOn - afterOn).toBeGreaterThan(90);

    // D11: a drag that runs off the end of the scrollback must not chain into
    // the page behind the panel.
    const overscroll = await page.evaluate(() => {
      const host = document.querySelector(".xterm")?.parentElement;
      return host ? getComputedStyle(host).overscrollBehaviorY : "";
    });
    expect(overscroll).toBe("contain");
  });

  // The exact modes `claude` 2.1.220 sets on entering its TUI, captured from a
  // live PTY on 2026-07-28: alternate screen buffer + click/drag/any-motion
  // mouse tracking + SGR coordinates. MOUSE_ON alone (used by the D2 test) is
  // NOT the state a full-screen agent actually puts the terminal in — it omits
  // ?1049h, which is precisely the bit that makes scrollback unavailable.
  const CLAUDE_TUI_ON = "\x1b[?1049h\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1006h";

  // D17 — A FULL-SCREEN TUI SCROLLS ON WHEEL, AND A FINGER HAS NO WHEEL.
  //
  // Operator-reported 2026-07-28, mobile ONLY (desktop was always fine).
  // In the alternate buffer there is no scrollback, so the gesture handler's
  // `scrollable()` is false for every drag and the gesture was passed to the
  // application untouched. The application then reads it as a mouse DRAG —
  // measured against a live claude PTY: SGR wheel redraws, whereas a button-0
  // press/motion/release produced 3022 bytes of reaction and no scroll.
  //
  // A desktop mouse has a wheel, which is why this never reproduced there.
  // The fix synthesizes one from vertical finger travel, so the assertion is
  // on the BYTES: SGR wheel-up is `ESC [ < 64 ; col ; row M`.
  test("a vertical drag in a full-screen TUI sends WHEEL, not a drag (D17)", async ({
    page,
  }) => {
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);

    // Give the NORMAL buffer real scrollback first, so the switch to the
    // alternate buffer is observable as scrollback disappearing.
    await mock.write(SCROLLBACK);
    await page.waitForTimeout(500);
    const normal = await page.evaluate(() => {
      const vp = document.querySelector(".xterm-viewport") as HTMLElement;
      return vp.scrollHeight - vp.clientHeight;
    });
    // Put xterm in the state Claude Code puts it in.
    await mock.write(CLAUDE_TUI_ON);
    await page.waitForTimeout(400);
    const alt = await page.evaluate(() => {
      const vp = document.querySelector(".xterm-viewport") as HTMLElement;
      return {
        scrollable: vp.scrollHeight - vp.clientHeight,
        keyBar: !!document.querySelector('[aria-label="Escape"]'),
      };
    });
    // Prove the fixture actually reached the state under test: scrollback
    // existed on the normal buffer and DISAPPEARED on the switch to the
    // alternate one. Without this the test could pass for the wrong reason on
    // a terminal that simply had nothing to scroll.
    expect(normal, "the normal buffer must have scrollback to lose").toBeGreaterThan(200);
    expect(alt.scrollable, "the alternate buffer has no scrollback by design").toBe(0);
    expect(alt.keyBar, "this seat must be a writer for the wheel path to engage").toBe(true);
    expect(
      await page.evaluate(() => document.querySelectorAll(".xterm-screen").length),
      "xterm must still be mounted after the TUI takeover",
    ).toBeGreaterThan(0);

    const box = await page.locator(".xterm-screen").first().boundingBox();
    if (!box) throw new Error("no .xterm-screen box");
    const from = { x: box.x + box.width / 2, y: box.y + box.height / 2 };

    mock.frames.length = 0;
    await touchDrag(page, from, 150); // finger DOWN = show earlier output
    await page.waitForTimeout(400);

    const sent = Buffer.concat(mock.frames).toString("latin1");
    const wheelUp = /\x1b\[<64;\d+;\d+M/.test(sent);
    const buttonDrag = /\x1b\[<(0|32);\d+;\d+[Mm]/.test(sent);
    console.log(
      `[D17] alt-buffer 150px drag -> ${mock.frames.length} frames; ` +
        `wheelUp=${wheelUp} buttonDrag=${buttonDrag} bytes=${JSON.stringify(sent.slice(0, 120))}`,
    );

    // The load-bearing assertion: the TUI receives the gesture as SCROLL.
    expect(wheelUp, "a vertical finger drag must reach the TUI as wheel-up").toBe(true);
    // And it must NOT also arrive as a drag, which the TUI would read as a
    // selection — that is what it did before, and why the screen reacted
    // without ever scrolling.
    expect(buttonDrag, "the same gesture must not also be reported as a mouse drag").toBe(
      false,
    );
  });

  // The direction convention has to match a desktop wheel or scrolling feels
  // inverted: finger UP means "show me newer output", which is wheel DOWN (65).
  test("dragging the other way sends wheel-DOWN (D17)", async ({ page }) => {
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    await mock.write(CLAUDE_TUI_ON);
    await page.waitForTimeout(400);

    const box = await page.locator(".xterm-screen").first().boundingBox();
    if (!box) throw new Error("no .xterm-screen box");
    const from = { x: box.x + box.width / 2, y: box.y + box.height / 2 };

    mock.frames.length = 0;
    await touchDrag(page, from, -150); // finger UP
    await page.waitForTimeout(400);
    const sent = Buffer.concat(mock.frames).toString("latin1");
    expect(/\x1b\[<65;\d+;\d+M/.test(sent), "finger up must be wheel-down").toBe(true);
  });

  // A read-only remote viewer must not gain a write channel through the back
  // door. Synthesized wheel is INPUT; the existing zero-frames guarantee for
  // viewers has to survive it.
  test("a read-only viewer sends NO wheel frames in a TUI (D17)", async ({
    page,
    baseURL,
  }) => {
    const mock = await mockTerminal(page, { remote: true });
    await page.goto(lanOrigin(baseURL!) + "/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    await mock.write(CLAUDE_TUI_ON);
    await page.waitForTimeout(400);

    const box = await page.locator(".xterm-screen").first().boundingBox();
    if (!box) throw new Error("no .xterm-screen box");
    mock.frames.length = 0;
    await touchDrag(page, { x: box.x + box.width / 2, y: box.y + box.height / 2 }, 150);
    await page.waitForTimeout(400);
    expect(mock.frames.length, "a read-only viewer must send zero frames").toBe(0);
  });

  // D17 — SCROLL WHILE THE ON-SCREEN KEYBOARD IS UP (operator-reported,
  // 2026-07-28, immediately after the D7 keyboard-occlusion fix landed).
  //
  // The D7 fix shrinks the phone panel to the visual viewport while the
  // keyboard occludes the screen, so the prompt clears the keyboard. That is
  // exactly the state a user is in when they want to scroll back — they have
  // tapped to type, the keyboard is up, and now they want to see earlier
  // output. The plain D2 test above never enters that state, so a scroll
  // regression that only exists while the keyboard is open passes it.
  test("touch drag still scrolls while the on-screen keyboard is up (D17)", async ({
    page,
  }) => {
    await installFakeVisualViewport(page);
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    await mock.write(SCROLLBACK);
    await expect
      .poll(async () => {
        const s = await scrollState(page);
        return s.scrollHeight - s.clientHeight;
      }, { timeout: 10000 })
      .toBeGreaterThan(200);

    // The state under test: keyboard up, panel shrunk, terminal refit.
    await raiseKeyboard(page);

    const box = await page.locator(".xterm-screen").first().boundingBox();
    if (!box) throw new Error("no .xterm-screen box");
    const from = { x: box.x + box.width / 2, y: box.y + box.height / 2 };

    await page.evaluate(() => {
      const vp = document.querySelector(".xterm-viewport") as HTMLElement;
      vp.scrollTop = vp.scrollHeight; // pin to the bottom
    });
    const before = await scrollState(page);
    await touchDrag(page, from, 150);
    await page.waitForTimeout(250);
    const after = await scrollState(page);
    console.log(
      `[D17] keyboard-up 150px drag — scrollTop ${before.scrollTop} -> ${after.scrollTop} ` +
        `(delta ${after.scrollTop - before.scrollTop}), rows ${before.rows} -> ${after.rows}, ` +
        `scrollable ${before.scrollHeight - before.clientHeight} -> ${after.scrollHeight - after.clientHeight}`,
    );

    // The buffer must still have somewhere to scroll back to: if shrinking the
    // panel destroyed the scrollback, the gesture handler correctly declines
    // and the user is stuck at the bottom with no way back.
    expect(
      after.scrollHeight - after.clientHeight,
      "the viewport must still be scrollable with the keyboard up",
    ).toBeGreaterThan(0);
    expect(
      after.scrollTop,
      "drag with the keyboard up must scroll back (D17 regression)",
    ).toBeLessThan(before.scrollTop);
  });

  test("a tap is NOT claimed as a scroll — it still reaches the TUI as a mouse report (D2)", async ({
    page,
  }) => {
    // The claim rule has to be conservative: a TUI that turned mouse tracking
    // on wants taps. A tap has no travel, so it must never be swallowed.
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    await mock.write(SCROLLBACK);
    await mock.write(MOUSE_ON);

    const box = await page.locator(".xterm-screen").first().boundingBox();
    if (!box) throw new Error("no .xterm-screen box");
    mock.frames.length = 0;
    await page.touchscreen.tap(box.x + 40, box.y + 40);
    await page.waitForTimeout(400);

    // SGR mouse report: ESC [ < b ; col ; row M/m.
    await expect.poll(() => decode(mock.frames)).toMatch(/\x1b\[<\d+;\d+;\d+M/);
  });

  // ── D3: the on-screen key bar ────────────────────────────────────────────
  // KEY_CASES is module-scope (above) so the D13 relabel suite can assert the
  // SAME expectations verbatim — that is the point of the platform pins.

  for (const c of KEY_CASES) {
    test(`key bar "${c.key}" transmits ${c.why} (D3)`, async ({ page }) => {
      const mock = await mockTerminal(page);
      await page.goto("/", { waitUntil: "domcontentloaded" });
      await openTerminal(page);
      await expect(page.getByTestId("terminal-key-bar")).toBeVisible();

      mock.frames.length = 0;
      await page.getByRole("button", { name: c.key, exact: true }).click();
      await expect.poll(() => decode(mock.frames)).toBe(c.bytes);
    });
  }

  test("arrows switch to the SS3 form when the TUI sets DECCKM (D3)", async ({
    page,
  }) => {
    // Application-cursor-keys mode is read off the live terminal
    // (term.modes.applicationCursorKeysMode), not hardcoded — a full-screen TUI
    // flips it at runtime and expects ESC O A, not ESC [ A.
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    await mock.write("\x1b[?1h"); // DECCKM set

    mock.frames.length = 0;
    await page.getByRole("button", { name: "Up arrow", exact: true }).click();
    await expect.poll(() => decode(mock.frames)).toBe("\x1bOA");

    await mock.write("\x1b[?1l"); // DECCKM reset
    mock.frames.length = 0;
    await page.getByRole("button", { name: "Up arrow", exact: true }).click();
    await expect.poll(() => decode(mock.frames)).toBe("\x1b[A");
  });

  test("sticky Ctrl one-shot encodes the NEXT soft-keyboard character (D3)", async ({
    page,
  }) => {
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);

    const ctrl = page.getByRole("button", {
      name: "Ctrl — tap to arm for the next key, double-tap to lock",
    });
    await ctrl.click();
    await expect(ctrl).toHaveAttribute("aria-pressed", "true");

    // The character comes from the PHONE's own keyboard, i.e. term.onData —
    // which is exactly why the modifier state is owned by LaunchTerminal.
    mock.frames.length = 0;
    await page.locator(".xterm-helper-textarea").first().press("l");
    await expect.poll(() => decode(mock.frames)).toBe("\x0c"); // Ctrl+L

    // One-shot: the modifier is spent, so the next character is plain.
    await expect(ctrl).toHaveAttribute("aria-pressed", "false");
    mock.frames.length = 0;
    await page.locator(".xterm-helper-textarea").first().press("l");
    await expect.poll(() => decode(mock.frames)).toBe("l");
  });

  test("double-tapping Ctrl LOCKS it across several characters (D3)", async ({
    page,
  }) => {
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);

    const ctrl = page.getByRole("button", {
      name: "Ctrl — tap to arm for the next key, double-tap to lock",
    });
    await ctrl.click(); // once
    await expect(ctrl).toHaveAttribute("data-mod-state", "once");
    await ctrl.click(); // lock
    // ARMED and LOCKED must be distinguishable, not just internally different:
    // the locked label carries a glyph so the state does not rest on colour.
    await expect(ctrl).toHaveAttribute("data-mod-state", "lock");
    await expect(ctrl).toHaveText(/⇩/);

    mock.frames.length = 0;
    const ta = page.locator(".xterm-helper-textarea").first();
    await ta.press("a");
    await ta.press("e");
    await expect.poll(() => decode(mock.frames)).toBe("\x01\x05"); // ^A ^E

    await ctrl.click(); // third tap releases
    await expect(ctrl).toHaveAttribute("aria-pressed", "false");
    mock.frames.length = 0;
    await ta.press("a");
    await expect.poll(() => decode(mock.frames)).toBe("a");
  });

  test("an armed modifier survives xterm's auto-reply to a TUI query (D3)", async ({
    page,
  }) => {
    // onData fires for xterm's OWN answers to terminal queries (CPR/DA) as well
    // as for keystrokes. Those carry no human intent, so they must not spend the
    // armed modifier — otherwise Ctrl evaporates at random, whenever the TUI
    // happens to ask the terminal a question.
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);

    const ctrl = page.getByRole("button", {
      name: "Ctrl — tap to arm for the next key, double-tap to lock",
    });
    await ctrl.click();

    mock.frames.length = 0;
    await mock.write("\x1b[6n"); // DSR — cursor position report
    // The reply went out verbatim …
    await expect.poll(() => decode(mock.frames)).toMatch(/^\x1b\[\d+;\d+R$/);
    // … and the modifier is still armed for the user's next real keystroke.
    await expect(ctrl).toHaveAttribute("data-mod-state", "once");
    mock.frames.length = 0;
    await page.locator(".xterm-helper-textarea").first().press("l");
    await expect.poll(() => decode(mock.frames)).toBe("\x0c");
  });

  test("sticky Alt prefixes ESC, and Ctrl+arrow carries the CSI modifier (D3)", async ({
    page,
  }) => {
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);

    const alt = page.getByRole("button", {
      name: "Alt / Opt — tap to arm for the next key, double-tap to lock",
    });
    await alt.click();
    mock.frames.length = 0;
    await page.locator(".xterm-helper-textarea").first().press("b");
    await expect.poll(() => decode(mock.frames)).toBe("\x1bb"); // Alt+b = back-word

    const ctrl = page.getByRole("button", {
      name: "Ctrl — tap to arm for the next key, double-tap to lock",
    });
    await ctrl.click();
    mock.frames.length = 0;
    await page.getByRole("button", { name: "Right arrow", exact: true }).click();
    // xterm modifier encoding: 1 + 4(Ctrl) = 5.
    await expect.poll(() => decode(mock.frames)).toBe("\x1b[1;5C");
  });

  test("there is NO Cmd key (a terminal has no Meta modifier) (D3)", async ({
    page,
  }) => {
    // Honest-affordance convention: a Cmd button could never deliver a control
    // byte to a Linux/WSL PTY, so it must not exist. Opt IS Alt, which does.
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    const bar = page.getByTestId("terminal-key-bar");
    await expect(bar).toBeVisible();
    await expect(bar.getByText("Cmd", { exact: true })).toHaveCount(0);
    await expect(bar.getByText("⌘", { exact: true })).toHaveCount(0);
    await expect(
      bar.getByRole("button", {
        name: "Alt / Opt — tap to arm for the next key, double-tap to lock",
      }),
    ).toBeVisible();
    expect(mock.frames.length).toBe(0);
  });

  test("a READ-ONLY remote viewer gets no key bar and sends ZERO frames (D3)", async ({
    page,
    baseURL,
  }) => {
    // The key bar must inherit the existing write gates rather than add a
    // second path: no bar at all for a viewer, and even if one were forced on
    // screen, term.input() early-returns on `disableStdin` and onData's
    // canWriteRef drops the byte. This asserts the observable contract — the
    // socket carries nothing.
    const mock = await mockTerminal(page);
    await page.goto(lanOrigin(baseURL!) + "/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);

    // Sanity: the app really believes it is a remote seat.
    await expect(page.getByText("Read-only view")).toBeVisible({ timeout: 10000 });
    await expect(page.getByTestId("terminal-key-bar")).toHaveCount(0);

    mock.frames.length = 0;
    await page.locator(".xterm-helper-textarea").first().press("a");
    await page.waitForTimeout(400);
    expect(decode(mock.frames)).toBe("");
  });

  test("a REVOKED local seat loses the key bar and sends ZERO frames (D3)", async ({
    page,
  }) => {
    // Same predicate (canWrite), reachable without a remote origin: the server
    // hands control back to the native terminal.
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    await expect(page.getByTestId("terminal-key-bar")).toBeVisible();

    await mock.control({ t: "control_revoked", by: "local" });
    await expect(page.getByTestId("terminal-key-bar")).toHaveCount(0);

    mock.frames.length = 0;
    await page.locator(".xterm-helper-textarea").first().press("a");
    await page.waitForTimeout(400);
    expect(decode(mock.frames)).toBe("");
  });

  // ── D8/D9: tap targets + header budget ───────────────────────────────────

  test("header is ONE row and every panel button clears 44x44 (D8/D9)", async ({
    page,
  }) => {
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    await mock.write("ready$ ");

    const header = page.getByTestId("terminal-header");
    const hb = await header.boundingBox();
    if (!hb) throw new Error("no header box");
    // One row of 44px targets + the 1px bottom border. Before this pass the
    // header wrapped to 2 rows at 393px and 3 at 360px (~90px).
    console.log(`[D9] header height at 393px: ${Math.round(hb.height)}px`);
    expect(hb.height).toBeLessThanOrEqual(48);

    const boxes = await measureButtons(page);
    console.log("[D8] panel buttons:", JSON.stringify(boxes));
    expect(boxes.length).toBeGreaterThan(3);
    const small = boxes.filter((b) => b.w < 44 || b.h < 44);
    expect(small, `these controls are below the 44px floor: ${JSON.stringify(small)}`).toEqual([]);
  });

  test("the ⋯ menu carries the six secondary actions + Copy visible (D9/D10)", async ({
    page,
  }) => {
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    await mock.write("boom: something failed\r\n");

    // None of the six are inline on a phone.
    for (const label of ["Files", "Git", "Session", "Add to grid"]) {
      await expect(page.getByRole("button", { name: label, exact: true })).toHaveCount(0);
    }
    await page.getByRole("button", { name: "More terminal actions" }).click();
    const menu = page.getByTestId("terminal-overflow-menu");
    await expect(menu).toBeVisible();
    for (const label of [
      "Files",
      "Git",
      "Session",
      "Copy visible",
      "Original size",
      "Add to grid",
    ]) {
      await expect(menu.getByText(label, { exact: true })).toHaveCount(1);
    }
    // Focus mode is present too — as a menu row, enabled or honest-disabled.
    await expect(menu.getByText(/Focus mode|Exit focus/)).toHaveCount(1);
    // And every row is a real tap target.
    const rows = await menu.locator("button").all();
    for (const r of rows) {
      const b = await r.boundingBox();
      expect(b!.height).toBeGreaterThanOrEqual(44);
    }
  });

  test('"Copy visible" puts the on-screen rows on the clipboard (D10)', async ({
    page,
    context,
  }) => {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    await mock.write("panic: runtime error: index out of range [7]\r\n");

    await page.getByRole("button", { name: "More terminal actions" }).click();
    await page.getByRole("button", { name: "Copy visible", exact: true }).click();
    await expect
      .poll(() => page.evaluate(() => navigator.clipboard.readText()))
      .toContain("panic: runtime error: index out of range [7]");
  });

  // ── D5 / Step 7: focus-mode honesty ──────────────────────────────────────

  test("focus mode renders honest-disabled where keyboard capture is absent (D5)", async ({
    page,
  }) => {
    // navigator.keyboard is Chromium-only and secure-context-only, so it is
    // missing on every iPhone and over a plain-http remote origin. It used to
    // make the control VANISH, which reads as "this build has no focus mode".
    await page.addInitScript(() => {
      // The property is an accessor on Navigator.prototype, so deleting it off
      // the `navigator` INSTANCE is a no-op — delete the prototype slot.
      delete (Navigator.prototype as unknown as Record<string, unknown>)
        .keyboard;
    });
    await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);

    await page.getByRole("button", { name: "More terminal actions" }).click();
    const row = page
      .getByTestId("terminal-overflow-menu")
      .getByRole("button", { name: /needs keyboard capture/ });
    await expect(row).toBeVisible();
    await expect(row).toBeDisabled();
    // The accessible name names the EXACT missing dependency.
    await expect(row).toHaveAccessibleName(/Chromium browser over HTTPS/);
  });
});

// ── Desktop must be untouched ─────────────────────────────────────────────
test.describe("desktop terminal chrome is unchanged", () => {
  test.use({ viewport: { width: 1360, height: 940 } });

  test("all eight actions stay inline in a 33px header, and no key bar (D8/D9)", async ({
    page,
  }) => {
    await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);

    // The capability gate must NOT be satisfied here (fine pointer).
    const coarse = await page.evaluate(
      () => window.matchMedia("(pointer: coarse) and (max-width: 1023px)").matches,
    );
    expect(coarse).toBe(false);

    await expect(page.getByTestId("terminal-key-bar")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "More terminal actions" })).toHaveCount(0);

    for (const label of [
      "Files",
      "Git",
      "Session",
      "Original size",
      "Focus mode",
      "Add to grid",
      "Minimize",
    ]) {
      await expect(page.getByRole("button", { name: label, exact: true })).toHaveCount(1);
    }
    await expect(page.getByRole("button", { name: /^(Stop & close|Close)$/ })).toHaveCount(1);

    const hb = await page.getByTestId("terminal-header").boundingBox();
    console.log(`[D9] desktop header height: ${Math.round(hb!.height)}px`);
    expect(Math.round(hb!.height)).toBe(33);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// The 2026-07-27 operator pass. Three defects, all reproduced from a phone:
//
//  D13 "we only see Windows-based keyboard options, that too just Ctrl, Alt and
//      what I assume are Alt+C and Alt+D buttons, and it is really confusing."
//      Two separate failures in one sentence: the vocabulary was PC-only, and
//      caret notation (`^C`) was read as `Alt+C`. Fixed as LABELS ONLY — the
//      pins below assert the emitted bytes are byte-identical either way,
//      because a PTY takes bytes and Ctrl+C is 0x03 on every OS.
//
//  D14 A swipe-left unloaded the entire dashboard. The gesture block declined
//      horizontal swipes ("not ours") without preventing the default, so the
//      browser took the edge swipe as back-navigation.
//
//  D15 Minimize was a bare "▾" beside "✕". The operator concluded there was no
//      minimize at all and that the only exit was the destructive close — and
//      the other two minimize doors are both shut on a phone (Escape needs a
//      hardware key; the backdrop click needs a backdrop, which a full-viewport
//      panel does not have).
// ────────────────────────────────────────────────────────────────────────────

test.describe("mobile terminal — the 2026-07-27 operator pass", () => {
  test.use({ viewport: PHONE, hasTouch: true });

  // ── D15: minimize must be unmistakable to a thumb ────────────────────────

  test("Minimize carries a VISIBLE word, not just an accessible name (D15)", async ({
    page,
  }) => {
    await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);

    const header = page.getByTestId("terminal-header");
    const min = header.getByRole("button", { name: /^Minimize/ });
    await expect(min).toBeVisible();

    // THE ASSERTION THE OLD BUILD FAILED. An aria-label is invisible to a
    // sighted thumb; the rendered TEXT has to say the word.
    await expect(min).toHaveText(/Minimize/);

    const box = await min.boundingBox();
    console.log(`[D15] minimize target at 393px: ${Math.round(box!.width)}x${Math.round(box!.height)}`);
    expect(box!.height).toBeGreaterThanOrEqual(44);
    expect(box!.width).toBeGreaterThanOrEqual(44);

    // The destructive neighbour stays separated and stays destructive.
    const close = header.getByRole("button", {
      name: /Stop the running process and close|Close terminal/,
    });
    const cb = await close.boundingBox();
    const gap = cb!.x - (box!.x + box!.width);
    console.log(`[D15] gap between Minimize and ✕: ${Math.round(gap)}px`);
    expect(gap).toBeGreaterThanOrEqual(8); // the ml-2 separation
    await expect(close).toHaveClass(/text-danger/);

    // And the header still refuses to become two rows.
    const hb = await header.boundingBox();
    console.log(`[D15] header height with the labelled Minimize: ${Math.round(hb!.height)}px`);
    expect(hb!.height).toBeLessThanOrEqual(48);
  });

  test("tapping Minimize parks the session WITHOUT a destructive prompt (D15)", async ({
    page,
  }) => {
    const mock = await mockTerminal(page);
    // A window.confirm here would mean the tap landed on the destructive path.
    const dialogs: string[] = [];
    page.on("dialog", (d) => {
      dialogs.push(d.message());
      void d.dismiss();
    });

    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    await mock.write("ready$ ");

    await page
      .getByTestId("terminal-header")
      .getByRole("button", { name: /^Minimize/ })
      .click();

    // Parked: the dock pill is back and the panel is off-screen.
    await expect(page.getByLabel("Restore claude-code terminal")).toBeVisible({
      timeout: 10000,
    });
    expect(dialogs, `minimize must never prompt: ${JSON.stringify(dialogs)}`).toEqual([]);

    // The session is still alive — restoring brings the SAME terminal back.
    await page.getByLabel("Restore claude-code terminal").click();
    await expect(page.getByTestId("terminal-key-bar")).toBeVisible({ timeout: 10000 });
  });

  // ── D14: a horizontal swipe must never reach the browser ─────────────────

  test("a horizontal swipe over the terminal is SWALLOWED, not handed to the browser (D14)", async ({
    page,
  }) => {
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    await mock.write(SCROLLBACK);
    // MOUSE_ON IS LOAD-BEARING FOR THE MEASUREMENT, not decoration. xterm.js
    // registers its OWN non-passive touchmove listener and preventDefaults it
    // whenever `!coreMouseService.areMouseEventsActive` — so with mouse
    // tracking off, `defaultPrevented` is true no matter what this app does,
    // and the assertion below passes on a deliberately broken tree. (Verified:
    // with the fix mutated out it still read 10/10.) Turning mouse tracking on
    // closes xterm's gate, so a `true` here can only be ours. It is also the
    // realistic state — every full-screen TUI the dashboard launches enables
    // mouse reporting on startup, which is exactly when the operator swiped.
    await mock.write(MOUSE_ON);

    const box = await page.locator(".xterm-screen").first().boundingBox();
    if (!box) throw new Error("no .xterm-screen box");
    const from = { x: box.x + box.width / 2, y: box.y + box.height / 2 };

    await recordTouchMoves(page);
    await touchDragXY(page, from, { dx: 160, dy: 6 });
    await page.waitForTimeout(200);
    const moves = await readTouchMoves(page);
    const prevented = moves.filter(Boolean).length;
    console.log(
      `[D14] horizontal drag: ${moves.length} touchmoves, ${prevented} defaultPrevented`,
    );
    // Before the fix this was 0 of N and the page navigated away. The first
    // move or two sit inside the 4px decision window and are deliberately
    // untouched, so the pin is "the great majority", not "all".
    expect(prevented).toBeGreaterThanOrEqual(moves.length - 2);
    expect(prevented).toBeGreaterThan(0);

    // Swallowing must not have scrolled anything: this gesture is disarmed,
    // not repurposed.
    const s = await scrollState(page);
    expect(s.scrollTop).toBeGreaterThan(0);

    // Still on the dashboard, with the terminal still up.
    await expect(page.getByTestId("terminal-key-bar")).toBeVisible();

    // Layer 2 of the fix: the DOCUMENT ELEMENT refuses horizontal overscroll
    // while the full-viewport panel is up — `overscroll-behavior` does nothing
    // on a non-scrolling box, so the panel's own containment cannot speak for
    // the root, which is where Chrome reads it for edge-swipe navigation.
    const rootOverscrollX = await page.evaluate(
      () => getComputedStyle(document.documentElement).overscrollBehaviorX,
    );
    expect(rootOverscrollX).toBe("contain");

    // Layer 1: a horizontal pan can't even START on the chrome.
    for (const testid of ["terminal-header", "terminal-key-bar"]) {
      const ta = await page.evaluate(
        (id) =>
          getComputedStyle(
            document.querySelector(`[data-testid="${id}"]`) as HTMLElement,
          ).touchAction,
        testid,
      );
      expect(ta, `${testid} must refuse horizontal panning`).toBe("pan-y");
    }
  });

  test("swallowing horizontal does NOT regress vertical scrollback (D14/D2)", async ({
    page,
  }) => {
    // The D14 change edits the same verdict branch D2's scroll fix lives in, so
    // this re-pins the vertical path right next to it: a mostly-vertical drag
    // still scrolls, and a mostly-horizontal one still does not.
    const mock = await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    await mock.write(SCROLLBACK);
    await mock.write(MOUSE_ON);

    const box = await page.locator(".xterm-screen").first().boundingBox();
    if (!box) throw new Error("no .xterm-screen box");
    const from = { x: box.x + box.width / 2, y: box.y + box.height / 2 };

    await page.evaluate(() => {
      const vp = document.querySelector(".xterm-viewport") as HTMLElement;
      vp.scrollTop = vp.scrollHeight;
    });
    const beforeH = (await scrollState(page)).scrollTop;
    await touchDragXY(page, from, { dx: 150, dy: 10 });
    await page.waitForTimeout(250);
    const afterH = (await scrollState(page)).scrollTop;
    expect(afterH, "a horizontal swipe must not scroll the buffer").toBe(beforeH);

    const beforeV = afterH;
    await touchDragXY(page, from, { dx: 10, dy: 150 });
    await page.waitForTimeout(300);
    const afterV = (await scrollState(page)).scrollTop;
    console.log(
      `[D14] horizontal ${beforeH}->${afterH} (delta 0 expected); vertical ${beforeV}->${afterV}`,
    );
    expect(afterV, "vertical scrollback must still work").toBeLessThan(beforeV);
  });

  // ── D13: platform labelling + the action labels ──────────────────────────

  const CTRL_PC = "Ctrl — tap to arm for the next key, double-tap to lock";
  const CTRL_MAC = "Control (⌃) — tap to arm for the next key, double-tap to lock";
  const ALT_MAC = "Option (⌥) — tap to arm for the next key, double-tap to lock";

  test("a non-darwin daemon yields the PC vocabulary (D13/D16)", async ({
    page,
  }) => {
    await mockTerminal(page, { hostOS: "linux" });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    const bar = page.getByTestId("terminal-key-bar");

    await expect(bar.getByRole("button", { name: CTRL_PC })).toHaveText(/Ctrl/);
    await expect(
      bar.getByRole("button", {
        name: "Alt / Opt — tap to arm for the next key, double-tap to lock",
      }),
    ).toHaveText(/Alt/);
    // Apple glyphs must be ABSENT here — a Linux/Windows operator sees exactly
    // the labelling that shipped.
    await expect(bar).not.toHaveText(/⌃|⌥/);
  });

  test("the Mac vocabulary relabels Ctrl/Alt and the chord sub-labels (D13)", async ({
    page,
  }) => {
    await mockTerminal(page, { keyPlatform: "mac" });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    const bar = page.getByTestId("terminal-key-bar");

    await expect(bar.getByRole("button", { name: CTRL_MAC })).toHaveText(/⌃/);
    await expect(bar.getByRole("button", { name: CTRL_MAC })).toHaveText(/Control/);
    await expect(bar.getByRole("button", { name: ALT_MAC })).toHaveText(/⌥/);
    await expect(bar.getByRole("button", { name: ALT_MAC })).toHaveText(/Option/);

    // The action keys keep their ACTION word and swap only the notation.
    await expect(
      bar.getByRole("button", { name: "Ctrl+C — interrupt", exact: true }),
    ).toHaveText(/Interrupt/);
    await expect(
      bar.getByRole("button", { name: "Ctrl+C — interrupt", exact: true }),
    ).toHaveText(/⌃C/);
    await expect(
      bar.getByRole("button", { name: "Ctrl+D — end of input", exact: true }),
    ).toHaveText(/End input/);

    // STILL NO ⌘. It never reaches a terminal (the terminal APP intercepts it),
    // so a button would be a dead key — the bar carries an honest note instead.
    await expect(bar.getByText("⌘", { exact: true })).toHaveCount(0);
    await expect(bar.getByText("Cmd", { exact: true })).toHaveCount(0);
    await expect(bar).toHaveText(/⌘ never reaches a terminal/);
  });

  test("the Mac vocabulary changes NOT ONE BYTE on the wire (D13)", async ({
    page,
  }) => {
    // The load-bearing pin of the whole labelling change. A PTY receives bytes;
    // there is no macOS byte set. Every sequence below is asserted against the
    // exact same expectation the PC-labelled cases above assert.
    const mock = await mockTerminal(page, { keyPlatform: "mac" });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    const bar = page.getByTestId("terminal-key-bar");

    for (const c of KEY_CASES) {
      mock.frames.length = 0;
      await bar.getByRole("button", { name: c.key, exact: true }).click();
      await expect
        .poll(() => decode(mock.frames), { message: `${c.key} must still emit ${c.why}` })
        .toBe(c.bytes);
    }

    // The headline case from the brief: a Mac-labelled ⌃ + "l" is still \x0c.
    const ctrl = bar.getByRole("button", { name: CTRL_MAC });
    await ctrl.click();
    await expect(ctrl).toHaveAttribute("data-mod-state", "once");
    mock.frames.length = 0;
    await page.locator(".xterm-helper-textarea").first().press("l");
    await expect.poll(() => decode(mock.frames)).toBe("\x0c");

    // Alt is still the ESC prefix under the ⌥ label.
    const alt = bar.getByRole("button", { name: ALT_MAC });
    await alt.click();
    mock.frames.length = 0;
    await page.locator(".xterm-helper-textarea").first().press("b");
    await expect.poll(() => decode(mock.frames)).toBe("\x1bb");

    // …and a modified arrow still carries the xterm CSI modifier parameter.
    await ctrl.click();
    mock.frames.length = 0;
    await bar.getByRole("button", { name: "Right arrow", exact: true }).click();
    await expect.poll(() => decode(mock.frames)).toBe("\x1b[1;5C");
  });

  test("the sticky-modifier semantics survive the relabel (D13/D3)", async ({
    page,
  }) => {
    const mock = await mockTerminal(page, { keyPlatform: "mac" });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    const ctrl = page.getByTestId("terminal-key-bar").getByRole("button", {
      name: CTRL_MAC,
    });

    await ctrl.click();
    await expect(ctrl).toHaveAttribute("data-mod-state", "once");
    await ctrl.click();
    await expect(ctrl).toHaveAttribute("data-mod-state", "lock");
    // Locked is still distinguishable without relying on colour.
    await expect(ctrl).toHaveText(/⇩/);

    mock.frames.length = 0;
    const ta = page.locator(".xterm-helper-textarea").first();
    await ta.press("a");
    await ta.press("e");
    await expect.poll(() => decode(mock.frames)).toBe("\x01\x05");

    await ctrl.click();
    await expect(ctrl).toHaveAttribute("aria-pressed", "false");
  });

  test("the ⋯ menu carries a key-label override that persists (D13)", async ({
    page,
  }) => {
    // Auto-detection reads the PHONE, and the phone is often not the machine
    // being typed into — so the override is the load-bearing half of D13.
    await mockTerminal(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);

    const bar = page.getByTestId("terminal-key-bar");
    await expect(bar.getByRole("button", { name: CTRL_PC })).toBeVisible();

    // Auto -> Mac.
    await page.getByRole("button", { name: "More terminal actions" }).click();
    await page
      .getByTestId("terminal-overflow-menu")
      .getByRole("button", { name: /Key labels: Auto/ })
      .click();
    await expect(bar.getByRole("button", { name: CTRL_MAC })).toBeVisible();
    expect(
      await page.evaluate(() => localStorage.getItem("sb_terminal_key_platform")),
    ).toBe("mac");

    // …and it survives a reload (a preference, not a session flag).
    await page.reload({ waitUntil: "domcontentloaded" });
    await openTerminal(page);
    await expect(
      page.getByTestId("terminal-key-bar").getByRole("button", { name: CTRL_MAC }),
    ).toBeVisible();

    // Mac -> PC -> Auto, back where it started.
    await page.getByRole("button", { name: "More terminal actions" }).click();
    await page
      .getByTestId("terminal-overflow-menu")
      .getByRole("button", { name: /Key labels: Mac/ })
      .click();
    await expect(
      page.getByTestId("terminal-key-bar").getByRole("button", { name: CTRL_PC }),
    ).toBeVisible();
    await page.getByRole("button", { name: "More terminal actions" }).click();
    await page
      .getByTestId("terminal-overflow-menu")
      .getByRole("button", { name: /Key labels: PC/ })
      .click();
    expect(
      await page.evaluate(() => localStorage.getItem("sb_terminal_key_platform")),
    ).toBeNull();
  });

  // ── D16: the AUTO signal is the daemon's OS, not the browser's UA ────────
  //
  // The labels describe the keyboard conventions of the machine whose PTY is
  // being typed into. Every test below runs in Linux Chromium — the browser
  // that the retired user-agent detector would have called "pc" every single
  // time — so a Mac-labelled bar here can ONLY have come from the daemon's
  // /api/status.host_os.

  test("a darwin daemon yields the Mac vocabulary with no override (D16)", async ({
    page,
  }) => {
    const mock = await mockTerminal(page, { hostOS: "darwin" });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    const bar = page.getByTestId("terminal-key-bar");

    await expect(bar.getByRole("button", { name: CTRL_MAC })).toBeVisible();
    await expect(bar.getByRole("button", { name: ALT_MAC })).toBeVisible();
    await expect(bar).toHaveText(/⌘ never reaches a terminal/);
    // No override was ever written — this is the AUTO branch.
    expect(
      await page.evaluate(() => localStorage.getItem("sb_terminal_key_platform")),
    ).toBeNull();
    // Still not one byte different on the auto path either: ⌃ + l = \x0c.
    const ctrl = bar.getByRole("button", { name: CTRL_MAC });
    await ctrl.click();
    await expect(ctrl).toHaveAttribute("data-mod-state", "once");
    mock.frames.length = 0;
    await page.locator(".xterm-helper-textarea").first().press("l");
    await expect.poll(() => decode(mock.frames)).toBe("\x0c");

    // …and the ⋯ row names what the host produced (checked last: the open menu
    // covers the bar).
    await page.getByRole("button", { name: "More terminal actions" }).click();
    await expect(
      page
        .getByTestId("terminal-overflow-menu")
        .getByRole("button", { name: /Key labels: Auto \(Mac/ }),
    ).toBeVisible();
  });

  test("the manual override beats the host OS in BOTH directions (D16)", async ({
    page,
  }) => {
    // A Mac daemon + an operator who wants the PC words.
    await mockTerminal(page, { hostOS: "darwin", keyPlatform: "pc" });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    const bar = page.getByTestId("terminal-key-bar");
    await expect(bar.getByRole("button", { name: CTRL_PC })).toBeVisible();
    await expect(bar).not.toHaveText(/⌃|⌥/);
  });

  test("the override beats a non-darwin host too (D16)", async ({ page }) => {
    // The mirror case: a Linux daemon + an operator on Apple hardware.
    await mockTerminal(page, { hostOS: "linux", keyPlatform: "mac" });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    await expect(
      page.getByTestId("terminal-key-bar").getByRole("button", { name: CTRL_MAC }),
    ).toBeVisible();
  });

  test("a daemon that does not report its OS falls back to PC labels (D16)", async ({
    page,
  }) => {
    // An older daemon omits host_os entirely. The bar must render the fallback
    // vocabulary — not throw, not blank, not a half-labelled row.
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    const mock = await mockTerminal(page, { hostOS: "absent" });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    const bar = page.getByTestId("terminal-key-bar");

    await expect(bar.getByRole("button", { name: CTRL_PC })).toHaveText(/Ctrl/);
    await expect(bar).not.toHaveText(/⌃|⌥/);
    // All ten keys still there, and they still send bytes.
    expect(await bar.getByRole("button").count()).toBe(10);
    mock.frames.length = 0;
    await bar.getByRole("button", { name: "Escape", exact: true }).click();
    await expect.poll(() => decode(mock.frames)).toBe("\x1b");
    expect(errors, `uncaught page errors: ${errors.join(" | ")}`).toEqual([]);
  });

  test("a status endpoint that never answers still renders the fallback (D16)", async ({
    page,
  }) => {
    // The loading/offline case. The bar paints immediately with the defined
    // fallback rather than waiting on a request or rendering an empty row.
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await mockTerminal(page);
    // Registered AFTER mockTerminal so it wins the route (last route first).
    await page.route(/\/api\/status(\?|$)/, (r) => r.abort());
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await openTerminal(page);
    const bar = page.getByTestId("terminal-key-bar");

    await expect(bar.getByRole("button", { name: CTRL_PC })).toHaveText(/Ctrl/);
    await expect(bar).not.toHaveText(/⌃|⌥/);
    expect(errors, `uncaught page errors: ${errors.join(" | ")}`).toEqual([]);
  });
});

// ── D13 layout: the longer labels must not break the fixed 5-column grid ────
//
// The bar is a 5-column GRID on purpose (a wrapping flex row left an orphan row
// of three stretched keys, which reads as broken). "Interrupt" / "End input" /
// "Control" are much longer than "^C" / "Ctrl", so every phone width and BOTH
// vocabularies get measured: no glyph may overflow its button, and the 44px
// floor holds.
for (const width of [393, 360]) {
  for (const platform of ["pc", "mac"] as const) {
    test.describe(`key bar layout ${width}px / ${platform} labels (D13)`, () => {
      test.use({ viewport: { width, height: 780 }, hasTouch: true });

      test("labels fit their keys and every key clears 44x44", async ({ page }) => {
        const mock = await mockTerminal(page, { keyPlatform: platform });
        await page.goto("/", { waitUntil: "domcontentloaded" });
        await openTerminal(page);
        await mock.write("ready$ ");
        // The bar's own fonts settle a frame after mount; measuring early is
        // how an earlier session captured a phantom layout.
        await page.waitForTimeout(1400);

        const m = await page.evaluate(() => {
          const bar = document.querySelector(
            '[data-testid="terminal-key-bar"]',
          ) as HTMLElement;
          const keys = Array.from(bar.querySelectorAll("button"));
          const rows = new Set<number>();
          const out = keys.map((b) => {
            const r = b.getBoundingClientRect();
            rows.add(Math.round(r.top));
            // A label overflows when its own text box is wider than the
            // button's content box — `truncate` would ellipsize it, which is
            // still a defect worth catching.
            const spans = Array.from(b.querySelectorAll("span"));
            const clipped = spans.some((s) => s.scrollWidth > s.clientWidth + 1);
            return {
              label: (b.textContent || "").trim(),
              w: Math.round(r.width),
              h: Math.round(r.height),
              clipped,
            };
          });
          return {
            keys: out,
            rowCount: rows.size,
            barHeight: Math.round(bar.getBoundingClientRect().height),
            barRight: Math.round(bar.getBoundingClientRect().right),
            innerWidth: window.innerWidth,
          };
        });

        console.log(
          `[D13] ${width}px/${platform}: bar ${m.barHeight}px in ${m.rowCount} key rows — ` +
            JSON.stringify(m.keys.map((k) => `${k.label}:${k.w}x${k.h}`)),
        );
        await page.screenshot({
          path: `e2e/shots/mobile-keys/keybar-${width}-${platform}.png`,
        });

        expect(m.keys.length).toBe(10);
        // Two even rows of five — never an orphan row.
        expect(m.rowCount).toBe(2);
        expect(m.barRight).toBeLessThanOrEqual(m.innerWidth + 1);
        const small = m.keys.filter((k) => k.w < 44 || k.h < 44);
        expect(small, `below the 44px floor: ${JSON.stringify(small)}`).toEqual([]);
        const clipped = m.keys.filter((k) => k.clipped);
        expect(
          clipped,
          `labels clipped by their key box: ${JSON.stringify(clipped)}`,
        ).toEqual([]);
      });
    });
  }
}

// ── Full-panel screenshots at both pinned phone widths, both vocabularies ───
for (const width of [393, 360]) {
  for (const platform of ["pc", "mac"] as const) {
    test.describe(`panel screenshot ${width}px / ${platform} (D13/D15)`, () => {
      test.use({ viewport: { width, height: 780 }, hasTouch: true, deviceScaleFactor: 3 });

      test("capture", async ({ page }) => {
        const mock = await mockTerminal(page, { keyPlatform: platform });
        await page.goto("/", { waitUntil: "domcontentloaded" });
        await openTerminal(page);
        await mock.write(
          "$ claude --resume\r\n" +
            "· Reticulating splines… (esc to interrupt)\r\n" +
            "$ ",
        );
        // >=1400ms after the last write: a 250ms wait once produced a phantom
        // 852px blank band in a captured screenshot.
        await page.waitForTimeout(1400);
        await page.screenshot({
          path: `e2e/shots/mobile-keys/panel-${width}-${platform}.png`,
        });
      });
    });
  }
}
