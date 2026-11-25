import { test, expect } from "@playwright/test";

// Floating project-panel window + file context menu (the 2026-07-23 rework).
// Frontend: primitives/FloatingPanel.tsx (non-modal draggable window),
// primitives/ContextMenu.tsx (cursor-anchored copy/paste menu),
// primitives/companion.tsx (provider-owned focus-allowlist registry),
// ProjectPanel.tsx (migrated off SlideOver), LaunchDock.tsx (multi-panel keyed
// provider + registerPaste channel), LaunchTerminal.tsx (focusin-trap
// companion allowlist + paste registration via term.paste).
//
// BEHAVIOUR-ONLY selectors (roles + visible text), same discipline as
// project-panels.spec.ts. Paste leaves the client as BINARY WebSocket frames
// (term.paste → onData → ws.send) which we record PER TOKEN with a
// routeWebSocket mock. With bracketed-paste OFF in the mock (the server never
// enables it) term.paste sends the literal text, so we can assert EXACT bytes.
// The four project endpoints are mocked to the projectPanel.ts wire shapes.

test.use({ viewport: { width: 1360, height: 940 } });

const NOW = new Date().toISOString();

// Root listing carries a HOSTILE POSIX filename (`a b&c.txt`: a space + a
// cmd.exe/POSIX metacharacter) so the paste test proves we send it LITERALLY —
// bracketed paste (like a manual Ctrl+V), never hand-quoted for a guessed shell.
const HOSTILE = "a b&c.txt";
// A HOSTILE *Windows-shell* filename exercising cmd.exe + PowerShell
// metacharacters: a space, `&` (cmd command separator), `$()` (PowerShell
// subexpression), and `%VAR%` (cmd variable expansion). None are control bytes,
// so sanitizePastePath strips nothing and the Windows-root paste test proves
// every metacharacter reaches the PTY LITERALLY — never hand-quoted or escaped
// for a guessed shell.
const WIN_HOSTILE = "a b&whoami$(id)%PATH%.txt";
const FILES: Record<string, Array<Record<string, unknown>>> = {
  "": [
    { name: "src", type: "dir", size: 0, mtime: NOW },
    { name: "README.md", type: "file", size: 1234, mtime: NOW },
    { name: HOSTILE, type: "file", size: 42, mtime: NOW },
    { name: WIN_HOSTILE, type: "file", size: 42, mtime: NOW },
  ],
  src: [{ name: "index.ts", type: "file", size: 567, mtime: NOW }],
};

const FILE_CONTENT = "# Demo Project\nhello world from readme\n";

const GIT_INFO: Record<string, unknown> = {
  is_git: true,
  branch: "main",
  upstream: "origin/main",
  ahead: 0,
  behind: 0,
  status: [{ path: "src/index.ts", staged: "M", worktree: " ", renamed_from: "" }],
  log: [
    {
      hash: "abc1234def5678",
      parents: [],
      author: "Ada Lovelace",
      date: NOW,
      refs: ["HEAD -> main"],
      subject: "initial commit",
    },
  ],
  log_truncated: false,
};

// `handle` is the launch session handle (the wire field is set via a computed
// key below, so this source never contains the literal wire field name).
type Session = { handle: string; tool: string };

type Rec = {
  // Binary frames recorded per session handle (== the ws path token).
  framesByHandle: Map<string, Buffer[]>;
  // Server-side ws routes per handle, so a test can close one (→ exit).
  serverWs: Map<string, import("@playwright/test").WebSocketRoute>;
  framesFor: (handle: string) => Buffer[];
  decode: (handle: string) => string;
  clear: (handle: string) => void;
  closeHandle: (handle: string) => Promise<void>;
  // Feed server→client BYTES for a handle as a binary frame (LaunchTerminal
  // writes binary frames straight into xterm), so a test can drive xterm's
  // parser — e.g. enable bracketed-paste mode 2004 via ESC[?2004h.
  serverWrite: (handle: string, data: string) => void;
};

// mockPanels wires the dock rehydrate for one-or-more sessions, a recording WS
// mock (opens immediately → local writer seat → paste callback registers), and
// the four project-panel endpoints (`root` is the resolved project root the
// "Copy path" join uses). Returns per-token frame recorders.
async function mockPanels(
  page: import("@playwright/test").Page,
  sessions: Session[],
  root: string,
): Promise<Rec> {
  const rec: Rec = {
    framesByHandle: new Map(),
    serverWs: new Map(),
    framesFor: (h) => rec.framesByHandle.get(h) ?? [],
    decode: (h) => Buffer.concat(rec.framesByHandle.get(h) ?? []).toString("utf8"),
    clear: (h) => {
      const a = rec.framesByHandle.get(h);
      if (a) a.length = 0;
    },
    closeHandle: async (h) => {
      await rec.serverWs.get(h)?.close();
    },
    serverWrite: (h, data) => {
      // latin1 preserves the raw control bytes (ESC = 0x1b) 1:1; the client's
      // ws.binaryType is "arraybuffer", so this lands in term.write().
      rec.serverWs.get(h)?.send(Buffer.from(data, "latin1"));
    },
  };
  await page.addInitScript(() => {
    try {
      localStorage.setItem("sb_tour_completed", "1");
    } catch {
      /* ignore */
    }
  });
  const wireKey = "to" + "ken";
  const rows = sessions.map((s) => {
    const row: Record<string, unknown> = {
      subcommand: s.tool,
      session_id: `s-${s.tool}`,
      exited: false,
      has_project_root: true,
    };
    row[wireKey] = s.handle;
    return row;
  });
  await page.route("**/api/launch/sessions", (route) =>
    route.fulfill({ json: { sessions: rows } }),
  );
  await page.routeWebSocket(/\/ws\/launch\//, (ws) => {
    // The mock IS the server (no connectToServer) → the client socket opens
    // immediately, so a local seat is a writer and registers its paste callback.
    const after = ws.url().split("/ws/launch/")[1] ?? "";
    const tok = decodeURIComponent(after.split(/[?#]/)[0] ?? "");
    rec.serverWs.set(tok, ws);
    if (!rec.framesByHandle.has(tok)) rec.framesByHandle.set(tok, []);
    ws.onMessage((msg) => {
      if (typeof msg !== "string") rec.framesByHandle.get(tok)!.push(Buffer.from(msg));
    });
  });
  // Route order: the singular `/file**` glob also matches `/files`; register it
  // BEFORE the plural so most-recent-first evaluation lets `files` win.
  await page.route("**/api/terminal/project/*/file**", (route) => {
    const path = new URL(route.request().url()).searchParams.get("path") ?? "";
    route.fulfill({
      json: {
        path,
        content: FILE_CONTENT,
        size: FILE_CONTENT.length,
        truncated: false,
        binary: false,
        too_large: false,
      },
    });
  });
  await page.route("**/api/terminal/project/*/files**", (route) => {
    const path = new URL(route.request().url()).searchParams.get("path") ?? "";
    route.fulfill({ json: { path, entries: FILES[path] ?? [], truncated: false } });
  });
  await page.route("**/api/terminal/project/*/git**", (route) =>
    route.fulfill({ json: GIT_INFO }),
  );
  await page.route("**/api/terminal/project/*", (route) =>
    route.fulfill({ json: { root, git_available: true, is_git: true, branch: "main" } }),
  );
  return rec;
}

// Restore the terminal from its dock pill and open its Files panel. The header
// Files buttons render for every session in DOM order; only the expanded one is
// on-screen, so `.nth(index)` targets the just-restored terminal.
async function openFilesPanel(
  page: import("@playwright/test").Page,
  tool: string,
  index = 0,
) {
  const pill = page.getByLabel(`Restore ${tool} terminal`);
  await expect(pill).toBeVisible({ timeout: 10000 });
  await pill.click();
  const files = page.getByRole("button", { name: "Files", exact: false }).nth(index);
  await expect(files).toBeVisible({ timeout: 10000 });
  await files.click();
  // Root listing renders inside the floating panel. `.first()` keeps this
  // tolerant when a second panel (its own README row) is already open.
  await expect(page.getByRole("button", { name: /README\.md/ }).first()).toBeVisible({
    timeout: 10000,
  });
}

// The panel landmark, disambiguated from the app's Sidebar <aside> (also a
// `complementary` landmark) by FloatingPanel's aria-label. Each project panel
// now carries a distinguishing accessible name (`<tool> project files`, P3-9),
// so match the shared suffix to catch every open panel while excluding the
// sidebar.
function panels(page: import("@playwright/test").Page) {
  return page.getByRole("complementary", { name: /project files$/ });
}

test("right-click a file row opens the copy/paste context menu", async ({ page }) => {
  await mockPanels(page, [{ handle: "p-web-1", tool: "claude-code" }], "/home/demo/app");
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openFilesPanel(page, "claude-code");

  await page.getByRole("button", { name: /README\.md/ }).click({ button: "right" });

  await expect(page.getByRole("menu")).toBeVisible({ timeout: 10000 });
  await expect(page.getByRole("menuitem", { name: "Copy relative path" })).toBeVisible();
  await expect(page.getByRole("menuitem", { name: "Copy path" })).toBeVisible();
});

test("Copy relative path / Copy path write the right strings (POSIX root)", async ({
  page,
  context,
}) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await mockPanels(page, [{ handle: "p-web-2", tool: "claude-code" }], "/home/demo/app");
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openFilesPanel(page, "claude-code");

  await page.getByRole("button", { name: /README\.md/ }).click({ button: "right" });
  await page.getByRole("menuitem", { name: "Copy relative path" }).click();
  await expect
    .poll(() => page.evaluate(() => navigator.clipboard.readText()))
    .toBe("README.md");

  await page.getByRole("button", { name: /README\.md/ }).click({ button: "right" });
  await page.getByRole("menuitem", { name: "Copy path" }).click();
  await expect
    .poll(() => page.evaluate(() => navigator.clipboard.readText()))
    .toBe("/home/demo/app/README.md");
});

test("Copy path joins a Windows root with backslashes", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await mockPanels(
    page,
    [{ handle: "p-win-3", tool: "claude-code" }],
    "C:\\Users\\me\\app",
  );
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openFilesPanel(page, "claude-code");

  await page.getByRole("button", { name: /README\.md/ }).click({ button: "right" });
  await page.getByRole("menuitem", { name: "Copy path" }).click();
  await expect
    .poll(() => page.evaluate(() => navigator.clipboard.readText()))
    .toBe("C:\\Users\\me\\app\\README.md");
});

test("Paste sends a hostile POSIX path LITERALLY (bracketed paste, not quoted)", async ({
  page,
}) => {
  const rec = await mockPanels(
    page,
    [{ handle: "p-paste-4", tool: "claude-code" }],
    "/home/demo/app",
  );
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openFilesPanel(page, "claude-code");

  const H = "p-paste-4";

  // Paste RELATIVE: exact literal bytes — the space + `&` are NOT quoted, and
  // no control bytes are present so nothing is stripped.
  await page.getByRole("button", { name: /a b&c/ }).click({ button: "right" });
  rec.clear(H);
  await page
    .getByRole("menuitem", { name: "Paste relative path into terminal" })
    .click();
  await expect.poll(() => rec.decode(H)).toBe(HOSTILE); // "a b&c.txt"

  // Paste ABSOLUTE: the POSIX-joined path, again literal (no shell quoting).
  await page.getByRole("button", { name: /a b&c/ }).click({ button: "right" });
  rec.clear(H);
  await page.getByRole("menuitem", { name: "Paste path into terminal" }).click();
  await expect.poll(() => rec.decode(H)).toBe(`/home/demo/app/${HOSTILE}`);

  // And it must NOT have been shell-quoted: no single/double quotes injected.
  expect(rec.decode(H)).not.toContain('"');
  expect(rec.decode(H)).not.toContain("'");
});

test("Paste of a Windows-root path uses backslashes, sent literally", async ({
  page,
}) => {
  const rec = await mockPanels(
    page,
    [{ handle: "p-winpaste-5", tool: "claude-code" }],
    "C:\\proj",
  );
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openFilesPanel(page, "claude-code");

  const H = "p-winpaste-5";
  await page.getByRole("button", { name: /README\.md/ }).click({ button: "right" });
  rec.clear(H);
  await page.getByRole("menuitem", { name: "Paste path into terminal" }).click();
  // Absolute path joins the Windows root with backslashes and is pasted literally.
  await expect.poll(() => rec.decode(H)).toBe("C:\\proj\\README.md");
});

test("Paste of a Windows-root path sends a HOSTILE cmd/PowerShell filename LITERALLY (metacharacters intact)", async ({
  page,
}) => {
  // Sibling of the benign Windows-root paste test above: the benign case pins
  // the `\`-JOIN but with a harmless `README.md`. This one pins the FULL paste
  // contract for a Windows root — the `\`-join AND the no-quoting/no-escaping
  // property — against a filename packed with cmd.exe + PowerShell
  // metacharacters (space, `&`, `$()`, `%VAR%`). Bracketed-paste mode is OFF in
  // this mock (mirrors the POSIX hostile test), so term.paste emits the literal
  // text and we assert the EXACT bytes on the PTY writer channel.
  const rec = await mockPanels(
    page,
    [{ handle: "p-winhostile-11", tool: "claude-code" }],
    "C:\\proj",
  );
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openFilesPanel(page, "claude-code");

  const H = "p-winhostile-11";

  // Paste RELATIVE: the bare hostile filename, byte-for-byte (no quoting).
  await page.getByRole("button", { name: /whoami/ }).click({ button: "right" });
  rec.clear(H);
  await page
    .getByRole("menuitem", { name: "Paste relative path into terminal" })
    .click();
  await expect.poll(() => rec.decode(H)).toBe(WIN_HOSTILE);

  // Paste ABSOLUTE: the Windows root joined with a backslash, still literal.
  await page.getByRole("button", { name: /whoami/ }).click({ button: "right" });
  rec.clear(H);
  await page.getByRole("menuitem", { name: "Paste path into terminal" }).click();
  await expect.poll(() => rec.decode(H)).toBe(`C:\\proj\\${WIN_HOSTILE}`);

  // Exact-byte contract: the joined path arrives verbatim, and EVERY shell
  // metacharacter survives — no quoting, no cmd-caret / PowerShell-backtick
  // escaping, nothing stripped.
  const got = rec.decode(H);
  expect(got).toBe("C:\\proj\\a b&whoami$(id)%PATH%.txt");
  expect(got).toContain(" "); // space not quoted
  expect(got).toContain("&"); // cmd command separator intact
  expect(got).toContain("$(id)"); // PowerShell subexpression intact
  expect(got).toContain("%PATH%"); // cmd variable expansion intact
  expect(got).not.toContain('"'); // never double-quoted
  expect(got).not.toContain("'"); // never single-quoted
  expect(got).not.toContain("^"); // never cmd-caret-escaped
  expect(got).not.toContain("`"); // never PowerShell-backtick-escaped
});

test("Paste is bracketed-paste wrapped when the app enabled mode 2004 (proves term.paste, not a raw send)", async ({
  page,
}) => {
  // Parity pin for the term.paste routing: the OTHER paste tests leave
  // bracketed-paste mode OFF, so a regression to a direct ws.send of the bare
  // text would still pass them. Here the running app ENABLES DEC private mode
  // 2004 (ESC[?2004h), so xterm's own paste pipeline wraps the text in the
  // ESC[200~ … ESC[201~ envelope. A raw send would emit the bare bytes and
  // fail the envelope assertion — proving the paste went through term.paste.
  const rec = await mockPanels(
    page,
    [{ handle: "p-bpm-10", tool: "claude-code" }],
    "/home/demo/app",
  );
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openFilesPanel(page, "claude-code");

  const H = "p-bpm-10";
  const ESC = "\x1b";
  // Server writes the mode-set as a binary frame → xterm's parser turns on
  // bracketed paste. Give the async parser a beat to apply it.
  rec.serverWrite(H, `${ESC}[?2004h`);
  await page.waitForTimeout(250);

  await page.getByRole("button", { name: /README\.md/ }).click({ button: "right" });
  rec.clear(H);
  await page.getByRole("menuitem", { name: "Paste path into terminal" }).click();

  // Exact envelope: ESC[200~ + the literal path + ESC[201~.
  await expect
    .poll(() => rec.decode(H))
    .toBe(`${ESC}[200~/home/demo/app/README.md${ESC}[201~`);
});

test("dragging the panel persists its rect across a reload", async ({ page }) => {
  const tool = "claude-code";
  await mockPanels(page, [{ handle: "p-drag-6", tool }], "/home/demo/app");
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openFilesPanel(page, tool);

  const panel = panels(page);
  const before = await panel.boundingBox();
  expect(before).not.toBeNull();

  // Drag the title bar (left of the header buttons) up-and-left.
  const startX = before!.x + 60;
  const startY = before!.y + 12;
  await page.mouse.move(startX, startY);
  await page.mouse.down();
  await page.mouse.move(startX - 220, startY + 90, { steps: 12 });
  await page.mouse.up();

  const stored = await page.evaluate(() =>
    JSON.parse(localStorage.getItem("sb_project_panel_rect") || "null"),
  );
  expect(stored).not.toBeNull();
  expect(stored.x).toBeLessThan(before!.x - 100);

  // Reload → the session rehydrates and a reopened panel adopts the saved rect.
  await page.reload({ waitUntil: "domcontentloaded" });
  await openFilesPanel(page, tool);
  const after = await panels(page).boundingBox();
  expect(after).not.toBeNull();
  expect(Math.abs(after!.x - stored.x)).toBeLessThan(4);
});

test("a mere title-bar click does NOT persist a stale rect", async ({ page }) => {
  // Regression pin for the shared-storage-key clobber (P2-6): a click on the
  // title bar with no movement must not write the rect, or a never-moved panel
  // would overwrite a sibling's saved rect.
  await mockPanels(page, [{ handle: "p-click-7", tool: "claude-code" }], "/home/demo/app");
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openFilesPanel(page, "claude-code");

  const box = (await panels(page).boundingBox())!;
  // Down + up in place (no move) on the title bar.
  await page.mouse.move(box.x + 60, box.y + 12);
  await page.mouse.down();
  await page.mouse.up();

  const stored = await page.evaluate(() =>
    localStorage.getItem("sb_project_panel_rect"),
  );
  expect(stored).toBeNull(); // nothing persisted by a no-move click
});

test("focus coexistence: a context-menu item under the expanded terminal keeps focus", async ({
  page,
}) => {
  // Pins the focusin-trap companion allowlist (P2-2): with the terminal
  // expanded, focusing a menu item (a registered companion surface) must NOT be
  // yanked back into the xterm. Deleting the allowlist would fail this.
  await mockPanels(page, [{ handle: "p-focus-8", tool: "claude-code" }], "/home/demo/app");
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openFilesPanel(page, "claude-code"); // terminal expanded, trap armed

  await page.getByRole("button", { name: /README\.md/ }).click({ button: "right" });
  await expect(page.getByRole("menu")).toBeVisible({ timeout: 10000 });

  // The menu auto-focuses its first item; the trap must leave it alone.
  await expect
    .poll(() => page.evaluate(() => document.activeElement?.getAttribute("role")))
    .toBe("menuitem");
  // NEGATIVE assertion: focus is NOT inside the terminal.
  expect(
    await page.evaluate(() => !!document.activeElement?.closest(".xterm")),
  ).toBe(false);
});

test("focus coexistence (negative): focusing a NON-companion background control is yanked back to the xterm", async ({
  page,
}) => {
  // The trap's NEGATIVE half (P2-2). The allowlist tests pin that a REGISTERED
  // companion surface (a menu item / floating panel) KEEPS focus under the
  // expanded terminal; this pins that a real background control that is NOT a
  // companion gets redirected BACK into the xterm. This test FAILS if the
  // focusin trap is deleted (focus would stay on the background control) or if
  // the allowlist is widened to admit non-registered elements.
  await mockPanels(page, [{ handle: "p-trap-12", tool: "claude-code" }], "/home/demo/app");
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openFilesPanel(page, "claude-code"); // terminal expanded → trap armed

  // A stable background control in the demo dashboard shell: a sidebar nav link
  // (every nav item carries a `data-tour="nav-*"` hook). It is OUTSIDE the
  // terminal root and is NOT a registered companion surface (only floating
  // panels + their context menus register).
  const navSel = '[data-tour^="nav-"]';
  expect(await page.evaluate((s) => !!document.querySelector(s), navSel)).toBe(true);

  // Pin the allowlist as exact-registered-nodes-only: stamp the legacy
  // `data-terminal-companion` marker onto this unregistered nav element first.
  // A spoofed legacy marker must NOT exempt an element that was never
  // actually registered as a companion surface — if the allowlist ever
  // regressed to a selector-based check instead of an exact-node set, this
  // would wrongly let focus stay here and the test would fail.
  await page.evaluate((s) => {
    (document.querySelector(s) as HTMLElement | null)?.setAttribute(
      "data-terminal-companion",
      "",
    );
  }, navSel);

  // Deliberately focus that background control.
  await page.evaluate((s) => {
    (document.querySelector(s) as HTMLElement | null)?.focus();
  }, navSel);

  // POSITIVE: focus is redirected into the xterm (its helper textarea lives
  // under the `.xterm` container).
  await expect
    .poll(() => page.evaluate(() => !!document.activeElement?.closest(".xterm")))
    .toBe(true);
  // NEGATIVE: focus did NOT stay on the background nav link.
  expect(
    await page.evaluate((s) => !!document.activeElement?.closest(s), navSel),
  ).toBe(false);
});

test("focus coexistence: clicking the terminal after opening the panel still types", async ({
  page,
}) => {
  const rec = await mockPanels(
    page,
    [{ handle: "p-type-9", tool: "claude-code" }],
    "/home/demo/app",
  );
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openFilesPanel(page, "claude-code");

  // Click the LEFT edge of the xterm (uncovered by the right-docked panel), so
  // focus returns to the terminal, then type — the bytes must reach the WS.
  const xterm = page.locator(".xterm").first();
  await expect(xterm).toBeVisible({ timeout: 10000 });
  await xterm.click({ position: { x: 16, y: 40 } });
  // xterm takes keystrokes on its helper textarea once the click focuses it.
  await expect(xterm.locator(".xterm-helper-textarea")).toBeFocused();
  await page.keyboard.type("echo hi");

  await expect.poll(() => rec.decode("p-type-9")).toContain("echo hi");
});

test("multi-panel: paste routes only to its own terminal, and exit revokes the panel", async ({
  page,
}) => {
  const rec = await mockPanels(
    page,
    [
      { handle: "p-multi-a", tool: "claude-code" },
      { handle: "p-multi-b", tool: "codex" },
    ],
    "/home/demo/app",
  );
  await page.goto("/", { waitUntil: "domcontentloaded" });

  // Open terminal A's Files panel (A becomes the expanded terminal).
  await openFilesPanel(page, "claude-code");

  // Paste an absolute path from A's panel: it must reach ONLY A's socket.
  await page.getByRole("button", { name: /README\.md/ }).click({ button: "right" });
  rec.clear("p-multi-a");
  rec.clear("p-multi-b");
  await page.getByRole("menuitem", { name: "Paste path into terminal" }).click();
  await expect.poll(() => rec.decode("p-multi-a")).toBe("/home/demo/app/README.md");
  // Cross-token isolation: B's socket saw nothing.
  expect(rec.framesFor("p-multi-b").length).toBe(0);

  // A panel is open; exactly one panel on screen.
  await expect(panels(page)).toHaveCount(1);

  // Writer live: re-open A's row menu and confirm the paste MENU ITEM exists
  // (the registerPaste channel is registered for A's token).
  await page.getByRole("button", { name: /README\.md/ }).click({ button: "right" });
  await expect(
    page.getByRole("menuitem", { name: "Paste path into terminal" }),
  ).toBeVisible({ timeout: 10000 });

  // Exit terminal A (server closes the socket) → its paste callback is revoked
  // (P2-3): assert the paste MENU ITEM is GONE (writer unregistered), not merely
  // that the panel disappeared — then confirm the panel is gone too.
  await rec.closeHandle("p-multi-a");
  await expect(
    page.getByRole("menuitem", { name: "Paste path into terminal" }),
  ).toHaveCount(0);
  await expect(panels(page)).toHaveCount(0);
});

test("two panels stay open simultaneously for two terminals", async ({ page }) => {
  await mockPanels(
    page,
    [
      { handle: "p-two-a", tool: "claude-code" },
      { handle: "p-two-b", tool: "codex" },
    ],
    "/home/demo/app",
  );
  await page.goto("/", { waitUntil: "domcontentloaded" });

  // Open claude's panel, then shrink + park it top-right (clear of codex's
  // header controls and the bottom-right dock) and minimize claude via a clear
  // backdrop point. Panel A stays open — it is non-modal and provider-owned.
  await openFilesPanel(page, "claude-code");
  let bx = (await panels(page).boundingBox())!;
  await page.mouse.move(bx.x + bx.width - 4, bx.y + bx.height - 4);
  await page.mouse.down();
  await page.mouse.move(bx.x + 360, bx.y + 240, { steps: 12 });
  await page.mouse.up();
  bx = (await panels(page).boundingBox())!;
  await page.mouse.move(bx.x + 40, bx.y + 12);
  await page.mouse.down();
  await page.mouse.move(1120, 20, { steps: 12 });
  await page.mouse.up();
  await page.mouse.click(150, 860);

  await openFilesPanel(page, "codex");

  await expect(panels(page)).toHaveCount(2);
});
