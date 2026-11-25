import { test, expect } from "@playwright/test";

// Terminal key / paste matrix (regression pin). Context: LaunchTerminal
// (src/components/LaunchTerminal.tsx) attaches an xterm customKeyEventHandler.
// xterm maps plain Ctrl+V to the control byte \x16 and CANCELS the keydown, so
// the browser paste never fires — that once silently swallowed dictation/paste
// input. The fix returns FALSE for the 'v'/'V' combo so xterm doesn't process
// it, the native paste fires, and xterm's own paste handler forwards the
// clipboard to the PTY. A future xterm upgrade could re-break this; these
// specs pin it.
//
// Harness: keystrokes leave the client as BINARY WebSocket frames
// (ws.send(new TextEncoder().encode(data)) in term.onData). We mock the
// /ws/launch/<token> socket with page.routeWebSocket and record the binary
// frames the page sends. A live session is injected via GET /api/launch/sessions
// (the dock rehydrate path), then restored from its minimized pill so the
// terminal is on-screen and focusable.

test.use({ viewport: { width: 1360, height: 940 } });

const TOKEN = ["kbd", "demo", "tok"].join("-");

type Sent = { frames: Buffer[] };

// mockTerminal wires the launch-session rehydrate + a recording WS mock.
// Returns the capture buffer the page's keystrokes accumulate into.
async function mockTerminal(
  page: import("@playwright/test").Page,
  opts: { hasProjectRoot?: boolean } = {},
): Promise<Sent> {
  const sent: Sent = { frames: [] };
  // Suppress the first-run tour: its full-viewport overlay would otherwise
  // intercept clicks on the dock pill / terminal (see tour.spec.ts).
  await page.addInitScript(() => {
    try {
      localStorage.setItem("sb_tour_completed", "1");
    } catch {
      /* private mode — ignore */
    }
  });
  const row: Record<string, unknown> = {
    subcommand: "claude-code",
    session_id: "s-kbd",
    exited: false,
    has_project_root: opts.hasProjectRoot ?? false,
  };
  row.token = TOKEN;
  await page.route("**/api/launch/sessions", (route) =>
    route.fulfill({ json: { sessions: [row] } }),
  );
  await page.routeWebSocket(/\/ws\/launch\//, (ws) => {
    // Do NOT connectToServer — the mock IS the server, so it opens immediately
    // (client ws.onopen → status "open" → canWrite true for a local seat).
    ws.onMessage((msg) => {
      // Resize control frames are JSON strings; keystrokes are binary.
      if (typeof msg !== "string") sent.frames.push(Buffer.from(msg));
    });
  });
  return sent;
}

// Bring the injected session on-screen: click its dock pill to restore the
// floating terminal, then focus the xterm grid so keystrokes route through it.
async function openTerminal(page: import("@playwright/test").Page) {
  // The restore pill carries a stable aria-label ("Restore <tool> terminal")
  // so it can be targeted independent of its visible text ("claude-code live ▴"),
  // which changes with connection status.
  const pill = page.getByLabel("Restore claude-code terminal");
  await expect(pill).toBeVisible({ timeout: 10000 });
  await pill.click();
  const xterm = page.locator(".xterm").first();
  await expect(xterm).toBeVisible({ timeout: 10000 });
  await xterm.click();
  // Wait for xterm to settle its focus on the helper textarea.
  await expect(xterm.locator(".xterm-helper-textarea")).toBeFocused();
}

function decode(sent: Sent): string {
  return Buffer.concat(sent.frames).toString("utf8");
}

test("printable chars + Enter reach the terminal data channel", async ({ page }) => {
  const sent = await mockTerminal(page);
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openTerminal(page);

  await page.keyboard.type("echo hi");
  await page.keyboard.press("Enter");

  await expect.poll(() => decode(sent)).toContain("echo hi");
  // Enter is transmitted as a carriage return (\r), not swallowed.
  await expect.poll(() => decode(sent)).toContain("\r");
});

test("plain Ctrl+V is NOT swallowed — pasted bytes reach the data channel", async ({
  page,
  context,
}) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const sent = await mockTerminal(page);
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openTerminal(page);

  const PAYLOAD = "pasted-via-ctrl-v";
  await page.evaluate((t) => navigator.clipboard.writeText(t), PAYLOAD);

  // Baseline: record what's already been sent, then press Ctrl+V.
  await page.keyboard.press("Control+v");
  await page.waitForTimeout(400);

  const out = decode(sent);
  // The regression byte: xterm mapping Ctrl+V → ^V (\x16) MUST NOT appear.
  expect(out.includes("\x16")).toBe(false);
  // And the clipboard payload IS forwarded to the PTY.
  await expect.poll(() => decode(sent)).toContain(PAYLOAD);
});

test("plain Ctrl+C (no selection) transmits ETX to the TUI", async ({ page }) => {
  // The handler only suppresses ^C when there is a selection (native copy);
  // with no selection, Ctrl+C is forwarded as \x03 so the TUI can interrupt.
  const sent = await mockTerminal(page);
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openTerminal(page);

  await page.keyboard.press("Control+c");
  await expect.poll(() => decode(sent)).toContain("\x03");
});
