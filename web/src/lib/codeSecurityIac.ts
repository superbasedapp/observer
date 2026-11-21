// codeSecurityIac is the pure half of the Code security page's IaC scanners
// card (components security.scan.trivy and security.scan.kics, lane
// GATES-SEC; dashboard CLI parity plan B-CS2,
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md): each selected
// engine's guided install behind a confirm dialog that states the pin, the
// download size and the consent text before anything is downloaded, the
// dashboard form of `observer security iac install --engine <id>`.
//
// GET /api/security/iac/install answers the engines and a confirm token;
// POST {engine, sha256} records the consent for the pin the dialog showed
// and installs, and a pin that changed since is refused (409) with the new
// one. The route is owner-local, and the accept is the developer's, never an
// agent's (guard rule R-165 denies the route). Copy rule: no em dashes.

/** The route the card reads and posts to. */
export const IAC_INSTALL_ROUTE = "/api/security/iac/install";

/** One IaC engine as the route answers it (dashapi.IaCScannerRow). */
export type IaCEngineRow = {
  component: string;
  driver: string;
  kind: string;
  compiled: boolean;
  platform: string;
  beta: boolean;
  note: string;
  labels: string[];
  selected: boolean;
  install_pin?: string;
  install_bytes?: number;
  install_consent?: string;
  install_blocked?: string;
  installed: boolean;
};

/** GET /api/security/iac/install. */
export type IaCInstallResponse = { engines: IaCEngineRow[] | null; confirm_token?: string };

/** An engine's install state on the card. */
export type IaCStage = "installed" | "waiting" | "blocked" | "unavailable";

const ENGINE_NAMES: Readonly<Record<string, string>> = { trivy: "Trivy", kics: "KICS" };

/** iacEngineName is the engine's name in a sentence. */
export function iacEngineName(driver: string): string {
  return ENGINE_NAMES[driver] ?? driver;
}

/** iacShownEngines are the engines the card lists: in this build and
 *  selected (an engine that is off is turned on with its switch above, and
 *  nothing about it is read until then). */
export function iacShownEngines(r: IaCInstallResponse | null | undefined): IaCEngineRow[] {
  return (r?.engines ?? []).filter((e) => e.compiled && e.selected);
}

// IAC_STAGE_RULES: walked top-down, the first row that holds decides.
const IAC_STAGE_RULES: readonly { when: (e: IaCEngineRow) => boolean; stage: IaCStage }[] = [
  { when: (e) => e.installed, stage: "installed" },
  { when: (e) => !!e.install_blocked, stage: "blocked" },
  { when: (e) => !!e.install_pin, stage: "waiting" },
  { when: () => true, stage: "unavailable" },
];

/** iacStage is an engine's install state. */
export function iacStage(e: IaCEngineRow): IaCStage {
  return IAC_STAGE_RULES.find((r) => r.when(e))?.stage ?? "unavailable";
}

/** iacMB renders bytes as "about N MB" ("less than 1 MB", "an unknown amount"). */
export function iacMB(n: number | undefined): string {
  if (!n || n <= 0) return "an unknown amount";
  if (n < 1_000_000) return "less than 1 MB";
  return `about ${Math.round(n / 1_000_000)} MB`;
}

/** iacStageLine is the card's one line for an engine. */
export function iacStageLine(e: IaCEngineRow): string {
  const name = iacEngineName(e.driver);
  switch (iacStage(e)) {
    case "installed":
      return e.note || `${name} is installed.`;
    case "blocked":
      return `${name} cannot be installed here: ${e.install_blocked}.`;
    case "waiting":
      return `${name} is not installed: no process starts and projects read not scanned. Install the pinned release (${iacMB(e.install_bytes)} download).`;
    default:
      return e.note || `${name} is not installed, and no guided install applies here.`;
  }
}

/** iacInstallBody is the POST body for the pin the dialog showed, or null
 *  when there is no pin to accept. */
export function iacInstallBody(e: IaCEngineRow, seenPin: string): { engine: string; sha256: string } | null {
  if (!seenPin || iacStage(e) !== "waiting") return null;
  return { engine: e.driver, sha256: seenPin };
}

/** iacPinChanged reports that the pin the route now answers is not the one
 *  the dialog showed. */
export function iacPinChanged(e: IaCEngineRow | undefined, seenPin: string): boolean {
  return !!seenPin && !!e?.install_pin && e.install_pin !== seenPin;
}

/** iacErrorText is a refused POST's message: the route's detail when its
 *  body is JSON ({"error","detail"}), else the text, else the status. */
export function iacErrorText(text: string, status: number): string {
  try {
    const v = JSON.parse(text) as { detail?: unknown; error?: unknown };
    if (typeof v.detail === "string" && v.detail) return v.detail;
    if (typeof v.error === "string" && v.error) return v.error;
  } catch {
    // Not JSON: the text itself.
  }
  return text.trim() || `HTTP ${status}`;
}
