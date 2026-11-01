// packageChecks - the pure half of the Code security page's Package checks
// card (component security.deps; security pillar plan section 8.3, lane
// sec-d1fix milestone 3b).
//
// The card is where the online package checks' first-run disclosure is
// shown and accepted: the accept is an explicit click (POST
// /api/security/deps with the confirm token), never a side effect of
// starting the daemon. The online switch writes security.deps.online
// through the same PUT /api/config/keys path every schema-driven setting
// uses, so the "turn this off" the disclosure promises is one click here.

import type { ConfigKeyPatch } from "./configSchema.ts";

/** The online switch's dotted config key. */
export const PACKAGE_CHECKS_ONLINE_KEY = "security.deps.online";

/** One signed index kind's state (GET /api/security/deps). */
export type PackageChecksIndex = {
  kind: string;
  state: "installed" | "not_installed" | "unreadable" | string;
  version?: number;
  freshness?: string;
  last_failure?: string;
};

/** GET /api/security/deps `status`. */
export type PackageChecksStatus = {
  active: boolean;
  online: boolean;
  managed: boolean;
  accepted: boolean;
  accepted_at?: string;
  accepted_on?: string;
  text: string;
  /** The [security.deps].index_download switch; absent (an older daemon) reads on. */
  index_download?: boolean;
  not_set_up: boolean;
  index: PackageChecksIndex[] | null;
};

/** GET /api/security/deps. */
export type PackageChecksResponse = { status: PackageChecksStatus; confirm_token?: string };

export type PackageChecksStage = "inactive" | "waiting" | "on" | "offline";

/**
 * packageChecksStage is the card's state: inactive (the component is not
 * active), waiting (online checks are on but the disclosure is not
 * accepted, so nothing is sent yet), on, or offline (the online switch is
 * off: the signed offline lists only).
 */
export function packageChecksStage(s: PackageChecksStatus | null | undefined): PackageChecksStage {
  if (!s || !s.active) return "inactive";
  if (!s.online) return "offline";
  return s.accepted ? "on" : "waiting";
}

/** The card's copy per stage (no em dashes: copy rule). */
export const PACKAGE_CHECKS_COPY: Readonly<Record<PackageChecksStage, { label: string; tone: "success" | "warn" | "neutral"; summary: string }>> = {
  inactive: {
    label: "Not active",
    tone: "neutral",
    summary: "Package checks are not active on this node (Settings, Components).",
  },
  waiting: {
    label: "Waiting for you",
    tone: "warn",
    summary: "Online package checks are on, but nothing is sent until you read what they send and accept it here.",
  },
  on: {
    label: "On",
    tone: "success",
    summary: "Agent installs are checked against the signed offline lists and, for public names, online.",
  },
  offline: {
    label: "Offline lists only",
    tone: "neutral",
    summary: "Online checks are off: agent installs are checked against the signed offline lists only.",
  },
};

/** packageChecksOnlinePatch flips the online switch from `online`. */
export function packageChecksOnlinePatch(online: boolean): ConfigKeyPatch {
  return { key: PACKAGE_CHECKS_ONLINE_KEY, value: !online, was: online };
}

/**
 * packageChecksIndexLine renders one index kind in plain words: never a
 * claim the data does not support (an index not installed says so).
 */
export function packageChecksIndexLine(i: PackageChecksIndex): string {
  const name = i.kind.replace(/^security\./, "").replaceAll("_", " ");
  switch (i.state) {
    case "installed":
      return `${name}: version ${i.version ?? "?"}, ${i.freshness || "unknown"}`;
    case "not_installed":
      return `${name}: not installed yet`;
    default:
      return `${name}: state unreadable`;
  }
}

/**
 * packageChecksIndexDownloadNote is the card's line while the signed index
 * download is switched off (operator ruling PT-19), or null while it is on
 * (an older daemon that does not report it reads on).
 */
export function packageChecksIndexDownloadNote(s: PackageChecksStatus | null | undefined): string | null {
  if (!s || s.index_download !== false) return null;
  return "Index download off (security.deps.index_download): the checks use the index already on disk and nothing is fetched from superbased.app.";
}
