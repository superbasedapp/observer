// integrity.ts — pure decision logic for the DB integrity banner (RES-3,
// codebase audit 2026-09-16). Turns the daemon's persisted startup
// `PRAGMA quick_check` verdict (StatusSnapshot.integrity, see
// internal/diag/status.go::IntegrityStatus) into banner copy. No fetch, no
// DOM — the IntegrityBanner component and the Settings -> Health row are
// both thin renderers over this.
import type { IntegrityStatus } from "@/lib/types";
import { fmtDateTime } from "@/lib/format";

export type IntegrityNotice = {
  // danger for a confirmed-corrupt database; warn for a probe that could
  // not complete (never rendered as corruption — that would be dishonest).
  tone: "danger" | "warn";
  label: string;
  text: string;
};

// integrityNotice returns null for "ok" and for an absent verdict (a
// database that has never been probed, or one size-gated off the check) —
// neither is a failure, and both must render nothing.
export function integrityNotice(
  integrity: IntegrityStatus | null | undefined,
): IntegrityNotice | null {
  if (!integrity) return null;
  const checkedAt = fmtDateTime(integrity.checked_at);
  const message = integrity.message?.trim();
  const detail = message ? `: ${message}` : "";

  if (integrity.status === "corrupt") {
    return {
      tone: "danger",
      label: "Database integrity",
      text: `Database integrity check failed on ${checkedAt}${detail}. Run \`observer doctor db\`.`,
    };
  }
  if (integrity.status === "error") {
    return {
      tone: "warn",
      label: "Integrity check",
      text: `Database integrity could not be verified on ${checkedAt}${detail}.`,
    };
  }
  // "ok" (or an unrecognized future status) - render nothing.
  return null;
}

export type IntegrityHealthRow = {
  status: "ok" | "warn" | "fail";
  message: string;
};

// integrityHealthRow renders ALL three states, INCLUDING "ok" - unlike
// integrityNotice, which renders nothing for "ok" because a banner should
// never announce good news. For the Settings -> Health additive row, an
// explicit muted "ok" row is the honest answer to "has this ever been
// checked, and what did it say" - null only when the daemon has never
// probed (nothing recorded yet, distinct from a probe that ran and passed).
export function integrityHealthRow(
  integrity: IntegrityStatus | null | undefined,
): IntegrityHealthRow | null {
  if (!integrity) return null;
  const checkedAt = fmtDateTime(integrity.checked_at);
  const message = integrity.message?.trim();
  const detail = message ? `: ${message}` : "";

  if (integrity.status === "ok") {
    return {
      status: "ok",
      message: `PRAGMA quick_check ok at startup (checked ${checkedAt})`,
    };
  }
  if (integrity.status === "corrupt") {
    return {
      status: "fail",
      message: `quick_check failed at startup on ${checkedAt}${detail}. Run \`observer doctor db\`.`,
    };
  }
  // "error": the probe could not COMPLETE - a timeout or locked file. Says
  // nothing about the data, so it is a warn, never a fail.
  return {
    status: "warn",
    message: `quick_check could not run at startup on ${checkedAt}${detail}.`,
  };
}

// integrityDismissKey identifies ONE verdict for per-session dismissal: a
// later probe that lands a different status or timestamp (e.g. after
// `observer doctor db` and a restart) re-shows even within the same tab
// session.
export function integrityDismissKey(integrity: IntegrityStatus): string {
  return `${integrity.status}|${integrity.checked_at}`;
}
