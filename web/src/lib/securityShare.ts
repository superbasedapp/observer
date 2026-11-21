// securityShare - the pure half of the Privacy page's "Code security
// sharing" picker (lane SEC-H2, security plan 6.5 "Share findings with the
// org").
//
// One key, org_client.share.security, written through the same PUT
// /api/config/keys path every schema-driven setting uses (dry run first).
// The picker offers the closed values (D-571, never typed). It is this
// machine's own setting: an organization never raises it remotely. On a
// managed machine the organization's managed pull decides instead (posture
// by default), so the picker there is shown read-only with that sentence.

import type { ConfigKeyPatch } from "./configSchema.ts";

/** Dotted config key the picker writes. */
export const SECURITY_SHARE_KEY = "org_client.share.security";

/** The closed values, in order (the schema's Off / Posture / Findings). */
export const SECURITY_SHARE_CHOICES = [
  {
    id: "off",
    label: "Off",
    sends: "Nothing about code security leaves this machine.",
  },
  {
    id: "posture",
    label: "Posture",
    sends:
      "One row a day of counts and states only: findings by category, severity and status, which security components run, scanner versions, scan freshness, advisory data age, platform gaps, launch trust and commit gate counts. No path, project, rule or name.",
  },
  {
    id: "findings",
    label: "Findings",
    sends:
      "The posture row, plus one row per finding: rule, category, severity, status, the project's hash, tool, model and times. Paths and redacted excerpts only if this machine already shares full content. A secret's value is never sent.",
  },
] as const;

export type SecurityShareLevel = (typeof SECURITY_SHARE_CHOICES)[number]["id"];

/**
 * securityShareLevel reads the level from GET /api/config's `config`
 * object: an unset or empty value is the default "posture" (ruling R1 of
 * lane CODESEC-ORG, 2026-11-03; the daemon resolves it the same way); a
 * value outside the
 * picker is null (an older or newer daemon), which offers no picker.
 */
export function securityShareLevel(config: unknown): SecurityShareLevel | null {
  if (!config || typeof config !== "object") return null;
  const oc = (config as Record<string, unknown>).OrgClient;
  if (!oc || typeof oc !== "object") return null;
  const share = (oc as Record<string, unknown>).Share;
  if (!share || typeof share !== "object") return null;
  const v = (share as Record<string, unknown>).Security;
  if (v === undefined || v === null || v === "") return "posture";
  return SECURITY_SHARE_CHOICES.some((c) => c.id === v) ? (v as SecurityShareLevel) : null;
}

/** securitySharePatch is the single-key patch, or null for no change. */
export function securitySharePatch(current: SecurityShareLevel, next: SecurityShareLevel): ConfigKeyPatch | null {
  if (current === next) return null;
  return { key: SECURITY_SHARE_KEY, value: next, was: current };
}

/** securityShareNote is the sentence under the picker for the tenancy. */
export function securityShareNote(managed: boolean): string {
  return managed
    ? "This machine is managed by your organization: its managed security policy decides what is shared (posture by default), so this setting does not apply here."
    : "Your choice, on this machine only. Your organization can never raise it. It is sent only while this machine is enrolled with an organization and the security module runs.";
}
