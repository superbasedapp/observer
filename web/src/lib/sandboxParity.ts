// sandboxParity.ts holds the pure models behind the sandbox controls the
// dashboard CLI parity plan added (docs/plans/dashboard-cli-parity-plan-
// 2026-11-06.md, lane L3): the credential injection key field (B-G1), the
// hosted Connect form (B-G2), the re-attach terminal (B-G3), the hosted and
// Windows row fields (B-G6) and the image set import (B-G7). Each check here
// only helps the user before a save; the daemon checks every value again.

/** MXC_TIER_OPTIONS is the closed [terminal.sandbox.windows].mxc_tier set,
 * strictest first ("" is no floor, the default). */
export const MXC_TIER_OPTIONS: { value: string; label: string; detail: string }[] = [
  {
    value: "process_container",
    label: "ProcessContainer only",
    detail: "The weaker AppContainer row is refused on this machine.",
  },
  {
    value: "appcontainer",
    label: "AppContainer allowed",
    detail: "The AppContainer row may be used (weaker: it sees every folder granted to ALL APPLICATION PACKAGES).",
  },
  { value: "", label: "No floor", detail: "The default: the AppContainer row may be used." },
];

// MXC_TIER_RANK orders the floor by strictness, higher is stricter (the
// daemon's mxcTierRank in terminal_sandbox_config_tiers.go).
const MXC_TIER_RANK: Record<string, number> = { "": 0, appcontainer: 0, process_container: 1 };

/** mxcTierLoosens reports whether moving the floor from saved to next lets
 * this machine use MXC's weaker AppContainer tier where it could not before:
 * the save then asks for a confirm. */
export function mxcTierLoosens(saved: string | undefined, next: string | undefined): boolean {
  return (MXC_TIER_RANK[(next ?? "").trim()] ?? 0) < (MXC_TIER_RANK[(saved ?? "").trim()] ?? 0);
}

/** hostedFieldIsSecret reports whether a provider credential field holds a
 * secret (a password input that never shows what was typed); an *_ID field
 * names an account, team or project and is a plain text input. */
export function hostedFieldIsSecret(name: string): boolean {
  return !/_ID$/i.test(name.trim());
}

/** hostedConnectReady reports whether every field the provider needs has a
 * value, so the Connect button can be pressed. */
export function hostedConnectReady(names: string[], values: Record<string, string>): boolean {
  return names.length > 0 && names.every((n) => (values[n] ?? "").trim() !== "");
}

/** credKeyProblem mirrors the daemon's credAdd check of a key (empty, too
 * long, or holding a space or a line break); null when it looks like a key.
 * It never repeats the value. */
export function credKeyProblem(key: string): string | null {
  const k = key.trim();
  if (k === "") return "Paste the key first.";
  if (k.length > 4096 || /[\s\0]/.test(k)) return "That is not a key: it is too long, or it holds a space or a line break.";
  return null;
}

// HOSTED_TEMPLATE_RE mirrors the config's hostedTemplateRE
// (internal/config/config.go): a template, image or runtime name.
const HOSTED_TEMPLATE_RE = /^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$/;

/** hostedTemplateProblem: "" (the vendor default) passes; anything else
 * must be a template, image or runtime name. */
export function hostedTemplateProblem(template: string): string | null {
  const v = template.trim();
  if (v === "" || HOSTED_TEMPLATE_RE.test(v)) return null;
  return "Use a template, image or runtime name: letters, digits and . _ / : @ - only.";
}

// WSLC_IMAGE_RE mirrors internal/sandboxwslc.ValidImage.
const WSLC_IMAGE_RE = /^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$/;

/** wslcImageProblem: "" (not set) passes; anything else must be pinned by
 * its digest. */
export function wslcImageProblem(image: string): string | null {
  const v = image.trim();
  if (v === "" || WSLC_IMAGE_RE.test(v)) return null;
  return "Pin the image by its digest: name@sha256: followed by 64 lowercase hex characters.";
}

/** isAbsolutePath accepts a POSIX path, a Windows drive path or a UNC path. */
export function isAbsolutePath(p: string): boolean {
  return /^(\/|[A-Za-z]:[\\/]|\\\\)/.test(p);
}

/** absPathProblem: "" (not set) passes; anything else must be absolute. */
export function absPathProblem(path: string): string | null {
  const v = path.trim();
  if (v === "" || isAbsolutePath(v)) return null;
  return "Use an absolute path.";
}

/** importDirProblem: the image set folder must be named, by an absolute path. */
export function importDirProblem(dir: string): string | null {
  const v = dir.trim();
  if (v === "") return "Name the folder that holds the image set.";
  return isAbsolutePath(v) ? null : "Use the folder's absolute path.";
}

/** readoptCanReattach: the run states a re-attach takes (an open offer, or
 * one held while an update waits), as the daemon's readoptAttachStates. */
export function readoptCanReattach(state: string): boolean {
  return state === "offered" || state === "held";
}
