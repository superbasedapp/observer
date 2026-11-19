// hostedClone.ts holds the New Terminal dialog's and the Hosted sandboxes
// card's decisions about a hosted row's "Clone a remote URL" source (lane
// CLONE2, decision SBXD-5) as pure functions: where the repository is
// cloned (in the box, or on this machine with the developer's own git login
// and its tracked files uploaded), the launch field that carries a
// per-launch choice, and the inline consent for that URL. The daemon
// decides; these only say it before Start and build the requests.

import type { SandboxCloneWhere } from "./types.ts";

/** The clone location values (internal/workspace CloneWhere). */
export const CLONE_WHERE_VALUES = ["auto", "box", "home"] as const;

/** CLONE_WHERE_LABELS are the plain words for each value. */
export const CLONE_WHERE_LABELS: Record<string, string> = {
  auto: "Automatically",
  box: "Inside the box",
  home: "On this machine",
};

/** cloneWhereLabel is a value's plain words (the value itself when unknown). */
export function cloneWhereLabel(value: string): string {
  return CLONE_WHERE_LABELS[value] ?? value;
}

/** One entry of the dialog's clone location picker. */
export type CloneWhereOption = { value: string; label: string; disabled: boolean; note?: string };

/**
 * cloneWhereOptions is the dialog's picker for the chosen row's clone
 * location: every value, each disabled with the daemon's sentence when the
 * row cannot take it now; only the setting itself when the setting is
 * fixed (box or home). Empty for a row with no choice (no clone_where).
 */
export function cloneWhereOptions(view: SandboxCloneWhere | undefined): CloneWhereOption[] {
  if (!view) return [];
  const values = view.fixed ? [view.setting] : [...CLONE_WHERE_VALUES];
  return values.map((value) => ({
    value,
    label: cloneWhereLabel(value),
    disabled: !view.choices.includes(value),
    ...(view.notes?.[value] ? { note: view.notes[value] } : {}),
  }));
}

/**
 * cloneWhereChoice is the dialog's effective choice: the person's pick when
 * the row lets a launch choose and can take it now, else the setting (an
 * absent view: "", nothing to choose).
 */
export function cloneWhereChoice(view: SandboxCloneWhere | undefined, picked: string): string {
  if (!view) return "";
  if (view.fixed) return view.setting;
  return view.choices.includes(picked) ? picked : view.setting;
}

/**
 * cloneWhereLaunchValue is the launch's workspace_clone_where: the choice
 * when it differs from the setting (a fixed setting sends nothing: the
 * daemon applies it), else undefined, so a launch that leaves it alone
 * sends the same body as before.
 */
export function cloneWhereLaunchValue(view: SandboxCloneWhere | undefined, picked: string): string | undefined {
  if (!view || view.fixed) return undefined;
  const choice = cloneWhereChoice(view, picked);
  return choice && choice !== view.setting ? choice : undefined;
}

/** The consent screen as GET /api/terminal/sandbox/hosted serves it. */
export type HostedConsentScreen = {
  lines: { label: string; value: string }[];
  excluded?: { path: string; reason: string }[] | null;
  /** clone_where is where the agreement's clone runs (box, home). */
  clone_where?: string;
};

/** One provider of GET /api/terminal/sandbox/hosted (the parts read here). */
export type HostedConsentProvider = {
  id: string;
  name: string;
  screen?: HostedConsentScreen;
  screen_error?: string;
  consent_verdict?: string;
};

/** WHERE_LINE_LABEL is the consent screen's clone location line. */
export const WHERE_LINE_LABEL = "Where the repository is cloned";

/** cloneWhereLine is where the screen says the clone runs and why ("" for none). */
export function cloneWhereLine(screen: HostedConsentScreen | undefined): string {
  return screen?.lines.find((l) => l.label === WHERE_LINE_LABEL)?.value ?? "";
}

/**
 * cloneConsentQuery is the GET query that asks the daemon for one row's
 * consent screen of a clone-remote launch (its URL, the folder, the
 * choice), or null while something it needs is missing.
 */
export function cloneConsentQuery(input: { provider: string; folder: string; url: string; choice: string }): Record<string, string> | null {
  const url = input.url.trim();
  if (!input.provider || !input.folder || !url) return null;
  return {
    workspace: input.folder,
    repository: url,
    provider: input.provider,
    ...(input.choice ? { clone_where: input.choice } : {}),
  };
}

/** cloneConsentBody is the consent route's body for that same screen. */
export function cloneConsentBody(input: { provider: string; folder: string; url: string; choice: string }) {
  return {
    provider: input.provider,
    workspace: input.folder,
    repository: input.url.trim(),
    ...(input.choice ? { clone_where: input.choice } : {}),
  };
}

/** What the inline consent shows for one provider's answer. */
export type CloneConsentState =
  | { kind: "none" }
  | { kind: "agreed"; where: string }
  | { kind: "ask"; where: string; again: boolean; changed: string; screen: HostedConsentScreen }
  | { kind: "error"; message: string };

/**
 * cloneConsentState reads one provider's answer: agreed (nothing to ask),
 * the screen to agree to (again: an earlier agreement no longer matches),
 * or the daemon's sentence why no screen could be made (an address the
 * launch would refuse says so here, before Start).
 */
export function cloneConsentState(p: HostedConsentProvider | undefined): CloneConsentState {
  if (!p) return { kind: "none" };
  if (p.screen_error) return { kind: "error", message: p.screen_error };
  if (!p.screen) return { kind: "none" };
  const where = cloneWhereLine(p.screen);
  if (p.consent_verdict === "ok") return { kind: "agreed", where };
  return {
    kind: "ask",
    where,
    again: !!p.consent_verdict && p.consent_verdict !== "consent_required",
    changed: consentChangeWords(p.consent_verdict ?? ""),
    screen: p.screen,
  };
}

/**
 * CONSENT_CHANGE_WORDS are the plain words for what a recorded agreement no
 * longer matches, by the consent verdict (internal/sandboxremote's closed
 * consent_changed_<field> spellings; the same words as the setup step's
 * consentChangeWords in cmd/observer, plus the fields only a launch meets).
 */
export const CONSENT_CHANGE_WORDS: Record<string, string> = {
  consent_changed_provider: "the provider",
  consent_changed_endpoint: "the provider's address",
  consent_changed_region: "the region",
  consent_changed_custody: "how the agent gets its model key",
  consent_changed_tier: "the box's network",
  consent_changed_capture: "what Observer records from the run",
  consent_changed_scope: "what is uploaded or cloned for this folder",
  consent_changed_box_binary: "the observer copied into the box",
  consent_changed_memory_images: "the memory image setting",
  consent_changed_cap: "the box time limits",
  consent_changed_private_ranges: "whether the box may reach private network addresses",
  consent_changed_in_box_keys: "the keys stored on this machine that can be put in the box",
  consent_changed_tool_keys: "which agents' own saved keys can be put in the box",
  consent_changed_login_seed: "which agents' logins are copied into the box",
  consent_stale_version: "the agreement's format (Observer was updated)",
};

/** consentChangeWords is a verdict's plain words ("" when it names no change). */
export function consentChangeWords(verdict: string): string {
  return CONSENT_CHANGE_WORDS[verdict] ?? "";
}

/** A launch refused for its hosted consent, as the daemon's 409 names it. */
export type HostedConsentRefusal = { provider: string; verdict: string };

/**
 * hostedConsentRefusalOf reads a launch error as the daemon's hosted
 * consent refusal: a 409 whose JSON body carries the closed code
 * "consent_required" with the row (provider) and the verdict
 * (dashapi.SandboxConsentRefusal). Read by its code, never by the
 * sentence; null for any other error.
 */
export function hostedConsentRefusalOf(e: unknown): HostedConsentRefusal | null {
  const err = e as { status?: unknown; body?: unknown } | null;
  if (!err || err.status !== 409 || typeof err.body !== "string" || err.body === "") return null;
  try {
    const b = JSON.parse(err.body) as { error?: unknown; provider?: unknown; verdict?: unknown };
    if (b && b.error === "consent_required" && typeof b.provider === "string" && typeof b.verdict === "string") {
      return { provider: b.provider, verdict: b.verdict };
    }
  } catch {
    // Not JSON: not this refusal.
  }
  return null;
}

/**
 * isHostedConsentRefusal reports a launch refused for a missing or changed
 * hosted consent (the daemon's hosted_consent_required verdict and the
 * sandboxremote consent verdicts), so the dialog shows the consent inline
 * instead of the raw sentence.
 */
export function isHostedConsentRefusal(message: string): boolean {
  return /\bconsent_required\b|\bconsent_changed_[a-z_]+\b|\bconsent_stale_version\b|\bconsent_tampered\b/.test(message);
}

/**
 * repositoryChoices is the Hosted sandboxes card's clone consent picker
 * state: the organization's published repositories when there are any
 * (picked from a list), else a typed one (free text).
 */
export function repositoryChoices(published: string[]): { mode: "list"; options: string[] } | { mode: "text" } {
  return published.length > 0 ? { mode: "list", options: published } : { mode: "text" };
}
