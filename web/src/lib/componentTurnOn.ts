// componentTurnOn: the one-click "Turn it on" a card shows where its module
// is installed but not turned on (ruling SBXD-9: the Sandbox isolation card
// on a fresh developer-edition install). It makes exactly the change Settings
// > Components makes for that row (preview, then apply naming the preview's
// fingerprint, through the same routes, confirm token and local-only rule;
// the guard's self-approval rules see the same request an agent would send),
// and says the outcome where the person clicked.
//
// Pure (no React, no app path aliases, the HTTP call injected) so
// componentTurnOn.test.ts runs under `node --test`.

/** The button's phases. */
export type TurnOnPhase = "idle" | "working" | "done" | "needs_restart" | "refused";

/** The button's state: the phase, and for a refusal the plain reason. */
export type TurnOnState = { phase: TurnOnPhase; reason?: string };

/** The fields of POST /api/components/preview this helper reads. */
export type TurnOnPreview = {
  activated?: string[] | null;
  refused?: string[] | null;
  managed_by?: string;
  managed_refused?: string[] | null;
  restart_required?: boolean;
  fingerprint: string;
  no_change?: boolean;
};

/** What happened: the preview, whether the apply was sent and answered,
 *  and an error sentence from either call. */
export type TurnOnFacts = {
  preview?: TurnOnPreview | null;
  applied?: boolean;
  error?: string | null;
  /** The error was the local-only refusal (a remote view, or a stale
   *  confirm token). */
  localOnly?: boolean;
  /** restart_class of each component the change activates, by id (the
   *  catalog's "hot", "soft" or "restart"; absent is hot). */
  restartClass?: Record<string, string | undefined>;
};

const list = (xs: string[] | null | undefined): string[] => (xs ?? []).filter((x) => x.trim() !== "");

const needsRestart = (f: TurnOnFacts): boolean =>
  list(f.preview?.activated).some((id) => f.restartClass?.[id] === "restart");

type OutcomeRule = { name: string; when: (f: TurnOnFacts) => boolean; state: (f: TurnOnFacts) => TurnOnState };

/** TURN_ON_OUTCOME_RULES is the ordered outcome table, walked top-down. */
export const TURN_ON_OUTCOME_RULES: readonly OutcomeRule[] = [
  {
    name: "the change is made only on this machine's own dashboard",
    when: (f) => !!f.localOnly,
    state: () => ({
      phase: "refused",
      reason: "Turning it on is done from this machine's own dashboard, not from a remote view. Open the dashboard on this machine and try again.",
    }),
  },
  {
    name: "a call failed",
    when: (f) => !!f.error,
    state: (f) => ({ phase: "refused", reason: (f.error ?? "").trim() }),
  },
  {
    name: "the organization decides",
    when: (f) => list(f.preview?.managed_refused).length > 0,
    state: (f) => ({
      phase: "refused",
      reason: `${f.preview?.managed_by ? f.preview.managed_by : "Your organization"} decides which components run on this machine: ${list(f.preview?.managed_refused).join("; ")}. Request it from your organization.`,
    }),
  },
  {
    name: "every part of the change was refused",
    when: (f) => list(f.preview?.refused).length > 0 && list(f.preview?.activated).length === 0,
    state: (f) => ({ phase: "refused", reason: list(f.preview?.refused).join("; ") }),
  },
  { name: "it was already on", when: (f) => !!f.preview?.no_change, state: () => ({ phase: "done" }) },
  { name: "not applied yet", when: (f) => !f.applied, state: () => ({ phase: "working" }) },
  { name: "applied, and an activated component waits for a restart", when: needsRestart, state: () => ({ phase: "needs_restart" }) },
  { name: "applied", when: () => true, state: () => ({ phase: "done" }) },
];

/** turnOnOutcome walks TURN_ON_OUTCOME_RULES top-down. */
export function turnOnOutcome(f: TurnOnFacts): TurnOnState {
  const r = TURN_ON_OUTCOME_RULES.find((x) => x.when(f)) ?? TURN_ON_OUTCOME_RULES[TURN_ON_OUTCOME_RULES.length - 1];
  return r.state(f);
}

/** The HTTP call, injected: POST path with a JSON body, resolving the reply
 *  or rejecting. */
export type TurnOnPost = (path: string, body: unknown) => Promise<unknown>;

/** How a rejected call reads: its sentence and whether it was the
 *  local-only refusal. */
export type TurnOnErrorReader = (e: unknown) => { message: string; localOnly: boolean };

/**
 * turnOnComponent previews adding `id` and applies it under the preview's
 * fingerprint when the preview has something to apply, then answers the
 * final state. Nothing is applied when the preview is refused, already on,
 * or managed by the organization.
 */
export async function turnOnComponent(
  id: string,
  post: TurnOnPost,
  readError: TurnOnErrorReader,
  restartClass: Record<string, string | undefined> = {},
): Promise<TurnOnState> {
  const change = { add: [id] };
  let preview: TurnOnPreview;
  try {
    preview = (await post("/api/components/preview", { change })) as TurnOnPreview;
  } catch (e) {
    const r = readError(e);
    return turnOnOutcome({ error: r.message, localOnly: r.localOnly });
  }
  const pre = turnOnOutcome({ preview, restartClass });
  if (pre.phase !== "working") return pre;
  try {
    await post("/api/components/apply", { change, fingerprint: preview.fingerprint, skip_teardown: false });
  } catch (e) {
    const r = readError(e);
    return turnOnOutcome({ preview, error: r.message, localOnly: r.localOnly });
  }
  return turnOnOutcome({ preview, applied: true, restartClass });
}

/** The button and the line under it, per phase. */
export type TurnOnView = {
  label: string;
  disabled: boolean;
  /** The line under the button, or null. */
  line: string | null;
  /** The line is a refusal (an alert), not a status. */
  alert: boolean;
};

/** turnOnView is what the card shows for a state. */
export function turnOnView(s: TurnOnState): TurnOnView {
  switch (s.phase) {
    case "working":
      return { label: "Turning it on...", disabled: true, line: null, alert: false };
    case "done":
      return { label: "Turned on", disabled: true, line: "Turned on. Its settings show here next.", alert: false };
    case "needs_restart":
      return {
        label: "Turned on",
        disabled: true,
        line: "Turned on. New commands use it at once; the daemon's background work for it starts after the next restart.",
        alert: false,
      };
    case "refused":
      return { label: "Turn it on", disabled: false, line: s.reason || "It could not be turned on here.", alert: true };
    default:
      return { label: "Turn it on", disabled: false, line: null, alert: false };
  }
}
