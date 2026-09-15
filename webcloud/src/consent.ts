// Cloud-sharing consent screen state, backed by real server state (F9).
//
// SCOPE, restated here because this file is where a future change would be
// tempted to blur it: these choices are PORTAL-plane preferences for the
// signed-in account. They are not what authorizes a device to upload — node
// egress consent is node-authoritative, granted on the device and withdrawn
// there. The server states the same thing in the `notice` string it serves,
// which the screens render verbatim rather than paraphrasing here.
//
// This module used to keep the chosen set in a module variable plus a
// localStorage "seen" marker, so choices were lost on reload and invisible to
// a second browser. Now the SERVER owns them: "has this account been through
// setup" is `choices !== null` from GET /portal/api/consent, and every write
// goes through POST. The module state below is a cache of the last server
// answer, refreshed at boot and after every write — never a source of truth.

import { getConsentChoices, saveConsentChoices } from "./api";
import type { ConsentChoices } from "./api";

export interface ConsentPurpose {
  id: string;
  label: string;
  description: string;
}

/**
 * CONSENT_COPY carries the human-readable label and description for each
 * purpose id. The server owns the LIST of purposes and which are mandatory
 * (GET /portal/api/consent), so this map is copy only: a purpose the server
 * offers but this map does not know still renders, under its id.
 */
export const CONSENT_COPY: Record<string, ConsentPurpose> = {
  structural_activity_insights: {
    id: "structural_activity_insights",
    label: "Name and tag my sessions",
    description:
      "Agent and model, bucketed time, durations, token and cost counts, " +
      "action outcome categories, and your first prompt. This is the " +
      "signed-in product: cloud features run on this data. Declining means " +
      "not signing in; the local product needs no sign-in and is unaffected " +
      "either way.",
  },
  bounded_context_enrichment: {
    id: "bounded_context_enrichment",
    label: "Also describe them using short excerpts of my prompts and outputs",
    description:
      "Short, scrubbed excerpts of your task and final summary, used only to " +
      "generate a better session title, tags, description and next step.",
  },
  community_cohort_benchmarking: {
    id: "community_cohort_benchmarking",
    label: "Community cohort benchmarking",
    description:
      "A derived structural contribution compared against a minimum-size " +
      "cohort, used to show your own private percentile against similar work.",
  },
};

/** copyFor returns the display copy for a purpose id, falling back to the id
 * itself so a server-side addition is never rendered as a blank row. */
export function copyFor(id: string): ConsentPurpose {
  return (
    CONSENT_COPY[id] ?? {
      id,
      label: id,
      description:
        "This purpose is offered by the service but this build has no " +
        "description for it. Nothing is enabled unless you check it.",
    }
  );
}

// The cached last server answer. `null` means "not loaded this page load".
let cached: ConsentChoices | null = null;

/**
 * loadConsent fetches the account's consent state and caches it. Callers must
 * await it before reading needsConsentSetup(); it is called at app boot right
 * after the session is known, and again when another tab signs in.
 *
 * A failure leaves the cache empty and resolves — the caller renders the app
 * rather than hard-failing on boot, and needsConsentSetup() then answers false
 * so an unreachable endpoint never traps a signed-in user on the setup screen.
 */
export async function loadConsent(): Promise<void> {
  try {
    cached = await getConsentChoices();
  } catch {
    cached = null;
  }
}

/**
 * needsConsentSetup reports whether the consent screen still has to run. It is
 * true ONLY when the server said, in so many words, that this account has no
 * stored choices — never when the state is simply unknown.
 */
export function needsConsentSetup(): boolean {
  return cached !== null && cached.choices === null;
}

/** getConsentState returns the cached server answer, or null if not loaded. */
export function getConsentState(): ConsentChoices | null {
  return cached;
}

/**
 * submitConsent stores the choice set and adopts the server's answer as the
 * new cache. The server forces mandatory purposes on and rejects unknown ones,
 * so the response — not the request — is what the UI reflects afterwards.
 */
export async function submitConsent(
  choices: Record<string, boolean>,
): Promise<ConsentChoices> {
  cached = await saveConsentChoices(choices);
  return cached;
}

/** clearConsentState drops the cached server answer (sign-out), so the next
 * signed-in account starts from its own server state rather than inheriting
 * the previous one. */
export function clearConsentState(): void {
  cached = null;
}
