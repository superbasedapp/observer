import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { copyFor, getConsentState, loadConsent, submitConsent } from "../consent";
import { AuthShell } from "../components/AuthShell";
import { Button } from "@shared/primitives/Button";
import { Toggle } from "@shared/primitives/Toggle";
import { Pill } from "@shared/primitives/Pill";
import { ErrorState } from "@shared/primitives/ErrorState";
import { InlineLoading } from "@shared/primitives/Spinner";
import { Lock } from "lucide-react";
import { DisclosureMark, SensitivityMeter } from "../components/Disclosure";
import { CONSENT_PURPOSE, orderPurposes } from "../lib/vocab";

/**
 * ConsentSetup is the one-screen consent shell shown right after first
 * sign-in (R2 UX, F10 disposition), now backed by REAL SERVER STATE (F9):
 * Continue POSTs the whole choice set to /portal/api/consent, and "has this
 * account been through setup" is the server's answer, not a localStorage
 * marker. Reload-safe by construction — a refresh re-reads the same state.
 *
 * No dark patterns: Continue never enables anything that was not visibly
 * checked, the mandatory purpose is shown checked AND disabled because it is
 * the condition of signing in at all, and the scope line is the server's own
 * copy rather than a paraphrase written here.
 */
export function ConsentSetup() {
  const navigate = useNavigate();
  const state = getConsentState();
  // Least to most sensitive, so the screen reads as an escalating
  // disclosure ladder (lib/vocab.ts CONSENT_PURPOSE).
  const options = orderPurposes(state?.purposes ?? []);
  const notice = state?.notice ?? "";

  const [selected, setSelected] = useState<Set<string>>(
    // Only mandatory purposes start on. An optional purpose is opt-IN.
    () => new Set(options.filter((p) => p.mandatory).map((p) => p.id)),
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Retry re-reads the server state. getConsentState() is module state, not
  // React state: clearing `retrying` is the re-render that shows the fresh
  // answer (loadConsent never rejects; a failure leaves the cache empty).
  const [retrying, setRetrying] = useState(false);

  async function onRetryLoad() {
    setRetrying(true);
    try {
      await loadConsent();
    } finally {
      setRetrying(false);
    }
  }

  function toggle(id: string, mandatory: boolean) {
    if (mandatory) {
      return;
    }
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  async function onContinue() {
    setError(null);
    setBusy(true);
    // The WHOLE set is submitted, each purpose with an explicit true/false:
    // an omission would be ambiguous, and the server treats a missing key as
    // declined anyway.
    const choices: Record<string, boolean> = {};
    for (const p of options) {
      choices[p.id] = p.mandatory || selected.has(p.id);
    }
    try {
      await submitConsent(choices);
      // The Overview shows a one-shot "saved" check from this history state
      // (the navigation itself is unchanged: immediate, replacing /consent).
      navigate("/overview", { replace: true, state: { consentSaved: true } });
    } catch (err) {
      setError(err instanceof Error ? err.message : "request failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      title="Set up your cloud sharing"
      width="wide"
      step="portal"
      intro={
        <p>
          Choose what this service may do with your data for cloud features.
          You can change these any time from Privacy &amp; devices.
        </p>
      }
    >
      {error && (
        <ErrorState
          variant="compact"
          title="Could not save your choices"
          error={error}
          className="mb-3"
        />
      )}

      {options.length === 0 &&
        (retrying ? (
          <InlineLoading block label="Loading your sharing options" />
        ) : (
          <ErrorState
            variant="page"
            title="Your sharing options could not be loaded"
            error="There is nothing to choose here yet. No choice is recorded until this screen can submit one."
            onRetry={() => void onRetryLoad()}
          />
        ))}

      {options.length > 0 && (
        <div className="consent-scale" aria-hidden="true">
          <span className="inline-flex items-center gap-1.5">
            <SensitivityMeter level={1} />
            Least sensitive
          </span>
          <span className="inline-flex items-center gap-1.5">
            Most sensitive
            <SensitivityMeter level={4} />
          </span>
        </div>
      )}

      <ul
        className="consent-list consent-ladder"
        aria-label="Sharing options, least to most sensitive"
      >
        {options.map((p) => {
          const text = copyFor(p.id);
          const checked = p.mandatory || selected.has(p.id);
          return (
            <li
              key={p.id}
              className="consent-row"
              data-level={CONSENT_PURPOSE[p.id]?.disclosure}
            >
              <Toggle
                size="md"
                on={checked}
                disabled={p.mandatory || busy}
                onChange={() => toggle(p.id, p.mandatory)}
                className="consent-toggle"
                labelClassName="consent-toggle-label"
                label={
                  <span className="inline-flex flex-wrap items-center gap-2">
                    <DisclosureMark kind="purpose" id={p.id} />
                    {text.label}
                    {p.mandatory && (
                      <Pill variant="neutral" icon={Lock} title="The condition of signing in: it cannot be turned off here.">
                        required
                      </Pill>
                    )}
                  </span>
                }
              />
              <p className="muted small consent-desc">{text.description}</p>
            </li>
          );
        })}
      </ul>

      {notice && <p className="disclosure">{notice}</p>}

      <Button
        variant="primary"
        className="mt-4 h-10 w-full"
        type="button"
        disabled={busy || options.length === 0}
        loading={busy}
        onClick={onContinue}
      >
        {busy ? "Saving" : "Continue"}
      </Button>
    </AuthShell>
  );
}
