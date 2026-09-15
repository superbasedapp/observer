import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { copyFor, getConsentState, submitConsent } from "../consent";
import { BrandMark } from "../components/BrandMark";

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
  const options = state?.purposes ?? [];
  const notice = state?.notice ?? "";

  const [selected, setSelected] = useState<Set<string>>(
    // Only mandatory purposes start on. An optional purpose is opt-IN.
    () => new Set(options.filter((p) => p.mandatory).map((p) => p.id)),
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
      navigate("/overview", { replace: true });
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "could not save your choices",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="signin">
      <div className="card signin-card consent-card">
        <div className="signin-brand">
          <BrandMark size={36} />
          <h1>Set up your cloud sharing</h1>
        </div>
        <p className="muted">
          Choose what this service may do with your data for cloud features.
          You can change these any time from Privacy &amp; devices.
        </p>

        {error && <div className="banner banner-error">{error}</div>}

        {options.length === 0 && (
          <div className="banner banner-warn">
            Your sharing options could not be loaded from the server, so there
            is nothing to choose here yet. Reload the page to try again - no
            choice is recorded until this screen can submit one.
          </div>
        )}

        <ul className="consent-list">
          {options.map((p) => {
            const text = copyFor(p.id);
            const checked = p.mandatory || selected.has(p.id);
            return (
              <li key={p.id} className="consent-row">
                <label className="check-row">
                  <input
                    type="checkbox"
                    className="switch"
                    checked={checked}
                    disabled={p.mandatory || busy}
                    onChange={() => toggle(p.id, p.mandatory)}
                  />
                  <span>
                    {text.label}
                    {p.mandatory && (
                      <span className="badge badge-mandatory">Required</span>
                    )}
                  </span>
                </label>
                <p className="muted small consent-desc">{text.description}</p>
              </li>
            );
          })}
        </ul>

        {notice && <p className="disclosure">{notice}</p>}

        <button
          className="btn btn-primary btn-block"
          type="button"
          disabled={busy || options.length === 0}
          onClick={onContinue}
        >
          {busy ? "Saving..." : "Continue"}
        </button>
      </div>
    </div>
  );
}
