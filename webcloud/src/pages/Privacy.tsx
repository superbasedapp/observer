import type { FormEvent } from "react";
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  ApiError,
  clearCsrf,
  downloadExport,
  getAuthMode,
  getBrowserSessions,
  getConsents,
  getDevices,
  getGrants,
  listExports,
  requestDeletion,
  requestDeletionWithStepUp,
  requestExport,
  requestExportWithStepUp,
  revokeAllBrowserSessions,
  revokeDevice,
} from "../api";
import type {
  BrowserSessionsResult,
  ConsentsResult,
  DevicesResult,
  DeletionResult,
  ExportResult,
  GrantsResult,
} from "../api";
import type { ConsentChoices } from "../api";
import { copyFor, getConsentState, submitConsent } from "../consent";
import { Pill } from "@shared/primitives/Pill";
import { CopyOnClick } from "@shared/primitives/CopyOnClick";
import { fmtDateTime, fmtRelative, fmtShortId } from "@shared/lib/format";
import { DELETION_STATE_LABELS, RETENTION_STATE_LABELS, labelFor } from "../lib/labels";

// The full-page navigation that kicks off WorkOS re-authentication for a
// deletion request. The browser returns to return_to with a single-use
// ?step_up=<id> appended (see the DeleteSection mount effect in Privacy()).
const STEP_UP_START_URL =
  "/portal/auth/workos/start?purpose=step_up&action=deletion&return_to=/portal/privacy";

// The export re-auth navigation (Doc B §3.2: export is a step-up action). Both
// re-auth flows return to /portal/privacy with a single-use ?step_up=<id>; the
// server does not echo which action the id was minted for, so the section that
// started the flow stamps its INTENT in sessionStorage before navigating and
// Privacy() routes the returned id back to the right section on mount. The
// step-up authorization is action-bound server-side regardless, so a
// mis-routed id is refused, not misused — the intent is purely a UX router.
const EXPORT_STEP_UP_START_URL =
  "/portal/auth/workos/start?purpose=step_up&action=export&return_to=/portal/privacy";
const STEP_UP_INTENT_KEY = "sbci_stepup_intent";

function rememberStepUpIntent(intent: "deletion" | "export"): void {
  try {
    window.sessionStorage.setItem(STEP_UP_INTENT_KEY, intent);
  } catch {
    // sessionStorage may be unavailable (private mode); the router defaults to
    // deletion, and an action-bound export id is simply refused there — safe.
  }
}

function takeStepUpIntent(): "deletion" | "export" {
  try {
    const v = window.sessionStorage.getItem(STEP_UP_INTENT_KEY);
    window.sessionStorage.removeItem(STEP_UP_INTENT_KEY);
    return v === "export" ? "export" : "deletion";
  } catch {
    return "deletion";
  }
}

function DevicesSection() {
  const [data, setData] = useState<DevicesResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(() => {
    setError(null);
    getDevices()
      .then(setData)
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : "failed to load"),
      );
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function onRevoke(id: string) {
    if (!window.confirm("Revoke this device? It will no longer be able to sync.")) {
      return;
    }
    setBusyId(id);
    try {
      await revokeDevice(id);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "revoke failed");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="card">
      <h2>Devices</h2>
      {error && <div className="banner banner-error">{error}</div>}
      {!data && !error && <p className="muted">Loading devices...</p>}
      {data && data.devices.length === 0 && (
        <p className="muted small">No devices enrolled.</p>
      )}
      {data && data.devices.length > 0 && (
        <ul className="device-list">
          {data.devices.map((d) => (
            <li key={d.id} className="device-row">
              <div className="device-info">
                <div className="device-label">{d.label || "(unlabeled)"}</div>
                <div className="device-meta">
                  <CopyOnClick value={d.thumbprint} className="mono">
                    {fmtShortId(d.thumbprint, 16)}
                  </CopyOnClick>{" "}
                  · created {fmtDateTime(d.created_at)}
                </div>
              </div>
              {d.revoked ? (
                <Pill variant="danger">Revoked</Pill>
              ) : (
                <button
                  className="btn btn-danger btn-sm"
                  disabled={busyId === d.id}
                  onClick={() => onRevoke(d.id)}
                >
                  {busyId === d.id ? "Revoking..." : "Revoke"}
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// BrowserSessionsSection is the "sign out everywhere" surface (Wave C gap 2.4
// residual (b)): every live portal sign-in on this account, and a single
// action to revoke every OTHER session (keep_current: true) - the current
// session stays signed in, which is the useful shape for "I think I left
// myself signed in somewhere else."
function BrowserSessionsSection() {
  const navigate = useNavigate();
  const [data, setData] = useState<BrowserSessionsResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  const load = useCallback(() => {
    setError(null);
    getBrowserSessions()
      .then(setData)
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : "failed to load"),
      );
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function onSignOutEverywhere() {
    if (
      !window.confirm(
        "Sign out every other session on this account? This session stays signed in.",
      )
    ) {
      return;
    }
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const res = await revokeAllBrowserSessions(true);
      setResult(
        res.revoked > 0
          ? `Signed out ${res.revoked} other session${res.revoked === 1 ? "" : "s"}.`
          : "No other sessions were signed in.",
      );
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "could not sign out other sessions");
    } finally {
      setBusy(false);
    }
  }

  async function onSignOutThisDevice() {
    if (!window.confirm("Sign out of this session too? You will need to sign in again.")) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await revokeAllBrowserSessions(false);
      clearCsrf();
      navigate("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "could not sign out");
      setBusy(false);
    }
  }

  const otherCount = data
    ? data.sessions.filter((s) => !s.is_current).length
    : 0;

  return (
    <div className="card">
      <h2>Signed-in sessions</h2>
      {error && <div className="banner banner-error">{error}</div>}
      {result && <div className="banner">{result}</div>}
      {!data && !error && <p className="muted">Loading sessions...</p>}
      {data && (
        <ul className="device-list">
          {data.sessions.map((s) => (
            <li key={s.id} className="device-row">
              <div className="device-info">
                <div className="device-label">
                  {s.is_current ? "This session" : "Another session"}
                </div>
                <div className="device-meta">
                  signed in {fmtDateTime(s.created_at)}
                  {s.last_seen_at && (
                    <> · last active {fmtRelative(s.last_seen_at)}</>
                  )}
                </div>
              </div>
              {s.is_current && <Pill variant="success">Current</Pill>}
            </li>
          ))}
        </ul>
      )}
      <div className="action-row">
        <button
          className="btn btn-danger btn-sm"
          type="button"
          disabled={busy || otherCount === 0}
          onClick={onSignOutEverywhere}
        >
          {busy ? "Working..." : "Sign out everywhere else"}
        </button>
        <button
          className="btn btn-ghost btn-sm"
          type="button"
          disabled={busy}
          onClick={onSignOutThisDevice}
        >
          Sign out everywhere, including this session
        </button>
      </div>
      {data && otherCount === 0 && (
        <p className="muted small">
          This is the only signed-in session on this account.
        </p>
      )}
    </div>
  );
}

function ConsentsSection() {
  const [data, setData] = useState<ConsentsResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    getConsents()
      .then((d) => {
        if (live) setData(d);
      })
      .catch((err: unknown) => {
        if (live) setError(err instanceof Error ? err.message : "failed to load");
      });
    return () => {
      live = false;
    };
  }, []);

  return (
    <div className="card">
      <h2>Consents</h2>
      {error && <div className="banner banner-error">{error}</div>}
      {!data && !error && <p className="muted">Loading consents...</p>}
      {data && data.purposes.length === 0 && (
        <p className="muted small">No purposes granted.</p>
      )}
      {data && data.purposes.length > 0 && (
        <ul className="breakdown">
          {data.purposes.map((p) => (
            <li key={p}>
              <span title={p}>{copyFor(p).label}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// CloudSharingSection is the F9 completion on the Privacy side: the consent
// choices the setup screen stored, each individually revocable.
//
// Two rules are rendered rather than hidden. An OPTIONAL purpose gets a real
// Grant/Revoke control, and the change is written server-side immediately. A
// MANDATORY one gets no control at all — it is the condition of the signed-in
// feature, and offering a button that would silently fail (the server forces
// it back on) would be a lie; the honest statement is that turning it off
// means not using the signed-in product, which the copy says.
//
// The scope line is the server's own `notice`: these are portal-plane
// preferences, NOT the grant that lets a device upload. That grant is made and
// withdrawn on the device.
function CloudSharingSection() {
  const [state, setState] = useState<ConsentChoices | null>(getConsentState);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function setPurpose(id: string, granted: boolean) {
    if (state === null || state.choices === null) {
      return;
    }
    setError(null);
    setBusyId(id);
    try {
      // Submit the WHOLE set with this one purpose changed: the endpoint
      // stores a complete choice set, so a partial body would read as
      // "everything else declined".
      const next: Record<string, boolean> = { ...state.choices, [id]: granted };
      setState(await submitConsent(next));
    } catch (err) {
      setError(err instanceof Error ? err.message : "could not save the change");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="card">
      <h2>Cloud sharing</h2>
      {error && <div className="banner banner-error">{error}</div>}
      {state === null && (
        <p className="muted small">
          Your cloud-sharing choices could not be loaded. Reload the page to try
          again.
        </p>
      )}
      {state !== null && state.choices === null && (
        <p className="muted small">
          You have not been through the cloud-sharing setup screen yet.
        </p>
      )}
      {state !== null &&
        state.choices !== null &&
        state.purposes.map((p) => {
          const text = copyFor(p.id);
          const granted = state.choices?.[p.id] === true;
          return (
            <div key={p.id} className="grant-block">
              <div className="grant-head">
                <span className="grant-title">
                  {text.label}{" "}
                  {granted ? (
                    <Pill variant="success">On</Pill>
                  ) : (
                    <Pill variant="neutral">Off</Pill>
                  )}
                </span>
                {!p.mandatory && (
                  <button
                    className={granted ? "btn btn-danger btn-sm" : "btn btn-sm"}
                    type="button"
                    disabled={busyId === p.id}
                    onClick={() => setPurpose(p.id, !granted)}
                  >
                    {busyId === p.id
                      ? "Saving..."
                      : granted
                        ? "Revoke"
                        : "Grant"}
                  </button>
                )}
              </div>
              <p className="muted small grant-desc">{text.description}</p>
              {p.mandatory && (
                <p className="muted small">
                  Required for the signed-in product: cloud features run on this
                  data, so it cannot be turned off while you use them. To
                  withdraw it, request deletion below.
                </p>
              )}
            </div>
          );
        })}
      {state !== null && state.notice && (
        <p className="disclosure">{state.notice}</p>
      )}
    </div>
  );
}

// StandingGrantsSection is the D19 completion: for every standing grant the
// server has registered, exactly which field classes it binds, which schema and
// data-dictionary version it was agreed against, which consent generation those
// terms sit at, and what happens to the data it authorized. Nothing here is
// inferred in the browser: every value is the server restating its own
// registration row.
function StandingGrantsSection() {
  const [data, setData] = useState<GrantsResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    getGrants()
      .then((d) => {
        if (live) setData(d);
      })
      .catch((err: unknown) => {
        if (live)
          setError(err instanceof Error ? err.message : "failed to load");
      });
    return () => {
      live = false;
    };
  }, []);

  return (
    <div className="card">
      <h2>Standing grants</h2>
      {error && <div className="banner banner-error">{error}</div>}
      {!data && !error && <p className="muted">Loading standing grants...</p>}
      {data && data.grants.length === 0 && (
        <p className="muted small">
          No standing grant has been registered on this account yet. One is
          registered the first time a device syncs under a grant you made
          locally.
        </p>
      )}
      {data &&
        data.grants.map((g) => (
          <div key={g.purpose} className="grant-block">
            <div className="grant-head">
              <span className="grant-title">
                <span title={g.purpose}>{copyFor(g.purpose).label}</span>{" "}
                {g.state === "revoked" ? (
                  <Pill variant="danger">Revoked</Pill>
                ) : (
                  <Pill variant="success">Active</Pill>
                )}
              </span>
            </div>
            <ul className="breakdown">
              <li>
                <span>Field classes</span>
                <span>{g.field_classes.join(", ") || "none recorded"}</span>
              </li>
              <li>
                <span>Schema version</span>
                <span>{g.schema_version}</span>
              </li>
              <li>
                <span>Data dictionary</span>
                <span>
                  <CopyOnClick value={g.data_dictionary_digest} className="mono">
                    {fmtShortId(g.data_dictionary_digest, 23)}
                  </CopyOnClick>
                  {g.dictionary_current ? " (current)" : " (superseded)"}
                </span>
              </li>
              <li>
                <span>Consent generation</span>
                <span>{g.consent_generation}</span>
              </li>
              <li>
                <span>Declared timezone</span>
                <span>{g.declared_timezone || "not recorded"}</span>
              </li>
              <li>
                <span>Source window rule</span>
                <span>{g.source_window_rule || "not recorded"}</span>
              </li>
              <li>
                <span>First seen</span>
                <span>{fmtDateTime(g.first_seen_at)}</span>
              </li>
              <li>
                <span>Last updated</span>
                <span>{fmtDateTime(g.updated_at)}</span>
              </li>
              {g.state === "revoked" && (
                <li>
                  <span>Revoked</span>
                  <span>{fmtDateTime(g.revoked_at)}</span>
                </li>
              )}
            </ul>
            {!g.dictionary_current && (
              <p className="muted small">
                The schema this grant was agreed against is no longer the one
                this service accepts. New uploads under it will be refused until
                you re-confirm the grant.
              </p>
            )}
          </div>
        ))}
      {data && (
        <>
          <ul className="breakdown">
            <li>
              <span>Stored snapshots</span>
              <span>{data.stored_snapshots}</span>
            </li>
            <li>
              <span>Stored account-days</span>
              <span>{data.stored_account_days}</span>
            </li>
            <li>
              <span>Contributing devices</span>
              <span>{data.contributing_device_count}</span>
            </li>
            <li>
              <span>Retention</span>
              <span title={data.retention_state}>
                {labelFor(RETENTION_STATE_LABELS, data.retention_state)}
              </span>
            </li>
          </ul>
          <p className="disclosure">{data.retention_detail}</p>
        </>
      )}
    </div>
  );
}

// ExportSection is the W6d "download your data first" affordance (D11). It is
// rendered ABOVE DeleteSection so a developer can take a portable copy before
// the irreversible deletion. Assembly requires the same re-auth/step-up the
// deletion path does (Doc B §3.2); the assembled artifact is encrypted at rest,
// expires within ≤7 days, and is deleted by the deletion pass. Its shape is
// auth-mode-dependent for the same reason DeleteSection's is.
function ExportSection({
  stepUpId,
  onConsumeStepUp,
}: {
  stepUpId: string | null;
  onConsumeStepUp: () => void;
}) {
  const authMode = getAuthMode();
  const [subject, setSubject] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [exports, setExports] = useState<ExportResult[]>([]);
  const [downloading, setDownloading] = useState<string | null>(null);

  const load = useCallback(() => {
    listExports()
      .then((r) => setExports(r.exports))
      .catch(() => {
        // A listing failure is non-fatal — the section still offers assembly.
        setExports([]);
      });
  }, []);
  useEffect(load, [load]);

  function onAssembled(res: ExportResult) {
    setExports((prev) => [res, ...prev.filter((e) => e.export_id !== res.export_id)]);
    // Offer the download immediately.
    void onDownload(res.export_id);
  }

  async function onDownload(id: string) {
    setError(null);
    setDownloading(id);
    try {
      await downloadExport(id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "download failed");
    } finally {
      setDownloading(null);
    }
  }

  async function onExportDev(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (subject.trim().length === 0) {
      setError("Re-enter your developer subject to confirm.");
      return;
    }
    setBusy(true);
    try {
      onAssembled(await requestExport(subject.trim()));
    } catch (err) {
      setError(err instanceof Error ? err.message : "export failed");
    } finally {
      setBusy(false);
    }
  }

  function onReauthClick() {
    rememberStepUpIntent("export");
    window.location.assign(EXPORT_STEP_UP_START_URL);
  }

  async function onConfirmStepUp() {
    if (stepUpId === null) {
      return;
    }
    setError(null);
    setBusy(true);
    try {
      onAssembled(await requestExportWithStepUp(stepUpId));
      onConsumeStepUp();
    } catch (err) {
      if (err instanceof ApiError && err.code === "step_up_invalid") {
        onConsumeStepUp();
        setError(err.message);
      } else {
        setError(err instanceof Error ? err.message : "export failed");
      }
    } finally {
      setBusy(false);
    }
  }

  const existing = exports.length > 0 && (
    <ul className="export-list">
      {exports.map((e) => (
        <li key={e.export_id}>
          <button
            className="btn btn-ghost"
            type="button"
            disabled={downloading === e.export_id}
            onClick={() => void onDownload(e.export_id)}
          >
            {downloading === e.export_id ? "Downloading…" : "Download"}
          </button>
          <span className="muted small">
            {" "}
            {Math.round(e.size_bytes / 1024)} KB · expires{" "}
            {fmtDateTime(e.expires_at)}
          </span>
        </li>
      ))}
    </ul>
  );

  return (
    <div className="card">
      <h2>Download your data</h2>
      <p className="muted">
        Assemble a portable copy of your account data - your enrichment results
        and corrections, consent receipts, usage summary, and activity
        aggregates. The download is encrypted at rest and expires within 7 days.
        Download your data first - <strong>deletion is immediate and
        unrecoverable</strong>.
      </p>
      {error && <div className="banner banner-error">{error}</div>}
      {existing}
      {authMode === "workos" ? (
        stepUpId === null ? (
          <button className="btn" type="button" onClick={onReauthClick}>
            Re-authenticate to export
          </button>
        ) : (
          <button
            className="btn"
            type="button"
            disabled={busy}
            onClick={onConfirmStepUp}
          >
            {busy ? "Assembling…" : "Re-authentication confirmed - assemble export"}
          </button>
        )
      ) : (
        <form onSubmit={onExportDev}>
          <label htmlFor="exp-subject">Re-enter developer subject</label>
          <input
            id="exp-subject"
            type="text"
            autoComplete="off"
            placeholder="alice"
            value={subject}
            onChange={(ev) => setSubject(ev.target.value)}
            disabled={busy}
          />
          <button className="btn" type="submit" disabled={busy}>
            {busy ? "Assembling…" : "Assemble export"}
          </button>
        </form>
      )}
    </div>
  );
}

// DeleteSection's shape is auth-mode-dependent: dev mode keeps the original
// re-enter-subject form; WorkOS mode replaces it with a two-step re-auth
// flow, since there is no dev-subject broker token to re-enter. stepUpId and
// onConsumeStepUp are owned by Privacy() because the step_up query param is
// a page-level concern (read once on mount, stripped from the address bar
// immediately) — see the comment on Privacy() below.
function DeleteSection({
  stepUpId,
  onConsumeStepUp,
}: {
  stepUpId: string | null;
  onConsumeStepUp: () => void;
}) {
  const navigate = useNavigate();
  const authMode = getAuthMode();
  const [subject, setSubject] = useState("");
  const [understood, setUnderstood] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<DeletionResult | null>(null);
  const [busy, setBusy] = useState(false);

  function onDeletionRequested(res: DeletionResult) {
    setResult(res);
    // The server clears the session on a deletion request; drop the
    // in-memory CSRF and return to sign-in.
    clearCsrf();
    window.setTimeout(() => navigate("/"), 2500);
  }

  async function onDeleteDev(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (subject.trim().length === 0) {
      setError("Re-enter your developer subject to confirm.");
      return;
    }
    if (!understood) {
      setError("You must acknowledge the consequences.");
      return;
    }
    if (
      !window.confirm(
        "This permanently requests deletion of your data, cancels jobs, and revokes devices. Continue?",
      )
    ) {
      return;
    }
    setBusy(true);
    try {
      onDeletionRequested(await requestDeletion(subject.trim()));
    } catch (err) {
      setError(err instanceof Error ? err.message : "deletion request failed");
    } finally {
      setBusy(false);
    }
  }

  function onReauthClick() {
    rememberStepUpIntent("deletion");
    window.location.assign(STEP_UP_START_URL);
  }

  async function onConfirmStepUp() {
    if (stepUpId === null) {
      return;
    }
    setError(null);
    setBusy(true);
    try {
      onDeletionRequested(await requestDeletionWithStepUp(stepUpId));
    } catch (err) {
      if (err instanceof ApiError && err.code === "step_up_invalid") {
        // Expired/single-use-already-consumed: fall back to the re-auth
        // button with the server's own honest explanation, never a generic
        // one written here.
        onConsumeStepUp();
        setError(err.message);
      } else {
        setError(err instanceof Error ? err.message : "deletion request failed");
      }
    } finally {
      setBusy(false);
    }
  }

  if (result) {
    return (
      <div className="card card-danger">
        <h2>Deletion requested</h2>
        <div className="banner">
          Deletion request{" "}
          <CopyOnClick value={result.id} className="mono">
            {fmtShortId(result.id)}
          </CopyOnClick>{" "}
          is now{" "}
          <strong title={result.state}>
            {labelFor(DELETION_STATE_LABELS, result.state)}
          </strong>
          .
          Jobs canceled: {result.jobs_canceled}. Devices revoked:{" "}
          {result.devices_revoked}. Tokens revoked: {result.tokens_revoked}.
        </div>
        <p className="muted small">Signing you out…</p>
      </div>
    );
  }

  if (authMode === "workos") {
    return (
      <div className="card card-danger">
        <h2>Delete my data</h2>
        <p className="muted">
          This cancels your enrichment jobs and revokes your devices. It
          requires re-authentication and a double confirmation.
        </p>
        {error && <div className="banner banner-error">{error}</div>}
        {stepUpId === null ? (
          <button
            className="btn btn-danger"
            type="button"
            onClick={onReauthClick}
          >
            Re-authenticate to delete
          </button>
        ) : (
          <button
            className="btn btn-danger"
            type="button"
            disabled={busy}
            onClick={onConfirmStepUp}
          >
            {busy
              ? "Requesting..."
              : "Re-authentication confirmed - permanently delete account"}
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="card card-danger">
      <h2>Delete my data</h2>
      <p className="muted">
        This cancels your enrichment jobs and revokes your devices. It requires
        re-authentication and a double confirmation.
      </p>
      {error && <div className="banner banner-error">{error}</div>}
      <form onSubmit={onDeleteDev}>
        <label htmlFor="del-subject">Re-enter developer subject</label>
        <input
          id="del-subject"
          type="text"
          autoComplete="off"
          placeholder="alice"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          disabled={busy}
        />
        <label className="check-row">
          <input
            type="checkbox"
            checked={understood}
            onChange={(e) => setUnderstood(e.target.checked)}
            disabled={busy}
          />
          <span>I understand this cancels jobs and revokes devices</span>
        </label>
        <button className="btn btn-danger" type="submit" disabled={busy}>
          {busy ? "Requesting..." : "Request deletion"}
        </button>
      </form>
    </div>
  );
}

export function Privacy() {
  // stepUpId holds the single-use WorkOS step-up authorization id, read once
  // from ?step_up=<id> on mount. It is stripped from the address bar
  // immediately via history.replaceState — it is a one-use secret-ish value
  // and must never linger in the URL (browser history, referrer headers,
  // shoulder-surfing a shared screen).
  const [deletionStepUpId, setDeletionStepUpId] = useState<string | null>(null);
  const [exportStepUpId, setExportStepUpId] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const id = params.get("step_up");
    if (id === null) {
      return;
    }
    params.delete("step_up");
    const rest = params.toString();
    const cleanUrl = window.location.pathname + (rest ? "?" + rest : "");
    window.history.replaceState(null, "", cleanUrl);
    // Route the one-use id to the section that started the re-auth (the intent
    // stamped in sessionStorage before the redirect). Default deletion for
    // back-compat; a mis-routed id is refused server-side (action-bound).
    if (takeStepUpIntent() === "export") {
      setExportStepUpId(id);
    } else {
      setDeletionStepUpId(id);
    }
  }, []);

  return (
    <div>
      <h1>Privacy &amp; devices</h1>
      <p className="muted small page-intro">
        This portal runs no analytics and no third-party scripts of its own -
        the only exception is Paddle.js, loaded on the Billing page and only
        at the moment you open a checkout.
      </p>
      <DevicesSection />
      <BrowserSessionsSection />
      <CloudSharingSection />
      <ConsentsSection />
      <StandingGrantsSection />
      <ExportSection
        stepUpId={exportStepUpId}
        onConsumeStepUp={() => setExportStepUpId(null)}
      />
      <DeleteSection
        stepUpId={deletionStepUpId}
        onConsumeStepUp={() => setDeletionStepUpId(null)}
      />
    </div>
  );
}
