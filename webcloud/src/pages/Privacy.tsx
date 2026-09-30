import type { FormEvent } from "react";
import { useCallback, useEffect, useState } from "react";
import { usePortalQuery } from "../lib/query";
import { CardSkeleton, ErrorPanel } from "../components/LoadState";
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
import { copyFor, getConsentState, loadConsent, submitConsent } from "../consent";
import { Pill } from "@shared/primitives/Pill";
import { CopyOnClick } from "@shared/primitives/CopyOnClick";
import { fmtDateTime, fmtRelative, fmtShortId } from "@shared/lib/format";
import { DELETION_STATE_LABELS, RETENTION_STATE_LABELS, labelFor } from "../lib/labels";
import { Button } from "@shared/primitives/Button";
import { ConfirmButton } from "@shared/primitives/ConfirmButton";
import { Input } from "@shared/primitives/Input";
import { SectionNav } from "@shared/primitives/SectionNav";
import { RawIdHint } from "../components/RawIdHint";
import { ErrorState } from "@shared/primitives/ErrorState";
import { InlineLoading } from "@shared/primitives/Spinner";
import { SuccessCheck } from "@shared/primitives/SuccessCheck";
import { Card } from "@shared/primitives/Card";
import { Toggle } from "@shared/primitives/Toggle";
import { DisclosureChip, DisclosureChips, DisclosureMark } from "../components/Disclosure";
import { byDisclosure, CONSENT_PURPOSE, orderPurposes } from "../lib/vocab";
import { vocabIcon } from "@shared/lib/vocabIcons";
import { PageHeader } from "@shared/primitives/PageHeader";
import { CardHeader } from "@shared/primitives/CardHeader";
import {
  Ban,
  Download,
  FileCheck,
  KeyRound,
  LogIn,
  LogOut,
  MonitorSmartphone,
  Share2,
  Trash2,
  type LucideIcon,
} from "lucide-react";
import { routeIcon } from "../lib/nav";

// PRIVACY_SECTIONS: the in-page navigation for the long Privacy page (the
// shared SectionNav), one row per section card. The same row gives the card
// title its glyph and the jump chip its label, so the two never drift. The
// destructive section is last; its card is the danger zone.
type PrivacySectionId =
  | "devices"
  | "sessions"
  | "sharing"
  | "consents"
  | "grants"
  | "export"
  | "delete";
const PRIVACY_SECTIONS: { id: PrivacySectionId; label: string; icon: LucideIcon; tone?: "danger" }[] = [
  { id: "devices", label: "Devices", icon: MonitorSmartphone },
  { id: "sessions", label: "Signed-in sessions", icon: LogIn },
  { id: "sharing", label: "Cloud sharing", icon: Share2 },
  { id: "consents", label: "Consents", icon: FileCheck },
  { id: "grants", label: "Standing grants", icon: KeyRound },
  { id: "export", label: "Export", icon: Download },
  { id: "delete", label: "Delete my data", icon: Trash2, tone: "danger" },
];
const SECTION_ICONS = Object.fromEntries(
  PRIVACY_SECTIONS.map((sec) => [sec.id, sec.icon]),
) as Record<PrivacySectionId, LucideIcon>;

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
  const q = usePortalQuery<DevicesResult>("privacy:devices", getDevices);
  const data = q.data;
  const load = q.reload;
  const [actionError, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  // The device whose revoke just succeeded: its row draws the success check.
  const [revokedId, setRevokedId] = useState<string | null>(null);

  // Called by the ConfirmButton's second click: the in-place confirm step
  // replaces the old window.confirm.
  async function onRevoke(id: string) {
    setBusyId(id);
    setRevokedId(null);
    try {
      await revokeDevice(id);
      setRevokedId(id);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "revoke failed");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Card className="mb-4" id="devices">
      <CardHeader icon={SECTION_ICONS.devices} title="Devices" />
      {actionError && <div className="banner banner-error">{actionError}</div>}
      {q.error && !data && (
        <ErrorPanel what="devices" error={q.error} onRetry={q.reload} />
      )}
      {q.loading && <CardSkeleton lines={3} />}
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
                <span className="inline-flex items-center gap-2">
                  {revokedId === d.id && <SuccessCheck label="Device revoked" />}
                  <Pill variant="danger">Revoked</Pill>
                </span>
              ) : revokedId === d.id ? (
                <SuccessCheck label="Device revoked" />
              ) : (
                <ConfirmButton
                  variant="danger-outline"
                  size="sm"
                  iconLeft={Ban}
                  loading={busyId === d.id}
                  confirmLabel="Revoke device?"
                  armedNote="It will no longer be able to sync."
                  onConfirm={() => void onRevoke(d.id)}
                >
                  {busyId === d.id ? "Revoking" : "Revoke"}
                </ConfirmButton>
              )}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

// BrowserSessionsSection is the "sign out everywhere" surface (Wave C gap 2.4
// residual (b)): every live portal sign-in on this account, and a single
// action to revoke every OTHER session (keep_current: true) - the current
// session stays signed in, which is the useful shape for "I think I left
// myself signed in somewhere else."
function BrowserSessionsSection() {
  const navigate = useNavigate();
  const q = usePortalQuery<BrowserSessionsResult>(
    "privacy:browser-sessions",
    getBrowserSessions,
  );
  const data = q.data;
  const load = q.reload;
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  // Both sign-outs run on their ConfirmButton's second click (the in-place
  // confirm step replaces the old window.confirm).
  async function onSignOutEverywhere() {
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
    <Card className="mb-4" id="sessions">
      <CardHeader icon={SECTION_ICONS.sessions} title="Signed-in sessions" />
      {error && <div className="banner banner-error">{error}</div>}
      {result && (
        <div className="banner inline-flex items-center gap-2" role="status">
          <SuccessCheck />
          {result}
        </div>
      )}
      {q.error && !data && (
        <ErrorPanel what="sessions" error={q.error} onRetry={q.reload} />
      )}
      {q.loading && <CardSkeleton lines={3} />}
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
        <ConfirmButton
          variant="danger-outline"
          size="sm"
          iconLeft={LogOut}
          disabled={otherCount === 0}
          loading={busy}
          confirmLabel="Sign out the other sessions?"
          armedNote="This session stays signed in."
          onConfirm={() => void onSignOutEverywhere()}
        >
          {busy ? "Working" : "Sign out everywhere else"}
        </ConfirmButton>
        <ConfirmButton
          variant="ghost"
          size="sm"
          iconLeft={LogOut}
          disabled={busy}
          confirmLabel="Sign out here too?"
          armedNote="You will need to sign in again."
          onConfirm={() => void onSignOutThisDevice()}
        >
          Sign out everywhere, including this session
        </ConfirmButton>
      </div>
      {data && otherCount === 0 && (
        <p className="muted small">
          This is the only signed-in session on this account.
        </p>
      )}
    </Card>
  );
}

function ConsentsSection() {
  const q = usePortalQuery<ConsentsResult>("privacy:consents", getConsents);
  const data = q.data;

  return (
    <Card className="mb-4" id="consents">
      <CardHeader icon={SECTION_ICONS.consents} title="Consents" />
      {q.error && !data && (
        <ErrorPanel what="consents" error={q.error} onRetry={q.reload} />
      )}
      {q.loading && <CardSkeleton lines={2} />}
      {data && data.purposes.length === 0 && (
        <p className="muted small">No purposes granted.</p>
      )}
      {data && data.purposes.length > 0 && (
        <ul className="breakdown">
          {byDisclosure(CONSENT_PURPOSE, data.purposes).map((p) => (
            <li key={p}>
              <RawIdHint id={p} className="inline-flex items-center gap-2">
                <DisclosureMark kind="purpose" id={p} />
                {copyFor(p).label}
              </RawIdHint>
              <DisclosureChip kind="purpose" id={p} />
            </li>
          ))}
        </ul>
      )}
    </Card>
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
  const [reloading, setReloading] = useState(false);
  // The purpose whose Grant / Revoke was just saved server-side: its row draws
  // the success check beside the new On / Off state.
  const [savedId, setSavedId] = useState<string | null>(null);

  // Retry for a failed boot-time consent read: re-read the server state and
  // adopt whatever it now says (loadConsent never rejects; a failure leaves
  // the cache empty, so the error stays).
  async function onReload() {
    setReloading(true);
    try {
      await loadConsent();
      setState(getConsentState());
    } finally {
      setReloading(false);
    }
  }

  async function setPurpose(id: string, granted: boolean) {
    if (state === null || state.choices === null) {
      return;
    }
    setError(null);
    setBusyId(id);
    setSavedId(null);
    try {
      // Submit the WHOLE set with this one purpose changed: the endpoint
      // stores a complete choice set, so a partial body would read as
      // "everything else declined".
      const next: Record<string, boolean> = { ...state.choices, [id]: granted };
      setState(await submitConsent(next));
      setSavedId(id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "could not save the change");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Card className="mb-4" id="sharing">
      <CardHeader icon={SECTION_ICONS.sharing} title="Cloud sharing" />
      {error && <div className="banner banner-error">{error}</div>}
      {state === null &&
        (reloading ? (
          <InlineLoading block label="Loading your cloud-sharing choices" />
        ) : (
          <ErrorState
            title="Could not load your cloud-sharing choices"
            onRetry={() => void onReload()}
            className="py-5"
          />
        ))}
      {state !== null && state.choices === null && (
        <p className="muted small">
          You have not been through the cloud-sharing setup screen yet.
        </p>
      )}
      {state !== null &&
        state.choices !== null &&
        orderPurposes(state.purposes).map((p) => {
          const text = copyFor(p.id);
          const granted = state.choices?.[p.id] === true;
          return (
            <div key={p.id} className="grant-block">
              <div className="grant-head">
                <span className="grant-title">
                  <DisclosureMark kind="purpose" id={p.id} /> {text.label}{" "}
                  {granted ? (
                    <Pill variant="success" icon={vocabIcon("featureState", "on")}>
                      On
                    </Pill>
                  ) : (
                    <Pill variant="neutral" icon={vocabIcon("featureState", "off")}>
                      Off
                    </Pill>
                  )}
                  {savedId === p.id && busyId !== p.id && (
                    <SuccessCheck label={granted ? "Granted" : "Revoked"} className="ml-1" />
                  )}
                </span>
                {!p.mandatory && (
                  <Button
                    variant={granted ? "danger-outline" : "secondary"}
                    size="sm"
                    type="button"
                    loading={busyId === p.id}
                    onClick={() => setPurpose(p.id, !granted)}
                  >
                    {busyId === p.id
                      ? "Saving"
                      : granted
                        ? "Revoke"
                        : "Grant"}
                  </Button>
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
    </Card>
  );
}

// StandingGrantsSection is the D19 completion: for every standing grant the
// server has registered, exactly which field classes it binds, which schema and
// data-dictionary version it was agreed against, which consent generation those
// terms sit at, and what happens to the data it authorized. Nothing here is
// inferred in the browser: every value is the server restating its own
// registration row.
function StandingGrantsSection() {
  const q = usePortalQuery<GrantsResult>("privacy:grants", getGrants);
  const data = q.data;

  return (
    <Card className="mb-4" id="grants">
      <CardHeader icon={SECTION_ICONS.grants} title="Standing grants" />
      {q.error && !data && (
        <ErrorPanel what="standing grants" error={q.error} onRetry={q.reload} />
      )}
      {q.loading && <CardSkeleton lines={3} />}
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
                <DisclosureMark kind="purpose" id={g.purpose} />{" "}
                <RawIdHint id={g.purpose}>{copyFor(g.purpose).label}</RawIdHint>{" "}
                {g.state === "revoked" ? (
                  <Pill variant="danger" icon={vocabIcon("credentialStatus", "revoked")}>
                    Revoked
                  </Pill>
                ) : (
                  <Pill variant="success" icon={vocabIcon("credentialStatus", "active")}>
                    Active
                  </Pill>
                )}
              </span>
            </div>
            <ul className="breakdown">
              <li>
                <span>Field classes</span>
                <DisclosureChips kind="fieldClass" ids={g.field_classes} empty="none recorded" />
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
              <RawIdHint id={data.retention_state}>
                {labelFor(RETENTION_STATE_LABELS, data.retention_state)}
              </RawIdHint>
            </li>
          </ul>
          <p className="disclosure">{data.retention_detail}</p>
        </>
      )}
    </Card>
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
  // Set when an assembly request just succeeded (the new row is listed and
  // its download starts): the section draws the success check.
  const [assembled, setAssembled] = useState(false);

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
    setAssembled(true);
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
    setAssembled(false);
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
    setAssembled(false);
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
          <Button
            variant="ghost"
            size="sm"
            type="button"
            loading={downloading === e.export_id}
            onClick={() => void onDownload(e.export_id)}
          >
            {downloading === e.export_id ? "Downloading" : "Download"}
          </Button>
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
    <Card className="mb-4" id="export">
      <CardHeader icon={SECTION_ICONS.export} title="Download your data" />
      <p className="muted">
        Assemble a portable copy of your account data - your enrichment results
        and corrections, consent receipts, usage summary, and activity
        aggregates. The download is encrypted at rest and expires within 7 days.
        Download your data first - <strong>deletion is immediate and
        unrecoverable</strong>.
      </p>
      {error && <div className="banner banner-error">{error}</div>}
      {assembled && <SuccessCheck label="Export assembled" className="mb-2" />}
      {existing}
      {authMode === "workos" ? (
        stepUpId === null ? (
          <Button size="sm" type="button" onClick={onReauthClick}>
            Re-authenticate to export
          </Button>
        ) : (
          <Button
            size="sm"
            type="button"
            loading={busy}
            onClick={onConfirmStepUp}
          >
            {busy ? "Assembling" : "Re-authentication confirmed - assemble export"}
          </Button>
        )
      ) : (
        <form onSubmit={onExportDev}>
          <label htmlFor="exp-subject" className="field-label">
            Re-enter developer subject
          </label>
          <Input
            id="exp-subject"
            type="text"
            autoComplete="off"
            placeholder="alice"
            value={subject}
            onChange={(ev) => setSubject(ev.target.value)}
            disabled={busy}
          />
          <Button size="sm" type="submit" loading={busy} className="mt-3">
            {busy ? "Assembling" : "Assemble export"}
          </Button>
        </form>
      )}
    </Card>
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

  // devFormError is the dev form's own validation, checked BEFORE the confirm
  // step: an incomplete form fires on the first click (showing its error), a
  // complete one arms the ConfirmButton, and the request goes out only on the
  // second click. Enter in the field validates but never deletes.
  function devFormError(): string | null {
    if (subject.trim().length === 0) {
      return "Re-enter your developer subject to confirm.";
    }
    if (!understood) {
      return "You must acknowledge the consequences.";
    }
    return null;
  }

  function onSubmitDev(e: FormEvent) {
    e.preventDefault();
    setError(devFormError());
  }

  async function onDeleteDev() {
    setError(null);
    const invalid = devFormError();
    if (invalid !== null) {
      setError(invalid);
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
      <Card className="mb-4" tone="danger" id="delete">
        <CardHeader icon={SECTION_ICONS.delete} title="Deletion requested" />
        <div className="banner">
          Deletion request{" "}
          <CopyOnClick value={result.id} className="mono">
            {fmtShortId(result.id)}
          </CopyOnClick>{" "}
          is now{" "}
          <RawIdHint id={result.state} className="font-semibold">
            {labelFor(DELETION_STATE_LABELS, result.state)}
          </RawIdHint>
          .
          Jobs canceled: {result.jobs_canceled}. Devices revoked:{" "}
          {result.devices_revoked}. Tokens revoked: {result.tokens_revoked}.
        </div>
        <InlineLoading size="sm" label="Signing you out" className="mt-2" />
      </Card>
    );
  }

  if (authMode === "workos") {
    return (
      <Card className="mb-4" tone="danger" id="delete">
        <CardHeader icon={SECTION_ICONS.delete} title="Delete my data" />
        <p className="muted">
          This cancels your enrichment jobs and revokes your devices. It
          requires re-authentication and a double confirmation.
        </p>
        {error && <div className="banner banner-error">{error}</div>}
        {stepUpId === null ? (
          <Button
            variant="danger-outline"
            size="sm"
            type="button"
            onClick={onReauthClick}
          >
            Re-authenticate to delete
          </Button>
        ) : (
          <Button
            variant="danger-outline"
            size="sm"
            type="button"
            loading={busy}
            onClick={onConfirmStepUp}
          >
            {busy
              ? "Requesting"
              : "Re-authentication confirmed - permanently delete account"}
          </Button>
        )}
      </Card>
    );
  }

  return (
    <Card className="mb-4" tone="danger" id="delete">
      <CardHeader icon={SECTION_ICONS.delete} title="Delete my data" />
      <p className="muted">
        This cancels your enrichment jobs and revokes your devices. It requires
        re-authentication and a double confirmation.
      </p>
      {error && <div className="banner banner-error">{error}</div>}
      <form onSubmit={onSubmitDev}>
        <label htmlFor="del-subject" className="field-label">
          Re-enter developer subject
        </label>
        <Input
          id="del-subject"
          type="text"
          autoComplete="off"
          placeholder="alice"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          disabled={busy}
        />
        <div className="mb-1.5 mt-3.5">
          <Toggle
            on={understood}
            onChange={setUnderstood}
            disabled={busy}
            label={
              <span className="block text-left text-body leading-snug text-fg-1">
                I understand this cancels jobs and revokes devices
              </span>
            }
          />
        </div>
        <ConfirmButton
          variant="danger-outline"
          size="sm"
          iconLeft={Trash2}
          loading={busy}
          requireConfirm={devFormError() === null}
          confirmLabel="Permanently delete?"
          armedNote="This requests deletion of your data, cancels jobs, and revokes devices."
          onConfirm={() => void onDeleteDev()}
        >
          {busy ? "Requesting" : "Request deletion"}
        </ConfirmButton>
      </form>
    </Card>
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
      <PageHeader
        title="Privacy & devices"
        icon={routeIcon("/privacy")}
        sub="This portal runs no analytics and no third-party scripts of its own - the only exception is Paddle.js, loaded on the Billing page and only at the moment you open a checkout."
        className="mb-6"
      />
      <SectionNav items={PRIVACY_SECTIONS} className="mb-4" />
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
