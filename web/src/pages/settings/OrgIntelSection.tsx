import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { GatedLink } from "@/components/GatedLink";
import { Check, LogOut, ShieldCheck, Undo2, type LucideIcon } from "lucide-react";
import { Button, ChartShell, ConfirmButton, Pill } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { apiCache, useApi } from "@/lib/useApi";
import { apiReason, fetchJSON } from "@/lib/api";
import { fmtDateTime, fmtInt } from "@/lib/format";
import {
  ORG_INTEL_EVENT_LABELS,
  ORG_INTEL_RECEIPT_LABELS,
  orgIntelBackgroundLine,
  orgIntelLevelLabel,
  orgIntelFix,
  orgIntelIsPersonal,
  orgIntelOrgName,
  orgIntelPhase,
  orgIntelPurposeLabel,
  orgIntelSubmissionState,
  ORG_INTEL_LEDGER_PATH,
  ORG_INTEL_TRIGGER_LABELS,
  type OrgIntelLedger,
  type OrgIntelStatus,
  type OrgIntelStatusResponse,
} from "@/lib/orgIntel";
import { NeedsSettingNotice } from "@/components/NeedsSettingNotice";

// OrgIntelSection is Settings > Org enrichment: the ORG-PLANE Cloud
// Intelligence of the organization this machine is enrolled with (design
// docs/plans/cloud-intelligence-parity-design-2026-10-03.md 3.3 + 3.7). It
// renders GET /api/intel/status and runs the same accept / withdraw code as
// `observer intel accept | disable` through POST /api/intel/*.
//
// Class I (individual tenancy): the consent screen. The disclosure text and
// its digest come from the daemon (one source of truth with the CLI); Accept
// echoes the digest of the text on screen, so a changed text is refused as
// stale instead of being accepted unseen.
// Class M (managed): a notice, never a consent; read-only.

const BOX = "rounded-2 border px-3 py-2 text-[11.5px]";

export const ORG_INTEL_STATUS_PATH = "/api/intel/status";

function intelError(e: unknown): string {
  const raw = apiReason(e);
  try {
    const parsed = JSON.parse(raw) as { message?: string };
    if (parsed.message) return parsed.message;
  } catch {
    // not JSON: show the reason as is
  }
  return raw;
}

export function OrgIntelSection({ icon, readOnly = false }: { icon?: LucideIcon; readOnly?: boolean }) {
  const st = useApi<OrgIntelStatusResponse>(ORG_INTEL_STATUS_PATH, undefined, [], { refreshMs: 60000 });
  const [busy, setBusy] = useState<"accept" | "withdraw" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  async function post(path: string, body: unknown) {
    const token = st.data?.confirm_token ?? "";
    return fetchJSON<{ status: OrgIntelStatus }>(path, undefined, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Observer-Confirm": token },
      body: JSON.stringify(body),
    });
  }

  async function run(kind: "accept" | "withdraw") {
    setBusy(kind);
    setErr(null);
    setNote(null);
    try {
      const body = kind === "accept" ? { disclosure_digest: st.data?.status.disclosure_digest ?? "" } : {};
      const res = await post(kind === "accept" ? "/api/intel/accept" : "/api/intel/withdraw", body);
      setNote(res.status.note ?? null);
      apiCache.invalidate(ORG_INTEL_STATUS_PATH);
      st.reload();
    } catch (e) {
      setErr(intelError(e));
      st.reload();
    } finally {
      setBusy(null);
    }
  }

  const unavailable = st.error != null && !st.data;
  return (
    <ChartShell
      title="Team AI summaries"
      icon={icon}
      sub="AI summaries run by the team this machine is connected to, on the team's own server and model. Personal AI summaries, for sessions captured while not connected, are in the AI summaries section."
    >
      <ChartState loading={st.loading && !st.data} error={null} denied={false} empty={false} height={160}>
        {unavailable ? (
          <div className={`${BOX} border-line-1 bg-bg-2 text-fg-2`}>
            Team AI summaries status is not available here: {intelError(st.error)}. On the machine itself, `observer intel
            status` shows the same.
          </div>
        ) : st.data ? (
          <div className="space-y-4">
            {err && (
              <div role="alert" className={`${BOX} border-danger/40 bg-danger-soft text-danger`}>
                {err}
              </div>
            )}
            {note && <div className={`${BOX} border-line-1 bg-bg-2 text-fg-2`}>{note}</div>}
            <OrgIntelBody s={st.data.status} readOnly={readOnly} busy={busy} onRun={run} />
          </div>
        ) : null}
      </ChartState>
    </ChartShell>
  );
}

function OrgIntelBody({
  s,
  readOnly,
  busy,
  onRun,
}: {
  s: OrgIntelStatus;
  readOnly: boolean;
  busy: "accept" | "withdraw" | null;
  onRun: (k: "accept" | "withdraw") => void;
}) {
  const phase = orgIntelPhase(s);
  const org = orgIntelOrgName(s);
  const fix = orgIntelFix(s);
  if (phase === "unenrolled") {
    return (
      <div className="space-y-2">
      <NeedsSettingNotice
        tone="info"
        text="This machine is not connected to a team, so there are no team AI summaries here. Connect it to a team in Settings > Account."
        link={fix.settings}
      />
      <p className="text-[12px] leading-relaxed text-fg-2">
        Personal AI summaries are
        under{" "}
        <GatedLink to="/settings?section=cloud" managed="AI summaries (managed by your team)" className="font-medium text-accent hover:text-accent-strong">
          AI summaries
        </GatedLink>
        .
      </p>
      </div>
    );
  }
  if (phase === "no_terms") {
    return (
      <NeedsSettingNotice
        tone="info"
        text={`${orgIntelIsPersonal(s) ? "Your personal dashboard" : org} has not sent its AI summaries terms yet. Its server may predate this feature, or the next sync has not run. Nothing is sent for enrichment from this machine.`}
        org={fix.org}
      />
    );
  }
  return (
    <div className="space-y-4">
      <TermsCard s={s} />
      {phase === "managed_notice" && (
        <div className={`${BOX} border-line-1 bg-bg-2 text-fg-2`}>
          <div className="mb-0.5 font-medium text-fg-1">Notice from {org}</div>
          This machine is managed by {org}, which decides session enrichment. There is nothing to accept here; this is
          what the organization runs.
          {s.managed_rail && (
            <div className="mt-1.5 flex flex-wrap items-center gap-2">
              <Pill variant={s.managed_rail.on ? "success" : "neutral"}>{s.managed_rail.on ? "running" : "not running"}</Pill>
              {s.managed_rail.on || !fix.org ? (
                <span>{s.managed_rail.message}</span>
              ) : (
                <NeedsSettingNotice variant="inline" className="min-w-0 flex-1" text={s.managed_rail.message} org={fix.org} />
              )}
            </div>
          )}
        </div>
      )}
      {phase === "org_off" && (
        <NeedsSettingNotice
          tone="info"
          text={
            orgIntelIsPersonal(s)
              ? "Your personal dashboard has session enrichment off. Nothing is sent."
              : `${org} has not turned on session enrichment. Nothing is sent.`
          }
          org={fix.org}
        />
      )}
      {(phase === "pending_required" || phase === "terms_changed" || phase === "not_opted_in" || phase === "accepted") && (
        <ConsentCard s={s} phase={phase} readOnly={readOnly} busy={busy} onRun={onRun} />
      )}
      <LedgerCard />
      <HistoryCard s={s} />
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5 sm:flex-row sm:gap-3">
      <dt className="w-44 shrink-0 text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">{label}</dt>
      <dd className="min-w-0 break-words text-[12px] text-fg-1">{children}</dd>
    </div>
  );
}

function TermsCard({ s }: { s: OrgIntelStatus }) {
  const r = s.requirement!;
  return (
    <dl className="space-y-2 rounded-3 border border-line-2 bg-bg-2 px-3 py-3">
      <Row label="Session enrichment">
        {r.enabled ? <Pill variant="success">on</Pill> : <Pill variant="neutral">off</Pill>}
      </Row>
      <Row label="Provider / model">
        {r.provider_label || "No provider configured"} / {r.model || "provider default"}
      </Row>
      <Row label="Evidence level">{orgIntelLevelLabel(r.evidence_level)}</Row>
      <Row label="Purposes">
        {(r.purposes ?? []).length === 0
          ? "None"
          : (r.purposes ?? []).map((p, i) => (
              <span key={p} className="mr-2 inline-block">
                {orgIntelPurposeLabel(p)}
                <span className="ml-1 font-mono text-[10px] text-fg-4">{p}</span>
                {i < (r.purposes ?? []).length - 1 ? "," : ""}
              </span>
            ))}
      </Row>
      <Row label="Background">{orgIntelBackgroundLine(r)}</Row>
      <Row label="Consent">
        {s.class === "managed"
          ? "Not asked: this machine is managed"
          : r.require_individual_consent
            ? "Required for membership"
            : "Optional"}
      </Row>
      {s.deadline_at && (
        <Row label="Deadline">
          {fmtDateTime(s.deadline_at)}
          {s.deadline_passed && (
            <span className="ml-2">
              <Pill variant="danger">passed</Pill>
            </span>
          )}
        </Row>
      )}
      <Row label="Results on this machine">{fmtInt(s.cached_results)}</Row>
    </dl>
  );
}

function ConsentCard({
  s,
  phase,
  readOnly,
  busy,
  onRun,
}: {
  s: OrgIntelStatus;
  phase: "pending_required" | "terms_changed" | "not_opted_in" | "accepted";
  readOnly: boolean;
  busy: "accept" | "withdraw" | null;
  onRun: (k: "accept" | "withdraw") => void;
}) {
  const navigate = useNavigate();
  const org = orgIntelOrgName(s);
  const accepted = phase === "accepted";
  const headline: Record<typeof phase, string> = {
    pending_required: `${org} requires AI summaries. Accept, or leave the team.`,
    terms_changed: "The terms widened since you accepted. Enrichment continues under the terms you accepted until you review these.",
    not_opted_in: "Not turned on. Nothing is sent for enrichment until you accept these terms.",
    accepted: `Accepted (terms version ${s.active?.requirement_version ?? 0}). Your sessions are enriched by ${org}.`,
  };
  return (
    <div className="space-y-3 rounded-3 border border-line-2 bg-bg-1 px-3 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <Pill variant={accepted ? "success" : phase === "not_opted_in" ? "neutral" : "warn"}>
          {accepted ? "accepted" : phase === "not_opted_in" ? "off" : "pending"}
        </Pill>
        <span className="text-[12px] font-medium text-fg-1">{headline[phase]}</span>
      </div>
      {!accepted && s.disclosure && (
        <div className="rounded-2 border border-line-1 bg-bg-2 px-3 py-2">
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
            What you are agreeing to
          </div>
          <p className="whitespace-pre-line text-[11.5px] leading-relaxed text-fg-2">{s.disclosure}</p>
        </div>
      )}
      {readOnly ? (
        <p className="text-[11px] text-fg-3">This section is read-only on this machine.</p>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          {!accepted && (
            <Button
              variant="primary"
              iconLeft={Check}
              loading={busy === "accept"}
              disabled={busy !== null || !s.disclosure_digest}
              onClick={() => onRun("accept")}
            >
              Accept these terms
            </Button>
          )}
          {(accepted || phase === "terms_changed") && (
            <ConfirmButton
              variant="danger-outline"
              iconLeft={Undo2}
              confirmLabel="Withdraw consent?"
              armedNote={
                s.required
                  ? `${org} requires this consent: withdrawing returns this machine to pending, and you will need to accept again or leave.`
                  : "Nothing more is sent, and results cached under this consent are removed from this machine."
              }
              loading={busy === "withdraw"}
              disabled={busy !== null}
              onConfirm={() => onRun("withdraw")}
            >
              Withdraw consent
            </ConfirmButton>
          )}
          {s.required && !accepted && (
            <Button variant="ghost" iconLeft={LogOut} onClick={() => navigate("/settings?section=enrolment")}>
              Leave the organization
            </Button>
          )}
        </div>
      )}
      <p className="text-[10.5px] text-fg-4">
        Same as the CLI: <code className="font-mono">observer intel accept</code>,{" "}
        <code className="font-mono">observer intel disable</code>, <code className="font-mono">observer unenroll</code>.
      </p>
    </div>
  );
}

function HistoryCard({ s }: { s: OrgIntelStatus }) {
  if (!s.history.length && !s.receipts.length) return null;
  return (
    <div className="space-y-2 rounded-3 border border-line-2 bg-bg-2 px-3 py-3">
      <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        <ShieldCheck className="h-3.5 w-3.5" aria-hidden />
        On this machine
      </div>
      <ul className="space-y-1 text-[11.5px] text-fg-2">
        {s.history.map((h, i) => (
          <li key={`h${i}`} className="flex flex-wrap gap-x-2">
            <span className="font-mono text-fg-3">{fmtDateTime(h.created_at)}</span>
            <span className="text-fg-1">{ORG_INTEL_EVENT_LABELS[h.event] ?? h.event}</span>
            {h.event === "accept" && (
              <span>
                terms version {h.requirement_version}, {orgIntelLevelLabel(h.evidence_level).toLowerCase()}
              </span>
            )}
          </li>
        ))}
        {s.receipts.map((r, i) => (
          <li key={`r${i}`} className="flex flex-wrap gap-x-2">
            <span className="font-mono text-fg-3">{fmtDateTime(r.created_at)}</span>
            <span className="text-fg-1">{ORG_INTEL_RECEIPT_LABELS[r.kind] ?? r.kind}</span>
            {r.count > 0 && <span>({fmtInt(r.count)})</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}

// LedgerCard is every org-plane submission from this machine (GET
// /api/intel/ledger, the same rows as `observer intel ledger`): what was sent,
// at which level, its digests and the organization's answer. A row still
// waiting to be sent holds its exact bytes and can show them; a sent row keeps
// only its digests.
function LedgerCard() {
  const ledger = useApi<OrgIntelLedger>(ORG_INTEL_LEDGER_PATH, undefined, [], { refreshMs: 60000 });
  const [open, setOpen] = useState<{ id: number; bytes: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const rows = ledger.data?.rows ?? [];

  async function show(id: number) {
    if (open?.id === id) {
      setOpen(null);
      return;
    }
    setErr(null);
    try {
      const one = await fetchJSON<OrgIntelLedger>(`${ORG_INTEL_LEDGER_PATH}?id=${id}`);
      setOpen({ id, bytes: one.rows[0]?.bytes ?? "" });
    } catch (e) {
      setErr(intelError(e));
    }
  }

  return (
    <div className="space-y-2 rounded-3 border border-line-2 bg-bg-2 px-3 py-3">
      <div className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">Submissions from this machine</div>
      {rows.length === 0 ? (
        <p className="text-[11.5px] text-fg-3">
          Nothing has been submitted for enrichment from this machine. Sessions are submitted in the background once your
          team's terms allow it, or from a session's Team AI summaries card.
        </p>
      ) : (
        <ul className="space-y-1.5 text-[11.5px] text-fg-2">
          {rows.map((r) => {
            const st = orgIntelSubmissionState(r.state);
            return (
              <li key={r.id} className="space-y-1">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="font-mono text-fg-3">{fmtDateTime(r.created_at)}</span>
                  <Pill variant={st.tone} case="none">{st.label}</Pill>
                  <span>{ORG_INTEL_TRIGGER_LABELS[r.trigger] ?? r.trigger}</span>
                  <span>{orgIntelLevelLabel(r.evidence_level)}</span>
                  <Link
                    to={`/sessions?session=${encodeURIComponent(r.session_id)}`}
                    className="font-mono text-accent hover:text-accent-strong"
                  >
                    {r.session_id.slice(0, 12)}
                  </Link>
                  {r.bytes_held && (
                    <Button size="sm" variant="ghost" onClick={() => void show(r.id)}>
                      {open?.id === r.id ? "Hide bytes" : "Show exact bytes"}
                    </Button>
                  )}
                </div>
                <div className="break-all font-mono text-[10.5px] text-fg-4">upload {r.upload_digest}</div>
                {r.reason && <div className="text-[10.5px] text-fg-3">Reason: {r.reason}</div>}
                {open?.id === r.id && (
                  <pre className="max-h-[16rem] overflow-auto whitespace-pre-wrap break-all rounded-2 border border-line-2 bg-bg-1 p-2 font-mono text-[10.5px] text-fg-2">
                    {open.bytes}
                  </pre>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {err && <p className="text-[11px] text-danger">{err}</p>}
      <p className="text-[10.5px] text-fg-4">
        Same as the CLI: <code className="font-mono">observer intel ledger</code>. Sent bytes are not kept here; their
        digests identify them.
      </p>
    </div>
  );
}
