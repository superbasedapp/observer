import { useState } from "react";
import { Link } from "react-router-dom";
import { ChartShell, PageHeader, Pill } from "@/components/primitives";
import { TitleWithHelp } from "@/components/HelpInd";
import { useApi } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";
import { fmtBytes, fmtDateTime, fmtInt } from "@/lib/format";
import {
  type GovernanceShareKey,
  type GovernancePricing,
  shareSourceLabel,
  shareSourceOf,
  useGovernance,
} from "@/lib/governance";
import type { ConfigResponse } from "@/lib/types";

// Privacy center (P6.5): one page answering "what does the observer
// capture, what never leaves this machine, and how do I verify it?".
// Composes existing surfaces (config flags, enrolment status, the
// last-payload transparency view) plus the live scrub tester.
//
// Working surface — calm register, zero delight elements (§9.4).
export function PrivacyPage() {
  const cfg = useApi<ConfigResponse>("/api/config");
  const secrets = (cfg.data?.config as Record<string, any> | undefined)
    ?.Observer?.Secrets;
  const retention = (cfg.data?.config as Record<string, any> | undefined)
    ?.Observer?.Retention;

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Privacy"
        sub="What the observer captures, what never leaves this machine, and the tools to verify both - the live scrub tester and the byte-for-byte view of anything shared with a Teams server."
        helpId="tab.privacy"
      />

      <ChartShell
        title={<TitleWithHelp text="What's captured" helpId="card.privacy_capture_map" />}
        sub="The capture contract, with this install's live settings"
      >
        <div className="grid grid-cols-1 gap-4 text-[12px] leading-relaxed xl:grid-cols-2">
          <div className="space-y-1.5">
            <p className="font-medium text-fg-1">Stored locally (observer.db)</p>
            <ul className="list-disc space-y-1 pl-4 text-fg-2">
              <li>Action metadata: tool, action type, timestamps, file paths, command lines</li>
              <li>Output excerpts, capped (FTS5 index; first/last bytes of long outputs)</li>
              <li>Token usage and API turn accounting (counts and costs, not content)</li>
              <li>Failure context: command summaries and error excerpts</li>
            </ul>
            <p className="font-medium text-fg-1">Never stored</p>
            <ul className="list-disc space-y-1 pl-4 text-fg-2">
              <li>Full file contents and full command outputs (paths and excerpts only)</li>
              <li>Credentials - secret-shaped strings are scrubbed before any row lands</li>
            </ul>
          </div>
          <div className="space-y-1.5">
            <p className="font-medium text-fg-1">Network posture</p>
            <ul className="list-disc space-y-1 pl-4 text-fg-2">
              <li>The observer and watcher make no network calls - everything is local</li>
              <li>The proxy only forwards your AI tool's own traffic to its provider</li>
              <li>
                Teams push happens only after explicit enrolment, hash-only by
                default; raw content requires the node-side{" "}
                <span className="font-mono text-[11px]">share.full_content</span>{" "}
                opt-in that no server can flip remotely
              </li>
            </ul>
            <p className="mt-2 font-medium text-fg-1">This install</p>
            <div className="flex flex-wrap gap-1.5 pt-1">
              <Pill variant={secrets?.EnableScrubbing ? "success" : "warn"}>
                scrubbing {secrets?.EnableScrubbing ? "on" : "off"}
              </Pill>
              <Pill>
                {fmtInt(secrets?.ExtraPatterns?.length ?? 0)} extra pattern
                {(secrets?.ExtraPatterns?.length ?? 0) === 1 ? "" : "s"}
              </Pill>
              <Pill>
                retention{" "}
                {retention?.Days ? `${retention.Days}d` : "unlimited"}
              </Pill>
            </div>
            <p className="pt-1 text-[11px] text-fg-3">
              Tune scrubbing in{" "}
              <Link to="/settings?section=secrets" className="font-medium text-accent hover:text-accent-strong">
                Settings → Secrets
              </Link>
              , retention (with a prune-now button) in{" "}
              <Link to="/settings?section=retention" className="font-medium text-accent hover:text-accent-strong">
                Settings → Retention
              </Link>
              .
            </p>
          </div>
        </div>
      </ChartShell>

      <ScrubTesterCard scrubbingEnabled={secrets?.EnableScrubbing ?? true} />
      <SharingSourceCard config={cfg.data?.config as Record<string, any> | undefined} />
      <OrgPushCard />
    </div>
  );
}

function ScrubTesterCard({ scrubbingEnabled }: { scrubbingEnabled: boolean }) {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<{
    enabled: boolean;
    scrubbed: string;
    changed: boolean;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(
        await fetchJSON("/api/privacy/scrub-test", undefined, {
          method: "POST",
          body: JSON.stringify({ text: input }),
        }),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <ChartShell
      title={<TitleWithHelp text="Scrub tester" helpId="card.privacy_scrub_tester" />}
      sub="Paste anything - see exactly what the scrubber would redact. Processed in memory only; nothing you paste here is logged or stored."
    >
      <div className="space-y-2">
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          rows={4}
          placeholder='Try a fake token: "export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwx123456"'
          className="w-full rounded-2 border border-line-2 bg-bg-1 p-2.5 font-mono text-[11.5px] text-fg-1 outline-none placeholder:text-fg-3 focus:border-accent/60"
        />
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={busy || input.trim() === ""}
            onClick={() => void run()}
            className="rounded-2 border border-accent/40 bg-accent-soft px-3 py-1 text-[11px] font-medium text-accent disabled:opacity-50"
          >
            {busy ? "scrubbing…" : "test scrub"}
          </button>
          {!scrubbingEnabled && (
            <Pill variant="warn">
              scrubbing is currently OFF - this shows what it would do once enabled
            </Pill>
          )}
          {result && (
            <Pill variant={result.changed ? "danger" : "success"}>
              {result.changed ? "secrets found and redacted" : "nothing to redact"}
            </Pill>
          )}
        </div>
        {error && <p className="text-[11px] text-danger">{error}</p>}
        {result && (
          <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-words rounded-2 border border-line-1 bg-bg-1 p-2.5 font-mono text-[11px] leading-relaxed text-fg-2">
            {result.scrubbed}
          </pre>
        )}
      </div>
    </ChartShell>
  );
}

// SHARE_ROWS is the sharing posture this page explains, one row per
// [org_client.share] key, paired with the wire key the org rail names it by.
//
// It is a display table, not a vocabulary: the organisation's own vocabulary
// is served by the org server, and SharingSourceCard renders ANY key the
// governance endpoint reports that is missing here rather than dropping it.
// So a new org-side key is visible on day one, worst case without a friendly
// label - never invisible.
const SHARE_ROWS: { key: string; field: string; label: string; help: string; list?: true }[] = [
  {
    key: "full_content",
    field: "FullContent",
    label: "Full file paths and command text",
    help: "Off means only sha256 hashes and counts cross the wire.",
  },
  {
    key: "target_action_allowlist",
    field: "TargetActionAllowlist",
    label: "Action types allowed to ship a raw target",
    help: "A per-action exception to the hash-only default.",
    list: true,
  },
  {
    key: "routing_summary",
    field: "RoutingSummary",
    label: "Routing summary rollup",
    help: "Counts and dollars by tier and reason. Never the decision rows.",
  },
  {
    key: "policy_state",
    field: "PolicyState",
    label: "Effective-policy-state reports",
    help: "Which policy version this machine is running. Content-free.",
  },
];

// shareValueText renders a share value for the table without ever printing
// "true"/"false" at a developer. A list-shaped key reads "none" when empty,
// because "not shared" would describe the key itself rather than its
// contents.
function shareValueText(v: unknown, list?: boolean): string {
  if (Array.isArray(v)) return v.length ? v.join(", ") : "none";
  if (typeof v === "boolean") return v ? "shared" : "not shared";
  if (v === undefined || v === null) return list ? "none" : "not shared";
  return String(v);
}

// SharingSourceCard is the Privacy page's Source column: for every sharing
// key, what this machine's own config asks for, what is actually in force,
// and which of the two decided it.
//
// The direction depends on the tenancy, and this card says WHICH ONE this
// machine is on rather than making one claim for both:
//
//   Individual / BYO - one-way by construction. An organisation can reduce
//   what this machine shares, or lock it at the level the operator already
//   chose. It cannot raise it: the raise no-ops without managed enrolment.
//
//   Managed (Enterprise-Managed Tenancy) - the organisation can also turn
//   sharing ON remotely, for the tiers it was granted at enrolment. That is
//   the deal a managed enrolment makes, and a row it raised is labelled as
//   its decision, not the developer's.
function SharingSourceCard({ config }: { config: Record<string, any> | undefined }) {
  const gov = useGovernance();
  const enrol = useApi<EnrolStatus>("/api/enrolment/status");
  const local = config?.OrgClient?.Share as Record<string, unknown> | undefined;
  const orgKeys = Object.keys(gov.data?.share ?? {});
  const known = new Set(SHARE_ROWS.map((r) => r.key));
  const extra = orgKeys.filter((k) => !known.has(k));

  const rows: {
    key: string;
    label: string;
    help: string;
    list?: boolean;
    local: unknown;
    row: GovernanceShareKey | null;
  }[] = [
    ...SHARE_ROWS.map((r) => ({
      key: r.key,
      label: r.label,
      help: r.help,
      list: r.list,
      local: local?.[r.field],
      row: shareSourceOf(gov.data, r.key),
    })),
    ...extra.map((k) => ({
      key: k,
      label: k,
      help: "This sharing key is newer than this dashboard build, so it has no description here yet.",
      local: undefined,
      row: shareSourceOf(gov.data, k),
    })),
  ];

  return (
    <ChartShell
      title={<TitleWithHelp text="Sharing keys and their source" helpId="card.privacy_share_source" />}
      sub={
        gov.data?.managed
          ? "Each sharing switch, what it is set to, and who decided. This machine is managed by your organisation, so it can reduce, lock, or increase what is shared - every row it decided is marked below."
          : "Each sharing switch, what it is set to, and who decided. An organisation can reduce or lock what this machine shares; on an unmanaged machine like this one it cannot increase it."
      }
    >
      {enrol.data && !enrol.data.enrolled && (
        <p className="pb-2 text-[11.5px] text-fg-2">
          This machine is not enrolled in any organisation, so nothing below is shared with anyone. The settings are
          what would apply if you enrolled.
        </p>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-[12px]">
          <thead>
            <tr className="border-b border-line-1 text-left text-[10.5px] uppercase tracking-wide text-fg-3">
              <th className="py-1.5 pr-3 font-medium">Setting</th>
              <th className="py-1.5 pr-3 font-medium">Your setting</th>
              <th className="py-1.5 pr-3 font-medium">In force</th>
              <th className="py-1.5 font-medium">Source</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line-1">
            {rows.map((r) => {
              const effective = r.row ? r.row.effective : r.local;
              const governed = !!r.row && r.row.source !== "you";
              return (
                <tr key={r.key}>
                  <td className="py-1.5 pr-3 align-top">
                    <div className="text-fg-1">{r.label}</div>
                    <div className="font-mono text-[10.5px] text-fg-3">{r.key}</div>
                    <div className="text-[11px] text-fg-3">{r.help}</div>
                  </td>
                  <td className="py-1.5 pr-3 align-top text-fg-2">{shareValueText(r.local, r.list)}</td>
                  <td className="py-1.5 pr-3 align-top text-fg-2">{shareValueText(effective, r.list)}</td>
                  <td className="py-1.5 align-top">
                    {governed ? (
                      // A raise is the one direction that shares MORE than
                      // the operator asked for, so it does not read as
                      // routine policy the way a reduce or a lock does.
                      <Pill variant={r.row?.source === "org_raised" ? "warn" : "info"}>
                        {shareSourceLabel(r.row)}
                      </Pill>
                    ) : (
                      <span className="text-fg-2">{shareSourceLabel(null)}</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <PricingSourceRow pricing={gov.data?.pricing} />
      <PricingFeedEgressRow config={config} />
      <p className="pt-2 text-[11px] text-fg-3">
        Change your own settings in{" "}
        <Link to="/settings?section=org" className="font-medium text-accent hover:text-accent-strong">
          Settings &rarr; Organisation
        </Link>
        . A row sourced to your organisation is applied on this machine and its control there is read-only; running{" "}
        <span className="font-mono">observer unenroll</span> removes it.
      </p>
      {gov.error && (
        <p
          className="pt-1 text-[11px] text-fg-3"
          title="GET /api/governance did not answer, so any organisation directive cannot be shown."
        >
          The governance posture could not be read, so every row shows your own setting as the source. Reload to try
          again.
        </p>
      )}
    </ChartShell>
  );
}

// PricingSourceRow says WHICH PRICE TABLE this machine is using.
//
// It sits on the sharing card because it answers the same question every other
// row here answers: what did my organisation decide for this machine, and how
// do I know? An organisation that distributes negotiated rates changes every
// dollar figure on every screen of this dashboard, and before this arc no
// surface said so anywhere.
//
// An ABSENT block renders nothing at all. "Not reported" and "using the
// built-in table" are different facts, and this page's whole discipline is
// that an absence never renders as a verdict.
function PricingSourceRow({ pricing }: { pricing: GovernancePricing | undefined }) {
  if (!pricing) return null;
  const version = pricing.org_version ?? 0;
  const feedVersion = pricing.feed_version ?? 0;
  const label =
    pricing.source === "org_authoritative"
      ? `Your organisation's negotiated rates (v${version}) price every turn on this machine, above any rate you set yourself.`
      : pricing.source === "org"
        ? `Your organisation's negotiated rates (v${version}) price every turn on this machine, below any rate you set yourself.`
        : pricing.source === "feed"
          ? `Market list prices from the Tokenomics pricing feed (v${feedVersion}) price every turn on this machine, below any rate you set yourself.`
          : "This machine prices every turn from its own table: the built-in rates plus anything you set in Settings.";
  return (
    <div className="pt-2 text-[11px] text-fg-3">
      <span className="font-medium text-fg-2">Pricing:</span> {label}
      {(pricing.warnings ?? []).length > 0 && (
        <ul className="pt-1 pl-4 list-disc">
          {(pricing.warnings ?? []).map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

// PricingFeedEgressRow states the public pricing feed's OUTBOUND posture
// honestly (plan §G): off (no feed fetch), manual-only, or auto on a cadence.
// It reads [pricing.feed] from the node's own config — this is a local egress
// decision, never an org directive — and renders nothing when the block is
// absent (an older build), so an absence never reads as a verdict.
function PricingFeedEgressRow({
  config,
}: {
  config: Record<string, any> | undefined;
}) {
  const feed = config?.pricing?.feed as
    | { enabled?: boolean; auto?: boolean; poll_interval_hours?: number }
    | undefined;
  if (!feed) return null;
  const hours = feed.poll_interval_hours ?? 24;
  const posture = !feed.enabled
    ? "off - no outbound request is made. A standalone node can still pull it on demand with `observer pricing sync`."
    : feed.auto
      ? `auto - this node fetches the public pricing feed about every ${hours}h (plus on demand). Enrolled nodes never consult it.`
      : "manual only - fetched only when you run `observer pricing sync`. No background request is made.";
  return (
    <div className="pt-2 text-[11px] text-fg-3">
      <span className="font-medium text-fg-2">Pricing feed egress:</span> {posture}
    </div>
  );
}

type EnrolStatus = {
  enrolled: boolean;
  org_name?: string;
  org_server_url?: string;
  user_email?: string;
  last_push?: {
    pushed_at: string;
    status: string;
    row_count: number;
    bytes: number;
    error?: string;
  };
};

function OrgPushCard() {
  const status = useApi<EnrolStatus>("/api/enrolment/status");
  const [payload, setPayload] = useState<string | null>(null);
  const [loadingPayload, setLoadingPayload] = useState(false);

  const showPayload = async () => {
    setLoadingPayload(true);
    try {
      const res = await fetch("/api/enrolment/last-payload");
      const text = await res.text();
      try {
        setPayload(JSON.stringify(JSON.parse(text), null, 2));
      } catch {
        setPayload(text);
      }
    } finally {
      setLoadingPayload(false);
    }
  };

  const st = status.data;
  return (
    <ChartShell
      title={<TitleWithHelp text="Teams sharing" helpId="card.privacy_org_push" />}
      sub="What (if anything) leaves this machine for an org server"
    >
      {!st?.enrolled ? (
        <p className="py-3 text-[12px] text-fg-2">
          Not enrolled in any org - nothing is shared, ever. Enrolment is an
          explicit <span className="font-mono text-[11px]">observer enroll</span>{" "}
          action; until then the observer has no outbound channel at all.
        </p>
      ) : (
        <div className="space-y-2 text-[12px]">
          <div className="flex flex-wrap items-center gap-1.5">
            <Pill variant="info">enrolled</Pill>
            <span className="text-fg-2">
              {st.org_name ?? "org"} · {st.org_server_url}
            </span>
            {st.last_push && (
              <span className="text-[11px] text-fg-3">
                last push {st.last_push.status} · {fmtInt(st.last_push.row_count)}{" "}
                rows · {fmtBytes(st.last_push.bytes)} · {fmtDateTime(st.last_push.pushed_at)}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={loadingPayload}
              onClick={() => void showPayload()}
              className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-2 hover:bg-bg-3"
            >
              {loadingPayload ? "loading…" : payload ? "refresh payload view" : "show exactly what was last sent"}
            </button>
            <Link
              to="/settings?section=org"
              className="text-[11px] font-medium text-accent hover:text-accent-strong"
            >
              Share-mode settings →
            </Link>
          </div>
          {payload && (
            <pre className="max-h-64 overflow-auto rounded-2 border border-line-1 bg-bg-1 p-2.5 font-mono text-[10.5px] leading-relaxed text-fg-2">
              {payload}
            </pre>
          )}
        </div>
      )}
    </ChartShell>
  );
}
