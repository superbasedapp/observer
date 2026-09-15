import { type ReactNode } from "react";
import { HeroStat, PageHeader, Pill } from "@/components/primitives";
import { CompassIcon } from "@/components/icons";
import { useApi } from "@/lib/useApi";
import { ApiError } from "@/lib/api";
import { fmtClock, fmtInt, fmtShortId } from "@/lib/format";

// Egress page (G22 Plane-A policy egress routing): the read-only node surface
// over the installed [observability.egress] policy and the NODE-LOCAL
// obs_egress_decisions audit log — the decision half (rule / action / verdict)
// plus the realized outcome the proxy reported back (applied / fail_closed /
// realized_outcome). Everything renders VERBATIM from the store; this page
// computes nothing. The data never rides the org push (design §8: no org
// tier), so this node view — like `observer obs egress` — is the ONLY place
// the audit log is viewable. Distinct from the Security page's Plane-B guard
// (the developer's own coding-agent tool calls); this governs a hosted app's
// end-user traffic.

type EgressRule = {
  name: string;
  action: string;
  target?: string;
  reason_code: string;
  on_unavailable: string;
  pinned: boolean;
};
type EgressTarget = { id: string; url: string; shape: string };
type EgressChain = { rows: number; ok: boolean; detail?: string };
type EgressStatus = {
  enabled: boolean;
  mode: string;
  policy_hash?: string;
  rules: EgressRule[] | null;
  targets: EgressTarget[] | null;
  decisions_by_action: Record<string, number>;
  decisions_24h: number;
  chain: EgressChain;
};
type EgressDecision = {
  id: number;
  ts: string;
  mode: string;
  rule_name: string;
  policy_hash: string;
  action: string;
  upstream_id?: string;
  target_shape?: string;
  model_from?: string;
  model_to?: string;
  effort?: string;
  reason_code: string;
  must_use_target: boolean;
  applied: boolean;
  fail_closed: boolean;
  switch_held: boolean;
  realized_outcome?: string;
  degraded?: string;
  verdict_decision?: string;
  criterion_id?: string;
  request_id?: string;
  session_id?: string;
  user?: string;
};
type DecisionsResponse = { decisions: EgressDecision[] | null };

// outcomeVariant maps the proxy's closed realized-outcome vocabulary to a
// Pill tone. Unknown labels render neutral — never invented.
function outcomeVariant(o: string): "success" | "warn" | "danger" | "neutral" | "info" {
  switch (o) {
    case "applied":
      return "success";
    case "fail_closed":
    case "breaker_open":
    case "upstream_error":
      return "danger";
    case "fallback_open":
    case "splice_failed":
      return "warn";
    default:
      return "neutral";
  }
}

function verdictVariant(d: string): "success" | "warn" | "info" | "danger" | "neutral" {
  switch (d) {
    case "allow":
      return "success";
    case "flag":
      return "warn";
    case "ask":
      return "info";
    case "deny":
      return "danger";
    default:
      return "neutral";
  }
}

export function EgressPage() {
  const status = useApi<EgressStatus>("/api/obs/egress/status");
  const decisions = useApi<DecisionsResponse>("/api/obs/egress/decisions", { limit: 200 });

  // The /api/obs/* routes are registered only when [observability] is
  // enabled. When they are absent, the dashboard's SPA catch-all serves the
  // index.html shell with a 200 — so "obs off" manifests as a JSON parse
  // error (a non-ApiError), or as a 404 from an older/stricter mux. A real
  // handler failure is an ApiError with a 5xx and renders as an error below.
  const obsOff = [status.error, decisions.error].some(
    (e) => e != null && (!(e instanceof ApiError) || e.status === 404),
  );

  const st = status.data;
  const rows = decisions.data?.decisions ?? [];
  const totalDecisions = st
    ? Object.values(st.decisions_by_action).reduce((a, n) => a + n, 0)
    : 0;

  return (
    <div className="space-y-4 p-5">
      <PageHeader
        title="Egress"
        sub="Plane-A policy egress routing: route a hosted app's end-user requests to another resource by admission verdict, end-user budget, or cohort. This audit log is node-local - it never rides the org push - so this page (and observer obs egress) is its only view. Read-only; policy is authored in config.toml."
      />
      {obsOff ? (
        <ObsDisabled />
      ) : status.error ? (
        <ErrorNote label="status" error={status.error} />
      ) : (
        <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <HeroStat
              label="Mode"
              icon={<CompassIcon />}
              loading={status.loading}
              variant={st?.mode === "enforce" ? "warn" : "accent"}
              value={st ? st.mode : "-"}
              sub={
                st?.enabled
                  ? st.policy_hash
                    ? <span title={st.policy_hash}>{`policy ${fmtShortId(st.policy_hash, 12)}`}</span>
                    : "policy installed"
                  : "no egress policy installed"
              }
            />
            <HeroStat
              label="Rules / targets"
              loading={status.loading}
              value={st ? `${(st.rules ?? []).length} / ${(st.targets ?? []).length}` : "-"}
              sub="first-match-wins · typed targets"
            />
            <HeroStat
              label="Decisions"
              loading={status.loading}
              value={st ? fmtInt(totalDecisions) : "-"}
              sub={st ? `${fmtInt(st.decisions_24h)} in the last 24h` : ""}
            />
            <HeroStat
              label="Audit chain"
              loading={status.loading}
              variant={st && !st.chain.ok ? "danger" : "accent"}
              value={st ? (st.chain.ok ? "intact" : "BROKEN") : "-"}
              sub={
                st
                  ? st.chain.ok
                    ? `${fmtInt(st.chain.rows)} hash-chained rows`
                    : (st.chain.detail ?? "verification failed")
                  : ""
              }
            />
          </div>

          {st && !st.enabled && <EgressDisabled />}

          {st && st.enabled && (
            <Section
              title="Policy"
              sub="The installed (compiled) policy - authored node-side in [observability.egress]; there is no dashboard write path."
            >
              <PolicyTables rules={st.rules ?? []} targets={st.targets ?? []} />
            </Section>
          )}

          <Section
            title="Decisions"
            sub="Newest first. Each row is the immutable decision plus the realized outcome the proxy reported back after the forward."
          >
            {decisions.loading ? (
              <Loading />
            ) : decisions.error ? (
              <ErrorNote label="decisions" error={decisions.error} />
            ) : rows.length === 0 ? (
              <DecisionsEmpty enabled={!!st?.enabled} mode={st?.mode ?? "off"} />
            ) : (
              <DecisionsTable rows={rows} />
            )}
          </Section>
        </>
      )}
    </div>
  );
}

function PolicyTables({ rules, targets }: { rules: EgressRule[]; targets: EgressTarget[] }) {
  return (
    <div className="space-y-4">
      {rules.length === 0 ? (
        <p className="py-2 text-[12px] text-fg-3">
          No rules - add <code className="rounded-1 bg-bg-2 px-1 font-mono">[[observability.egress.rules]]</code>{" "}
          entries to config.toml.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[12px]">
            <thead>
              <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                <th className="py-1.5 pr-3 font-semibold">Rule</th>
                <th className="py-1.5 pr-3 font-semibold">Action</th>
                <th className="py-1.5 pr-3 font-semibold">Target</th>
                <th className="py-1.5 pr-3 font-semibold">On unavailable</th>
                <th className="py-1.5 font-semibold">Reason code</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.name} className="border-b border-line-1/60">
                  <td className="py-1.5 pr-3 font-semibold text-fg-1">{r.name}</td>
                  <td className="py-1.5 pr-3 font-mono text-[11px] text-fg-2">{r.action}</td>
                  <td className="py-1.5 pr-3 font-mono text-[11px] text-fg-2">{r.target || "-"}</td>
                  <td className="py-1.5 pr-3">
                    <Pill variant={r.on_unavailable === "deny" ? "danger" : "neutral"}>
                      {r.on_unavailable}
                    </Pill>
                    {r.pinned && (
                      <Pill
                        variant="warn"
                        className="ml-1"
                        title="Proxy-pinned: retries never substitute another target; if the target is unavailable the request fails CLOSED (provider-shaped 403), never leaking to the default upstream."
                      >
                        pinned
                      </Pill>
                    )}
                  </td>
                  <td className="py-1.5 font-mono text-[11px] text-fg-3">{r.reason_code}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {targets.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[12px]">
            <thead>
              <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                <th className="py-1.5 pr-3 font-semibold">Typed target</th>
                <th className="py-1.5 pr-3 font-semibold">Shape</th>
                <th className="py-1.5 font-semibold">URL</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((tg) => (
                <tr key={tg.id} className="border-b border-line-1/60">
                  <td className="py-1.5 pr-3 font-semibold text-fg-1">{tg.id}</td>
                  <td className="py-1.5 pr-3">
                    <Pill variant="info">{tg.shape}</Pill>
                  </td>
                  <td className="py-1.5 font-mono text-[11px] text-fg-3">{tg.url}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function DecisionsTable({ rows }: { rows: EgressDecision[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[12px]">
        <thead>
          <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
            <th className="py-1.5 pr-3 font-semibold">When</th>
            <th className="py-1.5 pr-3 font-semibold">Mode</th>
            <th className="py-1.5 pr-3 font-semibold">Rule</th>
            <th className="py-1.5 pr-3 font-semibold">Action</th>
            <th className="py-1.5 pr-3 font-semibold">Verdict</th>
            <th className="py-1.5 pr-3 font-semibold">Realized</th>
            <th className="py-1.5 pr-3 font-semibold">Request</th>
            <th className="py-1.5 font-semibold">End-user</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((d) => (
            <tr key={d.id} className="border-b border-line-1/60">
              <td className="whitespace-nowrap py-1.5 pr-3 text-fg-3">
                {fmtClock(d.ts)}
              </td>
              <td className="py-1.5 pr-3">
                <Pill variant={d.mode === "enforce" ? "warn" : "neutral"}>{d.mode}</Pill>
              </td>
              <td className="py-1.5 pr-3 font-semibold text-fg-1">{d.rule_name}</td>
              <td className="py-1.5 pr-3 font-mono text-[11px] text-fg-2">
                {d.action}
                {actionDetail(d) && <span className="text-fg-3"> {actionDetail(d)}</span>}
                {d.must_use_target && (
                  <Pill variant="warn" className="ml-1">
                    pinned
                  </Pill>
                )}
                {d.switch_held && (
                  <Pill variant="neutral" className="ml-1">
                    held
                  </Pill>
                )}
              </td>
              <td className="py-1.5 pr-3">
                {d.verdict_decision ? (
                  <Pill variant={verdictVariant(d.verdict_decision)}>{d.verdict_decision}</Pill>
                ) : (
                  <span className="text-fg-3">-</span>
                )}
              </td>
              <td className="py-1.5 pr-3">
                <RealizedCell d={d} />
              </td>
              <td className="py-1.5 pr-3 font-mono text-[10px] text-fg-3" title={d.request_id || undefined}>
                {d.request_id ? fmtShortId(d.request_id, 12) : "-"}
              </td>
              <td className="py-1.5 font-mono text-[11px] text-fg-3">{d.user || "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// actionDetail renders the action's operator-config operand verbatim.
function actionDetail(d: EgressDecision): string {
  if (d.upstream_id) return `→ ${d.upstream_id}`;
  if (d.model_to) return `${d.model_from || "?"} → ${d.model_to}`;
  if (d.effort) return `→ ${d.effort}`;
  return "";
}

// RealizedCell renders the proxy-reported outcome VERBATIM, or an honest
// pending dash when the proxy has not (yet) reported one — advise-mode rows
// are never routed, so they legitimately stay unreported.
function RealizedCell({ d }: { d: EgressDecision }) {
  if (!d.realized_outcome) {
    return (
      <span className="text-fg-3" title="No realized outcome reported - advise-mode decisions are recorded but never routed, so the proxy reports nothing back.">
        -
      </span>
    );
  }
  return (
    <>
      <Pill variant={outcomeVariant(d.realized_outcome)}>{d.realized_outcome}</Pill>
      {d.fail_closed && d.realized_outcome !== "fail_closed" && (
        <Pill variant="danger" className="ml-1">
          fail-closed
        </Pill>
      )}
    </>
  );
}

// --- empty / error states ---------------------------------------------------

// ObsDisabled names the exact missing dependency: the /api/obs/* routes are
// registered into this dashboard only when [observability] is enabled.
function ObsDisabled() {
  return (
    <EmptyCard title="Observability is off">
      <p>
        Egress routing rides the observability subsystem, and its API routes are not registered.
        Enable it in <code className="rounded-1 bg-bg-2 px-1 font-mono">~/.observer/config.toml</code>:
      </p>
      <pre className="mt-2 inline-block rounded-2 bg-bg-2 px-3 py-2 text-left font-mono text-[11px] text-fg-2">
        {"[observability]\nenabled = true"}
      </pre>
      <p className="mt-2">then restart the daemon.</p>
    </EmptyCard>
  );
}

// EgressDisabled names the exact gate: [observability.egress] enabled (and its
// admission dependency — egress composes on the admission verdict).
function EgressDisabled() {
  return (
    <EmptyCard title="No egress policy installed">
      <p>
        Egress is default-off. It needs{" "}
        <code className="rounded-1 bg-bg-2 px-1 font-mono">[observability.egress] enabled = true</code>{" "}
        plus at least one rule, and{" "}
        <code className="rounded-1 bg-bg-2 px-1 font-mono">[observability.admission] enabled = true</code>{" "}
        - egress composes on the admission verdict. A policy that fails to compile is also reported
        here as not installed (the daemon logs the compile error and keeps admission running).
      </p>
      <p className="mt-2">
        Validate with <code className="rounded-1 bg-bg-2 px-1 font-mono">observer obs egress lint</code>.
      </p>
    </EmptyCard>
  );
}

function DecisionsEmpty({ enabled, mode }: { enabled: boolean; mode: string }) {
  return (
    <div className="py-8 text-center text-[12px] leading-relaxed text-fg-3">
      <p className="text-[13px] font-semibold text-fg-2">No egress decisions recorded</p>
      {enabled ? (
        <p className="mt-1">
          The policy is installed in <b>{mode}</b> mode. A row appears when an admission-judged
          request matches a rule - {mode === "advise" ? "advise records the directive without applying it" : "enforce applies it on the proxy path and reports the realized outcome back"}.
        </p>
      ) : (
        <p className="mt-1">Decisions are recorded only while an egress policy is installed.</p>
      )}
    </div>
  );
}

function ErrorNote({ label, error }: { label: string; error: Error }) {
  return (
    <div className="rounded-3 border border-danger/30 bg-danger-soft p-4 text-[12px] text-danger">
      egress {label}: {error.message}
    </div>
  );
}

function EmptyCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-3 border border-line-1 bg-bg-1 p-8 text-center text-[12px] leading-relaxed text-fg-3">
      <p className="mb-2 text-[13px] font-semibold text-fg-2">{title}</p>
      <div className="mx-auto max-w-xl">{children}</div>
    </div>
  );
}

function Loading() {
  return (
    <div className="flex items-center gap-2 py-6 text-[12px] text-fg-3">
      <span className="inline-block h-3 w-3 animate-spin rounded-full border border-line-3 border-t-accent" />
      Loading…
    </div>
  );
}

function Section({
  title,
  sub,
  children,
}: {
  title: ReactNode;
  sub?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-3 border border-line-1 bg-bg-1 p-4">
      <div className="mb-3">
        <h2 className="text-[13px] font-bold text-fg-0">{title}</h2>
        {sub && <p className="mt-0.5 text-[11.5px] text-fg-3">{sub}</p>}
      </div>
      {children}
    </section>
  );
}
