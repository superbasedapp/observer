import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ListChecks } from "lucide-react";
import {
  ChartShell,
  ConfirmButton,
  InlineLoading,
  SegmentedControl,
  Table,
  ToolBadge,
  Tooltip,
} from "@/components/primitives";
import { TitleWithHelp } from "@/components/HelpInd";
import { StatusTile } from "@/components/security/StatusTile";
import { useApi } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";
import { fmtDateTime } from "@/lib/format";
import { CHECK_STATUS } from "@/lib/vocabTones";
import { VocabPill } from "@shared/lib/vocabPill";
import type { Tone } from "@shared/lib/tone";
import {
  HookCapabilityMatrix,
  HookCapabilityMatrixLegend,
  HookCapabilitySummary,
} from "@shared/primitives/HookCapabilityMatrix";
import {
  hookRowGateWired,
  hookRowHasVendorSurface,
  hookRowObserverWired,
  type HookMatrixRow,
  type HookMatrixView,
} from "@shared/lib/hookMatrix";

// HookCoverageCard - the node Security page's hook capability coverage
// (hook-parity Lane G): the matrix generated from the registry's hook
// bindings (`observer adapters --hooks`), the node's guard posture as a hook
// reads it, the gate hook failures the daemon recorded (fail-closed blocks
// and fail-open passes, T-049), and the dashboard face of `observer doctor
// --hooks <tool>` (Doctor) and `observer doctor --hooks --probe-hook <tool>`
// (Probe gates). Probing records one guard verdict per wired gate, so it is
// a confirmed action carrying the confirm token.

type HookFailure = { tool: string; outcome: string; kind: string; count: number; last_at?: string };

// hookSetupLink opens the tool's Set up wizard in Settings > Connected tools (the
// /api/setup/hooks and /api/setup/codex-hooks writers), the dashboard twin of
// the `observer init --<tool>` a doctor message names (cli-parity L4).
function hookSetupLink(tool: string): string {
  return `/settings?section=tools&tool=${encodeURIComponent(tool)}&open=setup`;
}

type HookPosture = {
  state: string;
  detail?: string;
  enforced: boolean;
  gate_caps: string[];
  source?: string;
  generation?: string;
  written_at?: string;
};

type HookCoverage = {
  matrix: HookMatrixView;
  posture: HookPosture;
  failures: HookFailure[] | null;
  window_hours: number;
  confirm_token?: string;
};

type DoctorCheck = { name: string; status: string; message: string; details?: string[] | null };

type DoctorResult = { tool: string; action: "doctor" | "probe"; checks: DoctorCheck[] };

// POSTURE_STATE - the posture tile per state: a valid posture is what hooks
// follow; stale means hooks fall back to config + bundle; tampered is a
// guard_error; absent means no daemon published one.
const POSTURE_STATE: Readonly<Record<string, { tone: Tone; sub: string }>> = {
  valid: { tone: "success", sub: "signed by the daemon and fresh; hooks follow it" },
  stale: { tone: "warn", sub: "older than its freshness window or the config; hooks re-derive from config + org bundle" },
  tampered: { tone: "danger", sub: "the signature does not verify; hooks fail closed on wired gates" },
  absent: { tone: "neutral", sub: "no daemon has published a posture; hooks follow the config" },
};

// The gate capabilities a probe can exercise (doctor --probe-hook --gate).
const PROBE_GATE_CAPS = ["tool_gate", "prompt_gate"] as const;

type RowFilter = "observer" | "vendor" | "all";

// ROW_FILTERS - which rows the matrix shows; the predicate lives here, the
// per-row facts come from the generated view.
const ROW_FILTERS: ReadonlyArray<{ value: RowFilter; label: string; keep: (r: HookMatrixRow) => boolean }> = [
  { value: "observer", label: "Observer-registered", keep: hookRowObserverWired },
  { value: "vendor", label: "Vendor has hooks", keep: hookRowHasVendorSurface },
  { value: "all", label: "All tools", keep: () => true },
];

// CHECK_ORDER - result rows that need attention first: the per-tool summary
// stays on top, then fail, warn, ok, each in the doctor's own order.
const CHECK_ORDER: Readonly<Record<string, number>> = { fail: 0, warn: 1, ok: 2 };

function orderChecks(checks: DoctorCheck[]): DoctorCheck[] {
  const rank = (c: DoctorCheck) => (c.name.startsWith("hook.bindings:") ? -1 : (CHECK_ORDER[c.status] ?? 1));
  return checks
    .map((c, i) => ({ c, i }))
    .sort((a, b) => rank(a.c) - rank(b.c) || a.i - b.i)
    .map((x) => x.c);
}

const actionBtn =
  "rounded-2 border border-line-2 bg-bg-3 px-2 py-0.5 text-caption text-fg-1 hover:border-line-3 hover:text-fg-0 disabled:opacity-50";

export function HookCoverageCard() {
  const api = useApi<HookCoverage>("/api/guard/hook-coverage", { hours: 168 });
  const [filter, setFilter] = useState<RowFilter>("observer");
  const [running, setRunning] = useState<string>("");
  const [err, setErr] = useState("");
  const [result, setResult] = useState<DoctorResult | null>(null);

  const data = api.data;
  const rows = useMemo(() => {
    const keep = ROW_FILTERS.find((f) => f.value === filter)?.keep ?? (() => true);
    return (data?.matrix.rows ?? []).filter(keep);
  }, [data, filter]);

  const failures = data?.failures ?? [];
  const failClosed = failures.filter((f) => f.outcome === "fail_closed").reduce((n, f) => n + f.count, 0);
  const failOpen = failures.filter((f) => f.outcome === "fail_open").reduce((n, f) => n + f.count, 0);
  const posture = data?.posture;
  const postureView = posture ? (POSTURE_STATE[posture.state] ?? { tone: "neutral" as Tone, sub: posture.state }) : null;

  const run = async (tool: string, action: "doctor" | "probe") => {
    setRunning(`${action}:${tool}`);
    setErr("");
    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (action === "probe" && data?.confirm_token) headers["X-Observer-Confirm"] = data.confirm_token;
      const res = await fetchJSON<{ checks: DoctorCheck[] | null }>(
        action === "probe" ? "/api/guard/hook-probe" : "/api/guard/hook-doctor",
        undefined,
        { method: "POST", headers, body: JSON.stringify({ tool, gate: "all" }) },
      );
      setResult({ tool, action, checks: res.checks ?? [] });
      if (action === "probe") api.reload();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning("");
    }
  };

  const trailing = (row: HookMatrixRow) => {
    const probeable = hookRowGateWired(row, PROBE_GATE_CAPS);
    const registered = hookRowObserverWired(row);
    return (
      <div className="flex items-center justify-end gap-1.5">
        <Tooltip content="Check each binding on this machine: registered in the tool's config, trusted, probe state (observer doctor --hooks)">
          <button
            type="button"
            className={actionBtn}
            disabled={running !== "" || !registered}
            onClick={() => run(row.tool, "doctor")}
          >
            {running === `doctor:${row.tool}` ? "Checking…" : "Doctor"}
          </button>
        </Tooltip>
        {probeable && (
          <ConfirmButton
            size="sm"
            variant="secondary"
            disabled={running !== ""}
            loading={running === `probe:${row.tool}`}
            confirmLabel="Run probe?"
            title="Fire a synthetic call at a fake path through each wired gate and check it blocked; records one guard verdict per gate (observer doctor --hooks --probe-hook)"
            onConfirm={() => run(row.tool, "probe")}
          >
            Probe gates
          </ConfirmButton>
        )}
      </div>
    );
  };

  return (
    <ChartShell
      title={<TitleWithHelp text="Hook capability coverage" helpId="card.security_hook_coverage" />}
      icon={ListChecks}
      sub={
        <>
          What each tool's hook surface offers per capability and what Observer registers on it,
          generated from the registry's hook bindings. Doctor checks the bindings on this machine;
          Probe gates fires a synthetic call at a fake path through each wired gate.
        </>
      }
      right={
        <SegmentedControl<RowFilter>
          size="sm"
          options={ROW_FILTERS.map((f) => ({ value: f.value, label: f.label }))}
          value={filter}
          onChange={setFilter}
        />
      }
      updating={api.isRefreshing}
    >
      {api.loading && !data ? (
        <InlineLoading label="Loading hook coverage" block />
      ) : api.error && !data ? (
        <div className="text-[11.5px] text-danger">{api.error.message}</div>
      ) : data ? (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {posture && postureView && (
              <StatusTile
                label="Guard posture"
                value={posture.state}
                tone={postureView.tone}
                sub={posture.detail || postureView.sub}
              />
            )}
            <StatusTile
              label="Gates enforce"
              value={posture?.state === "valid" ? (posture.enforced ? "yes" : "no") : "per config"}
              tone={posture?.enforced ? "accent" : "neutral"}
              sub={posture?.gate_caps.length ? `gate capabilities: ${posture.gate_caps.join(", ")}` : "no gate capability enforced"}
            />
            <StatusTile
              label={`Blocked on failure (${data.window_hours / 24}d)`}
              value={String(failClosed)}
              tone={failClosed > 0 ? "danger" : "neutral"}
              sub="a wired gate hook failed under enforcement and the call was refused (fail closed)"
            />
            <StatusTile
              label={`Passed on failure (${data.window_hours / 24}d)`}
              value={String(failOpen)}
              tone={failOpen > 0 ? "warn" : "neutral"}
              sub="a wired gate hook failed and the call went ahead unchecked (fail open)"
            />
          </div>

          {err && <div className="text-[11.5px] text-danger">{err}</div>}

          {result && (
            <div className="rounded-2 border border-line-2 bg-bg-3 p-3">
              <div className="mb-2 flex items-center justify-between gap-2">
                <div className="text-caption font-semibold uppercase tracking-[0.06em] text-fg-2">
                  {result.action === "probe" ? "Probe" : "Doctor"} · {result.tool}
                </div>
                <button type="button" className={actionBtn} onClick={() => setResult(null)}>
                  Dismiss
                </button>
              </div>
              {result.checks.length === 0 ? (
                <div className="text-[11.5px] text-fg-3">No checks returned.</div>
              ) : (
                <ul className="max-h-[320px] space-y-1 overflow-y-auto text-[11.5px]">
                  {orderChecks(result.checks).map((c) => (
                    <li key={c.name} className="flex min-w-0 items-start gap-2">
                      <VocabPill vocab="healthCheck" table={CHECK_STATUS} value={c.status} />
                      <span className="min-w-0 break-words text-fg-2">
                        <span className="font-mono text-[10.5px] text-fg-3">{c.name}</span> {c.message}
                        {c.status !== "ok" &&
                          (c.details ?? [])
                            .filter((d) => !d.startsWith("grounding:"))
                            .map((d) => (
                              <span key={d} className="block text-[11px] text-fg-3">
                                {d}
                              </span>
                            ))}
                        {c.status !== "ok" && (
                          // The doctor's message names the CLI twin (`observer
                          // init --<tool>`); the dashboard's hook registration
                          // is the tool's Set up wizard in Settings > Connected tools.
                          <Link
                            to={hookSetupLink(result.tool)}
                            className="mt-0.5 block text-[11px] text-accent hover:underline"
                          >
                            Fix in Setup
                          </Link>
                        )}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          <HookCapabilityMatrix matrix={data.matrix} rows={rows} trailing={trailing} trailingHead="Check" maxHeight={560} />
          <HookCapabilityMatrixLegend />

          {failures.length > 0 && (
            <div>
              <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-2">
                Gate hook failures (last {data.window_hours / 24} days)
              </div>
              <Table
                minWidth={520}
                head={
                  <tr>
                    <th className="py-1.5 pr-3 font-medium">Tool</th>
                    <th className="py-1.5 pr-3 font-medium">Outcome</th>
                    <th className="py-1.5 pr-3 font-medium">Failure</th>
                    <th className="py-1.5 pr-3 text-right font-medium">Count</th>
                    <th className="py-1.5 font-medium">Last</th>
                  </tr>
                }
              >
                {failures.map((f) => (
                  <tr key={`${f.tool}/${f.outcome}/${f.kind}`} className="border-b border-line-1/60 last:border-0">
                    <td className="py-1.5 pr-3">
                      <ToolBadge tool={f.tool} />
                    </td>
                    <td className="py-1.5 pr-3">
                      <span className={f.outcome === "fail_closed" ? "text-danger" : "text-warn"}>
                        {f.outcome === "fail_closed" ? "blocked" : "passed unchecked"}
                      </span>
                    </td>
                    <td className="py-1.5 pr-3 text-fg-2">{f.kind}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums text-fg-1">{f.count}</td>
                    <td className="whitespace-nowrap py-1.5 text-fg-3">{f.last_at ? fmtDateTime(f.last_at) : "-"}</td>
                  </tr>
                ))}
              </Table>
            </div>
          )}

          <details className="group">
            <summary className="cursor-pointer text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-2">
              Per capability, over every registry tool
            </summary>
            <div className="mt-2">
              <HookCapabilitySummary matrix={data.matrix} />
            </div>
          </details>
        </div>
      ) : null}
    </ChartShell>
  );
}
