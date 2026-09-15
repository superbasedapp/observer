import { useState } from "react";
import { ChartShell, Pill } from "@/components/primitives";
import { TitleWithHelp } from "@/components/HelpInd";
import { useApi } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";
import { fmtCompact, fmtInt, fmtUSD } from "@/lib/format";
import type {
  ConfigResponse,
  ExperimentDef,
  ExperimentReportResponse,
} from "@/lib/types";

// ExperimentsCard — productized profile A/B (P6.4), on the
// Compression page where the evidence lives. Start/stop write
// [[experiments]] through the dashboard API (shared config-write
// owner + hot reload); reports recompute arm membership from the
// session hash, so the numbers here and `observer experiment report`
// can never disagree.
export function ExperimentsCard() {
  const list = useApi<{ experiments: ExperimentDef[] }>("/api/experiments");
  const [showStart, setShowStart] = useState(false);
  const [reportFor, setReportFor] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const exps = list.data?.experiments ?? [];
  const stop = async (name: string) => {
    setError(null);
    try {
      await fetchJSON("/api/experiments/stop", undefined, {
        method: "POST",
        body: JSON.stringify({ name }),
      });
      list.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <ChartShell
      title={<TitleWithHelp text="Profile experiments" helpId="card.experiments" />}
      sub="A/B two profiles on one traffic class - sessions split by hash, both arms live simultaneously"
      right={
        <button
          type="button"
          onClick={() => setShowStart((s) => !s)}
          className="rounded-2 border border-line-2 bg-bg-2 px-2 py-0.5 text-[11px] text-fg-2 hover:bg-bg-3"
        >
          {showStart ? "close" : "new experiment"}
        </button>
      }
    >
      {error && <p className="mb-2 text-[11px] text-danger">{error}</p>}
      {showStart && (
        <StartForm
          onStarted={() => {
            setShowStart(false);
            list.reload();
          }}
        />
      )}
      {exps.length === 0 && !showStart ? (
        <p className="py-3 text-center text-[12px] text-fg-3">
          No experiments yet. Try a candidate profile against its control on
          live traffic - the report gives $/session, CV, turns, cache causes,
          and compression savings per arm.
        </p>
      ) : (
        <ul className="space-y-2">
          {exps.map((e) => (
            <li key={e.name} className="rounded-2 border border-line-1 p-2.5">
              <div className="flex flex-wrap items-center gap-2 text-[12px]">
                <span className="font-mono font-medium text-fg-1">{e.name}</span>
                <Pill variant={!e.stopped_at ? "success" : "neutral"}>
                  {!e.stopped_at ? "running" : "stopped"}
                </Pill>
                <Pill>{e.class}</Pill>
                <span className="text-[11px] text-fg-3">
                  {e.control} vs {e.candidate}
                </span>
                <span className="flex-1" />
                <button
                  type="button"
                  onClick={() =>
                    setReportFor(reportFor === e.name ? null : e.name)
                  }
                  className="rounded-2 border border-line-2 bg-bg-2 px-2 py-0.5 text-[10.5px] text-fg-2 hover:bg-bg-3"
                >
                  {reportFor === e.name ? "hide report" : "report"}
                </button>
                {!e.stopped_at && (
                  <button
                    type="button"
                    onClick={() => void stop(e.name)}
                    className="rounded-2 border border-warn/40 bg-warn-soft px-2 py-0.5 text-[10.5px] text-warn hover:opacity-80"
                  >
                    stop
                  </button>
                )}
              </div>
              {e.note && (
                <p className="mt-1 text-[11px] text-fg-3">{e.note}</p>
              )}
              {reportFor === e.name && <ReportView name={e.name} />}
            </li>
          ))}
        </ul>
      )}
    </ChartShell>
  );
}

function StartForm({ onStarted }: { onStarted: () => void }) {
  const cfg = useApi<ConfigResponse>("/api/config");
  const [name, setName] = useState("");
  const [klass, setKlass] = useState("anthropic");
  const [toolName, setToolName] = useState("");
  const [control, setControl] = useState("");
  const [candidate, setCandidate] = useState("");
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const profiles = cfg.data?.profile_names ?? [];

  const start = async () => {
    setSaving(true);
    setError(null);
    try {
      await fetchJSON("/api/experiments", undefined, {
        method: "POST",
        body: JSON.stringify({
          name,
          class: klass === "tool" ? `tool:${toolName}` : klass,
          control,
          candidate,
          note,
        }),
      });
      onStarted();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  const sel =
    "rounded-2 border border-line-2 bg-bg-1 px-2 py-1 text-[11.5px] text-fg-1 outline-none focus:border-accent/60";
  return (
    <div className="mb-3 space-y-2 rounded-2 border border-line-1 bg-bg-1 p-3 text-[12px]">
      <div className="flex flex-wrap items-center gap-2">
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="experiment-name"
          className={sel + " font-mono"}
        />
        <select value={klass} onChange={(e) => setKlass(e.target.value)} className={sel}>
          <option value="anthropic">anthropic traffic</option>
          <option value="openai">openai traffic</option>
          <option value="tool">one tool…</option>
        </select>
        {klass === "tool" && (
          <input
            value={toolName}
            onChange={(e) => setToolName(e.target.value)}
            placeholder="tool name (e.g. cline)"
            className={sel + " font-mono"}
          />
        )}
        <select value={control} onChange={(e) => setControl(e.target.value)} className={sel}>
          <option value="">control profile…</option>
          {profiles.map((p) => (
            <option key={p}>{p}</option>
          ))}
        </select>
        <select value={candidate} onChange={(e) => setCandidate(e.target.value)} className={sel}>
          <option value="">candidate profile…</option>
          {profiles.map((p) => (
            <option key={p}>{p}</option>
          ))}
        </select>
      </div>
      <input
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="note (what question is this answering?)"
        className={sel + " w-full"}
      />
      {error && <p className="text-[11px] text-danger">{error}</p>}
      <div className="flex items-center justify-between gap-2">
        <span className="text-[10.5px] text-fg-3">
          Sessions split deterministically by hash; new sessions enter
          immediately, in-flight ones keep their parameters. One running
          experiment per class.
        </span>
        <button
          type="button"
          disabled={saving || !name || !control || !candidate}
          onClick={() => void start()}
          className="shrink-0 rounded-2 border border-accent/40 bg-accent-soft px-3 py-1 text-[11px] font-medium text-accent disabled:opacity-50"
        >
          {saving ? "starting…" : "start experiment"}
        </button>
      </div>
    </div>
  );
}

function ReportView({ name }: { name: string }) {
  const rep = useApi<ExperimentReportResponse>(
    "/api/experiments/report",
    { name },
    [name],
  );
  if (rep.loading) {
    return <p className="mt-2 text-[11px] text-fg-3">computing report…</p>;
  }
  if (rep.error || !rep.data) {
    return (
      <p className="mt-2 text-[11px] text-danger">
        {rep.error?.message ?? "report unavailable"}
      </p>
    );
  }
  const r = rep.data;
  return (
    <div className="mt-2 space-y-2 border-t border-line-1 pt-2">
      <table className="w-full text-left text-[11.5px]">
        <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
          <tr>
            <th className="py-1 font-medium">Arm</th>
            <th className="py-1 font-medium">Profile</th>
            <th className="py-1 text-right font-medium">Sessions</th>
            <th className="py-1 text-right font-medium">Mean $</th>
            <th className="py-1 text-right font-medium">CV</th>
            <th className="py-1 text-right font-medium">Turns</th>
            <th className="py-1 text-right font-medium">Cache r/w</th>
            <th className="py-1 text-right font-medium">Comp. saved</th>
          </tr>
        </thead>
        <tbody>
          {[r.control, r.candidate].map((a) => (
            <tr key={a.arm} className="border-t border-line-1">
              <td className="py-1">{a.arm}</td>
              <td className="py-1 font-mono text-[10.5px]">{a.profile}</td>
              <td className="py-1 text-right tabular-nums">{fmtInt(a.sessions)}</td>
              <td className="py-1 text-right tabular-nums">{fmtUSD(a.mean_cost_usd)}</td>
              <td className="py-1 text-right tabular-nums">
                {a.sessions >= 2 ? a.cv_pct.toFixed(1) + "%" : "-"}
              </td>
              <td className="py-1 text-right tabular-nums">{a.mean_turns.toFixed(1)}</td>
              <td className="py-1 text-right tabular-nums">
                {a.cache_write_tokens > 0
                  ? (a.cache_read_tokens / a.cache_write_tokens).toFixed(1) + "×"
                  : "-"}
              </td>
              <td
                className="py-1 text-right tabular-nums"
                title="Genuine, retrievable compression only. Lossy-evicted (dropped) bytes are excluded and shown separately; that content stays recoverable via search_past_outputs markers."
              >
                {fmtCompact(a.compression_saved_bytes)}B
                {(a.compression_evicted_bytes ?? 0) > 0 && (
                  <span className="block text-[10px] text-fg-3">
                    +{fmtCompact(a.compression_evicted_bytes ?? 0)}B evicted
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {r.control.sessions > 0 && r.candidate.sessions > 0 && (
        <p className="text-[11px] text-fg-2">
          candidate vs control:{" "}
          <span className="font-medium tabular-nums">
            {r.delta_cost_pct > 0 ? "+" : ""}
            {r.delta_cost_pct.toFixed(1)}% $/session
          </span>
          {" · "}
          <span className="tabular-nums">
            {r.delta_turns_pct > 0 ? "+" : ""}
            {r.delta_turns_pct.toFixed(1)}% turns
          </span>
        </p>
      )}
      <CauseLine label="control" causes={r.control.cache_events_by_cause} />
      <CauseLine label="candidate" causes={r.candidate.cache_events_by_cause} />
      <p className="text-[10.5px] leading-relaxed text-fg-3">
        Decision guidance: believe deltas at n≥8 sessions per arm and CV under
        ~10–13%. A candidate that wins on cost but adds invalidation-class
        cache events (tools_changed, system_changed) or inflates turns fails.
      </p>
    </div>
  );
}

function CauseLine({
  label,
  causes,
}: {
  label: string;
  causes: Record<string, number>;
}) {
  const entries = Object.entries(causes);
  if (entries.length === 0) return null;
  return (
    <p className="text-[10.5px] text-fg-3">
      cache events, {label}:{" "}
      {entries
        .sort((a, b) => b[1] - a[1])
        .map(([k, v]) => `${k} ${fmtInt(v)}`)
        .join(" · ")}
    </p>
  );
}
