import { useCallback, useEffect, useState } from "react";
import { fetchJSON } from "../../lib/api";
import type { ProjectsResponse } from "../../lib/types";

// Agent Arena tab (plan: agent-arena-terminal-multi-harness-2026-08-22.md):
// run one prompt against several harnesses in isolated worktrees, compare
// judged scorecards, keep the winner (squash merge) or discard.

interface JudgeScores {
  correctness: number;
  completeness: number;
  code_quality: number;
  performance: number;
  risk: number;
  overall: number;
  verdict_rationale?: string;
}

interface ArenaCandidate {
  id: string;
  tool: string;
  model: string;
  seq: number;
  status: string;
  branch_name: string;
  exit_code: number;
  wall_ms: number;
  timed_out: boolean;
  diff_files: number;
  diff_added: number;
  diff_removed: number;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  session_ids: string[];
  scores?: JudgeScores | null;
  verdict?: string;
  final_answer?: string;
  has_patch?: boolean;
}

export interface ArenaRun {
  id: string;
  project_root: string;
  base_branch: string;
  prompt: string;
  judge_tool: string;
  status: string;
  created_at: string;
  candidates: ArenaCandidate[];
}

const HARNESS_OPTIONS = [
  { tool: "claude-code", label: "claude-code" },
  { tool: "codex", label: "codex" },
  { tool: "grok", label: "grok" },
  { tool: "opencode", label: "opencode" },
  { tool: "aider", label: "aider" },
];

const STATUS_COLORS: Record<string, string> = {
  pending: "text-fg-3",
  running: "text-blue-400",
  done: "text-green-400",
  failed: "text-red-400",
  timeout: "text-orange-400",
  judged: "text-cyan-400",
  kept: "text-green-300",
  discarded: "text-fg-3",
  running_run: "text-blue-400",
  complete: "text-green-400",
};

function StatusPill({ status }: { status: string }) {
  return (
    <span className={`rounded-[6px] border border-line-2 px-1.5 py-0.5 text-[11px] ${STATUS_COLORS[status] ?? "text-fg-2"}`}>
      {status}
    </span>
  );
}

function ScoreBar({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-center gap-2 text-[11px]">
      <span className="w-20 text-fg-3">{label}</span>
      <div className="h-1.5 w-28 rounded bg-bg-3">
        <div className="h-1.5 rounded bg-accent" style={{ width: `${value * 10}%` }} />
      </div>
      <span className="text-fg-2">{value}/10</span>
    </div>
  );
}

async function getConfirmToken(): Promise<string> {
  const cfg = await fetchJSON<{ confirm_token?: string }>("/api/remote/config");
  return cfg.confirm_token ?? "";
}

function NewRunForm({ onCreated }: { onCreated: (id: string) => void }) {
  const [projects, setProjects] = useState<string[]>([]);
  const [projectRoot, setProjectRoot] = useState("");
  const [prompt, setPrompt] = useState("");
  const [contextFiles, setContextFiles] = useState("");
  const [tools, setTools] = useState<string[]>(["claude-code"]);
  const [models, setModels] = useState<Record<string, string>>({});
  const [judgeTool, setJudgeTool] = useState("claude-code");
  const [timeoutMin, setTimeoutMin] = useState(15);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    fetchJSON<ProjectsResponse>("/api/projects")
      .then((d) => {
        const roots = (d.rows ?? []).map((p) => p.root_path);
        setProjects(roots);
        if (roots.length > 0 && !projectRoot) setProjectRoot(roots[0]);
      })
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const toggleTool = (t: string) =>
    setTools((cur) => (cur.includes(t) ? cur.filter((x) => x !== t) : [...cur, t]));

  const submit = async () => {
    setErr("");
    if (!projectRoot || !prompt.trim() || tools.length === 0) {
      setErr("Pick a project, write a prompt, select at least one harness.");
      return;
    }
    setBusy(true);
    try {
      const ctok = await getConfirmToken();
      const body = {
        project_root: projectRoot,
        prompt: prompt.trim(),
        context_files: contextFiles
          .split(/[\n,]/)
          .map((p) => p.trim())
          .filter(Boolean),
        run_id: `arena-${Date.now()}`,
        judge_tool: judgeTool,
        timeout_sec: timeoutMin * 60,
        allow_dirty: false,
        candidates: tools.map((t) => ({ tool: t, model: models[t] ?? "" })),
      };
      await fetchJSON("/api/arena/runs", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Observer-Confirm": ctok },
        body: JSON.stringify(body),
      });
      onCreated(body.run_id);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-2 border border-line-2 bg-bg-0 p-4 text-[12px]">
      <div className="grid gap-3 md:grid-cols-2">
        <label className="flex flex-col gap-1">
          <span className="text-fg-3">Project folder</span>
          <select value={projectRoot} onChange={(e) => setProjectRoot(e.target.value)} className="rounded bg-bg-1 p-1.5 text-fg-1">
            {projects.length === 0 && <option value="">no known projects</option>}
            {projects.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-fg-3">Judge harness</span>
          <select value={judgeTool} onChange={(e) => setJudgeTool(e.target.value)} className="rounded bg-bg-1 p-1.5 text-fg-1">
            {HARNESS_OPTIONS.map((h) => (
              <option key={h.tool} value={h.tool}>{h.label}</option>
            ))}
          </select>
        </label>
      </div>
      <textarea
        value={prompt}
        onChange={(e) => setPrompt(e.target.value)}
        placeholder="The single prompt every candidate will receive…"
        rows={3}
        className="mt-3 w-full rounded bg-bg-1 p-2 text-fg-1"
      />
      <label className="mt-3 flex flex-col gap-1">
        <span className="text-fg-3">Context files</span>
        <input
          value={contextFiles}
          onChange={(e) => setContextFiles(e.target.value)}
          placeholder="project-relative paths, separated by commas"
          className="rounded bg-bg-1 p-1.5 text-fg-1"
        />
      </label>
      <div className="mt-3 flex flex-wrap gap-3">
        {HARNESS_OPTIONS.map((h) => (
          <label key={h.tool} className="flex items-center gap-2 rounded border border-line-2 px-2 py-1">
            <input type="checkbox" checked={tools.includes(h.tool)} onChange={() => toggleTool(h.tool)} />
            <span>{h.label}</span>
            <input
              value={models[h.tool] ?? ""}
              onChange={(e) => setModels((cur) => ({ ...cur, [h.tool]: e.target.value }))}
              placeholder="model (default)"
              className="w-32 rounded bg-bg-1 p-0.5"
            />
          </label>
        ))}
        <label className="flex items-center gap-2">
          <span className="text-fg-3">timeout</span>
          <input type="number" min={1} max={120} value={timeoutMin} onChange={(e) => setTimeoutMin(Number(e.target.value))} className="w-16 rounded bg-bg-1 p-0.5" />
          <span className="text-fg-3">min</span>
        </label>
      </div>
      {err && <p className="mt-2 text-[11px] text-red-400">{err}</p>}
      <button
        type="button"
        onClick={submit}
        disabled={busy}
        className="mt-3 rounded bg-bg-3 px-3 py-1.5 text-fg-1 hover:bg-bg-3/80 disabled:opacity-50"
      >
        {busy ? "Starting…" : "Start arena run"}
      </button>
    </div>
  );
}

function CandidateCard({ runId, runStatus, cand, onChanged }: { runId: string; runStatus: string; cand: ArenaCandidate; onChanged: () => void }) {
  const [patch, setPatch] = useState<string | null>(null);
  const [msg, setMsg] = useState("");
  const [strategy, setStrategy] = useState("squash");
  const [actionBusy, setActionBusy] = useState(false);

  const act = async (action: "keep" | "discard") => {
    if (actionBusy) return;
    setActionBusy(true);
    setMsg("");
    try {
      const ctok = await getConfirmToken();
      const res = await fetchJSON<Record<string, unknown>>(`/api/arena/runs/${runId}/action/${cand.id}`, undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Observer-Confirm": ctok },
        body: JSON.stringify({ action, strategy }),
      });
      onChanged();
      if (action === "keep") setMsg(`kept as ${(res.kept_commit_sha as string) ?? "?"}`);
    } catch (e) {
      // 409 = dirty tree / merge conflict — surface the server's explanation.
      setMsg(String(e));
    } finally {
      setActionBusy(false);
    }
  };

  const runTerminal = runStatus === "complete" || runStatus === "failed";
  const canKeep = runTerminal && cand.status === "judged" && !actionBusy;
  const canDiscard = runTerminal && ["done", "failed", "timeout", "judged"].includes(cand.status) && !actionBusy;

  const loadPatch = async () => {
    if (patch !== null) {
      setPatch(null);
      return;
    }
    try {
      const d = await fetchJSON<{ patch: string }>(`/api/arena/runs/${runId}/diff/${cand.id}`);
      setPatch(d.patch || "(empty diff - inert candidate)");
    } catch (e) {
      setPatch("failed to load: " + String(e));
    }
  };

  return (
    <div className="rounded-2 border border-line-2 bg-bg-0 p-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="font-medium text-fg-1">{cand.tool}</span>
          {cand.model && <span className="text-[11px] text-fg-3">{cand.model}</span>}
          <StatusPill status={cand.status} />
        </div>
        <div className="flex items-center gap-2">
          <select value={strategy} onChange={(e) => setStrategy(e.target.value)} disabled={!canKeep} className="rounded bg-bg-1 p-0.5 text-[11px] disabled:opacity-40" title="merge strategy">
            <option value="squash">squash merge</option>
            <option value="judge_merge">judge-managed merge</option>
          </select>
          <button type="button" onClick={() => act("keep")} disabled={!canKeep} className="rounded border border-line-2 px-2 py-0.5 text-[11px] text-fg-1 hover:bg-bg-2 disabled:opacity-40">
            Keep → main
          </button>
          <button type="button" onClick={() => act("discard")} disabled={!canDiscard} className="rounded border border-line-2 px-2 py-0.5 text-[11px] text-fg-3 hover:bg-bg-2 disabled:opacity-40">
            Discard
          </button>
        </div>
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-fg-3">
        <span>{cand.wall_ms.toLocaleString()} ms</span>
        {cand.timed_out && <span className="text-orange-400">timed out</span>}
        {cand.exit_code !== 0 && <span className="text-red-400">exit {cand.exit_code}</span>}
        <span>{cand.diff_files} files · +{cand.diff_added} / −{cand.diff_removed}</span>
        {(cand.input_tokens > 0 || cand.output_tokens > 0) && (
          <span>{cand.input_tokens.toLocaleString()} in / {cand.output_tokens.toLocaleString()} out · ≈${cand.cost_usd.toFixed(4)}</span>
        )}
        {cand.has_patch && (
          <button type="button" onClick={loadPatch} className="underline hover:text-fg-1">
            {patch === null ? "view diff" : "hide diff"}
          </button>
        )}
      </div>
      {cand.scores && (
        <div className="mt-2 grid gap-1 md:grid-cols-2">
          <ScoreBar label="correctness" value={cand.scores.correctness} />
          <ScoreBar label="completeness" value={cand.scores.completeness} />
          <ScoreBar label="code quality" value={cand.scores.code_quality} />
          <ScoreBar label="performance" value={cand.scores.performance} />
          <ScoreBar label="risk" value={cand.scores.risk} />
          <ScoreBar label="overall" value={cand.scores.overall} />
        </div>
      )}
      {cand.verdict && <p className="mt-2 text-[11px] text-fg-2">{cand.verdict}</p>}
      {msg && <p className="mt-1 text-[11px] text-fg-3">{msg}</p>}
      {patch !== null && (
        <pre className="mt-2 max-h-80 overflow-auto rounded bg-bg-1 p-2 text-[10px] leading-relaxed text-fg-2">{patch}</pre>
      )}
    </div>
  );
}

function RunCard({ run, refresh }: { run: ArenaRun; refresh: () => void }) {
  return (
    <details className="rounded-2 border border-line-2 bg-bg-1 p-3" open>
      <summary className="cursor-pointer text-[12px] text-fg-1">
        <span className="font-medium">{run.id}</span>
        <span className="ml-2 text-fg-3">{run.project_root}</span>
        <span className="ml-2"><StatusPill status={run.status} /></span>
      </summary>
      <p className="mt-1 whitespace-pre-wrap text-[11px] text-fg-2">{run.prompt}</p>
      <div className="mt-2 grid gap-2">
        {[...run.candidates]
          .sort((a, b) => a.seq - b.seq)
          .map((c) => (
            <CandidateCard key={c.id} runId={run.id} runStatus={run.status} cand={c} onChanged={refresh} />
          ))}
      </div>
    </details>
  );
}

export function ArenaTab() {
  const [runs, setRuns] = useState<ArenaRun[]>([]);
  const [loaded, setLoaded] = useState(false);

  const refresh = useCallback(() => {
    fetchJSON<{ runs: ArenaRun[] }>("/api/arena/runs")
      .then((d) => {
        setRuns(d.runs ?? []);
        setLoaded(true);
      })
      .catch(() => setLoaded(true));
  }, []);

  useEffect(() => {
    refresh();
    const iv = setInterval(refresh, 5000);
    return () => clearInterval(iv);
  }, [refresh]);

  return (
    <div className="grid gap-4">
      <NewRunForm onCreated={refresh} />
      {loaded && runs.length === 0 && (
        <p className="text-[12px] text-fg-3">No arena runs yet.</p>
      )}
      <div className="grid gap-3">
        {runs.map((r) => (
          <RunCard key={r.id} run={r} refresh={refresh} />
        ))}
      </div>
    </div>
  );
}
