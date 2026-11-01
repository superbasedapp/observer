import { useCallback, useEffect, useState } from "react";
import { fetchJSON } from "../../lib/api";
import { arenaUsageLine } from "../../lib/costSurfaces";
import { ComboChip, ConfirmButton, EntityMultiPicker, ModelId, Pill, Tooltip } from "@/components/primitives";
import { joinList, keepSelected, splitList } from "@/lib/pickerOptions";
import { useProjectFileOptions } from "@/lib/usePickerSources";

// folderName is a project root's last path segment (the picker's label).
function folderName(path: string): string {
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] ?? path;
}
import { Summary } from "@/components/Summary";
import { toneOf, type Tone } from "@shared/lib/tone";
import type { ProjectsResponse } from "../../lib/types";
import {
  CUSTOM_MODEL,
  buildArenaModelItems,
  loadArenaPrefs,
  modelForSubmit,
  modelLabel,
  saveArenaPrefs,
  type ArenaHarnessModels,
  type ArenaModelsResponse,
  type ArenaPrefs,
} from "../../lib/arenaModels";

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

// permissionLaneLabel names the permission lane a drive ran in, in words.
export function permissionLaneLabel(lane: string): string {
  switch (lane) {
    case "bypass":
      return "permissions skipped";
    case "edit":
      return "edits only";
    case "read_only":
      return "read only";
  }
  return lane;
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
  // The permission lane the drive ran in (OSH-R-005); absent on older rows.
  permission_lane?: "bypass" | "edit" | "read_only" | string;
}

export interface ArenaRun {
  id: string;
  project_root: string;
  base_branch: string;
  prompt: string;
  judge_tool: string;
  judge_model?: string;
  status: string;
  created_at: string;
  candidates: ArenaCandidate[];
}

// FALLBACK_HARNESSES is used only until (or if) GET /api/arena/models answers;
// the daemon's list (the registry's headless rows) is authoritative.
const FALLBACK_HARNESSES = ["claude-code", "codex", "grok", "aider", "opencode"];

function browserStorage(): Storage | undefined {
  try {
    return window.localStorage;
  } catch {
    return undefined;
  }
}

// ModelPicker is one harness's model chooser: the shared ComboChip over the
// daemon-composed groups, an inline input for "Other model id", and the
// harness's reason (when it cannot take a model) or caveat note underneath.
function ModelPicker({
  id,
  tool,
  harness,
  loaded,
  value,
  onChange,
}: {
  id: string;
  tool: string;
  harness: ArenaHarnessModels | undefined;
  loaded: boolean;
  value: string;
  onChange: (next: string) => void;
}) {
  const [typing, setTyping] = useState(false);
  const items = buildArenaModelItems(harness, tool, value);
  const locked = !harness || !harness.selectable;
  const selected = items.find((it) => it.value === value);
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <ComboChip
        label={`${tool} model`}
        labelledBy={id}
        hideTriggerLabel
        fullWidth
        value={typing ? CUSTOM_MODEL : value}
        onChange={(next) => {
          if (next === CUSTOM_MODEL) {
            setTyping(true);
            return;
          }
          setTyping(false);
          onChange(next);
        }}
        disabled={locked}
        triggerTooltip={selected && !typing ? `${selected.name}: ${selected.detail}` : null}
        placeholder="Filter models…"
        emptyHint="No matching model. Pick Other model id to type one."
        options={items.map((it) => ({
          value: it.value,
          label: <span className={it.value && it.value !== CUSTOM_MODEL ? "font-mono" : undefined}>{it.name}</span>,
          detail: it.detail,
          groupLabel: it.group,
          disabled: it.disabled,
          title: it.title,
          searchable: it.searchable,
        }))}
      />
      {typing && (
        <input
          autoFocus
          aria-label={`${tool} model id`}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={harness?.default_model ? `e.g. ${harness.default_model}` : "model id"}
          className="rounded-1 bg-bg-1 p-1.5 font-mono text-[11px] text-fg-1"
        />
      )}
      {!loaded && <p className="text-caption text-fg-3">Loading models…</p>}
      {loaded && !harness && <p className="text-caption text-fg-3">Model list unavailable; the harness default is used.</p>}
      {harness && !harness.selectable && harness.reason && <p className="text-caption text-fg-3">{harness.reason}</p>}
      {harness?.selectable && harness.note && <p className="text-caption text-fg-3">{harness.note}</p>}
    </div>
  );
}

// ARENA_STATUS_TONE: the one table for run and candidate statuses (both
// vocabularies share the pill). Semantic tones, so the colours follow the
// theme; an unknown status stays neutral (unknown means unknown).
const ARENA_STATUS_TONE: Readonly<Record<string, Tone>> = {
  pending: "neutral",
  running: "info",
  done: "success",
  failed: "danger",
  timeout: "warn",
  judged: "accent",
  kept: "success",
  discarded: "neutral",
  running_run: "info",
  complete: "success",
};

function StatusPill({ status }: { status: string }) {
  return <Pill variant={toneOf(ARENA_STATUS_TONE, status)}>{status}</Pill>;
}

function ScoreBar({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-center gap-2 text-[11px]">
      <span className="w-20 text-fg-3">{label}</span>
      <div className="h-1.5 w-28 rounded-1 bg-bg-3">
        <div className="h-1.5 rounded-1 bg-accent" style={{ width: `${value * 10}%` }} />
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
  // D-571: context files are picked from the files this project's sessions
  // read or edited; any other project-relative path can still be typed.
  const projectFiles = useProjectFileOptions(projectRoot);
  // The last choices (harness set, judge, and a model per harness) come back
  // from a per-viewer local preference so a repeat run is quick.
  const [initialPrefs] = useState<ArenaPrefs>(() => loadArenaPrefs(browserStorage()));
  const [tools, setTools] = useState<string[]>(initialPrefs.tools ?? ["claude-code"]);
  const [models, setModels] = useState<Record<string, string>>(initialPrefs.models);
  const [judgeTool, setJudgeTool] = useState(initialPrefs.judgeTool ?? "claude-code");
  const [judgeModels, setJudgeModels] = useState<Record<string, string>>(initialPrefs.judgeModels);
  const [catalog, setCatalog] = useState<ArenaModelsResponse | null>(null);
  const [catalogLoaded, setCatalogLoaded] = useState(false);
  const [timeoutMin, setTimeoutMin] = useState(15);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    fetchJSON<ArenaModelsResponse>("/api/arena/models")
      .then((d) => setCatalog(d))
      .catch(() => setCatalog(null))
      .finally(() => setCatalogLoaded(true));
  }, []);

  useEffect(() => {
    saveArenaPrefs(browserStorage(), { judgeTool, tools, models, judgeModels });
  }, [judgeTool, tools, models, judgeModels]);

  const harnessOf = (tool: string): ArenaHarnessModels | undefined =>
    catalog?.harnesses.find((h) => h.tool === tool);
  const harnessIds = catalog?.harnesses.map((h) => h.tool) ?? FALLBACK_HARNESSES;
  const judgeModel = judgeModels[judgeTool] ?? "";

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
        judge_model: modelForSubmit(harnessOf(judgeTool), judgeModel),
        timeout_sec: timeoutMin * 60,
        allow_dirty: false,
        candidates: tools
          .filter((t) => harnessIds.includes(t))
          .map((t) => ({ tool: t, model: modelForSubmit(harnessOf(t), models[t] ?? "") })),
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
        <div className="flex flex-col gap-1">
          <span id="arena-project-label" className="text-fg-3">Project folder</span>
          {/* Absolute project roots overflow a native select on a phone:
              the chip shows the folder name, the row the full path. */}
          <ComboChip
            label="Project folder"
            labelledBy="arena-project-label"
            hideTriggerLabel
            fullWidth
            value={projectRoot}
            onChange={setProjectRoot}
            disabled={projects.length === 0}
            placeholder="Filter projects…"
            options={
              projects.length === 0
                ? [{ value: "", label: "no known projects", searchable: "" }]
                : projects.map((p) => ({
                    value: p,
                    label: <span className="font-mono">{folderName(p)}</span>,
                    detail: <span className="break-all font-mono">{p}</span>,
                    searchable: p.toLowerCase(),
                  }))
            }
          />
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="flex min-w-0 flex-col gap-1">
            <span className="text-fg-3">Judge harness</span>
            <select value={judgeTool} onChange={(e) => setJudgeTool(e.target.value)} className="h-7 rounded-1 bg-bg-1 px-1.5 text-fg-1">
              {harnessIds.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </label>
          <div className="flex min-w-0 flex-col gap-1">
            <span id="arena-judge-model-label" className="text-fg-3">Judge model</span>
            <ModelPicker
              id="arena-judge-model-label"
              tool={judgeTool}
              harness={harnessOf(judgeTool)}
              loaded={catalogLoaded}
              value={judgeModel}
              onChange={(m) => setJudgeModels((cur) => ({ ...cur, [judgeTool]: m }))}
            />
          </div>
        </div>
      </div>
      <textarea
        value={prompt}
        onChange={(e) => setPrompt(e.target.value)}
        placeholder="The single prompt every candidate will receive…"
        rows={3}
        className="mt-3 w-full rounded-1 bg-bg-1 p-2 text-fg-1"
      />
      <div className="mt-3 flex flex-col gap-1">
        <span className="text-fg-3">Context files</span>
        <EntityMultiPicker
          options={keepSelected(projectFiles.options, splitList(contextFiles), "Typed")}
          value={splitList(contextFiles)}
          onChange={(next) => setContextFiles(joinList(next))}
          allowFreeId
          freeIdLabel="Add path"
          loading={projectFiles.loading}
          notice={projectRoot ? "Files this project's sessions read or edited" : undefined}
          emptyHint={projectRoot ? "No files seen yet; type a project-relative path." : "Pick a project first."}
          placeholder="Pick files, or type a project-relative path…"
          ariaLabel="Context files"
        />
      </div>
      <div className="mt-3 flex flex-col gap-1">
        <span className="text-fg-3">Competing harnesses</span>
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {harnessIds.map((t) => {
            const h = harnessOf(t);
            const labelId = `arena-model-${t}`;
            return (
              <div key={t} className="flex min-w-0 flex-col gap-1.5 rounded-1 border border-line-2 p-2">
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={tools.includes(t)} onChange={() => toggleTool(t)} />
                  <span id={labelId} className="font-medium text-fg-1">{t}</span>
                  {h && !h.installed && <span className="ml-auto text-caption text-warn">not found on PATH</span>}
                </label>
                <ModelPicker
                  id={labelId}
                  tool={t}
                  harness={h}
                  loaded={catalogLoaded}
                  value={models[t] ?? ""}
                  onChange={(m) => {
                    setModels((cur) => ({ ...cur, [t]: m }));
                    // Choosing a model for a harness enters it in the run.
                    if (m && !tools.includes(t)) setTools((cur) => [...cur, t]);
                  }}
                />
              </div>
            );
          })}
        </div>
      </div>
      <div className="mt-3 flex flex-wrap gap-3">
        <label className="flex items-center gap-2">
          <span className="text-fg-3">timeout</span>
          <input type="number" min={1} max={120} value={timeoutMin} onChange={(e) => setTimeoutMin(Number(e.target.value))} className="w-16 rounded-1 bg-bg-1 p-0.5" />
          <span className="text-fg-3">min</span>
        </label>
      </div>
      {err && <p className="mt-2 text-caption text-danger">{err}</p>}
      <button
        type="button"
        onClick={submit}
        disabled={busy}
        className="mt-3 rounded-1 bg-bg-3 px-3 py-1.5 text-fg-1 hover:bg-bg-3/80 disabled:opacity-50"
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
          {cand.model ? (
            <ModelId model={cand.model} mono={false} className="min-w-0 text-[11px]" />
          ) : (
            <span className="text-[11px] text-fg-3">{modelLabel(cand.model)}</span>
          )}
          <StatusPill status={cand.status} />
        </div>
        <div className="flex items-center gap-2">
          <Tooltip content="Merge strategy">
            <select value={strategy} onChange={(e) => setStrategy(e.target.value)} disabled={!canKeep} aria-label="Merge strategy" className="rounded-1 bg-bg-1 p-0.5 text-caption disabled:opacity-40">
              <option value="squash">squash merge</option>
              <option value="judge_merge">judge-managed merge</option>
            </select>
          </Tooltip>
          <button type="button" onClick={() => act("keep")} disabled={!canKeep} className="rounded-1 border border-line-2 px-2 py-0.5 text-[11px] text-fg-1 hover:bg-bg-2 disabled:opacity-40">
            Keep → main
          </button>
          {/* Discard removes the candidate's worktree and branch, so it
              takes the shared two-step in-place confirm. */}
          <ConfirmButton
            variant="secondary"
            size="sm"
            onConfirm={() => void act("discard")}
            disabled={!canDiscard}
            confirmLabel="Discard?"
            armedNote="Deletes this candidate's worktree and branch."
          >
            Discard
          </ConfirmButton>
        </div>
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-fg-3">
        <span>{cand.wall_ms.toLocaleString()} ms</span>
        {cand.permission_lane && (
          <span
            className={cand.permission_lane === "bypass" ? "text-warn" : undefined}
            title="How the harness's own permission prompts were handled during this unattended drive"
          >
            {permissionLaneLabel(cand.permission_lane)}
          </span>
        )}
        {cand.timed_out && <span className="text-warn">timed out</span>}
        {cand.exit_code !== 0 && <span className="text-danger">exit {cand.exit_code}</span>}
        <span>{cand.diff_files} files · +{cand.diff_added} / −{cand.diff_removed}</span>
        {(cand.input_tokens > 0 || cand.output_tokens > 0) && (
          <span>{arenaUsageLine(cand.input_tokens, cand.output_tokens, cand.cost_usd)}</span>
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
        <pre className="mt-2 max-h-80 overflow-auto rounded-1 bg-bg-1 p-2 text-[10px] leading-relaxed text-fg-2">{patch}</pre>
      )}
    </div>
  );
}

function RunCard({ run, refresh }: { run: ArenaRun; refresh: () => void }) {
  return (
    <details className="rounded-2 border border-line-2 bg-bg-1 p-3" open>
      <Summary className="text-small text-fg-1">
        <span className="font-medium">{run.id}</span>
        <span className="ml-2 text-fg-3">{run.project_root}</span>
        <span className="ml-2"><StatusPill status={run.status} /></span>
      </Summary>
      <p className="mt-1 whitespace-pre-wrap text-[11px] text-fg-2">{run.prompt}</p>
      {/* Which model judged: the run record stores the resolved judge model
          ("" = the judge harness's own default). */}
      <p className="mt-1 flex flex-wrap items-center gap-1 text-[11px] text-fg-3">
        <span>Judged by</span>
        <span className="font-medium text-fg-2">{run.judge_tool}</span>
        <span>·</span>
        {run.judge_model ? (
          <ModelId model={run.judge_model} mono={false} className="min-w-0 text-[11px]" />
        ) : (
          <span>{modelLabel(run.judge_model)}</span>
        )}
      </p>
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
