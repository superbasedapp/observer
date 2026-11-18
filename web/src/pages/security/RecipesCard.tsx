import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { NeedsSettingLink } from "@/components/NeedsSettingNotice";
import { placeLink } from "@/lib/settingsPlaces";
import { GatedLink } from "@/components/GatedLink";
import clsx from "clsx";
import { ArrowRight, CopyPlus, Download, Eye, Layers, Trash2, Upload } from "lucide-react";
import {
  Button,
  Callout,
  Card,
  ComboChip,
  type ComboOption,
  InfoDisclosure,
  InlineLoading,
  Input,
  Modal,
  Pill,
  RowActions,
  SegmentedControl,
  Textarea,
  Toggle,
  Tooltip,
  confirmDialog,
} from "@/components/primitives";
import { pushToast } from "@/components/Toast";
import { ApiError, apiReason, fetchJSON, localConfirmHeaders } from "@/lib/api";
import { writeClipboard } from "@/lib/clipboard";
import { fmtDateTime } from "@/lib/format";
import { markRestartPending } from "@/lib/restartPending";
import type { ProjectRow } from "@/lib/types";
import { useApi } from "@/lib/useApi";
import {
  APPLY_TOAST,
  GUARD_OFF_NOTE,
  NOT_A_FIREWALL_NOTE,
  PROJECT_MODE_NOTE,
  RECIPE_TEMPLATE,
  REPLAY_WINDOWS,
  appliedFor,
  appliedLine,
  appliedVia,
  applyRefusal,
  applyBody,
  applyConfirmBody,
  applyConfirmTone,
  changeCountLine,
  changeDecisionLabel,
  changeDirection,
  changeRuleLabel,
  changeTally,
  configMoves,
  copyName,
  groupChanges,
  levelStops,
  modeLabel,
  packChoices,
  previewQuery,
  promptModeLabel,
  recipeInput,
  recipeNameFromToml,
  recipeNameProblem,
  recipeTitle,
  removeBody,
  removeConfirmBody,
  renameRecipeToml,
  copyTitleToml,
  REPLAY_POLL_MS,
  isReplayProgress,
  replayModeNote,
  replayProgressText,
  replaySentence,
  selectionFromApplied,
  selectionKey,
  scopeBlockedReason,
  selectionReady,
  simulateQuery,
  togglePack,
  topBlockingRules,
  type AppliedRecipe,
  type Recipe,
  type RecipePreview,
  type RecipeReplay,
  type ReplayProgress,
  type RecipeScope,
  type RecipeSelection,
  type RecipesState,
} from "@/lib/guardRecipes";
import { decisionTone } from "@shared/lib/guardCatalog";
import { guardRuleName } from "@shared/lib/guardRuleNames";

// RecipesCard - guard recipes on the Security page's Rules tab (plan
// docs/plans/profile-guard-recipes-repo-grouping-plan-2026-11-07.md section
// 3d). Two axes: one LEVEL per scope (a slider, none to lockdown, then the
// user's own levels) and any number of PACKS (chips). A scope is this whole
// machine or one project (the trusted per-project layer). Every selection
// change refetches a debounced preview (what moves, every rule whose
// decision changes, problems that refuse the apply); a replay runs the
// selection over the last 7 or 30 days of real actions through the existing
// simulate route. Apply and remove confirm in an in-app dialog and write
// through the owner-local confirm token. Customise: view, duplicate and
// edit, export, import and delete the user's own recipes. The pure half is
// web/src/lib/guardRecipes.ts.

export const RECIPES_PATH = "/api/guard/recipes";

type SimulateResponse = { recipe_replay?: RecipeReplay | null };

/** fetchRecipePreview asks what a selection (or a removal) would change. */
export function fetchRecipePreview(sel: RecipeSelection, remove: boolean, signal?: AbortSignal): Promise<RecipePreview> {
  return fetchJSON<RecipePreview>(`${RECIPES_PATH}/preview`, previewQuery(sel, remove), { signal });
}

/** fetchRecipeReplay replays a selection over the last `hours`; null when
 *  the daemon's simulate route has no recipe replay. It polls with
 *  progress=1: the daemon answers 202 with the run's counts while it works
 *  (reported through onProgress) and the result once it is done, and an
 *  identical replay already running (another tab, a second click) is joined
 *  rather than run again. A daemon without progress answers the result on the
 *  first request, so the loop ends at once. */
export async function fetchRecipeReplay(
  sel: RecipeSelection,
  hours: number,
  remove: boolean,
  signal?: AbortSignal,
  onProgress?: (p: ReplayProgress) => void,
): Promise<RecipeReplay | null> {
  const query = { ...simulateQuery(sel, hours, remove), progress: 1 };
  for (;;) {
    const out = await fetchJSON<SimulateResponse | ReplayProgress>("/api/guard/simulate", query, { signal });
    if (!isReplayProgress(out)) return (out as SimulateResponse).recipe_replay ?? null;
    onProgress?.(out);
    await new Promise<void>((resolve, reject) => {
      const t = setTimeout(resolve, REPLAY_POLL_MS);
      signal?.addEventListener("abort", () => {
        clearTimeout(t);
        reject(new DOMException("aborted", "AbortError"));
      });
    });
  }
}

/** recipeWrite POSTs one owner-local recipe write with the confirm token
 *  GET /api/guard/recipes handed out (fetchJSON swaps in the current cookie
 *  value when the tab holds a newer one). */
export async function recipeWrite<T>(path: string, body: unknown, token: string): Promise<T> {
  const headers: Record<string, string> = token ? { "Content-Type": "application/json", "X-Observer-Confirm": token } : await localConfirmHeaders();
  return fetchJSON<T>(path, undefined, { method: "POST", headers, body: JSON.stringify(body) });
}

type WriteResult = { wrote?: string; config_changed?: boolean };
type ApplyResponse = { applied: boolean; result?: WriteResult; restart_required: boolean };
type RemoveResponse = { removed: boolean; result?: WriteResult; restart_required: boolean };
type ShowResponse = { recipe: Recipe; toml: string };

/** Loaded is one async read's view state. */
export type Loaded<T> = { key: string; data: T | null; loading: boolean; error: string };

const IDLE = { key: "", data: null, loading: false, error: "" };

/** ReplayState is the replay block's view: the result, or the running run's
 *  progress while it works. */
type ReplayState = Loaded<RecipeReplay> & { hours: number; progress?: ReplayProgress | null };

function shortenRoot(p: string): string {
  if (!p) return "-";
  const parts = p.split(/[\\/]/).filter(Boolean);
  return parts.length <= 2 ? p : ".../" + parts.slice(-2).join("/");
}

function downloadText(name: string, text: string) {
  const blob = new Blob([text], { type: "application/toml" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${name}.toml`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// writeErrorText turns a failed write into what the card says: a refused
// apply (422 with the compiled file's lint problems) lists them, anything
// else is the plain-text reason the daemon sent.
export function writeErrorText(e: unknown, remove = false): string {
  const problems = e instanceof ApiError && e.status === 422 ? applyRefusal(e.body) : null;
  if (problems && problems.length > 0) return [remove ? "This recipe cannot be removed yet:" : "This recipe did not pass the check:", ...problems.map((x) => `- ${x}`)].join("\n");
  return apiReason(e);
}

type EditorState =
  | { mode: "view"; recipe: Recipe; toml: string }
  | { mode: "edit"; title: string; name: string; toml: string; editing: string };

export function RecipesCard({ projects, onChanged }: { projects: ProjectRow[]; onChanged?: () => void }) {
  const [scope, setScope] = useState<RecipeScope>("global");
  const [projectRoot, setProjectRoot] = useState("");
  const api = useApi<RecipesState>(RECIPES_PATH, scope === "project" && projectRoot ? { project_root: projectRoot } : undefined);
  const state = api.data;

  const [level, setLevel] = useState("");
  const [packs, setPacks] = useState<string[]>([]);
  const [removing, setRemoving] = useState(false);
  const sel: RecipeSelection = useMemo(() => ({ level, packs, scope, projectRoot }), [level, packs, scope, projectRoot]);

  // Start the picker at what the scope already has, once per scope and
  // whenever what is applied there changes (after an apply or a remove).
  const applied = appliedFor(state, scope, projectRoot);
  const appliedSig = `${scope}|${projectRoot}|${JSON.stringify(applied?.meta.level ?? null)}|${JSON.stringify(applied?.meta.packs ?? null)}`;
  const [seeded, setSeeded] = useState("");
  useEffect(() => {
    if (!state || appliedSig === seeded) return;
    setSeeded(appliedSig);
    const s = selectionFromApplied(applied, scope, projectRoot);
    setLevel(s.level);
    setPacks(s.packs);
    setRemoving(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state, appliedSig]);

  // The preview: debounced, refetched on every selection change and after
  // every write (gen).
  const [gen, setGen] = useState(0);
  const scopeReady = scope === "global" || projectRoot !== "";
  const previewKey = removing ? (scopeReady ? selectionKey(sel, true) : "") : selectionReady(sel) ? selectionKey(sel) : "";
  const [preview, setPreview] = useState<Loaded<RecipePreview>>(IDLE);
  useEffect(() => {
    if (!previewKey) {
      setPreview(IDLE);
      return;
    }
    const ctl = new AbortController();
    setPreview((p) => ({ ...p, key: previewKey, loading: true, error: "" }));
    const t = setTimeout(() => {
      fetchRecipePreview(sel, removing, ctl.signal)
        .then((data) => setPreview({ key: previewKey, data, loading: false, error: "" }))
        .catch((e) => {
          if (!ctl.signal.aborted) setPreview({ key: previewKey, data: null, loading: false, error: apiReason(e) });
        });
    }, 300);
    return () => {
      clearTimeout(t);
      ctl.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [previewKey, gen]);

  const [replay, setReplay] = useState<ReplayState>({ ...IDLE, hours: 0, progress: null });
  // The running replay's poll loop stops when the card goes away; the daemon
  // then drops the run once nobody polls it.
  const replayAbort = useRef<AbortController | null>(null);
  useEffect(() => () => replayAbort.current?.abort(), []);
  async function runReplay(hours: number) {
    if (!previewKey) return;
    const key = previewKey;
    replayAbort.current?.abort();
    const ctl = new AbortController();
    replayAbort.current = ctl;
    setReplay({ key, hours, data: null, loading: true, error: "", progress: null });
    try {
      const data = await fetchRecipeReplay(sel, hours, removing, ctl.signal, (progress) =>
        setReplay((r) => (r.key === key && r.hours === hours && r.loading ? { ...r, progress } : r)),
      );
      setReplay({ key, hours, data, loading: false, error: data ? "" : "This daemon cannot replay a recipe yet.", progress: null });
    } catch (e) {
      if (ctl.signal.aborted) return;
      setReplay({ key, hours, data: null, loading: false, error: apiReason(e), progress: null });
    }
  }

  const [busy, setBusy] = useState<string | null>(null);
  const [writeError, setWriteError] = useState("");
  const token = state?.confirm_token ?? "";

  // The recipe file binds at daemon start like the policy files (the
  // RuleManager's "guard-policy" marker); a machine-wide apply or remove
  // also moves three config keys, named when the write says it changed them.
  function afterWrite(restart: boolean, configChanged: boolean) {
    if (restart) markRestartPending("guard-policy", configChanged ? ["guard.level", "guard.mode", "guard.prompt.mode"] : undefined);
    setGen((g) => g + 1);
    api.reload();
    onChanged?.();
  }

  async function apply() {
    const p = preview.data;
    if (!p || removing) return;
    const where = scope === "project" ? `to ${shortenRoot(projectRoot)}` : "to this machine";
    const ok = await confirmDialog({
      title: `Apply this recipe ${where}?`,
      body: applyConfirmBody(p),
      confirmLabel: "Apply recipe",
      tone: applyConfirmTone(p),
    });
    if (!ok) return;
    setBusy("apply");
    setWriteError("");
    try {
      const out = await recipeWrite<ApplyResponse>(`${RECIPES_PATH}/apply`, applyBody(sel), token);
      pushToast(out.restart_required ? APPLY_TOAST : "Recipe applied.", "success");
      afterWrite(out.restart_required, out.result?.config_changed === true);
    } catch (e) {
      setWriteError(writeErrorText(e));
    } finally {
      setBusy(null);
    }
  }

  async function remove() {
    const p = preview.data;
    if (!p || !removing) return;
    const ok = await confirmDialog({ title: "Remove the recipe here?", body: removeConfirmBody(p), confirmLabel: "Remove recipe", tone: "danger" });
    if (!ok) return;
    setBusy("remove");
    setWriteError("");
    try {
      const out = await recipeWrite<RemoveResponse>(`${RECIPES_PATH}/remove`, removeBody(scope, projectRoot), token);
      pushToast(out.removed ? "Recipe removed." : "Nothing was applied here.", "success");
      setRemoving(false);
      afterWrite(out.restart_required, out.result?.config_changed === true);
    } catch (e) {
      setWriteError(writeErrorText(e, true));
    } finally {
      setBusy(null);
    }
  }

  // --- Customise: view, duplicate and edit, export, import, delete. ---
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [editorError, setEditorError] = useState("");

  async function loadRecipe(name: string): Promise<ShowResponse | null> {
    try {
      return await fetchJSON<ShowResponse>(`${RECIPES_PATH}/show`, { name });
    } catch (e) {
      pushToast(apiReason(e), "danger");
      return null;
    }
  }
  async function view(name: string) {
    const out = await loadRecipe(name);
    if (out) setEditor({ mode: "view", recipe: out.recipe, toml: out.toml });
  }
  async function duplicate(name: string, toml?: string) {
    const text = toml ?? (await loadRecipe(name))?.toml;
    if (text == null) return;
    const next = copyName(name, state?.catalog);
    setEditorError("");
    setEditor({ mode: "edit", title: `Duplicate ${recipeTitle(state?.catalog, name)}`, name: next, toml: copyTitleToml(renameRecipeToml(text, next)), editing: "" });
  }
  async function exportRecipe(name: string, how: "copy" | "download") {
    const out = await loadRecipe(name);
    if (!out) return;
    if (how === "download") {
      downloadText(name, out.toml);
      return;
    }
    const r = await writeClipboard(out.toml);
    pushToast(r === "failed" ? "Could not copy: use Download instead." : "Recipe file copied.", r === "failed" ? "warn" : "success");
  }
  function importRecipe() {
    setEditorError("");
    setEditor({ mode: "edit", title: "Import a recipe", name: "", toml: "", editing: "" });
  }
  async function saveUser() {
    if (!editor || editor.mode !== "edit") return;
    setBusy("save");
    setEditorError("");
    try {
      const name = editor.name.trim();
      await recipeWrite(`${RECIPES_PATH}/user`, { name, toml: renameRecipeToml(editor.toml, name) }, token);
      pushToast(`Saved ${name}. It changes no rule until you apply it.`, "success");
      setEditor(null);
      api.reload();
    } catch (e) {
      setEditorError(apiReason(e));
    } finally {
      setBusy(null);
    }
  }
  async function deleteUser(name: string) {
    setBusy("delete");
    try {
      await recipeWrite(`${RECIPES_PATH}/user/delete`, { name }, token);
      pushToast(`Deleted ${name}.`, "success");
      if (level === name) setLevel("");
      if (packs.includes(name)) setPacks(packs.filter((p) => p !== name));
      api.reload();
    } catch (e) {
      pushToast(apiReason(e), "danger");
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <RecipesView
        state={state}
        loading={api.loading && !state}
        loadError={api.error ? apiReason(api.error) : ""}
        projects={projects}
        sel={sel}
        removing={removing}
        applied={applied}
        onScope={(s) => {
          setScope(s);
          setRemoving(false);
        }}
        onProject={(r) => {
          setProjectRoot(r);
          setRemoving(false);
        }}
        onLevel={setLevel}
        onTogglePack={(name) => setPacks((cur) => togglePack(cur, name))}
        preview={preview.key === previewKey ? preview : { ...IDLE, loading: previewKey !== "" }}
        replay={replay.key === previewKey && previewKey !== "" ? replay : null}
        onReplay={(h) => void runReplay(h)}
        onApply={() => void apply()}
        onStartRemove={() => setRemoving(true)}
        onCancelRemove={() => setRemoving(false)}
        onRemove={() => void remove()}
        busy={busy}
        writeError={writeError}
        onView={(n) => void view(n)}
        onDuplicate={(n) => void duplicate(n)}
        onExport={(n, how) => void exportRecipe(n, how)}
        onDelete={(n) => void deleteUser(n)}
        onImport={importRecipe}
      />
      {editor?.mode === "view" && (
        <Modal
          open
          onClose={() => setEditor(null)}
          title={editor.recipe.title || editor.recipe.name}
          subtitle={editor.recipe.summary}
          width={720}
          footer={
            <>
              <Button variant="ghost" onClick={() => setEditor(null)}>
                Close
              </Button>
              <Button variant="secondary" iconLeft={Download} onClick={() => downloadText(editor.recipe.name, editor.toml)}>
                Download
              </Button>
              <Button variant="primary" iconLeft={CopyPlus} onClick={() => void duplicate(editor.recipe.name, editor.toml)}>
                Duplicate and edit
              </Button>
            </>
          }
        >
          <pre className="max-h-[60vh] overflow-auto rounded-2 border border-line-2 bg-bg-2 p-3 font-mono text-[11px] leading-relaxed text-fg-1">{editor.toml}</pre>
        </Modal>
      )}
      {editor?.mode === "edit" && (
        <RecipeEditorModal
          editor={editor}
          catalog={state?.catalog ?? []}
          busy={busy === "save"}
          error={editorError}
          onChange={(next) => setEditor({ ...editor, ...next })}
          onClose={() => setEditor(null)}
          onSave={() => void saveUser()}
        />
      )}
    </>
  );
}

function RecipeEditorModal({
  editor,
  catalog,
  busy,
  error,
  onChange,
  onClose,
  onSave,
}: {
  editor: Extract<EditorState, { mode: "edit" }>;
  catalog: Recipe[];
  busy: boolean;
  error: string;
  onChange: (next: { name?: string; toml?: string }) => void;
  onClose: () => void;
  onSave: () => void;
}) {
  const problem = recipeNameProblem(editor.name, catalog, editor.editing);
  const blocking = problem !== "" && !problem.endsWith("saving replaces it.");
  const empty = editor.toml.trim() === "";
  return (
    <Modal
      open
      onClose={onClose}
      title={editor.title}
      subtitle="Saved recipes are checked first and change no rule until you apply them."
      width={720}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={busy} disabled={busy || blocking || empty} onClick={onSave}>
            Save recipe
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <Input
          label="Name"
          mono
          value={editor.name}
          onChange={(e) => onChange({ name: e.target.value })}
          placeholder="my-recipe"
          maxLength={64}
          error={blocking ? problem : undefined}
          help={!blocking && problem ? problem : "Lowercase letters, digits and dashes."}
        />
        <Textarea
          label="Recipe file"
          mono
          rows={18}
          value={editor.toml}
          onChange={(e) => onChange({ toml: e.target.value, name: editor.name || recipeNameFromToml(e.target.value) })}
          placeholder={RECIPE_TEMPLATE}
          spellCheck={false}
        />
        {error && <Callout tone="danger" title="Not saved">{error}</Callout>}
      </div>
    </Modal>
  );
}

// ---------- the view ----------

export type RecipesViewProps = {
  state: RecipesState | null;
  loading: boolean;
  loadError: string;
  projects: ProjectRow[];
  sel: RecipeSelection;
  removing: boolean;
  applied: AppliedRecipe | null;
  onScope: (s: RecipeScope) => void;
  onProject: (root: string) => void;
  onLevel: (name: string) => void;
  onTogglePack: (name: string) => void;
  preview: Loaded<RecipePreview>;
  replay: ReplayState | null;
  onReplay: (hours: number) => void;
  onApply: () => void;
  onStartRemove: () => void;
  onCancelRemove: () => void;
  onRemove: () => void;
  busy: string | null;
  writeError: string;
  onView: (name: string) => void;
  onDuplicate: (name: string) => void;
  onExport: (name: string, how: "copy" | "download") => void;
  onDelete: (name: string) => void;
  onImport: () => void;
};

/** RecipesView is the card's pure render (component-tested). */
export function RecipesView(props: RecipesViewProps) {
  const { state, sel, projects } = props;
  const catalog = state?.catalog ?? [];
  const projectOptions: ComboOption[] = projects.map((p) => ({
    value: p.root_path,
    label: <span className="font-mono text-[11px]">{shortenRoot(p.root_path)}</span>,
    searchable: p.root_path.toLowerCase(),
    title: p.root_path,
    rightMeta: p.action_count.toLocaleString(),
  }));
  const projectBlocked = scopeBlockedReason(state, "project");

  return (
    <Card
      title="Recipes"
      icon={Layers}
      sub="Pick how strict the guard is and add packs for your kind of work. See every change, and replay real actions, before you apply."
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <SegmentedControl<RecipeScope>
            size="sm"
            options={[
              { value: "global", label: "This machine" },
              {
                value: "project",
                label: "One project",
                disabled: projectBlocked !== "",
                disabledReason: projectBlocked || undefined,
              },
            ]}
            value={sel.scope}
            onChange={props.onScope}
          />
          {sel.scope === "project" && (
            <ComboChip
              label="Project"
              value={sel.projectRoot}
              onChange={props.onProject}
              options={projectOptions}
              popoverWidth={420}
              placeholder="Pick a project…"
            />
          )}
        </div>
      }
    >
      {props.loading ? (
        <InlineLoading label="Loading recipes" block />
      ) : !state ? (
        <div className="text-[11.5px] text-danger">{props.loadError || "Recipes are not available from this daemon."}</div>
      ) : sel.scope === "project" && !sel.projectRoot ? (
        <p className="py-2 text-[11.5px] text-fg-3" data-testid="recipes-pick-project">
          Pick a project above. A project recipe applies only to sessions in that project, and the agent cannot edit it.
        </p>
      ) : (
        <div className="space-y-5" data-testid="recipes-card">
          <CurrentState {...props} catalog={catalog} />
          {!props.removing && (
            <>
              <LevelPicker catalog={catalog} level={sel.level} onLevel={props.onLevel} />
              <PackPicker catalog={catalog} packs={sel.packs} onToggle={props.onTogglePack} />
            </>
          )}
          <PreviewPanel {...props} catalog={catalog} />
          <CustomiseSection {...props} catalog={catalog} />
        </div>
      )}
    </Card>
  );
}

function SectionTitle({ children }: { children: ReactNode }) {
  return <h4 className="mb-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">{children}</h4>;
}

function CurrentState(props: RecipesViewProps & { catalog: Recipe[] }) {
  const { state, applied, sel, catalog } = props;
  if (!state) return null;
  const line = appliedLine(applied, catalog);
  const via = appliedVia(applied?.meta.applied_via);
  const drift = sel.scope === "global" ? state.level_drift : (applied?.drift ?? "");
  return (
    <div className="rounded-2 border border-line-2 bg-bg-3 p-3 text-[11.5px]" data-testid="recipes-current">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-fg-3">{sel.scope === "global" ? "This machine:" : "This project:"}</span>
        {applied ? (
          <span className="font-medium text-fg-1">{line}</span>
        ) : (
          <span className="text-fg-2">no recipe applied</span>
        )}
        {applied?.meta.applied_at && (
          <span className="text-fg-3">
            applied {fmtDateTime(applied.meta.applied_at)}
            {via ? ` from ${via}` : ""}
          </span>
        )}
        {applied && !props.removing && (
          <span className="ml-auto">
            <Button size="sm" variant="secondary" disabled={props.busy !== null} onClick={props.onStartRemove}>
              Remove…
            </Button>
          </span>
        )}
      </div>
      {sel.scope === "global" && (
        <div className="mt-1 text-fg-3">
          Guard mode {modeLabel(state.mode)}, prompt guard {promptModeLabel(state.prompt_mode)}.
        </div>
      )}
      {applied && !applied.readable && <div className="mt-1 text-warn">The applied recipe file could not be read. Applying again writes a fresh one.</div>}
      {(applied?.updates ?? []).length > 0 && (
        <div className="mt-1 text-fg-2">Newer version available: {(applied?.updates ?? []).join(", ")}. Apply again to update.</div>
      )}
      {(applied?.missing ?? []).length > 0 && (
        <div className="mt-1 text-warn">No longer in the catalog: {(applied?.missing ?? []).join(", ")}. Remove it or apply another recipe.</div>
      )}
      {drift && <div className="mt-1 text-warn" data-testid="recipes-drift">{drift}</div>}
      {state.enabled === false && (
        <div className="mt-1 text-warn" data-testid="recipes-guard-off">
          {GUARD_OFF_NOTE} <NeedsSettingLink link={placeLink("guard_settings")} />
        </div>
      )}
      {(state.issues ?? []).map((i, n) => (
        <div key={n} className="mt-1 text-warn">
          {i}
        </div>
      ))}
    </div>
  );
}

function LevelPicker({ catalog, level, onLevel }: { catalog: Recipe[]; level: string; onLevel: (name: string) => void }) {
  const stops = levelStops(catalog);
  if (stops.length === 0) return null;
  const idx = stops.findIndex((s) => s.name === level);
  const noLevel = level === "";
  const balanced = Math.max(0, stops.findIndex((s) => s.name === "balanced"));
  const current = idx >= 0 ? stops[idx] : null;
  return (
    <div data-testid="recipes-level">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <SectionTitle>Level</SectionTitle>
        <Toggle on={noLevel} onChange={(on) => onLevel(on ? "" : stops[balanced].name)} label="No level (packs only)" />
      </div>
      <input
        type="range"
        min={0}
        max={stops.length - 1}
        step={1}
        value={idx >= 0 ? idx : balanced}
        aria-label="Level"
        aria-valuetext={current ? current.title || current.name : "No level"}
        data-level-state={noLevel ? "none" : "set"}
        onChange={(e) => onLevel(stops[Number(e.target.value)]?.name ?? "")}
        // With no level picked the thumb still has to sit somewhere, so it
        // waits at Balanced - but neutral (grey, faded), never in the accent
        // colour that reads as "Balanced is selected" (demo bug #9). Moving
        // it picks that level and turns the toggle off.
        className={clsx("w-full", noLevel ? "accent-fg-4 opacity-40 grayscale" : "accent-accent")}
      />
      {noLevel && <div className="mt-0.5 text-[11px] text-fg-3">No level selected: move the slider or pick one below to choose a level.</div>}
      <div className="mt-1 grid gap-1" style={{ gridTemplateColumns: `repeat(${stops.length}, minmax(0, 1fr))` }}>
        {stops.map((s) => (
          <button
            key={s.name}
            type="button"
            aria-pressed={s.name === level}
            onClick={() => onLevel(s.name)}
            className={clsx(
              "min-w-0 truncate rounded-1 px-1 py-0.5 text-center text-[11px]",
              s.name === level ? "bg-accent-soft font-semibold text-accent" : "text-fg-3 hover:text-fg-1",
            )}
            title={s.summary}
          >
            {s.title || s.name}
            {s.source === "user" ? " (yours)" : ""}
          </button>
        ))}
      </div>
      <p className="mt-1.5 text-[11.5px] text-fg-2" data-testid="recipes-level-summary">
        {current
          ? current.summary
          : "No level: the guard mode stays as it is, and only the packs you pick change rules."}
      </p>
    </div>
  );
}

function PackPicker({ catalog, packs, onToggle }: { catalog: Recipe[]; packs: string[]; onToggle: (name: string) => void }) {
  const choices = packChoices(catalog);
  if (choices.length === 0) return null;
  return (
    <div data-testid="recipes-packs">
      <SectionTitle>Packs</SectionTitle>
      <div className="flex flex-wrap gap-1.5">
        {choices.map((p) => {
          const on = packs.includes(p.name);
          return (
            <Tooltip key={p.name} content={p.summary || undefined}>
              <button
                type="button"
                aria-pressed={on}
                onClick={() => onToggle(p.name)}
                className={clsx(
                  "rounded-full border px-2.5 py-1 text-[11.5px]",
                  on ? "border-accent/50 bg-accent-soft font-medium text-accent" : "border-line-2 bg-bg-3 text-fg-2 hover:text-fg-1",
                )}
              >
                {p.title || p.name}
                {p.source === "user" ? " (yours)" : ""}
              </button>
            </Tooltip>
          );
        })}
      </div>
    </div>
  );
}

function DecisionPill({ d }: { d: string }) {
  return <Pill variant={decisionTone(d)}>{changeDecisionLabel(d)}</Pill>;
}

function PreviewPanel(props: RecipesViewProps & { catalog: Recipe[] }) {
  const { preview, sel, removing, catalog, busy } = props;
  const p = preview.data;
  const ready = removing || selectionReady(sel);
  const problems = p?.problems ?? [];
  const issues = p?.issues ?? [];
  const groups = groupChanges(p?.changes);
  const tally = changeTally(p?.changes);
  const moves = p ? configMoves(p, catalog) : [];
  const touchesNetwork = (p?.changes ?? []).some((c) => /^R-17[4-9]$/.test(c.rule_id));
  const blocked = scopeBlockedReason(props.state, sel.scope);
  const applyDisabled = !ready || !p || preview.loading || problems.length > 0 || busy !== null || (!removing && blocked !== "");
  const applyReason = !removing && blocked
    ? blocked
    : !ready
      ? "Pick a level or a pack first."
      : preview.loading || !p
        ? "Working out what changes."
        : problems.length > 0
          ? removing ? "Resolve the problems above first." : "Fix the problems above first."
          : undefined;

  return (
    <div className="space-y-3 border-t border-line-1 pt-3" data-testid="recipes-preview">
      <SectionTitle>{removing ? "What removing changes" : "What this changes"}</SectionTitle>
      {!ready ? (
        <p className="text-[11.5px] text-fg-3">Pick a level or at least one pack to see what changes.</p>
      ) : preview.error ? (
        <div className="text-[11.5px] text-danger">{preview.error}</div>
      ) : !p ? (
        <InlineLoading label="Working out what changes" block />
      ) : (
        <>
          <div className={clsx("space-y-2 text-[11.5px]", preview.loading && "opacity-60")}>
            <div className="font-medium text-fg-1" data-testid="recipes-count">
              {changeCountLine(p.changes)}
              {tally.tighter + tally.looser > 0 && (
                <span className="font-normal text-fg-3">
                  {" "}
                  ({[tally.tighter > 0 ? `${tally.tighter} stricter` : "", tally.looser > 0 ? `${tally.looser} looser` : ""].filter(Boolean).join(", ")})
                </span>
              )}
            </div>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5">
              {moves.map((m) => (
                <div key={m.label} className="contents">
                  <dt className="text-fg-3">{m.label}</dt>
                  <dd className={clsx("m-0", m.changed ? "font-medium text-fg-1" : "text-fg-3")}>
                    {m.changed ? (
                      <>
                        {m.before} <ArrowRight className="inline h-3 w-3 align-[-2px]" aria-label="to" /> {m.after}
                      </>
                    ) : (
                      `${m.after} (unchanged)`
                    )}
                  </dd>
                </div>
              ))}
            </dl>
            {p.mode_note && <p className="m-0 text-fg-2">{p.mode_note}</p>}
            {sel.scope === "project" && <p className="m-0 text-fg-3">{PROJECT_MODE_NOTE}</p>}
          </div>

          {problems.length > 0 && (
            <Callout tone="danger" title={removing ? "This cannot be removed yet" : "This cannot be applied yet"}>
              <ul className="m-0 list-disc space-y-0.5 pl-4" data-testid="recipes-problems">
                {problems.map((x, i) => (
                  <li key={i}>{x}</li>
                ))}
              </ul>
            </Callout>
          )}
          {issues.length > 0 && (
            <Callout tone={problems.length > 0 ? "info" : "warn"} title="Check before applying">
              <ul className="m-0 list-disc space-y-0.5 pl-4" data-testid="recipes-issues">
                {issues.map((x, i) => (
                  <li key={i}>{x}</li>
                ))}
              </ul>
            </Callout>
          )}

          {groups.length > 0 && (
            <div className="max-h-[320px] space-y-2 overflow-y-auto rounded-2 border border-line-1 p-2" data-testid="recipes-changes">
              {groups.map((g) => (
                <div key={g.category}>
                  <div className="mb-0.5 text-[11px] font-medium text-fg-2">{g.label}</div>
                  {g.changes.map((c) => {
                    const dir = changeDirection(c.before, c.after);
                    return (
                      <div key={c.rule_id} className="flex flex-wrap items-center gap-2 py-0.5 text-[11.5px]">
                        <span className="min-w-0 flex-1 truncate text-fg-1" title={c.doc || undefined}>
                          {changeRuleLabel(c)} <span className="font-mono text-[10.5px] text-fg-3">{c.rule_id}</span>
                        </span>
                        <DecisionPill d={c.before} />
                        <ArrowRight className="h-3 w-3 text-fg-3" aria-label="to" />
                        <DecisionPill d={c.after} />
                        <span className="w-[52px] text-right text-[10.5px] text-fg-3">{dir === "tighter" ? "stricter" : dir === "looser" ? "looser" : ""}</span>
                      </div>
                    );
                  })}
                </div>
              ))}
            </div>
          )}
          {touchesNetwork && <p className="m-0 text-[11px] text-fg-3">{NOT_A_FIREWALL_NOTE}</p>}

          {(p.advice ?? []).length > 0 && (
            <div className="text-[11.5px]">
              <div className="text-fg-3">Also worth doing:</div>
              <ul className="m-0 list-disc space-y-0.5 pl-4 text-fg-2" data-testid="recipes-advice">
                {(p.advice ?? []).map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
              </ul>
            </div>
          )}
          {(p.inputs ?? []).length > 0 && (
            <div className="text-[11.5px]">
              <div className="text-fg-3">These rules read settings you fill in:</div>
              <ul className="m-0 list-disc space-y-0.5 pl-4 text-fg-2" data-testid="recipes-inputs">
                {(p.inputs ?? []).map((k) => {
                  const inp = recipeInput(k);
                  return (
                    <li key={k}>
                      {inp.href ? (
                        <GatedLink to={inp.href} managed={<span title={k}>{inp.label}</span>} className="text-accent hover:underline" title={k}>
                          {inp.label}
                        </GatedLink>
                      ) : (
                        <span title={k}>{inp.label}</span>
                      )}
                      {inp.where && <span className="text-fg-3"> ({inp.where})</span>}
                    </li>
                  );
                })}
              </ul>
            </div>
          )}

          {p.text && (
            <InfoDisclosure summary="Show the file">
              <pre className="max-h-[320px] overflow-auto rounded-2 border border-line-2 bg-bg-2 p-2 font-mono text-[11px] leading-relaxed text-fg-1" data-testid="recipes-file">
                {p.text}
              </pre>
            </InfoDisclosure>
          )}

          <ReplayBlock {...props} />
        </>
      )}

      {props.writeError && <div className="whitespace-pre-line text-[11.5px] text-danger" data-testid="recipes-write-error">{props.writeError}</div>}
      <div className="flex flex-wrap items-center gap-2">
        {removing ? (
          <>
            <Button variant="danger-outline" disabled={applyDisabled} loading={busy === "remove"} onClick={props.onRemove} data-testid="recipes-remove">
              Remove recipe
            </Button>
            <Button variant="ghost" disabled={busy !== null} onClick={props.onCancelRemove}>
              Keep it
            </Button>
          </>
        ) : (
          <Button
            variant="primary"
            disabled={applyDisabled}
            loading={busy === "apply"}
            title={applyReason}
            onClick={props.onApply}
            data-testid="recipes-apply"
          >
            Apply recipe
          </Button>
        )}
        {applyReason && !removing && !preview.error && (
          <span className="text-[11px] text-fg-3">
            {applyReason}
            {blocked && (
              <>
                {" "}
                <NeedsSettingLink link={placeLink("guard_settings")} />
              </>
            )}
          </span>
        )}
      </div>
    </div>
  );
}

function ReplayBlock(props: RecipesViewProps) {
  const r = props.replay;
  return (
    <div className="space-y-1.5 text-[11.5px]" data-testid="recipes-replay">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-fg-3">Replay real actions:</span>
        {REPLAY_WINDOWS.map((w) => (
          <Button key={w.hours} size="sm" variant="secondary" loading={r?.loading && r.hours === w.hours} disabled={r?.loading} onClick={() => props.onReplay(w.hours)}>
            {w.label}
          </Button>
        ))}
      </div>
      {r?.loading && (
        <div className="space-y-1" role="status" aria-live="polite" data-testid="recipes-replay-progress">
          <p className="m-0 text-fg-3">
            {r.progress ? replayProgressText(r.progress) : "Starting the replay..."}
          </p>
          {r.progress && r.progress.total > 0 && !r.progress.queued && (
            <div className="h-1.5 w-full max-w-[520px] overflow-hidden rounded-2 bg-bg-3">
              <div
                className="h-full rounded-2 bg-accent transition-[width] duration-500"
                style={{ width: `${Math.min(100, (r.progress.evaluated / r.progress.total) * 100)}%` }}
              />
            </div>
          )}
        </div>
      )}
      {r?.error && <div className="text-danger">{r.error}</div>}
      {r?.data && (
        <>
          <p className="m-0 text-fg-1" data-testid="recipes-replay-line">
            {replaySentence(r.data, r.hours)}
          </p>
          {replayModeNote(r.data) && <p className="m-0 text-fg-3">{replayModeNote(r.data)}</p>}
          {topBlockingRules(r.data).length > 0 && (
            <table className="w-full max-w-[520px] text-left">
              <thead>
                <tr className="text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                  <th className="py-0.5 pr-3 font-medium">Rule</th>
                  <th className="py-0.5 pr-3 text-right font-medium">With this recipe</th>
                  <th className="py-0.5 text-right font-medium">Today</th>
                </tr>
              </thead>
              <tbody>
                {topBlockingRules(r.data).map((row) => (
                  <tr key={row.rule} className="border-t border-line-1/60">
                    <td className="py-0.5 pr-3">
                      {guardRuleName(row.rule) ?? row.rule} <span className="font-mono text-[10.5px] text-fg-3">{row.rule}</span>
                    </td>
                    <td className="py-0.5 pr-3 text-right tabular-nums">{row.after.toLocaleString()}</td>
                    <td className="py-0.5 text-right tabular-nums text-fg-3">{row.before.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}

function CustomiseSection(props: RecipesViewProps & { catalog: Recipe[] }) {
  const { catalog, busy } = props;
  const rows = [...levelStops(catalog), ...packChoices(catalog)];
  return (
    <div className="border-t border-line-1 pt-3" data-testid="recipes-customise">
      <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
        <SectionTitle>Customise</SectionTitle>
        <Button size="sm" variant="secondary" iconLeft={Upload} onClick={props.onImport}>
          Import a recipe
        </Button>
      </div>
      <p className="mb-1.5 text-[11px] text-fg-3">
        Duplicate a recipe to make it your own. Your recipes are saved on this machine and change no rule until you apply them.
      </p>
      <div className="divide-y divide-line-1/60 rounded-2 border border-line-1">
        {rows.map((r) => (
          <div key={r.name} className="flex flex-wrap items-center gap-2 px-2 py-1 text-[11.5px]">
            <span className="min-w-0 flex-1 truncate text-fg-1" title={r.summary}>
              {r.title || r.name}
            </span>
            <Pill variant="neutral">{r.kind === "level" ? "level" : "pack"}</Pill>
            <Pill variant={r.source === "user" ? "accent" : "neutral"}>{r.source === "user" ? "yours" : "built-in"}</Pill>
            <span className="w-[28px] text-right font-mono text-[10.5px] text-fg-3">v{r.version}</span>
            <RowActions
              menuLabel={`Actions for ${r.title || r.name}`}
              disabled={busy !== null}
              actions={[
                { id: "view", label: "View", icon: Eye, inline: true, onSelect: () => props.onView(r.name) },
                { id: "dup", label: "Duplicate and edit", icon: CopyPlus, inline: true, onSelect: () => props.onDuplicate(r.name) },
                { id: "copy", label: "Copy the file", onSelect: () => props.onExport(r.name, "copy") },
                { id: "download", label: "Download the file", icon: Download, onSelect: () => props.onExport(r.name, "download") },
                ...(r.source === "user"
                  ? [
                      {
                        id: "delete",
                        label: "Delete",
                        icon: Trash2,
                        destructive: true,
                        confirm: { label: "Delete for good", note: "A scope that applied it keeps its file until you remove it." },
                        onSelect: () => props.onDelete(r.name),
                      },
                    ]
                  : []),
              ]}
            />
          </div>
        ))}
      </div>
    </div>
  );
}
