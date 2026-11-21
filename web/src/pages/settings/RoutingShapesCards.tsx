import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Plus, Trash2 } from "lucide-react";
import {
  Button,
  Card,
  EntityMultiPicker,
  ErrorState,
  InlineLoading,
  Input,
  Pill,
  Select,
  SinglePicker,
  Table,
  Toggle,
  Tooltip,
} from "@/components/primitives";
import { fetchJSON } from "@/lib/api";
import { ConfigSaveCancelled, saveConfigSection } from "@/lib/configSectionSave";
import { apiErrorMessage } from "@/lib/enrolment";
import { keepSelected, type PickOption } from "@/lib/pickerOptions";
import { markRestartPending } from "@/lib/restartPending";
import { useApi } from "@/lib/useApi";
import { usePricedModels, useProjectRootOptions, useToolOptions } from "@/lib/usePickerSources";
import {
  BLANK,
  PROVIDER_CLASSES,
  SHAPE_BODY,
  budgetRows,
  checkBudgetScopes,
  checkFallbacks,
  checkLocalUpstreams,
  checkPathClasses,
  checkPrivacyRules,
  checkTiers,
  fallbackRows,
  pathClassRows,
  pathClassUses,
  privacyRows,
  projectNames,
  sameValue,
  tierOptions,
  tierRows,
  upstreamRows,
  type BudgetRow,
  type BudgetScopeKind,
  type FallbackRow,
  type PathClassRow,
  type PrivacyRow,
  type RoutingShapesWire,
  type TierRow,
  type UpstreamRow,
} from "@/lib/routingShapes";

// RoutingShapesCards - Settings > Routing editors for the [routing] shapes
// that used to be config-file-only: tier overrides, path classes, budget
// scopes, privacy rules, local upstreams and model fallbacks (dashboard CLI
// parity plan, section 9). Key pools are not here: they hold API keys, and
// secret keys never go over HTTP (decision P-4).
//
// Each card edits its rows, checks them with the pure model
// (lib/routingShapes.ts), and saves ONE Set* field through the routing
// section save: {...GET /api/config Routing, Set<Shape>: value} via
// saveConfigSection, which previews the exact file change, carries the
// confirm token and refuses a file changed since the preview. The daemon
// runs every check again (routing_shapes.go) and refuses with the file
// untouched. Routing binds at daemon start, so a save marks a restart
// pending, the same as the Custom rules card.

type ConfigEnvelope = { config: { Routing: RoutingShapesWire & Record<string, unknown> } };
type TiersResponse = { tiers: Record<string, string[] | null> | null };

const cellCls = "py-1.5 pr-2 align-top";
const headCls = "py-1.5 pr-2 font-medium";
const code = (s: string) => <code className="rounded-1 bg-bg-1 px-1 font-mono text-[10.5px]">{s}</code>;

/** tierSelectOptions: a "Pick a tier" prompt, the tiers, and the row's own
 *  value when it is none of them (a hand-edited file), so the select never
 *  shows a value it cannot explain. */
function tierSelectOptions(opts: { value: string; label: string }[], current: string): { value: string; label: string }[] {
  const extra = current && !opts.some((o) => o.value === current) ? [{ value: current, label: `${current} (not a tier)` }] : [];
  return [{ value: "", label: "Pick a tier" }, ...opts, ...extra];
}

/** saveRoutingShape writes one shape; false when the file already said it. */
async function saveRoutingShape(body: Record<string, unknown>, title: string): Promise<boolean> {
  const cur = await fetchJSON<ConfigEnvelope>("/api/config");
  const res = await saveConfigSection("routing", { ...cur.config.Routing, ...body }, { title });
  if (res.write_mode === "noop") return false;
  markRestartPending("routing");
  return true;
}

export function RoutingShapesCards({ readOnly }: { readOnly?: boolean }) {
  const cfg = useApi<ConfigEnvelope>("/api/config");
  const tiersApi = useApi<TiersResponse>("/api/routing/tiers");
  const priced = usePricedModels();
  const projects = useProjectRootOptions();
  const tools = useToolOptions();

  const rc = cfg.data?.config?.Routing ?? null;
  const reload = () => {
    cfg.reload();
    tiersApi.reload();
  };

  const tiers = useMemo(() => tierOptions(tiersApi.data?.tiers ?? null), [tiersApi.data]);
  const localModels = useMemo(
    () => (tiersApi.data?.tiers?.local ?? []).map((id) => ({ id, label: id, group: "In the local tier" })),
    [tiersApi.data],
  );
  const projectOpts = useMemo(() => projectNames(projects.options), [projects.options]);
  const savedClassNames = useMemo(() => Object.keys(rc?.PathClasses ?? {}).sort(), [rc]);

  const saved = useMemo(
    () => ({
      tiers: tierRows(rc),
      pathClasses: pathClassRows(rc),
      budgets: budgetRows(rc),
      privacy: privacyRows(rc),
      upstreams: upstreamRows(rc),
      fallbacks: fallbackRows(rc),
    }),
    [rc],
  );

  if (!rc) {
    if (cfg.error) {
      return (
        <div className="mt-4">
          <ErrorState title="Couldn't load the routing settings" error={cfg.error.message} onRetry={() => cfg.reload()} />
        </div>
      );
    }
    return <InlineLoading label="Loading routing settings" className="mt-4" />;
  }

  const modelOpts = (selected: readonly string[]): PickOption[] => keepSelected(priced.options, selected);
  const tierPickOpts: PickOption[] = tiers.map((o) => ({ ...o, group: "Tiers" }));

  return (
    <>
      <ShapeEditor<TierRow>
        title="Tier overrides"
        intro={
          <>
            Put a model in a different tier than the built-in table does. Routing compares tiers, so this decides
            which turns can move to or away from that model. Your overrides win over benchmark imports. The local
            tier is only for models a local upstream serves (privacy rules treat it as this machine), so add those
            under Local upstreams. In the file: {code("[routing.tiers]")}.
          </>
        }
        saved={saved.tiers}
        blank={BLANK.tier}
        body={SHAPE_BODY.tiers}
        check={(rows) => checkTiers(rows, rc)}
        readOnly={readOnly}
        onSaved={reload}
        addLabel="Add an override"
        saveLabel="Save tier overrides"
        empty="No overrides: every model sits in its built-in tier."
        head={
          <tr className="border-b border-line-2">
            <th className={headCls}>Model</th>
            <th className={headCls}>Tier</th>
          </tr>
        }
        renderRow={(r, set, disabled) => (
          <>
            <td className={`${cellCls} min-w-[16rem]`}>
              <SinglePicker
                value={r.model}
                onChange={(model) => set({ ...r, model })}
                options={modelOpts([r.model])}
                allowFree
                freeLabel="Use model"
                placeholder="Pick a model or family"
                loading={priced.loading}
                disabled={disabled}
                ariaLabel="Model"
              />
            </td>
            <td className={`${cellCls} min-w-[12rem]`}>
              <Select
                aria-label="Tier"
                value={r.tier}
                onChange={(e) => set({ ...r, tier: e.target.value })}
                disabled={disabled}
                options={tierSelectOptions(
                  tiers.map((o) => ({ value: o.id, label: o.sublabel ? `${o.label} (${o.sublabel})` : o.label })),
                  r.tier,
                )}
              />
            </td>
          </>
        )}
      />

      <ShapeEditor<PathClassRow>
        title="Path classes"
        intro={
          <>
            Name a group of file paths once, then use it in privacy rules and custom rules. A turn is in a class
            when its recent file actions touch a matching path. In a pattern, {code("*")} and {code("?")} match
            within one name, {code("**/")} in front matches at any depth, and {code("/**")} at the end matches
            everything under a folder. In the file: {code("[routing.path_classes]")}.
          </>
        }
        saved={saved.pathClasses}
        blank={BLANK.pathClass}
        body={SHAPE_BODY.pathClasses}
        check={(rows) => checkPathClasses(rows, rc)}
        readOnly={readOnly}
        onSaved={reload}
        addLabel="Add a class"
        saveLabel="Save path classes"
        empty="No path classes yet."
        head={
          <tr className="border-b border-line-2">
            <th className={headCls}>Name</th>
            <th className={headCls}>Path patterns</th>
            <th className={headCls}>Used by</th>
          </tr>
        }
        renderRow={(r, set, disabled) => {
          const uses = pathClassUses(rc).filter((u) => u.name === r.name.trim());
          return (
            <>
              <td className={`${cellCls} w-[11rem]`}>
                <Input
                  mono
                  aria-label="Class name"
                  value={r.name}
                  placeholder="secrets"
                  onChange={(e) => set({ ...r, name: e.target.value })}
                  disabled={disabled}
                />
              </td>
              <td className={`${cellCls} min-w-[18rem]`}>
                <EntityMultiPicker
                  options={r.patterns.map((p) => ({ id: p, label: p }))}
                  value={r.patterns}
                  onChange={(patterns) => set({ ...r, patterns })}
                  allowFreeId
                  freeIdLabel="Add pattern"
                  placeholder="Type a pattern, then Enter (**/*.pem)"
                  emptyHint="Type a pattern such as **/*.pem or infra/**, then press Enter."
                  disabled={disabled}
                  ariaLabel="Path patterns"
                />
              </td>
              <td className={`${cellCls} text-fg-3`}>{uses.length ? uses.map((u) => u.by).join(", ") : "not used yet"}</td>
            </>
          );
        }}
      />

      <ShapeEditor<BudgetRow>
        title="Budget scopes"
        intro={
          <>
            Give a scope a spend limit over a rolling window. As spending passes each band (a share of the limit),
            routing moves softer turns to cheaper tiers. At the limit it does what When used up says: only advising
            never caps live traffic, so pick Move every turn for a limit that bites. Routing never blocks a request
            itself, and in advise mode it only records what it would do. Leave Bands empty for 0.5, 0.8, 0.95. In
            the file: {code("[[routing.budget.scopes]]")}.
          </>
        }
        saved={saved.budgets}
        blank={BLANK.budget}
        body={SHAPE_BODY.budgetScopes}
        check={checkBudgetScopes}
        readOnly={readOnly}
        onSaved={reload}
        addLabel="Add a budget"
        saveLabel="Save budget scopes"
        empty="No routing budgets."
        minWidth={860}
        head={
          <tr className="border-b border-line-2">
            <th className={headCls}>Applies to</th>
            <th className={headCls}>Limit (USD)</th>
            <th className={headCls}>Window</th>
            <th className={headCls}>Bands</th>
            <th className={headCls}>When used up</th>
          </tr>
        }
        renderRow={(r, set, disabled) => (
          <>
            <td className={`${cellCls} min-w-[16rem]`}>
              <div className="flex flex-col gap-1">
                <Select
                  aria-label="Applies to"
                  value={r.kind}
                  onChange={(e) => set({ ...r, kind: e.target.value as BudgetScopeKind, target: "" })}
                  disabled={disabled}
                  options={[
                    { value: "global", label: "Everything" },
                    { value: "project", label: "One project" },
                    { value: "tool", label: "One AI tool" },
                    { value: "tier", label: "One tier" },
                  ]}
                />
                {r.kind === "project" && (
                  <SinglePicker
                    value={r.target}
                    onChange={(target) => set({ ...r, target })}
                    options={keepSelected(projectOpts, [r.target])}
                    allowFree
                    freeLabel="Use project"
                    placeholder="Pick a project"
                    loading={projects.loading}
                    disabled={disabled}
                    ariaLabel="Project"
                  />
                )}
                {r.kind === "tool" && (
                  <SinglePicker
                    value={r.target}
                    onChange={(target) => set({ ...r, target })}
                    options={keepSelected(tools.options, [r.target])}
                    allowFree
                    freeLabel="Use tool"
                    placeholder="Pick an AI tool"
                    loading={tools.loading}
                    disabled={disabled}
                    ariaLabel="AI tool"
                  />
                )}
                {r.kind === "tier" && (
                  <Select
                    aria-label="Tier"
                    value={r.target}
                    onChange={(e) => set({ ...r, target: e.target.value })}
                    disabled={disabled}
                    options={tierSelectOptions(
                      tiers.map((o) => ({ value: o.id, label: o.label })),
                      r.target,
                    )}
                  />
                )}
              </div>
            </td>
            <td className={`${cellCls} w-[7rem]`}>
              <Input
                mono
                type="number"
                min="0"
                step="1"
                aria-label="Limit in US dollars"
                value={r.limit}
                placeholder="100"
                onChange={(e) => set({ ...r, limit: e.target.value })}
                disabled={disabled}
              />
            </td>
            <td className={`${cellCls} w-[9rem]`}>
              <Select
                aria-label="Window"
                value={r.window}
                onChange={(e) => set({ ...r, window: e.target.value })}
                disabled={disabled}
                options={[
                  { value: "day", label: "Rolling day" },
                  { value: "week", label: "Rolling week" },
                  { value: "month", label: "Rolling month" },
                ]}
              />
            </td>
            <td className={`${cellCls} w-[9rem]`}>
              <Input
                mono
                aria-label="Bands"
                value={r.bands}
                placeholder="0.5, 0.8, 0.95"
                onChange={(e) => set({ ...r, bands: e.target.value })}
                disabled={disabled}
              />
            </td>
            <td className={`${cellCls} min-w-[13rem]`}>
              <Select
                aria-label="When used up"
                value={r.exhausted}
                onChange={(e) => set({ ...r, exhausted: e.target.value })}
                disabled={disabled}
                options={[
                  { value: "", label: "Default: only advise" },
                  { value: "advise_only", label: "Only advise" },
                  { value: "degrade_all", label: "Move every turn to a cheaper tier" },
                  { value: "hard_stop", label: "Hard stop: move every turn, record a stop" },
                ]}
              />
            </td>
          </>
        )}
      />

      <ShapeEditor<PrivacyRow>
        title="Privacy rules"
        intro={
          <>
            Keep a project&apos;s or a path class&apos;s turns away from providers. Keep on local models allows only
            your local upstreams; otherwise list providers to block, and {code("*")} in the block list blocks
            every provider not in the allow list. A project is matched by its folder name; with both a project and
            a path class, a turn must match both. Privacy rules run before any custom rule, so no rule can skip
            them. Provider names: anthropic, openai, google, local, or a router prefix such as openrouter. In the
            file: {code("[[routing.privacy.rules]]")}.
          </>
        }
        saved={saved.privacy}
        blank={BLANK.privacy}
        body={SHAPE_BODY.privacyRules}
        check={(rows) => checkPrivacyRules(rows, rc)}
        readOnly={readOnly}
        onSaved={reload}
        addLabel="Add a privacy rule"
        saveLabel="Save privacy rules"
        empty="No privacy rules: every provider is allowed for every project."
        minWidth={900}
        head={
          <tr className="border-b border-line-2">
            <th className={headCls}>Project</th>
            <th className={headCls}>Path class</th>
            <th className={headCls}>Local models only</th>
            <th className={headCls}>Block these providers</th>
            <th className={headCls}>Always allow</th>
          </tr>
        }
        renderRow={(r, set, disabled) => (
          <>
            <td className={`${cellCls} min-w-[11rem]`}>
              <SinglePicker
                value={r.project}
                onChange={(project) => set({ ...r, project })}
                options={keepSelected(projectOpts, [r.project])}
                allowFree
                freeLabel="Use project"
                placeholder="Any project"
                loading={projects.loading}
                disabled={disabled}
                ariaLabel="Project"
              />
            </td>
            <td className={`${cellCls} min-w-[10rem]`}>
              <SinglePicker
                value={r.pathClass}
                onChange={(pathClass) => set({ ...r, pathClass })}
                options={keepSelected(
                  savedClassNames.map((id) => ({ id, label: id })),
                  [r.pathClass],
                  "Not saved under Path classes",
                )}
                placeholder="Any path"
                emptyHint="Save a class under Path classes first."
                disabled={disabled}
                ariaLabel="Path class"
              />
            </td>
            <td className={cellCls}>
              <Toggle
                on={r.localOnly}
                onChange={(localOnly) => set({ ...r, localOnly })}
                disabled={disabled}
                ariaLabel="Local models only"
              />
            </td>
            <td className={`${cellCls} min-w-[12rem]`}>
              <Tooltip content="Local models only already blocks every other provider." disabled={!r.localOnly}>
                <div>
                  <EntityMultiPicker
                    options={keepSelected(
                      [
                        { id: "*", label: "Every provider not allowed", sublabel: "*" },
                        ...PROVIDER_CLASSES.map((id) => ({ id, label: id })),
                      ],
                      r.deny,
                    )}
                    value={r.deny}
                    onChange={(deny) => set({ ...r, deny })}
                    allowFreeId
                    freeIdLabel="Block"
                    placeholder="None"
                    disabled={disabled || r.localOnly}
                    ariaLabel="Block these providers"
                  />
                </div>
              </Tooltip>
            </td>
            <td className={`${cellCls} min-w-[12rem]`}>
              <EntityMultiPicker
                options={keepSelected(
                  PROVIDER_CLASSES.map((id) => ({ id, label: id })),
                  r.allow,
                )}
                value={r.allow}
                onChange={(allow) => set({ ...r, allow })}
                allowFreeId
                freeIdLabel="Allow"
                placeholder="None"
                disabled={disabled || r.localOnly}
                ariaLabel="Always allow these providers"
              />
            </td>
          </>
        )}
      />

      <ShapeEditor<UpstreamRow>
        title="Local upstreams"
        intro={
          <>
            Add an Ollama, LM Studio or vLLM endpoint as a routing target. Its models join the local tier, and when
            routing picks one, the request goes to this address in the OpenAI wire format. Any host works: a
            loopback address (localhost, 127.0.0.1) keeps your prompts on this machine; any other address sends
            them to that machine, so use one you control, over https when it is not on your own network. The
            address takes no user name or password. In the file: {code("[[routing.local_upstreams]]")}.
          </>
        }
        saved={saved.upstreams}
        blank={BLANK.upstream}
        body={SHAPE_BODY.localUpstreams}
        check={(rows) => checkLocalUpstreams(rows, rc)}
        readOnly={readOnly}
        onSaved={reload}
        addLabel="Add an endpoint"
        saveLabel="Save local upstreams"
        empty="No local endpoints."
        minWidth={820}
        head={
          <tr className="border-b border-line-2">
            <th className={headCls}>Name</th>
            <th className={headCls}>Address</th>
            <th className={headCls}>Models it serves</th>
          </tr>
        }
        renderRow={(r, set, disabled) => (
          <>
            <td className={`${cellCls} w-[10rem]`}>
              <Input
                mono
                aria-label="Endpoint name"
                value={r.name}
                placeholder="ollama"
                onChange={(e) => set({ ...r, name: e.target.value })}
                disabled={disabled}
              />
            </td>
            <td className={`${cellCls} min-w-[16rem]`}>
              <Input
                mono
                aria-label="Endpoint address"
                value={r.baseURL}
                placeholder="http://localhost:11434/v1"
                onChange={(e) => set({ ...r, baseURL: e.target.value })}
                disabled={disabled}
              />
            </td>
            <td className={`${cellCls} min-w-[16rem]`}>
              <EntityMultiPicker
                options={keepSelected(localModels, r.models, "Typed here")}
                value={r.models}
                onChange={(models) => set({ ...r, models })}
                allowFreeId
                freeIdLabel="Add model"
                placeholder="Type a model id, then Enter (qwen3:32b)"
                disabled={disabled}
                ariaLabel="Models it serves"
              />
            </td>
          </>
        )}
      />

      <ShapeEditor<FallbackRow>
        title="Model fallbacks"
        intro={
          <>
            When a model answers with a rate limit (429), a server error (5xx) or a timeout, try the next model in
            its chain. Start a chain from one model or from a whole tier; a model&apos;s own chain wins over its
            tier&apos;s. Chains stay within one provider&apos;s request format. Models are tried in the order you
            add them. In the file: {code("[routing.reliability.fallbacks]")}.
          </>
        }
        saved={saved.fallbacks}
        blank={BLANK.fallback}
        body={SHAPE_BODY.fallbacks}
        check={checkFallbacks}
        readOnly={readOnly}
        onSaved={reload}
        addLabel="Add a chain"
        saveLabel="Save model fallbacks"
        empty="No fallback chains."
        head={
          <tr className="border-b border-line-2">
            <th className={headCls}>When this fails</th>
            <th className={headCls}>Try these, in order</th>
          </tr>
        }
        renderRow={(r, set, disabled) => (
          <>
            <td className={`${cellCls} min-w-[15rem]`}>
              <SinglePicker
                value={r.from}
                onChange={(from) => set({ ...r, from })}
                options={keepSelected([...tierPickOpts, ...priced.options.map((o) => ({ ...o, group: "Models" }))], [r.from])}
                allowFree
                freeLabel="Use"
                placeholder="Pick a model or tier"
                loading={priced.loading}
                disabled={disabled}
                ariaLabel="Model or tier"
              />
            </td>
            <td className={`${cellCls} min-w-[20rem]`}>
              <EntityMultiPicker
                options={modelOpts(r.chain)}
                value={r.chain}
                onChange={(chain) => set({ ...r, chain })}
                allowFreeId
                freeIdLabel="Add model"
                placeholder="Add fallback models in order"
                loading={priced.loading}
                disabled={disabled}
                ariaLabel="Fallback models"
              />
            </td>
          </>
        )}
      />
    </>
  );
}

// ShapeEditor is one card: a table of rows with add, edit and remove, the
// live problem list, and its own Save. Rows carry a stable key so removing
// one never hands its picker state to the next.
type Keyed<R> = { k: number; r: R };

function ShapeEditor<R>({
  title,
  intro,
  saved,
  blank,
  body,
  check,
  readOnly,
  onSaved,
  addLabel,
  saveLabel,
  empty,
  head,
  renderRow,
  minWidth,
}: {
  title: string;
  intro: ReactNode;
  saved: R[];
  blank: () => R;
  body: (rows: readonly R[]) => Record<string, unknown>;
  check: (rows: readonly R[]) => string[];
  readOnly?: boolean;
  onSaved: () => void;
  addLabel: string;
  saveLabel: string;
  empty: string;
  head: ReactNode;
  renderRow: (row: R, set: (next: R) => void, disabled: boolean) => ReactNode;
  minWidth?: number;
}) {
  const [draft, setDraft] = useState<Keyed<R>[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState<"" | "saved" | "noop">("");
  const nextKey = useRef(1_000_000);

  const savedKeyed = useMemo(() => saved.map((r, k) => ({ k, r })), [saved]);
  const rows = draft ?? savedKeyed;
  const plain = rows.map((x) => x.r);
  const value = body(plain);
  const dirty = draft !== null && !sameValue(value, body(saved));
  const problems = check(plain);

  // Once the reload after this card's own save brings the file's rows back
  // equal to the draft, drop the draft. A reload from another card's save
  // leaves an unsaved draft alone.
  useEffect(() => {
    if (draft !== null && status === "saved" && sameValue(body(draft.map((x) => x.r)), body(saved))) setDraft(null);
  }, [saved, draft, status, body]);

  const update = (next: Keyed<R>[]) => {
    setDraft(next);
    setStatus("");
    setError("");
  };

  const save = async () => {
    setBusy(true);
    setError("");
    try {
      const wrote = await saveRoutingShape(value, saveLabel);
      setStatus(wrote ? "saved" : "noop");
      onSaved();
    } catch (e) {
      if (!(e instanceof ConfigSaveCancelled)) setError(apiErrorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const disabled = Boolean(readOnly) || busy;
  return (
    <Card className="mt-4 text-[11.5px]">
      <div className="text-[12px] font-semibold text-fg-1">{title}</div>
      <p className="m-0 mt-0.5 text-fg-3">{intro}</p>
      {rows.length === 0 ? (
        <p className="m-0 mt-3 rounded-2 border border-dashed border-line-2 bg-bg-3/40 px-3 py-2 text-fg-3">{empty}</p>
      ) : (
        <Table className="mt-3" minWidth={minWidth} head={head}>
          {rows.map((x) => (
            <tr key={x.k} className="border-b border-line-1 last:border-b-0">
              {renderRow(x.r, (next) => update(rows.map((y) => (y.k === x.k ? { k: x.k, r: next } : y))), disabled)}
              <td className={`${cellCls} w-8 text-right`}>
                <Tooltip content="Remove this row">
                  <Button
                    variant="ghost"
                    size="sm"
                    iconLeft={Trash2}
                    aria-label="Remove this row"
                    onClick={() => update(rows.filter((y) => y.k !== x.k))}
                    disabled={disabled}
                    className="!px-1.5 hover:!text-danger"
                  />
                </Tooltip>
              </td>
            </tr>
          ))}
        </Table>
      )}

      {problems.length > 0 && (
        <div className="mt-2 space-y-0.5 text-danger">
          {problems.map((p, i) => (
            <div key={i}>{p}</div>
          ))}
        </div>
      )}
      {error && <p className="m-0 mt-2 text-danger">{error}</p>}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button
          size="sm"
          iconLeft={Plus}
          onClick={() => update([...rows, { k: nextKey.current++, r: blank() }])}
          disabled={disabled}
        >
          {addLabel}
        </Button>
        <Button
          variant="primary"
          onClick={save}
          disabled={disabled || !dirty || problems.length > 0 || status === "saved"}
          loading={busy}
          title={readOnly ? "Managed by your organization" : undefined}
        >
          {saveLabel}
        </Button>
        {dirty && status !== "saved" && (
          <Button
            variant="ghost"
            onClick={() => {
              setDraft(null);
              setError("");
            }}
            disabled={disabled}
          >
            Undo changes
          </Button>
        )}
        {status === "saved" && <Pill variant="warn">saved - applies after a restart (Restart now in the banner)</Pill>}
        {status === "noop" && <span className="text-fg-3">Nothing to change: the file already says that.</span>}
      </div>
    </Card>
  );
}
