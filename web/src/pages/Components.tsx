import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ChevronLeft } from "lucide-react";
import { navIcon } from "@/lib/nav";
import { Button, Card, EmptyState, Icon, PageHeader, Pill, SegmentedControl } from "@/components/primitives";
import { componentsErrorText, componentsPost } from "@/lib/componentsApi";
import { componentRequestLink } from "@/lib/requestEntry";
import { HIGHLIGHT_CLASS } from "@/lib/scrollHighlight";
import { useScrollHighlight } from "@/lib/useScrollHighlight";
import { isInAppLink, teardownLinkText } from "@/lib/setupExtras";
import { useComponentCatalog, useComponentState } from "@/lib/useComponents";
import { useApi } from "@/lib/useApi";
import { APPS_STATUS_PATH, type FirstRunApps } from "@/lib/firstRun";
import { hotEnabledPending } from "@/lib/planeaFirstRun";
import {
  ARTIFACT_STATE_LABEL,
  BADGE_LABEL,
  BADGE_TONE,
  COMPONENT_GROUPS,
  artifactWarns,
  badgeFor,
  componentRowAnchor,
  distrosWith,
  groupOf,
  manifestFor,
  selectionSentence,
  stateCopy,
  verdictCopy,
  type ArtifactStatus,
  type CatalogComponent,
  type ComponentRowState,
  type ComponentVerdict,
} from "@/lib/componentState";

// Settings > Components (modular packaging plan 7.2, lane MP-DASH): what
// Observer runs on this machine, one row per catalog component, each with
// its level badge, its "What this adds" disclosure (entirely from the
// catalog) and the one action valid for its state. Every change goes
// preview first, then confirm, through the same service `observer
// components` runs (internal/componentsvc): the page never writes a
// selection the operator did not see, and never calls an inactive component
// "removed" (it is installed but inert until a restart applies it).

type Preview = {
  activated: string[];
  deactivated: string[];
  cascade: string[];
  teardown: { component: string; kind: string; tool?: string; what: string; command?: string; link?: string; link_label?: string }[];
  refused: string[];
  issues: string[];
  restart_required: boolean;
  fingerprint: string;
  no_change: boolean;
};

type Change = { set_base?: string; add?: string[]; remove?: string[] };

type PurgePlan = { id: string; component: string; expires_at: string; counts: Record<string, number> };

type Pending =
  | { kind: "change"; change: Change; preview: Preview; deleteData: string | null }
  | { kind: "purge"; plan: PurgePlan }
  | null;

const BASES = ["all", "minimal", "developer", "managed", "full"] as const;

// The page's writes are lib/componentsApi's, the same calls a card's Turn it
// on button sends (ruling SBXD-9).
const post = componentsPost;
const errText = componentsErrorText;

export function ComponentsPage() {
  const [params] = useSearchParams();
  const focus = params.get("component") ?? "";
  const st = useComponentState();
  const cat = useComponentCatalog();
  const [pending, setPending] = useState<Pending>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const view = st.data?.view;
  // AI Apps turned on in the running daemon (POLISH-F1 hot enable): the
  // component set was recorded at start, so its activation would still read
  // as waiting for a restart. While AI Apps is on, that row is not pending.
  const appsOn = useApi<FirstRunApps, boolean>(APPS_STATUS_PATH, undefined, [], { select: (a) => a.on === true }).data ?? false;
  const restartPending = (st.data?.pending ?? []).filter((p) => !hotEnabledPending(p, appsOn));
  const rows = useMemo(() => {
    const byId = new Map<string, ComponentRowState>((view?.components ?? []).map((r) => [r.id, r]));
    return (cat.data?.components ?? [])
      .map((c) => ({ c, s: byId.get(c.id) }))
      .filter((x): x is { c: CatalogComponent; s: ComponentRowState } => !!x.s);
  }, [cat.data, view]);

  const preview = async (change: Change, deleteData: string | null = null) => {
    setBusy(true);
    setErr(null);
    setNotice(null);
    try {
      const p = await post<Preview>("/api/components/preview", { change });
      setPending({ kind: "change", change, preview: p, deleteData });
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const apply = async (skipTeardown: boolean) => {
    if (pending?.kind !== "change") return;
    setBusy(true);
    setErr(null);
    try {
      await post("/api/components/apply", {
        change: pending.change,
        fingerprint: pending.preview.fingerprint,
        skip_teardown: skipTeardown,
      });
      const del = pending.deleteData;
      setPending(null);
      setNotice(`Applied. ${view?.restart_note ?? ""}`);
      st.reload();
      if (del) await purgePreview(del);
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const purgePreview = async (component: string) => {
    setBusy(true);
    setErr(null);
    try {
      const plan = await post<PurgePlan>("/api/components/purge/preview", { component });
      setPending({ kind: "purge", plan });
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const purgeExecute = async () => {
    if (pending?.kind !== "purge") return;
    setBusy(true);
    setErr(null);
    try {
      const res = await post<{ deleted: Record<string, number> }>("/api/components/purge/execute", {
        plan_id: pending.plan.id,
      });
      const n = Object.values(res.deleted ?? {}).reduce((a, b) => a + b, 0);
      setPending(null);
      setNotice(`Deleted ${n} local rows. Nothing was sent to your organization.`);
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const downloadManifest = () => {
    if (!view) return;
    const blob = new Blob([manifestFor(view)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "observer-components.json";
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div className="flex flex-col gap-5 p-4 sm:p-6" data-testid="components-page">
      <Link to="/settings" className="inline-flex w-fit items-center gap-1 text-small text-fg-3 hover:text-fg-1">
        <Icon icon={ChevronLeft} size={12} /> Settings
      </Link>
      <PageHeader
        title="Components"
        icon={navIcon("settings")}
        sub="What Observer runs on this machine. An inactive component stays in this build but starts nothing: no listener, no network, no changes to your tools."
        right={
          view ? (
            <Button size="sm" onClick={downloadManifest}>
              Download component manifest
            </Button>
          ) : undefined
        }
      />
      {st.data && !st.data.wired && (
        <EmptyState
          variant="inline"
          title="This dashboard cannot change components"
          body="It has no component service. Open the dashboard of `observer start`, or use Settings > Components there."
        />
      )}
      {view && (
        <Card>
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-small text-fg-2">
            <span>
              Build: <strong className="text-fg-1">{view.binary_distro}</strong>
            </span>
            <span>
              {view.active_count} of {view.compiled_count} compiled components active
            </span>
            <span className="text-fg-3">Signature: not signed (vendor-signed builds arrive with the signed distros)</span>
            <span className="font-mono text-caption text-fg-3">digest {view.components_digest.slice(0, 12)}</span>
            <a
              className="rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-caption text-accent hover:border-line-3"
              href="/api/components/sbom"
              download
              title="CycloneDX software bill of materials of this binary: every Go module it links, its build, tags and components digest"
            >
              Download SBOM
            </a>
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <span className="text-small text-fg-3">Base selection</span>
            <SegmentedControl
              size="sm"
              value={view.base as (typeof BASES)[number]}
              onChange={(b) => void preview({ set_base: b })}
              options={BASES.map((b) => ({ value: b, label: b === "all" ? "Everything in this build" : b }))}
            />
          </div>
          {/* Who decides this machine's components and how many are active
              (lib/componentState SELECTION_RULES): with no selection
              recorded, the build's own defaults decide. */}
          <p
            role={view.org_managed ? "status" : undefined}
            className={`mt-2 text-small ${view.org_managed ? "text-fg-2" : "text-fg-3"}`}
            data-testid="components-selection"
          >
            {selectionSentence(view)}
          </p>
          {restartPending.length > 0 && (
            <p role="status" className="mt-2 text-small text-fg-2">
              {view.restart_note}
            </p>
          )}
          {view.issues.length > 0 && (
            <ul className="mt-2 list-disc pl-5 text-small text-fg-2">
              {view.issues.map((i) => (
                <li key={i}>{i}</li>
              ))}
            </ul>
          )}
        </Card>
      )}

      {err && (
        <p role="alert" className="text-small text-danger">
          {err}
        </p>
      )}
      {notice && (
        <p role="status" className="text-small text-fg-2">
          {notice}
        </p>
      )}
      {pending?.kind === "change" && (
        <PreviewCard
          preview={pending.preview}
          deleteData={pending.deleteData}
          busy={busy}
          onApply={apply}
          onCancel={() => setPending(null)}
        />
      )}
      {pending?.kind === "purge" && (
        <Card title="Delete this component's data" tone="danger">
          <p className="text-small text-fg-2">
            These local rows are deleted once you confirm (plan {pending.plan.id}, valid until{" "}
            {new Date(pending.plan.expires_at).toLocaleTimeString()}). Rows that arrive after this preview are not
            touched. Nothing already sent to your organization is deleted.
          </p>
          <ul className="mt-2 text-small text-fg-1">
            {Object.entries(pending.plan.counts).map(([t, n]) => (
              <li key={t} className="font-mono">
                {t}: {n}
              </li>
            ))}
          </ul>
          <div className="mt-3 flex gap-2">
            <Button variant="danger" size="sm" disabled={busy} onClick={() => void purgeExecute()}>
              Delete these rows
            </Button>
            <Button size="sm" disabled={busy} onClick={() => setPending(null)}>
              Keep the data
            </Button>
          </div>
        </Card>
      )}

      {COMPONENT_GROUPS.map((g) => {
        const items = rows.filter((r) => groupOf(r.c) === g.id);
        if (items.length === 0) return null;
        return (
          <Card key={g.id} title={g.label}>
            <ul className="divide-y divide-line-1">
              {items.map(({ c, s }) => (
                <ComponentRow
                  key={c.id}
                  c={c}
                  s={s}
                  open={focus === c.id}
                  badge={badgeFor(s, restartPending)}
                  purgeable={st.data?.purgeable.includes(c.id) ?? false}
                  verdict={st.data?.feasibility?.find((v) => v.id === c.id)}
                  disabled={busy || !st.data?.wired}
                  onAdd={() => void preview({ add: [c.id] })}
                  onRemove={(del) => void preview({ remove: [c.id] }, del ? c.id : null)}
                  onPurge={() => void purgePreview(c.id)}
                />
              ))}
            </ul>
          </Card>
        );
      })}

      {cat.data?.artifact_states && cat.data.artifact_states.length > 0 && (
        <ArtifactStatesCard states={cat.data.artifact_states} />
      )}
    </div>
  );
}

// ArtifactStatesCard shows what Observer can observe about the components
// that ship separately (browser and VS Code extensions, plugin shims,
// helpers; T-707): the same states `observer components artifacts` prints.
// Observer never installs or removes these, so there is no action here, only
// the remedy text when one applies.
function ArtifactStatesCard({ states }: { states: ArtifactStatus[] }) {
  return (
    <Card title="Separately installed">
      <p className="text-small text-fg-3">
        These ship apart from the observer binary, so Observer observes them and never installs or removes them. Not
        detected means Observer cannot see it, not that it is absent.
      </p>
      <ul className="mt-2 divide-y divide-line-1" data-testid="artifact-states">
        {states.map((s) => (
          <li key={s.id} className="flex flex-col gap-1 py-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-small text-fg-1">{s.id}</span>
              <Pill variant={artifactWarns(s) ? "warn" : s.state === "connected" || s.state === "installed" ? "success" : "neutral"}>
                {ARTIFACT_STATE_LABEL[s.state] ?? s.state}
                {s.leftover ? ", leftover" : ""}
              </Pill>
              {s.version && <span className="text-caption text-fg-3">{s.version}</span>}
            </div>
            {s.detail && <p className="text-small text-fg-2">{s.detail}</p>}
            {s.remedy && <p className="text-small text-fg-3">Fix: {s.remedy}</p>}
            {s.items && s.items.length > 0 && (
              <ul className="pl-4 text-caption text-fg-3">
                {s.items.map((it) => (
                  <li key={it.name}>
                    {it.name}: {it.state}
                    {it.version ? ` ${it.version}` : ""}
                    {it.detail ? `, ${it.detail}` : ""}
                  </li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ul>
    </Card>
  );
}

function PreviewCard({
  preview,
  deleteData,
  busy,
  onApply,
  onCancel,
}: {
  preview: Preview;
  deleteData: string | null;
  busy: boolean;
  onApply: (skipTeardown: boolean) => void;
  onCancel: () => void;
}) {
  const [undoWrites, setUndoWrites] = useState(true);
  // D-514: a preview where every part was refused cannot be applied; the
  // button says why and Cancel becomes Back to the selection.
  const onlyRefused =
    !preview.no_change &&
    (preview.refused?.length ?? 0) > 0 &&
    (preview.activated?.length ?? 0) === 0 &&
    (preview.deactivated?.length ?? 0) === 0;
  const list = (label: string, xs: string[]) =>
    xs.length > 0 && (
      <p className="text-small text-fg-2">
        {label}: <span className="font-mono text-fg-1">{xs.join(", ")}</span>
      </p>
    );
  return (
    <Card title="Preview" tone="featured">
      {preview.no_change ? (
        <p className="text-small text-fg-2">Nothing changes.</p>
      ) : (
        <div className="flex flex-col gap-1">
          {list("Becomes active", preview.activated)}
          {list("Becomes inactive", preview.deactivated)}
          {list("Also inactive (they need it)", preview.cascade)}
          {list("Refused", preview.refused)}
          {list("Selection problems", preview.issues)}
          {preview.teardown.length > 0 && (
            <div className="mt-1">
              <p className="text-small text-fg-2">Undo what they wrote into other tools, in this order:</p>
              <ol className="list-decimal pl-5 text-small text-fg-1">
                {preview.teardown.map((t, i) => (
                  <li key={i}>
                    {t.what}
                    {isInAppLink(t.link) && (
                      <>
                        {" "}
                        <Link className="text-accent hover:underline" to={t.link}>
                          {teardownLinkText(t.link_label)}
                        </Link>
                      </>
                    )}
                    {t.command && (
                      <span className="font-mono text-fg-3">
                        {" "}
                        ({isInAppLink(t.link) ? "command line: " : ""}
                        {t.command})
                      </span>
                    )}
                  </li>
                ))}
              </ol>
              <label className="mt-1 flex items-center gap-2 text-small text-fg-2">
                <input type="checkbox" checked={undoWrites} onChange={(e) => setUndoWrites(e.target.checked)} />
                Undo the automatic steps now (a step with a link is finished from that page; otherwise the writes stay as they are)
              </label>
            </div>
          )}
          {preview.restart_required && (
            <p className="text-small text-fg-3">
              New commands follow at once; the daemon's background work follows after the next restart.
            </p>
          )}
          {deleteData && (
            <p className="text-small text-fg-2">After this, you will see the rows that would be deleted before anything is.</p>
          )}
        </div>
      )}
      {onlyRefused && (
        <p className="mt-2 text-small text-warn" role="status">
          Nothing in this change can be applied here; the Refused line says why. Go back and change the selection.
        </p>
      )}
      <div className="mt-3 flex gap-2">
        <Button
          variant="primary"
          size="sm"
          disabled={busy || preview.no_change || onlyRefused}
          title={onlyRefused ? "Every part of this change was refused; see the reasons above." : undefined}
          onClick={() => onApply(!undoWrites)}
        >
          Apply
        </Button>
        <Button size="sm" disabled={busy} onClick={onCancel}>
          {onlyRefused ? "Back" : "Cancel"}
        </Button>
      </div>
    </Card>
  );
}

function ComponentRow({
  c,
  s,
  badge,
  open,
  purgeable,
  disabled,
  verdict,
  onAdd,
  onRemove,
  onPurge,
}: {
  c: CatalogComponent;
  s: ComponentRowState;
  verdict?: ComponentVerdict;
  badge: ReturnType<typeof badgeFor>;
  open: boolean;
  purgeable: boolean;
  disabled: boolean;
  onAdd: () => void;
  onRemove: (deleteData: boolean) => void;
  onPurge: () => void;
}) {
  const [alsoDelete, setAlsoDelete] = useState(false);
  const core = c.class === "core";
  // ?component=<id> (settingslink.Component): the row the link names
  // scrolls into view and carries a short highlight, the same landing every
  // settings link uses (lib/useScrollHighlight).
  const anchor = componentRowAnchor(c.id);
  const highlighted = useScrollHighlight(anchor, open);
  return (
    <li
      className={`scroll-mt-6 rounded-2 py-3 transition-shadow ${highlighted ? HIGHLIGHT_CLASS : ""}`}
      id={anchor}
      data-highlighted={highlighted ? "true" : undefined}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-body font-medium text-fg-1">{c.title}</span>
            <span className="font-mono text-caption text-fg-3">{c.id}</span>
            <Pill variant={BADGE_TONE[badge]}>{BADGE_LABEL[badge]}</Pill>
            {c.stability !== "stable" && <Pill variant="neutral">{c.stability}</Pill>}
          </div>
          <p className="mt-0.5 text-small text-fg-3">{c.about}</p>
          {s.state !== "active" && (
            <p className="mt-0.5 text-small text-fg-2">
              {verdictCopy(verdict) ?? stateCopy(s.state, c.title, distrosWith(c))}
            </p>
          )}
          {s.because && <p className="mt-0.5 text-small text-fg-3">Because of {s.because}.</p>}
        </div>
        {!core && (
          <div className="flex shrink-0 flex-col items-end gap-1">
            {s.state === "active" && (
              <>
                <Button size="sm" disabled={disabled} onClick={() => onRemove(alsoDelete)}>
                  Remove
                </Button>
                {purgeable && (
                  <label className="flex items-center gap-1 text-caption text-fg-3">
                    <input type="checkbox" checked={alsoDelete} onChange={(e) => setAlsoDelete(e.target.checked)} />
                    Also delete its data (kept by default)
                  </label>
                )}
              </>
            )}
            {s.state === "available" && (
              <>
                <Button variant="primary" size="sm" disabled={disabled} onClick={onAdd}>
                  Add
                </Button>
                {purgeable && (
                  <Button variant="danger-outline" size="sm" disabled={disabled} onClick={onPurge}>
                    Delete its data
                  </Button>
                )}
              </>
            )}
            {s.state === "blocked" && (s.reason === "policy_unlisted" || s.reason === "policy_denied") && (
              <Link className="text-small text-accent" to={componentRequestLink(c.id)}>
                Request from your organization
              </Link>
            )}
            {s.state === "absent" && (
              <span className="max-w-[16rem] text-right text-caption text-fg-3">
                Install a build that includes it: {distrosWith(c).join(", ") || "none listed"}. A package manager
                install changes builds with its own upgrade command.
              </span>
            )}
          </div>
        )}
      </div>
      <details className="mt-2" open={open}>
        <summary className="cursor-pointer text-small text-fg-2">What this adds</summary>
        <WhatThisAdds c={c} />
      </details>
    </li>
  );
}

function WhatThisAdds({ c }: { c: CatalogComponent }) {
  const s = c.surface;
  const rows: [string, string[]][] = [
    ["Listeners", s.listeners.map((l) => `${l.proto} ${l.addr}${l.loopback ? " (loopback)" : ""}, auth ${l.auth}`)],
    ["Outbound", s.egress.map((e) => `${e.host}: ${e.purpose} (${e.gate}, ${e.trigger})`)],
    ["Files written", s.files_written],
    ["Other tools' config it edits", s.vendor_configs],
    ["OS integration", s.os_integration],
    ["Processes it runs", s.processes],
    ["Credential stores", s.credentials],
    ["Third-party modules", c.direct_modules],
    ["Tables", c.tables],
    ["Requires", c.requires],
    ["Security ledger rows", c.ledger],
  ];
  const shown = rows.filter(([, v]) => v.length > 0);
  return (
    <dl className="mt-2 grid grid-cols-1 gap-x-4 gap-y-1 text-small sm:grid-cols-[12rem_minmax(0,1fr)]">
      {shown.length === 0 && <dd className="text-fg-3">Nothing beyond Observer's own process.</dd>}
      {shown.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-fg-3">{k}</dt>
          <dd className="break-words font-mono text-caption text-fg-1">{v.join("; ")}</dd>
        </div>
      ))}
      {c.restart_class && (
        <div className="contents">
          <dt className="text-fg-3">Takes effect</dt>
          <dd className="text-fg-1">{c.restart_class === "restart" ? "after a restart" : c.restart_class}</dd>
        </div>
      )}
    </dl>
  );
}
