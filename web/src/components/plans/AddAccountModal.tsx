import { useEffect, useMemo, useState } from "react";
import clsx from "clsx";
import { ArrowLeft, Check, Search } from "lucide-react";
import {
  Button,
  Callout,
  Icon,
  Input,
  Modal,
  Pill,
  SegmentedControl,
} from "@/components/primitives";
import {
  EXPERIMENTAL_WARNING,
  GROUP_LABELS,
  canSave,
  methodOptions,
  providerLabel,
  statusVocab,
  type CatalogProvider,
} from "@/lib/plans";
import {
  GROUP_ORDER,
  methodView,
  passiveNames,
  pickerCount,
  pickerGroups,
  pickerItem,
  vendorCount,
  type PickerItem,
} from "@/lib/plansView";
import { ProviderMark } from "./ProviderMark";
import { SourceFields } from "./SourceFields";

// AddAccountModal: the add flow. Step 1 picks a provider from the whole
// catalogue (searchable, grouped by kind, each row with its mark, what the
// vendor reports and how Observer reads it); step 2 picks how to read it,
// takes the fields, and offers Test and Save. A centred Modal (full screen
// on a phone), so nothing behind it is clipped.

type ProbeReply = { ok: boolean; outcome?: string };

export type AddAccountProps = {
  open: boolean;
  /** Open straight at step 2 for this provider (a Track more tile). */
  initialProvider?: string;
  catalog: CatalogProvider[];
  optIns: Set<string>;
  onClose: () => void;
  onOptIn: (provider: string) => void;
  onSaved: () => void;
  post: <T>(path: string, body: unknown) => Promise<T>;
  reason: (e: unknown) => string;
};

type GroupFilter = "all" | string;

export function AddAccountModal(props: AddAccountProps) {
  const { open, initialProvider, catalog, optIns, onClose, onOptIn, onSaved, post, reason } = props;
  const [provider, setProvider] = useState("");
  const [query, setQuery] = useState("");
  const [groupFilter, setGroupFilter] = useState<GroupFilter>("all");
  const [source, setSource] = useState("");
  const [label, setLabel] = useState("");
  const [params, setParams] = useState<Record<string, string>>({});
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  function reset(next: string) {
    setProvider(next);
    const first = methodOptions(catalog.find((p) => p.id === next))[0];
    setSource(first?.id ?? "");
    setLabel("");
    setParams({});
    setSecrets({});
    setMsg(null);
  }

  useEffect(() => {
    if (open) {
      reset(initialProvider ?? "");
      setQuery("");
      setGroupFilter("all");
    }
    // Reset only when the modal opens; the catalogue reloads every minute.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, initialProvider]);

  const prov = catalog.find((p) => p.id === provider);
  const step = prov ? 2 : 1;

  async function test() {
    setBusy(true);
    setMsg(null);
    try {
      const r = await post<ProbeReply>("/api/plans/probe", { provider, source, label, params, secrets });
      setMsg(
        r.ok
          ? { ok: true, text: "It works. Save to start tracking." }
          : { ok: false, text: `Check failed: ${statusVocab(r.outcome ?? "error").label}.` },
      );
    } catch (e) {
      setMsg({ ok: false, text: reason(e) });
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    setBusy(true);
    setMsg(null);
    try {
      await post("/api/plans/accounts", { provider, source, label, params, secrets });
      onSaved();
    } catch (e) {
      setMsg({ ok: false, text: reason(e) });
    } finally {
      setBusy(false);
    }
  }

  const methods = methodOptions(prov);
  const src = methods.find((s) => s.id === source);
  const needsSwitch = !!src?.experimental && !optIns.has(provider);
  const ready = !!src && !needsSwitch && canSave(src, params, secrets);
  const notReadyReason = !src
    ? "Choose how to read it."
    : needsSwitch
      ? "Turn on experimental sources for this provider first."
      : "Fill in every required field.";

  return (
    <Modal
      open={open}
      onClose={onClose}
      width={720}
      fullOnPhone
      title={step === 1 ? "Add account" : `Add ${providerLabel(provider)}`}
      subtitle={step === 1 ? "Step 1 of 2: choose a provider" : "Step 2 of 2: choose how to read it"}
      bodyClassName="px-0 py-0"
      footer={
        step === 2 ? (
          <>
            <Button variant="ghost" iconLeft={ArrowLeft} onClick={() => reset("")} className="mr-auto">
              Back
            </Button>
            {src && !src.passive && src.id !== "manual" && (
              <Button variant="secondary" onClick={test} disabled={!ready || busy} title={ready ? undefined : notReadyReason}>
                Test
              </Button>
            )}
            <Button
              variant="primary"
              onClick={save}
              disabled={!ready || busy}
              loading={busy}
              title={ready ? undefined : notReadyReason}
            >
              Save
            </Button>
          </>
        ) : (
          <span className="mr-auto text-[11.5px] text-fg-3">
            Keys stay in your system keychain and go only to that vendor.
          </span>
        )
      }
    >
      {step === 1 ? (
        <ProviderPicker
          catalog={catalog}
          query={query}
          setQuery={setQuery}
          groupFilter={groupFilter}
          setGroupFilter={setGroupFilter}
          onPick={reset}
        />
      ) : (
        prov && (
          <div className="space-y-4 px-5 py-4">
            <ProviderSummary item={pickerItem(prov)} passive={passiveNames(prov)} />

            {methods.length > 1 && (
              <div role="radiogroup" aria-label="How to read it" className="grid gap-2 sm:grid-cols-2">
                {methods.map((s) => {
                  const v = methodView(s);
                  const on = s.id === source;
                  return (
                    <button
                      key={s.id}
                      type="button"
                      role="radio"
                      aria-checked={on}
                      onClick={() => {
                        setSource(s.id);
                        setParams({});
                        setSecrets({});
                        setMsg(null);
                      }}
                      className={clsx(
                        "flex min-w-0 flex-col items-start gap-1 rounded-3 border p-3 text-left transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring",
                        on ? "border-accent bg-accent-soft" : "border-line-2 bg-bg-2 hover:border-line-3 hover:bg-bg-3",
                      )}
                    >
                      <span className="flex w-full flex-wrap items-center gap-1.5">
                        <span className="text-[13px] font-medium text-fg-0">{v.label}</span>
                        {v.experimental && (
                          <Pill variant="info" case="none">
                            Experimental
                          </Pill>
                        )}
                        {on && <Icon icon={Check} size="sm" className="ml-auto text-accent" />}
                      </span>
                      {v.handOver && <span className="text-[11.5px] text-fg-2">You hand over: {v.handOver}</span>}
                    </button>
                  );
                })}
              </div>
            )}

            {src && (
              <div className="space-y-1">
                {methods.length === 1 && (
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-[13px] font-medium text-fg-0">{methodView(src).label}</span>
                    {src.experimental && (
                      <Pill variant="info" case="none">
                        Experimental
                      </Pill>
                    )}
                  </div>
                )}
                <p className="text-[12px] text-fg-2">{methodView(src).howto}</p>
              </div>
            )}

            {src && needsSwitch && (
              <Callout
                tone="warn"
                title="Turn on experimental sources first"
                action={
                  <Button variant="secondary" size="sm" onClick={() => onOptIn(provider)}>
                    Turn on for {providerLabel(provider)}
                  </Button>
                }
              >
                {EXPERIMENTAL_WARNING}
              </Callout>
            )}

            {src && !needsSwitch && (
              <div className="space-y-3">
                <Input
                  label="Name"
                  placeholder="Optional, for example Work"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                />
                <SourceFields
                  src={src}
                  params={params}
                  secrets={secrets}
                  setParam={(k, v) => setParams((p) => ({ ...p, [k]: v }))}
                  setSecret={(k, v) => setSecrets((x) => ({ ...x, [k]: v }))}
                />
              </div>
            )}

            {msg && (
              <p role="status" className={clsx("text-[12px]", msg.ok ? "text-success" : "text-fg-1")}>
                {msg.text}
              </p>
            )}
          </div>
        )
      )}
    </Modal>
  );
}

function ProviderSummary({ item, passive }: { item: PickerItem; passive: string[] }) {
  return (
    <div className="space-y-3">
      <div className="flex min-w-0 items-start gap-3">
        <ProviderMark provider={item.id} size={40} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[15px] font-semibold text-fg-0">{item.label}</span>
            {item.coverage && (
              <Pill variant={item.coverage.tone} case="none">
                {item.coverage.label}
              </Pill>
            )}
          </div>
          {item.shows && <p className="text-[12px] text-fg-2">Shows: {item.shows}</p>}
        </div>
      </div>
      {item.gap && (
        <Callout tone="info" title="No live reading for this provider">
          {item.gap}. You can still type your plan in.
        </Callout>
      )}
      {passive.length > 0 && (
        <p className="text-[12px] text-fg-2">Already read without an account: {passive.join(", ")}.</p>
      )}
    </div>
  );
}

const SEARCH_ID = "plans-provider-search";

function ProviderPicker({
  catalog,
  query,
  setQuery,
  groupFilter,
  setGroupFilter,
  onPick,
}: {
  catalog: CatalogProvider[];
  query: string;
  setQuery: (q: string) => void;
  groupFilter: GroupFilter;
  setGroupFilter: (g: GroupFilter) => void;
  onPick: (id: string) => void;
}) {
  // The Modal focuses its first control a frame after opening; the search
  // box takes focus a frame after that, so typing filters at once.
  useEffect(() => {
    let inner = 0;
    const outer = requestAnimationFrame(() => {
      inner = requestAnimationFrame(() => document.getElementById(SEARCH_ID)?.focus({ preventScroll: true }));
    });
    return () => {
      cancelAnimationFrame(outer);
      cancelAnimationFrame(inner);
    };
  }, []);
  const all = useMemo(() => pickerGroups(catalog, query), [catalog, query]);
  const groups = groupFilter === "all" ? all : all.filter((g) => g.group === groupFilter);
  const shown = pickerCount(groups);
  const total = vendorCount(catalog);
  const present = new Set(catalog.map((p) => p.group));
  const segments = [
    { value: "all", label: "All" },
    ...GROUP_ORDER.filter((g) => present.has(g)).map((g) => ({ value: g, label: GROUP_LABELS[g] })),
  ];
  const first = groups[0]?.items[0];

  return (
    <div className="flex h-full min-h-0 flex-col sm:h-[min(560px,calc(100vh-13rem))]">
      <div className="space-y-2 border-b border-line-1 px-5 py-3">
        <div className="relative">
          <Icon icon={Search} size="sm" className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-fg-3" />
          <Input
            id={SEARCH_ID}
            type="search"
            autoComplete="off"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && first) {
                e.preventDefault();
                onPick(first.id);
              }
            }}
            placeholder={`Search ${total} providers`}
            aria-label="Search providers"
            className="pl-8"
          />
        </div>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <SegmentedControl options={segments} value={groupFilter} onChange={setGroupFilter} size="sm" />
          <span className="text-[11px] text-fg-3" aria-live="polite">
            {query || groupFilter !== "all" ? `${shown} of ${total}` : `${total} providers`}
          </span>
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain">
        {groups.length === 0 ? (
          <div className="space-y-2 px-5 py-8 text-center">
            <p className="text-[13px] text-fg-1">No provider matches that.</p>
            <p className="text-[12px] text-fg-3">Choose Other to type in any plan by hand.</p>
            <Button variant="secondary" size="sm" onClick={() => onPick("other")}>
              Use Other
            </Button>
          </div>
        ) : (
          groups.map((g) => (
            <section key={g.group} aria-label={g.label}>
              <h3 className="sticky top-0 z-[1] border-b border-line-1 bg-bg-1 px-5 py-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
                {g.label} <span className="font-normal normal-case tracking-normal">{g.items.length}</span>
              </h3>
              <ul>
                {g.items.map((it) => (
                  <li key={it.id}>
                    <PickerRow item={it} onPick={onPick} />
                  </li>
                ))}
              </ul>
            </section>
          ))
        )}
      </div>
    </div>
  );
}

function PickerRow({ item, onPick }: { item: PickerItem; onPick: (id: string) => void }) {
  return (
    <button
      type="button"
      onClick={() => onPick(item.id)}
      className="flex w-full min-w-0 items-start gap-3 px-5 py-2.5 text-left transition-colors hover:bg-bg-2 focus:outline-none focus-visible:bg-bg-2 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent-ring"
    >
      <ProviderMark provider={item.id} size={32} />
      <span className="min-w-0 flex-1">
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="text-[13px] font-medium text-fg-0">{item.label}</span>
          {item.coverage && (
            <Pill variant={item.coverage.tone} case="none">
              {item.coverage.label}
            </Pill>
          )}
        </span>
        {item.shows && <span className="block text-[11.5px] text-fg-2">{item.shows}</span>}
        {item.gap && <span className="block text-[11.5px] text-fg-3">{item.gap}</span>}
      </span>
    </button>
  );
}
