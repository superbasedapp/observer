import { FlaskConical, LayoutGrid, Plus } from "lucide-react";
import { Button, Callout, Card, EmptyState, Pill, Toggle } from "@/components/primitives";
import { toolMeta } from "@shared/lib/tools";
import { EXPERIMENTAL_WARNING } from "@/lib/plans";
import type { ExperimentalRow, Suggestion } from "@/lib/plansView";
import { ProviderMark } from "./ProviderMark";

// TrackMore: a few suggested providers as tiles (the ones behind tools the
// person uses first) and the way into the whole catalogue.
export function TrackMore({
  items,
  total,
  onPick,
  onBrowse,
}: {
  items: Suggestion[];
  total: number;
  onPick: (id: string) => void;
  onBrowse: () => void;
}) {
  return (
    <Card
      title="Track more"
      icon={Plus}
      sub={items.some((s) => s.usedTool) ? "Suggested from the tools you use." : "Providers Observer reads with an official source."}
      actions={
        <Button variant="secondary" size="sm" iconLeft={LayoutGrid} onClick={onBrowse}>
          Browse all {total} providers
        </Button>
      }
    >
      {items.length === 0 ? (
        <p className="text-[12px] text-fg-3">Every suggested provider is tracked. Browse the list for more.</p>
      ) : (
        <ul className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {items.map((it) => (
            <li key={it.id} className="min-w-0">
              <button
                type="button"
                onClick={() => onPick(it.id)}
                className="flex h-full w-full min-w-0 items-start gap-3 rounded-3 border border-line-2 bg-bg-3 p-3 text-left transition-colors hover:border-accent/50 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
              >
                <ProviderMark provider={it.id} size={32} />
                <span className="min-w-0 flex-1">
                  <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <span className="text-[13px] font-medium text-fg-0">{it.label}</span>
                    {it.coverage && (
                      <Pill variant={it.coverage.tone} case="none">
                        {it.coverage.label}
                      </Pill>
                    )}
                  </span>
                  {it.shows && <span className="block text-[11.5px] text-fg-2">{it.shows}</span>}
                  {it.usedTool && (
                    <span className="block text-[11px] text-fg-3">You use {toolMeta(it.usedTool).label}</span>
                  )}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

// ExperimentalSources: the providers whose experimental sources are on (or
// that have an account on one), each with its switch. The warning is said
// once, at the top; switching a provider on happens in the add flow.
export function ExperimentalSources({
  rows,
  onToggle,
}: {
  rows: ExperimentalRow[];
  onToggle: (provider: string, on: boolean) => void;
}) {
  return (
    <Card title="Experimental sources" icon={FlaskConical} sub="Off by default, per provider. Turn one on from Add account.">
      {rows.length === 0 ? (
        <EmptyState
          variant="inline"
          icon={FlaskConical}
          title="None switched on"
          body="Pick a provider in Add account and choose a method marked Experimental to use one."
        />
      ) : (
        <div className="space-y-3">
          <Callout tone="info" title="What experimental means">
            {EXPERIMENTAL_WARNING}
          </Callout>
          <ul className="divide-y divide-line-1">
            {rows.map((r) => (
              <li key={r.id} className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-2 py-2.5">
                <ProviderMark provider={r.id} size={28} />
                <div className="min-w-0 flex-1 basis-48">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <span className="text-[13px] font-medium text-fg-0">{r.label}</span>
                    {r.accounts > 0 && (
                      <span className="text-[11px] text-fg-3">
                        {r.accounts === 1 ? "1 account" : `${r.accounts} accounts`}
                      </span>
                    )}
                  </div>
                  <div className="text-[11.5px] text-fg-2">{r.methods.join(", ")}</div>
                  {r.shows && <div className="text-[11px] text-fg-3">Reads: {r.shows}</div>}
                </div>
                <Toggle
                  on={r.on}
                  onChange={(next) => onToggle(r.id, next)}
                  label={r.on ? "On" : "Off"}
                  ariaLabel={`Experimental sources for ${r.label}`}
                />
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}
