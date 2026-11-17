import { useMemo, type ReactNode } from "react";
import { EmptyState, Pill, Table } from "@/components/primitives";
import { enumWords, type ModelVocab, type ThreatModelDoc } from "@/lib/secAssessModel";
import { RefList } from "./RefList";
import { SubHeading } from "./modelParts";

// SystemView lists what the agent says the system is made of: its components,
// trust zones, actors and assets. Names, types and zones are the agent's; the
// places in the code a component cites carry Observer's finding about each.
// The flows and the entry points are on the Flows tab.

function Section({ title, count, children }: { title: string; count: number; children: ReactNode }) {
  return (
    <div className="space-y-1.5">
      <SubHeading agent>{`${title} (${count})`}</SubHeading>
      {children}
    </div>
  );
}

function Th({ children, last }: { children: ReactNode; last?: boolean }) {
  return (
    <th scope="col" className={last ? "py-1.5 pr-1 font-medium" : "py-1.5 pr-3 font-medium"}>
      {children}
    </th>
  );
}

const NONE = <span className="text-fg-3">none listed</span>;

export function SystemView({ doc, vocab }: { doc: ThreatModelDoc; vocab: ModelVocab }) {
  const sys = doc?.system ?? {};
  const components = sys.components ?? [];
  const zones = sys.zones ?? [];
  const actors = sys.actors ?? [];
  const assets = sys.assets ?? [];
  const zoneName = useMemo(() => new Map(zones.map((z) => [z.id, z.name] as const)), [zones]);
  const componentName = useMemo(() => new Map(components.map((c) => [c.id, c.name] as const)), [components]);
  const typeName = (id: string) => (vocab?.component_types ?? []).find((t) => t.id === id)?.name ?? id;

  if (components.length + zones.length + actors.length + assets.length === 0) {
    return (
      <div data-testid="assess-system">
        <EmptyState variant="inline" title="The model describes no system" body="The agent listed no component, trust zone, actor or asset." />
      </div>
    );
  }

  return (
    <div className="min-w-0 space-y-4" data-testid="assess-system">
      <Section title="Components" count={components.length}>
        {components.length === 0 ? (
          <p className="m-0 text-[11.5px] text-fg-3">The model lists no component.</p>
        ) : (
          <Table
            minWidth={760}
            size="sm"
            head={
              <tr>
                <Th>Name</Th>
                <Th>Type</Th>
                <Th>Trust zone</Th>
                <Th>Technology</Th>
                <Th last>Where in the code</Th>
              </tr>
            }
          >
            {components.map((c, i) => (
              <tr key={`${c.id}#${i}`} data-testid="assess-component" data-component-id={c.id} className="border-b border-line-1 align-top">
                <td className="min-w-[10rem] py-1.5 pr-3">
                  <div className="break-words text-fg-1">{c.name}</div>
                  {c.description && <div className="break-words text-[11px] text-fg-3">{c.description}</div>}
                </td>
                <td className="py-1.5 pr-3 text-fg-2">{typeName(c.type)}</td>
                <td className="py-1.5 pr-3 text-fg-2">{c.zone ? (zoneName.get(c.zone) ?? c.zone) : <span className="text-fg-3">not stated</span>}</td>
                <td className="py-1.5 pr-3">
                  {(c.tech ?? []).length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {(c.tech ?? []).map((t, n) => (
                        <Pill key={n} variant="neutral" case="none">
                          {t}
                        </Pill>
                      ))}
                    </div>
                  ) : (
                    NONE
                  )}
                </td>
                <td className="min-w-[12rem] py-1.5 pr-1">
                  <RefList refs={c.paths} />
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Section>

      <Section title="Trust zones" count={zones.length}>
        {zones.length === 0 ? (
          <p className="m-0 text-[11.5px] text-fg-3">The model lists no trust zone.</p>
        ) : (
          <ul className="m-0 list-none space-y-1 p-0 text-[12px]">
            {zones.map((z, i) => (
              <li key={`${z.id}#${i}`} className="min-w-0 break-words text-fg-1">
                {z.name}
                {z.description && <span className="text-fg-3">{`: ${z.description}`}</span>}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Actors" count={actors.length}>
        {actors.length === 0 ? (
          <p className="m-0 text-[11.5px] text-fg-3">The model lists no actor.</p>
        ) : (
          <ul className="m-0 list-none space-y-1 p-0 text-[12px]">
            {actors.map((a, i) => (
              <li key={`${a.id}#${i}`} className="min-w-0 break-words text-fg-1">
                {a.name}
                <span className="text-fg-3">{`: ${enumWords("actor_kind", a.kind)}`}</span>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Assets" count={assets.length}>
        {assets.length === 0 ? (
          <p className="m-0 text-[11.5px] text-fg-3">The model lists no asset.</p>
        ) : (
          <Table
            minWidth={560}
            size="sm"
            head={
              <tr>
                <Th>Name</Th>
                <Th>Sensitivity</Th>
                <Th>Data classes</Th>
                <Th last>Stored in</Th>
              </tr>
            }
          >
            {assets.map((a, i) => (
              <tr key={`${a.id}#${i}`} data-testid="assess-asset" className="border-b border-line-1 align-top">
                <td className="break-words py-1.5 pr-3 text-fg-1">{a.name}</td>
                <td className="py-1.5 pr-3 text-fg-2">{enumWords("sensitivity", a.sensitivity)}</td>
                <td className="py-1.5 pr-3 text-fg-2">{(a.data_classes ?? []).length > 0 ? (a.data_classes ?? []).join(", ") : NONE}</td>
                <td className="py-1.5 pr-1 text-fg-2">{(a.stored_in ?? []).length > 0 ? (a.stored_in ?? []).map((id) => componentName.get(id) ?? id).join(", ") : NONE}</td>
              </tr>
            ))}
          </Table>
        )}
      </Section>
    </div>
  );
}
