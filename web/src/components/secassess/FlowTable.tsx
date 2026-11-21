import { useMemo } from "react";
import { Copy } from "lucide-react";
import { Button, EmptyState, Pill, Table } from "@/components/primitives";
import { enumWords, flowRows, mermaidCountsLine, mermaidCutLine, mermaidSettingsLine, type FlowRow, type ModelMermaid, type ThreatModelDoc } from "@/lib/secAssessModel";
import { RefList } from "./RefList";
import { CopyNote, SubHeading, useCopy } from "./modelParts";

// FlowTable is the data-flow view of a threat model: the flows between
// components as a table, the entry points, and the data-flow diagram as
// Mermaid SOURCE TEXT. Observer draws no diagram and loads nothing to draw
// one: the source sits in a text block beside the table, and a button copies
// it for any Mermaid viewer. A flow that crosses a trust zone with no
// authentication or no encryption is marked in words, not only by colour. The
// zones, the protocols and the encryption words are what the agent wrote.

/** weakWords is the sentence for a flow that crosses a trust zone weakly: what is missing, from the row's own fields. */
export function weakWords(row: Pick<FlowRow, "authn" | "encrypted">): string {
  const noAuth = row.authn === "none";
  const noEnc = row.encrypted === "no";
  if (noAuth && noEnc) return "Crosses a trust zone without authentication or encryption";
  if (noAuth) return "Crosses a trust zone without authentication";
  return "Crosses a trust zone without encryption";
}

function FlowCrossing({ row }: { row: FlowRow }) {
  if (row.weakCrossing) {
    return (
      <div className="space-y-0.5">
        <Pill variant="warn" case="none">
          {weakWords(row)}
        </Pill>
        {row.zones.length > 0 && <div className="text-[10.5px] text-fg-3">{row.zones.join(" to ")}</div>}
      </div>
    );
  }
  if (row.crossing) {
    return (
      <div className="space-y-0.5">
        <Pill variant="neutral" case="none">
          Crosses a trust zone
        </Pill>
        {row.zones.length > 0 && <div className="text-[10.5px] text-fg-3">{row.zones.join(" to ")}</div>}
      </div>
    );
  }
  return <span className="text-fg-3">No crossing recorded</span>;
}

export function FlowTable({ doc, mermaid }: { doc: ThreatModelDoc; mermaid?: ModelMermaid }) {
  const rows = useMemo(() => flowRows(doc), [doc]);
  const entries = doc?.system?.entry_points ?? [];
  const components = useMemo(() => new Map((doc?.system?.components ?? []).map((c) => [c.id, c.name] as const)), [doc]);
  const { status, copy } = useCopy();
  const counts = mermaid ? mermaidCountsLine(mermaid) : "";
  const cut = mermaid ? mermaidCutLine(mermaid) : "";
  const settings = mermaid ? mermaidSettingsLine(mermaid) : "";

  return (
    <div className="min-w-0 space-y-4" data-testid="assess-flows">
      <div className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,20rem)]">
        <div className="min-w-0 space-y-4">
          <div className="space-y-1.5">
            <SubHeading agent>{`Flows (${rows.length})`}</SubHeading>
            {rows.length === 0 ? (
              <EmptyState variant="inline" title="The model records no flows" body="The agent named no data flow between components, so there is nothing to list here." />
            ) : (
              <Table
                minWidth={880}
                size="sm"
                head={
                  <tr>
                    <th scope="col" className="py-1.5 pr-3 font-medium">
                      From
                    </th>
                    <th scope="col" className="py-1.5 pr-3 font-medium">
                      To
                    </th>
                    <th scope="col" className="py-1.5 pr-3 font-medium">
                      Zone crossing
                    </th>
                    <th scope="col" className="py-1.5 pr-3 font-medium">
                      Data
                    </th>
                    <th scope="col" className="py-1.5 pr-3 font-medium">
                      Protocol
                    </th>
                    <th scope="col" className="py-1.5 pr-3 font-medium">
                      Authentication
                    </th>
                    <th scope="col" className="py-1.5 pr-3 font-medium">
                      Encrypted
                    </th>
                    <th scope="col" className="py-1.5 pr-1 font-medium">
                      Personal data
                    </th>
                  </tr>
                }
              >
                {rows.map((r, i) => (
                  <tr
                    key={`${r.id}#${i}`}
                    data-testid="assess-flow"
                    data-flow-id={r.id}
                    data-weak={r.weakCrossing ? "true" : "false"}
                    className={r.weakCrossing ? "border-b border-line-1 align-top bg-warn-soft" : "border-b border-line-1 align-top"}
                  >
                    <td className="break-words py-1.5 pr-3 text-fg-1">{r.fromName}</td>
                    <td className="break-words py-1.5 pr-3 text-fg-1">{r.toName}</td>
                    <td className="py-1.5 pr-3">
                      <FlowCrossing row={r} />
                    </td>
                    <td className="break-words py-1.5 pr-3 text-fg-2">{r.data.length > 0 ? r.data.join(", ") : <span className="text-fg-3">none listed</span>}</td>
                    <td className="py-1.5 pr-3 text-fg-2">{r.protocol}</td>
                    <td className="py-1.5 pr-3 text-fg-2">{enumWords("authn", r.authn)}</td>
                    <td className="py-1.5 pr-3 text-fg-2">{enumWords("encrypted", r.encrypted)}</td>
                    <td className="py-1.5 pr-1 text-fg-2">{r.personalData ? "yes" : <span className="text-fg-3">not flagged</span>}</td>
                  </tr>
                ))}
              </Table>
            )}
          </div>

          <div className="space-y-1.5">
            <SubHeading agent>{`Entry points (${entries.length})`}</SubHeading>
            {entries.length === 0 ? (
              <p className="m-0 text-[11.5px] text-fg-3" data-testid="assess-entry-points-none">
                The model lists no entry point.
              </p>
            ) : (
              <Table
                minWidth={640}
                size="sm"
                head={
                  <tr>
                    <th scope="col" className="py-1.5 pr-3 font-medium">
                      Component
                    </th>
                    <th scope="col" className="py-1.5 pr-3 font-medium">
                      Kind
                    </th>
                    <th scope="col" className="py-1.5 pr-3 font-medium">
                      Authentication
                    </th>
                    <th scope="col" className="py-1.5 pr-3 font-medium">
                      Exposure
                    </th>
                    <th scope="col" className="py-1.5 pr-1 font-medium">
                      Where in the code
                    </th>
                  </tr>
                }
              >
                {entries.map((e, i) => (
                  <tr key={`${e.id}#${i}`} data-testid="assess-entry-point" className="border-b border-line-1 align-top">
                    <td className="break-words py-1.5 pr-3 text-fg-1">{components.get(e.component) ?? e.component}</td>
                    <td className="py-1.5 pr-3 text-fg-2">{enumWords("entry_kind", e.kind)}</td>
                    <td className="py-1.5 pr-3 text-fg-2">{e.authn ? enumWords("authn", e.authn) : <span className="text-fg-3">not stated</span>}</td>
                    <td className="py-1.5 pr-3 text-fg-2">{e.exposure ? enumWords("exposure", e.exposure) : <span className="text-fg-3">not stated</span>}</td>
                    <td className="min-w-[12rem] py-1.5 pr-1">
                      <RefList refs={e.ref ? [e.ref] : []} />
                    </td>
                  </tr>
                ))}
              </Table>
            )}
          </div>
        </div>

        <div className="min-w-0 space-y-1.5" data-testid="assess-diagram">
          <SubHeading>Data-flow diagram source</SubHeading>
          {mermaid ? (
            <>
              <p className="m-0 text-[11.5px] text-fg-3">Paste this into any Mermaid viewer. Observer does not render it or load anything to draw it.</p>
              <pre
                tabIndex={0}
                aria-label="Mermaid source of the data-flow diagram"
                data-testid="assess-mermaid-source"
                className="m-0 max-h-80 overflow-auto whitespace-pre rounded-2 border border-line-2 bg-bg-2 p-3 font-mono text-[11px] leading-relaxed text-fg-1"
              >
                {mermaid.source}
              </pre>
              <div className="flex flex-wrap items-center gap-2">
                <Button size="sm" variant="secondary" iconLeft={Copy} onClick={() => copy(mermaid.source)}>
                  Copy diagram source
                </Button>
                <CopyNote status={status} testId="assess-diagram-copied" />
              </div>
              {(counts || cut) && (
                <div className="space-y-1" data-testid="assess-diagram-counts">
                  {counts && <p className="m-0 text-[11.5px] text-fg-3">{counts}</p>}
                  {cut && <p className="m-0 text-[11.5px] text-fg-3">{cut}</p>}
                  {settings && <p className="m-0 text-[11.5px] text-fg-3">{settings}</p>}
                </div>
              )}
            </>
          ) : (
            <p className="m-0 text-[11.5px] text-fg-3" data-testid="assess-diagram-none">
              No diagram source was built for this model.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
