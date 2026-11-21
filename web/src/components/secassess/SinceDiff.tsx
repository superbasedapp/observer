import type { ReactNode } from "react";
import { Pill } from "@/components/primitives";
import { bandTone, categoryLabel, elementName, pairingNote, plural, similarBasisWords, statusWords, type ModelBand, type ModelDiffChange, type ModelDiffItem, type ModelDiffSimilar, type ModelNameDiff, type ModelSince, type ModelVocab, type ThreatModelDoc } from "@/lib/secAssessModel";
import { SubHeading } from "./modelParts";

// SinceDiff shows what changed between this run's threat model and an earlier
// run's, as Observer computed it from the two checked copies. Every threat
// that was added or removed is listed, none is left out, and the sentence the
// comparison comes with is always shown: a threat that reads as removed may be
// the same threat re-worded, and one that reads as added may be a re-worded old
// one. A pair made by the place a threat cites rather than by its words is listed
// apart as "probably the same", with what the two have in common, and is never
// counted among the threats that read the same. Nothing of the earlier model is
// given to an agent.

function BandPill({ band, score }: { band?: ModelBand; score?: number }) {
  if (!band) return <span className="text-fg-3">no band</span>;
  return (
    <Pill variant={bandTone(band)} case="none">
      {typeof score === "number" ? `${band} ${score}` : band}
    </Pill>
  );
}

function ItemList({ title, items, doc, vocab, testId }: { title: string; items: ModelDiffItem[]; doc: ThreatModelDoc; vocab: ModelVocab | undefined; testId: string }) {
  if (items.length === 0) return null;
  return (
    <div className="space-y-1" data-testid={testId}>
      <SubHeading>{`${title} (${items.length})`}</SubHeading>
      <ul className="m-0 list-none space-y-1 p-0">
        {items.map((it, i) => (
          <li key={`${it.id}#${i}`} className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5 text-[12px]" data-threat-id={it.id}>
            <span className="font-mono text-[11px] text-fg-1">{it.id}</span>
            <span className="min-w-0 break-words text-fg-1">{it.title}</span>
            <BandPill band={it.band} score={it.score} />
            <span className="text-[11.5px] text-fg-3">{`${elementName(doc, it.element)}, ${categoryLabel(it.category, vocab)}`}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function ChangedList({ items, doc, vocab }: { items: ModelDiffChange[]; doc: ThreatModelDoc; vocab: ModelVocab | undefined }) {
  if (items.length === 0) return null;
  return (
    <div className="space-y-1" data-testid="assess-since-changed">
      <SubHeading>{`Changed (${items.length})`}</SubHeading>
      <ul className="m-0 list-none space-y-2 p-0">
        {items.map((c, i) => {
          const details: ReactNode[] = [];
          if (c.title_changed) details.push(<span key="title">the title changed</span>);
          if (c.from_status !== undefined && c.to_status !== undefined && c.from_status !== c.to_status) {
            details.push(<span key="status">{`status ${statusWords(c.from_status).toLowerCase()} to ${statusWords(c.to_status).toLowerCase()}, as the agent says`}</span>);
          }
          if (c.missing_from !== undefined && c.missing_to !== undefined && c.missing_from !== c.missing_to) {
            details.push(<span key="missing">{`missing mitigations ${c.missing_from} to ${c.missing_to}`}</span>);
          }
          if (c.existing_from !== undefined && c.existing_to !== undefined && c.existing_from !== c.existing_to) {
            details.push(<span key="existing">{`existing mitigations ${c.existing_from} to ${c.existing_to}`}</span>);
          }
          return (
            <li key={`${c.id}#${i}`} className="space-y-0.5 text-[12px]" data-threat-id={c.id}>
              <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5">
                <span className="font-mono text-[11px] text-fg-1">{c.id}</span>
                {c.prev_id !== c.id && <span className="text-[11px] text-fg-3">{`was ${c.prev_id}`}</span>}
                <span className="min-w-0 break-words text-fg-1">{c.title}</span>
                <span className="inline-flex flex-wrap items-center gap-1" data-testid="assess-since-band">
                  <BandPill band={c.from_band} score={c.from_score} />
                  <span className="text-[11px] text-fg-3">to</span>
                  <BandPill band={c.to_band} score={c.to_score} />
                </span>
              </div>
              <div className="text-[11.5px] text-fg-3">
                {`${elementName(doc, c.element)}, ${categoryLabel(c.category, vocab)}. Matched by ${c.match === "title" ? "title" : "id"}.`}
                {details.length > 0 && (
                  <>
                    {" Also: "}
                    {details.map((d, n) => (
                      <span key={n}>
                        {n > 0 ? ", " : ""}
                        {d}
                      </span>
                    ))}
                    {"."}
                  </>
                )}
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function SimilarList({ items, doc, vocab }: { items: ModelDiffSimilar[]; doc: ThreatModelDoc; vocab: ModelVocab | undefined }) {
  if (items.length === 0) return null;
  return (
    <div className="space-y-1" data-testid="assess-since-similar">
      <SubHeading>{`Probably the same (${items.length})`}</SubHeading>
      <p className="m-0 text-[11.5px] text-fg-3">Matched by what the two have in common, not by their words. Read both titles before you rely on a pair.</p>
      <ul className="m-0 list-none space-y-2 p-0">
        {items.map((s, i) => (
          <li key={`${s.id}#${i}`} className="space-y-0.5 text-[12px]" data-threat-id={s.id}>
            <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5">
              <span className="font-mono text-[11px] text-fg-1">{s.id}</span>
              <span className="min-w-0 break-words text-fg-1">{s.title}</span>
              <span className="inline-flex flex-wrap items-center gap-1" data-testid="assess-since-band">
                <BandPill band={s.from_band} score={s.from_score} />
                <span className="text-[11px] text-fg-3">to</span>
                <BandPill band={s.to_band} score={s.to_score} />
              </span>
            </div>
            <div className="min-w-0 break-words text-[11.5px] text-fg-3" data-testid="assess-since-similar-was">
              {`Earlier run, ${s.prev_id}: ${s.prev_title}`}
            </div>
            <div className="text-[11.5px] text-fg-3">
              {`${elementName(doc, s.element)}, ${categoryLabel(s.category, vocab)}`}
              {s.prev_category ? ` (earlier: ${categoryLabel(s.prev_category, vocab)})` : ""}
              {`. Probably the same, matched by ${similarBasisWords(s.basis)}.`}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function NameDiffLine({ title, diff }: { title: string; diff: ModelNameDiff | undefined }) {
  const added = diff?.added ?? [];
  const removed = diff?.removed ?? [];
  if (added.length === 0 && removed.length === 0) return null;
  return (
    <li className="min-w-0 break-words text-[12px] text-fg-2">
      <span className="font-medium text-fg-1">{`${title}: `}</span>
      {added.length > 0 && <span>{`added ${added.join(", ")}`}</span>}
      {added.length > 0 && removed.length > 0 && "; "}
      {removed.length > 0 && <span>{`removed ${removed.join(", ")}`}</span>}
    </li>
  );
}

export function SinceDiff({ since, doc, vocab }: { since: ModelSince; doc: ThreatModelDoc; vocab?: ModelVocab }) {
  const added = since.added ?? [];
  const removed = since.removed ?? [];
  const changed = since.changed ?? [];
  const similar = since.similar ?? [];
  const note = pairingNote(since);
  const sys = since.system;
  const sysChanged = [sys?.components, sys?.zones, sys?.flows].some((d) => (d?.added ?? []).length + (d?.removed ?? []).length > 0);
  return (
    <div className="space-y-3 rounded-2 border border-line-2 bg-bg-2 p-3" data-testid="assess-since">
      <p className="m-0 text-[12px] text-fg-1" data-testid="assess-since-note">
        {since.note}
      </p>
      <p className="m-0 text-[12px] text-fg-2" data-testid="assess-since-counts">
        {`${added.length} added, ${removed.length} removed, ${changed.length} changed, ${since.unchanged} ${plural(since.unchanged, "reads", "read")} the same`}
        {similar.length > 0 ? `, ${similar.length} probably the same` : ""}
      </p>
      {note !== "" && (
        <p className="m-0 text-[12px] text-fg-1" data-testid="assess-since-pairing">
          {note}
        </p>
      )}
      <ItemList title="Added" items={added} doc={doc} vocab={vocab} testId="assess-since-added" />
      <ItemList title="Removed" items={removed} doc={doc} vocab={vocab} testId="assess-since-removed" />
      <ChangedList items={changed} doc={doc} vocab={vocab} />
      <SimilarList items={similar} doc={doc} vocab={vocab} />
      {sysChanged && (
        <div className="space-y-1" data-testid="assess-since-system">
          <SubHeading>System changes</SubHeading>
          <ul className="m-0 list-none space-y-1 p-0">
            <NameDiffLine title="Components" diff={sys?.components} />
            <NameDiffLine title="Trust zones" diff={sys?.zones} />
            <NameDiffLine title="Flows" diff={sys?.flows} />
          </ul>
        </div>
      )}
    </div>
  );
}
