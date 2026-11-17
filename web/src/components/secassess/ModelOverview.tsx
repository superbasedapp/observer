import { Callout, Pill, Select } from "@/components/primitives";
import { fmtDateTime } from "@/lib/format";
import { assessRunLabel, assessRunState, type AssessRun } from "@/lib/secAssess";
import { bandCounts, bandTone, type AssessModelResponse, type ModelSince, type ModelVocab, type ThreatModelDoc } from "@/lib/secAssessModel";
import { SinceDiff } from "./SinceDiff";
import { AgentText, SubHeading } from "./modelParts";

// ModelOverview is the threat model's first tab: what the agent says the model
// is, the threats by band, what was covered, the scope, the questions the agent
// left open and its own limits, then the comparison with an earlier run. The
// summary, the scope, the questions and the limits are the agent's text; the
// band counts and the coverage line are Observer's.

/** ModelHeader is what both kinds put first: what a result with nothing shown in it reads as (a sentence about what it is not, or about what the check refused), and the coverage line. */
export function ModelHeader({ data }: { data: AssessModelResponse }) {
  return (
    <div className="space-y-2">
      {data.reading && (
        <div data-testid="assess-model-reading">
          <Callout tone="info" title="What this result says">
            {data.reading}
          </Callout>
        </div>
      )}
      {data.coverage_line && (
        <p className="m-0 text-[12px] text-fg-1" data-testid="assess-model-coverage-line">
          {data.coverage_line}
        </p>
      )}
    </div>
  );
}

function TextList({ title, items, empty, tagged = true }: { title: string; items: string[] | undefined; empty?: string; tagged?: boolean }) {
  const list = (items ?? []).filter((s) => typeof s === "string" && s !== "");
  if (list.length === 0 && !empty) return null;
  return (
    <div className="space-y-1">
      <SubHeading agent={tagged}>{title}</SubHeading>
      {list.length === 0 ? (
        <p className="m-0 text-[11.5px] text-fg-3">{empty}</p>
      ) : (
        <ul className="m-0 list-disc space-y-0.5 pl-5 text-[12px] text-fg-1">
          {list.map((s, i) => (
            <li key={i} className="min-w-0 whitespace-pre-wrap break-words">
              {s}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export type SinceState = {
  /** The earlier run the reader chose ("" for none). */
  value: string;
  onChange: (id: string) => void;
  candidates: AssessRun[];
  loading: boolean;
  /** The server's words when the comparison was refused or could not be read. */
  error: string;
  diff: ModelSince | undefined;
};

function SinceControl({ since, doc, vocab }: { since: SinceState; doc: ThreatModelDoc; vocab: ModelVocab | undefined }) {
  const none = since.candidates.length === 0;
  return (
    <div className="space-y-2" data-testid="assess-since-control">
      <SubHeading>Changes since another run</SubHeading>
      <Select
        aria-label="Compare with an earlier run"
        data-testid="assess-since-select"
        className="w-72"
        disabled={none}
        value={since.value}
        onChange={(e) => since.onChange(e.target.value)}
        options={[
          { value: "", label: "None" },
          ...since.candidates.map((r) => ({ value: r.id, label: assessRunLabel(r.kind_title, r.created_at, fmtDateTime, assessRunState(r).label) })),
        ]}
      />
      {none && <p className="m-0 text-[11.5px] text-fg-3">There is no earlier checked run of this project and kind to compare with.</p>}
      {since.loading && (
        <p className="m-0 text-[11.5px] text-fg-3" role="status">
          Reading the comparison
        </p>
      )}
      {since.error && (
        <p role="alert" className="m-0 text-[12px] text-fg-2" data-testid="assess-since-error">
          {since.error}
        </p>
      )}
      {!since.loading && !since.error && since.diff && <SinceDiff since={since.diff} doc={doc} vocab={vocab} />}
    </div>
  );
}

export function ModelOverview({ data, doc, since }: { data: AssessModelResponse; doc: ThreatModelDoc; since: SinceState }) {
  const threats = doc.threats ?? [];
  const counts = bandCounts(threats);
  const scope = doc.scope ?? {};
  return (
    <div className="min-w-0 space-y-4" data-testid="assess-overview">
      <ModelHeader data={data} />

      <div className="space-y-1">
        <SubHeading>The agent says</SubHeading>
        {doc.summary ? <AgentText>{doc.summary}</AgentText> : <p className="m-0 text-[11.5px] text-fg-3">The agent wrote no summary.</p>}
      </div>

      <div className="space-y-1.5" data-testid="assess-model-bands">
        <SubHeading>{`Threats by band (${threats.length} in all)`}</SubHeading>
        <div className="flex flex-wrap items-center gap-1.5">
          {[...counts].reverse().map((c) => (
            <Pill key={c.band} variant={c.n > 0 ? bandTone(c.band) : "neutral"} case="none">
              {`${c.band} ${c.n}`}
            </Pill>
          ))}
        </div>
        <p className="m-0 text-[11px] text-fg-3">The band is Observer's reading of the agent's likelihood and impact ratings, an ordinal heuristic and not a probability.</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <TextList title="In scope" items={scope.in_scope} empty="The agent named no folder or area as in scope." />
        <TextList title="Out of scope" items={scope.out_of_scope} empty="The agent named nothing as out of scope." />
        <TextList title="Assumptions" items={scope.assumptions} />
        <TextList title="Open questions" items={doc.open_questions} />
      </div>
      <TextList title="The agent's own limits" items={doc.limits} tagged={false} />

      <p className="m-0 text-[11.5px] text-fg-3" data-testid="assess-model-generator">
        {`The file names ${doc.generator?.tool || "no tool"}${doc.generator?.model ? ` (${doc.generator.model})` : ""} as its writer${doc.prompt_version ? `, prompt version ${doc.prompt_version}` : ""}. That is what the agent wrote about itself.`}
      </p>

      <SinceControl since={since} doc={doc} vocab={data.vocab} />
    </div>
  );
}
