import { Callout, EmptyState, Pill, Table, Tooltip } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { agentCoverageWords, coverageCountsLine, coverageReasonExpected, coverageWords, type ModelVocab, type PTCoverage, type PTCoverageClaim, type PentestDoc } from "@/lib/secAssessModel";
import { AgentText, SubHeading } from "./modelParts";

// CoverageMatrix is the pen test's coverage matrix, shown before the findings:
// one row for each test category, what the agent marked it as, and what
// Observer reads it as. Observer cannot see the agent's requests, so a category
// the agent marked tested reads as claimed; "tested (logged request)" appears
// only when a helper log holds a request for it, and that log is a file the
// agent can write, so it is not a trace. What each word means is printed once,
// above the table, for each word the table uses (a fact true of every row that
// carries a word is not repeated on each of them), not only in a hover. The
// agent's reason for a skipped category is the agent's text; a category that was
// tested has no reason to give, so its Reason cell is blank and does not read
// as a missing reason; one line above the table says what the dash means.

export function CoverageMatrix({
  pt,
  claims,
  doc,
  vocab,
  showCounts = true,
}: {
  pt: PTCoverage | undefined;
  /** The agent's own coverage rows (probes and notes), to show beside the reasons. */
  claims?: PTCoverageClaim[];
  /** The pen test as the agent wrote it, for how the target was started. */
  doc?: PentestDoc;
  /** The vocabulary the category intents come from. */
  vocab?: ModelVocab;
  /** Print the counts sentence under the table. The model view turns it off when the page already carries the coverage line, which says the same. */
  showCounts?: boolean;
}) {
  const rows = pt?.rows ?? [];
  const claimOf = new Map<string, PTCoverageClaim>();
  for (const c of claims ?? doc?.coverage ?? []) if (!claimOf.has(c.category)) claimOf.set(c.category, c);
  const intent = (id: string) => (vocab?.wstg ?? []).find((w) => w.id === id)?.intent;
  const start = doc?.target?.start;
  // Each word the table uses, once, in the order the rows first use it.
  const used: string[] = [];
  for (const r of rows) if (!used.includes(r.effective)) used.push(r.effective);
  const dashes = rows.some((r) => !r.reason && !coverageReasonExpected(r.effective));

  return (
    <div className="min-w-0 space-y-3" data-testid="assess-coverage">
      <p className="m-0 flex flex-wrap items-center text-[12px] text-fg-2">
        This is the agent's claim. Observer cannot see the agent's requests, so a category it marked tested reads as claimed until a request log backs it.
        <HelpInd id="card.code_security_assess_coverage" />
      </p>

      {pt && !pt.started && (
        <div data-testid="assess-coverage-not-started">
          <Callout tone="warn" title="The agent says the target did not start">
            Every category reads as skipped: nothing was tested in a running application.
          </Callout>
        </div>
      )}

      {start && (
        <p className="m-0 break-words text-[11.5px] text-fg-3" data-testid="assess-coverage-start">
          {start.argv && start.argv.length > 0 ? (
            <>
              {"Start command, as the agent wrote it: "}
              <code className="font-mono text-[11px] text-fg-2">{start.argv.join(" ")}</code>
              {start.source ? ` (from ${start.source})` : ""}
              {". "}
            </>
          ) : (
            "The agent gave no start command. "
          )}
          {start.started ? (typeof start.startup_seconds === "number" ? `It says the target started after ${start.startup_seconds} seconds.` : "It says the target started.") : "It says the target did not start."}
        </p>
      )}

      {rows.length > 0 && (
        <div className="space-y-1.5" data-testid="assess-coverage-legend">
          <SubHeading>What the words mean</SubHeading>
          <ul className="m-0 list-none space-y-1 p-0">
            {used.map((effective) => {
              const w = coverageWords(effective);
              return (
                <li key={effective} className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-[11.5px] text-fg-3" data-testid="assess-coverage-detail" data-word={effective}>
                  <Pill variant={w.tone} case="none">
                    {w.label}
                  </Pill>
                  <span className="min-w-0 break-words">{w.detail}</span>
                </li>
              );
            })}
          </ul>
          {dashes && <p className="m-0 text-[11.5px] text-fg-3">A dash in the Reason column means the word gives no reason to expect one.</p>}
        </div>
      )}

      {rows.length === 0 ? (
        <EmptyState variant="inline" title="No coverage rows" body="The check built no coverage rows for this run, so nothing can be said about which categories were tested." />
      ) : (
        <Table
          minWidth={720}
          size="sm"
          head={
            <tr>
              <th scope="col" className="py-1.5 pr-3 font-medium">
                Category
              </th>
              <th scope="col" className="py-1.5 pr-3 font-medium">
                The agent marked it
              </th>
              <th scope="col" className="py-1.5 pr-3 font-medium">
                Observer reads it as
              </th>
              <th scope="col" className="py-1.5 pr-1 font-medium">
                Reason
              </th>
            </tr>
          }
        >
          {rows.map((r) => {
            const w = coverageWords(r.effective);
            const claim = claimOf.get(r.category);
            const why = intent(r.category);
            return (
              <tr key={r.category} data-testid="assess-coverage-row" data-effective={r.effective} data-category={r.category} className="border-b border-line-1 align-top">
                <td className="min-w-[10rem] py-1.5 pr-3">
                  <div className="font-mono text-[10.5px] text-fg-3">{r.category}</div>
                  {why ? (
                    <Tooltip content={why}>
                      <span tabIndex={0} className="cursor-help break-words text-fg-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]">
                        {r.title || r.category}
                      </span>
                    </Tooltip>
                  ) : (
                    <span className="break-words text-fg-1">{r.title || r.category}</span>
                  )}
                </td>
                <td className="whitespace-nowrap py-1.5 pr-3 text-fg-2">{agentCoverageWords(r.agent)}</td>
                <td className="min-w-[13rem] py-1.5 pr-3">
                  <Pill variant={w.tone} case="none">
                    {w.label}
                  </Pill>
                </td>
                <td className="min-w-[12rem] py-1.5 pr-1">
                  {r.reason ? (
                    <AgentText className="text-fg-2">{r.reason}</AgentText>
                  ) : coverageReasonExpected(r.effective) ? (
                    <span className="text-fg-3">The agent gave no reason</span>
                  ) : (
                    <span className="relative text-fg-3">
                      <span aria-hidden>{"\u2014"}</span>
                      <span className="sr-only">None expected</span>
                    </span>
                  )}
                  {claim?.probes && claim.probes.length > 0 && <div className="mt-0.5 break-words text-[11px] text-fg-3">{`Probes the agent names: ${claim.probes.join(", ")}`}</div>}
                  {claim?.notes && <div className="mt-0.5 break-words text-[11px] text-fg-3">{`Notes: ${claim.notes}`}</div>}
                </td>
              </tr>
            );
          })}
        </Table>
      )}

      {showCounts && pt && rows.length > 0 && (
        <p className="m-0 text-[11.5px] text-fg-2" data-testid="assess-coverage-counts">
          {coverageCountsLine(pt)}
        </p>
      )}
    </div>
  );
}
