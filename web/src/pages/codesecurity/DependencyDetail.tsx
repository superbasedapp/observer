import { useState } from "react";
import clsx from "clsx";
import { Button, Pill } from "@/components/primitives";
import { DefinitionRow } from "@shared/primitives/DefinitionList";
import { fmtRelative } from "@/lib/format";
import {
  advisoryDetailsCollapsible,
  advisoryRangeWords,
  advisorySourceNote,
  dependencyFixedIn,
  dependencyKindWords,
  dependencyPackage,
  findingSignalLabels,
  locationNotFoundWords,
  lockfileLocationLabel,
  safeReference,
  type DependencyAdvisory,
  type DependencyLocation,
  type FindingDependency,
  type SecurityFinding,
  type SecurityFindingDetail,
} from "@/lib/codeSecurity";

// DependencyDetail is the dependency half of the finding drawer: the
// definition rows naming the package, the lockfile excerpt, and the
// advisories read from the local OSV database at view time. Every piece
// renders only where its data exists, never an empty heading. The advisory
// text is third-party: it is shown as plain text (never markdown or HTML)
// and its links are external http(s) only.

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-1.5">
      <h3 className="m-0 text-[11px] font-medium uppercase tracking-wide text-fg-3">{title}</h3>
      {children}
    </section>
  );
}

/** DependencyRows are the drawer's definition rows for a dependency finding:
 *  package, ecosystem, how it is used, who pulled it in, and what fixes it. */
export function DependencyRows({ dep }: { dep: FindingDependency }) {
  const kind = dependencyKindWords(dep);
  const introducedBy = dep.introduced_by ?? [];
  const fixed = dep.fixed_versions ?? [];
  return (
    <>
      <DefinitionRow label="Package" value={<span className="break-all font-mono">{dependencyPackage(dep)}</span>} />
      {dep.ecosystem && <DefinitionRow label="Ecosystem" value={dep.ecosystem} />}
      {kind && <DefinitionRow label="Used as" value={kind} />}
      {introducedBy.length > 0 && (
        <DefinitionRow
          label="Introduced by"
          value={
            <ul className="m-0 list-none space-y-0.5 p-0 font-mono text-[11.5px]">
              {introducedBy.map((p) => (
                <li key={p} className="break-all">
                  {p}
                </li>
              ))}
            </ul>
          }
        />
      )}
      {fixed.length > 0 && (
        <DefinitionRow
          label="Fixed in"
          value={
            <span className="font-mono" title={dependencyFixedIn(dep)}>
              {fixed.map((v, i) => (
                <span key={v}>
                  {i > 0 && ", "}
                  {v === dep.suggested_version ? (
                    <strong className="text-accent" data-testid="code-security-suggested-version">
                      {v}
                    </strong>
                  ) : (
                    v
                  )}
                </span>
              ))}
            </span>
          }
        />
      )}
    </>
  );
}

/** LockfileExcerpt is the "In the lockfile" section: the path with its line
 *  and the excerpt's numbered lines, the match tinted; or one muted line
 *  saying why the line could not be found. */
export function LockfileExcerpt({ loc }: { loc: DependencyLocation }) {
  const context = loc.context ?? [];
  return (
    <Section title="In the lockfile">
      <p className="m-0 break-all font-mono text-[11.5px] text-fg-2">{lockfileLocationLabel(loc)}</p>
      {!loc.found ? (
        <p className="m-0 text-fg-3">{locationNotFoundWords(loc.reason)}</p>
      ) : (
        context.length > 0 && (
          <pre
            className="m-0 overflow-x-auto rounded-2 border border-line-2 bg-bg-2 py-1 font-mono text-[11.5px] leading-5"
            data-testid="code-security-lockfile-excerpt"
          >
            {context.map((c) => (
              <div
                key={c.line}
                className={clsx("flex", c.match && "bg-warn-soft")}
                data-match={c.match ? "true" : undefined}
              >
                <span className="w-12 shrink-0 select-none pr-3 text-right tabular-nums text-fg-4">{c.line}</span>
                <span className={clsx("whitespace-pre pr-3", c.match ? "text-fg-1" : "text-fg-2")}>{c.text}</span>
              </div>
            ))}
          </pre>
        )
      )}
    </Section>
  );
}

function AdvisoryView({ a }: { a: DependencyAdvisory }) {
  const [open, setOpen] = useState(false);
  const details = a.details ?? "";
  const collapsible = advisoryDetailsCollapsible(details);
  const refs = (a.references ?? []).map(safeReference).filter((r): r is NonNullable<typeof r> => r !== null);
  const ranges = (a.ranges ?? []).map(advisoryRangeWords).filter(Boolean);
  const dates = [
    a.published ? `published ${fmtRelative(a.published)}` : "",
    a.modified ? `modified ${fmtRelative(a.modified)}` : "",
  ].filter(Boolean);
  return (
    <div className="space-y-2 rounded-2 border border-line-2 p-3" data-testid={`code-security-advisory-${a.id}`}>
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
        <span className="font-mono text-fg-1">{a.id}</span>
        {(a.aliases ?? []).length > 0 && (
          <span className="font-mono text-[11px] text-fg-3">{(a.aliases ?? []).join(", ")}</span>
        )}
      </div>
      {a.summary && <p className="m-0 font-semibold text-fg-1">{a.summary}</p>}
      {dates.length > 0 && <p className="m-0 text-[11.5px] text-fg-3">{dates.join(", ")}</p>}
      {((a.cwe ?? []).length > 0) && (
        <div className="flex flex-wrap gap-1.5">
          {(a.cwe ?? []).map((c) => (
            <Pill key={c} variant="neutral">
              {c}
            </Pill>
          ))}
        </div>
      )}
      {(a.cvss ?? []).length > 0 && (
        <ul className="m-0 list-none space-y-0.5 p-0">
          {(a.cvss ?? []).map((v) => (
            <li key={v} className="break-all font-mono text-[11px] text-fg-3">
              {v}
            </li>
          ))}
        </ul>
      )}
      {details && (
        <div>
          <p
            className={clsx(
              "m-0 whitespace-pre-wrap break-words text-fg-2",
              collapsible && !open && "line-clamp-6",
            )}
            data-testid="code-security-advisory-details"
          >
            {details}
          </p>
          {a.details_truncated && (
            <p className="m-0 mt-1 text-[11.5px] text-fg-3">The advisory text was truncated.</p>
          )}
          {collapsible && (
            <Button size="sm" variant="ghost" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
              {open ? "Show less" : "Show more"}
            </Button>
          )}
        </div>
      )}
      {ranges.length > 0 && (
        <ul className="m-0 list-none space-y-0.5 p-0 text-fg-2">
          {ranges.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      )}
      {(a.affected_symbols ?? []).length > 0 && (
        <div className="space-y-1">
          <span className="text-[11px] text-fg-3">Affected symbols</span>
          <div className="flex flex-wrap gap-1.5">
            {(a.affected_symbols ?? []).map((s) => (
              <code key={s} className="rounded-1 bg-bg-3 px-1.5 py-0.5 font-mono text-[11px] text-fg-1">
                {s}
              </code>
            ))}
          </div>
        </div>
      )}
      {refs.length > 0 && (
        <ul className="m-0 list-none space-y-0.5 p-0">
          {refs.map((r) => (
            <li key={r.href} className="break-all">
              <a href={r.href} target="_blank" rel="noopener noreferrer nofollow" className="text-accent hover:underline">
                {r.host}
              </a>
              {r.type && <span className="ml-2 text-[11px] text-fg-3">{r.type}</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** AdvisorySections is the Advisory section (one block per advisory, labelled
 *  with its source), or the muted note saying why there is none. */
export function AdvisorySections({ dep }: { dep: FindingDependency }) {
  const note = advisorySourceNote(dep.advisory_source);
  if (note) return <p className="m-0 text-fg-3" data-testid="code-security-advisory-note">{note}</p>;
  const advisories = dep.advisories ?? [];
  if (dep.advisory_source !== "local_database" || advisories.length === 0) return null;
  return (
    <Section title={advisories.length > 1 ? `Advisories (${advisories.length})` : "Advisory"}>
      <p className="m-0 text-[11.5px] text-fg-3">From the local OSV database</p>
      <div className="space-y-3">
        {advisories.map((a) => (
          <AdvisoryView key={a.id} a={a} />
        ))}
      </div>
    </Section>
  );
}

/** DependencySections are the lockfile and advisory sections of a finding's
 *  detail; nothing at all for a finding that is not a dependency. */
export function DependencySections({ detail }: { detail: Pick<SecurityFindingDetail, "dependency"> }) {
  const dep = detail.dependency;
  if (!dep) return null;
  return (
    <>
      {dep.location && <LockfileExcerpt loc={dep.location} />}
      <AdvisorySections dep={dep} />
    </>
  );
}

/** SignalLabels are a dependency finding's small exploit and reach labels
 *  (KEV, EPSS, then the reach tier), as written by the server; nothing for
 *  a finding that carries none. "Exploit data unavailable" is a label of
 *  its own: missing data is never shown as "not exploited". */
export function SignalLabels({ finding }: { finding: Pick<SecurityFinding, "reach" | "exploit"> }) {
  const labels = findingSignalLabels(finding);
  if (labels.length === 0) return null;
  return (
    <span className="inline-flex flex-wrap gap-1" data-testid="code-security-signal-labels">
      {labels.map((l) => (
        <Pill key={l.text} variant={l.tone} case="none" title={l.title}>
          {l.text}
        </Pill>
      ))}
    </span>
  );
}

/** DependencySignalRows are the drawer's rows for the ranking signals: the
 *  reach tier (with its source and why it is unknown) and the exploit
 *  labels, with FIRST's citation under any EPSS score and the plain-words
 *  KEV source line (no CISA branding) under a listing. They rank and label
 *  only; they change nothing about the finding. */
export function DependencySignalRows({ finding }: { finding: Pick<SecurityFinding, "reach" | "exploit"> }) {
  const { reach, exploit } = finding;
  return (
    <>
      {reach && (
        <DefinitionRow
          label="Reachability"
          value={
            <span data-testid="code-security-reach">
              {reach.label}
              {reach.level === "not_imported_directly" && (
                <span className="block text-[11px] text-fg-3">It may still be reached through another dependency.</span>
              )}
              {reach.level === "potentially_affected" && (
                <span className="block text-[11px] text-fg-3">
                  The binary was built with an affected Go release. Whether it uses the affected code is not checked.
                </span>
              )}
              {reach.level === "called" && reach.approximate && (
                <span className="block text-[11px] text-fg-3">A call matched by name, not a resolved call.</span>
              )}
              {reach.level === "not_called" && (
                <span className="block text-[11px] text-fg-3">
                  No function the advisory lists is linked into this build. Tests, other build tags and other platforms are outside the check.
                </span>
              )}
            </span>
          }
        />
      )}
      {exploit && (
        <DefinitionRow
          label="Exploit data"
          value={
            <div className="space-y-1" data-testid="code-security-exploit">
              <SignalLabels finding={{ exploit }} />
              {exploit.kev_notice && <p className="m-0 text-[11px] text-fg-3">{exploit.kev_notice}</p>}
              {exploit.epss_citation && (
                <p className="m-0 text-[11px] text-fg-3" data-testid="code-security-epss-citation">
                  {exploit.epss_citation}
                </p>
              )}
            </div>
          }
        />
      )}
    </>
  );
}
