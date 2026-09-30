import { useState } from "react";
import { Icon, Pill, Table, TruncatedPath } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { TruncationBanner } from "@/components/projectdetail/TruncationBanner";
import { useApi } from "@/lib/useApi";
import { fmtDateOnly, fmtDateRange, fmtInt, fmtRelative } from "@/lib/format";
import {
  AMBIGUOUS_INVOCATIONS_NOTE,
  cellsForSkill,
  commitStatusLabel,
  currentCaveat,
  currentLabel,
  headLabel,
  invocationLabel,
  invokedEventLabel,
  observedLabel,
  sessionsForSkill,
  UNMATCHED_INVOCATIONS_NOTE,
  versionLabel,
  type SkillLabel,
  type SkillTone,
} from "@/lib/skills";
import type {
  ProjectSkill,
  ProjectSkillsResponse,
  SkillGitCapture,
  SkillGitCaptureState,
  SkillSessionRelation,
} from "@/lib/types";
import { ChevronDown, ChevronRight } from "lucide-react";

// SkillsTab — per-project Claude Code skills (.claude/skills/<name>/SKILL.md,
// project-scoped and home ~/.claude/skills), how each changed across
// commits, and which version each session had. THREE facts are shown
// separately and never merged: "Available at start (observed)" — a hook
// snapshot hashed on disk; "HEAD at start" — the committed content at the
// commit the git reflog says HEAD was on, NOT the working copy; "Invoked" —
// Skill-tool invocations with the version invoked.

const TONE_VARIANT: Record<SkillTone, "success" | "neutral" | "warn"> = {
  ok: "success",
  muted: "neutral",
  warn: "warn",
};

function LabelPill({ label }: { label: SkillLabel }) {
  return (
    <Pill variant={TONE_VARIANT[label.tone]} title={label.tip}>
      {label.text}
    </Pill>
  );
}

// GIT_STATE_COPY is the table-driven capture-strip line for each git scan
// state; "ok" and "partial" need a field off the row (a date, an error
// string) so they're functions rather than bare strings.
const GIT_STATE_COPY: Record<SkillGitCaptureState, (git: SkillGitCapture) => { text: string; tone: SkillTone }> = {
  not_scanned: () => ({
    text: "Git history not scanned yet (or not a git repository).",
    tone: "muted",
  }),
  partial: (git) => ({
    text: git.error || "Git history scan incomplete.",
    tone: "warn",
  }),
  ok: (git) => ({
    text: git.reflog_since
      ? `HEAD reflog captured since ${fmtDateOnly(git.reflog_since)}.`
      : "Git history scanned; no HEAD reflog entries yet.",
    tone: "ok",
  }),
};

const RELATION_LABEL: Record<SkillSessionRelation, string> = {
  "": "",
  subagent: "subagent",
  fork: "fork",
};

export function SkillsTab({ projectId, days }: { projectId: number; days: number }) {
  const [expanded, setExpanded] = useState<string | null>(null);

  const skills = useApi<ProjectSkillsResponse>(
    `/api/project/${projectId}/skills`,
    { days },
    [projectId, days],
  );
  const d = skills.data;
  const rows = d?.skills ?? [];

  // sessionRelation looks up a session's relation tag (subagent/fork) by
  // id, for labelling a notable cell's session.
  const sessionRelation = (sessionId: string): string => {
    const s = d?.sessions.find((row) => row.id === sessionId);
    return s ? RELATION_LABEL[s.relation] : "";
  };

  return (
    <div className="space-y-3">
      {d && <CaptureStrip capture={d.capture} />}
      {d?.truncated && (
        <TruncationBanner>
          Row caps hit for this window - some skills, versions, or sessions may be missing from
          the view below.
        </TruncationBanner>
      )}

      <ChartState
        loading={skills.loading && !skills.data}
        error={skills.error}
        denied={skills.denied}
        deniedPermission={skills.deniedPermission}
        empty={!skills.loading && rows.length === 0}
        emptyHint="No skills found for this project. Skills live in .claude/skills/<name>/SKILL.md (project) or ~/.claude/skills (home)."
        height={200}
      >
        {d && (
          <div className="space-y-4">
            <Table
              head={
                <tr>
                  <th className="w-4 py-1.5" />
                  <th className="py-1.5 font-medium">Name</th>
                  <th className="py-1.5 font-medium">Git status</th>
                  <th className="py-1.5 font-medium">Current version</th>
                  <th className="py-1.5 text-right font-medium">Versions</th>
                  <th className="py-1.5 text-right font-medium">Commits</th>
                  <th className="py-1.5 pr-1 text-right font-medium">Invoked</th>
                </tr>
              }
            >
              {rows.map((skill) => (
                <SkillRows
                  key={skill.key}
                  skill={skill}
                  resp={d}
                  open={expanded === skill.key}
                  onToggle={() => setExpanded((cur) => (cur === skill.key ? null : skill.key))}
                  sessionRelation={sessionRelation}
                />
              ))}
            </Table>

            {d.unmatched_invocations.length > 0 && (
              <div className="text-[10.5px] text-fg-4">
                <p>{UNMATCHED_INVOCATIONS_NOTE}</p>
                <ul className="mt-1 space-y-0.5">
                  {d.unmatched_invocations.map((u, i) => (
                    <li key={i}>
                      {u.tool}: {u.name} ({fmtInt(u.count)})
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {d.ambiguous_invocations.length > 0 && (
              <div className="text-[10.5px] text-fg-4">
                <p>{AMBIGUOUS_INVOCATIONS_NOTE}</p>
                <ul className="mt-1 space-y-0.5">
                  {d.ambiguous_invocations.map((a, i) => (
                    <li key={i}>
                      {a.tool}: {a.name} ({fmtInt(a.count)}) - candidates: {a.candidates.join(", ")}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <Legend />
          </div>
        )}
      </ChartState>
    </div>
  );
}

function CaptureStrip({ capture }: { capture: ProjectSkillsResponse["capture"] }) {
  const observedLine = capture.observed_since
    ? `Observed since ${fmtDateOnly(capture.observed_since)}.`
    : "No skill snapshots yet.";
  const git = GIT_STATE_COPY[capture.git.state](capture.git);

  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 px-3 py-2 text-[11px] text-fg-3">
      <p>{observedLine}</p>
      <p className={git.tone === "warn" ? "mt-0.5 text-warn" : "mt-0.5"}>{git.text}</p>
      {capture.git.shallow && (
        <p className="mt-0.5">Shallow clone: older history unavailable.</p>
      )}
      {capture.git.probe_unknown.length > 0 && (
        <p className="mt-0.5 text-warn">
          Repository probe failed ({capture.git.probe_unknown.join(", ")}): treated as unknown.
        </p>
      )}
    </div>
  );
}

function Legend() {
  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 px-3 py-2 text-[10.5px] text-fg-4">
      <p className="mb-1 font-medium text-fg-3">Three facts, never merged</p>
      <ul className="space-y-0.5">
        <li>
          <span className="text-fg-3">Available at start (observed)</span> - what a hook snapshot
          hashed on disk at the start of a session.
        </li>
        <li>
          <span className="text-fg-3">HEAD at start</span> - the committed content at the commit
          the git reflog says HEAD was on at that time, not the working copy.
        </li>
        <li>
          <span className="text-fg-3">Invoked</span> - Skill-tool invocations, with the version
          invoked when captured.
        </li>
      </ul>
    </div>
  );
}

function SkillRows({
  skill,
  resp,
  open,
  onToggle,
  sessionRelation,
}: {
  skill: ProjectSkill;
  resp: ProjectSkillsResponse;
  open: boolean;
  onToggle: () => void;
  sessionRelation: (sessionId: string) => string;
}) {
  const caveat = currentCaveat(skill);
  const headVersionText = versionLabel(skill, skill.current.head_version);

  return (
    <>
      <tr
        onClick={onToggle}
        className="cursor-pointer border-b border-line-1 last:border-0 hover:bg-bg-3/40"
      >
        <td className="py-1.5 text-center text-fg-4">
          <Icon icon={open ? ChevronDown : ChevronRight} size="xs" className="inline-block" />
        </td>
        <td className="py-1.5">
          <div className="flex items-center gap-1.5">
            <TruncatedPath value={skill.name} className="max-w-[220px] font-mono text-[11px] text-fg-1" />
            <Pill variant="neutral">{skill.scope}</Pill>
            {skill.ambiguous && (
              <Pill variant="warn" title="More than one skill shares this name; invocations by name could not be attributed with confidence.">
                ambiguous
              </Pill>
            )}
            {!skill.present && <Pill variant="neutral">not present</Pill>}
          </div>
          <div className="mt-0.5 max-w-[320px] truncate text-[11px] text-fg-3">{skill.dir}</div>
        </td>
        <td className="py-1.5">
          <div className="flex items-center gap-1.5">
            <LabelPill label={currentLabel(skill)} />
            {caveat && <Pill variant="warn" title={caveat}>versions unmatched</Pill>}
          </div>
        </td>
        <td className="py-1.5 font-mono text-[11px] text-fg-2">{headVersionText || "-"}</td>
        <td className="py-1.5 text-right tabular-nums text-fg-3">{fmtInt(skill.versions.length)}</td>
        <td className="py-1.5 text-right tabular-nums text-fg-3">{fmtInt(skill.commits.length)}</td>
        <td className="py-1.5 pr-1 text-right">
          <LabelPill label={invocationLabel(skill)} />
        </td>
      </tr>
      {open && (
        <tr className="border-b border-line-1 last:border-0 bg-bg-2/60">
          <td />
          <td colSpan={6} className="space-y-4 py-3 pr-3">
            <SkillVersionSection skill={skill} />
            <SkillCommitSection skill={skill} />
            <SkillSessionSection skill={skill} resp={resp} sessionRelation={sessionRelation} />
          </td>
        </tr>
      )}
    </>
  );
}

function SectionHeading({ children }: { children: string }) {
  return (
    <h4 className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
      {children}
    </h4>
  );
}

function SkillVersionSection({ skill }: { skill: ProjectSkill }) {
  if (skill.versions.length === 0) {
    return (
      <div>
        <SectionHeading>Versions</SectionHeading>
        <p className="text-[11px] text-fg-4">No versions recorded.</p>
      </div>
    );
  }
  return (
    <div>
      <SectionHeading>Versions</SectionHeading>
      <ul className="space-y-1.5">
        {skill.versions.map((v) => (
          <li key={v.id} className="text-[11px]">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="font-mono text-fg-1">{`#${v.ordinal} ${v.id}`}</span>
              {v.introduced_by ? (
                <span className="text-fg-3">
                  introduced by <span className="font-mono">{v.introduced_by.sha.slice(0, 7)}</span>{" "}
                  {v.introduced_by.subject} ({fmtDateOnly(v.introduced_by.committed_at)})
                </span>
              ) : v.in_commits ? (
                <Pill
                  variant="neutral"
                  title="The content is in a recorded commit, but the commit that introduced it is not resolved yet, or is no longer on the branch."
                >
                  introducing commit not resolved
                </Pill>
              ) : (
                <Pill variant="neutral">content not in any recorded commit</Pill>
              )}
              {v.reintroduced_in.length > 0 && (
                <Pill variant="neutral" title={v.reintroduced_in.join(", ")}>
                  reintroduced x{v.reintroduced_in.length}
                </Pill>
              )}
            </div>
            <div className="mt-0.5 text-fg-4">
              {v.observed_first ? `observed ${fmtDateRange(v.observed_first, v.observed_last)}` : "not observed by a hook snapshot"} ·{" "}
              {fmtInt(v.sessions_available)} sessions available · {fmtInt(v.invocations)} invocations
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function SkillCommitSection({ skill }: { skill: ProjectSkill }) {
  if (skill.commits.length === 0) {
    return (
      <div>
        <SectionHeading>Commits</SectionHeading>
        <p className="text-[11px] text-fg-4">No recorded commit touched this skill's directory.</p>
      </div>
    );
  }
  return (
    <div>
      <SectionHeading>Commits</SectionHeading>
      <ul className="space-y-1">
        {skill.commits.map((c) => (
          <li key={c.sha} className="flex flex-wrap items-center gap-1.5 text-[11px]">
            <span className="font-mono text-fg-1">{c.sha.slice(0, 7)}</span>
            <span className="text-fg-4">{fmtDateOnly(c.committed_at)}</span>
            <span className="min-w-0 flex-1 truncate text-fg-2">{c.subject}</span>
            {c.status && (
              <Pill
                variant="neutral"
                title={c.status === "?" ? "Not certain yet: this or an earlier commit's tree is not resolved, or it shares a second with an unrelated commit." : undefined}
              >
                {commitStatusLabel(c.status)}
              </Pill>
            )}
            {c.is_merge && <Pill variant="neutral">merge</Pill>}
            {!c.skill_md_changed && <Pill variant="neutral">SKILL.md unchanged</Pill>}
            {!c.reachable && (
              <Pill variant="warn" title="This sha fell out of the checked-out branch's history on a later scan.">
                unreachable
              </Pill>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function SkillSessionSection({
  skill,
  resp,
  sessionRelation,
}: {
  skill: ProjectSkill;
  resp: ProjectSkillsResponse;
  sessionRelation: (sessionId: string) => string;
}) {
  const spans = sessionsForSkill(resp, skill.key);
  const cells = cellsForSkill(resp, skill.key);

  return (
    <div>
      <SectionHeading>Sessions</SectionHeading>
      {spans.length === 0 ? (
        <p className="text-[11px] text-fg-4">No sessions recorded for this skill in this window.</p>
      ) : (
        <ul className="space-y-1">
          {spans.map((s, i) => (
            <li key={`${s.from_session}-${s.to_session}-${i}`} className="flex flex-wrap items-center gap-1.5 text-[11px]">
              <span className="text-fg-3">{fmtDateRange(s.from, s.to)}</span>
              <span className="text-fg-4">
                ({fmtInt(s.sessions)} session{s.sessions === 1 ? "" : "s"})
              </span>
              <span className="text-fg-4">observed</span>
              <LabelPill label={observedLabel(skill, s.observed)} />
              <span className="text-fg-4">HEAD</span>
              <LabelPill label={headLabel(skill, s.head)} />
            </li>
          ))}
        </ul>
      )}

      {cells.length > 0 && (
        <ul className="mt-2 space-y-1 border-t border-line-1 pt-2">
          {cells.map((c, i) => {
            const relation = sessionRelation(c.session_id);
            return (
              <li key={`${c.session_id}-${i}`} className="text-[11px]">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="font-mono text-fg-2">{c.session_id.slice(0, 8)}</span>
                  {relation && <Pill variant="neutral">{relation}</Pill>}
                  <span className="text-fg-4">observed</span>
                  <LabelPill label={observedLabel(skill, c.observed)} />
                  <span className="text-fg-4">HEAD</span>
                  <LabelPill label={headLabel(skill, c.head)} />
                </div>
                {c.invoked.length > 0 && (
                  <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
                    {c.invoked.map((inv, j) => (
                      <span key={j} className="flex items-center gap-1 text-fg-4">
                        <LabelPill label={invokedEventLabel(skill, inv)} />
                        <span>{fmtRelative(inv.at)}</span>
                      </span>
                    ))}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
