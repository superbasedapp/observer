import { useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import clsx from "clsx";
import { ChevronDown, ChevronRight, ExternalLink, GitPullRequest, Link2, RefreshCw, Unlink } from "lucide-react";
import {
  Button,
  Callout,
  EmptyState,
  Icon,
  IdLink,
  Meter,
  Pill,
  SegmentedControl,
  StatCard,
  Table,
  Toggle,
} from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { ChartState } from "@/components/ChartState";
import { VocabPill } from "@shared/lib/vocabPill";
import { DeliveryWriteError, deliveryWrite, projectDeliveryPath } from "@/lib/api";
import { fmtDateTime, fmtInt, fmtRelative, fmtShortId } from "@/lib/format";
import { useApi } from "@/lib/useApi";
import { windowKey, type WindowParams } from "@/lib/projectDrawer";
import {
  CODE_HOST_STATUS,
  DELIVERY_SOURCE,
  LANDING_KIND,
  LANDING_STATUS,
  PR_CHIP,
  SCHEDULE_OPTIONS,
  entry,
  facetSentence,
  fmtSpan,
  funnelSteps,
  landingDetail,
  landingMix,
  notLandedSentence,
  prChipKey,
  prChipLabel,
  rateText,
  scheduleLabel,
  sourceSummary,
  CODE_HOSTS_HREF,
} from "@/lib/deliveryModel";
import type { DeliveryCheckResponse, DeliveryLanding, DeliveryPR, DeliverySettings, ProjectDelivery } from "@/lib/types";

// DeliveryTab - the Projects drawer's "Delivery" tab (commit to PR to merge,
// D-689; docs/projects-page.md "Delivery"). Reads GET
// /api/project/{id}/delivery and shows, for the AI-touched commits of the
// window: where the evidence comes from and how fresh it is, the accepted
// work rate (in-flight work kept apart), PR metrics only when a code host is
// connected, the prompt funnel, how commits landed, the PR table and the
// commits that are in no PR. Every row links to its session, its commit on
// the Commits tab and the PR on the code host.
//
// Writes: "Check now" (POST .../delivery/check) and the per-project mirror
// opt-in (PUT .../delivery/settings). Connecting a code host lives on
// Settings > Connected tools > Code hosts, linked from every state that
// needs it, so nothing here ends in "run this command".

type PRFilter = "all" | "open" | "merged" | "closed";

const rel = (iso?: string) => (iso ? fmtRelative(iso) : "never");

export function DeliveryTab({
  projectId,
  win,
  onOpenCommit,
  onOpenTab,
}: {
  projectId: number;
  win: WindowParams;
  /** Opens the Commits tab with that commit expanded. */
  onOpenCommit: (sha: string) => void;
  onOpenTab: (tab: "commits") => void;
}) {
  const res = useApi<ProjectDelivery>(projectDeliveryPath(projectId), { ...win }, [projectId, windowKey(win)]);
  const d = res.data;
  return (
    <div className="space-y-4">
      <ChartState
        loading={res.loading && !d}
        error={res.error}
        denied={res.denied}
        deniedPermission={res.deniedPermission}
        onRetry={res.reload}
        empty={false}
        height={220}
      >
        {d && <DeliveryBody d={d} projectId={projectId} onReload={res.reload} onOpenCommit={onOpenCommit} onOpenTab={onOpenTab} />}
      </ChartState>
    </div>
  );
}

function DeliveryBody({
  d,
  projectId,
  onReload,
  onOpenCommit,
  onOpenTab,
}: {
  d: ProjectDelivery;
  projectId: number;
  onReload: () => void;
  onOpenCommit: (sha: string) => void;
  onOpenTab: (tab: "commits") => void;
}) {
  const navigate = useNavigate();
  const openSession = (id: string) => navigate(`/sessions?session=${encodeURIComponent(id)}`);
  const s = d.summary;
  const branch = d.source.default_branch;

  if (d.source.kind === "none") {
    return (
      <EmptyState
        icon={Unlink}
        title="No remote for this project"
        body="This repository has no remote, so there is no default branch to land on. Commits are still tracked on the Commits tab."
      >
        <Button size="sm" variant="secondary" onClick={() => onOpenTab("commits")}>
          Open Commits tab
        </Button>
      </EmptyState>
    );
  }

  return (
    <div className="space-y-3">
      <SourceLine d={d} projectId={projectId} onChecked={onReload} />
      <StateCallouts d={d} />

      {s.ai_commits === 0 ? (
        <EmptyState
          icon={GitPullRequest}
          title="No AI-touched commits in this window"
          body={
            d.pending_commits > 0
              ? `${d.pending_commits} AI-touched commit${d.pending_commits === 1 ? " is" : "s are"} waiting for the next landing check. Check now evaluates them immediately.`
              : "Delivery follows commits that carried AI edits. Try a longer window in the filter bar, or open the Commits tab to see every commit."
          }
        >
          <Button size="sm" variant="secondary" onClick={() => onOpenTab("commits")}>
            Open Commits tab
          </Button>
        </EmptyState>
      ) : (
        <>
          <KpiBand d={d} />
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            <FunnelPanel d={d} />
            <MixPanel d={d} />
          </div>
          {d.provider_linked || d.pull_requests.length > 0 ? (
            <PRTable d={d} onOpenSession={openSession} onOpenCommit={onOpenCommit} />
          ) : null}
          <NotInPR d={d} onOpenSession={openSession} onOpenCommit={onOpenCommit} />
        </>
      )}
      {d.mirror_eligible && <MirrorSettings d={d} projectId={projectId} onSaved={onReload} />}
      {d.truncated && (
        <p className="text-[10.5px] text-fg-3">
          This window is larger than the dashboard reads in one go, so some rows are left out. Narrow the window to see every commit.
        </p>
      )}
      {branch && s.ai_commits > 0 && (
        <p className="text-[10.5px] text-fg-3">
          Delivery is file-level and commit-level: a commit lands when it, its patch, or the squash that carried it is on {branch}. Nothing
          here is graded.
        </p>
      )}
    </div>
  );
}

// SourceLine is the top line: where the evidence comes from, how fresh it
// is, what "landed" means, and Check now.
function SourceLine({ d, projectId, onChecked }: { d: ProjectDelivery; projectId: number; onChecked: () => void }) {
  const [phase, setPhase] = useState<"idle" | "running" | "done">("idle");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const src = entry(DELIVERY_SOURCE, d.source.kind);
  const parts = sourceSummary(d.source, rel);

  async function check() {
    setPhase("running");
    setMsg(null);
    try {
      const r = await deliveryWrite<DeliveryCheckResponse>("POST", `/api/project/${projectId}/delivery/check`);
      if (!r.done) setMsg({ ok: true, text: "Still checking in the background. Reopen this tab in a minute to see the result." });
      else if (r.error) setMsg({ ok: false, text: r.error });
      else {
        const problems = (r.result?.repos ?? []).filter((x) => !["ok", "unchanged", "refreshed", "cloned", "skipped", "not_due"].includes(x.status));
        setMsg(
          problems.length
            ? { ok: false, text: problems.map((p) => `${p.remote_name}: ${p.detail || p.status}`).join(". ") }
            : { ok: true, text: `Checked ${fmtRelative(r.result?.checked_at)}.` },
        );
      }
      onChecked();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof DeliveryWriteError ? e.message : String(e) });
    } finally {
      setPhase("done");
    }
  }

  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 px-3 py-2">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-fg-2">
          <VocabPill vocab="deliverySource" table={DELIVERY_SOURCE} value={d.source.kind} title={src.tip} />
          {parts.map((p, i) => (
            <span key={i} className={clsx("min-w-0", i > 0 && "text-fg-3")}>
              {i > 0 && <span className="mr-2 text-line-3" aria-hidden>|</span>}
              {p}
            </span>
          ))}
          <HelpInd id="glossary.delivery_sources" />
        </div>
        {d.can_check && (
          <Button
            size="sm"
            variant="secondary"
            iconLeft={RefreshCw}
            loading={phase === "running"}
            onClick={() => void check()}
            title="Ask the code host now (when connected), refresh this project's mirror (when on), then re-evaluate where every commit landed"
          >
            Check now
          </Button>
        )}
      </div>
      {msg && (
        <p aria-live="polite" className={clsx("mt-1.5 text-[11px]", msg.ok ? "text-fg-2" : "text-danger")}>
          {msg.text}
        </p>
      )}
    </div>
  );
}

// StateCallouts are the designed states: local detection off, not
// connected, a connection that stopped, stale evidence, pending commits.
function StateCallouts({ d }: { d: ProjectDelivery }) {
  const navigate = useNavigate();
  const hasGitHub = d.remotes.some((r) => r.provider === "github");
  const out: ReactNode[] = [];
  if (!d.local_enabled) {
    out.push(
      <Callout key="local" tone="info" title="Local landing detection is off.">
        Landings shown are the last ones recorded. Turn local landing detection back on in Settings, Code hosts.
      </Callout>,
    );
  }
  if (d.link_problem) {
    const st = CODE_HOST_STATUS[d.link_problem.status];
    out.push(
      <Callout
        key="link"
        tone={st?.tone === "danger" ? "danger" : "warn"}
        title={st?.action === "reconnect" ? "The code host stopped answering for this project." : "Partly up to date."}
        action={
          <Button size="sm" variant={st?.action === "reconnect" ? "primary" : "secondary"} onClick={() => navigate(CODE_HOSTS_HREF)}>
            {st?.action === "reconnect" ? "Reconnect" : "Open Code hosts"}
          </Button>
        }
      >
        {((m) => (/[.!?]$/.test(m) ? m : `${m}.`))((d.link_problem.message || st?.tip || d.link_problem.status).trim())}{" "}
        {d.link_problem.last_ok_at ? `Pull request data below is from the last good sync, ${fmtRelative(d.link_problem.last_ok_at)}, and is dimmed.` : ""}{" "}
        Landing on the default branch is still detected locally.
      </Callout>,
    );
  } else if (!d.provider_linked && d.source.kind === "mirror") {
    out.push(
      <Callout key="connect" tone="info" title="Landing from your Observer mirror.">
        Landing is read from the Observer mirror{d.source.mirror_refresh_at ? `, refreshed ${fmtRelative(d.source.mirror_refresh_at)}` : ""}, including squash and
        rebase merges, without touching your repository.{" "}
        {hasGitHub
          ? "Open PRs, drafts, conflicts, checks, reviews and closed PRs need a code host connection."
          : "This remote is not on GitHub, so PR state is not available in this release."}
      </Callout>,
    );
  } else if (!d.provider_linked) {
    out.push(
      <Callout
        key="connect"
        tone="info"
        title="Local git only."
        action={
          hasGitHub ? (
            <Button size="sm" variant="primary" iconLeft={Link2} onClick={() => navigate(CODE_HOSTS_HREF)}>
              Connect a code host
            </Button>
          ) : undefined
        }
      >
        Landing is detected from your own fetches{d.source.last_fetch_at ? ` (last fetch ${fmtRelative(d.source.last_fetch_at)})` : ""}, including
        squash and rebase merges.{" "}
        {hasGitHub
          ? "Open PRs, drafts, conflicts, checks, reviews and closed PRs need a code host connection. Nothing is sent anywhere until you connect one."
          : "This remote is not on GitHub, so PR state is not available in this release; an Observer mirror below can keep landing fresh without touching your repository."}
      </Callout>,
    );
  }
  if (d.summary.stale_caveat) {
    out.push(
      <Callout key="stale" tone="warn" title="The evidence is old.">
        The rate below is {d.summary.stale_caveat}. Fetch in your clone, or use Check now with a code host or a mirror.
      </Callout>,
    );
  }
  return out.length ? <div className="space-y-2">{out}</div> : null;
}

function KpiBand({ d }: { d: ProjectDelivery }) {
  const s = d.summary;
  const b = s.by_status;
  const inFlight = (b["in_flight"] ?? 0) + (b["in_pr"] ?? 0) + (b["pushed"] ?? 0) + (b["local_only"] ?? 0);
  const acc = rateText(s.accepted_work_rate);
  const prRate = rateText(s.pr_merge_rate);
  const merged = s.pr_merge_rate.num;
  const openPRs = d.pull_requests.filter((p) => p.state === "open").length;
  const blocked = Object.entries(s.blocked_backlog)
    .filter(([, n]) => n > 0)
    .map(([k, n]) => `${PR_CHIP[k]?.label ?? k}: ${n}`);
  const drafts = d.pull_requests.filter((p) => p.state === "draft").length;
  if (drafts) blocked.push(`draft: ${drafts}`);
  const ttm = s.time_to_merge;
  const p50 = ttm.known ? fmtSpan(ttm.p50_seconds) : null;
  const p75 = ttm.known ? fmtSpan(ttm.p75_seconds) : null;
  const landedOn = d.source.default_branch ? `Landed on ${d.source.default_branch}` : "Landed";

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard
        label="Accepted-work rate"
        helpId="glossary.delivery_accepted_rate"
        value={acc ?? "unknown"}
        sub={
          acc
            ? `${fmtInt(s.accepted_work_rate.num)} landed of ${fmtInt(s.accepted_work_rate.den)} resolved AI-touched commits. ${fmtInt(inFlight)} still in flight, left out.`
            : `${s.accepted_work_rate.unknown_reason ?? "nothing to measure yet"}: nothing has landed or been abandoned in this window. ${fmtInt(inFlight)} in flight.`
        }
      />
      {d.provider_linked ? (
        <StatCard
          label="PRs merged"
          stale={Boolean(d.link_problem)}
          value={s.pr_merge_rate.known ? fmtInt(merged) : "unknown"}
          unit={s.pr_merge_rate.known ? `of ${fmtInt(s.pr_merge_rate.den)} closed` : undefined}
          sub={prRate ? `PR merge rate ${prRate}. ${fmtInt(s.pr_merge_rate.den - merged)} closed without merging.` : "No PR holding an AI-touched commit was merged or closed in this window."}
        />
      ) : (
        <StatCard
          label={landedOn}
          value={fmtInt(b["landed"] ?? 0)}
          unit={`of ${fmtInt(s.ai_commits)}`}
          sub={`${fmtInt(s.landed_exact)} exact sha, ${fmtInt(s.landed_patch)} patch-id, ${fmtInt(s.landed_squash)} squash.`}
        />
      )}
      {d.provider_linked ? (
        <StatCard
          label="Open and mergeable"
          stale={Boolean(d.link_problem)}
          value={s.open_mergeable.known ? fmtInt(s.open_mergeable.value) : "unknown"}
          unit={s.open_mergeable.known ? `of ${fmtInt(openPRs)} open` : undefined}
          sub={blocked.length ? `${blocked.join(", ")}.` : openPRs ? "Nothing blocking." : "No open PR holds an AI-touched commit."}
        />
      ) : (
        <StatCard label="PRs merged" value="unknown" sub="Needs a code host connection. Local git cannot see pull requests." />
      )}
      <StatCard
        label="Time to merge"
        stale={ttm.source === "provider" && Boolean(d.link_problem)}
        value={p50 ?? "unknown"}
        unit={p50 ? (ttm.source === "provider" ? "median" : "median, approx") : undefined}
        sub={
          p50
            ? `p75 ${p75}, ${fmtInt(ttm.samples)} ${ttm.source === "provider" ? "merged PRs, opened to merged" : "commits, first commit to first seen landed; depends on how often you fetch"}.`
            : "Nothing merged in this window yet."
        }
      />
    </div>
  );
}

function FunnelPanel({ d }: { d: ProjectDelivery }) {
  const f = d.summary.funnel;
  const steps = funnelSteps(f, d.source.default_branch, d.provider_linked);
  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 px-4 py-3">
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          From prompt to landed <HelpInd id="glossary.delivery_funnel" />
        </span>
        <span className="text-[10px] text-fg-4">prompt units</span>
      </div>
      {!f.known || f.edited_prompts === 0 ? (
        <p className="mt-2 text-[11px] text-fg-3">No prompt in this window had the AI edit a file.</p>
      ) : (
        <ul className="mt-2 space-y-2">
          {steps.map((st) => (
            <li key={st.key} className="grid grid-cols-[minmax(0,8rem)_1fr_auto] items-center gap-2 text-[11px] sm:grid-cols-[10rem_1fr_auto]">
              <span className="truncate text-fg-2">{st.label}</span>
              <Meter ratio={st.ofFirst} tone="accent" label={st.label} />
              <span className="whitespace-nowrap tabular-nums text-fg-1">
                {st.value == null ? (
                  <span className="italic text-fg-4" title="Local git cannot see pull requests, and no merge commit named one. Connect a code host to see this step.">
                    unknown
                  </span>
                ) : (
                  fmtInt(st.value)
                )}
                <span className="ml-1.5 inline-block w-9 text-right text-fg-4">{st.ofPrev == null ? "" : `${Math.round(st.ofPrev * 100)}%`}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
      <p className="mt-2 text-[10.5px] text-fg-3">{f.caveat} Percent is step over step.</p>
    </section>
  );
}

// DOT is the legend dot colour per tone (the same tone the Meter segment uses).
const DOT: Record<string, string> = { accent: "bg-accent", info: "bg-info", success: "bg-success", neutral: "bg-fg-4" };

function MixPanel({ d }: { d: ProjectDelivery }) {
  const s = d.summary;
  const mix = landingMix(s);
  const total = mix.reduce((a, m) => a + m.value, 0);
  const rest = notLandedSentence(s);
  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 px-4 py-3">
      <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        How AI-touched commits landed <HelpInd id="glossary.delivery_landing" />
      </span>
      {total === 0 ? (
        <p className="mt-2 text-[11px] text-fg-3">Nothing has landed in this window yet.</p>
      ) : (
        <>
          <Meter className="mt-2" segments={mix.filter((m) => m.value > 0).map((m) => ({ value: m.value / total, label: m.label, tone: m.tone }))} label="Landing mix" />
          <ul className="mt-2 space-y-1 text-[11px]">
            {mix.map((m) => (
              <li key={m.key} className="flex items-center justify-between gap-2">
                <span className="flex min-w-0 items-center gap-1.5 text-fg-2">
                  <span className={clsx("h-2 w-2 shrink-0 rounded-full", DOT[m.tone] ?? "bg-fg-4")} aria-hidden />
                  <span className="truncate">{m.label}</span>
                </span>
                <span className="tabular-nums text-fg-1">{fmtInt(m.value)}</span>
              </li>
            ))}
          </ul>
        </>
      )}
      {rest && <p className="mt-2 text-[10.5px] text-fg-3">{rest}</p>}
    </section>
  );
}

function prMatches(p: DeliveryPR, f: PRFilter): boolean {
  if (f === "all") return true;
  if (f === "open") return p.state === "open" || p.state === "draft";
  if (f === "merged") return p.state === "merged";
  return p.state === "closed_unmerged";
}

function PRTable({
  d,
  onOpenSession,
  onOpenCommit,
}: {
  d: ProjectDelivery;
  onOpenSession: (id: string) => void;
  onOpenCommit: (sha: string) => void;
}) {
  const [filter, setFilter] = useState<PRFilter>("all");
  const [open, setOpen] = useState<number | null>(null);
  const counts = useMemo(() => {
    const c: Record<PRFilter, number> = { all: 0, open: 0, merged: 0, closed: 0 };
    for (const p of d.pull_requests) for (const k of ["all", "open", "merged", "closed"] as PRFilter[]) if (prMatches(p, k)) c[k]++;
    return c;
  }, [d.pull_requests]);
  const rows = d.pull_requests.filter((p) => prMatches(p, filter));

  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 px-3 py-3 sm:px-4">
      <div className="mb-2 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">Pull requests with AI-touched commits</span>
        <SegmentedControl
          size="sm"
          value={filter}
          onChange={setFilter}
          options={[
            { value: "all", label: `All ${counts.all}` },
            { value: "open", label: `Open ${counts.open}` },
            { value: "merged", label: `Merged ${counts.merged}` },
            { value: "closed", label: `Closed ${counts.closed}` },
          ]}
        />
      </div>
      {rows.length === 0 ? (
        <p className="text-[11px] text-fg-3">
          {d.pull_requests.length === 0
            ? "No pull request holds an AI-touched commit from this window yet. The first sync after connecting can take a few minutes; Check now reads it immediately."
            : "No pull request in this group."}
        </p>
      ) : (
        <Table
          size="sm"
          head={
            <tr>
              <th className="w-4 py-1.5" />
              <th className="w-full py-1.5 font-medium">Pull request</th>
              <th className="whitespace-nowrap py-1.5 pl-3 font-medium">State</th>
              <th className="hidden whitespace-nowrap py-1.5 pl-3 text-right font-medium sm:table-cell">AI commits</th>
              <th className="hidden whitespace-nowrap py-1.5 pl-3 font-medium md:table-cell">Sessions</th>
              <th className="hidden whitespace-nowrap py-1.5 pl-3 text-right font-medium md:table-cell">Opened</th>
              <th className="hidden whitespace-nowrap py-1.5 pl-3 pr-1 text-right font-medium sm:table-cell">Merged or closed</th>
            </tr>
          }
        >
          {rows.map((p) => (
            <PRRows
              key={p.id}
              p={p}
              open={open === p.id}
              onToggle={() => setOpen((c) => (c === p.id ? null : p.id))}
              onOpenSession={onOpenSession}
              onOpenCommit={onOpenCommit}
            />
          ))}
        </Table>
      )}
    </section>
  );
}

function PRRows({
  p,
  open,
  onToggle,
  onOpenSession,
  onOpenCommit,
}: {
  p: DeliveryPR;
  open: boolean;
  onToggle: () => void;
  onOpenSession: (id: string) => void;
  onOpenCommit: (sha: string) => void;
}) {
  const chip = PR_CHIP[prChipKey(p)];
  const end = p.state === "merged" ? p.merged_at : p.state === "closed_unmerged" ? p.closed_at : undefined;
  const facets = facetSentence(p);
  const endText = end ? `${p.state === "merged" ? "merged" : "closed"} ${fmtRelative(end)}` : p.state;
  return (
    <>
      <tr
        className={clsx("cursor-pointer border-b border-line-1 last:border-0 hover:bg-bg-3/40", p.stale && "opacity-60")}
        onClick={onToggle}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onToggle();
          }
        }}
        tabIndex={0}
        aria-expanded={open}
      >
        <td className="py-1.5 text-center text-fg-4">
          <Icon icon={open ? ChevronDown : ChevronRight} size="xs" className="inline-block" />
        </td>
        <td className="w-full min-w-[8rem] max-w-0 py-1.5">
          <div className="flex min-w-0 items-center gap-1.5">
            {p.url ? (
              <a
                href={p.url}
                target="_blank"
                rel="noreferrer noopener"
                onClick={(e) => e.stopPropagation()}
                className="inline-flex shrink-0 items-center gap-0.5 font-mono text-[11px] font-semibold text-accent hover:underline"
                title={`Open #${p.number} on ${p.host}`}
              >
                #{p.number}
                <Icon icon={ExternalLink} size="xs" />
              </a>
            ) : (
              <span className="shrink-0 font-mono text-[11px] font-semibold text-fg-1">#{p.number}</span>
            )}
            <span className="truncate text-[11px] text-fg-2" title={p.title}>
              {p.title || "(no title)"}
            </span>
          </div>
          <div className="mt-0.5 flex items-center gap-1.5 text-[10.5px] tabular-nums text-fg-4 sm:hidden">
            <span>{endText}</span>
            {p.stale && (
              <Pill variant="warn" title={`Last synced ${rel(p.fetched_at)}; the connection is not healthy right now.`}>
                stale
              </Pill>
            )}
          </div>
        </td>
        <td className="py-1.5 pl-3">
          <span className="inline-flex items-center gap-1 whitespace-nowrap">
            <VocabPill vocab="deliveryPR" table={PR_CHIP} value={prChipKey(p)} title={`${chip?.tip ?? ""}${p.raw_state ? ` Code host says: ${p.raw_state}.` : ""}`}>
              {prChipLabel(p)}
            </VocabPill>
            {p.stale && (
              // On a phone the stale chip moves under the title (above), so the
              // state column stays narrow and nothing clips at the edge.
              <span className="hidden sm:inline-flex">
                <Pill variant="warn" title={`Last synced ${rel(p.fetched_at)}; the connection is not healthy right now.`}>
                  stale
                </Pill>
              </span>
            )}
          </span>
        </td>
        <td className="hidden py-1.5 pl-3 text-right tabular-nums text-fg-2 sm:table-cell">{fmtInt(p.ai_commits.length)}</td>
        <td className="hidden py-1.5 pl-3 md:table-cell" onClick={(e) => e.stopPropagation()}>
          <span className="flex gap-1.5 whitespace-nowrap">
            {p.sessions.slice(0, 3).map((id) => (
              <IdLink key={id} onClick={() => onOpenSession(id)} title={id}>
                {fmtShortId(id, 8)}
              </IdLink>
            ))}
            {p.sessions.length > 3 && <span className="text-[10.5px] text-fg-4">+{p.sessions.length - 3}</span>}
          </span>
        </td>
        <td className="hidden whitespace-nowrap py-1.5 pl-3 text-right tabular-nums text-fg-3 md:table-cell" title={p.created_at ? fmtDateTime(p.created_at) : undefined}>
          {rel(p.created_at)}
        </td>
        <td className="hidden whitespace-nowrap py-1.5 pl-3 pr-1 text-right tabular-nums text-fg-3 sm:table-cell" title={end ? fmtDateTime(end) : undefined}>
          {endText}
        </td>
      </tr>
      {open && (
        <tr className="border-b border-line-1 bg-bg-2/60 last:border-0">
          <td />
          <td colSpan={6} className="py-2 pr-2">
            <p className="mb-1.5 text-[11px] text-fg-3">
              {p.state === "merged" && p.merge_seconds ? `Merged ${fmtSpan(p.merge_seconds)} after it opened` : `In ${p.repo_slug}`}
              {p.merge_method ? ` (${p.merge_method})` : ""}. {fmtInt(p.ai_commits.length)} AI-touched commit{p.ai_commits.length === 1 ? "" : "s"},{" "}
              {fmtInt(p.sessions.length)} session{p.sessions.length === 1 ? "" : "s"}.{facets ? ` ${facets[0].toUpperCase()}${facets.slice(1)}.` : ""}
            </p>
            <ul className="divide-y divide-line-1">
              {p.ai_commits.map((c) => (
                <LandingLine key={c.commit_id} l={c} hasPR onOpenSession={onOpenSession} onOpenCommit={onOpenCommit} />
              ))}
            </ul>
          </td>
        </tr>
      )}
    </>
  );
}

// LandingLine is one commit with its landing chips, session and prompt.
function LandingLine({
  l,
  hasPR,
  onOpenSession,
  onOpenCommit,
}: {
  l: DeliveryLanding;
  hasPR: boolean;
  onOpenSession: (id: string) => void;
  onOpenCommit: (sha: string) => void;
}) {
  const detail = landingDetail(l, hasPR);
  const session = l.owner_session_id || l.session_ids[0];
  return (
    <li className="flex flex-col gap-1 py-1.5 text-[11px]">
      <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
        <button
          type="button"
          onClick={() => onOpenCommit(l.sha)}
          className="font-mono text-fg-1 hover:text-accent hover:underline"
          title="Open this commit on the Commits tab"
        >
          {l.sha.slice(0, 7)}
        </button>
        <span className="min-w-0 flex-1 truncate text-fg-2" title={l.subject}>
          {l.subject}
        </span>
        <span className="flex shrink-0 flex-wrap items-center gap-1">
          {!(hasPR && l.status === "landed") && (
            <VocabPill vocab="landingStatus" table={LANDING_STATUS} value={l.status} title={entry(LANDING_STATUS, l.status).tip} />
          )}
          {l.kind && <VocabPill vocab="landingKind" table={LANDING_KIND} value={l.kind} title={entry(LANDING_KIND, l.kind).tip} />}
        </span>
      </div>
      <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5 text-fg-3">
        {session && (
          <span className="inline-flex items-center gap-1">
            session
            <IdLink onClick={() => onOpenSession(session)} title={session}>
              {fmtShortId(session, 8)}
            </IdLink>
          </span>
        )}
        {l.prompt && (
          <span className="min-w-0 max-w-full truncate" title={l.prompt.preview}>
            prompt <span className="text-fg-2">"{l.prompt.preview}"</span>
          </span>
        )}
        {detail && <span>{detail}</span>}
        {l.landed_at && l.status === "landed" && <span title={fmtDateTime(l.landed_at)}>landed {fmtRelative(l.landed_at)}</span>}
      </div>
    </li>
  );
}

function NotInPR({
  d,
  onOpenSession,
  onOpenCommit,
}: {
  d: ProjectDelivery;
  onOpenSession: (id: string) => void;
  onOpenCommit: (sha: string) => void;
}) {
  const [all, setAll] = useState(false);
  if (d.not_in_pr_total === 0) return null;
  const shown = all ? d.not_in_pr : d.not_in_pr.slice(0, 6);
  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 px-3 py-3 sm:px-4">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          {d.provider_linked ? "Not in a pull request" : "AI-touched commits"}{" "}
          <span className="ml-1 font-normal normal-case tracking-normal text-fg-4">
            {fmtInt(d.not_in_pr_total)} commit{d.not_in_pr_total === 1 ? "" : "s"}
          </span>
        </span>
      </div>
      <ul className="mt-1 divide-y divide-line-1">
        {shown.map((l) => (
          <LandingLine key={l.commit_id} l={l} hasPR={false} onOpenSession={onOpenSession} onOpenCommit={onOpenCommit} />
        ))}
      </ul>
      {(d.not_in_pr.length > shown.length || d.not_in_pr_total > d.not_in_pr.length) && (
        <p className="mt-1 text-[10.5px] text-fg-3">
          {d.not_in_pr.length > shown.length ? (
            <button type="button" className="text-accent hover:underline" onClick={() => setAll(true)}>
              Show all {fmtInt(d.not_in_pr.length)}
            </button>
          ) : (
            `Showing ${fmtInt(d.not_in_pr.length)} of ${fmtInt(d.not_in_pr_total)}. Narrow the window to see the rest.`
          )}
        </p>
      )}
    </section>
  );
}

// MirrorSettings is the per-project mirror opt-in and refresh schedule, for
// remotes no code host link serves.
function MirrorSettings({ d, projectId, onSaved }: { d: ProjectDelivery; projectId: number; onSaved: () => void }) {
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const settings = d.settings;
  const mirrors = d.remotes.filter((r) => r.mirror).map((r) => r.mirror!);

  async function save(next: DeliverySettings) {
    setSaving(true);
    setErr(null);
    try {
      await deliveryWrite<DeliverySettings>("PUT", `/api/project/${projectId}/delivery/settings`, {
        mirror_enabled: next.mirror_enabled,
        schedule_minutes: next.mirror_enabled ? next.schedule_minutes : 0,
      });
      onSaved();
    } catch (e) {
      setErr(e instanceof DeliveryWriteError ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  const options: readonly (typeof SCHEDULE_OPTIONS)[number][] = SCHEDULE_OPTIONS.some((o) => o.value === settings.schedule_minutes)
    ? SCHEDULE_OPTIONS
    : [...SCHEDULE_OPTIONS, { value: settings.schedule_minutes, label: scheduleLabel(settings.schedule_minutes) }];

  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 px-3 py-3 sm:px-4">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 text-[11.5px] font-medium text-fg-1">
            Observer mirror for this project <HelpInd id="glossary.delivery_mirrors" />
          </div>
          <p className="mt-0.5 text-[11px] text-fg-3">
            A bare, blobless copy of the remote, kept in Observer's own data folder, keeps landing fresh without waiting for you to fetch. It uses
            your own git credentials read-only, and never writes to your repository. Off by default.
          </p>
        </div>
        <Toggle
          on={settings.mirror_enabled}
          disabled={saving}
          onChange={(on) => void save({ ...settings, mirror_enabled: on })}
          label={settings.mirror_enabled ? "On" : "Off"}
          ariaLabel="Keep an Observer mirror for this project"
        />
      </div>
      {settings.mirror_enabled && (
        <div className="mt-2 space-y-1.5">
          <span className="block text-[11px] font-medium text-fg-2">Refresh</span>
          {/* The shared SegmentedControl, never a native select. A click while
              a save is in flight is ignored rather than queued. */}
          <SegmentedControl
            size="sm"
            className="flex-wrap"
            value={String(settings.schedule_minutes)}
            onChange={(v) => {
              if (!saving) void save({ ...settings, schedule_minutes: Number(v) });
            }}
            options={options.map((o) => ({ value: String(o.value), label: o.short ?? o.label }))}
          />
          <p className="text-[10.5px] text-fg-3">
            Each refresh first asks the remote whether the default branch moved, and skips the download when it did not.
          </p>
        </div>
      )}
      {mirrors.length > 0 && (
        <ul className="mt-2 space-y-0.5 text-[10.5px] text-fg-3">
          {mirrors.map((m) => (
            <li key={m.id} className="flex flex-wrap items-center gap-x-2">
              <span className="font-mono text-fg-2">{m.url}</span>
              <span>{m.status}</span>
              {m.last_refresh_at && <span>refreshed {fmtRelative(m.last_refresh_at)}</span>}
              {m.last_error && <span className="text-danger">{m.last_error}</span>}
            </li>
          ))}
        </ul>
      )}
      <p className="mt-2 text-[10.5px] text-fg-3">
        Mirrors count toward disk; see sizes and delete them under{" "}
        <Link to={CODE_HOSTS_HREF} className="text-accent hover:underline">
          Settings, Code hosts
        </Link>
        .
      </p>
      {err && <p className="mt-1 text-[11px] text-danger">{err}</p>}
      {!d.can_check && settings.mirror_enabled && (
        <p className="mt-1 text-[10.5px] text-fg-3">Scheduled refreshes run while the Observer daemon is running; this dashboard process does not run them.</p>
      )}
    </section>
  );
}
