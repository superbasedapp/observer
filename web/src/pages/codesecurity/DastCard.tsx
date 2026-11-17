import { useState } from "react";
import { Button, Card, ConfirmButton, Input, Pill, Select, Toggle } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { fmtInt, fmtRelative } from "@/lib/format";
import { findingsHref } from "@/lib/codeSecurityApi";
import { NodeLink } from "./NodeLink";

// DastCard is the Scanners tab's passive DAST card (component security.dast;
// security coverage gaps plan docs/plans/security-coverage-gaps-plan-2026-11-13.md
// section 2). Pick a project and one of its dev servers (named by the
// project's own files; nothing is dialed to list them) or type a URL on this
// machine, accept once, and Run: a few plain GET requests to that one dev
// server, the findings stored against the project (flag only). The card
// shows only while security.dast is selected (the route answers 404
// otherwise). Every POST carries the confirm token the GET minted; the
// routes are owner-local and guard rule R-165 denies an agent the prefix.
//
// Working surface: calm register, zero delight elements.

/** The DAST route (GET state and candidates; POST .../accept and .../run). */
export const DAST_ROUTE = "/api/security/dast";
/** The driver id DAST findings carry (secdast.Driver). */
export const DAST_DRIVER = "observer-dast";

export type DastState = {
  selected: boolean;
  accepted: boolean;
  accepted_at?: string;
  accepted_on?: string;
  accept_text: string;
};

export type DastCandidate = { url: string; name: string; source: string; listening: string };
export type DastOriginRun = { origin: string; at: string; outcome: string; findings: number };

export type DastResponse = {
  state: DastState;
  confirm_token: string;
  project?: { project_root_hash: string; name: string; candidates: DastCandidate[]; last_runs: DastOriginRun[] };
};

export type DastRunResult = {
  target: string;
  outcome: string;
  requests: number;
  checks: number;
  findings: number;
  new: number;
  reason?: string;
};

export type DastProject = { project_root_hash: string; label?: string };

/** dastResultLine is one run's result in words. An unreachable dev server
 *  checked nothing and never reads as clean. */
export function dastResultLine(r: DastRunResult): string {
  if (r.outcome === "unreachable") {
    return `The dev server at ${r.target} did not answer${r.reason ? `: ${r.reason}` : ""}. Nothing was checked.`;
  }
  const found = r.findings === 0 ? "no finding" : `${fmtInt(r.findings)} ${r.findings === 1 ? "finding" : "findings"} (${fmtInt(r.new)} new)`;
  const partial = r.outcome === "partial" ? " Some probes got no answer, so nothing was closed." : "";
  return `Checked ${r.target}: ${found}, ${fmtInt(r.requests)} requests, ${fmtInt(r.checks)} checks.${partial}`;
}

/** listeningPill is a candidate's listen state as a pill, or null when the
 *  operating system exposes no listen table (unknown). */
function listeningPill(listening: string) {
  if (listening === "yes") return <Pill variant="success">listening</Pill>;
  if (listening === "no") return <Pill variant="neutral">not listening</Pill>;
  return null;
}

/** dastErrorText reads a refusal's JSON body ({error, detail}) as words. */
export function dastErrorText(status: number, body: string): string {
  try {
    const j = JSON.parse(body) as { error?: string; detail?: string };
    if (j.detail) return j.detail;
    if (j.error) return j.error;
  } catch {
    // not JSON: the text itself
  }
  return body.trim() || `HTTP ${status}`;
}

async function postDast<T>(path: string, body: unknown): Promise<T> {
  // A fresh token: the page may have been open longer than the last one.
  const res0 = await fetch(DAST_ROUTE);
  const text0 = await res0.text();
  if (!res0.ok) throw new Error(dastErrorText(res0.status, text0));
  const token = (JSON.parse(text0) as DastResponse).confirm_token ?? "";
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json", "X-Observer-Confirm": token },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(dastErrorText(res.status, text));
  return JSON.parse(text) as T;
}

export function DastCard({ projects }: { projects: DastProject[] }) {
  const [project, setProject] = useState("");
  const chosen = project || projects[0]?.project_root_hash || "";
  const api = useApi<DastResponse>(DAST_ROUTE, chosen ? { project: chosen } : undefined, [chosen]);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ project: string; run: DastRunResult } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const data = api.data;
  if (!data?.state?.selected) return null;

  async function accept() {
    setBusy(true);
    setErr(null);
    try {
      await postDast(`${DAST_ROUTE}/accept`, {});
      api.reload();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function run(url: string, insecureTLS: boolean) {
    setBusy(true);
    setErr(null);
    setResult(null);
    try {
      const out = await postDast<DastRunResult>(`${DAST_ROUTE}/run`, { project: chosen, url, insecure_tls: insecureTLS });
      setResult({ project: chosen, run: out });
      api.reload();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <DastCardView
      state={data.state}
      projects={projects}
      project={chosen}
      onProject={(h) => {
        setProject(h);
        setResult(null);
        setErr(null);
      }}
      candidates={data.project?.candidates ?? []}
      lastRuns={data.project?.last_runs ?? []}
      busy={busy}
      result={result?.project === chosen ? result.run : null}
      error={err}
      onAccept={accept}
      onRun={run}
    />
  );
}

/** DastCardView is the card's markup, pure in its props (tests render it). */
export function DastCardView({
  state,
  projects,
  project,
  onProject,
  candidates,
  lastRuns,
  busy,
  result,
  error,
  onAccept,
  onRun,
}: {
  state: DastState;
  projects: DastProject[];
  project: string;
  onProject: (hash: string) => void;
  candidates: DastCandidate[];
  lastRuns: DastOriginRun[];
  busy: boolean;
  result: DastRunResult | null;
  error: string | null;
  onAccept: () => void;
  onRun: (url: string, insecureTLS: boolean) => void;
}) {
  const [url, setURL] = useState("");
  const [insecureTLS, setInsecureTLS] = useState(false);
  const target = url.trim();
  return (
    <Card title="Passive DAST" sub="Plain GET requests to one dev server on this machine: security headers, cookies, CORS, exposed files">
      <div className="space-y-3 text-[12.5px]" data-testid="dast-card">
        {!state.accepted ? (
          <div className="space-y-2" data-testid="dast-accept">
            <p className="m-0 whitespace-pre-line rounded-2 border border-line-2 bg-bg-2 p-3 text-fg-2">{state.accept_text}</p>
            <ConfirmButton
              variant="primary"
              onConfirm={onAccept}
              disabled={busy}
              loading={busy}
              confirmLabel="Accept?"
              armedNote="Records that you read this text; a check runs only when you press Run."
            >
              I have read this, accept
            </ConfirmButton>
          </div>
        ) : (
          state.accepted_at && (
            <p className="m-0 text-fg-3">
              Accepted {fmtRelative(state.accepted_at)}
              {state.accepted_on ? ` (${state.accepted_on})` : ""}.
            </p>
          )
        )}
        {projects.length === 0 ? (
          <p className="m-0 text-fg-3">No projects yet: a project appears once an AI tool session runs in it.</p>
        ) : (
          <>
            <Select
              label="Project"
              value={project}
              onChange={(e) => onProject(e.target.value)}
              options={projects.map((p) => ({ value: p.project_root_hash, label: p.label ?? `Unknown project (${p.project_root_hash.slice(0, 8)})` }))}
            />
            <div className="space-y-1">
              <div className="text-fg-2">Dev servers this project's files name</div>
              {candidates.length === 0 ? (
                <p className="m-0 text-fg-3" data-testid="dast-no-candidates">
                  None found in .claude/launch.json, package.json scripts or framework configs. Type the URL below.
                </p>
              ) : (
                <ul className="m-0 list-none space-y-1 p-0" data-testid="dast-candidates">
                  {candidates.map((c) => (
                    <li key={c.url} className="flex flex-wrap items-center gap-2">
                      <button type="button" className="font-mono text-[11.5px] text-accent hover:underline" onClick={() => setURL(c.url)}>
                        {c.url}
                      </button>
                      <span className="text-fg-3">{c.name || c.source}</span>
                      {listeningPill(c.listening)}
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <Input
              label="URL"
              mono
              value={url}
              onChange={(e) => setURL(e.target.value)}
              placeholder="http://localhost:3000/"
              help="localhost, 127.0.0.1 or [::1] with a port; anything else is refused."
            />
            <Toggle on={insecureTLS} onChange={setInsecureTLS} label="Accept a self-signed certificate (https only)" />
            <Button variant="primary" disabled={busy || !state.accepted || !target || !project} onClick={() => onRun(target, insecureTLS)}>
              {busy ? "Checking..." : "Run"}
            </Button>
          </>
        )}
        {result && (
          <div className="flex flex-wrap items-center gap-2" data-testid="dast-result">
            <span className={result.outcome === "unreachable" ? "text-warn" : "text-fg-2"}>{dastResultLine(result)}</span>
            {result.findings > 0 && (
              <NodeLink to={findingsHref({ driver: [DAST_DRIVER], project: [project] })} variant="text">
                See them in Findings
              </NodeLink>
            )}
          </div>
        )}
        {lastRuns.length > 0 && (
          <ul className="m-0 list-none space-y-0.5 p-0 text-fg-3" data-testid="dast-last-runs">
            {lastRuns.map((r) => (
              <li key={r.origin}>
                <span className="font-mono text-[11.5px]">{r.origin}</span>
                {`: last run ${fmtRelative(r.at)}, ${r.outcome}, ${fmtInt(r.findings)} ${r.findings === 1 ? "finding" : "findings"}`}
              </li>
            ))}
          </ul>
        )}
        <p className="m-0 text-fg-3">Findings are flag only and stored against the project. An agent cannot start a run.</p>
        {error && <p className="m-0 text-danger">{error}</p>}
      </div>
    </Card>
  );
}
