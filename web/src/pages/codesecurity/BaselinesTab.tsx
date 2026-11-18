import { useState } from "react";
import { Button, Card, EmptyState, Select } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { ApiErrorNotice } from "@/components/NeedsSettingNotice";
import { errorNote, type ErrorNote } from "@/lib/needsSetting";
import { BaselineStatus } from "@/components/security/BaselineStatus";
import { useApi } from "@/lib/useApi";
import {
  baselineApproveBody,
  baselineCommitLabel,
  githooksStateLabel,
  provenanceKeyLabel,
  provenanceLinesLabel,
  provenanceVerificationLabel,
  securityPost,
  type BaselineResponse,
  type GithooksResponse,
  type ProvenanceResponse,
} from "@/lib/codeSecurityExceptions";
import { projectLabel, type SecurityProject } from "@/lib/codeSecurity";

// BaselinesTab is the Code security page's Baselines tab (lane sec-c3): the
// commit a project's findings are judged against (a finding the same rules
// also report at that commit is pre-existing), and, for the chosen project,
// its opt-in local git hooks and its AI change records. Moved out of
// CodeSecurity.tsx unchanged by the page redesign
// (docs/plans/code-security-page-redesign-plan-2026-11-06.md section 4.1:
// the git hooks and the change records stay under Baselines). Every action
// here is also a CLI verb (`observer security baseline`, `observer security
// provenance consent`).

/** GithooksCard is the opt-in local git hooks of one repository (component security.githooks). */
function GithooksCard({ project }: { project: string }) {
  const state = useApi<GithooksResponse>(project ? "/api/security/githooks" : null, { project }, [project]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<ErrorNote | null>(null);
  const d = state.data;
  const installed = (d?.hooks ?? []).some((h) => h.installed || h.outdated);
  async function act(action: "install" | "uninstall") {
    if (!d) return;
    setBusy(true);
    setErr(null);
    try {
      await securityPost("/api/security/githooks", d.confirm_token, { project, action });
      state.reload();
    } catch (e: unknown) {
      setErr(errorNote(e));
    } finally {
      setBusy(false);
    }
  }
  // Hidden while the component is off and nothing is installed: an
  // inactive component adds nothing to the page.
  if (!d || (!d.active && !installed)) return null;
  return (
    <Card
      title="Local git hooks"
      sub="On your consent for this repository: the pre-commit and pre-push hooks check a commit or push for secrets. Advisory (git commit --no-verify skips it), and a hook of your own keeps running after it."
    >
      <div className="grid gap-2 text-[13px]">
        {d.hooks.map((h) => (
          <p key={h.hook} className="m-0 text-fg-2">
            <span className="font-mono">{h.hook}</span>: {githooksStateLabel(h)}
          </p>
        ))}
        {d.refusal && <p className="m-0 text-fg-3">Not installable here: {d.refusal}</p>}
        <div className="flex gap-2">
          {d.active && !d.refusal && (
            <Button size="sm" variant="primary" disabled={busy} onClick={() => void act("install")}>
              Install in this repository
            </Button>
          )}
          {installed && (
            <Button size="sm" variant="danger-outline" disabled={busy} onClick={() => void act("uninstall")}>
              Remove
            </Button>
          )}
        </div>
        <ApiErrorNotice note={err} plainClassName="m-0 text-danger" />
      </div>
    </Card>
  );
}

/**
 * ProvenanceCard is the AI change records of one repository (component
 * security.provenance): the signing key, the records, and the person's
 * per-repository consent for the two writers (git notes, the commit
 * trailer), on the same seam as `observer security provenance consent`.
 */
function ProvenanceCard({ project }: { project: string }) {
  const state = useApi<ProvenanceResponse>(project ? "/api/security/provenance" : null, { project }, [project]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // The trailer writes a block into the repository's prepare-commit-msg
  // hook: it is shown first, and installed only on a second click (PR11).
  const [showBlock, setShowBlock] = useState(false);
  const d = state.data;
  async function send(body: Record<string, unknown>) {
    if (!d) return;
    setBusy(true);
    setErr(null);
    try {
      await securityPost("/api/security/provenance", d.confirm_token, body);
      setShowBlock(false);
      state.reload();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  const consent = d?.consent ?? { notes: false, trailer: false };
  // Hidden while the component is off and nothing was ever recorded or consented.
  if (!d || (!d.status.selected && d.status.records.Records === 0 && !consent.notes && !consent.trailer)) return null;
  return (
    <Card
      title="AI change records"
      sub="A signed record per commit the attribution ties to agent activity: node-reported attribution, never proof of authorship, and never prompt text. Written into this repository only with your consent."
    >
      <div className="grid gap-2 text-[13px]">
        <p className="m-0 text-fg-2">{provenanceKeyLabel(d.status.key)}</p>
        <p className="m-0 text-fg-2">
          {d.records.length} record(s) for this repository; {d.status.records.NotesWritten} written as git notes overall.
        </p>
        {d.records.slice(0, 5).map((r) => (
          <p key={r.commit} className="m-0 text-fg-3">
            <span className="font-mono">{r.commit.slice(0, 12)}</span> {provenanceLinesLabel(r)}
            {r.note_written ? ", note written" : ""}
            {", "}
            <span className={r.verification === "verified" ? "" : "text-danger"}>{provenanceVerificationLabel(r)}</span>
          </p>
        ))}
        <div className="flex flex-wrap gap-2">
          {d.status.selected && (
            <Button size="sm" variant={consent.notes ? "danger-outline" : "primary"} disabled={busy}
              onClick={() => void send({ action: "consent", project, notes: !consent.notes, trailer: consent.trailer })}>
              {consent.notes ? "Stop git notes" : "Write git notes (refs/notes/observer)"}
            </Button>
          )}
          {d.status.selected && (
            <Button size="sm" variant={consent.trailer ? "danger-outline" : "primary"} disabled={busy}
              onClick={() =>
                consent.trailer
                  ? void send({ action: "consent", project, notes: consent.notes, trailer: false })
                  : setShowBlock(true)
              }>
              {consent.trailer ? "Stop the commit trailer" : "Add an Assisted-by trailer to the agent's commits"}
            </Button>
          )}
          {!d.status.selected && (consent.notes || consent.trailer) && (
            <Button size="sm" variant="danger-outline" disabled={busy}
              onClick={() => void send({ action: "consent", project, notes: false, trailer: false })}>
              Withdraw consent
            </Button>
          )}
          {d.status.selected && d.status.key && (
            <Button size="sm" variant="secondary" disabled={busy} onClick={() => void send({ action: "rotate_key" })}>
              Rotate key
            </Button>
          )}
        </div>
        {showBlock && !consent.trailer && d.trailer_preview && (
          <div className="grid gap-2">
            {d.trailer_preview.refusal ? (
              <p className="m-0 text-danger">{d.trailer_preview.refusal}</p>
            ) : (
              <>
                <p className="m-0 text-fg-2">
                  This block goes into <span className="font-mono">{d.trailer_preview.hook_path}</span>. It never fails a
                  commit, and withdrawing consent removes it byte for byte.
                </p>
                <pre className="m-0 max-h-[160px] overflow-auto whitespace-pre-wrap break-words rounded-2 bg-bg-2 px-3 py-2 font-mono text-[11px] leading-snug text-fg-1">
                  {d.trailer_preview.block}
                </pre>
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="primary" disabled={busy}
                    onClick={() =>
                      void send({
                        action: "consent",
                        project,
                        notes: consent.notes,
                        trailer: true,
                        trailer_block_digest: d.trailer_preview?.digest,
                      })
                    }>
                    Install this block
                  </Button>
                  <Button size="sm" variant="secondary" disabled={busy} onClick={() => setShowBlock(false)}>
                    Cancel
                  </Button>
                </div>
              </>
            )}
          </div>
        )}
        {err && <p className="m-0 text-danger">{err}</p>}
      </div>
    </Card>
  );
}

export function BaselinesTab({ projects }: { projects: SecurityProject[] }) {
  const [project, setProject] = useState("");
  const chosen = project || projects[0]?.project_root_hash || "";
  const view = useApi<BaselineResponse>(chosen ? "/api/security/baseline" : null, { project: chosen }, [chosen]);
  const [pick, setPick] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const b = view.data?.baseline;
  const proposed = b?.proposed ?? [];
  const selected = pick && proposed.some((c) => c.sha === pick) ? pick : (proposed[0]?.sha ?? "");
  async function send(body: unknown) {
    if (!view.data) return;
    setBusy(true);
    setErr(null);
    try {
      await securityPost("/api/security/baseline", view.data.confirm_token, body);
      view.reload();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  if (projects.length === 0) {
    return (
      <Card title="Baselines">
        <EmptyState title="No projects yet" body="A project appears once an AI tool session runs in it." variant="inline" />
      </Card>
    );
  }
  return (
    <Card
      title="Baselines"
      sub="Approve a commit as the project's starting point: a finding the same rules also report at that commit is pre-existing, a backlog rather than a wall. Secrets and malicious packages are never pre-existing."
    >
      <div className="grid max-w-xl gap-3">
        <Select
          label="Project"
          value={chosen}
          onChange={(e) => {
            setProject(e.target.value);
            setPick("");
          }}
          options={projects.map((p) => ({ value: p.project_root_hash, label: projectLabel(p) }))}
        />
        <ChartState
          kind="table"
          loading={view.loading}
          stale={view.isStale}
          onRetry={view.reload}
          error={view.error}
          denied={view.denied}
          empty={false}
          emptyHint=""
        >
          <div className="grid gap-3 text-[13px]">
            <BaselineStatus current={b?.current ?? null} />
            {b?.proposal_error && <p className="m-0 text-fg-3">No commits to offer: {b.proposal_error}.</p>}
            {proposed.length > 0 && (
              <>
                <Select
                  label="Commit"
                  value={selected}
                  onChange={(e) => setPick(e.target.value)}
                  options={proposed.map((c) => ({ value: c.sha, label: baselineCommitLabel(c) }))}
                />
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="primary"
                    disabled={busy}
                    onClick={() => {
                      const body = baselineApproveBody(chosen, selected, proposed);
                      if (body) void send(body);
                    }}
                  >
                    Approve as baseline
                  </Button>
                  {b?.current && (
                    <Button size="sm" variant="danger-outline" disabled={busy} onClick={() => void send({ project: chosen, action: "reset" })}>
                      Reset baseline
                    </Button>
                  )}
                </div>
              </>
            )}
            {err && <p className="m-0 text-danger">{err}</p>}
          </div>
        </ChartState>
      </div>
      <div className="mt-4">
        <GithooksCard project={chosen} />
      </div>
      <div className="mt-4">
        <ProvenanceCard project={chosen} />
      </div>
    </Card>
  );
}
