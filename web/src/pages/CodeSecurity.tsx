import { useState } from "react";
import {
  Button,
  Card,
  EmptyState,
  Modal,
  PageHeader,
  Pill,
  Select,
  TabPanel,
  TabStrip,
  useTabVisited,
  type TabDef,
} from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { CustomScannersCard } from "@/components/security/CustomScannersCard";
import { BaselineStatus } from "@/components/security/BaselineStatus";
import { OpengrepScannerCard } from "@/components/security/OpengrepScannerCard";
import { SARIFImportCard } from "@/components/security/SARIFImportCard";
import { ExplainButton } from "@/components/security/ExplainButton";
import { useApi } from "@/lib/useApi";
import { navIcon } from "@/lib/nav";
import { useUrlTab } from "@/lib/useUrlTab";
import { usePageTabs } from "@/lib/governance";
import { CODE_SECURITY_TABS, defaultTab, type CodeSecurityTab } from "@/lib/nodePageTabs";
import {
  baselineApproveBody,
  baselineCommitLabel,
  exceptionGrantBody,
  exceptionStateLabel,
  githooksStateLabel,
  provenanceKeyLabel,
  provenanceLinesLabel,
  provenanceVerificationLabel,
  historySummary,
  pickerLabel,
  securityPost,
  type BaselineResponse,
  type ExceptionsResponse,
  type GithooksResponse,
  type ProvenanceResponse,
  type HistoryResult,
} from "@/lib/codeSecurityExceptions";
import { toneOf, type Tone } from "../../../shared/lib/tone";
import { PackageChecksCard } from "./codesecurity/PackageChecksCard";
import {
  scannerDBAcceptLabel,
  scannerDBLine,
  scannerDBStage,
  type ScannerDBResponse,
  type ScannerDBStatus,
} from "@/lib/scannerDB";
import { useComponentState } from "@/lib/useComponents";

// Code security (the security pillar's module root, component `security`;
// security pillar plan sections 4.10 and 6.3). Guard keeps its own Security
// page; this one sits beside it and reads only /api/security. Tabs:
// Findings (the commit-gate posture each project's hook reads, and the
// findings the local store holds, each with "Except"), Exceptions (local,
// expiring, one finding each, never rule-wide) and Baselines (the commit a
// project's findings are judged against). Every action here is also a CLI
// verb (`observer security exception`, `observer security baseline`).
// The Findings tab also holds the Package checks card (component
// security.deps) and, from Phase D3, the custom scanners card (component
// security.scan.custom; it answers 404 and shows nothing while inactive).
// Phase D2 adds the Scanners card there (the dependency drivers, their
// platform label, the local OSV databases and the OSV attribution, from
// /api/security/scanners), shown under the same rule: the route answers 404
// unless the opt-in rule selects security.scan.scalibr or security.scan.osv.
//
// Working surface: calm register, zero delight elements.

type SecurityCount = { category: string; severity: string; n: number };

type SecurityProject = {
  project_root_hash: string;
  state: string;
  reason: string;
  blocking: number;
  counts: SecurityCount[];
};

type SecurityStatus = { module: string; projects: SecurityProject[] };

type ScannerDriver = {
  component: string;
  driver: string;
  kind: string;
  compiled: boolean;
  platform: string;
  beta: boolean;
  note: string;
  /** What the driver's newest recorded run says about itself ("not isolated", "untested engine version"). */
  labels?: string[];
};

type ScannerDatabase = {
  ecosystem: string;
  installed: boolean;
  last_modified?: string;
  size?: number;
  fetched_at?: string;
  last_error?: string;
};

type SecurityScanners = {
  drivers: ScannerDriver[];
  databases: ScannerDatabase[];
  attribution: string;
  /** The one-time database download accept (PT-19); absent on an older daemon. */
  db?: ScannerDBStatus;
};

type SecurityFinding = {
  id: string;
  project_root_hash: string;
  rule_id: string;
  driver: string;
  category: string;
  severity: string;
  confidence: string;
  baseline: string;
  status: string;
  rel_path: string;
  start_line: number;
  message: string;
  last_seen: string;
};

// One tone per posture state (the five states of section 4.8).
const STATE_TONE: Readonly<Record<string, Tone>> = {
  clean: "success",
  dirty: "warn",
  blocking: "danger",
  unknown: "warn",
  absent: "neutral",
};

// One tone per finding severity.
const SEVERITY_TONE: Readonly<Record<string, Tone>> = {
  critical: "danger",
  high: "danger",
  medium: "warn",
  low: "info",
  info: "neutral",
};

// The status filter of the Findings tab: a closed picker.
const STATUS_FILTER = [
  { value: "open", label: "Open" },
  { value: "suppressed", label: "Excepted: test fixture" },
  { value: "false_positive", label: "Excepted: false positive" },
  { value: "accepted_risk", label: "Excepted: risk accepted" },
  { value: "not_reproduced", label: "Not reproduced" },
  { value: "", label: "Every status" },
];

function shortHash(h: string): string {
  return h.slice(0, 12);
}

/** ExceptForm is the inline "Except" form under one finding: pickers only. */
function ExceptForm({
  finding,
  pickers,
  onDone,
  onCancel,
}: {
  finding: SecurityFinding;
  pickers: ExceptionsResponse;
  onDone: () => void;
  onCancel: () => void;
}) {
  const [reason, setReason] = useState(pickers.reasons[0]?.id ?? "");
  const [expiry, setExpiry] = useState(pickers.expiries[0]?.id ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  async function save() {
    const body = exceptionGrantBody(finding.id, reason, expiry, pickers);
    if (!body) return;
    setBusy(true);
    setErr(null);
    try {
      await securityPost("/api/security/exceptions", pickers.confirm_token, body);
      onDone();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="mt-2 grid gap-2 rounded-2 border border-line-2 bg-bg-2 p-3" data-testid={`code-security-except-${finding.id}`}>
      <p className="m-0 text-small text-fg-3">
        Excepts this one finding in this project. The rule keeps firing everywhere else, and the finding comes back
        when the exception ends.
      </p>
      <Select
        label="Reason"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        options={pickers.reasons.map((r) => ({ value: r.id, label: r.label }))}
      />
      <Select
        label="Until"
        value={expiry}
        onChange={(e) => setExpiry(e.target.value)}
        options={pickers.expiries.map((x) => ({ value: x.id, label: x.label }))}
      />
      <div className="flex gap-2">
        <Button size="sm" variant="primary" disabled={busy} onClick={() => void save()}>
          Except this finding
        </Button>
        <Button size="sm" variant="ghost" disabled={busy} onClick={onCancel}>
          Cancel
        </Button>
      </div>
      {err && <p className="m-0 text-danger">{err}</p>}
    </div>
  );
}

function FindingsTab({ status }: { status: ReturnType<typeof useApi<SecurityStatus>> }) {
  const [project, setProject] = useState("");
  const [statusFilter, setStatusFilter] = useState("open");
  const [excepting, setExcepting] = useState<string | null>(null);
  const findings = useApi<{ findings: SecurityFinding[] }>(
    "/api/security/findings",
    { status: statusFilter, project: project || undefined, limit: 200 },
    [statusFilter, project],
  );
  const pickers = useApi<ExceptionsResponse>("/api/security/exceptions");
  // Explain shows only while security.feedback is selected (the opt-in rule;
  // ExplainButton checks the selection itself).
  const securitySelected = useComponentState().data?.security_selected;
  // The custom scanners card shows only while its component answers.
  const customProbe = useApi<{ templates: unknown[] }>("/api/security/scanners/custom");
  const customScannersActive = Boolean(customProbe.data?.templates);
  // The dependency Scanners card shows only while a D2 driver is selected
  // (the route answers 404 otherwise).
  const scanners = useApi<SecurityScanners>("/api/security/scanners");
  const scannersActive = Boolean(scanners.data?.drivers);
  const projects = status.data?.projects ?? [];
  const rows = findings.data?.findings ?? [];
  const [historyBusy, setHistoryBusy] = useState(false);
  const [historyNote, setHistoryNote] = useState<string | null>(null);
  async function scanHistory() {
    if (!project || !pickers.data) return;
    setHistoryBusy(true);
    setHistoryNote(null);
    try {
      const out = await securityPost<{ history: HistoryResult; complete: boolean }>(
        "/api/security/scan-history",
        pickers.data.confirm_token,
        { project },
      );
      setHistoryNote(historySummary(out.history, out.complete));
      findings.reload();
      status.reload();
    } catch (e: unknown) {
      setHistoryNote(e instanceof Error ? e.message : String(e));
    } finally {
      setHistoryBusy(false);
    }
  }
  return (
    <div className="space-y-6">
      <PackageChecksCard />
      <Card title="Projects" sub={status.data ? `module ${status.data.module}` : undefined}>
        <ChartState
          kind="table"
          loading={status.loading}
          stale={status.isStale}
          onRetry={status.reload}
          error={status.error}
          denied={status.denied}
          empty={!status.loading && projects.length === 0}
          emptyHint="No projects yet: a project appears once an AI tool session runs in it."
        >
          <table className="w-full text-[13px]">
            <thead className="text-left text-fg-3">
              <tr>
                <th className="py-1.5 pr-3 font-normal">Project</th>
                <th className="py-1.5 pr-3 font-normal">State</th>
                <th className="py-1.5 pr-3 font-normal">Why</th>
                <th className="py-1.5 font-normal">Open findings</th>
              </tr>
            </thead>
            <tbody>
              {projects.map((p) => (
                <tr key={p.project_root_hash} className="border-t border-line-1">
                  <td className="py-1.5 pr-3 font-mono text-fg-2">{shortHash(p.project_root_hash)}</td>
                  <td className="py-1.5 pr-3">
                    <Pill variant={toneOf(STATE_TONE, p.state)}>
                      {p.state === "blocking" ? `blocking (${p.blocking})` : p.state}
                    </Pill>
                  </td>
                  <td className="py-1.5 pr-3 text-fg-3">{p.reason.replaceAll("_", " ")}</td>
                  <td className="py-1.5 text-fg-2">{p.counts.reduce((n, c) => n + c.n, 0)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </ChartState>
      </Card>
      <Card title="Findings">
        <div className="mb-3 grid gap-3 sm:grid-cols-2">
          <Select
            label="Project"
            value={project}
            onChange={(e) => setProject(e.target.value)}
            options={[
              { value: "", label: "Every project" },
              ...projects.map((p) => ({ value: p.project_root_hash, label: shortHash(p.project_root_hash) })),
            ]}
          />
          <Select label="Status" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} options={STATUS_FILTER} />
        </div>
        {project && (
          <div className="mb-3 flex flex-wrap items-center gap-2 text-small text-fg-3">
            <Button size="sm" variant="secondary" disabled={historyBusy || !pickers.data} onClick={() => void scanHistory()}>
              {historyBusy ? "Scanning history..." : "Scan commit history for secrets"}
            </Button>
            <span>The newest 200 commits, one by one, for at most 30 seconds.</span>
            {historyNote && <span className="text-fg-2">{historyNote}</span>}
          </div>
        )}
        <ChartState
          kind="table"
          loading={findings.loading}
          stale={findings.isStale}
          onRetry={findings.reload}
          error={findings.error}
          denied={findings.denied}
          empty={false}
          emptyHint=""
        >
          {rows.length === 0 ? (
            <EmptyState title="No findings" body="Findings appear here once a scanner reports one." variant="inline" />
          ) : (
            <table className="w-full text-[13px]">
              <thead className="text-left text-fg-3">
                <tr>
                  <th className="py-1.5 pr-3 font-normal">Severity</th>
                  <th className="py-1.5 pr-3 font-normal">Category</th>
                  <th className="py-1.5 pr-3 font-normal">Rule</th>
                  <th className="py-1.5 pr-3 font-normal">Where</th>
                  <th className="py-1.5 pr-3 font-normal">What</th>
                  <th className="py-1.5 font-normal">Baseline</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((f) => (
                  <tr key={f.id} className="border-t border-line-1 align-top">
                    <td className="py-1.5 pr-3">
                      <Pill variant={toneOf(SEVERITY_TONE, f.severity)}>{f.severity}</Pill>
                    </td>
                    <td className="py-1.5 pr-3 text-fg-2">{f.category.replaceAll("_", " ")}</td>
                    <td className="py-1.5 pr-3 font-mono text-fg-2">{f.rule_id}</td>
                    <td className="py-1.5 pr-3 font-mono text-fg-3">
                      {f.rel_path}
                      {f.start_line > 0 ? `:${f.start_line}` : ""}
                    </td>
                    <td className="py-1.5 pr-3 text-fg-2">
                      {f.message}
                      {f.status === "open" && pickers.data && excepting !== f.id && (
                        <div className="mt-1">
                          <Button size="sm" variant="ghost" onClick={() => setExcepting(f.id)}>
                            Except...
                          </Button>
                        </div>
                      )}
                      {pickers.data && (
                        <ExplainButton findingId={f.id} token={pickers.data.confirm_token} selected={securitySelected} />
                      )}
                      {excepting === f.id && pickers.data && (
                        <ExceptForm
                          finding={f}
                          pickers={pickers.data}
                          onCancel={() => setExcepting(null)}
                          onDone={() => {
                            setExcepting(null);
                            findings.reload();
                            pickers.reload();
                          }}
                        />
                      )}
                    </td>
                    <td className="py-1.5 text-fg-3">{f.baseline.replaceAll("_", " ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </ChartState>
      </Card>
      {customScannersActive ? <CustomScannersCard /> : null}
      {scannersActive && scanners.data ? <ScannersCard data={scanners.data} onChanged={scanners.reload} /> : null}
      <OpengrepScannerCard />
      <SARIFImportCard
        projects={projects}
        onImported={() => {
          findings.reload();
          status.reload();
        }}
      />
    </div>
  );
}

/** ScannersCard is the dependency scanners (components security.scan.scalibr and security.scan.osv, Phase D2). */
function ScannersCard({ data, onChanged }: { data: SecurityScanners; onChanged: () => void }) {
  return (
    <Card title="Scanners" sub="Dependency scanners: a project's lockfiles matched against the local OSV database">
      <div className="space-y-4">
        {data.db ? <ScannerDBAccept db={data.db} onChanged={onChanged} /> : null}
        <table className="w-full text-[13px]" data-testid="scanner-drivers">
          <thead className="text-left text-fg-3">
            <tr>
              <th className="py-1.5 pr-3 font-normal">Driver</th>
              <th className="py-1.5 pr-3 font-normal">In this build</th>
              <th className="py-1.5 pr-3 font-normal">This platform</th>
              <th className="py-1.5 font-normal">Notes</th>
            </tr>
          </thead>
          <tbody>
            {data.drivers.map((d) => (
              <tr key={d.component} className="border-t border-line-1">
                <td className="py-1.5 pr-3 font-mono text-fg-2">{d.component}</td>
                <td className="py-1.5 pr-3">
                  <Pill variant={d.compiled ? "success" : "neutral"}>{d.compiled ? "yes" : "no"}</Pill>
                </td>
                <td className="py-1.5 pr-3">
                  <Pill variant={d.beta ? "warn" : "success"}>{d.beta ? `beta (${d.platform})` : d.platform}</Pill>
                </td>
                <td className="py-1.5 text-fg-3">
                  {(d.labels ?? []).map((l) => (
                    <span key={l} className="mr-1.5" data-testid="scanner-run-label">
                      <Pill variant="warn">{`last run: ${l}`}</Pill>
                    </span>
                  ))}
                  {d.note}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <table className="w-full text-[13px]" data-testid="scanner-databases">
          <thead className="text-left text-fg-3">
            <tr>
              <th className="py-1.5 pr-3 font-normal">Ecosystem</th>
              <th className="py-1.5 pr-3 font-normal">Local database</th>
              <th className="py-1.5 font-normal">Epoch</th>
            </tr>
          </thead>
          <tbody>
            {(data.databases ?? []).map((db) => (
              <tr key={db.ecosystem} className="border-t border-line-1">
                <td className="py-1.5 pr-3 text-fg-2">{db.ecosystem}</td>
                <td className="py-1.5 pr-3">
                  <Pill variant={db.installed ? "success" : "neutral"}>{db.installed ? "installed" : "none: not scanned"}</Pill>
                </td>
                <td className="py-1.5 text-fg-3">
                  {db.installed ? db.last_modified : ""}
                  {db.last_error ? ` (last refresh failed: ${db.last_error})` : ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {data.attribution ? (
          <p className="text-[12px] text-fg-3" data-testid="osv-attribution">
            {data.attribution}
          </p>
        ) : null}
      </div>
    </Card>
  );
}

/**
 * ScannerDBAccept is the Scanners card's one-time accept of the OSV
 * database download (operator ruling PT-19 (2)): before it nothing is
 * downloaded and dependencies read "not scanned"; the accept is a confirm
 * dialog that shows the size and the source, and the refreshes are
 * automatic after it. The route is owner-local, so a remote viewer sees
 * the state but the accept fails there.
 */
function ScannerDBAccept({ db, onChanged }: { db: ScannerDBStatus; onChanged: () => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const stage = scannerDBStage(db);
  async function accept() {
    setBusy(true);
    setErr(null);
    try {
      const res = await fetch("/api/security/scanners/db");
      if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
      const got = (await res.json()) as ScannerDBResponse;
      await securityPost("/api/security/scanners/db", got.confirm_token ?? "", { accept: true });
      setOpen(false);
      onChanged();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="space-y-2 text-[12.5px]" data-testid="scanner-db-accept">
      <div className="flex flex-wrap items-center gap-2">
        <Pill variant={stage === "waiting" ? "warn" : stage === "accepted" ? "success" : "neutral"}>
          {stage === "waiting" ? "Databases not downloaded" : stage === "accepted" ? "Databases accepted" : "Org mirror"}
        </Pill>
        <span className="text-fg-3">{scannerDBLine(db)}</span>
      </div>
      {stage === "waiting" && (
        <Button variant="primary" onClick={() => setOpen(true)} disabled={busy}>
          Download the OSV databases...
        </Button>
      )}
      {err && !open && <p className="m-0 text-danger">{err}</p>}
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        dismissible={!busy}
        title="Download the OSV databases?"
        subtitle={`About ${db.approx_mb} MB from ${db.source}`}
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setOpen(false)} disabled={busy}>
              Cancel
            </Button>
            <Button variant="primary" onClick={accept} disabled={busy} loading={busy}>
              {scannerDBAcceptLabel(db)}
            </Button>
          </div>
        }
      >
        <div className="space-y-2 text-[12.5px]">
          <p className="m-0 text-fg-2">{db.text}</p>
          <p className="m-0 text-fg-3">Recorded once, on this machine, with the time. The same accept is `observer security scan db accept`.</p>
          {err && <p className="m-0 text-danger">{err}</p>}
        </div>
      </Modal>
    </div>
  );
}

function ExceptionsTab() {
  const [showEnded, setShowEnded] = useState("0");
  const list = useApi<ExceptionsResponse>("/api/security/exceptions", { all: showEnded === "1" ? 1 : undefined }, [showEnded]);
  const [err, setErr] = useState<string | null>(null);
  const rows = list.data?.exceptions ?? [];
  async function revoke(id: number) {
    if (!list.data) return;
    setErr(null);
    try {
      await securityPost("/api/security/exceptions/revoke", list.data.confirm_token, { id });
      list.reload();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }
  return (
    <Card
      title="Exceptions"
      sub="Each one excepts a single finding for a while. It ends at its expiry, when its file changes (for 'until the file changes'), or when you revoke it; the finding is then open again."
    >
      <div className="mb-3 max-w-xs">
        <Select
          label="Show"
          value={showEnded}
          onChange={(e) => setShowEnded(e.target.value)}
          options={[
            { value: "0", label: "Exceptions that still apply" },
            { value: "1", label: "Every exception, ended ones too" },
          ]}
        />
      </div>
      {err && <p className="m-0 mb-2 text-danger">{err}</p>}
      <ChartState
        kind="table"
        loading={list.loading}
        stale={list.isStale}
        onRetry={list.reload}
        error={list.error}
        denied={list.denied}
        empty={!list.loading && rows.length === 0}
        emptyHint="No exceptions. Except a finding from the Findings tab, or with `observer security exception add`."
      >
        <table className="w-full text-[13px]">
          <thead className="text-left text-fg-3">
            <tr>
              <th className="py-1.5 pr-3 font-normal">Rule</th>
              <th className="py-1.5 pr-3 font-normal">Where</th>
              <th className="py-1.5 pr-3 font-normal">Reason</th>
              <th className="py-1.5 pr-3 font-normal">Until</th>
              <th className="py-1.5 pr-3 font-normal">State</th>
              <th className="py-1.5 font-normal" />
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.id} className="border-t border-line-1">
                <td className="py-1.5 pr-3 font-mono text-fg-2">{e.rule_id}</td>
                <td className="py-1.5 pr-3 font-mono text-fg-3">{e.rel_path}</td>
                <td className="py-1.5 pr-3 text-fg-2">{pickerLabel(list.data?.reasons ?? [], e.reason)}</td>
                <td className="py-1.5 pr-3 text-fg-3">
                  {e.expiry === "until_change" ? "file changes, at the latest " : ""}
                  {e.expires_at.slice(0, 10)}
                </td>
                <td className="py-1.5 pr-3 text-fg-3">{exceptionStateLabel(e)}</td>
                <td className="py-1.5">
                  {!e.ended_at && (
                    <Button size="sm" variant="danger-outline" onClick={() => void revoke(e.id)}>
                      Revoke
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </ChartState>
    </Card>
  );
}

/** GithooksCard is the opt-in local git hooks of one repository (component security.githooks). */
function GithooksCard({ project }: { project: string }) {
  const state = useApi<GithooksResponse>(project ? "/api/security/githooks" : null, { project }, [project]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
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
      setErr(e instanceof Error ? e.message : String(e));
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
        {err && <p className="m-0 text-danger">{err}</p>}
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

function BaselinesTab({ projects }: { projects: SecurityProject[] }) {
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
          options={projects.map((p) => ({ value: p.project_root_hash, label: shortHash(p.project_root_hash) }))}
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

export function CodeSecurityPage() {
  const pageTabs = usePageTabs("code-security", CODE_SECURITY_TABS);
  const [tab, setTab] = useUrlTab(pageTabs.ids, defaultTab(pageTabs));
  const status = useApi<SecurityStatus>("/api/security/status");
  const exceptionsVisited = useTabVisited<CodeSecurityTab>("exceptions", tab);
  const baselinesVisited = useTabVisited<CodeSecurityTab>("baselines", tab);
  const findingsVisited = useTabVisited<CodeSecurityTab>("findings", tab);
  const tabs: TabDef<CodeSecurityTab>[] = pageTabs.ids.map((id) => ({ id, label: CODE_SECURITY_TABS.labels[id] }));

  return (
    <div className="space-y-6 p-4 sm:p-6" data-page="code-security">
      <PageHeader
        icon={navIcon("code-security")}
        title="Code security"
        sub="The commit-gate posture each project's hook reads, the findings this machine holds, your exceptions and baselines, and the scanners you selected. Preview."
      />
      <TabStrip tabs={tabs} value={tab} onChange={setTab} idPrefix="code-security" ariaLabel="Code security sections" className="mb-4" />
      <TabPanel id="findings" active={tab} idPrefix="code-security">
        {findingsVisited && <FindingsTab status={status} />}
      </TabPanel>
      <TabPanel id="exceptions" active={tab} idPrefix="code-security">
        {exceptionsVisited && <ExceptionsTab />}
      </TabPanel>
      <TabPanel id="baselines" active={tab} idPrefix="code-security">
        {baselinesVisited && <BaselinesTab projects={status.data?.projects ?? []} />}
      </TabPanel>
    </div>
  );
}
