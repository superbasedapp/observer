import { useEffect, useState } from "react";
import clsx from "clsx";
import {
  Button,
  Card,
  ChartShell,
  CopyOnClick,
  Pill,
  StatCard,
  Table,
} from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { TitleWithHelp } from "@/components/HelpInd";
import { useApi } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";
import { fmtInt } from "@/lib/format";
import type { BackfillJob, BackfillRunResponse } from "@/lib/types";

// StorageSection — Settings → Storage (usability arc P6.8): per-table
// size breakdown, vacuum, one-click backup, restore instructions.
// The report endpoint walks every DB page (dbstat), so it loads on
// section open / explicit refresh only. Vacuum and backup run as
// `observer db …` subprocesses through the shared job registry — the
// same code path as the CLI.

type StorageTable = { name: string; bytes: number; rows: number };
type StorageResponse = {
  db_path: string;
  report: {
    page_size: number;
    page_count: number;
    freelist_pages: number;
    total_bytes: number;
    reclaimable_bytes: number;
    tables: StorageTable[];
  };
  backup_dir?: string;
  backups?: { name: string; bytes: number; modified: string }[];
};

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

export function StorageSection() {
  const storage = useApi<StorageResponse>("/api/storage");
  const rep = storage.data?.report;
  const restoreCommand = `cp ${storage.data?.backup_dir ?? "<backup dir>"}/<file> ${storage.data?.db_path ?? "<db path>"}`;

  return (
    <div className="space-y-4">
      <ChartShell
        title={<TitleWithHelp text="Storage" helpId="glossary.settings_storage" />}
        sub="Where the database's bytes live - per table, indexes and search shadow tables folded into their owners"
        right={
          <Button variant="secondary" size="sm" onClick={() => storage.reload()}>
            refresh
          </Button>
        }
      >
        <ChartState
          loading={storage.loading && !storage.data}
          error={storage.error}
          empty={!rep}
          emptyHint="No report."
          height={200}
        >
          {rep && (
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-3">
                <StatCard label="Database size" value={fmtBytes(rep.total_bytes)} sub={storage.data?.db_path ?? ""} />
                <StatCard
                  label="Reclaimable by vacuum"
                  value={fmtBytes(rep.reclaimable_bytes)}
                  sub={`${fmtInt(rep.freelist_pages)} free pages - live-page fragmentation can add more`}
                />
                <StatCard label="Tables" value={fmtInt(rep.tables.length)} sub="indexes + FTS internals folded in" />
              </div>
              <Table
                minWidth={420}
                head={
                  <tr className="border-b border-line-2 text-left">
                    <th className="py-1 pr-2 font-medium">Table</th>
                    <th className="py-1 pr-2 text-right font-medium">Size</th>
                    <th className="py-1 text-right font-medium">Rows</th>
                  </tr>
                }
              >
                {rep.tables.map((t) => (
                  <tr key={t.name} className="border-b border-line-1 last:border-0">
                    <td className="py-1 pr-2 font-mono text-fg-2">{t.name}</td>
                    <td className="py-1 pr-2 text-right text-fg-2">{fmtBytes(t.bytes)}</td>
                    <td className="py-1 text-right text-fg-3">{t.rows >= 0 ? fmtInt(t.rows) : "-"}</td>
                  </tr>
                ))}
              </Table>
            </div>
          )}
        </ChartState>
      </ChartShell>

      <MaintenanceCard
        title="Back up the database"
        description="Writes a consistent snapshot next to the live DB (VACUUM INTO - online-safe; capture keeps running). Months of history are worth a copy before upgrades or machine moves."
        buttonLabel="Back up now"
        runningLabel="Backing up…"
        path="/api/storage/backup"
        onDone={() => storage.reload()}
      />

      <MaintenanceCard
        title="Vacuum"
        description="Rebuilds the database file to return free pages to the OS. Needs the write lock and temporarily doubles disk usage - pick a quiet moment; if the daemon is busy writing, the job reports the conflict honestly."
        buttonLabel="Vacuum now"
        runningLabel="Vacuuming…"
        path="/api/storage/vacuum"
        onDone={() => storage.reload()}
      />

      <ChartShell title="Backups & restore" sub={storage.data?.backup_dir ?? ""}>
        <div className="space-y-3 text-[11.5px]">
          {(storage.data?.backups?.length ?? 0) > 0 ? (
            <Table>
              {storage.data?.backups?.map((b) => (
                <tr key={b.name} className="border-b border-line-1 last:border-0">
                  <td className="py-1 pr-2 font-mono text-fg-2">{b.name}</td>
                  <td className="py-1 pr-2 text-right text-fg-3">{fmtBytes(b.bytes)}</td>
                  <td className="py-1 text-right text-fg-4">{b.modified}</td>
                </tr>
              ))}
            </Table>
          ) : (
            <p className="m-0 text-fg-4">No backups yet.</p>
          )}
          <Card title="To restore" bodyClassName="text-fg-3">
            <ol className="list-decimal space-y-2 pl-4">
              <li>stop the daemon (ctrl-c the observer start process, or kill its PID)</li>
              <li>
                replace the live DB with the snapshot, and delete the -wal /
                -shm files next to it if present:
                <div className="mt-1">
                  <CopyOnClick value={restoreCommand}>
                    <code className="block rounded-2 border border-line-1 bg-bg-3 px-2 py-1 font-mono text-[11px] text-fg-2">
                      {restoreCommand}
                    </code>
                  </CopyOnClick>
                </div>
              </li>
              <li>
                start the daemon again:{" "}
                <code className="font-mono text-fg-2">observer start</code>
              </li>
            </ol>
          </Card>
        </div>
      </ChartShell>
    </div>
  );
}

// MaintenanceCard — one POST-then-poll job button (the PruneNowCard
// pattern, reused for the two storage operations).
function MaintenanceCard({
  title,
  description,
  buttonLabel,
  runningLabel,
  path,
  onDone,
}: {
  title: string;
  description: string;
  buttonLabel: string;
  runningLabel: string;
  path: string;
  onDone?: () => void;
}) {
  const [job, setJob] = useState<Pick<BackfillJob, "id" | "status" | "output" | "error"> | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!job || job.status !== "running") return;
    const t = window.setInterval(() => {
      fetchJSON<BackfillJob>(`/api/backfill/jobs/${job.id}`)
        .then((j) => {
          setJob({ id: j.id, status: j.status, output: j.output, error: j.error });
          if (j.status !== "running") onDone?.();
        })
        .catch(() => {
          // transient poll failure — keep trying until a terminal status.
        });
    }, 2000);
    return () => window.clearInterval(t);
  }, [job?.id, job?.status]);

  async function run() {
    setBusy(true);
    setErr(null);
    try {
      const res = await fetchJSON<BackfillRunResponse>(path, undefined, { method: "POST" });
      setJob({ id: res.job_id, status: "running", output: "", error: undefined });
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const outputTail = job?.output ? job.output.split("\n").slice(-10).join("\n").trim() : "";
  return (
    <Card className="text-[11.5px]">
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 text-[12px] font-semibold text-fg-1">
            {title}
            {job?.status === "running" && <Pill variant="warn">running</Pill>}
          </div>
          <p className="m-0 mt-0.5 text-fg-3">{description}</p>
        </div>
        <Button
          variant="primary"
          onClick={run}
          disabled={busy || job?.status === "running"}
          loading={busy}
          className="shrink-0"
        >
          {job?.status === "running" ? runningLabel : buttonLabel}
        </Button>
      </div>
      {err && <p className="m-0 mt-2 text-danger">{err}</p>}
      {job && job.status !== "running" && (
        <p className={clsx("m-0 mt-2", job.status === "done" ? "text-success" : "text-danger")}>
          {job.status === "done" ? "Done." : `Failed${job.error ? `: ${job.error}` : "."}`}
        </p>
      )}
      {outputTail && (
        <div className="mt-2">
          <div className="mb-1 flex items-center justify-between gap-2">
            <span className="text-[10px] uppercase tracking-[0.06em] text-fg-4">Output</span>
            <CopyOnClick value={outputTail} className="text-[10px] text-fg-3">
              copy
            </CopyOnClick>
          </div>
          <pre className="m-0 max-h-40 overflow-auto whitespace-pre-wrap rounded-2 border border-line-1 bg-bg-3 px-3 py-2 font-mono text-[11px] text-fg-3">
            {outputTail}
          </pre>
        </div>
      )}
    </Card>
  );
}
