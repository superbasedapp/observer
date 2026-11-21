import { useState, type ReactNode } from "react";
import { projectPickerOptions } from "@/lib/securityComponents";
import { Button, Card, Modal, Pill, Select } from "@/components/primitives";
import { CopyOnClick } from "@/components/CopyOnClick";
import { fetchJSON } from "@/lib/api";
import { securityPost } from "@/lib/codeSecurityExceptions";
import type { ConfigKeysDryRun, ConfigKeysResponse } from "@/lib/configSchema";
import { putConfigKeys, type ConfigKeysBase } from "@/lib/configKeysPut";
import { markRestartPending } from "@/lib/restartPending";
import {
  exploitCitations,
  exploitKindLine,
  imageDriverLine,
  imageDriverOptions,
  imageDriverPatch,
  megabytes,
  osDBLine,
  osReleaseNotes,
  osSizesLine,
  osvInstallFor,
  scannerDBAcceptLabel,
  scannerDBLine,
  scannerDBStage,
  trivyDBAcceptLabel,
  trivyDBLine,
  trivyEngineLine,
  type ScannerDBStage,
  type ScannerDBStatus,
  type ScannerExploitStatus,
  type ScannerImageStatus,
  type ScannerOSDBStatus,
  type ScannerTrivyImageStatus,
  type OSVScannerInstall,
} from "@/lib/scannerDB";
import { LookupPostureRow } from "@/components/security/PackageLookupCard";
import { ArtifactFoldersRow } from "@/components/security/ArtifactFoldersRow";
import { ProjectPicker, ReachSourceRow, type ReachSourceProject } from "@/components/security/ReachSourceRow";

// ScannersCard - the Code security page's dependency Scanners card
// (components security.scan.scalibr and security.scan.osv, Phase D2;
// GET /api/security/scanners, 404 unless a dependency driver is selected).
// Rows: the language OSV databases' one-time accept (PT-19 (2)), the OS
// release databases' one accept (OS-2, ruling Q1 (b)), the image OS package
// driver with its picker and the Trivy driver's binary and database accept
// (lane OS-2 T, plan section 6.7), the exploit data with FIRST's EPSS
// citation (plan section 14.7 item 5), the build artifact folders of a
// project (M3L-2 item 4: off until the developer switches each on), then the
// drivers and the language databases. The osv-scanner row carries "How to
// install" (the vendor's ways, the offer `observer security scan
// install-osv-scanner` prints; Observer installs nothing itself, D-766).
//
// Every accept is a human click on this owner-local surface: a dialog that
// shows the accept's own text (the same words the CLI shows) before the
// button, then a POST carrying the confirm token its route's GET minted.
// Nothing is ever accepted on the developer's behalf, and an agent can give
// none of them (guard rule R-165 denies the routes and the records). A
// managed node has nothing to accept. The driver picker writes
// [security.scan.image] driver through PUT /api/config/keys, the path every
// other [security] key takes, with the confirm token (the key is sensitive
// tier; R-165 denies an agent the [security] section there).
//
// Working surface: calm register, zero delight elements.

/** One dependency driver row. */
export type ScannerDriver = {
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

/** One language database row. */
export type ScannerDatabase = {
  ecosystem: string;
  installed: boolean;
  last_modified?: string;
  size?: number;
  fetched_at?: string;
  last_error?: string;
};

/** GET /api/security/scanners. */
export type SecurityScanners = {
  drivers: ScannerDriver[];
  databases: ScannerDatabase[];
  attribution: string;
  /** The one-time database download accept (PT-19); absent on an older daemon. */
  db?: ScannerDBStatus;
  /** The image driver's state (OS-2 T); the same as db.image. */
  image?: ScannerImageStatus;
  /** The osv-scanner row's "How to install"; absent in a build without it. */
  osv_install?: OSVScannerInstall;
};

/**
 * ArtifactFoldersPicked puts the searchable project picker (active projects
 * first, then idle) in front of the build artifact folders row, which lists
 * one project at a time.
 */
function ArtifactFoldersPicked({ projects }: { projects: ReachSourceProject[] }) {
  const [project, setProject] = useState(projectPickerOptions(projects)[0]?.id ?? "");
  const chosen = projects.find((p) => p.project_root_hash === project) ?? projects[0];
  if (!chosen) return null;
  return (
    <div className="space-y-2">
      {projects.length > 1 && (
        <ProjectPicker projects={projects} value={chosen.project_root_hash} onChange={setProject} testId="scanner-artifacts-project" />
      )}
      <ArtifactFoldersRow key={chosen.project_root_hash} projects={[chosen]} />
    </div>
  );
}

const STAGE_PILL: Record<ScannerDBStage, "warn" | "success" | "neutral"> = {
  waiting: "warn",
  accepted: "success",
  managed: "neutral",
};

/** ScannersCard is the dependency scanners card. */
export function ScannersCard({
  data,
  onChanged,
  projects = [],
}: {
  data: SecurityScanners;
  onChanged: () => void;
  /** The projects whose build artifact folders the row can show (M3L-2 item 4); none hides the row. */
  projects?: ReachSourceProject[];
}) {
  const image = data.image ?? data.db?.image;
  // The package lookup posture (lane RM-2): read-only here with a link to
  // the Privacy page, or the first-run choice on a fresh install. The
  // database download's accept shows only where the posture downloads.
  const lookup = data.db?.lookup;
  const showDBAccept = !lookup || lookup.managed || lookup.mode === "local" || lookup.mode === "both";
  return (
    <Card title="Databases and images" sub="The local vulnerability databases, the image driver, build artifact folders and the Go source check">
      <div className="space-y-4">
        {lookup ? <LookupPostureRow st={lookup} onChanged={onChanged} /> : null}
        {data.db && showDBAccept ? <ScannerDBAccept db={data.db} onChanged={onChanged} /> : null}
        {data.db?.os ? <OSDBAccept os={data.db.os} onChanged={onChanged} /> : null}
        {image ? <ImageDriverRow img={image} onChanged={onChanged} /> : null}
        {data.drivers.some((d) => d.component === "security.scan.scalibr" && d.compiled) ? <ArtifactFoldersPicked projects={projects} /> : null}
        {/* The Go source check (3b-src) runs osv-scanner's call analysis. */}
        {data.drivers.some((d) => d.component === "security.scan.osv" && d.compiled) ? <ReachSourceRow projects={projects} /> : null}
        {data.db?.exploit ? <ExploitDataRow exploit={data.db.exploit} /> : null}
        <div className="overflow-x-auto"><table className="w-full text-[13px]" data-testid="scanner-drivers">
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
                <td className="py-1.5 pr-3 font-mono text-fg-2 [overflow-wrap:anywhere]">{d.component}</td>
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
                  {(() => {
                    const offer = osvInstallFor(d.component, data.osv_install);
                    return offer ? <OSVInstallHelp offer={offer} /> : null;
                  })()}
                </td>
              </tr>
            ))}
          </tbody>
        </table></div>
        <div className="overflow-x-auto"><table className="w-full text-[13px]" data-testid="scanner-databases">
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
        </table></div>
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
 * OSVInstallHelp is the osv-scanner row's "How to install": the vendor's own
 * ways, each command copyable, never run by Observer.
 */
function OSVInstallHelp({ offer }: { offer: OSVScannerInstall }) {
  return (
    <details className="mt-1" data-testid="osv-install-help">
      <summary className="cursor-pointer text-accent hover:underline">How to install</summary>
      <div className="mt-1.5 space-y-1.5 text-[12.5px]">
        <p className="m-0 text-fg-2">
          {offer.intro}
          {offer.docs_url ? (
            <>
              {" ("}
              <a href={offer.docs_url} target="_blank" rel="noreferrer noopener" className="text-accent hover:underline">
                installation guide
              </a>
              {")"}
            </>
          ) : null}
          .
        </p>
        <ul className="m-0 list-none space-y-1 p-0">
          {offer.ways.map((w) => (
            <li key={w.label} className="min-w-0">
              <span className="text-fg-2">{`${w.label}: `}</span>
              {w.command ? (
                <CopyOnClick value={w.command} title="Copy the command">
                  <code className="break-all font-mono text-[11.5px] text-fg-1">{w.command}</code>
                </CopyOnClick>
              ) : w.url ? (
                <a href={w.url} target="_blank" rel="noreferrer noopener" className="break-all text-accent hover:underline">
                  {w.url}
                </a>
              ) : null}
              {w.note ? <span className="block break-all text-fg-3">{w.note}</span> : null}
            </li>
          ))}
        </ul>
        <p className="m-0 text-fg-3">{offer.outro}</p>
      </div>
    </details>
  );
}

/**
 * AcceptControl is one accept's button and confirm dialog: the dialog shows
 * the accept's own text before its button, and the accept re-reads the
 * route for the confirm token its GET mints, then POSTs `body` with it. The
 * routes are owner-local, so a remote viewer sees the state but the accept
 * fails there.
 */
function AcceptControl({
  testid,
  open: openLabel,
  title,
  subtitle,
  text,
  extra,
  note,
  acceptLabel,
  route,
  body,
  onChanged,
}: {
  testid: string;
  open: string;
  title: string;
  subtitle: string;
  text: string;
  extra?: ReactNode;
  note: string;
  acceptLabel: string;
  route: string;
  body: unknown;
  onChanged: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  async function accept() {
    setBusy(true);
    setErr(null);
    try {
      const res = await fetch(route);
      if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
      const got = (await res.json()) as { confirm_token?: string };
      await securityPost(route, got.confirm_token ?? "", body);
      setOpen(false);
      onChanged();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Button variant="primary" onClick={() => setOpen(true)} disabled={busy} data-testid={testid}>
        {openLabel}
      </Button>
      {err && !open && <p className="m-0 text-danger">{err}</p>}
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        dismissible={!busy}
        title={title}
        subtitle={subtitle}
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setOpen(false)} disabled={busy}>
              Cancel
            </Button>
            <Button variant="primary" onClick={accept} disabled={busy} loading={busy}>
              {acceptLabel}
            </Button>
          </div>
        }
      >
        <div className="space-y-2 text-[12.5px]">
          <p className="m-0 whitespace-pre-wrap text-fg-2">{text}</p>
          {extra}
          <p className="m-0 text-fg-3">{note}</p>
          {err && <p className="m-0 text-danger">{err}</p>}
        </div>
      </Modal>
    </>
  );
}

/** StageLine is an accept's pill and its one line. */
function StageLine({ stage, labels, line }: { stage: ScannerDBStage | null; labels: Record<ScannerDBStage, string>; line: string }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {stage ? <Pill variant={STAGE_PILL[stage]}>{labels[stage]}</Pill> : null}
      <span className="text-fg-3">{line}</span>
    </div>
  );
}

/**
 * ScannerDBAccept is the one-time accept of the language OSV databases
 * (operator ruling PT-19 (2)): before it nothing is downloaded and
 * dependencies read "not scanned"; after it the refreshes are automatic.
 */
function ScannerDBAccept({ db, onChanged }: { db: ScannerDBStatus; onChanged: () => void }) {
  const stage = scannerDBStage(db);
  return (
    <div className="space-y-2 text-[12.5px]" data-testid="scanner-db-accept">
      <StageLine
        stage={stage}
        labels={{ waiting: "Databases not downloaded", accepted: "Databases accepted", managed: "Org mirror" }}
        line={scannerDBLine(db)}
      />
      {stage === "waiting" && (
        <AcceptControl
          testid="scanner-db-accept-open"
          open="Download the OSV databases..."
          title="Download the OSV databases?"
          subtitle={`About ${db.approx_mb} MB from ${db.source}`}
          text={db.text}
          note="Recorded once, on this machine, with the time. The same accept is `observer security scan db accept`."
          acceptLabel={scannerDBAcceptLabel(db)}
          route="/api/security/scanners/db"
          body={{ accept: true }}
          onChanged={onChanged}
        />
      )}
    </div>
  );
}

/**
 * OSDBAccept is the OS release databases' one accept (ruling Q1 (b)): one
 * accept covers every release the scanned images use, each fetched on
 * demand from superbased's signed mirror only; each distribution's largest
 * release is stated before the click. Then the installed releases with
 * their epoch, source, size and labels.
 */
function OSDBAccept({ os, onChanged }: { os: ScannerOSDBStatus; onChanged: () => void }) {
  const stage = scannerDBStage(os);
  return (
    <div className="space-y-2 border-t border-line-1 pt-3 text-[12.5px]" data-testid="scanner-os-db">
      <div className="text-fg-2">Image OS release databases</div>
      <StageLine
        stage={stage}
        labels={{ waiting: "Not downloaded", accepted: "Accepted", managed: "Org mirror" }}
        line={osDBLine(os)}
      />
      {os.blocked && stage === "accepted" ? <p className="m-0 text-fg-3">{`Download gate: ${os.blocked}`}</p> : null}
      {stage === "waiting" && (
        <AcceptControl
          testid="scanner-os-db-accept-open"
          open="Download the OS release databases..."
          title="Download the OS release databases?"
          subtitle={`The release each scanned image uses, from ${os.source} only`}
          text={os.text}
          extra={osSizesLine(os) ? <p className="m-0 text-fg-3">{`Largest release per distribution: ${osSizesLine(os)}.`}</p> : null}
          note="Recorded once, on this machine, with the time. The same accept is `observer security scan db accept --os`."
          acceptLabel="Accept the OS release databases"
          route="/api/security/scanners/db"
          body={{ os: true }}
          onChanged={onChanged}
        />
      )}
      {(os.installed ?? []).length > 0 && (
        <div className="overflow-x-auto"><table className="w-full text-[13px]" data-testid="scanner-os-releases">
          <thead className="text-left text-fg-3">
            <tr>
              <th className="py-1.5 pr-3 font-normal">Release</th>
              <th className="py-1.5 pr-3 font-normal">Epoch</th>
              <th className="py-1.5 pr-3 font-normal">Source</th>
              <th className="py-1.5 pr-3 font-normal">Size</th>
              <th className="py-1.5 font-normal">Labels</th>
            </tr>
          </thead>
          <tbody>
            {(os.installed ?? []).map((r) => (
              <tr key={r.artifact} className="border-t border-line-1">
                <td className="py-1.5 pr-3 text-fg-2">{`${r.distro} ${r.version}`}</td>
                <td className="py-1.5 pr-3 font-mono text-fg-3">{r.epoch}</td>
                <td className="py-1.5 pr-3 text-fg-3">{r.source ?? ""}</td>
                <td className="py-1.5 pr-3 text-fg-3">{megabytes(r.bytes)}</td>
                <td className="py-1.5 text-fg-3">
                  {osReleaseNotes(r).map((n) => (
                    <span key={n} className="mr-1.5">
                      <Pill variant="neutral">{n}</Pill>
                    </span>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table></div>
      )}
    </div>
  );
}

/**
 * ImageDriverRow is the "Image OS packages" row: the driver in force, the
 * picker over the drivers this build compiles (when there is a choice), and
 * the Trivy driver's binary and database. The picker writes the key with a
 * dry run first, then the write under the same etag, both with the confirm
 * token GET /api/config minted.
 */
function ImageDriverRow({ img, onChanged }: { img: ScannerImageStatus; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  async function choose(next: string) {
    const patch = imageDriverPatch(img, next);
    if (!patch) return;
    setBusy(true);
    setErr(null);
    try {
      const base = await fetchJSON<ConfigKeysBase>("/api/config");
      await putConfigKeys<ConfigKeysDryRun>(base, [patch], true);
      const out = await putConfigKeys<ConfigKeysResponse>(base, [patch], false);
      if (out.restart_required_keys.length > 0) markRestartPending("guard", out.restart_required_keys);
      onChanged();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  const options = imageDriverOptions(img);
  return (
    <div className="space-y-2 border-t border-line-1 pt-3 text-[12.5px]" data-testid="scanner-image-driver">
      <div className="text-fg-2">Image OS packages</div>
      <p className="m-0 text-fg-3">{imageDriverLine(img)}</p>
      {options.length > 1 && (
        <Select
          label="Image driver"
          help="Which engine scans a container image's OS packages ([security.scan.image] driver). After a switch, the other driver's open findings stay listed until that driver scans the image again."
          value={img.driver}
          disabled={busy}
          onChange={(e) => void choose(e.target.value)}
          options={options}
          data-testid="scanner-image-driver-picker"
        />
      )}
      {err && <p className="m-0 text-danger">{err}</p>}
      {img.trivy ? <TrivyRow trivy={img.trivy} onChanged={onChanged} /> : null}
    </div>
  );
}

/**
 * TrivyRow is the Trivy image driver's binary line and its database's
 * separate accept (trivy-db-consent.json): choosing Trivy does not imply
 * the accept, and until it is given Trivy image scans read not scanned.
 */
function TrivyRow({ trivy, onChanged }: { trivy: ScannerTrivyImageStatus; onChanged: () => void }) {
  const db = trivy.db;
  const stage = scannerDBStage(db);
  return (
    <div className="space-y-2" data-testid="scanner-trivy-db">
      <p className="m-0 text-fg-3">{trivyEngineLine(trivy)}</p>
      <StageLine
        stage={stage}
        labels={{ waiting: "Trivy database not downloaded", accepted: "Trivy database accepted", managed: "Org mirror" }}
        line={trivyDBLine(db)}
      />
      {trivy.selected && stage === "waiting" && (
        <AcceptControl
          testid="scanner-trivy-db-accept-open"
          open="Download Trivy's database..."
          title="Download Trivy's vulnerability database?"
          subtitle={`About ${db.approx_download_mb} MB from ${db.source}, about ${db.approx_disk_mb} MB on disk`}
          text={db.text}
          note="Recorded once, on this machine, with the time. The same accept is `observer security scan trivy-db accept`."
          acceptLabel={trivyDBAcceptLabel(db)}
          route="/api/security/scanners/trivydb"
          body={{ accept: true }}
          onChanged={onChanged}
        />
      )}
    </div>
  );
}

/**
 * ExploitDataRow is the exploit data's state (CISA KEV and FIRST EPSS):
 * each kind installed or why it is unavailable (never "not exploited"),
 * then the citation lines the daemon set: FIRST's EPSS citation only while
 * the EPSS data is available, the KEV source line only while the KEV data
 * is. No CISA logo or other branding.
 */
function ExploitDataRow({ exploit }: { exploit: ScannerExploitStatus }) {
  return (
    <div className="space-y-1 border-t border-line-1 pt-3 text-[12.5px]" data-testid="scanner-exploit-data">
      <div className="text-fg-2">Exploit data</div>
      {(exploit.kinds ?? []).map((k) => (
        <div key={k.kind} className="flex flex-wrap items-center gap-2">
          <Pill variant={k.available ? "success" : "neutral"}>{k.available ? "installed" : "unavailable"}</Pill>
          <span className="text-fg-3">{exploitKindLine(k)}</span>
        </div>
      ))}
      {exploitCitations(exploit).map((c) => (
        <p key={c} className="m-0 text-[12px] text-fg-3" data-testid="scanner-exploit-citation">
          {c}
        </p>
      ))}
    </div>
  );
}
