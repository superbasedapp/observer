import { useState } from "react";
import { Button, Card, EmptyState, Pill, Select } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { fetchJSON, localConfirmHeaders } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { useProjectRootOptions } from "@/lib/usePickerSources";
import {
  CUSTOM_ROUTE,
  hostsLabel,
  isolationWords,
  limitLabel,
  readyToAccept,
  runProjectOptions,
  selfTestWords,
  verdictWords,
  type CustomChoices,
  type CustomList,
  type CustomPrepared,
  type CustomRunReport,
} from "@/lib/customScanners";

// The Code security page's custom scanners section (component
// security.scan.custom; security pillar plan section 8.6, Phase D3). Import
// a built-in template or a manifest file, review it in full with its
// digest, change only what the pickers offer, accept exactly that digest.
// Every route is owner-local and every write carries the confirm token.
//
// Working surface: calm register, zero delight elements.

const TONE = { ok: "success", warn: "warn", danger: "danger" } as const;

async function post<T>(verb: string, body: unknown): Promise<T> {
  return fetchJSON<T>(`${CUSTOM_ROUTE}/${verb}`, undefined, {
    method: "POST",
    headers: await localConfirmHeaders(),
    body: JSON.stringify(body),
  });
}

function errorText(e: unknown): string {
  const m = e instanceof Error ? e.message : String(e);
  const json = m.match(/\{"error":"(.*)"\}/);
  return json ? json[1] : m;
}

export function CustomScannersCard() {
  const list = useApi<CustomList>(CUSTOM_ROUTE);
  const [template, setTemplate] = useState("");
  const [file, setFile] = useState<string | null>(null);
  const [choices, setChoices] = useState<CustomChoices>({});
  const [prepared, setPrepared] = useState<CustomPrepared | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [runDir, setRunDir] = useState("");
  const [reports, setReports] = useState<Record<string, CustomRunReport>>({});
  // The run takes a project this machine knows, never a typed path (the
  // pickers rule, D-571); the server refuses any other directory.
  const projects = useProjectRootOptions();

  const data = list.data;
  const pickers = data?.pickers;
  const source = () => (file !== null ? { file } : { template });

  const preview = async (next: CustomChoices) => {
    setBusy(true);
    setMessage("");
    try {
      const p = await post<CustomPrepared>("preview", { ...source(), choices: next });
      setChoices(next);
      setPrepared(p);
    } catch (e) {
      setPrepared(null);
      setMessage(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const accept = async () => {
    if (!prepared) return;
    setBusy(true);
    try {
      await post("accept", { ...source(), choices, manifest_sha256: prepared.ManifestSHA256 });
      setMessage(`Accepted ${prepared.ID}. Its self-test runs in the background.`);
      setPrepared(null);
      list.reload();
    } catch (e) {
      setMessage(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const act = async (verb: "remove" | "selftest" | "run", id: string) => {
    setBusy(true);
    setMessage("");
    try {
      if (verb === "run") {
        const rep = await post<CustomRunReport>("run", { id, dir: runDir });
        setReports((r) => ({ ...r, [id]: rep }));
      } else {
        await post(verb, { id });
      }
      list.reload();
    } catch (e) {
      setMessage(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const pick = (patch: CustomChoices) => void preview({ ...choices, ...patch, limits: { ...choices.limits, ...patch.limits } });

  return (
    <Card title="Custom scanners" sub="Scanners you configured through a digest-pinned manifest. Findings are flag-only.">
      <ChartState
        kind="table"
        loading={list.loading}
        stale={list.isStale}
        onRetry={list.reload}
        error={list.error}
        denied={list.denied}
        empty={false}
        emptyHint=""
      >
        <div className="space-y-4 text-[13px]" data-testid="custom-scanners">
          {(data?.scanners ?? []).length === 0 ? (
            <EmptyState title="No custom scanners" body="Import a template or a manifest file below." variant="inline" />
          ) : (
            <table className="w-full">
              <thead className="text-left text-fg-3">
                <tr>
                  <th className="py-1.5 pr-3 font-normal">Scanner</th>
                  <th className="py-1.5 pr-3 font-normal">Executable</th>
                  <th className="py-1.5 pr-3 font-normal">Self-test</th>
                  <th className="py-1.5 font-normal">Actions</th>
                </tr>
              </thead>
              <tbody>
                {(data?.scanners ?? []).map((r) => {
                  const st = selfTestWords(r.self_test, Boolean(r.manifest.self_test));
                  const rep = reports[r.id];
                  return (
                    <tr key={r.id} className="border-t border-line-1 align-top">
                      <td className="py-1.5 pr-3">
                        <div className="text-fg-1">
                          {r.manifest.name} {r.manifest.version}
                        </div>
                        <div className="text-fg-3">
                          pin {r.pin}
                          {r.org_approved ? ", org approved" : ""}
                        </div>
                      </td>
                      <td className="py-1.5 pr-3 font-mono text-fg-3">{r.manifest.executable}</td>
                      <td className="py-1.5 pr-3">
                        <Pill variant={TONE[st.tone]}>{st.text}</Pill>
                        {rep ? (
                          <div className="mt-1 text-fg-3">
                            last run: {verdictWords(rep)}, {rep.findings} findings; {isolationWords(rep)}
                            {rep.toolchain_skew ? <div>toolchain: {rep.toolchain_skew}</div> : null}
                          </div>
                        ) : null}
                      </td>
                      <td className="space-x-1 py-1.5">
                        <Button size="sm" variant="secondary" disabled={busy || !runDir} onClick={() => void act("run", r.id)}>
                          Run
                        </Button>
                        <Button size="sm" variant="secondary" disabled={busy || !r.manifest.self_test} onClick={() => void act("selftest", r.id)}>
                          Self-test
                        </Button>
                        <Button size="sm" variant="danger-outline" disabled={busy} onClick={() => void act("remove", r.id)}>
                          Remove
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          <Select
            label="Project to run against"
            aria-label="Project to scan"
            value={runDir}
            onChange={(e) => setRunDir(e.target.value)}
            disabled={projects.loading}
            options={runProjectOptions(projects.options)}
          />

          <div className="space-y-2 border-t border-line-1 pt-3">
            <div className="text-fg-2">Import a scanner</div>
            <div className="flex flex-wrap items-end gap-2">
              <Select
                label="Built-in template"
                value={file !== null ? "" : template}
                onChange={(e) => {
                  setFile(null);
                  setTemplate(e.target.value);
                  setPrepared(null);
                  setChoices({});
                }}
                options={[{ value: "", label: "Choose a template" }, ...(data?.templates ?? []).map((t) => ({ value: t.id, label: t.title }))]}
              />
              <label className="text-fg-3">
                or a manifest file{" "}
                <input
                  type="file"
                  accept=".json,application/json"
                  aria-label="Manifest file"
                  onChange={async (e) => {
                    const f = e.target.files?.[0];
                    if (!f) return;
                    setTemplate("");
                    setFile(await f.text());
                    setPrepared(null);
                    setChoices({});
                  }}
                />
              </label>
              <Button size="sm" variant="primary" disabled={busy || (!template && file === null)} onClick={() => void preview({})}>
                Preview
              </Button>
            </div>
            {message ? <div className="text-warn">{message}</div> : null}
            {prepared && pickers ? (
              <div className="space-y-3 rounded-2 border border-line-2 p-3">
                <div className="text-fg-2">
                  {prepared.Replaces ? "Replaces the accepted" : "New"} scanner <span className="font-mono">{prepared.ID}</span>, pin {prepared.Pin}
                  {prepared.OrgApproved ? ", from the org catalog" : ""}
                </div>
                {prepared.Note ? <div className="text-fg-3">{prepared.Note}</div> : null}
                {prepared.ExecNote ? <div className="text-warn">{prepared.ExecNote}</div> : null}
                <div className="flex flex-wrap gap-2">
                  <Select
                    label="Executable (discovered)"
                    value={prepared.Manifest.executable}
                    onChange={(e) => pick({ executable: e.target.value })}
                    options={(prepared.Candidates.Executable ?? []).map((c) => ({ value: c, label: c }))}
                  />
                  {(prepared.Candidates.Companions ?? []).map((list, i) => (
                    <Select
                      key={i}
                      label={`Companion ${i + 1} (discovered)`}
                      value={prepared.Manifest.companions?.[i]?.path ?? ""}
                      onChange={(e) => {
                        const next = [...(choices.companions ?? [])];
                        next[i] = e.target.value;
                        pick({ companions: next });
                      }}
                      options={(list ?? []).map((c) => ({ value: c, label: c }))}
                    />
                  ))}
                </div>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(pickers.limits).map(([field, steps]) => (
                    <Select
                      key={field}
                      label={limitLabel(field, pickers.children_unit)}
                      value={String(prepared.Manifest.limits[field as keyof typeof prepared.Manifest.limits])}
                      onChange={(e) => pick({ limits: { [field]: Number(e.target.value) } })}
                      options={steps.map((s) => String(s))}
                    />
                  ))}
                  <Select label="Cache" value={prepared.Manifest.cache} onChange={(e) => pick({ cache: e.target.value })} options={pickers.caches} />
                  <Select label="Category" value={prepared.Manifest.category} onChange={(e) => pick({ category: e.target.value })} options={pickers.categories} />
                  {Object.entries(prepared.Manifest.severity_map.levels).map(([level, sev]) => (
                    <Select
                      key={level}
                      label={`Severity of ${level}`}
                      value={sev}
                      onChange={(e) => pick({ severity: { ...choices.severity, [level]: e.target.value } })}
                      options={pickers.severities}
                    />
                  ))}
                  {prepared.Manifest.network.mode === "hosts" ? (
                    <Select
                      label="Network"
                      value={choices.network_none ? "none" : "hosts"}
                      onChange={(e) => pick({ network_none: e.target.value === "none" })}
                      options={[
                        { value: "hosts", label: hostsLabel(prepared.Manifest.network.hosts ?? []) },
                        { value: "none", label: "none" },
                      ]}
                    />
                  ) : null}
                </div>
                <div className="text-fg-3">The manifest, in full:</div>
                <pre className="max-h-80 overflow-auto rounded-2 bg-bg-2 p-2 font-mono text-[12px] text-fg-2">
                  {JSON.stringify(prepared.Manifest, null, 2)}
                </pre>
                {prepared.FileSHA256 ? <div className="font-mono text-fg-3">file sha256 {prepared.FileSHA256}</div> : null}
                <div className="font-mono text-fg-2">manifest sha256 {prepared.ManifestSHA256}</div>
                <Button variant="primary" disabled={busy || !readyToAccept(prepared)} onClick={() => void accept()}>
                  Accept this manifest
                </Button>
              </div>
            ) : null}
          </div>
        </div>
      </ChartState>
    </Card>
  );
}
