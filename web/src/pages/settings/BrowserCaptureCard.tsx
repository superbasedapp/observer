import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Pill } from "@/components/primitives";
import { fetchJSON } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import {
  browserBadge,
  changedSites,
  errorText,
  extensionIdProblem,
  siteDraft,
  validExtensionId,
  type BrowserCaptureStatus,
  type BrowserSiteRow,
} from "@/lib/setupExtras";
import { BTN, CODE, OutcomeView, PRIMARY_BTN, PreviewActions, SetupCardShell, useSetupFlow } from "./SetupCardParts";

// BrowserCaptureCard - Settings > Browser capture.
//
// Two controls that used to need the command line or config.toml:
//   1. "Set up browser capture": write the native-messaging host and the
//      per-browser manifests the superbased extension talks to (same code as
//      `observer init --browser`), previewed first, then confirmed.
//   2. Per-site switches: turn capture of one chat site (ChatGPT, Claude.ai,
//      Perplexity, Gemini, Copilot) off at the daemon, whatever the extension
//      sends. Each captured turn reads the list, so no restart is needed.
// Removing the host stays on Settings > Components (its deactivate step).

const SITES = "/api/browser/sites";

interface SitesResponse {
  confirm_token: string;
  config_etag: string;
  sites: BrowserSiteRow[];
}

export function BrowserCaptureCard({ readOnly = false }: { readOnly?: boolean }) {
  return (
    <>
      <BrowserHostPart readOnly={readOnly} />
      <BrowserSitesPart readOnly={readOnly} />
    </>
  );
}

function BrowserHostPart({ readOnly }: { readOnly: boolean }) {
  const flow = useSetupFlow<BrowserCaptureStatus>("/api/setup/browser");
  const { res, status: st, preview, result } = flow;
  const [extId, setExtId] = useState("");

  if (res.error) {
    return (
      <SetupCardShell title="Set up browser capture" badge={{ text: "unavailable", tone: "neutral" }}>
        <p className="text-[11px] text-fg-3">
          Browser capture setup is managed from this machine only (it writes files your browser reads).{" "}
          {res.error.message}
        </p>
      </SetupCardShell>
    );
  }
  if (!st) return null;

  const problem = extensionIdProblem(extId);
  const label = st.installed ? "Reinstall the host" : "Install the host";
  const buttons = st.supported
    ? [
        {
          label,
          onClick: () =>
            void flow.doPreview(label, { action: "install", extension_id: validExtensionId(extId) ? extId.trim() : "" }),
        },
      ]
    : [];

  return (
    <SetupCardShell title="Set up browser capture" badge={browserBadge(st)}>
      <p className="text-[11.5px] leading-relaxed text-fg-2">
        Lets the superbased browser extension hand captured ChatGPT, Claude.ai, Perplexity, Gemini and Copilot turns
        to Observer. This writes a small helper (the native-messaging host) and one manifest per Chromium-family
        browser. Nothing is written until you preview and confirm. The same control exists on the command line as{" "}
        <code className={CODE}>observer init --browser</code>.
      </p>
      {st.supported ? (
        <>
          <div className="space-y-1">
            <label className="block text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3" htmlFor="browser-ext-id">
              Extension id (optional)
            </label>
            <input
              id="browser-ext-id"
              type="text"
              value={extId}
              onChange={(e) => {
                setExtId(e.target.value);
                flow.cancel();
              }}
              placeholder="32 letters a to p, from your browser's extensions page"
              spellCheck={false}
              className="w-full max-w-md rounded-2 border border-line-2 bg-bg-3 px-2 py-1 font-mono text-[12px] text-fg-1"
              aria-invalid={problem !== ""}
            />
            {problem && <p className="text-[11px] text-warn">{problem}</p>}
            {st.candidates.length > 0 && (
              <div className="flex flex-wrap items-center gap-2 text-[11px] text-fg-3">
                <span>Found loaded in your browsers:</span>
                {st.candidates.map((c) => (
                  <button
                    key={`${c.browser}/${c.profile}/${c.id}`}
                    type="button"
                    className={BTN}
                    onClick={() => {
                      setExtId(c.id);
                      flow.cancel();
                    }}
                  >
                    Use {c.browser} ({c.profile})
                  </button>
                ))}
              </div>
            )}
          </div>
          {st.host_files.length > 0 && (
            <details className="text-[11px] text-fg-3">
              <summary className="cursor-pointer">Files Observer wrote ({st.host_files.length})</summary>
              <ul className="mt-1 space-y-0.5 font-mono">
                {st.host_files.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
            </details>
          )}
          <PreviewActions buttons={buttons} flow={flow} readOnly={readOnly} />
          {preview && <OutcomeView out={preview.out} />}
          {result && <OutcomeView out={result} />}
          <p className="text-[10.5px] text-fg-3">
            To remove the host, deactivate Browser capture in{" "}
            <Link to="/settings/components" className="text-accent hover:underline">
              Settings &gt; Components
            </Link>
            ; its preview lists exactly what is removed.
          </p>
        </>
      ) : (
        <p className="text-[11.5px] text-fg-3">{st.reason}</p>
      )}
    </SetupCardShell>
  );
}

function BrowserSitesPart({ readOnly }: { readOnly: boolean }) {
  const res = useApi<SitesResponse>(SITES);
  const rows = res.data?.sites ?? [];
  const token = res.data?.confirm_token ?? "";
  const [draft, setDraft] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  // Re-seed the switches from the daemon's answer whenever it changes.
  useEffect(() => {
    if (res.data) setDraft(siteDraft(res.data.sites));
  }, [res.data]);

  if (res.error) {
    return (
      <SetupCardShell title="Capture by site" badge={{ text: "unavailable", tone: "neutral" }}>
        <p className="text-[11px] text-fg-3">{res.error.message}</p>
      </SetupCardShell>
    );
  }
  if (!res.data) return null;

  const body = changedSites(rows, draft);
  const dirty = Object.keys(body).length > 0;

  async function save() {
    if (busy || !dirty) return;
    setBusy(true);
    setErr(null);
    try {
      await fetchJSON(SITES, undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Observer-Confirm": token },
        body: JSON.stringify({ sites: body }),
      });
      setSaved(true);
      res.reload();
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <SetupCardShell title="Capture by site">
      <p className="text-[11.5px] leading-relaxed text-fg-2">
        Choose which chat sites the daemon accepts turns from. A site switched off here is dropped even if the
        extension sends it. Each captured turn reads this list, so a change applies to the next turn without a
        restart.
      </p>
      <ul className="divide-y divide-line-1 rounded-2 border border-line-1">
        {rows.map((r) => (
          <li key={r.site} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-1.5 text-[12px]">
            <label className="flex min-w-[200px] items-center gap-1.5 text-fg-1">
              <input
                type="checkbox"
                checked={draft[r.site] ?? r.enabled}
                disabled={busy || readOnly}
                onChange={(e) => {
                  setDraft({ ...draft, [r.site]: e.target.checked });
                  setSaved(false);
                }}
              />
              {r.label}
            </label>
            <span className="font-mono text-[10.5px] text-fg-3">{r.site}</span>
            {!(draft[r.site] ?? r.enabled) && <Pill variant="warn">dropped</Pill>}
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className={PRIMARY_BTN} onClick={save} disabled={busy || readOnly || !dirty}>
          {busy ? "saving..." : "Save"}
        </button>
        {saved && !dirty && <span className="text-[11.5px] text-fg-3">Saved. The next captured turn uses it.</span>}
        {err && <span className="text-[11.5px] text-danger">{err}</span>}
        {readOnly && <span className="text-[11px] text-fg-3">Pinned by your organization.</span>}
      </div>
    </SetupCardShell>
  );
}
