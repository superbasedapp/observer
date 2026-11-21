import { useState } from "react";
import { Link } from "react-router-dom";
import { Button, ChartShell, Modal, Pill } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import {
  cacheLine,
  consentFor,
  firstRunNeeded,
  kindsChange,
  LOOKUP_INTRO,
  LOOKUP_KIND_LABELS,
  LOOKUP_MODES,
  LOOKUP_PRIVATE_NOTE,
  LOOKUP_ROUTE,
  lookupModeLine,
  modeChange,
  orgPostureLines,
  privateChange,
  privateLine,
  remoteDriverNotes,
  type PackageLookupChange,
  type PackageLookupResponse,
  type PackageLookupStatus,
} from "@/lib/packageLookup";

// PackageLookupCard - the Privacy page's "Package lookup" card (OS and CI
// vulnerability scanning plan section 13.10, lane RM-2), beside the Code
// security sharing picker, because it decides what leaves the machine:
// download the OSV databases (local), the superbased lookup with no
// download (remote), or both. A fresh install sees the first-run choice
// (ruling Q8 (a)): the download and the lookup side by side, and nothing is
// scanned until one is picked.
//
// Every data-sending choice is a human click on this owner-local surface: a
// dialog shows its consent's own text (the same words the CLI shows) before
// the button, then a PUT carrying the confirm token its GET minted. Nothing
// is chosen on the developer's behalf, and an agent can give none of them
// (guard rule R-165 denies the route, the keys and the records). A managed
// node's organization decides: the card reads, with no controls.
//
// Working surface: calm register, zero delight elements.

/** applyLookup re-reads the route for a fresh confirm token, then PUTs. */
export async function applyLookup(change: PackageLookupChange): Promise<PackageLookupStatus> {
  const res = await fetch(LOOKUP_ROUTE);
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
  const got = (await res.json()) as PackageLookupResponse;
  const put = await fetch(LOOKUP_ROUTE, {
    method: "PUT",
    headers: { "content-type": "application/json", ...(got.confirm_token ? { "X-Observer-Confirm": got.confirm_token } : {}) },
    body: JSON.stringify(change),
  });
  const text = await put.text();
  if (!put.ok) throw new Error(text.trim() || `HTTP ${put.status}`);
  return (JSON.parse(text) as PackageLookupResponse).status;
}

/** A pending consent dialog: the change it makes and the text it shows first. */
type Pending = { title: string; text: string; extra?: string; accept: string; change: PackageLookupChange };

/** pendingFor is the dialog a change needs, or null when it sends nothing new. */
function pendingFor(st: PackageLookupStatus, change: PackageLookupChange): Pending | null {
  if (change.accept_download) {
    return { title: "Download the OSV databases?", text: st.download.text, extra: `About ${st.approx_mb} MB at first.`, accept: "Accept and download", change };
  }
  if (change.accept_remote) {
    return {
      title: "Use the superbased lookup?",
      text: st.remote.text,
      extra: `Hosts: ${(st.remote_hosts ?? []).join(" and ")}.`,
      accept: "Accept the superbased lookup",
      change,
    };
  }
  if (change.accept_private) {
    return { title: "Send private package names too?", text: st.remote_private.text, accept: "Accept and send private names", change };
  }
  return null;
}

/** PackageLookupCard fetches the posture and renders the card (nothing on a 404: no dependency driver selected). */
export function PackageLookupCard() {
  const api = useApi<PackageLookupResponse>(LOOKUP_ROUTE);
  const st = api.data?.status;
  if (!st) return null;
  return <PackageLookupView st={st} onChanged={() => void api.reload()} />;
}

/** PackageLookupView is the card for one posture (pure enough to render in a test). */
export function PackageLookupView({ st, onChanged }: { st: PackageLookupStatus; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  async function run(change: PackageLookupChange) {
    setBusy(true);
    setErr(null);
    try {
      await applyLookup(change);
      setPending(null);
      onChanged();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  function choose(change: PackageLookupChange) {
    const p = pendingFor(st, change);
    if (p) setPending(p);
    else void run(change);
  }
  return (
    <ChartShell title="Package lookup" sub="How your dependencies are checked for known vulnerabilities, and what that sends">
      <div className="space-y-3 text-[12px]" data-testid="package-lookup">
        <p className="m-0 text-fg-2">{LOOKUP_INTRO}</p>
        <p className="m-0 text-fg-1" data-testid="package-lookup-line">
          {lookupModeLine(st)}
        </p>
        {st.managed ? (
          <ManagedPosture st={st} />
        ) : firstRunNeeded(st) ? (
          <PackageLookupFirstRun st={st} busy={busy} onChoose={choose} />
        ) : (
          <LookupControls st={st} busy={busy} onChoose={choose} />
        )}
        {err && !pending && <p className="m-0 text-danger">{err}</p>}
      </div>
      <Modal
        open={pending !== null}
        onClose={() => setPending(null)}
        dismissible={!busy}
        title={pending?.title ?? ""}
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setPending(null)} disabled={busy}>
              Cancel
            </Button>
            <Button variant="primary" onClick={() => pending && void run(pending.change)} disabled={busy} loading={busy}>
              {pending?.accept ?? "Accept"}
            </Button>
          </div>
        }
      >
        <div className="space-y-2 text-[12.5px]">
          <p className="m-0 whitespace-pre-wrap text-fg-2">{pending?.text}</p>
          {pending?.extra ? <p className="m-0 text-fg-3">{pending.extra}</p> : null}
          <p className="m-0 text-fg-3">Recorded on this machine, with the time; you can withdraw it here at any time. The same choice is `observer security lookup` on the CLI.</p>
          {err && <p className="m-0 text-danger">{err}</p>}
        </div>
      </Modal>
    </ChartShell>
  );
}

/**
 * PackageLookupFirstRun is the first-run choice (ruling Q8 (a)): the
 * download and the superbased lookup side by side, each with what it sends;
 * a click opens that choice's consent dialog.
 */
export function PackageLookupFirstRun({
  st,
  busy,
  onChoose,
}: {
  st: PackageLookupStatus;
  busy: boolean;
  onChoose: (change: PackageLookupChange) => void;
}) {
  const offers = LOOKUP_MODES.filter((m) => m.id !== "both");
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2" data-testid="package-lookup-first-run">
      {offers.map((m) => (
        <div key={m.id} className="space-y-2 rounded border border-line-1 p-3">
          <div className="font-medium text-fg-1">{m.label}</div>
          <p className="m-0 text-[11.5px] text-fg-3">{m.sends}</p>
          <Button variant="primary" disabled={busy} onClick={() => onChoose(modeChange(st, m.id))} data-testid={`package-lookup-choose-${m.id}`}>
            {m.id === "local" ? `Download (about ${st.approx_mb} MB)...` : "Use the superbased lookup..."}
          </Button>
        </div>
      ))}
    </div>
  );
}

/** LookupControls is the chosen posture's controls: mode, kinds, private names, withdrawals. */
function LookupControls({ st, busy, onChoose }: { st: PackageLookupStatus; busy: boolean; onChoose: (change: PackageLookupChange) => void }) {
  const remote = st.mode === "remote" || st.mode === "both";
  return (
    <div className="space-y-3">
      <div role="radiogroup" aria-label="Package lookup mode" className="space-y-2">
        {LOOKUP_MODES.map((m) => (
          <label key={m.id} className="flex items-start gap-2 text-fg-1">
            <input
              type="radio"
              name="package-lookup-mode"
              value={m.id}
              checked={st.mode === m.id}
              disabled={busy}
              onChange={() => onChoose(modeChange(st, m.id))}
              className="mt-0.5"
            />
            <span>
              <span className="font-medium">{m.label}</span>
              {consentFor(st, m.id) ? <span className="ml-1.5 text-[11px] text-fg-3">(asks for its consent)</span> : null}
              <span className="block text-[11.5px] text-fg-3">{m.sends}</span>
            </span>
          </label>
        ))}
      </div>
      {remote && (
        <div className="space-y-2 border-t border-line-1 pt-3" data-testid="package-lookup-remote">
          <div className="text-fg-2">What the superbased lookup covers</div>
          <div className="flex flex-wrap gap-3">
            {(st.kind_choices ?? []).map((k) => {
              const on = (st.kinds ?? []).includes(k);
              const change = kindsChange(st, k, !on);
              return (
                <label key={k} className="flex items-center gap-1.5 text-fg-1">
                  <input type="checkbox" checked={on} disabled={busy || change === null} onChange={() => change && onChoose(change)} />
                  {LOOKUP_KIND_LABELS[k] ?? k}
                </label>
              );
            })}
          </div>
          <p className="m-0 text-[11.5px] text-fg-3">{LOOKUP_PRIVATE_NOTE}</p>
          <label className="flex items-center gap-1.5 text-fg-1">
            <input
              type="checkbox"
              checked={st.private_sending}
              disabled={busy}
              onChange={() => onChoose(privateChange(st, !st.private_sending))}
              data-testid="package-lookup-private"
            />
            Send private and internal package names too
          </label>
          <p className="m-0 text-fg-3">{privateLine(st)}</p>
          {remoteDriverNotes(st).map((n) => (
            <p key={n} className="m-0 text-[11.5px] text-fg-3">
              {n}
            </p>
          ))}
          <p className="m-0 text-[11.5px] text-fg-3">{cacheLine(st.cache_bytes)}</p>
          <div className="flex flex-wrap gap-2">
            {st.remote.accepted && (
              <Button variant="secondary" disabled={busy} onClick={() => onChoose({ withdraw_remote: true, withdraw_private: true })} data-testid="package-lookup-withdraw">
                Withdraw the superbased lookup consent
              </Button>
            )}
            {st.remote_private.accepted && (
              <Button variant="secondary" disabled={busy} onClick={() => onChoose({ withdraw_private: true, private: "withhold" })}>
                Withdraw the private-names consent
              </Button>
            )}
          </div>
          <p className="m-0 text-[11.5px] text-fg-3">
            A change takes effect at the next scan; past scans keep the result they had.
          </p>
        </div>
      )}
    </div>
  );
}

/** ManagedPosture is the organization's posture, read-only (lane RM-3). */
function ManagedPosture({ st }: { st: PackageLookupStatus }) {
  return (
    <div className="space-y-1" data-testid="package-lookup-managed">
      <Pill variant="neutral">Set by your organization</Pill>
      {orgPostureLines(st).map((line) => (
        <p key={line} className="m-0 text-fg-3">
          {line}
        </p>
      ))}
      <p className="m-0 text-fg-3">The choice is your organization&apos;s; this card shows what leaves this machine and to where.</p>
    </div>
  );
}

/**
 * LookupPostureRow is the Scanners card's read-only view of the posture,
 * with a link to the Privacy page's card; on a fresh install it carries the
 * first-run choice too, since that is where "not scanned" is first seen.
 */
export function LookupPostureRow({ st, onChanged }: { st: PackageLookupStatus; onChanged: () => void }) {
  if (firstRunNeeded(st)) {
    return (
      <div className="border-t border-line-1 pt-3" data-testid="scanner-lookup-first-run">
        <PackageLookupView st={st} onChanged={onChanged} />
      </div>
    );
  }
  return (
    <div className="space-y-1 text-[12.5px]" data-testid="scanner-lookup">
      <div className="text-fg-2">Package lookup</div>
      <p className="m-0 text-fg-3">
        {lookupModeLine(st)}{" "}
        {!st.managed && (
          <Link to="/privacy" className="font-medium text-accent hover:text-accent-strong">
            Change on the Privacy page
          </Link>
        )}
      </p>
      {(st.mode === "remote" || st.mode === "both") && remoteDriverNotes(st).map((n) => (
        <p key={n} className="m-0 text-[11.5px] text-fg-3">
          {n}
        </p>
      ))}
    </div>
  );
}
