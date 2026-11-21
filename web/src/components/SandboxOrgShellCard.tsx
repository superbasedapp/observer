// SandboxOrgShellCard.tsx is the "Org-hosted OpenShell" section of the
// Sandbox settings card (tracker F-019, g1-design.md sections 3.5, 3.6, 3.7
// and 5.3, lane G4). It shows what the organization publishes, the
// machine's sign-in (with the code to type on the organization's
// dashboard), the laptop-relay opt-in with its disclosure, the member's
// hold-on-end preference, the last explicit check, and the member's own
// held sessions (discard, fetch, and the resume command). It renders nothing
// on a node the organization offers no gateway to. Every write goes through
// an owner-local route with the hosted panel's confirm token; no route
// returns a grant handle or a token.

import { useState } from "react";
import { ConfirmButton, ErrorState, InlineLoading } from "@/components/primitives";
import { fetchJSON } from "@/lib/api";
import { useApi } from "@/lib/useApi";

type Published = {
  FrontURL: string;
  GatewayID: string;
  Version: string;
  IsoClass: string;
  Region: string;
  Tiers: string[] | null;
  LaptopRelay: string;
  HoldPolicy: string;
  MaxHoldHours: number;
  ReturnToNode: boolean;
  MaxRunMinutes: number;
};

type Check = { at: string; verdict: string; reason?: string; gateway_version?: string };
type Login = { user_code: string; verification_uri: string; expires_at: string; error?: string };

export type OrgShellStatus = {
  confirm_token: string;
  offered: boolean;
  published?: Published;
  signed_in: boolean;
  sign_in_expires_at?: string;
  laptop_relay: boolean;
  hold_on_end: boolean;
  disclosure: string;
  last_check?: Check;
  login?: Login;
};

type HeldBox = {
  run_id: string;
  state: string;
  held_since?: string;
  expires_at?: string;
  reason?: string;
  resume_count: number;
  tier: string;
  source: string;
};

export function SandboxOrgShellCard() {
  const status = useApi<OrgShellStatus>("/api/terminal/sandbox/orgshell");
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState<string | null>(null);

  async function post(path: string, body: unknown, key: string) {
    if (!status.data?.confirm_token) return;
    setBusy(key);
    setErr(null);
    try {
      await fetchJSON(path, undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Observer-Confirm": status.data.confirm_token },
        body: JSON.stringify(body),
      });
      status.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy("");
    }
  }

  if (status.loading && !status.data) return <InlineLoading label="Reading your organization's sandbox status" />;
  if (status.error && !status.data) return null; // no hosted driver active: nothing to show
  return <SandboxOrgShellView data={status.data} busy={busy} err={err} post={(p, b, k) => void post(p, b, k)} />;
}

export type SandboxOrgShellViewProps = {
  data: OrgShellStatus | null | undefined;
  busy: string;
  err: string | null;
  post: (path: string, body: unknown, key: string) => void;
};

/** SandboxOrgShellView renders one status answer (a render test needs no fetch). */
export function SandboxOrgShellView({ data, busy, err, post }: SandboxOrgShellViewProps) {
  if (!data || !data.offered || !data.published) return null;
  const p = data.published;
  const forbidden = p.LaptopRelay === "forbidden";
  return (
    <section className="mt-4 space-y-3" aria-label="Org-hosted OpenShell">
      <h4 className="text-sm font-medium">Org-hosted OpenShell (beta)</h4>
      <p className="text-xs text-muted">
        Your organization runs an OpenShell gateway ({p.GatewayID}, OpenShell {p.Version}) reached through {p.FrontURL}. The
        box runs on your organization's machines and its administrators can see into it. Tiers: {(p.Tiers ?? []).join(", ")};
        holding: {p.HoldPolicy} (at most {p.MaxHoldHours} h); work returned to this machine: {p.ReturnToNode ? "yes" : "no"}; box
        lifetime at most {p.MaxRunMinutes} minutes.
      </p>
      <div className="text-sm">
        {data.signed_in ? (
          <span>
            Signed in until {new Date(data.sign_in_expires_at ?? "").toLocaleString()}{" "}
            <ConfirmButton size="sm" variant="secondary" confirmLabel="Sign out of your organization's sandboxes" loading={busy === "logout"} onConfirm={() => post("/api/terminal/sandbox/orgshell/logout", {}, "logout")}>
              Sign out
            </ConfirmButton>
          </span>
        ) : (
          <span>
            Not signed in on this machine.{" "}
            <button type="button" className="underline" disabled={busy === "login"} onClick={() => post("/api/terminal/sandbox/orgshell/login", {}, "login")}>
              Sign in
            </button>
          </span>
        )}
        {data.login && (
          <p className="mt-1">
            Open <a className="underline" href={data.login.verification_uri} target="_blank" rel="noreferrer">{data.login.verification_uri}</a> and type{" "}
            <code>{data.login.user_code}</code>.{data.login.error ? ` (${data.login.error})` : ""}
          </p>
        )}
      </div>
      <div className="text-sm">
        <p className="text-xs text-muted">{data.disclosure}</p>
        {forbidden ? (
          <p>Your organization does not allow runs through a laptop, and this release has no other model route.</p>
        ) : data.laptop_relay ? (
          <span>
            Org sandboxes run through this laptop.{" "}
            <button type="button" className="underline" disabled={busy === "relay"} onClick={() => post("/api/terminal/sandbox/orgshell/laptop-relay", { on: false }, "relay")}>
              Opt out
            </button>
          </span>
        ) : (
          <ConfirmButton size="sm" confirmLabel="I agree: opt in" armedNote={data.disclosure} loading={busy === "relay"} onConfirm={() => post("/api/terminal/sandbox/orgshell/laptop-relay", { on: true }, "relay")}>
            Run org sandboxes through this laptop
          </ConfirmButton>
        )}
      </div>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={data.hold_on_end} disabled={busy === "hold"} onChange={(e) => post("/api/terminal/sandbox/orgshell/hold-on-end", { on: e.target.checked }, "hold")} />
        Hold my box when a run ends (where my organization holds on end)
      </label>
      <div className="text-sm">
        <button type="button" className="underline" disabled={busy === "check"} onClick={() => post("/api/terminal/sandbox/orgshell/check", {}, "check")}>
          Check
        </button>
        {data.last_check && (
          <span className="ml-2 text-muted">
            last checked {new Date(data.last_check.at).toLocaleTimeString()}: {data.last_check.verdict}
            {data.last_check.reason ? ` (${data.last_check.reason})` : ""}
          </span>
        )}
      </div>
      {data.signed_in && <SandboxOrgShellHeld confirmToken={data.confirm_token} />}
      {err && <ErrorState title="The organization's sandbox action failed" error={err} />}
    </section>
  );
}

/**
 * SandboxOrgShellHeld lists the member's own held sessions. The list is a
 * signed call to the organization, so it is made only when the member
 * clicks "Show held sessions", never by rendering the page (G4 fix round 1,
 * A6). A held box has not been collected, so it offers Discard and the
 * resume command, never "Fetch work" (fetch is for collected runs, from the
 * CLI).
 */
function SandboxOrgShellHeld({ confirmToken }: { confirmToken: string }) {
  const [rows, setRows] = useState<HeldBox[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const headers = { "Content-Type": "application/json", "X-Observer-Confirm": confirmToken };
  async function load() {
    setLoading(true);
    setMsg(null);
    try {
      const out = await fetchJSON<{ held: HeldBox[] | null }>("/api/terminal/sandbox/orgshell/held", undefined, { method: "POST", headers, body: "{}" });
      setRows(out?.held ?? []);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }
  async function discard(run: string) {
    setMsg(null);
    try {
      await fetchJSON(`/api/terminal/sandbox/orgshell/held/${encodeURIComponent(run)}/discard`, undefined, { method: "POST", headers, body: "{}" });
      setMsg(`discard requested for ${run}`);
      void load();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    }
  }
  return (
    <div className="text-sm">
      <h5 className="font-medium">Held sessions</h5>
      {rows === null ? (
        <button type="button" className="underline" disabled={loading} onClick={() => void load()}>
          Show held sessions
        </button>
      ) : rows.length === 0 ? (
        <p className="text-muted">None.</p>
      ) : (
        <ul className="space-y-1">
          {rows.map((h) => (
            <li key={h.run_id}>
              <code>{h.run_id}</code> {h.state}
              {h.expires_at ? `, expires ${new Date(h.expires_at).toLocaleString()}` : ""} (resumed {h.resume_count} times).{" "}
              Resume from a terminal: <code>observer sandbox org-shell resume {h.run_id}</code>.{" "}
              <ConfirmButton size="sm" variant="secondary" confirmLabel={`Delete held box ${h.run_id}`} onConfirm={() => void discard(h.run_id)}>
                Discard
              </ConfirmButton>
            </li>
          ))}
        </ul>
      )}
      {loading && <InlineLoading label="Reading your held sessions" />}
      {msg && <p className="text-muted">{msg}</p>}
    </div>
  );
}
