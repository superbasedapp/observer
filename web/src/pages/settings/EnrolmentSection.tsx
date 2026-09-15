import { useState } from "react";
import { ChartShell, SlideOver, StatCard, Tooltip } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { useApi } from "@/lib/useApi";
import { fmtBytes, fmtDateTime, fmtInt } from "@/lib/format";
import type { EnrolmentInvite, EnrolmentStatus } from "@/lib/types";

// EnrolmentSection is the Settings → Enrolment page: it shows whether this
// agent is enrolled in a Teams org, what the last push shared, lets the
// developer inspect the exact bytes sent, and lets them unenrol. It is purely
// a view over /api/enrolment/* — on a solo-local install (org mode off) the
// status reports not-enrolled and the page shows how to join.
export function EnrolmentSection() {
  const status = useApi<EnrolmentStatus>("/api/enrolment/status", undefined, [], {
    refreshMs: 15000,
  });
  const [payloadOpen, setPayloadOpen] = useState(false);
  const [unenroll, setUnenroll] = useState<{
    state: "idle" | "confirm" | "working" | "err";
    message?: string;
  }>({ state: "idle" });

  const data = status.data;
  const enrolled = !!data?.enrolled;

  async function doUnenroll() {
    setUnenroll({ state: "working" });
    try {
      const res = await fetch("/api/enrolment/unenroll", { method: "POST" });
      if (!res.ok) throw new Error(`server returned ${res.status}`);
      setUnenroll({ state: "idle" });
      status.reload();
    } catch (e) {
      setUnenroll({ state: "err", message: e instanceof Error ? e.message : String(e) });
    }
  }

  return (
    <ChartShell
      title="Organisation enrolment"
      sub="Teams visibility: when enrolled, this agent shares content-free activity rollups (counts, costs, timings, paths - never prompt text or tool output) with your organisation's SuperBased server. Enrol with `observer enroll <org-url> <token>`; unenrol any time below."
      right={
        enrolled ? (
          <div className="flex items-center gap-2 text-[11px]">
            <button
              type="button"
              onClick={() => setPayloadOpen(true)}
              className="rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-fg-1 hover:bg-bg-3"
            >
              View raw push payload
            </button>
            {unenroll.state === "confirm" ? (
              <span className="flex items-center gap-1.5">
                <span className="text-fg-2">Unenrol?</span>
                <button
                  type="button"
                  onClick={doUnenroll}
                  className="rounded-2 border border-danger/40 bg-danger-soft px-2.5 py-1 font-medium text-danger hover:bg-danger/20"
                >
                  Confirm
                </button>
                <button
                  type="button"
                  onClick={() => setUnenroll({ state: "idle" })}
                  className="rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-fg-2 hover:bg-bg-3"
                >
                  Cancel
                </button>
              </span>
            ) : (
              <button
                type="button"
                onClick={() => setUnenroll({ state: "confirm" })}
                disabled={unenroll.state === "working"}
                className="rounded-2 border border-danger/40 bg-danger-soft px-3 py-1 font-medium text-danger disabled:opacity-40"
              >
                {unenroll.state === "working" ? "Unenrolling…" : "Unenrol"}
              </button>
            )}
          </div>
        ) : null
      }
    >
      <ChartState
        loading={status.loading && !data}
        error={status.error}
        empty={false}
        height={160}
      >
        {unenroll.state === "err" && (
          <div className="mb-3 rounded-2 border border-danger/40 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
            Unenrol failed: {unenroll.message}
          </div>
        )}

        {!enrolled ? (
          <div className="rounded-2 border border-dashed border-line-2 bg-bg-3/40 px-4 py-3 text-[12px] text-fg-2">
            <div className="mb-1 font-medium text-fg-1">Not enrolled</div>
            This agent is not enrolled in an organisation - nothing is shared.
            To join, ask an admin for a one-time token and run{" "}
            <code className="font-mono text-fg-1">observer enroll &lt;org-url&gt; &lt;token&gt;</code>,
            then set <code className="font-mono text-fg-1">[org_client] enabled = true</code> and
            restart <code className="font-mono text-fg-1">observer start</code>.
            <div className="mt-2 text-fg-3">
              Working in a team and don&apos;t have an org server yet?{" "}
              <a
                href="https://superbased.app/docs/teams/getting-started"
                target="_blank"
                rel="noreferrer"
                className="text-accent underline underline-offset-2"
              >
                Teams getting-started guide
              </a>{" "}
              - bring one up locally in about five minutes.
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
              <StatCard label="Organisation" value={data?.org_name || "-"} sub={data?.org_id} />
              <StatCard label="You" value={data?.user_email || "-"} />
              <StatCard label="Server" value={<Mono>{data?.org_server_url || "-"}</Mono>} />
              <StatCard
                label="Credential store"
                value={data?.credential_store || "-"}
                sub={data?.enrolled_at ? `enrolled ${fmtDateTime(data.enrolled_at)}` : undefined}
              />
            </div>
            <PushPaused paused={data?.push_paused} />
            <LastPush push={data?.last_push} />
            <InviteTeammate />
          </div>
        )}
      </ChartState>

      <RawPayloadDrawer open={payloadOpen} onClose={() => setPayloadOpen(false)} />
    </ChartShell>
  );
}

// PushPaused renders the OPEN oversized-batch circuit. It is deliberately the
// loudest thing on the page while it is up: the push loop is parked for an hour
// and nothing is reaching the org server, which is otherwise only inferable from
// a "failed" row in the push history. The copy names the actual cause and the
// three knobs that fix it (the honest-disabled-copy rule: say WHICH dependency
// is at fault, never a bare "unavailable").
function PushPaused({ paused }: { paused?: EnrolmentStatus["push_paused"] }) {
  if (!paused) return null;
  return (
    <div className="rounded-2 border border-danger/40 bg-danger/5 px-3 py-2 text-[11.5px]">
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.06em] text-danger">
        Pushes paused
      </div>
      <div className="text-fg-2">
        The composed rollup is larger than the accepted push limit, so nothing is reaching the org
        server. The loop retries at <b>{paused.until}</b>.
      </div>
      {paused.reason && <div className="mt-1 text-fg-3">{paused.reason}</div>}
      <div className="mt-1 text-fg-3">
        Raise <Mono>[org_client].max_push_bytes</Mono>, narrow <Mono>[org_client.scope]</Mono>, or
        turn off a large <Mono>[org_client.share]</Mono> tier. The org server enforces its own body
        limit too, so raising the node-side value alone may not be enough.
      </div>
    </div>
  );
}

function LastPush({ push }: { push?: EnrolmentStatus["last_push"] }) {
  if (!push) {
    return (
      <div className="rounded-2 border border-line-1 bg-bg-2 px-3 py-2 text-[11.5px] text-fg-3">
        No push yet - the first content-free rollup is shared on the next push interval.
      </div>
    );
  }
  const ok = push.status === "ok";
  return (
    <div className="rounded-2 border border-line-1 bg-bg-2 px-3 py-2 text-[11.5px]">
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        Last push
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-fg-2">
        <span>
          status{" "}
          <b className={ok ? "text-success" : "text-danger"}>{push.status}</b>
        </span>
        <span>{fmtDateTime(push.pushed_at)}</span>
        <span>{fmtInt(push.row_count)} rows</span>
        <span>{fmtBytes(push.bytes)}</span>
        {push.error && <span className="text-danger">{push.error}</span>}
      </div>
    </div>
  );
}

// InviteTeammate is the loop-closing nudge: an enrolled developer can hand a
// teammate a one-time enrolment token without going through an admin — IF the
// org has enabled it ([server].member_invites on the org server).
//
// Every authority decision is the org server's. This component only asks; a
// refusal is rendered as honest copy naming the exact cause (the disabled-copy
// rule: say WHICH dependency is missing, never a bare "unavailable"):
//
//   403 — the org has not enabled member invites, and names the server key
//   404 — the teammate isn't a member yet (an invite is a handoff, not a signup)
//   429 — this developer's monthly allowance is spent
//   409 — this agent isn't enrolled
//
// The minted token is held in component state only, shown once, and cleared on
// reset — it is never written anywhere node-side.
function InviteTeammate() {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [state, setState] = useState<"idle" | "working" | "done" | "err">("idle");
  const [message, setMessage] = useState("");
  const [invite, setInvite] = useState<EnrolmentInvite | null>(null);
  const [copied, setCopied] = useState(false);

  async function mint(e: React.FormEvent) {
    e.preventDefault();
    if (!email.trim()) return;
    setState("working");
    setMessage("");
    try {
      const res = await fetch("/api/enrolment/invite", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim() }),
      });
      const body = await res.json().catch(() => ({}) as Record<string, string>);
      if (!res.ok) {
        setState("err");
        setMessage(body.message || `server returned ${res.status}`);
        return;
      }
      setInvite(body as EnrolmentInvite);
      setState("done");
    } catch (err) {
      setState("err");
      setMessage(err instanceof Error ? err.message : String(err));
    }
  }

  function reset() {
    setInvite(null);
    setEmail("");
    setState("idle");
    setMessage("");
    setCopied(false);
  }

  if (!open) {
    return (
      <div className="rounded-2 border border-dashed border-line-2 bg-bg-3/40 px-4 py-3 text-[12px] text-fg-2">
        <span className="font-medium text-fg-1">Working in a team?</span> Invite a teammate
        who is already a member of this organisation - they get a one-time enrolment token.{" "}
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-[11px] text-fg-1 hover:bg-bg-3"
        >
          Invite a teammate
        </button>
      </div>
    );
  }

  return (
    <div className="rounded-2 border border-line-1 bg-bg-2 px-4 py-3 text-[12px]">
      <div className="mb-2 flex items-center justify-between">
        <div className="font-medium text-fg-1">Invite a teammate</div>
        <button
          type="button"
          onClick={() => {
            reset();
            setOpen(false);
          }}
          className="rounded-2 border border-line-2 px-2 py-0.5 text-[11px] text-fg-3 hover:bg-bg-3"
        >
          Close
        </button>
      </div>

      {invite ? (
        <div className="space-y-2">
          <div className="text-fg-2">
            One-time token for <b className="text-fg-1">{invite.user_email}</b>. Send them this
            command - it works once and expires {fmtDateTime(invite.expires_at)}.
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 break-all rounded-2 border border-line-1 bg-bg-1 px-2 py-1 font-mono text-[11.5px] text-fg-1">
              {invite.command}
            </code>
            <button
              type="button"
              onClick={() => {
                void navigator.clipboard?.writeText(invite.command);
                setCopied(true);
              }}
              className="rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-[11px] text-fg-1 hover:bg-bg-3"
            >
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
          <div className="text-warn">
            Shown once. Nothing here is stored on this machine - close this panel and the token
            is gone.
          </div>
          {invite.monthly_cap > 0 && (
            <div className="text-fg-3">
              {invite.minted_this_month} of {invite.monthly_cap} invites used this month.
            </div>
          )}
          <button
            type="button"
            onClick={reset}
            className="rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-[11px] text-fg-2 hover:bg-bg-3"
          >
            Invite someone else
          </button>
        </div>
      ) : (
        <form onSubmit={mint} className="space-y-2">
          <div className="text-fg-3">
            They must already be a member of your organisation - an invite hands over a token, it
            does not create an account.
          </div>
          <div className="flex items-center gap-2">
            <input
              type="email"
              required
              value={email}
              onChange={(ev) => setEmail(ev.target.value)}
              placeholder="teammate@example.com"
              className="flex-1 rounded-2 border border-line-2 bg-bg-1 px-2.5 py-1 text-[12px] text-fg-1"
            />
            <button
              type="submit"
              disabled={state === "working" || !email.trim()}
              className="rounded-2 border border-line-2 bg-bg-2 px-3 py-1 text-[11px] font-medium text-fg-1 disabled:opacity-40"
            >
              {state === "working" ? "Minting…" : "Mint invite"}
            </button>
          </div>
          {state === "err" && (
            <div className="rounded-2 border border-danger/40 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
              {message}
            </div>
          )}
        </form>
      )}
    </div>
  );
}

// RawPayloadDrawer fetches /api/enrolment/last-payload and shows it verbatim —
// this is the exact content-free JSON last shared with the org, so a developer
// can audit precisely what was sent.
function RawPayloadDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [text, setText] = useState<string>("");
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const res = await fetch("/api/enrolment/last-payload");
      const raw = await res.text();
      try {
        setText(JSON.stringify(JSON.parse(raw), null, 2));
      } catch {
        setText(raw);
      }
    } catch (e) {
      setText(`failed to load: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setLoading(false);
    }
  }

  // Lazy-load when the drawer opens.
  if (open && text === "" && !loading) void load();

  return (
    <SlideOver
      open={open}
      onClose={onClose}
      title="Last shared payload"
      subtitle="The exact content-free rollup last pushed to your org - byte-for-byte. No prompt text or tool output is ever included."
      width={760}
    >
      <div className="p-4">
        {loading ? (
          <div className="text-[12px] text-fg-3">loading…</div>
        ) : text === "null" || text === "" ? (
          <div className="rounded-2 border border-dashed border-line-2 px-4 py-6 text-center text-[12px] text-fg-3">
            Nothing pushed yet.
          </div>
        ) : (
          <pre className="m-0 max-h-[70vh] overflow-auto whitespace-pre-wrap break-all rounded-2 border border-line-1 bg-bg-1 px-3 py-2 font-mono text-[11.5px] text-fg-2">
            {text}
          </pre>
        )}
      </div>
    </SlideOver>
  );
}

function Mono({ children }: { children: React.ReactNode }) {
  return (
    <Tooltip content={<span className="break-all font-mono">{children}</span>} maxWidth={420}>
      <span tabIndex={0} className="block cursor-help truncate font-mono text-[13px] focus:outline-none">
        {children}
      </span>
    </Tooltip>
  );
}
