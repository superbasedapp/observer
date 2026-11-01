import { useEffect, useRef, useState } from "react";
import clsx from "clsx";
import { ExternalLink, KeyRound, Link2, RefreshCw, Trash2, Unplug } from "lucide-react";
import { Button, ConfirmButton, Input, Meter, SegmentedControl } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { ChartState } from "@/components/ChartState";
import { VocabPill } from "@shared/lib/vocabPill";
import { DELIVERY_LINKS_PATH, DELIVERY_MIRRORS_PATH, DeliveryWriteError, deliveryWrite } from "@/lib/api";
import { fmtBytes, fmtDateTime, fmtInt, fmtRelative } from "@/lib/format";
import { useApi, type ApiState } from "@/lib/useApi";
import { CODE_HOST_STATUS, MIRROR_STATUS, codeHostEntry, entry } from "@/lib/deliveryModel";
import type { DeliveryLink, DeliveryLinksResponse, DeliveryMirror, DeliveryMirrorsResponse } from "@/lib/types";

// CodeHostsCard - Settings > Connected tools > "Code hosts" (commit to PR to
// merge, D-689). Connect GitHub so the Projects "Delivery" tab and the
// session Commits card can say whether work is in an open PR, blocked,
// merged or closed. Off until the user adds a connection.
//
// The operator ruling sets the order: a fine-grained read-only token FIRST
// (least privilege, stored in the system keychain, called through Observer's
// own HTTPS client), the gh CLI login SECOND, with the note that a gh login
// is usually a read and write token. Every CLI verb (`observer delivery
// connect | test | disconnect | mirrors`) has its control here.

const TOKEN_HELP_URL = "https://github.com/settings/personal-access-tokens/new";

type Mode = "token" | "gh_cli";

// PROVIDERS is the provider picker: only GitHub has a connection in this
// release; the others are listed so the user sees they are known, not
// forgotten.
// It is the shared SegmentedControl (the Plans "Add account" picker), never a
// native select.
const COMING_LATER = "Coming later: only GitHub (github.com) can be connected in this release.";
const PROVIDERS = [
  { value: "github", label: "GitHub (github.com)" },
  { value: "gitlab", label: "GitLab, coming later", disabled: true, disabledReason: COMING_LATER },
  { value: "bitbucket", label: "Bitbucket, coming later", disabled: true, disabledReason: COMING_LATER },
  { value: "azure_devops", label: "Azure DevOps, coming later", disabled: true, disabledReason: COMING_LATER },
];

export function CodeHostsCard({ focus = false }: { focus?: boolean }) {
  const links = useApi<DeliveryLinksResponse>(DELIVERY_LINKS_PATH);
  const mirrors = useApi<DeliveryMirrorsResponse>(DELIVERY_MIRRORS_PATH);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (focus) ref.current?.scrollIntoView({ block: "start", behavior: "smooth" });
  }, [focus]);
  const list = links.data?.links ?? [];
  const reload = () => {
    links.reload();
    mirrors.reload();
  };

  return (
    <div ref={ref} id="code-hosts" className="mt-3 rounded-2 border border-line-2 bg-bg-3/40 px-3 py-3" data-testid="code-hosts-card">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 text-[12.5px] font-semibold text-fg-1">
            Code hosts <HelpInd id="glossary.delivery_code_hosts" />
          </div>
          <p className="mt-0.5 text-[11px] text-fg-3">
            Read pull request state (open, draft, conflicts, checks, reviews, merged or closed) for repositories with AI-touched commits. Off
            until you add one; without it, the Delivery tab uses your own git history only.
          </p>
        </div>
        {list.length > 0 && <span className="text-[10.5px] text-fg-3">{fmtInt(list.length)} connected</span>}
      </div>

      <ChartState loading={links.loading && !links.data} error={links.error} denied={links.denied} deniedPermission={links.deniedPermission} onRetry={links.reload} empty={false} height={80}>
        {links.data && (
          <>
            {!links.data.service_available && (
              <p className="mt-2 text-[11px] text-warn">
                The delivery service is not running in this dashboard process, so connecting and testing are unavailable here. They work from
                the dashboard the Observer daemon serves.
              </p>
            )}
            {list.length > 0 && (
              <ul className="mt-2 space-y-2">
                {list.map((l) => (
                  <LinkRow key={l.id} l={l} canWrite={links.data!.service_available} onChanged={reload} />
                ))}
              </ul>
            )}
            <AddCodeHost pollMinutes={links.data.poll_minutes} canWrite={links.data.service_available} first={list.length === 0} onAdded={reload} />
          </>
        )}
      </ChartState>

      <MirrorsSection res={mirrors} onChanged={reload} />
    </div>
  );
}

function authText(mode: string): string {
  return mode === "gh_cli" ? "gh CLI login" : "fine-grained token";
}

function LinkRow({ l, canWrite, onChanged }: { l: DeliveryLink; canWrite: boolean; onChanged: () => void }) {
  const [busy, setBusy] = useState<"test" | "disconnect" | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const st = codeHostEntry(l.status);

  async function run(kind: "test" | "disconnect") {
    setBusy(kind);
    setMsg(null);
    try {
      if (kind === "test") {
        const next = await deliveryWrite<DeliveryLink>("POST", `${DELIVERY_LINKS_PATH}/${l.id}/test`);
        const ok = next.status === "ok";
        setMsg({ ok, text: ok ? "Connection works." : next.last_error || entry(CODE_HOST_STATUS, next.status).tip });
      } else {
        await deliveryWrite("DELETE", `${DELIVERY_LINKS_PATH}/${l.id}`);
      }
      onChanged();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof DeliveryWriteError ? e.message : String(e) });
    } finally {
      setBusy(null);
    }
  }

  return (
    <li className="rounded-2 border border-line-2 bg-bg-2 px-3 py-2 text-[11px]">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
          <span className="font-medium text-fg-1">{l.host}</span>
          {l.account_login && <span className="text-fg-2">@{l.account_login}</span>}
          <span className="text-fg-3">{authText(l.auth_mode)}</span>
          <span className="text-fg-3">
            {fmtInt(l.repos)} repositor{l.repos === 1 ? "y" : "ies"}
            {l.last_ok_at ? `, synced ${fmtRelative(l.last_ok_at)}` : ", not synced yet"}
          </span>
          <VocabPill vocab="codeHostStatus" table={CODE_HOST_STATUS} value={l.status} title={st.tip} />
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          <Button size="sm" variant="secondary" iconLeft={RefreshCw} loading={busy === "test"} disabled={!canWrite || busy !== null} onClick={() => void run("test")}>
            Test
          </Button>
          <ConfirmButton
            size="sm"
            variant="secondary"
            iconLeft={Unplug}
            disabled={!canWrite || busy !== null}
            loading={busy === "disconnect"}
            confirmLabel="Disconnect?"
            armedNote="Removes the keychain entry and the PR data it fetched. Local landing detection keeps running."
            onConfirm={() => void run("disconnect")}
          >
            Disconnect
          </ConfirmButton>
        </div>
      </div>
      {l.status !== "ok" && l.status !== "never_checked" && (
        <p className="mt-1 text-fg-3">
          {/* The stored error is the code host's own text and may end without a
              stop; close the sentence before the hint that follows it. */}
          {((s) => (/[.!?]$/.test(s) ? s : `${s}.`))((l.last_error || st.tip || "").trim())}
          {st.action === "reconnect" && " Disconnect, then add it again with a fresh token (or sign in to gh again and use your gh login)."}
          {l.next_run_at && st.action === "wait" && ` Next try ${fmtRelative(l.next_run_at)}.`}
        </p>
      )}
      {l.auth_mode === "gh_cli" && <p className="mt-1 text-fg-4">Your gh login is usually a read and write token; Observer only ever reads with it.</p>}
      {msg && (
        <p aria-live="polite" className={clsx("mt-1", msg.ok ? "text-fg-2" : "text-danger")}>
          {msg.text}
        </p>
      )}
    </li>
  );
}

function AddCodeHost({ pollMinutes, canWrite, first, onAdded }: { pollMinutes: number; canWrite: boolean; first: boolean; onAdded: () => void }) {
  const [open, setOpen] = useState(first);
  const [mode, setMode] = useState<Mode>("token");
  const [token, setToken] = useState("");
  const [phase, setPhase] = useState<"idle" | "connecting">("idle");
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  useEffect(() => setOpen(first), [first]);

  async function connect() {
    setPhase("connecting");
    setErr(null);
    setDone(null);
    try {
      const l = await deliveryWrite<DeliveryLink>("POST", DELIVERY_LINKS_PATH, {
        provider: "github",
        host: "github.com",
        auth_mode: mode,
        token: mode === "token" ? token.trim() : undefined,
      });
      setToken("");
      setDone(`Connected as @${l.account_login || "unknown"}. Pull request state appears within a few minutes; Check now on a project's Delivery tab reads it immediately.`);
      setOpen(false);
      onAdded();
    } catch (e) {
      setErr(e instanceof DeliveryWriteError ? e.message : String(e));
    } finally {
      setPhase("idle");
    }
  }

  if (!open) {
    return (
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <Button size="sm" variant="secondary" iconLeft={Link2} onClick={() => setOpen(true)} disabled={!canWrite}>
          Add a code host
        </Button>
        {done && <span className="text-[11px] text-fg-2">{done}</span>}
      </div>
    );
  }

  const tokenOK = mode === "gh_cli" || token.trim().length >= 10;
  return (
    <div className="mt-3 border-t border-line-1 pt-3 text-[11px]">
      <div className="mb-2 text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">Add a code host</div>
      <dl className="grid grid-cols-1 gap-x-4 gap-y-3 sm:grid-cols-[9rem_1fr]">
        <dt className="text-fg-3 sm:pt-1.5">Provider</dt>
        <dd>
          <SegmentedControl size="sm" className="flex-wrap" value="github" onChange={() => undefined} options={PROVIDERS} />
        </dd>

        <dt className="text-fg-3 sm:pt-1">Sign in with</dt>
        <dd className="space-y-1.5">
          <SegmentedControl
            size="sm"
            value={mode}
            onChange={(m) => {
              setMode(m);
              setErr(null);
            }}
            options={[
              { value: "token", label: "Fine-grained token (recommended)", icon: KeyRound },
              { value: "gh_cli", label: "My gh CLI login" },
            ]}
          />
          {mode === "token" ? (
            <p className="text-fg-3">
              Read only, limited to the repositories you pick. Stored in the system keychain, never in the database or in config files. If
              this machine has no keychain, use your gh login instead.
            </p>
          ) : (
            <p className="text-fg-3">
              Reuses the login you made with <code className="font-mono text-fg-2">gh auth login</code>. Observer stores nothing. Note: a gh
              login is usually a read and write token on every repository you can reach; Observer only ever reads with it. The token option
              is narrower.
            </p>
          )}
        </dd>

        {mode === "token" && (
          <>
            <dt className="text-fg-3 sm:pt-1">Permissions needed</dt>
            <dd className="text-fg-2">
              Metadata: read. Pull requests: read. Contents: read. Commit statuses: read.{" "}
              <a href={TOKEN_HELP_URL} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-0.5 text-accent hover:underline">
                Create a token on GitHub
                <ExternalLink className="h-3 w-3" aria-hidden />
              </a>
            </dd>
            <dt className="text-fg-3 sm:pt-1.5">Token</dt>
            <dd>
              <Input
                type="password"
                autoComplete="off"
                spellCheck={false}
                mono
                className="w-full sm:w-96"
                placeholder="github_pat_..."
                value={token}
                onChange={(e) => setToken(e.target.value)}
                aria-label="Fine-grained token"
              />
            </dd>
          </>
        )}

        <dt className="text-fg-3">What Observer sends</dt>
        <dd className="text-fg-2">
          GET requests to <code className="font-mono">api.github.com</code> only, about every {fmtInt(pollMinutes || 10)} minutes while a
          repository has AI-touched commits that have not landed. Read only, no redirects followed, nothing about your code or prompts.
        </dd>
      </dl>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button size="sm" variant="primary" loading={phase === "connecting"} disabled={!canWrite || !tokenOK || phase === "connecting"} onClick={() => void connect()}>
          {mode === "token" ? "Connect and test token" : "Use my gh login"}
        </Button>
        {!first && (
          <Button size="sm" variant="ghost" onClick={() => setOpen(false)}>
            Cancel
          </Button>
        )}
        {phase === "connecting" && <span className="text-fg-3">Checking the credential with GitHub before anything is saved.</span>}
      </div>
      {err && (
        <p role="alert" className="mt-2 text-danger">
          {err}
        </p>
      )}
    </div>
  );
}

function MirrorsSection({ res, onChanged }: { res: ApiState<DeliveryMirrorsResponse>; onChanged: () => void }) {
  const d = res.data;
  if (!d) return null;
  const ratio = d.cap_bytes > 0 ? d.used_bytes / d.cap_bytes : 0;
  return (
    <div className="mt-3 border-t border-line-1 pt-3 text-[11px]">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Observer mirrors <HelpInd id="glossary.delivery_mirrors" />
        </span>
        <span className="tabular-nums text-fg-2">
          {fmtBytes(d.used_bytes)} of {d.cap_bytes > 0 ? fmtBytes(d.cap_bytes) : "no"} cap
        </span>
      </div>
      {d.cap_bytes > 0 && <Meter className="mt-1.5" ratio={ratio} tone={ratio > 0.9 ? "warn" : "accent"} label="Mirror disk use" />}
      {d.mirrors.length === 0 ? (
        <p className="mt-2 text-fg-3">
          No mirrors. A project can opt into one from its Delivery tab when its remote has no code host connection. Mirrors live in
          Observer's own data folder and never touch your repository.
        </p>
      ) : (
        <ul className="mt-2 space-y-1.5">
          {d.mirrors.map((m) => (
            <MirrorRow key={m.id} m={m} canWrite={d.service_available} onChanged={onChanged} />
          ))}
        </ul>
      )}
    </div>
  );
}

function MirrorRow({ m, canWrite, onChanged }: { m: DeliveryMirror; canWrite: boolean; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  async function del() {
    setBusy(true);
    setErr(null);
    try {
      await deliveryWrite("DELETE", `${DELIVERY_MIRRORS_PATH}/${m.id}`);
      onChanged();
    } catch (e) {
      setErr(e instanceof DeliveryWriteError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <li className="flex flex-col gap-1 rounded-2 border border-line-2 bg-bg-2 px-3 py-2 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span className="truncate font-mono text-fg-1" title={m.url}>
            {m.url}
          </span>
          <VocabPill vocab="mirrorStatus" table={MIRROR_STATUS} value={m.status} title={entry(MIRROR_STATUS, m.status).tip} />
        </div>
        <div className="mt-0.5 flex flex-wrap gap-x-3 text-fg-3">
          <span className="tabular-nums">{fmtBytes(m.size_bytes)}</span>
          <span title={m.last_refresh_at ? fmtDateTime(m.last_refresh_at) : undefined}>
            {m.last_refresh_at ? `refreshed ${fmtRelative(m.last_refresh_at)}` : "never refreshed"}
          </span>
          <span className="truncate font-mono" title={m.path}>
            {m.path}
          </span>
        </div>
        {m.last_error && <p className="mt-0.5 text-danger">{m.last_error}</p>}
        {err && <p className="mt-0.5 text-danger">{err}</p>}
      </div>
      <ConfirmButton
        size="sm"
        variant="secondary"
        iconLeft={Trash2}
        disabled={!canWrite || busy}
        loading={busy}
        confirmLabel="Delete mirror?"
        armedNote="Deletes the copy on disk. A project that still opts in re-creates it on its next refresh."
        onConfirm={() => void del()}
      >
        Delete
      </ConfirmButton>
    </li>
  );
}
