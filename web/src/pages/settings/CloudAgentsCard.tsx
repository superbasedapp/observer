import { useEffect, useRef, useState } from "react";
import clsx from "clsx";
import { FlaskConical, KeyRound, Link2, RefreshCw, Unplug, UserCheck, Users } from "lucide-react";
import { Button, Callout, ConfirmButton, Input, Pill, Select } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { ChartState } from "@/components/ChartState";
import { VocabPill } from "@shared/lib/vocabPill";
import { ApiError, CloudAgentsWriteError, cloudAgentsWrite } from "@/lib/api";
import { fmtDateTime, fmtRelative } from "@/lib/format";
import { useApi } from "@/lib/useApi";
import {
  CLOUD_AGENTS_CONNECT_PATH,
  CLOUD_AGENTS_PATH,
  CLOUD_AGENTS_SYNC_ALL_PATH,
  CLOUD_AGENTS_TEST_PATH,
  COVERAGE,
  ERROR_CLASS,
  GROUNDING,
  SIGNAL_LABEL,
  USER_STATE,
  accountName,
  accountPath,
  checkConnectForm,
  connectBody,
  connectorFor,
  connectorParams,
  coverageEntry,
  errorEntry,
  gapText,
  lastPassText,
  needsLabel,
  needsUser,
  paramControl,
  probeText,
  syncText,
  taskCounts,
  userNotes,
  userOptions,
  type CloudAgentAccount,
  type CloudAgentChooseResponse,
  type CloudAgentConnectResponse,
  type CloudAgentConnector,
  type CloudAgentProbeResponse,
  type CloudAgentSignal,
  type CloudAgentSyncAllResponse,
  type CloudAgentSyncResponse,
  type CloudAgentUsers,
  type CloudAgentUsersResponse,
  type CloudAgentsResponse,
  type CloudAgentsView,
} from "@/lib/cloudAgents";

// CloudAgentsCard - Settings > Connected tools > "Cloud agents" (cloud-agents
// lane CA-B5, docs/cloud-agents.md). Every `observer cloud-agents` action has
// its control here: status (this card), test and connect (the form), sync one
// account or all, disconnect, and, for a connector whose catalog row says
// chooses_user, list the organization's users and choose your own.
//
// Placement: the routes are governed as the Settings "tools" subsection, so
// the card sits in that section beside Code hosts, the other "connect an
// outside account" card. An organization that hides or locks Connected tools
// hides or locks this too, with no second governance key.
//
// Keys: the API key field is a password field the user types; it is sent
// only in the POST body of test and connect, cleared after a connect, and
// never shown back (the server never returns a stored key).

type Msg = { ok: boolean; text: string } | null;

function writeReason(e: unknown): string {
  if (e instanceof CloudAgentsWriteError) {
    const s = e.message.trim();
    return /[.!?]$/.test(s) ? s : `${s}.`;
  }
  return e instanceof Error ? e.message : String(e);
}

function when(iso: string): string {
  return fmtRelative(iso);
}

export function CloudAgentsCard({ focus = false }: { focus?: boolean }) {
  const res = useApi<CloudAgentsResponse>(CLOUD_AGENTS_PATH);
  const ref = useRef<HTMLDivElement>(null);
  const [preset, setPreset] = useState<{ connector: string; n: number } | null>(null);
  useEffect(() => {
    if (focus) ref.current?.scrollIntoView({ block: "start", behavior: "smooth" });
  }, [focus]);
  const unavailable = res.error instanceof ApiError && res.error.status === 503;

  return (
    <div ref={ref} id="cloud-agents" className="mt-3 rounded-2 border border-line-2 bg-bg-3/40 px-3 py-3" data-testid="cloud-agents-card">
      <div className="min-w-0">
        <div className="flex items-center gap-1.5 text-[12.5px] font-semibold text-fg-1">
          Cloud agents <HelpInd id="glossary.cloud_agents" />
        </div>
        <p className="mt-0.5 text-[11px] text-fg-3">
          Pull the sessions your coding agents ran in a vendor's cloud. Off until you connect an account.
        </p>
      </div>
      {unavailable ? (
        <p className="mt-2 text-[11px] text-warn">
          Cloud agents are not running in this dashboard process, so nothing can be connected here. They work from the dashboard the
          Observer daemon serves.
        </p>
      ) : (
        <ChartState
          loading={res.loading && !res.data}
          error={res.error}
          denied={res.denied}
          deniedPermission={res.deniedPermission}
          onRetry={res.reload}
          empty={false}
          height={80}
        >
          {res.data && (
            <CloudAgentsBody
              view={res.data.view}
              onChanged={res.reload}
              preset={preset}
              onReplaceKey={(connector) => setPreset((p) => ({ connector, n: (p?.n ?? 0) + 1 }))}
            />
          )}
        </ChartState>
      )}
    </div>
  );
}

/** CloudAgentsBody renders the accounts and the connect form for one page
 *  model. Exported for the component tests (no fetch on render). */
export function CloudAgentsBody({
  view,
  onChanged,
  preset = null,
  onReplaceKey = () => undefined,
}: {
  view: CloudAgentsView;
  onChanged: () => void;
  preset?: { connector: string; n: number } | null;
  onReplaceKey?: (connector: string) => void;
}) {
  const accounts = view.accounts ?? [];
  const connectors = view.connectors ?? [];
  return (
    <>
      {accounts.length > 0 ? (
        <>
          <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
            <span className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">
              {accounts.length} connected account{accounts.length === 1 ? "" : "s"}
            </span>
            <SyncAllButton onChanged={onChanged} />
          </div>
          <ul className="mt-2 space-y-2">
            {accounts.map((a) => (
              <AccountRow key={a.id} a={a} c={connectorFor(view, a.connector)} onChanged={onChanged} onReplaceKey={onReplaceKey} />
            ))}
          </ul>
        </>
      ) : (
        <p className="mt-2 text-[11px] text-fg-3">No account connected. Nothing is pulled and no vendor is called until you connect one.</p>
      )}
      <ConnectForm connectors={connectors} onConnected={onChanged} preset={preset} />
    </>
  );
}

function SyncAllButton({ onChanged }: { onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Msg>(null);
  async function run() {
    setBusy(true);
    setMsg(null);
    try {
      const r = await cloudAgentsWrite<CloudAgentSyncAllResponse>(CLOUD_AGENTS_SYNC_ALL_PATH);
      const list = r.syncs ?? [];
      const failed = list.filter((s) => s.error_class).length;
      setMsg({
        ok: failed === 0,
        text: failed === 0 ? `Pulled ${list.length} account${list.length === 1 ? "" : "s"}.` : `${failed} of ${list.length} accounts failed; see each account.`,
      });
      onChanged();
    } catch (e) {
      setMsg({ ok: false, text: writeReason(e) });
    } finally {
      setBusy(false);
    }
  }
  return (
    <span className="flex flex-wrap items-center gap-2">
      {msg && (
        <span aria-live="polite" className={clsx("text-[11px]", msg.ok ? "text-fg-2" : "text-danger")}>
          {msg.text}
        </span>
      )}
      <Button size="sm" variant="secondary" iconLeft={RefreshCw} loading={busy} disabled={busy} onClick={() => void run()}>
        Sync all
      </Button>
    </span>
  );
}

/** AccountRow is one linked account: state, last pass, coverage and gaps,
 *  errors by class, the user picker when the connector chooses a user, and
 *  the account's actions. Exported for the component tests. */
export function AccountRow({
  a,
  c,
  onChanged,
  onReplaceKey = () => undefined,
}: {
  a: CloudAgentAccount;
  c: CloudAgentConnector | undefined;
  onChanged: () => void;
  onReplaceKey?: (connector: string) => void;
}) {
  const [busy, setBusy] = useState<"test" | "sync" | "disconnect" | null>(null);
  const [msg, setMsg] = useState<Msg>(null);
  const cov = coverageEntry(a.coverage);
  const pass = lastPassText(a, when);
  const counts = taskCounts(a);
  const gaps = gapText(a);
  const signals = a.signals ?? [];

  async function run(kind: "test" | "sync" | "disconnect") {
    setBusy(kind);
    setMsg(null);
    try {
      if (kind === "test") {
        const r = await cloudAgentsWrite<CloudAgentProbeResponse>(CLOUD_AGENTS_TEST_PATH, { connector: a.connector });
        const other = r.probe.ok && r.probe.account_id && r.probe.account_id !== a.account_id;
        setMsg({
          ok: r.probe.ok,
          text: other ? `${probeText(r.probe)} That is a different account than this one; connect it to pull it.` : probeText(r.probe),
        });
      } else if (kind === "sync") {
        const r = await cloudAgentsWrite<CloudAgentSyncResponse>(accountPath(a.id, "sync"));
        setMsg({ ok: !r.sync.error_class && r.sync.user_state !== "vendor_user_not_chosen", text: syncText(r.sync) });
        onChanged();
      } else {
        await cloudAgentsWrite(accountPath(a.id, "disconnect"));
        onChanged();
      }
    } catch (e) {
      setMsg({ ok: false, text: writeReason(e) });
    } finally {
      setBusy(null);
    }
  }

  return (
    <li className="rounded-2 border border-line-2 bg-bg-2 px-3 py-2 text-[11px]" data-testid="cloud-agent-account">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 space-y-1">
          <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
            <span className="font-medium text-fg-1">{a.label}</span>
            <span className="truncate font-mono text-fg-2" title={a.account_id}>
              {accountName(a)}
            </span>
            <VocabPill vocab="cloudAgentCoverage" table={COVERAGE} value={a.coverage} title={cov.tip}>
              {cov.label}
            </VocabPill>
            {a.last_error && (
              <VocabPill vocab="cloudAgentError" table={ERROR_CLASS} value={a.last_error} title={errorEntry(a.last_error).tip}>
                {errorEntry(a.last_error).label}
              </VocabPill>
            )}
          </div>
          <div className="flex flex-wrap gap-x-3 text-fg-3">
            <span title={a.last_attempt ? fmtDateTime(a.last_attempt) : undefined}>{pass ?? "No pass yet"}</span>
            {counts && <span>{counts}</span>}
            {gaps && <span className="text-warn">{gaps}</span>}
          </div>
          {a.last_error && <p className="text-fg-3">{errorEntry(a.last_error).tip}</p>}
          {!c && <p className="text-fg-3">This connector is not known to this version of Observer: the account is shown, never synced.</p>}
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-1.5">
          {c && !c.needs_key && (
            <Button
              size="sm"
              variant="secondary"
              iconLeft={FlaskConical}
              loading={busy === "test"}
              disabled={busy !== null}
              title="Check the vendor CLI login again; links nothing"
              onClick={() => void run("test")}
            >
              Test
            </Button>
          )}
          {c?.needs_key && (
            <Button
              size="sm"
              variant="secondary"
              iconLeft={KeyRound}
              disabled={busy !== null}
              title="The stored key is checked by Sync now. To test or store a different key, enter it in the form below."
              onClick={() => onReplaceKey(a.connector)}
            >
              Replace key
            </Button>
          )}
          {c && (
            <Button
              size="sm"
              variant="secondary"
              iconLeft={RefreshCw}
              loading={busy === "sync"}
              disabled={busy !== null}
              onClick={() => void run("sync")}
            >
              Sync now
            </Button>
          )}
          <ConfirmButton
            size="sm"
            variant="secondary"
            iconLeft={Unplug}
            disabled={busy !== null}
            loading={busy === "disconnect"}
            confirmLabel="Disconnect?"
            armedNote={c?.needs_key ? "Deletes the stored key and unlinks the account. Sessions already pulled stay." : "Unlinks the account. Sessions already pulled stay."}
            onConfirm={() => void run("disconnect")}
          >
            Disconnect
          </ConfirmButton>
        </div>
      </div>

      {c?.chooses_user && <UserPicker a={a} c={c} onChanged={onChanged} />}

      {signals.length > 0 && (
        <details className="mt-1.5">
          <summary className="w-fit cursor-pointer text-fg-3 hover:text-fg-2">What this account reports</summary>
          <SignalList signals={signals} />
        </details>
      )}
      {msg && (
        <p aria-live="polite" className={clsx("mt-1", msg.ok ? "text-fg-2" : "text-danger")}>
          {msg.text}
        </p>
      )}
    </li>
  );
}

function SignalList({ signals }: { signals: CloudAgentSignal[] }) {
  return (
    <dl className="mt-1.5 grid grid-cols-[minmax(0,9rem)_1fr] gap-x-3 gap-y-1">
      {signals.map((s) => (
        <div key={s.signal} className="contents">
          <dt className="text-fg-3">{SIGNAL_LABEL[s.signal] ?? s.signal}</dt>
          <dd>
            <VocabPill vocab="cloudAgentCoverage" table={COVERAGE} value={s.state} title={coverageEntry(s.state).tip}>
              {s.label || coverageEntry(s.state).label}
            </VocabPill>
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** UserPicker is the member-users picker of one account (catalog
 *  chooses_user): the chosen user, a list read on request (a bounded vendor
 *  call, never on render), and Save. Exported for the component tests. */
export function UserPicker({
  a,
  c,
  onChanged,
  initial = null,
}: {
  a: CloudAgentAccount;
  c: CloudAgentConnector;
  onChanged: () => void;
  initial?: CloudAgentUsers | null;
}) {
  const label = c.user_label || "User";
  const [users, setUsers] = useState<CloudAgentUsers | null>(initial);
  const [pick, setPick] = useState(initial?.chosen ?? a.vendor_user ?? "");
  const [busy, setBusy] = useState<"list" | "save" | null>(null);
  const [msg, setMsg] = useState<Msg>(null);
  const notChosen = needsUser(a, c);

  async function list() {
    setBusy("list");
    setMsg(null);
    try {
      const r = await cloudAgentsWrite<CloudAgentUsersResponse>(accountPath(a.id, "users"));
      setUsers(r.users);
      setPick(r.users.chosen ?? "");
    } catch (e) {
      setMsg({ ok: false, text: writeReason(e) });
    } finally {
      setBusy(null);
    }
  }

  async function save() {
    setBusy("save");
    setMsg(null);
    try {
      const r = await cloudAgentsWrite<CloudAgentChooseResponse>(accountPath(a.id, "user"), { user_id: pick });
      setMsg({ ok: true, text: r.sync ? `Saved. ${syncText(r.sync)}` : "Saved." });
      onChanged();
    } catch (e) {
      setMsg({ ok: false, text: writeReason(e) });
    } finally {
      setBusy(null);
    }
  }

  const options = users ? userOptions(users) : [];
  const listError = users?.error_class ? errorEntry(users.error_class) : null;
  const notes = users && !listError ? userNotes(users) : [];
  const saveReason = !pick ? `Choose a ${label}.` : pick === a.vendor_user ? "That user is already chosen." : undefined;

  return (
    <div className="mt-2 border-t border-line-1 pt-2" data-testid="cloud-agent-user-picker">
      {notChosen ? (
        <Callout tone="warn" title={`No ${label} chosen: nothing is pulled`}>
          This organization's list holds every member's sessions. Choose your own {label} and only its sessions are
          pulled.
        </Callout>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-fg-3">{label}</span>
          {a.vendor_user ? (
            <span className="font-mono text-fg-1">{a.vendor_user}</span>
          ) : (
            <span className="text-fg-3">not reported</span>
          )}
          {a.user_state && (
            <VocabPill vocab="cloudAgentUser" table={USER_STATE} value={a.user_state} title={USER_STATE[a.user_state]?.tip} />
          )}
          {a.purge_pending && <span className="text-fg-3">Sessions other members started are removed on the next pass.</span>}
        </div>
      )}

      <div className="mt-2 flex flex-wrap items-end gap-2">
        {users && !listError && options.length > 0 && (
          <Select
            label={label}
            className="w-full sm:w-96"
            value={pick}
            onChange={(e) => setPick(e.target.value)}
            options={[{ value: "", label: `Choose a ${label}`, disabled: true }, ...options]}
          />
        )}
        <Button
          size="sm"
          variant="secondary"
          iconLeft={Users}
          loading={busy === "list"}
          disabled={busy !== null}
          title="Reads one page of the organization's sessions to list its users; nothing is stored"
          onClick={() => void list()}
        >
          {users ? "List again" : notChosen ? `Choose your ${label}` : `Change ${label}`}
        </Button>
        {users && !listError && options.length > 0 && (
          <Button
            size="sm"
            variant="primary"
            iconLeft={UserCheck}
            loading={busy === "save"}
            disabled={busy !== null || saveReason !== undefined}
            title={saveReason}
            onClick={() => void save()}
          >
            Save and pull
          </Button>
        )}
      </div>
      {listError && (
        <p className="mt-1 text-danger">
          Could not list users: {listError.label}. {listError.tip}
        </p>
      )}
      {users && !listError && options.length === 0 && (
        <p className="mt-1 text-fg-3">No user with a session was found on the first page. Start a session in the vendor's app, then list again.</p>
      )}
      {notes.map((n) => (
        <p key={n} className="mt-1 text-fg-3">
          {n}
        </p>
      ))}
      {msg && (
        <p aria-live="polite" className={clsx("mt-1", msg.ok ? "text-fg-2" : "text-danger")}>
          {msg.text}
        </p>
      )}
    </div>
  );
}

/** ConnectorSummary is what one catalog connector is, reads and needs.
 *  Exported for the component tests. */
export function ConnectorSummary({ c }: { c: CloudAgentConnector }) {
  const hosts = c.hosts ?? [];
  return (
    <div className="space-y-1.5" data-testid="cloud-agent-connector">
      <div className="flex flex-wrap items-center gap-1.5">
        <VocabPill vocab="cloudAgentGrounding" table={GROUNDING} value={c.grounding} title={c.grounding_meaning}>
          {c.grounding_label || c.grounding}
        </VocabPill>
        {c.experimental && (
          <Pill variant="info" case="none">
            Experimental
          </Pill>
        )}
      </div>
      <p className="text-fg-2">{c.grounding_meaning}</p>
      <p className="text-fg-2">Needs {needsLabel(c)}.</p>
      <p className="text-fg-3">
        {c.needs_key
          ? hosts.length > 0
            ? `Calls ${hosts.join(", ")} only, over HTTPS. The key is kept in the system keychain and nowhere else.`
            : "The key is kept in the system keychain and nowhere else."
          : `Runs your own ${c.command || "vendor"} CLI with its existing login. Observer stores no credential for it.`}
      </p>
      <details>
        <summary className="w-fit cursor-pointer text-fg-3 hover:text-fg-2">What it can report at best</summary>
        <SignalList signals={c.signals ?? []} />
      </details>
    </div>
  );
}

/** ConnectForm picks a catalog connector and takes what it needs: a typed
 *  key (password field) and the declared parameters, pickers for closed
 *  lists. Test probes and links nothing; Connect probes, links and pulls
 *  once. Exported for the component tests. */
export function ConnectForm({
  connectors,
  onConnected,
  preset = null,
  initialConnector = "",
}: {
  connectors: CloudAgentConnector[];
  onConnected: () => void;
  preset?: { connector: string; n: number } | null;
  initialConnector?: string;
}) {
  const [connector, setConnector] = useState(initialConnector);
  const [key, setKey] = useState("");
  const [params, setParams] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<"test" | "connect" | null>(null);
  const [msg, setMsg] = useState<Msg>(null);
  const formRef = useRef<HTMLDivElement>(null);

  function choose(id: string) {
    setConnector(id);
    setKey("");
    setParams({});
    setMsg(null);
  }

  useEffect(() => {
    if (!preset) return;
    choose(preset.connector);
    formRef.current?.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [preset]);

  const c = connectors.find((x) => x.id === connector);
  const check = checkConnectForm(c, key, params);

  async function send(kind: "test" | "connect") {
    if (!c || !check.ok) return;
    setBusy(kind);
    setMsg(null);
    try {
      const body = connectBody(c, key, params);
      if (kind === "test") {
        const r = await cloudAgentsWrite<CloudAgentProbeResponse>(CLOUD_AGENTS_TEST_PATH, body);
        setMsg({ ok: r.probe.ok, text: r.probe.ok ? `${probeText(r.probe)} Connect to start pulling.` : probeText(r.probe) });
      } else {
        const r = await cloudAgentsWrite<CloudAgentConnectResponse>(CLOUD_AGENTS_CONNECT_PATH, body);
        if (!r.account) {
          setMsg({ ok: false, text: `${probeText(r.probe)} Nothing was linked or stored.` });
        } else {
          setKey("");
          const pulled = r.sync ? ` ${syncText(r.sync)}` : "";
          const user = c.chooses_user ? ` Now choose your ${c.user_label || "user"} on the account above.` : "";
          setMsg({ ok: true, text: `Connected ${r.account.display || r.account.account_id}.${pulled}${user}` });
          onConnected();
        }
      }
    } catch (e) {
      setMsg({ ok: false, text: writeReason(e) });
    } finally {
      setBusy(null);
    }
  }

  const options = [
    { value: "", label: "Choose a connector", disabled: true },
    ...connectors.map((x) => ({ value: x.id, label: x.experimental ? `${x.label} (experimental)` : x.label })),
  ];

  return (
    <div ref={formRef} className="mt-3 border-t border-line-1 pt-3 text-[11px]" data-testid="cloud-agent-connect">
      <div className="mb-2 text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">Connect an account</div>
      <div className="space-y-3">
        <Select label="Connector" className="w-full sm:w-96" value={connector} onChange={(e) => choose(e.target.value)} options={options} />
        {c && <ConnectorSummary c={c} />}
        {c?.needs_key && (
          <Input
            type="password"
            autoComplete="new-password"
            spellCheck={false}
            mono
            className="w-full sm:w-96"
            label="API key"
            help={c.key_label}
            value={key}
            onChange={(e) => setKey(e.target.value)}
          />
        )}
        {c &&
          connectorParams(c).map((p) =>
            paramControl(p) === "select" ? (
              <Select
                key={p.name}
                label={p.label}
                help={p.hint}
                className="w-full sm:w-96"
                value={params[p.name] ?? ""}
                onChange={(e) => setParams((x) => ({ ...x, [p.name]: e.target.value }))}
                options={[{ value: "", label: `Choose the ${p.label.toLowerCase()}`, disabled: true }, ...(p.choices ?? [])]}
              />
            ) : (
              <Input
                key={p.name}
                label={p.label}
                help={p.hint}
                mono
                spellCheck={false}
                autoComplete="off"
                className="w-full sm:w-96"
                value={params[p.name] ?? ""}
                onChange={(e) => setParams((x) => ({ ...x, [p.name]: e.target.value }))}
              />
            ),
          )}
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button
          size="sm"
          variant="secondary"
          iconLeft={FlaskConical}
          loading={busy === "test"}
          disabled={!check.ok || busy !== null}
          title={check.ok ? "Checks the login or key; links nothing and stores nothing" : check.reason}
          onClick={() => void send("test")}
        >
          Test
        </Button>
        <Button
          size="sm"
          variant="primary"
          iconLeft={Link2}
          loading={busy === "connect"}
          disabled={!check.ok || busy !== null}
          title={check.ok ? "Checks, links the account and pulls once" : check.reason}
          onClick={() => void send("connect")}
        >
          Connect
        </Button>
        {busy === "connect" && <span className="text-fg-3">Checking with the vendor before anything is linked or stored.</span>}
      </div>
      {msg && (
        <p role={msg.ok ? undefined : "alert"} aria-live="polite" className={clsx("mt-2", msg.ok ? "text-fg-2" : "text-danger")}>
          {msg.text}
        </p>
      )}
    </div>
  );
}
