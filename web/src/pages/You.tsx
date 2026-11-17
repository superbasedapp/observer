import { useState, type ReactNode } from "react";
import { Button, Callout, Card, PageHeader, Pill } from "@/components/primitives";
import { DisplayControls } from "@/components/TopBar";
import { BudgetCard } from "@/components/BudgetCard";
import { GatedLink } from "@/components/GatedLink";
import { applyLookup } from "@/components/security/PackageLookupCard";
import { navIcon } from "@/lib/nav";
import { apiReason, fetchJSON } from "@/lib/api";
import { apiCache, useApi, type ApiState } from "@/lib/useApi";
import { dollarsShown, fmtBytes, fmtCompact, fmtDateTime, fmtUSD } from "@/lib/format";
import { orgDisplayLabel } from "@/lib/orgName";
import { CLOUD_PURPOSE_LABELS } from "@/lib/cloud";
import { ORG_INTEL_STATUS_PATH } from "@/pages/settings/OrgIntelSection";
import { useGovernance } from "@/lib/governance";
import { cardPill, cardTitle, fmtAmount, healthText, type PlansResponse } from "@/lib/plans";
import type { BudgetStatus } from "@/lib/budgetWarning";
import type { OrgIntelStatusResponse } from "@/lib/orgIntel";
import type { PackageLookupResponse } from "@/lib/packageLookup";
import type { ProvenanceResponse } from "@/lib/codeSecurityExceptions";
import type { GrantReport } from "@/lib/enrolment";
import type { StatuslineStatus, LoginStartStatus, BrowserCaptureStatus } from "@/lib/setupExtras";
import type {
  CloudGrantsResponse,
  CloudStatusResponse,
  EnrolmentStatus,
  ShellWrapStatusResponse,
  StatusSnapshot,
  ToolsStatusResponse,
} from "@/lib/types";
import {
  accountLabel,
  consentRows,
  costDisplayLine,
  guardBudgetLines,
  integrationSummary,
  machineSourceWords,
  multiAccountTools,
  orgBudgetLine,
  planHeadlineText,
  policyLine,
  presenceWords,
  shareLines,
  shortFingerprint,
  type ConsentRow,
  type MeAggregateShare,
  type MeCredentialsResponse,
  type MeMachine,
  type MeToolAccountsResponse,
  type GuardBudgetLike,
} from "@/lib/you";

// You (docs/you-page.md): one scrolling page about this machine and this
// person. Every section READS routes that exist and LINKS to the page that
// edits it. Each row reads its own route, so one slow or failed read shows
// "could not read" on that row only. Withdrawing a consent is the only write
// here; accepting one stays on its owning page (R-165).

const SECTIONS: { id: string; label: string }[] = [
  { id: "machine", label: "This machine" },
  { id: "accounts", label: "AI tool accounts" },
  { id: "organization", label: "Organization" },
  { id: "cloud", label: "Cloud" },
  { id: "spend", label: "Plans and spend" },
  { id: "consents", label: "Consents" },
  { id: "credentials", label: "Stored credentials" },
  { id: "devices", label: "Devices and remote access" },
  { id: "integrations", label: "Integrations" },
  { id: "preferences", label: "Preferences" },
];

function Row({ label, children, to }: { label: ReactNode; children: ReactNode; to?: string }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-b border-line-1 py-1.5 text-[12px] last:border-b-0">
      <span className="text-fg-3">{label}</span>
      <span className="flex min-w-0 items-baseline gap-3 text-right text-fg-1">
        {children}
        {to && <ManageLink to={to}>Open</ManageLink>}
      </span>
    </div>
  );
}

/** ManageLink is every link on this page. It goes through GatedLink, so a
 *  link to a page or Settings section the organization hid on this machine
 *  (Cloud, Code security, Security > Budgets on a managed node) reads
 *  "Managed by your organization" instead of landing on a notice (CG-20,
 *  CG-21). */
function ManageLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <GatedLink to={to} className="text-[12px] font-medium text-accent hover:text-accent-strong">
      {children}
    </GatedLink>
  );
}

const NOT_MEASURED = <span className="text-fg-3">not measured</span>;

/** StateRow is one row backed by one read: reading, could not read, or the
 *  rendered answer. A failed read never blanks the rest of the page. */
function StateRow<T>({ label, api, show, to }: { label: ReactNode; api: ApiState<T>; show: (d: T) => ReactNode; to?: string }) {
  let body: ReactNode;
  if (api.data != null) body = show(api.data);
  else if (api.error) body = <span className="text-fg-3">could not read</span>;
  else body = <span className="text-fg-3">reading</span>;
  return (
    <Row label={label} to={to}>
      {body}
    </Row>
  );
}

export function YouPage() {
  return (
    <div className="space-y-4">
      <PageHeader
        title="You"
        icon={navIcon("you")}
        sub="Who this machine is, which accounts it has seen, and what you have agreed to. Each section links to where it is changed."
      />
      <nav aria-label="Sections" className="flex flex-wrap gap-x-3 gap-y-1 text-[12px]">
        {SECTIONS.map((s) => (
          <a key={s.id} href={`#you-${s.id}`} className="text-fg-2 hover:text-fg-0">
            {s.label}
          </a>
        ))}
      </nav>
      <MachineCard />
      <AccountsCard />
      <OrganizationCard />
      <CloudCard />
      <SpendCard />
      <ConsentsCard />
      <CredentialsCard />
      <DevicesCard />
      <IntegrationsCard />
      <PreferencesCard />
    </div>
  );
}

function MachineCard() {
  const status = useApi<StatusSnapshot>("/api/status");
  const me = useApi<MeMachine>("/api/me/machine");
  const m = me.data;
  const s = status.data;
  return (
    <Card id="you-machine" title="This machine" sub="Where Observer runs and how an organization would recognize this machine.">
      <Row label="Computer">{m?.host || s?.host_name || NOT_MEASURED}</Row>
      <Row label="Signed in as">{m?.os_user || NOT_MEASURED}</Row>
      <Row label="Observer version">{s?.version || "development build"}</Row>
      <Row label="Database size">{s ? fmtBytes(s.db_size_bytes) : NOT_MEASURED}</Row>
      <Row label={m?.org_bound ? "Machine fingerprint (as your organization sees it)" : "Machine fingerprint"}>
        {m?.fingerprint ? <code title="The first 16 characters of a one-way hash">{shortFingerprint(m.fingerprint)}</code> : NOT_MEASURED}
      </Row>
      {m && (
        <p className="pt-2 text-[11px] text-fg-3">
          Taken from {machineSourceWords(m.source)}.{" "}
          {m.org_bound ? "This is the value your organization holds." : "You are not enrolled, so no organization holds this value."} The
          machine&apos;s own id is never shown or sent.
        </p>
      )}
      <div className="pt-2">
        <ManageLink to="/settings?section=health">Open Health</ManageLink>
      </div>
    </Card>
  );
}

function AccountsCard() {
  const accounts = useApi<MeToolAccountsResponse>("/api/me/tool-accounts");
  const tools = accounts.data?.tools ?? [];
  const multi = multiAccountTools(tools);
  return (
    <Card id="you-accounts" title="AI tool accounts" sub="The vendor accounts each tool was seen signed in as, from sign-in events on this machine.">
      {accounts.error && !accounts.data ? (
        <p className="text-[12px] text-fg-3">could not read</p>
      ) : !accounts.data ? (
        <p className="text-[12px] text-fg-3">reading</p>
      ) : tools.length === 0 ? (
        <p className="text-[12px] text-fg-2">No tool has reported an account yet. Tools that do not share who is signed in never appear here.</p>
      ) : (
        <div className="space-y-3">
          {multi.length > 0 && (
            <Callout tone="warn" title="More than one account">
              {multi.join(", ")} {multi.length === 1 ? "was" : "were"} used with more than one account.
            </Callout>
          )}
          {tools.map((t) => (
            <div key={t.tool}>
              <div className="mb-1 flex items-center gap-2 text-[12px] font-medium text-fg-0">
                {t.tool}
                {t.multiple_accounts && <Pill variant="warn">{t.accounts.length} accounts</Pill>}
              </div>
              {t.accounts.map((a, i) => (
                <Row key={i} label={accountLabel(a)}>
                  {a.name && a.email ? `${a.name}, ` : ""}
                  {a.sessions} {a.sessions === 1 ? "session" : "sessions"}, first {fmtDateTime(a.first_seen)}, last {fmtDateTime(a.last_seen)}
                </Row>
              ))}
            </div>
          ))}
        </div>
      )}
      <p className="pt-2 text-[11px] text-fg-3">The plan an account is on is not captured. Whether account details leave this machine is set under Privacy.</p>
      <div className="pt-1">
        <ManageLink to="/privacy">Open Privacy</ManageLink>
      </div>
    </Card>
  );
}

type ConfigShare = { config?: { OrgClient?: { Share?: Record<string, unknown> } } };
type CostDisplayInfo = { mode?: string; source?: string; org_name?: string };

function OrganizationCard() {
  const enrol = useApi<EnrolmentStatus>("/api/enrolment/status");
  const gov = useGovernance();
  const cfg = useApi<ConfigShare>("/api/config");
  const display = useApi<CostDisplayInfo>("/api/cost-display");
  const budgets = useApi<BudgetStatus>("/api/budget/status");
  const e = enrol.data;
  const enrolled = !!e?.enrolled;
  const lines = shareLines(cfg.data?.config?.OrgClient?.Share, gov.data?.share);
  const windows = (budgets.data?.windows ?? []).map(orgBudgetLine);
  return (
    <Card id="you-organization" title="Organization" sub="Whether this machine reports to an organization, what it shares, and what the organization decides here.">
      <StateRow
        label="Enrolment"
        api={enrol}
        to="/settings?section=enrolment"
        show={(d) => (d.enrolled ? `Enrolled in ${orgDisplayLabel(d.org_display, d.org_name)}` : "Not enrolled. Nothing leaves this machine for an organization.")}
      />
      {enrolled && e && (
        <>
          <Row label="Your email there">{e.user_email || NOT_MEASURED}</Row>
          <Row label="Enrolled since">{e.enrolled_at ? fmtDateTime(e.enrolled_at) : NOT_MEASURED}</Row>
          <Row label="Last report sent">{e.last_push ? fmtDateTime(e.last_push.pushed_at) : "none yet"}</Row>
        </>
      )}
      <StateRow label="Policies in force" api={gov} show={(g) => policyLine(g)} />
      {enrolled && (
        <>
          <StateRow label="How amounts are shown" api={display} show={(d) => costDisplayLine(d)} />
          <StateRow
            label="Organization budgets that apply"
            api={budgets}
            show={(b) => (b.available && windows.length > 0 ? `${windows.length} ${windows.length === 1 ? "budget" : "budgets"}` : "None apply to you")}
          />
          {windows.map((w) => (
            <Row key={w.label} label={<span className="pl-3">{w.label}</span>}>
              <span className={w.tone === "danger" ? "text-danger" : w.tone === "warn" ? "text-warn" : ""}>{w.value}</span>
            </Row>
          ))}
        </>
      )}
      <div className="pt-3 text-[12px] font-medium text-fg-0">What this machine shares</div>
      {!enrolled && e ? (
        <p className="py-1 text-[12px] text-fg-2">Nothing, because this machine is not enrolled.</p>
      ) : cfg.error && !cfg.data ? (
        <p className="py-1 text-[12px] text-fg-3">could not read</p>
      ) : (
        lines.map((l) => (
          <Row key={l.key} label={l.label}>
            {l.value}
            <span className="text-fg-3">decided by {l.decidedBy}</span>
          </Row>
        ))
      )}
      <div className="flex gap-4 pt-2">
        <ManageLink to="/settings?section=enrolment">Enrolment and leaving</ManageLink>
        <ManageLink to="/privacy">Change what is shared</ManageLink>
      </div>
    </Card>
  );
}

function CloudCard() {
  const cloud = useApi<CloudStatusResponse>("/api/cloud/status");
  return (
    <Card id="you-cloud" title="Cloud" sub="Optional Cloud Intelligence for your own sessions.">
      <StateRow
        label="Signed in"
        api={cloud}
        show={(c) => (!c.sign_in || !c.sign_in.known ? "Not available on this build" : c.sign_in.signed_in ? "Yes" : "No")}
      />
      <div className="pt-2">
        <ManageLink to="/settings?section=cloud">Sign in, sign out or delete the account</ManageLink>
      </div>
    </Card>
  );
}

function SpendCard() {
  const plans = useApi<PlansResponse>("/api/plans");
  const guard = useApi<GuardBudgetLike>("/api/guard/budget");
  const cards = plans.data?.view.cards ?? [];
  const guardLines = guard.data ? guardBudgetLines(guard.data, dollarsShown(), (n) => fmtUSD(n), (n) => fmtCompact(n)) : [];
  return (
    <Card id="you-spend" title="Plans and spend" sub="Your plan balances, and this month's spend against the budgets that apply.">
      <div className="text-[12px] font-medium text-fg-0">Plan accounts</div>
      {plans.error && !plans.data ? (
        <p className="py-1 text-[12px] text-fg-3">could not read</p>
      ) : !plans.data ? (
        <p className="py-1 text-[12px] text-fg-3">reading</p>
      ) : cards.length === 0 ? (
        <p className="py-1 text-[12px] text-fg-2">No plan or balance accounts yet.</p>
      ) : (
        cards.map((c) => {
          const pill = cardPill(c);
          return (
            <Row key={c.id} label={cardTitle(c)}>
              {planHeadlineText(c.headline, fmtAmount) || healthText(c) || NOT_MEASURED}
              {pill && <Pill variant={pill.tone === "danger" ? "danger" : pill.tone === "warn" ? "warn" : "neutral"}>{pill.label}</Pill>}
            </Row>
          );
        })
      )}
      <div className="pt-3 text-[12px] font-medium text-fg-0">Enforced budgets on this machine</div>
      {guard.error && !guard.data ? (
        <p className="py-1 text-[12px] text-fg-3">could not read</p>
      ) : !guard.data ? (
        <p className="py-1 text-[12px] text-fg-3">reading</p>
      ) : guardLines.length === 0 ? (
        <p className="py-1 text-[12px] text-fg-2">No enforced cap is set.</p>
      ) : (
        guardLines.map((l) => (
          <Row key={l.label} label={l.label}>
            {l.value}
          </Row>
        ))
      )}
      <div className="flex gap-4 pt-2">
        <ManageLink to="/plans">Plans and limits</ManageLink>
        <ManageLink to="/security?tab=budgets">Enforced budgets</ManageLink>
        <ManageLink to="/cost">Cost</ManageLink>
      </div>
      <div className="pt-3">
        <BudgetCard />
      </div>
    </Card>
  );
}

type SandboxConfigReply = { sandbox: { sign_in_seed_tools?: string[]; oci?: { allow_devcontainer_image?: boolean } } };

function ConsentsCard() {
  const intel = useApi<OrgIntelStatusResponse>(ORG_INTEL_STATUS_PATH);
  const grants = useApi<CloudGrantsResponse>("/api/cloud/consent/grants");
  const lookup = useApi<PackageLookupResponse>("/api/security/lookup");
  const prov = useApi<ProvenanceResponse>("/api/security/provenance");
  const grant = useApi<GrantReport>("/api/enrolment/grant");
  const sandbox = useApi<SandboxConfigReply>("/api/terminal/sandbox/config");
  const agg = useApi<MeAggregateShare>("/api/me/aggregate-share");
  const [busy, setBusy] = useState<string | null>(null);
  const [armed, setArmed] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const settled = ![intel, grants, lookup, prov, grant, sandbox, agg].some((a) => a.loading && !a.data);
  const rows = consentRows(
    {
      intel: intel.data?.status ?? null,
      cloud: grants.data?.receipts ?? null,
      lookup: lookup.data?.status ?? null,
      provenance: prov.data ? { consents: prov.data.status.consents } : null,
      grant: grant.data ?? null,
      signInSeed: sandbox.data ? (sandbox.data.sandbox.sign_in_seed_tools ?? []) : null,
      devcontainer: sandbox.data ? !!sandbox.data.sandbox.oci?.allow_devcontainer_image : null,
      aggregate: agg.data ?? null,
    },
    (p) => CLOUD_PURPOSE_LABELS[p] ?? p,
  );

  async function withdraw(row: ConsentRow) {
    if (!row.withdraw) return;
    if (armed !== row.id) {
      setArmed(row.id);
      return;
    }
    setArmed(null);
    setBusy(row.id);
    setErr(null);
    try {
      const w = row.withdraw;
      if (w.kind === "intel") {
        await fetchJSON(`/api/intel/withdraw`, undefined, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Observer-Confirm": intel.data?.confirm_token ?? "" },
          body: "{}",
        });
        apiCache.invalidate(ORG_INTEL_STATUS_PATH);
        intel.reload();
      } else if (w.kind === "cloud") {
        await fetchJSON(`/api/cloud/consent/revoke`, undefined, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ purpose: w.purpose }),
        });
        grants.reload();
      } else {
        await applyLookup(w.change);
        lookup.reload();
      }
    } catch (e) {
      setErr(apiReason(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <Card id="you-consents" title="Consents" sub="Everything you have agreed to, in one list. You can take back a consent here when its page allows it; agreeing happens on the page that explains it.">
      {err && (
        <Callout tone="danger" title="Could not withdraw">
          {err}
        </Callout>
      )}
      <ul>
        {rows.map((r) => (
          <li key={r.id} className="flex flex-wrap items-center justify-between gap-2 border-b border-line-1 py-2 text-[12px] last:border-b-0">
            <div className="min-w-0">
              <div className="text-fg-0">{r.title}</div>
              <div className="text-[11px] text-fg-3">
                {r.state === "given" && `Agreed${r.since ? ` ${fmtDateTime(r.since)}` : ""}${r.detail ? `. ${r.detail}` : ""}`}
                {r.state === "not_given" && `Not agreed${r.detail ? `. ${r.detail}` : ""}`}
                {r.state === "unreadable" && (settled ? "could not read" : "reading")}
                {r.state === "see_page" && (r.detail ?? "Status is shown on its own page")}
              </div>
            </div>
            <div className="flex items-center gap-3">
              {r.withdraw && (
                <Button size="sm" variant={armed === r.id ? "danger" : "secondary"} disabled={busy === r.id} onClick={() => void withdraw(r)}>
                  {armed === r.id ? "Click again to withdraw" : "Withdraw"}
                </Button>
              )}
              <ManageLink to={r.owner}>{r.state === "given" ? "Details" : "Open"}</ManageLink>
            </div>
          </li>
        ))}
      </ul>
      <p className="pt-2 text-[11px] text-fg-3">
        Withdrawing the vulnerability database download, the sign-in seed, signed change records and the organization grant happens on their own pages
        (the grant ends when you leave the organization). Community aggregate sharing has no dashboard control yet.
      </p>
    </Card>
  );
}

function CredentialsCard() {
  const list = useApi<MeCredentialsResponse>("/api/me/credentials");
  const [checked, setChecked] = useState<MeCredentialsResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const data = checked ?? list.data;
  async function check() {
    setBusy(true);
    setErr(null);
    try {
      setChecked(await fetchJSON<MeCredentialsResponse>("/api/me/credentials", { check: "1" }));
    } catch (e) {
      setErr(apiReason(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Card
      id="you-credentials"
      title="Stored credentials"
      sub="The keychain entries Observer writes on this machine. Values are never shown."
      actions={
        <Button size="sm" disabled={busy} onClick={() => void check()}>
          {busy ? "Checking" : "Check what is stored"}
        </Button>
      }
    >
      {err && <p className="text-[12px] text-danger">{err}</p>}
      {list.error && !data && <p className="text-[12px] text-fg-3">could not read</p>}
      {(data?.services ?? []).map((c) => (
        <div key={c.service} className="flex flex-wrap items-center justify-between gap-2 border-b border-line-1 py-1.5 text-[12px] last:border-b-0">
          <div className="min-w-0">
            <div className="text-fg-0">{c.purpose}</div>
            <div className="text-[11px] text-fg-3">
              <code>{c.service}</code>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Pill variant={c.presence === "present" ? "success" : "neutral"}>{presenceWords(c.presence)}</Pill>
            <ManageLink to={c.owner}>Manage</ManageLink>
          </div>
        </div>
      ))}
      <p className="pt-2 text-[11px] text-fg-3">
        Checking asks your keychain, which may ask you to unlock it. Some entries depend on the accounts you added, so they cannot be told from here.
      </p>
    </Card>
  );
}

type RemoteSessions = { sessions: { fingerprint: string; last_seen: string }[]; controller_live: boolean };

function DevicesCard() {
  const rs = useApi<RemoteSessions>("/api/remote/sessions");
  return (
    <Card id="you-devices" title="Devices and remote access" sub="Browsers and phones that are signed in to this dashboard from elsewhere.">
      <StateRow
        label="Signed-in remote devices"
        api={rs}
        show={(d) => (!d.controller_live ? "Remote access is off" : d.sessions.length)}
      />
      <div className="pt-2">
        <ManageLink to="/remote">Pair, revoke one or revoke all</ManageLink>
      </div>
    </Card>
  );
}

function IntegrationsCard() {
  const tools = useApi<ToolsStatusResponse>("/api/tools/status");
  const wrap = useApi<ShellWrapStatusResponse>("/api/shell-wrap/status");
  const line = useApi<{ status: StatuslineStatus }>("/api/setup/statusline");
  const login = useApi<{ status: LoginStartStatus }>("/api/setup/login-start");
  const browser = useApi<{ status: BrowserCaptureStatus }>("/api/setup/browser");
  const sum = tools.data ? integrationSummary(tools.data.tools) : null;
  const of = (key: "hooks" | "mcp" | "proxy") => (sum ? (sum[key] === "not available" ? "Not available for the tools found" : `Set up for ${sum[key]} tools found`) : "");
  return (
    <Card id="you-integrations" title="Integrations" sub="How Observer connects to your AI tools. Each is set on its own page.">
      <StateRow label="Hooks" api={tools} to="/settings?section=hooks" show={() => of("hooks")} />
      <StateRow label="MCP" api={tools} to="/settings?section=mcp" show={() => of("mcp")} />
      <StateRow label="Proxy route" api={tools} to="/settings?section=proxy" show={() => of("proxy")} />
      <StateRow
        label="Command wrapping"
        api={wrap}
        to="/settings?section=terminal"
        show={(w) => (w.status.enabled ? (w.status.in_sync ? "On" : "On, but out of date") : "Off")}
      />
      <StateRow
        label="Status line"
        api={line}
        to="/settings?section=tools"
        show={(d) =>
          !d.status.supported
            ? "Not available here"
            : d.status.state === "installed"
              ? "Installed"
              : d.status.state === "stale"
                ? "Installed, out of date"
                : d.status.state === "foreign"
                  ? "Another status line is in place"
                  : "Not installed"
        }
      />
      <StateRow
        label="Start at login"
        api={login}
        to="/settings?section=health"
        show={(d) => (!d.status.supported ? "Not available here" : !d.status.installed ? "Off" : d.status.enabled ? "On" : "Installed, not enabled")}
      />
      <StateRow
        label="Browser capture"
        api={browser}
        to="/settings?section=browser"
        show={(d) => (!d.status.supported ? "Not available here" : d.status.installed ? "Host installed" : "Host not installed")}
      />
      <div className="pt-2">
        <ManageLink to="/agent-config">AI tool settings</ManageLink>
      </div>
    </Card>
  );
}

function PreferencesCard() {
  return (
    <Card id="you-preferences" title="Preferences" sub="Kept in this browser only.">
      <Row label="Theme and density">
        <DisplayControls />
      </Row>
      <div className="pt-2">
        <ManageLink to="/settings?section=dashboard">More dashboard settings</ManageLink>
      </div>
    </Card>
  );
}
