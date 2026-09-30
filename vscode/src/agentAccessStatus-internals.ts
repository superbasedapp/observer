// Pure helpers for the "MCP access" status bar item (src/agentAccessStatus.ts,
// Agent Access P10, doc3 §15 "VS Code").
//
// The item renders GET /api/mcp-access/status, the daemon read the node
// dashboard's Security page uses too; its `status` object IS the
// `observer mcp status --json` body (cmd/observer/mcp_access_dashboard.go),
// so the editor, the dashboard and the CLI can never disagree. The connect
// URL comes from the same origin rules as `observer mcp connect`: the org
// dashboard's My Connections page (R-S3-1 - the OAuth callback lands on the
// org dashboard origin, never on this machine).
//
// Kept vscode-import-free so it is unit-tested under plain node
// (test/unit/agentAccessStatus.test.ts, driven by the real daemon payloads in
// test/fixtures/agentAccess/), the costBar-internals.ts convention.

/** The daemon route the item reads. */
export const MCP_ACCESS_PATH = '/api/mcp-access/status';

/** Poll cadence: the cost bar's 60 s, never faster than an existing item. */
export const MCP_ACCESS_POLL_MS = 60_000;

/** Remote forwarding as the relay runtime resolved it. */
export interface AgentAccessRemote {
  wired: boolean;
  reason?: string;
  credential_id?: string;
  cred_gen?: number;
}

/** The subset of the `observer mcp status --json` body the item uses. */
export interface AgentAccessRelayStatus {
  enabled: boolean;
  mode: string;
  audit_mode: string;
  table_loaded: boolean;
  table_version?: number;
  point_status: string;
  missing_capabilities?: string[];
  chain_head: number;
  chain_ok?: boolean;
  pending_loss: number;
  launch_specs: number;
  projected_clients?: string[];
  remote_forwarding: AgentAccessRemote;
  coverage: Record<string, number>;
}

/** One server inside an approved vserver. */
export interface AgentAccessServer {
  id: string;
  target: string;
  credential_mode?: string;
  pinned: boolean;
  per_user_connect: boolean;
}

/** One approved virtual server. */
export interface AgentAccessVServer {
  id: string;
  slug: string;
  servers: AgentAccessServer[];
}

/** The effective-state row (enum-only). */
export interface AgentAccessEffective {
  status: string;
  reason: string;
  mode: string;
  running_version: number;
  restart_required: boolean;
}

/** The org-dashboard connect target; url absent when unavailable says why. */
export interface AgentAccessConnect {
  url?: string;
  unavailable?: string;
}

/** GET /api/mcp-access/status from the daemon. */
export interface AgentAccessView {
  available: true;
  status: AgentAccessRelayStatus;
  daemon_relay: boolean;
  enrolled: boolean;
  managed: boolean;
  vservers: AgentAccessVServer[];
  effective_state: AgentAccessEffective;
  connect: AgentAccessConnect;
}

/** GET /api/mcp-access/status from a process with no relay seam. */
export interface AgentAccessUnavailable {
  available: false;
  reason: string;
}

export type AgentAccessResponse = AgentAccessView | AgentAccessUnavailable;

/**
 * fetchAgentAccessStatus reads the route. A 404 is an older daemon that has
 * no such route: it resolves to null (the item stays hidden) rather than
 * throwing on every poll. Any other non-2xx throws.
 */
export async function fetchAgentAccessStatus(
  url: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
): Promise<AgentAccessResponse | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { method: 'GET', signal: controller.signal });
    if (res.status === 404) return null;
    if (!res.ok) {
      throw new Error(`SuperBased API ${MCP_ACCESS_PATH} -> HTTP ${res.status} ${res.statusText}`);
    }
    return (await res.json()) as AgentAccessResponse;
  } finally {
    clearTimeout(timer);
  }
}

/** What the status bar item shows. */
export interface AgentAccessItemModel {
  visible: boolean;
  /** Why the item is hidden (logged, never shown). */
  hiddenReason?: string;
  text: string;
  tooltip: string[];
  warning: boolean;
}

const HIDDEN = (hiddenReason: string): AgentAccessItemModel => ({
  visible: false,
  hiddenReason,
  text: '',
  tooltip: [],
  warning: false,
});

/** approvedServerCount counts distinct server ids across vservers. */
export function approvedServerCount(vservers: AgentAccessVServer[]): number {
  return new Set(vservers.flatMap((v) => v.servers.map((s) => s.id))).size;
}

/**
 * coverageSummary words the matrix summary: mediated cells only are
 * governed; hook-only / best-effort are best-effort; uncovered is
 * ungoverned. It never adds a label the matrix did not measure.
 */
export function coverageSummary(coverage: Record<string, number>): string {
  const n = (k: string): number => coverage[k] ?? 0;
  const total = Object.values(coverage).reduce((a, b) => a + b, 0);
  if (total === 0) return 'no coverage measured';
  const parts = [`${n('mediated')} of ${total} cells relay-governed`];
  parts.push(`${n('hook-only') + n('best-effort')} best-effort`);
  parts.push(`${n('uncovered')} ungoverned`);
  if (n('planned') > 0) parts.push(`${n('planned')} planned`);
  return parts.join(', ');
}

/** effectiveSummary words the effective-state row. */
export function effectiveSummary(e: AgentAccessEffective): string {
  const version = e.running_version > 0 ? ` (grant v${e.running_version})` : '';
  if (e.status === 'effective') {
    return e.mode === 'enforce' ? `effective, enforcing${version}` : `effective, ${e.mode} only (not enforcing)${version}`;
  }
  if (e.status === 'none') return 'no grant in force';
  const reason = e.reason && e.reason !== 'ok' ? ` - ${e.reason.replace(/_/g, ' ')}` : '';
  return `${e.status.replace(/_/g, ' ')}${reason}`;
}

/**
 * agentAccessItem decides the item. It is hidden (inert) when the daemon
 * has no route or no relay, when the relay is disabled, and when the node is
 * not enrolled with an organization - the item is about an org grant.
 */
export function agentAccessItem(resp: AgentAccessResponse | null): AgentAccessItemModel {
  if (!resp) return HIDDEN('the daemon does not serve /api/mcp-access/status (older build)');
  if (resp.available === false) return HIDDEN(resp.reason);
  const s = resp.status;
  if (!s.enabled) return HIDDEN('the node MCP relay is disabled ([mcp_relay].enabled = false)');
  if (!resp.enrolled) return HIDDEN('this node is not enrolled with an organization');

  const servers = approvedServerCount(resp.vservers);
  const effectivePoint = s.point_status === 'effective';
  const chainBroken = s.chain_ok === false;
  const warning = !effectivePoint || chainBroken || !resp.daemon_relay;
  const icon = warning ? '$(warning)' : '$(plug)';
  const text = `${icon} MCP ${servers}`;

  const tooltip: string[] = ['**SuperBased: MCP access**', ''];
  tooltip.push(`- Relay: on (${s.mode}, audit ${s.audit_mode}), point ${s.point_status}` +
    ((s.missing_capabilities ?? []).length > 0 ? ` - missing ${(s.missing_capabilities ?? []).join(', ')}` : ''));
  if (!resp.daemon_relay) tooltip.push('- The daemon was started with the relay off: restart it to bind the relay');
  tooltip.push(`- Approved servers: ${servers} in ${resp.vservers.length} virtual server${resp.vservers.length === 1 ? '' : 's'}`);
  tooltip.push(`- Coverage: ${coverageSummary(s.coverage)}`);
  tooltip.push(`- Effective state: ${effectiveSummary(resp.effective_state)}`);
  tooltip.push(`- Remote forwarding: ${s.remote_forwarding.wired ? 'on' : `off - ${s.remote_forwarding.reason || 'no reason reported'}`}`);
  if (chainBroken) tooltip.push('- Decision record chain BROKEN - run `observer mcp doctor`');
  if (s.pending_loss > 0) tooltip.push(`- ${s.pending_loss} decision record(s) pending as a recorded gap`);
  const perUser = resp.vservers.flatMap((v) => v.servers).filter((x) => x.per_user_connect).length;
  if (perUser > 0) tooltip.push(`- ${perUser} server(s) need your own sign-in (Connect)`);
  tooltip.push('', '_Click for per-server state and Connect._');
  return { visible: true, text, tooltip, warning };
}

/**
 * isSafeExternalURL admits only an absolute http(s) URL (the connect target
 * the daemon built from the enrolment origin) before openExternal.
 */
export function isSafeExternalURL(raw: string | undefined): boolean {
  if (!raw) return false;
  try {
    const u = new URL(raw);
    return (u.protocol === 'https:' || u.protocol === 'http:') && u.host !== '';
  } catch {
    return false;
  }
}

/** What selecting a quick pick entry does. */
export type AgentAccessAction =
  | { kind: 'connect'; url: string }
  | { kind: 'dashboard' }
  | { kind: 'none' };

/** One quick pick entry (vscode.QuickPickItem-shaped plus the action). */
export interface AgentAccessPickEntry {
  label: string;
  description?: string;
  detail?: string;
  action: AgentAccessAction;
}

/**
 * agentAccessQuickPick lists every approved server with its state; a
 * per-user (vault_user) server's entry connects in the org dashboard, the
 * same page `observer mcp connect` prints. The last entry opens the local
 * dashboard (Security page carries the full coverage matrix).
 */
export function agentAccessQuickPick(view: AgentAccessView): AgentAccessPickEntry[] {
  const entries: AgentAccessPickEntry[] = [];
  const connectURL = isSafeExternalURL(view.connect.url) ? (view.connect.url as string) : '';
  for (const v of view.vservers) {
    for (const s of v.servers) {
      const pinned = s.pinned ? ', tool snapshot pinned' : '';
      if (s.per_user_connect) {
        entries.push({
          label: `$(key) ${s.id}`,
          description: `${v.slug || v.id} - per-user sign-in`,
          detail: connectURL
            ? `Connect: sign in to this server in your org dashboard (My Connections); this machine never sees the token${pinned}`
            : `Per-user sign-in happens in the org dashboard: ${view.connect.unavailable ?? 'no org dashboard URL is known'}${pinned}`,
          action: connectURL ? { kind: 'connect', url: connectURL } : { kind: 'none' },
        });
      } else {
        entries.push({
          label: `$(server) ${s.id}`,
          description: `${v.slug || v.id} - ${s.credential_mode || 'no credential'}`,
          detail: `${s.target}${pinned}`,
          action: { kind: 'none' },
        });
      }
    }
  }
  if (entries.length === 0) {
    entries.push({ label: '$(info) No approved MCP servers', detail: 'The accepted grant approves no MCP server on this node.', action: { kind: 'none' } });
  }
  entries.push({
    label: '$(shield) Open the SuperBased dashboard',
    detail: 'Security page: relay status, approved servers, the full coverage matrix, effective state',
    action: { kind: 'dashboard' },
  });
  return entries;
}
