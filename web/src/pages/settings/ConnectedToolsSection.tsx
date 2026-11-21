import {
  Check,
  Copy,
  History,
  RefreshCw,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import clsx from "clsx";
import { Summary } from "@/components/Summary";
import { Button, ChartShell, ConfirmButton, Pill, Table, Tooltip } from "@/components/primitives";
import { markRestartPending, RESTART_HINT } from "@/lib/restartPending";
import { ChartState } from "@/components/ChartState";
import { useApi } from "@/lib/useApi";
import { localConfirmHeaders } from "@/lib/api";
import { fmtInt } from "@/lib/format";
import { probeLabel } from "@/lib/toolProbe";
import { hasWizard } from "@/lib/wizardSteps";
import { openFirstRun } from "@/lib/firstRun";
import type {
  ToolLaunchResponse,
  ToolProbe,
  ToolsStatusResponse,
  ToolStatusRow,
} from "@/lib/types";
import { SetupWizard } from "./SetupWizard";
import { WindowsHomesCard } from "./WindowsHomesCard";
import { CodeHostsCard } from "./CodeHostsCard";
import { CloudAgentsCard } from "./CloudAgentsCard";
import { DashboardInstallsList } from "./DashboardInstallsList";
import { ToolDoctorPanel } from "./ToolDoctorPanel";

// Tools the P4.6 launch endpoint can open a terminal for (the
// server-side hardcoded allow-list, mirrored for button placement).
const LAUNCH_TOOLS = new Set(["claude-code", "codex"]);

// ConnectedToolsSection — the per-tool status matrix (usability arc
// P4.1 / review row B1): every supported tool with its detected /
// capturing / hooks / MCP / proxied state, from GET /api/tools/status.
// All server probes are read-only. Writes go through the per-row Set up
// wizard, offered for every tool whose row carries server-computed `wiring`
// (T-421: the registry's hook mechanisms, MCP formats and persisted routes).
// `icon` is the section glyph from the Settings SECTIONS table.
export function ConnectedToolsSection({ icon }: { icon?: LucideIcon }) {
  const status = useApi<ToolsStatusResponse>("/api/tools/status");
  // A Health remediation deep link (T-421): `?section=tools&tool=<t>&open=
  // setup|remove|doctor` opens that tool's wizard (and its Remove panel) or
  // its Run checks panel.
  const [params] = useSearchParams();
  const linkTool = params.get("tool");
  const linkOpen = params.get("open");
  const deepLink: ToolDeepLink | null =
    linkTool && (linkOpen === "setup" || linkOpen === "remove" || linkOpen === "doctor") ? { tool: linkTool, mode: linkOpen } : null;
  const rows = status.data?.tools ?? [];
  const detected = rows.filter((r) => r.detected || r.action_count > 0);
  const others = rows.filter((r) => !r.detected && r.action_count === 0);
  const missingDefaults = status.data?.missing_default_adapters ?? [];
  const missingDefaultsSet = new Set(missingDefaults);

  return (
    <ChartShell
      title="Connected tools"
      icon={icon}
      sub="Every AI tool observer can capture, with its live integration state. Detection = the tool's storage directory exists on this machine; capturing = rows in this observer's database."
    >
      <ChartState
        loading={status.loading}
        stale={status.isStale}
        onRetry={status.reload}
        error={status.error}
        denied={status.denied}
        deniedPermission={status.deniedPermission}
        empty={!status.loading && rows.length === 0}
        emptyHint="No tool catalog - daemon restart may be required after upgrading."
      >
        {missingDefaults.length > 0 && (
          <AdoptDefaultsBanner missing={missingDefaults} onAdopted={status.reload} />
        )}
        <ToolsTable rows={detected} missingDefaults={missingDefaultsSet} onChanged={status.reload} deepLink={deepLink} />
        {/* WSL daemon only (T-421 item 4): choose the Windows-side home an
            AI tool's config lives in; renders nothing elsewhere. */}
        <WindowsHomesCard focusTarget={linkOpen === "windows-home" ? params.get("target") : null} />
        {/* Code hosts (commit to PR to merge, D-689): connect GitHub for PR
            state, manage Observer-owned mirrors. `?section=tools&open=code-hosts`
            (every "Connect a code host" button) scrolls here. */}
        <CodeHostsCard focus={linkOpen === "code-hosts"} />
        {/* Cloud agents (cloud-agents lane CA-B5): connect a vendor cloud
            account, sync, disconnect, choose your user. Same governance key
            as this section; `?section=tools&open=cloud-agents` scrolls here. */}
        <CloudAgentsCard focus={linkOpen === "cloud-agents"} />
        {/* Tools THIS dashboard installed, with their Uninstall (owner-local;
            renders nothing when there are none or the read is refused). */}
        <div className="mt-3">
          <DashboardInstallsList />
        </div>
        {others.length > 0 && (
          <details className="mt-3" open={deepLink !== null && others.some((r) => r.tool === deepLink.tool) ? true : undefined}>
            <Summary className="w-fit text-[11.5px] text-fg-3 hover:text-fg-2">
              {others.length} supported tools not detected on this machine
            </Summary>
            <div className="mt-2">
              <ToolsTable rows={others} missingDefaults={missingDefaultsSet} onChanged={status.reload} deepLink={deepLink} />
            </div>
          </details>
        )}
        <div className="mt-3 flex flex-wrap items-center gap-3 border-t border-line-1 pt-3 text-[11px] text-fg-3">
          <Button variant="secondary" size="sm" iconLeft={RefreshCw} onClick={status.reload}>
            Refresh
          </Button>
          {/* T-922: reopen the first-run capture view. */}
          <Button variant="secondary" size="sm" iconLeft={History} onClick={openFirstRun}>
            Show history capture
          </Button>
          <span>
            <strong className="font-semibold text-fg-2">Set up</strong> walks
            hooks, MCP, and proxy routing per tool with a preview before every
            write. The route buttons also live on the{" "}
            <Link to="/compression" className="text-accent hover:underline">
              Compression page
            </Link>
            ; CLI parity: <code className="font-mono text-fg-2">observer init</code>.
          </span>
        </div>
      </ChartState>
    </ChartShell>
  );
}

type AdoptDefaultsResponse = {
  missing: string[];
  written: boolean;
  restart_required: boolean;
  error?: string;
};

// AdoptDefaultsBanner: `observer config adopt-defaults --write` from the
// dashboard (backlog item 6, sweep row 19). The list shown IS the preview
// (the same pure diff the CLI previews); the confirm posts exactly that list
// and the server refuses it (409) if the file changed in between. The write
// only appends names (comments and order kept, config.toml.bak first), and
// a new adapter captures from the next daemon start.
function AdoptDefaultsBanner({ missing, onAdopted }: { missing: string[]; onAdopted: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const many = missing.length !== 1;

  async function adopt() {
    setBusy(true);
    setErr(null);
    try {
      const res = await fetch("/api/config/adopt-defaults", {
        method: "POST",
        headers: await localConfirmHeaders(),
        body: JSON.stringify({ adapters: missing }),
      });
      const out = (await res.json().catch(() => null)) as AdoptDefaultsResponse | null;
      if (!res.ok) throw new Error(out?.error || `HTTP ${res.status}`);
      if (out?.restart_required) markRestartPending("observer", ["observer.watch.enabled_adapters"]);
      setDone(true);
      onAdopted();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      onAdopted();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mb-3 rounded-2 border border-warn/40 bg-warn-soft px-3 py-2 text-[11.5px] text-warn">
      <strong className="font-semibold">
        {missing.length} default {many ? "adapters are" : "adapter is"} not enabled
      </strong>{" "}
      in config.toml ({missing.join(", ")}) - sessions from {many ? "them" : "it"} are not captured at all.
      <div className="mt-2 flex flex-wrap items-center gap-3">
        <ConfirmButton
          variant="secondary"
          armedVariant="primary"
          size="sm"
          onConfirm={() => void adopt()}
          disabled={busy || done}
          confirmLabel={missing.length === 1 ? `Add ${missing[0]}?` : `Add these ${missing.length} adapters?`}
          armedNote="Appends only these names to [observer.watch] enabled_adapters; your other entries and comments stay. A backup goes to config.toml.bak."
        >
          {busy ? "Adding…" : `Enable ${many ? "them" : "it"}`}
        </ConfirmButton>
        {done && <span className="text-fg-2">Added. Capture starts after a daemon restart: {RESTART_HINT}.</span>}
        {err && <span className="text-danger">{err}</span>}
      </div>
    </div>
  );
}

/** ToolDeepLink is the Connected tools part of a remediation link. */
type ToolDeepLink = { tool: string; mode: "setup" | "remove" | "doctor" };

function ToolsTable({
  rows,
  missingDefaults,
  onChanged,
  deepLink,
}: {
  rows: ToolStatusRow[];
  missingDefaults: Set<string>;
  onChanged: () => void;
  deepLink: ToolDeepLink | null;
}) {
  const linked = deepLink !== null && deepLink.mode !== "doctor" && rows.some((r) => r.tool === deepLink.tool && hasWizard(r.wiring));
  const linkedTool = linked ? deepLink.tool : null;
  const [openWizard, setOpenWizard] = useState<string | null>(linkedTool);
  // The rows can arrive after the first render: honour the deep link once,
  // when its row first shows up.
  const applied = useRef(linkedTool !== null);
  useEffect(() => {
    if (linkedTool !== null && !applied.current) {
      applied.current = true;
      setOpenWizard(linkedTool);
    }
  }, [linkedTool]);
  if (rows.length === 0) {
    return (
      <p className="rounded-2 border border-dashed border-line-2 bg-bg-3/40 px-3 py-2 text-[11.5px] text-fg-3">
        Nothing detected yet.
      </p>
    );
  }
  return (
    <Table
      minWidth={720}
      head={
        <tr className="text-left">
          <th className="pb-1.5 pr-3 font-semibold">Tool</th>
          <th className="pb-1.5 pr-3 font-semibold">Detected</th>
          <th className="pb-1.5 pr-3 font-semibold">Capturing</th>
          <th className="pb-1.5 pr-3 font-semibold">Hooks</th>
          <th className="pb-1.5 pr-3 font-semibold">MCP</th>
          <th className="pb-1.5 pr-3 font-semibold">Proxied</th>
          <th className="pb-1.5 font-semibold"></th>
        </tr>
      }
    >
      {rows.map((r) => (
        <ToolRow
          key={r.tool}
          row={r}
          missingDefault={missingDefaults.has(r.tool)}
          wizardOpen={openWizard === r.tool}
          removeOpen={deepLink !== null && deepLink.mode === "remove" && deepLink.tool === r.tool}
          checksLinked={deepLink !== null && deepLink.mode === "doctor" && deepLink.tool === r.tool}
          onToggleWizard={() =>
            setOpenWizard(openWizard === r.tool ? null : r.tool)
          }
          onChanged={onChanged}
        />
      ))}
    </Table>
  );
}

function ToolRow({
  row: r,
  missingDefault,
  wizardOpen,
  removeOpen,
  checksLinked,
  onToggleWizard,
  onChanged,
}: {
  row: ToolStatusRow;
  /** Open the wizard's Remove panel (a Health remediation deep link). */
  removeOpen: boolean;
  /** Open the Run checks panel (a Health remediation deep link). */
  checksLinked: boolean;
  // True when this tool is a compiled-in default adapter absent from
  // the operator's explicit enabled_adapters list (ToolsStatusResponse
  // .missing_default_adapters) — distinct from a tool the operator
  // deliberately turned off, or a non-default tool that was never
  // enabled. Renders a fix-it pill instead of the plain "adapter off"
  // label so the one-time capture gap this represents (e.g. grokbot's
  // 2026-09-22 incident) is actionable from the row itself.
  missingDefault: boolean;
  wizardOpen: boolean;
  onToggleWizard: () => void;
  onChanged: () => void;
}) {
  const [launch, setLaunch] = useState<ToolLaunchResponse | null>(null);
  // Per-tool doctor (T-421 item 3): `observer doctor <tool>` for this row.
  const [checksOpen, setChecksOpen] = useState(checksLinked);
  return (
    <>
      <tr className="border-t border-line-1">
        <td className="py-1.5 pr-3">
          <Tooltip
            content={
              <span className="break-all font-mono">
                {r.detected_path || "not found on this machine"}
              </span>
            }
            maxWidth={420}
          >
            <span
              tabIndex={0}
              className={clsx(
                "cursor-help font-mono focus:outline-none focus-visible:ring-1 focus-visible:ring-accent-ring",
                r.detected || r.action_count > 0 ? "text-fg-1" : "text-fg-3",
              )}
            >
              {r.tool}
            </span>
          </Tooltip>
          {missingDefault ? (
            <Pill
              variant="warn"
              className="ml-2"
              title="A compiled-in default adapter is missing from your Enabled adapters list. Add it with the banner above, then restart the daemon (Restart now in the banner at the top, or Restart daemon in Settings > Health)."
            >
              not enabled (new default)
            </Pill>
          ) : (
            !r.enabled && (
              <Pill variant="neutral" case="upper" className="ml-2">
                adapter off
              </Pill>
            )
          )}
        </td>
        <td className="py-1.5 pr-3">
          <BoolDot on={r.detected} />
        </td>
        <td className="py-1.5 pr-3">
          {r.action_count > 0 ? (
            <Tooltip
              content={`last seen ${r.last_seen_at ?? "?"}`}
              maxWidth={300}
            >
              <span className="cursor-help text-fg-2">
                {fmtInt(r.action_count)} actions
              </span>
            </Tooltip>
          ) : (
            <span className="text-fg-4">none</span>
          )}
        </td>
        <td className="py-1.5 pr-3">
          <ProbePill probe={r.hooks} />
        </td>
        <td className="py-1.5 pr-3">
          <ProbePill probe={r.mcp} />
        </td>
        <td className="py-1.5 pr-3">
          <ProbePill probe={r.proxy} />
        </td>
        <td className="py-1.5 text-right">
          <span className="inline-flex items-center gap-1.5">
            {LAUNCH_TOOLS.has(r.tool) && (
              <LaunchButton tool={r.tool} onResult={setLaunch} />
            )}
            <Button
              variant={checksOpen ? "soft" : "secondary"}
              size="sm"
              onClick={() => setChecksOpen(!checksOpen)}
              title={`Run the ${r.tool} checks (observer doctor ${r.tool})`}
            >
              {checksOpen ? "Hide checks" : "Run checks"}
            </Button>
            {hasWizard(r.wiring) && (
              <Button
                variant={wizardOpen ? "soft" : "secondary"}
                size="sm"
                onClick={onToggleWizard}
              >
                {wizardOpen ? "Close" : "Set up"}
              </Button>
            )}
          </span>
        </td>
      </tr>
      {launch && (
        <tr>
          <td colSpan={7}>
            <LaunchResult result={launch} onDismiss={() => setLaunch(null)} />
          </td>
        </tr>
      )}
      {checksOpen && (
        <tr>
          <td colSpan={7}>
            <ToolDoctorPanel tool={r.tool} onClose={() => setChecksOpen(false)} />
          </td>
        </tr>
      )}
      {wizardOpen && (
        <tr>
          <td colSpan={7}>
            <SetupWizard tool={r.tool} wiring={r.wiring} onChanged={onChanged} initialRemoveOpen={removeOpen} />
          </td>
        </tr>
      )}
    </>
  );
}

function BoolDot({ on }: { on: boolean }) {
  return on ? (
    <Pill variant="success">yes</Pill>
  ) : (
    <span className="text-fg-4">-</span>
  );
}

// LaunchButton — POST /api/tools/launch for one tool (P4.6). The
// server decides plain-vs-wrapper from the live routing state and
// spawns best-effort; the result (incl. the always-present copy-paste
// command) renders in the LaunchResult row below.
function LaunchButton({
  tool,
  onResult,
}: {
  tool: string;
  onResult: (r: ToolLaunchResponse) => void;
}) {
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try {
      const res = await fetch("/api/tools/launch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ tool }),
      });
      if (!res.ok) {
        const text = await res.text();
        onResult({
          tool,
          routed: false,
          command: "",
          method: "none",
          spawned: false,
          detail: text || `HTTP ${res.status}`,
        });
        return;
      }
      onResult((await res.json()) as ToolLaunchResponse);
    } catch (e) {
      onResult({
        tool,
        routed: false,
        command: "",
        method: "none",
        spawned: false,
        detail: e instanceof Error ? e.message : String(e),
      });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Button variant="secondary" size="sm" onClick={run} loading={busy}>
      {busy ? "Launching…" : "Launch"}
    </Button>
  );
}

// LaunchResult — the honest outcome line. The command is always
// rendered with a copy affordance; when nothing spawned, the copy IS
// the product (never fake success).
function LaunchResult({
  result: r,
  onDismiss,
}: {
  result: ToolLaunchResponse;
  onDismiss: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(r.command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard unavailable (http origin) — the command stays
      // selectable text either way.
    }
  };
  return (
    <div className="my-1.5 rounded-2 border border-line-2 bg-bg-3/40 px-3 py-2 text-[11.5px]">
      <div className="flex flex-wrap items-center gap-2">
        {r.spawned ? (
          <>
            <Pill variant="success">terminal opened</Pill>
            <span className="text-fg-3">
              A window should be up running the command below - if you
              don't see one, run it yourself:
            </span>
          </>
        ) : (
          <>
            <Pill variant="warn">no window opened</Pill>
            <span className="text-fg-3">
              {r.detail || "This host has no way to open a terminal."}{" "}
              Run it in your own terminal:
            </span>
          </>
        )}
        <Button variant="ghost" size="sm" onClick={onDismiss} className="ml-auto">
          Dismiss
        </Button>
      </div>
      {r.command && (
        <div className="mt-1.5 flex items-center gap-2">
          <code className="select-all rounded-2 bg-bg-3 px-2 py-1 font-mono text-fg-1">
            {r.command}
          </code>
          <Button variant="secondary" size="sm" iconLeft={copied ? Check : Copy} onClick={copy}>
            {copied ? "Copied" : "Copy"}
          </Button>
        </div>
      )}
    </div>
  );
}

// ProbePill - one integration state. Absent probe = the integration
// doesn't exist for the tool (honest n/a). The probe detail (counts,
// conflicts, status words, or why a tool has no hooks) lives in the
// tooltip. The label rules are lib/toolProbe's table.
function ProbePill({ probe }: { probe?: ToolProbe }) {
  if (!probe) {
    return <span className="text-fg-4">n/a</span>;
  }
  const { label, variant } = probeLabel(probe);
  const pill = <Pill variant={variant}>{label}</Pill>;
  if (!probe.detail) return pill;
  return (
    <Tooltip content={probe.detail} maxWidth={380}>
      <span className="cursor-help">{pill}</span>
    </Tooltip>
  );
}
