import {
  Check,
  Copy,
  RefreshCw,
  type LucideIcon,
} from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import clsx from "clsx";
import { Summary } from "@/components/Summary";
import { Button, ChartShell, Pill, Table, Tooltip } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { useApi } from "@/lib/useApi";
import { fmtInt } from "@/lib/format";
import type {
  ToolLaunchResponse,
  ToolProbe,
  ToolsStatusResponse,
  ToolStatusRow,
} from "@/lib/types";
import { SetupWizard } from "./SetupWizard";

// Tools the P4.2 wizard can set up (the hook/MCP/route registries'
// management set).
const WIZARD_TOOLS = new Set(["claude-code", "cursor", "codex"]);

// Tools the P4.6 launch endpoint can open a terminal for (the
// server-side hardcoded allow-list, mirrored for button placement).
const LAUNCH_TOOLS = new Set(["claude-code", "codex"]);

// ConnectedToolsSection — the per-tool status matrix (usability arc
// P4.1 / review row B1): every supported tool with its detected /
// capturing / hooks / MCP / proxied state, from GET /api/tools/status.
// All server probes are read-only; the write paths stay where they
// are (routing buttons on the Compression page, hooks/MCP via
// `observer init` until the P4.2 wizard lands).
// `icon` is the section glyph from the Settings SECTIONS table.
export function ConnectedToolsSection({ icon }: { icon?: LucideIcon }) {
  const status = useApi<ToolsStatusResponse>("/api/tools/status");
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
          <div className="mb-3 rounded-2 border border-warn/40 bg-warn-soft px-3 py-2 text-[11.5px] text-warn">
            <strong className="font-semibold">
              {missingDefaults.length} default{" "}
              {missingDefaults.length === 1 ? "adapter is" : "adapters are"} not enabled
            </strong>{" "}
            in config.toml ({missingDefaults.join(", ")}) - sessions from{" "}
            {missingDefaults.length === 1 ? "it" : "them"} are not captured at all. Fix:{" "}
            <code className="font-mono text-fg-1">
              {status.data?.missing_default_remediation ?? "observer config adopt-defaults --write"}
            </code>
            , then restart the daemon.
          </div>
        )}
        <ToolsTable rows={detected} missingDefaults={missingDefaultsSet} onChanged={status.reload} />
        {others.length > 0 && (
          <details className="mt-3">
            <Summary className="w-fit text-[11.5px] text-fg-3 hover:text-fg-2">
              {others.length} supported tools not detected on this machine
            </Summary>
            <div className="mt-2">
              <ToolsTable rows={others} missingDefaults={missingDefaultsSet} onChanged={status.reload} />
            </div>
          </details>
        )}
        <div className="mt-3 flex flex-wrap items-center gap-3 border-t border-line-1 pt-3 text-[11px] text-fg-3">
          <Button variant="secondary" size="sm" iconLeft={RefreshCw} onClick={status.reload}>
            Refresh
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

function ToolsTable({
  rows,
  missingDefaults,
  onChanged,
}: {
  rows: ToolStatusRow[];
  missingDefaults: Set<string>;
  onChanged: () => void;
}) {
  const [openWizard, setOpenWizard] = useState<string | null>(null);
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
  onToggleWizard,
  onChanged,
}: {
  row: ToolStatusRow;
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
              title="A compiled-in default adapter is missing from your enabled_adapters list - run `observer config adopt-defaults --write`, then restart the daemon."
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
            {WIZARD_TOOLS.has(r.tool) && (
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
      {wizardOpen && (
        <tr>
          <td colSpan={7}>
            <SetupWizard tool={r.tool} onChanged={onChanged} />
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
// conflicts, status words) lives in the tooltip.
function ProbePill({ probe }: { probe?: ToolProbe }) {
  if (!probe) {
    return <span className="text-fg-4">n/a</span>;
  }
  const pill = probe.registered ? (
    <Pill variant="success">on</Pill>
  ) : probe.partial ? (
    <Pill variant="warn">partial</Pill>
  ) : (
    <Pill variant="neutral">off</Pill>
  );
  if (!probe.detail) return pill;
  return (
    <Tooltip content={probe.detail} maxWidth={380}>
      <span className="cursor-help">{pill}</span>
    </Tooltip>
  );
}
