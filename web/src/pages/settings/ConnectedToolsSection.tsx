import { useState } from "react";
import { Link } from "react-router-dom";
import clsx from "clsx";
import { ChartShell, Pill, Tooltip } from "@/components/primitives";
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
export function ConnectedToolsSection() {
  const status = useApi<ToolsStatusResponse>("/api/tools/status");
  const rows = status.data?.tools ?? [];
  const detected = rows.filter((r) => r.detected || r.action_count > 0);
  const others = rows.filter((r) => !r.detected && r.action_count === 0);

  return (
    <ChartShell
      title="Connected tools"
      sub="Every AI tool observer can capture, with its live integration state. Detection = the tool's storage directory exists on this machine; capturing = rows in this observer's database."
    >
      <ChartState
        loading={status.loading}
        error={status.error}
        empty={!status.loading && rows.length === 0}
        emptyHint="No tool catalog - daemon restart may be required after upgrading."
      >
        <ToolsTable rows={detected} onChanged={status.reload} />
        {others.length > 0 && (
          <details className="mt-3">
            <summary className="cursor-pointer text-[11.5px] text-fg-3 hover:text-fg-2">
              {others.length} supported tools not detected on this machine
            </summary>
            <div className="mt-2">
              <ToolsTable rows={others} onChanged={status.reload} />
            </div>
          </details>
        )}
        <div className="mt-3 flex flex-wrap items-center gap-3 border-t border-line-1 pt-3 text-[11px] text-fg-3">
          <button
            type="button"
            onClick={status.reload}
            className="rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-[11px] text-fg-2 hover:bg-bg-3"
          >
            Refresh
          </button>
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
  onChanged,
}: {
  rows: ToolStatusRow[];
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
    <table className="w-full border-collapse text-[11.5px]">
      <thead>
        <tr className="text-left text-[10px] uppercase tracking-[0.06em] text-fg-3">
          <th className="pb-1.5 pr-3 font-semibold">Tool</th>
          <th className="pb-1.5 pr-3 font-semibold">Detected</th>
          <th className="pb-1.5 pr-3 font-semibold">Capturing</th>
          <th className="pb-1.5 pr-3 font-semibold">Hooks</th>
          <th className="pb-1.5 pr-3 font-semibold">MCP</th>
          <th className="pb-1.5 pr-3 font-semibold">Proxied</th>
          <th className="pb-1.5 font-semibold"></th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <ToolRow
            key={r.tool}
            row={r}
            wizardOpen={openWizard === r.tool}
            onToggleWizard={() =>
              setOpenWizard(openWizard === r.tool ? null : r.tool)
            }
            onChanged={onChanged}
          />
        ))}
      </tbody>
    </table>
  );
}

function ToolRow({
  row: r,
  wizardOpen,
  onToggleWizard,
  onChanged,
}: {
  row: ToolStatusRow;
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
              className={clsx(
                "cursor-help font-mono",
                r.detected || r.action_count > 0 ? "text-fg-1" : "text-fg-3",
              )}
            >
              {r.tool}
            </span>
          </Tooltip>
          {!r.enabled && (
            <span className="ml-2 text-[10px] uppercase tracking-[0.05em] text-fg-4">
              adapter off
            </span>
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
              <button
                type="button"
                onClick={onToggleWizard}
                className={clsx(
                  "rounded-2 border px-2.5 py-1 text-[11px]",
                  wizardOpen
                    ? "border-accent/40 bg-accent-soft text-accent"
                    : "border-line-2 bg-bg-2 text-fg-2 hover:bg-bg-3",
                )}
              >
                {wizardOpen ? "Close" : "Set up"}
              </button>
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
    <button
      type="button"
      onClick={run}
      disabled={busy}
      className="rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-[11px] text-fg-2 hover:bg-bg-3 disabled:opacity-50"
    >
      {busy ? "Launching…" : "Launch"}
    </button>
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
        <button
          type="button"
          onClick={onDismiss}
          className="ml-auto text-[11px] text-fg-4 hover:text-fg-2"
        >
          Dismiss
        </button>
      </div>
      {r.command && (
        <div className="mt-1.5 flex items-center gap-2">
          <code className="select-all rounded-2 bg-bg-1 px-2 py-1 font-mono text-fg-1">
            {r.command}
          </code>
          <button
            type="button"
            onClick={copy}
            className="rounded-2 border border-line-2 bg-bg-2 px-2 py-0.5 text-[11px] text-fg-2 hover:bg-bg-3"
          >
            {copied ? "Copied" : "Copy"}
          </button>
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
