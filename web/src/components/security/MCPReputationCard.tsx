import { useState } from "react";
import { PackageSearch } from "lucide-react";
import { Button, ChartShell, Pill, SinglePicker } from "@/components/primitives";
import { keepSelected } from "@/lib/pickerOptions";
import { useMCPPackageOptions } from "@/lib/usePickerSources";
import { TitleWithHelp } from "@/components/HelpInd";
import { useApi } from "@/lib/useApi";
import { fetchJSON, localConfirmHeaders } from "@/lib/api";
import { errorNote, type ErrorNote } from "@/lib/needsSetting";
import { ApiErrorNotice } from "@/components/NeedsSettingNotice";
import {
  optInLine,
  validPackageName,
  type MCPReputationResult,
  type MCPReputationStatus,
} from "@/lib/mcpReputation";

// MCPReputationCard is `observer guard mcp reputation <package>` on the
// Security page's MCP tab (T-496): npm-registry metadata for an MCP server
// package before you trust it. The server runs the same lookup the CLI runs
// (notify.LookupNPMReputation): off until Reputation lookups are turned on in
// the Network features card above it (GuardCloudCard, B-G5), one outbound
// request per lookup, nothing automatic.
export function MCPReputationCard() {
  const status = useApi<MCPReputationStatus>("/api/guard/mcp/reputation");
  const [pkg, setPkg] = useState("");
  // D-571: the packages the configured MCP servers run are offered first.
  const packages = useMCPPackageOptions();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ErrorNote | null>(null);
  const [res, setRes] = useState<MCPReputationResult | null>(null);

  const st = status.data;
  const offLine = st ? optInLine(st) : "";

  async function lookup(e: React.FormEvent) {
    e.preventDefault();
    if (!validPackageName(pkg)) return;
    setBusy(true);
    setError(null);
    setRes(null);
    try {
      setRes(
        await fetchJSON<MCPReputationResult>("/api/guard/mcp/reputation", undefined, {
          method: "POST",
          headers: await localConfirmHeaders(),
          body: JSON.stringify({ package: pkg.trim() }),
        }),
      );
    } catch (err) {
      setError(errorNote(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <ChartShell
      title={<TitleWithHelp text="MCP package reputation" helpId="card.security_mcp_reputation" />}
      icon={PackageSearch}
      sub="Look up an MCP server's npm package before you trust it: latest version, age, maintainers. Each lookup is one request to the npm registry, only when you ask."
    >
      {status.loading && !st ? null : offLine ? (
        <p className="m-0 mb-3 text-[11.5px] text-fg-3" data-testid="mcp-reputation-off">
          <Pill variant="neutral" case="none" className="mr-2">
            off
          </Pill>
          {offLine}
        </p>
      ) : null}
      <form className="flex flex-col gap-2 sm:flex-row" onSubmit={(e) => void lookup(e)}>
        <SinglePicker
          className="min-w-0 flex-1"
          ariaLabel="npm package name"
          placeholder="@modelcontextprotocol/server-filesystem"
          options={keepSelected(packages.options, pkg ? [pkg] : [])}
          value={pkg}
          allowFree
          freeLabel="Look up"
          loading={packages.loading}
          emptyHint="No configured MCP server runs an npm package; type a package name."
          notice="Packages your configured MCP servers run"
          disabled={!st?.available}
          onChange={(v) => setPkg(v.slice(0, 214))}
        />
        <Button
          type="submit"
          size="sm"
          variant="primary"
          iconLeft={PackageSearch}
          loading={busy}
          disabled={!st?.available || !validPackageName(pkg)}
        >
          Look up
        </Button>
      </form>
      <ApiErrorNotice note={error} className="mt-2" plainClassName="mt-2 text-[11.5px] text-danger" />
      {res && (
        <div className="mt-3 space-y-1.5 rounded-2 border border-line-2 bg-bg-3 p-3 text-[11.5px]" aria-live="polite">
          {res.young && res.warning && (
            <div className="flex flex-wrap items-center gap-2">
              <Pill variant="warn" case="none">
                new package
              </Pill>
              <span className="text-warn">{res.warning}</span>
            </div>
          )}
          <pre className="m-0 overflow-x-auto whitespace-pre-wrap break-words font-mono text-[11px] text-fg-2">
            {res.lines.join("\n")}
          </pre>
        </div>
      )}
    </ChartShell>
  );
}
