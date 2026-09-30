import { MCPCallsPanel } from "@shared/components/sessiondetail/MCPCallsPanel";
import type { SessionMCPCallsLike } from "@shared/lib/mcpCalls";
import { useApi } from "@/lib/useApi";
import { Tooltip } from "@/components/primitives";

// MCP calls tab (Agent Access P11(a)) - the session's MCP tool calls the node
// relay recorded, each tied to the action / turn / session it belongs to with
// an honest exact / inferred grade. GET /api/session/<id>/mcp-calls returns
// the SAME correlate.Result the org drawer renders, and both drawers render
// the SAME shared panel, so a call's link reads identically on the node and
// in the org. The tab mounts on first visit, so nothing is fetched until it
// is opened.
//
// onFocusMessage jumps to the matched message on the Messages tab (the
// shell's cross-tab handler, the Processes-panel precedent).
export function MCPCallsTab({
  sessionId,
  onFocusMessage,
}: {
  sessionId: string | null;
  onFocusMessage?: (messageId: string) => void;
}) {
  const calls = useApi<SessionMCPCallsLike>(sessionId ? `/api/session/${sessionId}/mcp-calls` : null, undefined, [
    sessionId,
  ]);
  const renderMessageLink = onFocusMessage
    ? (id: string) => (
        <Tooltip content={`Jump to the message this call belongs to (${id})`}>
          <button
            type="button"
            onClick={() => onFocusMessage(id)}
            className="font-mono text-caption text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
          >
            message {id}
          </button>
        </Tooltip>
      )
    : undefined;
  return (
    <div className="mt-5">
      <MCPCallsPanel
        result={calls.data}
        loading={calls.loading}
        error={calls.error ? calls.error.message : null}
        denied={calls.denied}
        deniedPermission={calls.deniedPermission}
        renderMessageLink={renderMessageLink}
      />
    </div>
  );
}
