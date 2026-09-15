import { useEffect, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { PageHeader, Pill, ToolBadge, Tooltip } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { useApi } from "@/lib/useApi";
import { fmtDateTime, fmtDuration, fmtInt } from "@/lib/format";
import type { SearchResponse } from "@/lib/types";

// Global search (P6.2): the FTS5 index behind the MCP
// search_past_outputs tool, surfaced as a page. The query lives in
// ?q= so searches are linkable and survive reloads.
//
// Working surface — calm register, zero delight elements (§9.4).
export function SearchPage() {
  const [params, setParams] = useSearchParams();
  const urlQ = params.get("q") ?? "";
  const [input, setInput] = useState(urlQ);

  // Debounce: the URL (and thus the fetch) follows the input after
  // 300ms of quiet. Direct URL edits flow back into the input.
  useEffect(() => {
    const id = window.setTimeout(() => {
      if (input !== urlQ) {
        setParams(input ? { q: input } : {}, { replace: true });
      }
    }, 300);
    return () => window.clearTimeout(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [input]);
  useEffect(() => {
    setInput(urlQ);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [urlQ]);

  const results = useApi<SearchResponse>(
    urlQ ? "/api/search" : null,
    { q: urlQ, limit: 50 },
    [urlQ],
  );

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Search"
        sub="Full-text search over everything the observer captured - command outputs, test failures, error messages. The same index your AI tool queries through MCP's search_past_outputs."
        helpId="tab.search"
      />
      <input
        autoFocus
        type="search"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder='Search past outputs - try an error message, a file name, or FTS5 syntax like "app.set" OR "app.use"'
        className="w-full rounded-3 border border-line-2 bg-bg-2 px-4 py-2.5 text-[13px] text-fg-1 outline-none placeholder:text-fg-3 focus:border-accent/60 focus:ring-2 focus:ring-[var(--accent-ring)]"
      />
      {!urlQ ? (
        <div className="rounded-3 border border-line-2 bg-bg-2 p-8 text-center">
          <p className="text-[13px] text-fg-2">
            Type to search the output index.
          </p>
          <p className="mx-auto mt-2 max-w-lg text-[12px] leading-relaxed text-fg-3">
            Results come from the FTS5 excerpt index, filled as sessions are
            captured. If searches come back empty on a fresh install, the
            index may still be growing - it fills as new tool outputs land.
          </p>
        </div>
      ) : (
        <ChartState
          loading={results.loading}
          error={results.error}
          empty={false}
          emptyHint=""
        >
          {results.data && results.data.hits.length === 0 ? (
            <div className="rounded-3 border border-line-2 bg-bg-2 p-8 text-center">
              <p className="text-[13px] text-fg-2">
                No matches for <span className="font-mono">{urlQ}</span>.
              </p>
            </div>
          ) : results.data ? (
            <>
              <p className="text-[11px] text-fg-3">
                {fmtInt(results.data.count)} match
                {results.data.count === 1 ? "" : "es"}, most relevant first
              </p>
              <ul className="space-y-2">
                {results.data.hits.map((h) => (
                  <SearchHitRow key={h.action_id} h={h} />
                ))}
              </ul>
            </>
          ) : null}
        </ChartState>
      )}
    </div>
  );
}

function SearchHitRow({ h }: { h: SearchResponse["hits"][number] }) {
  return (
    <li className="rounded-3 border border-line-2 bg-bg-2 p-3">
      <div className="flex items-center gap-2">
        {h.tool && <ToolBadge tool={h.tool} />}
        {h.tool_name && <Pill>{h.tool_name}</Pill>}
        <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-fg-2">
          {h.target}
        </span>
        {h.timestamp && (
          <Tooltip content={fmtDateTime(h.timestamp)}>
            <span
              tabIndex={0}
              className="shrink-0 cursor-help text-[10.5px] tabular-nums text-fg-3 focus:outline-none"
            >
              {relTime(h.timestamp)}
            </span>
          </Tooltip>
        )}
        {h.session_id && (
          <Link
            to={`/sessions?session=${encodeURIComponent(h.session_id)}`}
            className="shrink-0 text-[11px] font-medium text-accent hover:text-accent-strong"
          >
            Session →
          </Link>
        )}
      </div>
      <p className="mt-2 whitespace-pre-wrap break-words font-mono text-[11.5px] leading-relaxed text-fg-2">
        {renderSnippet(h.snippet)}
      </p>
      {h.error_message && (
        <p className="mt-1 truncate font-mono text-[10.5px] text-danger">
          {h.error_message}
        </p>
      )}
    </li>
  );
}

// renderSnippet maps the server's sentinel marks (\x01 … \x02) onto
// <mark> elements. The snippet is plain text by construction — the
// sentinels are the only markup channel, so stored output can never
// inject styling or tags.
function renderSnippet(snippet?: string): ReactNode {
  if (!snippet) return null;
  const parts: ReactNode[] = [];
  let rest = snippet;
  let key = 0;
  while (rest.length > 0) {
    const start = rest.indexOf("\x01");
    if (start === -1) {
      parts.push(rest);
      break;
    }
    const end = rest.indexOf("\x02", start + 1);
    if (end === -1) {
      parts.push(rest.replaceAll("\x01", ""));
      break;
    }
    if (start > 0) parts.push(rest.slice(0, start));
    parts.push(
      <mark
        key={key++}
        className="rounded-[2px] bg-accent-soft px-0.5 text-accent"
      >
        {rest.slice(start + 1, end)}
      </mark>,
    );
    rest = rest.slice(end + 1);
  }
  return parts;
}

function relTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "-";
  const diff = Date.now() - t;
  if (diff < 0) return "now";
  return `${fmtDuration(diff)} ago`;
}
