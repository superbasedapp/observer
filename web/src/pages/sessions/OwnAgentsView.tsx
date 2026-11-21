// Own agents view (P-228, docs/own-agents.md): the Sessions page's third
// view. Lists every agent the developer built on a raw provider API or SDK
// and pointed at the node proxy with X-Superbased-Agent, or that sends its
// own OpenTelemetry spans with the sbo.agent resource attribute (PT-55),
// grouped by agent name (custom-agent sessions, surface_host
// "agent:<name>"). The Via column is the only place the two paths differ. Picking an
// agent filters the Sessions table to its sessions. With no agent yet the
// view shows the setup snippet instead of an empty table, so the page is
// never a dead end.
import { useState } from "react";
import { GatedLink } from "@/components/GatedLink";
import { ChartState } from "@/components/ChartState";
import { CopyOnClick } from "@/components/CopyOnClick";
import { SegmentedControl, Table } from "@/components/primitives";
import { fmtCost, fmtDateTime, fmtInt } from "@/lib/format";
import { useApi } from "@/lib/useApi";
import { ownAgentSnippet, snippetBase, SNIPPET_LANGS, viaLabel, type SnippetLang } from "@/lib/ownAgents";

export type OwnAgentRow = {
  agent: string;
  surface_host: string;
  sessions: number;
  turns: number;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  last_seen: string;
  /** Which capture path saw the agent: "proxy", "otlp" or "proxy+otlp". */
  via?: string;
};

export type OwnAgentsResponse = {
  agents: OwnAgentRow[];
  proxy_base_url: string;
  agent_header: string;
  session_header: string;
  tool: string;
  /** The node wants the proxy client token (the token is never sent). */
  client_auth?: boolean;
  /** Where that token lives ([proxy].client_token_file); the path only. */
  client_token_file?: string;
  /** The OpenTelemetry resource attribute that names an agent (sbo.agent). */
  agent_attr?: string;
};

export function OwnAgentsView({ onPick }: { onPick: (row: OwnAgentRow) => void }) {
  const res = useApi<OwnAgentsResponse>("/api/own-agents", {}, [], { refreshMs: 30000 });
  const agents = res.data?.agents ?? [];
  const loaded = !!res.data;
  return (
    <div className="space-y-4">
      <ChartState
        loading={res.loading && !res.data}
        error={res.error}
        denied={res.denied}
        deniedPermission={res.deniedPermission}
        empty={false}
        height={160}
      >
        {agents.length > 0 && (
          <Table
            minWidth={640}
            zebra
            head={
              <tr>
                <th className="px-2 py-1.5 text-left">Agent</th>
                <th className="px-2 py-1.5 text-left">Via</th>
                <th className="px-2 py-1.5 text-right">Sessions</th>
                <th className="px-2 py-1.5 text-right">Turns</th>
                <th className="px-2 py-1.5 text-right">Input</th>
                <th className="px-2 py-1.5 text-right">Output</th>
                <th className="px-2 py-1.5 text-right">Cost</th>
                <th className="px-2 py-1.5 text-left">Last seen</th>
              </tr>
            }
          >
            {agents.map((a) => (
              <tr
                key={a.surface_host}
                className="cursor-pointer"
                onClick={() => onPick(a)}
                title={`Show ${a.agent}'s sessions`}
              >
                <td className="px-2 py-1.5 font-mono text-fg-0">{a.agent}</td>
                <td className="px-2 py-1.5 text-fg-2">{viaLabel(a.via)}</td>
                <td className="px-2 py-1.5 text-right tabular-nums">{fmtInt(a.sessions)}</td>
                <td className="px-2 py-1.5 text-right tabular-nums">{fmtInt(a.turns)}</td>
                <td className="px-2 py-1.5 text-right tabular-nums">{fmtInt(a.input_tokens)}</td>
                <td className="px-2 py-1.5 text-right tabular-nums">{fmtInt(a.output_tokens)}</td>
                <td className="px-2 py-1.5 text-right tabular-nums">{fmtCost(a.cost_usd, a.input_tokens + a.output_tokens)}</td>
                <td className="px-2 py-1.5 text-fg-2">{a.last_seen ? fmtDateTime(a.last_seen) : "-"}</td>
              </tr>
            ))}
          </Table>
        )}
      </ChartState>
      {loaded && res.data && <OwnAgentSetup data={res.data} first={agents.length === 0} />}
    </div>
  );
}

// OwnAgentSetup prints the base URL and the two headers for each language.
// It is the whole view while no agent exists, and a reminder below the
// table once one does.
function OwnAgentSetup({ data, first }: { data: OwnAgentsResponse; first: boolean }) {
  const [lang, setLang] = useState<SnippetLang>("curl");
  const facts = {
    baseURL: data.proxy_base_url,
    agentHeader: data.agent_header,
    sessionHeader: data.session_header,
    clientAuth: !!data.client_auth,
  };
  const snippet = ownAgentSnippet(lang, facts);
  return (
    <div className="rounded-3 border border-line-1 bg-bg-1 p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="text-[12.5px] font-medium text-fg-0">
            {first ? "No own agents yet: track one in two steps" : "Track another agent"}
          </div>
          <p className="mt-1 text-[11.5px] text-fg-2">
            Point your agent&apos;s provider base URL at the Observer proxy ({snippetBase(facts)}) and send{" "}
            <code className="font-mono">{data.agent_header}</code> with a name. Add{" "}
            <code className="font-mono">{data.session_header}</code> to group calls into one session; without it, calls
            less than 30 minutes apart share a session. Anthropic, OpenAI and Gemini clients work; AWS Bedrock does not.
          </p>
          {data.agent_attr && (
            <p className="mt-1 text-[11.5px] text-fg-2">
              An agent traced with OpenTelemetry can send its spans instead of (or as well as) using the proxy: turn on
              this node&apos;s OTLP receiver (<code className="font-mono">[ingest.otel]</code>, under More settings in{" "}
              <GatedLink to="/settings?section=otel" managed="Settings > OTel export (managed by your organization)" className="text-accent hover:underline">
                Settings &gt; OTel export
              </GatedLink>
              ), export OTLP to it and set the resource attribute{" "}
              <code className="font-mono">{data.agent_attr}</code> to the agent&apos;s name (see the own agents guide).
            </p>
          )}
          {data.client_auth && (
            <p className="mt-1 text-[11.5px] text-fg-2">
              This node requires the proxy client token: replace <code className="font-mono">&lt;token&gt;</code> with
              the contents of the token file{" "}
              <code className="font-mono">{data.client_token_file || "~/.observer/proxy-client-token"}</code>{" "}
              (<code className="font-mono">[proxy].client_token_file</code>).{" "}
              <CopyOnClick
                value={data.client_token_file || "~/.observer/proxy-client-token"}
                ariaLabel="Copy the token file path"
              >
                <span className="rounded-2 border border-line-2 bg-bg-2 px-1.5 py-0.5 text-[10.5px] text-fg-2">
                  Copy path
                </span>
              </CopyOnClick>{" "}
              The dashboard shows the path, not the token: it never serves a stored credential over HTTP, so read
              the file on this machine.
            </p>
          )}
        </div>
        <SegmentedControl<SnippetLang> options={[...SNIPPET_LANGS]} value={lang} onChange={setLang} size="sm" />
      </div>
      <div className="relative">
        <pre className="m-0 max-h-80 overflow-auto whitespace-pre rounded-2 border border-line-1 bg-bg-3 p-2 font-mono text-[11px] text-fg-1">
          {snippet}
        </pre>
        <div className="absolute right-2 top-2">
          <CopyOnClick value={snippet} ariaLabel="Copy the setup snippet">
            <span className="rounded-2 border border-line-2 bg-bg-2 px-2 py-0.5 text-[10.5px] text-fg-2">Copy</span>
          </CopyOnClick>
        </div>
      </div>
    </div>
  );
}
