import { useEffect, useRef, useState } from "react";
import { vocabView, type VocabTable } from "@shared/lib/vocabEntry";
import { VocabPill } from "@shared/lib/vocabPill";
import { Icon, Pill } from "@/components/primitives";
import { agentStatusMotion } from "@/lib/liveSignals";

// useTerminalStatuses subscribes ONCE to the multiplexed agent-status stream
// (GET /ws/terminal/status, F4) and returns a map of PTY handle → fused status.
// The status is HEURISTIC + fused (PTY activity + OSC hints + lifecycle) — the
// UI surfaces it with its confidence and never as certainty. A dashboard
// without the status seam (WS closes immediately) simply yields an empty map.

export type AgentStatusInfo = {
  handle: string;
  run_id?: string;
  status:
    | "working"
    | "waiting-for-input"
    | "blocked"
    | "idle"
    | "exited"
    | "unknown";
  evidence: string;
  confidence: "trusted" | "hint" | "none";
  age_seconds: number;
};

export function useTerminalStatuses(): Record<string, AgentStatusInfo> {
  const [statuses, setStatuses] = useState<Record<string, AgentStatusInfo>>({});
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let disposed = false;
    let retry: ReturnType<typeof setTimeout> | null = null;

    const connect = () => {
      if (disposed) return;
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(
        `${proto}://${window.location.host}/ws/terminal/status`,
      );
      wsRef.current = ws;
      ws.onmessage = (ev: MessageEvent) => {
        try {
          const s = JSON.parse(ev.data as string) as AgentStatusInfo;
          if (!s.handle) return;
          setStatuses((prev) => ({ ...prev, [s.handle]: s }));
        } catch {
          /* ignore malformed frame */
        }
      };
      ws.onclose = () => {
        wsRef.current = null;
        // Reconnect with a gentle backoff (the seam may be briefly down on
        // dashboard restart); a permanently-disabled seam just keeps retrying
        // harmlessly at a low rate.
        if (!disposed) retry = setTimeout(connect, 5000);
      };
      ws.onerror = () => {
        try {
          ws.close();
        } catch {
          /* ignore */
        }
      };
    };
    connect();

    return () => {
      disposed = true;
      if (retry) clearTimeout(retry);
      try {
        wsRef.current?.close();
      } catch {
        /* ignore */
      }
    };
  }, []);

  return statuses;
}

// AGENT_STATUS - the ONE presentation row per fused agent status (tone +
// label); working is in flight (spins). Glyph from
// VOCAB_ICONS.terminalAgentStatus.
const AGENT_STATUS: VocabTable = {
  working: { tone: "success", spin: true },
  "waiting-for-input": { tone: "warn", label: "waiting" },
  blocked: { tone: "danger" },
  idle: { tone: "neutral" },
  exited: { tone: "neutral" },
  unknown: { tone: "neutral" },
};

// AgentStatusBadge renders one fused status compactly. Low-confidence and
// "unknown" states are visually muted so a hint never reads as a fact.
// `inControl` drops the badge's own focusable tooltip when it sits inside a
// button (the dock tab), whose own tooltip already describes the terminal.
//
// Motion comes from AGENT_STATUS_MOTION (lib/liveSignals): working spins its
// LoaderCircle (the table's spin flag), waiting-for-input blinks its Keyboard
// glyph like a caret, blocked is a static OctagonAlert.
export function AgentStatusBadge({ info, inControl }: { info?: AgentStatusInfo; inControl?: boolean }) {
  if (!info || info.status === "exited") return null;
  const title =
    info.evidence +
    (info.confidence !== "trusted" ? ` (${info.confidence})` : "");
  const className = info.confidence !== "trusted" ? "opacity-80" : undefined;
  if (agentStatusMotion(info.status) === "blink") {
    // The pill's own icon slot only spins, so a blinking glyph rides in the
    // children (same 11px size and gap as the icon slot).
    const v = vocabView("terminalAgentStatus", AGENT_STATUS, info.status);
    return (
      <Pill variant={v.tone} title={inControl ? undefined : title} className={className}>
        <Icon icon={v.icon} size={11} className="sb-caret shrink-0" />
        {v.label}
      </Pill>
    );
  }
  return (
    <VocabPill
      vocab="terminalAgentStatus"
      table={AGENT_STATUS}
      value={info.status}
      title={inControl ? undefined : title}
      className={className}
    />
  );
}
