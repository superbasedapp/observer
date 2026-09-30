import { useMemo, useRef } from "react";
import { FloatingPanel } from "@/components/primitives/FloatingPanel";
import { Icon } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { toolMeta } from "@/lib/tools";
import {
  parseLinkError,
  shortId,
  terminalLinkPath,
  type TerminalSessionLink,
} from "@/lib/cockpit";
import { CockpitContent } from "./CockpitContent";
import { CircleDot } from "lucide-react";

// SessionCockpitPanel — the per-terminal floating "⊙ Session" cockpit. Wraps
// the FloatingPanel primitive and owns Phase-1 link resolution (terminal token
// → live session); CockpitContent owns Phase-2 per-section vitals + layout.
//
// Default-exported for React.lazy. Props are the FloatingPanel provider
// contract (z / cascade / onRaise / onClose) plus the opaque terminal `token`.
export default function SessionCockpitPanel({
  token,
  z,
  cascade,
  onRaise,
  onClose,
}: {
  token: string;
  z: number;
  cascade: number;
  onRaise: () => void;
  onClose: () => void;
}) {
  // Client mount instant — the honest elapsed floor before a session start
  // time is known (the link wire carries no launch timestamp).
  const mountMs = useRef<number>(Date.now()).current;

  // Phase 1: poll the link endpoint at 4s until correlated, then SLOW to 15s —
  // but NEVER fully stop while the panel is open. A first correlation can be a
  // weak (0.70 marker) match that a later authoritative (0.95 OOB) correlation
  // RE-POINTS to a different session; stopping at the first would freeze the
  // cockpit on the wrong session forever. useApi reads refreshMs each render,
  // so flipping the cadence is enough — the resolved link keeps updating and a
  // session_id change swaps every Phase-2 poll to the new id (see the keyed
  // CockpitContent below).
  // 4s while hunting for a correlation, 15s once we have one — read from a ref
  // set at the end of the render so the cadence follows the latest correlation
  // state without a dedicated state/effect (useApi re-arms its interval when
  // refreshMs changes). A weak first correlation can be re-pointed by a later
  // authoritative one, so we never drop to 0.
  const correlatedRef = useRef(false);
  const link = useApi<TerminalSessionLink>(
    terminalLinkPath(token),
    undefined,
    [token],
    { refreshMs: correlatedRef.current ? 15000 : 4000 },
  );
  const resolved = link.data ?? null;
  const correlated = Boolean(resolved?.correlated && resolved.session_id);
  correlatedRef.current = correlated;
  const linkError = useMemo(() => parseLinkError(link.error), [link.error]);

  const tool = resolved?.tool ?? "";
  const sessionId = resolved?.session_id ?? "";

  const subtitle = useMemo(() => {
    if (!tool) return undefined;
    const label = toolMeta(tool).label;
    return sessionId ? `${label} · ${shortId(sessionId)}` : `${label} · linking…`;
  }, [tool, sessionId]);

  return (
    <FloatingPanel
      storageKey="sb_session_cockpit_rect"
      z={z}
      cascade={cascade}
      onRaise={onRaise}
      onClose={onClose}
      title={
        <span className="inline-flex items-center gap-1.5">
          <Icon icon={CircleDot} size="sm" />
          Session
        </span>
      }
      ariaLabel={sessionId ? `Session cockpit ${shortId(sessionId)}` : "Session cockpit"}
      subtitle={subtitle}
    >
      {/* Key on the correlated session id: when a later correlation re-points
          the link to a DIFFERENT session, remounting resets every per-section
          useApi cleanly (no stale cost/tokens/procs bleed from the old id
          across the swap). Stable while uncorrelated so the waiting state
          doesn't churn on each poll. */}
      <CockpitContent
        key={sessionId || "uncorrelated"}
        link={resolved}
        linkError={linkError}
        linkLoading={link.loading && !resolved}
        mountMs={mountMs}
      />
    </FloatingPanel>
  );
}
