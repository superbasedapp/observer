import { useState } from "react";
import { Link } from "react-router-dom";
import { Obs } from "@/components/Obs";
import { useApi } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";

// OnboardingCard — F1 + delight moment D-1 (usability arc P5.1):
// the empty-DB Overview's first-run checklist. Replaces the dead-end
// ("no data") first minute with the three steps that get a session on
// the board, each linking to the dashboard control that does it — no
// terminal required (the arc's Phase-1/4 buttons are the steps).
//
// Restraint rules §9.4: shows only while the DB has zero sessions,
// permanently dismissable (node-local flag), Obs idle cameo + ONE
// pixel-chip accent (the ▸ chip carries the arcade register at chip
// size; body copy stays calm), reduced-motion handled inside Obs.

const KEY = "sb_onboarding_dismissed";

function dismissed(): boolean {
  try {
    return localStorage.getItem(KEY) === "1";
  } catch {
    return false;
  }
}

export function OnboardingCard({ sessions }: { sessions: number | null }) {
  const [hidden, setHidden] = useState(dismissed);
  // Demo-mode offer (P6.7): only rendered when the server can seed.
  // While demo is active sessions > 0, so this card is gone anyway.
  const demo = useApi<{ available: boolean; active: boolean }>("/api/demo");
  const [seeding, setSeeding] = useState(false);
  if (hidden || sessions == null || sessions > 0) return null;
  const dismiss = () => {
    try {
      localStorage.setItem(KEY, "1");
    } catch {
      // ignore
    }
    setHidden(true);
  };
  const startDemo = async () => {
    setSeeding(true);
    try {
      await fetchJSON("/api/demo/start", undefined, { method: "POST" });
      window.location.reload();
    } catch {
      setSeeding(false);
    }
  };
  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 p-5">
      <div className="flex items-start gap-4">
        <Obs state="idle" size={44} />
        <div className="min-w-0 flex-1">
          <h2 className="text-[14px] font-semibold text-fg-0">
            Welcome. Let's get your first session on the board.
          </h2>
          <p className="mt-1 text-[12px] text-fg-3">
            SuperBased captures what your AI coding tools actually do - once a
            tool is wired, sessions, costs, and cache behavior appear here on
            their own.
          </p>
          <ol className="mt-3 space-y-2 text-[12px] text-fg-2">
            <li className="flex items-baseline gap-2">
              <span className="font-mono text-[10.5px] text-fg-4">1</span>
              <span>
                <Link
                  to="/settings?section=tools"
                  className="font-medium text-accent hover:underline"
                >
                  Check your connected tools
                </Link>{" "}
                - see what's detected on this machine and run the per-tool
                setup wizard (every write previews first).
              </span>
            </li>
            <li className="flex items-baseline gap-2">
              <span className="font-mono text-[10.5px] text-fg-4">2</span>
              <span>
                <Link
                  to="/compression"
                  className="font-medium text-accent hover:underline"
                >
                  Route Claude Code / Codex through the proxy
                </Link>{" "}
                - one click, durable, unlocks exact token accounting and
                compression. Optional but worth it.
              </span>
            </li>
            <li className="flex items-baseline gap-2">
              <span className="font-mono text-[10.5px] text-fg-4">3</span>
              <span>
                Use your AI tool like you normally would - the first session
                shows up here the moment it lands.
              </span>
            </li>
          </ol>
          <div className="mt-3 flex items-center gap-3">
            <Link
              to="/settings?section=tools"
              className="rounded-2 border border-accent/40 bg-accent-soft px-3 py-1.5 text-[11.5px] font-semibold text-accent hover:opacity-90"
            >
              <span className="font-mono tracking-[0.08em]">▸ PRESS START</span>
            </Link>
            <span className="text-[11px] text-fg-4">
              CLI twin: <code className="font-mono">observer init</code>
            </span>
          </div>
          {demo.data?.available && !demo.data.active && (
            <p className="mt-3 border-t border-line-2 pt-3 text-[11.5px] text-fg-3">
              Just looking around?{" "}
              <button
                type="button"
                onClick={startDemo}
                disabled={seeding}
                className="font-medium text-accent hover:underline disabled:opacity-60"
              >
                {seeding ? "seeding…" : "Explore with demo data"}
              </button>{" "}
              - a seeded sample in a temporary database. Your real data stays
              untouched; one click clears it.
            </p>
          )}
        </div>
        <button
          type="button"
          onClick={dismiss}
          className="shrink-0 text-[11px] text-fg-4 hover:text-fg-2"
          aria-label="Dismiss welcome"
        >
          ✕
        </button>
      </div>
    </section>
  );
}
