import { useEffect, useState } from "react";
import { Obs } from "@/components/Obs";
import { Icon } from "@/components/primitives";
import { X } from "lucide-react";

// KonamiEgg — delight moment D-7 (usability arc P6.11 / §9.3):
// ↑ ↑ ↓ ↓ ← → ← → B A anywhere in the dashboard → Obs runs once
// across the footer and a corner toast links to the arcade. The
// purest "hey, that's nice": invisible until earned.
//
// Restraint rules §9.4 (binding): fires ONCE EVER (node-local flag —
// no recurring cheer, even on re-entry); no sound, no confetti (the
// sprite pulse is the celebration); prefers-reduced-motion skips the
// footer run and shows the static toast only; never gates or
// interrupts (passive overlay, no focus steal); key tracking ignores
// editable targets so working surfaces stay untouched.

const KEY = "sb_konami_seen";

const SEQUENCE = [
  "ArrowUp",
  "ArrowUp",
  "ArrowDown",
  "ArrowDown",
  "ArrowLeft",
  "ArrowRight",
  "ArrowLeft",
  "ArrowRight",
  "KeyB",
  "KeyA",
];

function seen(): boolean {
  try {
    return localStorage.getItem(KEY) === "1";
  } catch {
    return true; // no storage = no once-only guarantee = stay quiet
  }
}

function markSeen() {
  try {
    localStorage.setItem(KEY, "1");
  } catch {
    // ignore
  }
}

function isEditable(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || target.isContentEditable;
}

export function KonamiEgg() {
  const [fired, setFired] = useState(false);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    if (seen()) return;
    let progress = 0;
    const onKey = (e: KeyboardEvent) => {
      if (isEditable(e.target)) {
        progress = 0;
        return;
      }
      progress = e.code === SEQUENCE[progress] ? progress + 1 : e.code === SEQUENCE[0] ? 1 : 0;
      if (progress < SEQUENCE.length) return;
      window.removeEventListener("keydown", onKey);
      markSeen();
      setFired(true);
      const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      if (!reduced) {
        setRunning(true);
        // The run lasts 4s; the toast stays until dismissed.
        window.setTimeout(() => setRunning(false), 4200);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (!fired) return null;
  return (
    <>
      {running && (
        <div className="pointer-events-none fixed inset-x-0 bottom-0 z-50 h-12 overflow-hidden">
          <style>{`
            @keyframes sb-konami-run {
              from { transform: translateX(-48px); }
              to { transform: translateX(100vw); }
            }
          `}</style>
          <div
            className="absolute bottom-1"
            style={{ animation: "sb-konami-run 4s linear forwards" }}
          >
            <Obs state="jump" size={32} />
          </div>
        </div>
      )}
      <div className="fixed bottom-5 right-5 z-50 flex items-center gap-3 rounded-3 border border-line-2 bg-bg-2 px-4 py-3 shadow-3">
        <Obs state="jump" size={36} />
        <div className="text-[12px]">
          <div className="font-mono text-[10.5px] tracking-[0.08em] text-accent">
            ★ YOU FOUND THE ARCADE ★
          </div>
          <a
            href="https://superbased.app/arcade"
            target="_blank"
            rel="noopener noreferrer"
            className="text-accent hover:underline"
            onClick={() => setFired(false)}
          >
            superbased.app/arcade
          </a>
        </div>
        <button
          type="button"
          onClick={() => setFired(false)}
          className="ml-2 self-start text-[11px] text-fg-4 hover:text-fg-2"
          aria-label="Dismiss"
        >
          <Icon icon={X} size="xs" />
        </button>
      </div>
    </>
  );
}
