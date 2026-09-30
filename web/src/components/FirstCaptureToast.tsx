import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Obs } from "@/components/Obs";
import { useApi } from "@/lib/useApi";
import type { StatusSnapshot } from "@/lib/types";
import { Icon } from "@/components/primitives";
import { X } from "lucide-react";

// FirstCaptureToast — delight moment D-2 (usability arc P5.1 / §9.3):
// when the sessions count is OBSERVED going 0→1 while the dashboard is
// open, one corner toast with the brand's celebration (Obs jump-pulse,
// teal→gold). Restraint rules §9.4: fires ONCE EVER (node-local
// flag), dismissable, never interrupts (passive corner card, no
// focus steal, no sound, no confetti); installs that already have
// sessions mark the flag silently and never see it.

const KEY = "sb_first_capture_seen";

function seen(): boolean {
  try {
    return localStorage.getItem(KEY) === "1";
  } catch {
    return true; // no storage = no way to fire once = don't fire
  }
}

function markSeen() {
  try {
    localStorage.setItem(KEY, "1");
  } catch {
    // ignore
  }
}

export function FirstCaptureToast() {
  const [armed, setArmed] = useState(false); // we observed zero sessions
  const [show, setShow] = useState(false);
  const done = useRef(seen());

  // Poll only while the moment can still happen: flag unseen AND
  // either we haven't observed a count yet or we're armed at zero.
  // Steady-state installs cost zero traffic (flag set on first look).
  //
  // The toast trails the actual first capture by up to one poll interval
  // plus the daemon's ~15s /api/status memoization — call it half a minute
  // in the worst case. That is fine for a celebration and is why the copy
  // says "first capture", never "just now": nothing here is a live tick.
  const status = useApi<StatusSnapshot>(
    done.current || show ? null : "/api/status",
    undefined,
    [armed, show],
    { refreshMs: 15000 },
  );

  useEffect(() => {
    if (done.current || show) return;
    const count = status.data?.counts?.sessions;
    if (count == null) return;
    if (count === 0) {
      setArmed(true);
      return;
    }
    // count >= 1: if we never saw zero this lifetime, this is an
    // existing install — retire silently. If we armed at zero, this
    // is THE moment.
    if (armed) {
      setShow(true);
    }
    done.current = true;
    markSeen();
  }, [status.data, armed, show]);

  if (!show) return null;
  return (
    <div className="fixed bottom-5 right-5 z-50 flex items-center gap-3 rounded-3 border border-line-2 bg-bg-2 px-4 py-3 shadow-3">
      <Obs state="jump" size={36} />
      <div className="text-[12px]">
        <div className="font-semibold text-fg-1">First session captured.</div>
        <Link
          to="/sessions"
          onClick={() => setShow(false)}
          className="text-accent hover:underline"
        >
          See it on the board
        </Link>
      </div>
      <button
        type="button"
        onClick={() => setShow(false)}
        className="ml-2 self-start text-[11px] text-fg-4 hover:text-fg-2"
        aria-label="Dismiss"
      >
        <Icon icon={X} size="xs" />
      </button>
    </div>
  );
}
