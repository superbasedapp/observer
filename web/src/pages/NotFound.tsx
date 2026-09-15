import { Link, useLocation } from "react-router-dom";
import { Obs } from "@/components/Obs";

// NotFound — delight moment D-6 (usability arc P5.6 / review §9.3):
// the SPA's unknown-route page. Previously the catch-all silently
// redirected to Overview, which made a mistyped or stale URL look
// like a navigation bug. Now it says what happened.
//
// Register (§9.1/§9.4): Obs "lost" frame + ONE ▸ transition chip at
// chip size; body copy stays calm; the "Press B" line is the arcade
// quoted, with B being a real button so the joke and the affordance
// are the same element. Zero data, zero polling.
export function NotFoundPage() {
  const { pathname } = useLocation();
  return (
    <div className="flex h-full items-center justify-center p-12">
      <div className="flex max-w-md flex-col items-center text-center">
        <Obs state="lost" size={56} />
        <span className="mt-4 rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 font-mono text-[10.5px] tracking-[0.12em] text-fg-3">
          ▸ AREA UNKNOWN
        </span>
        <p className="mt-3 text-[13px] text-fg-2">
          There's nothing at{" "}
          <code className="break-all font-mono text-[12px] text-fg-1">
            {pathname}
          </code>
          .
        </p>
        <p className="mt-4 flex items-center gap-2 text-[12px] text-fg-3">
          Press
          <button
            type="button"
            onClick={() => window.history.back()}
            className="rounded-2 border border-accent/40 bg-accent-soft px-2.5 py-0.5 font-mono text-[11.5px] font-semibold text-accent hover:opacity-90"
            aria-label="Go back"
          >
            B
          </button>
          to go back - or head to the{" "}
          <Link to="/" className="font-medium text-accent hover:underline">
            Overview
          </Link>
          .
        </p>
      </div>
    </div>
  );
}
