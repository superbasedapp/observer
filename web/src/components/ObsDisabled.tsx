import type { ReactNode } from "react";
import { EmptyState } from "@/components/primitives";

// ObsDisabled: the page-level "observability is off" state for the pages
// whose /api/obs/* routes are registered only when [observability] is
// enabled (Egress, Policies). It names the exact gate to flip; each page
// passes its own lead sentence and the TOML block it needs. One component
// so the two pages cannot drift (each held its own copy before 2026-09-28).
export function ObsDisabled({
  children,
  toml = "[observability]\nenabled = true",
}: {
  /** Why this page needs the observability subsystem (one sentence). */
  children: ReactNode;
  /** The config.toml block that turns the dependency on. */
  toml?: string;
}) {
  return (
    <EmptyState illustration="connect" title="Observability is off">
      <div className="mx-auto max-w-xl text-small leading-relaxed text-fg-3">
        <p>
          {children} Enable it in{" "}
          <code className="rounded-1 bg-bg-2 px-1 font-mono">~/.observer/config.toml</code>:
        </p>
        <pre className="mt-2 inline-block rounded-2 bg-bg-2 px-3 py-2 text-left font-mono text-caption text-fg-2">
          {toml}
        </pre>
        <p className="mt-2">then restart the daemon.</p>
      </div>
    </EmptyState>
  );
}
