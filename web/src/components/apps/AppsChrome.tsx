// AppsChrome - the pieces every "Your apps" page shares (Plane A lane B5,
// plan W2-5, D17): the time window, the gate that shows the first-run card
// until the /api/obs routes answer, and the "needs a newer daemon" state for
// a route another lane ships (B7 scores, B8 prompts, B9 alerts). Each page
// file renders its own PageHeader (nav.test.ts pins icon={navIcon(...)}).

import type { ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { Callout, EmptyState, ErrorState, InlineLoading, SegmentedControl } from "@/components/primitives";
import { APP_WINDOWS, routeMissing } from "@/lib/planeaApi";
import { receiverNotice, type OTLPReceiverState } from "@/lib/planeaFirstRun";
import { useApi } from "@/lib/useApi";
import { AppsFirstRunCard, useObsRoutesUp } from "./AppsFirstRunCard";

/** useAppsWindow reads ?days= (one of APP_WINDOWS, default 30). */
export function useAppsWindow(): [number, (d: number) => void] {
  const [sp, setSp] = useSearchParams();
  const raw = Number(sp.get("days"));
  const days = (APP_WINDOWS as readonly number[]).includes(raw) ? raw : 30;
  return [
    days,
    (d: number) => {
      const next = new URLSearchParams(sp);
      next.set("days", String(d));
      setSp(next, { replace: true });
    },
  ];
}

/** APPS_HEADER_CLASS stacks a page header's right slot (the WindowPicker,
 *  a New button) under the title below sm. Side by side at 375 px the
 *  subtitle was squeezed into a column a few words wide (U-32). */
export const APPS_HEADER_CLASS = "flex-col sm:flex-row";

/** WindowPicker is the page header's window control. */
export function WindowPicker({ days, onChange }: { days: number; onChange: (d: number) => void }) {
  return (
    <SegmentedControl
      options={APP_WINDOWS.map((d) => ({ value: String(d), label: d === 1 ? "Today" : `${d}d` }))}
      value={String(days)}
      onChange={(v) => onChange(Number(v))}
    />
  );
}

/** AppsGate renders the page body once the Your apps routes answer, and
 *  the first-run card (turn it on, the SDK snippet) until then. */
export function AppsGate({ children }: { children: ReactNode }) {
  const up = useObsRoutesUp();
  if (up === null) return <InlineLoading label="Loading..." />;
  if (!up) return <AppsFirstRunCard variant="page" />;
  return (
    <>
      <ReceiverCallout />
      {children}
    </>
  );
}

/** ReceiverCallout says so when the local OTLP receiver could not open its
 *  port (review E-72): before it, only `observer doctor` did, and the pages
 *  just stayed empty. Renders nothing while the receiver listens or the
 *  daemon has recorded nothing (or is too old to answer). */
export function ReceiverCallout() {
  const r = useApi<OTLPReceiverState>("/api/sdk/receiver", undefined, [], { refreshMs: 60_000 });
  const n = receiverNotice(r.data);
  if (!n) return null;
  return (
    <div className="mb-4" data-testid="apps-receiver-callout">
      <Callout tone={n.tone} title={n.title}>
        {n.body}
      </Callout>
    </div>
  );
}

/** ReadState renders a read's failure: a route this daemon does not serve
 *  yet reads as "needs a newer superbased", any other failure as an error
 *  with a retry. Null when there is no error. */
export function ReadState({
  error,
  onRetry,
  feature,
}: {
  error: Error | null;
  onRetry: () => void;
  /** What the missing route would show ("Scores"). */
  feature: string;
}) {
  if (!error) return null;
  if (routeMissing(error)) {
    return (
      <EmptyState
        variant="inline"
        title={`${feature} needs a newer superbased`}
        body="This machine's daemon does not serve this view yet. Update superbased and restart the daemon."
      />
    );
  }
  return <ErrorState error={error} onRetry={onRetry} />;
}
