import { useState, useSyncExternalStore } from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/primitives";
import { useComponentState } from "@/lib/useComponents";
import { dismissalsSnapshot, isDismissed, subscribeDismissals } from "@/lib/uiDismissals";
import { useDismissNotice } from "@/lib/useDismissNotice";

// ComponentsSetupCard: the dashboard's first-visit prompt (modular packaging
// plan 7.1) while no component selection is recorded on this machine. It
// says what is true (every component in this build is active, as before)
// and links to Settings > Components. A dismissal is kept in the browser and
// on the daemon (WINNODE2 16b: it came back on every Overview load where the
// browser's own storage did not persist); it never renders once a selection
// exists or while the state read is unknown.

const DISMISS_KEY = "sbo_components_setup_dismissed";

function readDismissed(): boolean {
  try {
    return globalThis.localStorage?.getItem(DISMISS_KEY) === "1";
  } catch {
    return false;
  }
}

/** The card's rule (WINNODE2 16b): dismissed here or on the daemon hides it. */
export function componentsCardShown(i: {
  localDismissed: boolean;
  serverDismissed: boolean;
  wired: boolean;
  configured: boolean;
}): boolean {
  return !i.localDismissed && !i.serverDismissed && i.wired && !i.configured;
}

export function ComponentsSetupCard() {
  const st = useComponentState();
  const [dismissed, setDismissed] = useState(readDismissed);
  useSyncExternalStore(subscribeDismissals, dismissalsSnapshot, dismissalsSnapshot);
  const dismissNotice = useDismissNotice();
  const shown = componentsCardShown({
    localDismissed: dismissed,
    serverDismissed: isDismissed("components_setup"),
    wired: !!st.data?.wired,
    configured: !!st.data?.view.configured,
  });
  if (!shown) return null;
  const dismiss = () => {
    setDismissed(true);
    dismissNotice("components_setup");
    try {
      globalThis.localStorage?.setItem(DISMISS_KEY, "1");
    } catch {
      // Storage unavailable: hidden for this page view.
    }
  };
  return <ComponentsSetupCardView onDismiss={dismiss} />;
}

/** The card itself, for the component test. */
export function ComponentsSetupCardView({ onDismiss }: { onDismiss: () => void }) {
  return (
    <div
      role="note"
      data-testid="components-setup-card"
      className="flex flex-wrap items-center justify-between gap-3 rounded-3 border border-line-2 bg-bg-1 px-4 py-3"
    >
      <div className="min-w-0 text-small text-fg-2">
        <span className="font-medium text-fg-1">Review what Observer runs on this machine.</span> Every
        component in this build is active. You can turn off what you do not use; an inactive component
        starts nothing and writes nothing into your tools.
      </div>
      <div className="flex shrink-0 gap-2">
        <Link
          to="/settings/components"
          className="rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-small font-medium text-accent hover:bg-accent/25"
        >
          Review components
        </Link>
        <Button size="sm" variant="ghost" onClick={onDismiss}>
          Dismiss
        </Button>
      </div>
    </div>
  );
}
