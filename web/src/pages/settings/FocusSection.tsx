// FocusSection - Settings > General > "What you use superbased for"
// (first-run plan revision 2, sections 2.5 and 6). The same three options as
// the first screen; the choice is stored on the daemon as `Focus` in its
// first-run state (POST /api/firstrun/seen {"focus"}), never in a browser.
//
// The daemon's rule lets a stored choice decide the coding fact (POLISH-F1
// finding F1-1), so picking "AI apps" here takes effect even on a machine
// with coding history. A machine fact still adds AI apps: with AI Apps on, or
// a trace already received, the track is Both whatever is picked, which the
// help line says.

import { useState } from "react";
import { Compass } from "lucide-react";
import { Button, Card, SegmentedControl } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { showGettingStartedAgain, postFocus } from "@/components/firstrun/GetStartedSurface";
import { PRODUCT_NAMES } from "@shared/lib/productNames";
import { FIRST_RUN_PATH, type FirstRunResponse, type PlaneChoice } from "@/lib/firstRun";
import { FOCUS_CHOICES, focusSelected } from "@/lib/getStarted";

const LABELS: Record<Exclude<PlaneChoice, "">, string> = {
  coding: PRODUCT_NAMES.first_run_coding,
  apps: PRODUCT_NAMES.first_run_apps,
  both: PRODUCT_NAMES.first_run_both,
};

/** The control's help line (F1-1): what the choice does, and the one case
 *  where a machine fact adds AI apps anyway. */
export const FOCUS_HELP = `Changes what the first screen and the navigation show first. Nothing is turned off. Your choice always takes effect, except that with ${PRODUCT_NAMES.planea} on, or a trace already received, AI apps stay on the first screen too.`;

export function FocusSection({ readOnly }: { readOnly: boolean }) {
  const brief = useApi<FirstRunResponse>(FIRST_RUN_PATH, { brief: "1" });
  const plane = brief.data?.plane;
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [shown, setShown] = useState(false);

  const choose = async (c: PlaneChoice) => {
    setBusy(true);
    setErr("");
    try {
      await postFocus(c, brief.data?.confirm_token);
      brief.reload();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="General" icon={Compass}>
      <FocusControl
        plane={plane}
        busy={busy}
        readOnly={readOnly}
        loaded={brief.data != null}
        err={err}
        shown={shown}
        onChoose={(c) => void choose(c)}
        onShowAgain={() => {
          showGettingStartedAgain();
          setShown(true);
        }}
      />
    </Card>
  );
}

/** FocusControl renders the control from props (tests render it). */
export function FocusControl({
  plane,
  busy,
  readOnly,
  loaded,
  err,
  shown,
  onChoose,
  onShowAgain,
}: {
  plane: FirstRunResponse["plane"];
  busy: boolean;
  readOnly: boolean;
  loaded: boolean;
  err: string;
  shown: boolean;
  onChoose: (c: PlaneChoice) => void;
  onShowAgain: () => void;
}) {
  const value = focusSelected(plane);
  const appsOff = plane?.apps_available?.available === false;
  return (
    <div className="space-y-3 text-[12px]" data-testid="settings-focus">
      <div>
        <p className="font-medium text-fg-1">What you use superbased for</p>
        <p className="mt-0.5 text-[11.5px] text-fg-3">{FOCUS_HELP}</p>
      </div>
      {!loaded ? (
        <p className="text-fg-3">Reading this machine...</p>
      ) : !plane ? (
        <p className="text-fg-3">This daemon is older than this choice. Restart it after updating to set it here.</p>
      ) : (
        <SegmentedControl
          options={FOCUS_CHOICES.map((c) => {
            const reason = readOnly
              ? "Managed by your organization."
              : appsOff && c !== "coding"
                ? plane.apps_available.text || `${PRODUCT_NAMES.planea} is not available on this machine.`
                : busy
                  ? "Saving..."
                  : "";
            return { value: c, label: LABELS[c], disabled: reason !== "", disabledReason: reason || undefined };
          })}
          value={value}
          onChange={(c) => onChoose(c)}
        />
      )}
      {plane && plane.focus === "" && (
        <p className="text-[11px] text-fg-4">Not chosen yet: this is what superbased worked out from this machine.</p>
      )}
      {plane && plane.focus !== "" && (
        <button
          type="button"
          disabled={busy || readOnly}
          onClick={() => onChoose("")}
          className="text-[11px] text-accent hover:underline disabled:opacity-60"
        >
          Let superbased work it out again
        </button>
      )}
      {appsOff && plane?.apps_available.text && <p className="text-[11px] text-fg-3">{plane.apps_available.text}</p>}
      {err && <p className="text-danger">{err}</p>}
      <div className="flex flex-wrap items-center gap-2 border-t border-line-1 pt-3">
        <Button size="sm" variant="ghost" iconLeft={Compass} onClick={onShowAgain}>
          Show the getting-started steps again
        </Button>
        {shown && <span className="text-[11px] text-success">They are back on the Overview.</span>}
      </div>
    </div>
  );
}
