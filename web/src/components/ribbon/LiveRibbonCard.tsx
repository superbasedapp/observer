import { useEffect, useState } from "react";
import { Activity } from "lucide-react";
import { Card, Toggle } from "@/components/primitives";
import { ConfigSaveCancelled, saveConfigSection } from "@/lib/configSectionSave";
import { apiCache } from "@/lib/useApi";
import { buildUrl } from "@/lib/api";
import { RIBBON_PARAMS, RIBBON_PATH } from "@/lib/ribbon";
import type { ConfigResponse } from "@/lib/types";

// LiveRibbonCard is the live ribbon's off switch, in Settings > Dashboard:
// [dashboard].live_ribbon (default on). It is kept on the daemon (config.toml),
// so it holds across browsers, and saves through the one section save path
// (preview, then write). The daemon reads it on every ribbon request, so a
// save applies at once, no restart. Off removes the top-bar chip and the
// strip; the nav's Live count stays.

/** The field path the schema-driven "More settings" card must not repeat. */
export const LIVE_RIBBON_FIELD = "Dashboard.LiveRibbon";

function savedValue(config: ConfigResponse | null): boolean {
  const v = (config?.config?.Dashboard as { LiveRibbon?: unknown } | undefined)?.LiveRibbon;
  return typeof v === "boolean" ? v : true;
}

export function LiveRibbonCard({
  config,
  readOnly,
  onSaved,
}: {
  config: ConfigResponse | null;
  readOnly?: boolean;
  onSaved: () => void;
}) {
  const saved = savedValue(config);
  const [on, setOn] = useState(saved);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => setOn(saved), [saved]);

  const change = async (next: boolean) => {
    setOn(next);
    setBusy(true);
    setErr(null);
    try {
      await saveConfigSection("dashboard", { LiveRibbon: next }, { title: "Live ribbon" });
      // The ribbon reads the switch from its own request: refresh it now.
      apiCache.invalidate(buildUrl(RIBBON_PATH, RIBBON_PARAMS));
      onSaved();
    } catch (e) {
      setOn(saved);
      if (!(e instanceof ConfigSaveCancelled)) setErr(e instanceof Error ? e.message : "Save failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card
      id="live-ribbon"
      className="mt-4"
      title="Live ribbon"
      icon={Activity}
      actions={
        <Toggle
          on={on}
          onChange={(v) => void change(v)}
          disabled={busy || readOnly}
          ariaLabel="Show the live ribbon"
        />
      }
    >
      <p className="text-[12px] text-fg-3">
        A chip in the top bar, and a slim strip under it while an agent is working. It shows the
        tool, the project name, the model, tokens and cost. It never shows a file name or what the
        agent is doing. Applies at once, no restart.
      </p>
      {err && (
        <p role="alert" className="mt-2 text-[12px] text-danger">
          {err}
        </p>
      )}
    </Card>
  );
}
