import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { Mail } from "lucide-react";
import { Button, Card, SuccessCheck, Toggle } from "@/components/primitives";
import { ConfigSaveCancelled, saveConfigSection } from "@/lib/configSectionSave";
import { apiCache } from "@/lib/useApi";
import { MESSAGES_SUMMARY_PATH, useMessagesSummary } from "@/lib/useMessagesSummary";
import {
  messagesConfigFrom,
  surfaceSwitch,
  surfacesDirty,
  SURFACE_SETTINGS,
  type MessagesConfigValues,
} from "@/lib/adminMessages";
import type { ConfigResponse } from "@/lib/types";

// MessageSurfacesCard: where messages from the organization's admins show up
// on this machine (the [messages] section, T-854). It lives in Settings > Org
// sharing, which no policy can hide, and saves through the one section
// save path (PUT /api/config/section/messages: preview, then write with the
// confirm token). Every key is read where it is used, so a save applies at
// once, no restart. Read receipts on a managed enrolment are shown fixed on
// and explained. The Messages page's "Where messages show up" panel links
// here (#messages-surfaces).

export const MESSAGE_SURFACES_ANCHOR = "messages-surfaces";

export function MessageSurfacesCard({
  config,
  readOnly,
  onSaved,
}: {
  config: ConfigResponse | null;
  readOnly?: boolean;
  onSaved: () => void;
}) {
  const saved = useMemo(() => messagesConfigFrom(config?.config), [config]);
  const [draft, setDraft] = useState<MessagesConfigValues>(saved);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  useEffect(() => setDraft(saved), [saved]);

  const summary = useMessagesSummary().data;
  const locked = summary?.surfaces?.read_receipts_locked === true;

  // A link to #messages-surfaces scrolls this card into view.
  const ref = useRef<HTMLDivElement>(null);
  const { hash } = useLocation();
  useEffect(() => {
    if (hash === `#${MESSAGE_SURFACES_ANCHOR}`) ref.current?.scrollIntoView({ block: "start", behavior: "smooth" });
  }, [hash]);

  const dirty = surfacesDirty(saved, draft);
  const save = async () => {
    setBusy(true);
    setErr(null);
    setOk(null);
    try {
      const out = await saveConfigSection("messages", draft, { title: "Where messages show up" });
      setOk(out.write_mode === "noop" ? "Nothing to save; config.toml already says this." : "Saved. It applies at once.");
      apiCache.invalidate(MESSAGES_SUMMARY_PATH);
      onSaved();
    } catch (e) {
      if (!(e instanceof ConfigSaveCancelled)) setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div id={MESSAGE_SURFACES_ANCHOR} ref={ref} className="mt-4 scroll-mt-4">
      <Card
        title="Where messages show up"
        icon={Mail}
        sub={
          <>
            Messages from your organization's admins always appear on the{" "}
            <Link to="/messages" className="text-accent hover:underline">
              Messages page
            </Link>{" "}
            and in the bell. These switches choose where else they reach you. Your organization cannot turn these on for
            you, and muting a surface never hides a message from the Messages page.
          </>
        }
      >
        <ul className="divide-y divide-line-1">
          {SURFACE_SETTINGS.map((s) => {
            const v = surfaceSwitch(s.key, draft, locked, "");
            return (
              <li key={s.key} className="flex items-start justify-between gap-4 py-2.5">
                <div className="min-w-0">
                  <div className="text-[12.5px] text-fg-1">{s.label}</div>
                  <p className="mt-0.5 text-[11.5px] text-fg-3">{s.help}</p>
                  {v.note && <p className="mt-0.5 text-[11.5px] text-warn">{v.note}</p>}
                </div>
                <Toggle
                  on={v.on}
                  disabled={readOnly || busy || v.disabled}
                  ariaLabel={s.label}
                  onChange={(next) => setDraft((d) => ({ ...d, [s.key]: next }))}
                />
              </li>
            );
          })}
        </ul>
        {!readOnly && (
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <Button variant="primary" size="sm" disabled={!dirty} loading={busy} onClick={() => void save()}>
              Save
            </Button>
            {dirty && (
              <Button size="sm" variant="ghost" onClick={() => setDraft(saved)}>
                Reset
              </Button>
            )}
            {ok && <SuccessCheck label={ok} className="!text-[11.5px]" />}
            {err && (
              <span className="text-[11.5px] text-danger" role="alert">
                {err}
              </span>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
