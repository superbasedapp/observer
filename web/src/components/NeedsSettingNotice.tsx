import clsx from "clsx";
import { useCallback, type MouseEvent, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { ExternalLink, Settings2 } from "lucide-react";
import { Button, Callout } from "@/components/primitives";
import { GatedLink, MANAGED_LINK_TEXT } from "@/components/GatedLink";
import { HelpTooltip } from "@shared/primitives/HelpTooltip";
import { useHrefGate } from "@/lib/governance";
import {
  errorNote,
  noteOf,
  orgActionLabel,
  orgAskText,
  settingsActionLabel,
  type ErrorNote,
  type OrgSettingsLink,
  type SettingsLink,
} from "@/lib/needsSetting";
import { pushToast, pushToastWith, type ToastVariant } from "@/components/Toast";
import { useCatalogRow } from "@/lib/useComponents";

// NeedsSettingNotice / ApiErrorNotice: the ONE renderer for a message whose
// fix is a setting or a component that is off (lib/needsSetting.ts reads the
// daemon's deep link). It shows the whole sentence (it wraps; it is never
// cut) and the way forward:
//
//   - the person can change it here: a button that opens the exact place
//     inside the dashboard ("Turn on <component>" / "Open <place>");
//   - only the organization's admins can: a line saying so and naming the
//     team-dashboard place, with a button that opens it in a new tab when
//     the node knows a safe address. Never a toggle of the node's own.
//
// Both may apply at once. Every surface renders such a message through this
// component (an error through ApiErrorNotice), so the wording and the
// buttons are the same everywhere. `variant="inline"` is the quiet form for
// a status line inside a card; the default is a callout.

/** NeedsSettingNotice renders a message that names a way forward. */
export function NeedsSettingNotice({
  text,
  link,
  org,
  technical,
  onNavigate,
  className,
  variant = "callout",
  tone = "warn",
}: {
  text: string;
  /** The detail behind the sentence, shown only as "Technical details". */
  technical?: string | null;
  /** The place on this machine, when the person can change it here. */
  link?: SettingsLink | null;
  /** The team-dashboard place, when only the organization's admins can. */
  org?: OrgSettingsLink | null;
  /** Called before navigating (a dialog closes itself here). */
  onNavigate?: () => void;
  className?: string;
  /** callout (default) or inline: a status line inside a card. */
  variant?: "callout" | "inline";
  /** The callout's tone: warn for a refusal, info for a status. */
  tone?: "warn" | "info";
}) {
  const navigate = useNavigate();
  const gate = useHrefGate()(link?.href ?? "");
  const title = useCatalogRow(link?.component ?? undefined)?.title;
  // The message usually names the command already; say it once.
  const showCommand = link?.command && !text.includes(link.command);
  const orgLine = org ? orgAskText(org) : null;

  function go(e: MouseEvent<HTMLButtonElement | HTMLAnchorElement>) {
    // A modified click keeps the browser's own behaviour (a new tab).
    if (!link || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    onNavigate?.();
    navigate(link.href);
  }

  const localAction = !link ? null : gate === "managed" ? (
    <span className="text-[11px] text-fg-3" data-testid="needs-setting-managed">
      {MANAGED_LINK_TEXT}
    </span>
  ) : (
    <Button size="sm" variant="secondary" iconLeft={Settings2} href={link.href} onClick={go} data-testid="needs-setting-open">
      {settingsActionLabel(link, title)}
    </Button>
  );
  const orgAction = org?.href ? (
    <Button size="sm" variant="ghost" iconLeft={ExternalLink} href={org.href} target="_blank" data-testid="needs-setting-org-open">
      {orgActionLabel(org)}
    </Button>
  ) : null;
  const actions =
    localAction || orgAction ? (
      <span className="flex flex-wrap items-center gap-2">
        {localAction}
        {orgAction}
      </span>
    ) : null;

  const body = (
    <>
      <span className="whitespace-pre-wrap" data-testid="needs-setting-text">
        {text}
      </span>
      {technical && (
        <HelpTooltip technical subject="this refusal" content={technical} className="ml-1 align-middle" />
      )}
      {orgLine && (
        <span className="mt-1 block" data-testid="needs-setting-org">
          {orgLine}
        </span>
      )}
      {showCommand && (
        <span className="mt-1 block text-[11px] text-fg-3">
          Or run <code className="font-mono">{link?.command}</code>
        </span>
      )}
    </>
  );

  if (variant === "inline") {
    return (
      <div className={clsx("flex flex-col gap-1.5 break-words text-caption text-fg-3", className)} data-testid="needs-setting-inline">
        <div>{body}</div>
        {actions}
      </div>
    );
  }
  return (
    <Callout tone={tone} className={clsx("break-words", className)} action={actions}>
      {body}
    </Callout>
  );
}

/**
 * NeedsSettingLink is the compact form of the same way forward, for a spot
 * with no room for a notice (a hero tile's sub line, a joined status line):
 * a text link to the place, gated like every in-app link (a place this
 * machine does not show reads "Managed by your organization"). The default
 * text is "Open <place>"; `children` overrides it ("Turn on").
 */
export function NeedsSettingLink({
  link,
  children,
  className,
}: {
  link: SettingsLink;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <GatedLink
      to={link.href}
      className={clsx("font-medium text-accent hover:text-accent-strong", className)}
      data-testid="needs-setting-link"
    >
      {children ?? settingsActionLabel(link)}
    </GatedLink>
  );
}

/**
 * ApiErrorNotice renders what a surface holds for a failed request: a note
 * from errorNote() (or the surface's own plain string). A note with a link
 * renders NeedsSettingNotice; anything else renders the surface's own error
 * line (`plainClassName`, default a small danger line), wrapped, never cut.
 */
export function ApiErrorNotice({
  note,
  onNavigate,
  className,
  plainClassName = "text-[11.5px] text-danger",
}: {
  note: ErrorNote | string | null | undefined;
  onNavigate?: () => void;
  /** Applied to the settings notice. */
  className?: string;
  /** Applied to a plain error line. */
  plainClassName?: string;
}) {
  const n = noteOf(note);
  if (!n) return null;
  if (n.settings || n.org) {
    return (
      <NeedsSettingNotice
        text={n.text}
        link={n.settings}
        org={n.org}
        technical={n.technical}
        onNavigate={onNavigate}
        className={className}
      />
    );
  }
  return (
    <div role="alert" className={clsx("whitespace-pre-wrap break-words", plainClassName)}>
      {n.text}
    </div>
  );
}

/**
 * useErrorToast is the toast form of the same renderer, for a surface that
 * reports a failure as a toast (no inline slot): the human sentence, and for
 * a "turn this on" refusal a button that opens the place to change it. It
 * stays up longer than a plain toast so the button can be pressed.
 */
export function useErrorToast(): (
  e: unknown,
  fallback?: (e: unknown) => string | null | undefined,
  variant?: ToastVariant,
) => void {
  const navigate = useNavigate();
  const gate = useHrefGate();
  return useCallback(
    (e: unknown, fallback?: (e: unknown) => string | null | undefined, variant: ToastVariant = "danger") => {
      const n = errorNote(e, fallback);
      const link = n.settings;
      if (link && gate(link.href) !== "managed") {
        pushToastWith({
          text: n.text,
          variant: "warn",
          durationMs: NEEDS_SETTING_TOAST_MS,
          actions: [{ label: settingsActionLabel(link), onClick: () => navigate(link.href), primary: true }],
        });
        return;
      }
      const text = n.org ? `${n.text} ${orgAskText(n.org)}` : n.text;
      pushToast(text, link || n.org ? "warn" : variant);
    },
    [navigate, gate],
  );
}

/** How long a "needs a setting" toast stays (it carries a button). */
const NEEDS_SETTING_TOAST_MS = 12_000;
