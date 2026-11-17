import clsx from "clsx";
import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { ChevronRight, Eye, LayoutDashboard, Lock, MonitorSmartphone, ShieldCheck } from "lucide-react";
import { AuthShell as SharedAuthShell, type AuthWidth } from "@shared/components/auth/AuthShell";
import { Icon } from "@shared/primitives/Icon";

// The portal's pre-app screens (SignIn, ConsentSetup) on the ONE shared
// sign-in recipe (shared/components/auth/AuthShell.tsx: backdrop, lockup,
// raised card; the same one the org dashboard uses). What stays here is
// portal CONTENT under the card: the "device -> preview -> portal" strip and
// the trust row. Purely presentational: no fetch, no state, no routing.

/** A step of the upload flow the strip explains. */
export type AuthStep = "device" | "preview" | "portal";

// AUTH_STEPS: the flow, in order. Each row is the glyph (a table, never
// inline in a page), the short label and the one honest line under it:
// sessions stay on the device, the `observer cloud` preview is the exact
// bytes an upload would send, and results come back to this portal.
const AUTH_STEPS: readonly { id: AuthStep; icon: LucideIcon; label: string; line: string }[] = [
  { id: "device", icon: MonitorSmartphone, label: "Your machine", line: "Observer runs there" },
  { id: "preview", icon: Eye, label: "Approve", line: "You choose what is sent" },
  { id: "portal", icon: LayoutDashboard, label: "Dashboard", line: "One place for every machine" },
];

// TRUST_ROW: the portal's one privacy promise ("Nothing leaves your machine
// until you preview it and approve it"), split into its three parts. No
// claim here that the promise itself does not already make.
const TRUST_ROW: readonly { icon: LucideIcon; label: string }[] = [
  { icon: ShieldCheck, label: "Stays on your machine" },
  { icon: Eye, label: "You see what is sent" },
  { icon: Lock, label: "You approve it" },
];

/** StepStrip is the three-step flow as an ordered list; `current` marks
 *  the step this screen is (aria-current="step"). */
export function StepStrip({ current }: { current?: AuthStep }) {
  return (
    <ol aria-label="How SuperBased works" className="auth-steps">
      {AUTH_STEPS.map((s, i) => {
        const on = s.id === current;
        return (
          <li
            key={s.id}
            aria-current={on ? "step" : undefined}
            className={clsx("auth-step", on && "auth-step-current")}
          >
            <span className="auth-step-icon">
              <Icon icon={s.icon} size="md" />
            </span>
            <span className="flex min-w-0 flex-col">
              <span className="text-[12px] font-semibold text-fg-0">
                <span className="sr-only">Step {i + 1}: </span>
                {s.label}
                {on && <span className="sr-only"> (you are here)</span>}
              </span>
              <span className="text-[11px] leading-snug text-fg-3">{s.line}</span>
            </span>
            {i < AUTH_STEPS.length - 1 && (
              <Icon icon={ChevronRight} size="xs" className="auth-step-sep" />
            )}
          </li>
        );
      })}
    </ol>
  );
}

/** TrustRow is the icon-led privacy promise with the Privacy link. */
export function TrustRow() {
  return (
    <div className="flex flex-col items-center gap-2 text-center">
      <ul aria-label="Privacy" className="flex flex-wrap items-center justify-center gap-x-4 gap-y-1.5">
        {TRUST_ROW.map((t) => (
          <li key={t.label} className="inline-flex items-center gap-1.5 text-[11.5px] font-medium text-fg-2">
            <Icon icon={t.icon} size="xs" className="text-accent" />
            {t.label}
          </li>
        ))}
      </ul>
      <p className="text-[11.5px] leading-relaxed text-fg-3">
        Nothing leaves your machine until you approve it.{" "}
        <a
          className="text-fg-2 underline decoration-line-3 underline-offset-2 transition-colors hover:text-fg-0"
          href="https://superbased.app/privacy"
          target="_blank"
          rel="noreferrer"
        >
          Privacy
        </a>
      </p>
    </div>
  );
}

export function AuthShell({
  title,
  intro,
  step,
  width = "narrow",
  children,
}: {
  title: string;
  /** One paragraph under the title. */
  intro?: ReactNode;
  /** The step of the flow this screen is, highlighted in the strip. */
  step?: AuthStep;
  width?: AuthWidth;
  children: ReactNode;
}) {
  return (
    <SharedAuthShell
      title={title}
      intro={intro}
      width={width}
      below={
        <>
          <StepStrip current={step} />
          <TrustRow />
        </>
      }
    >
      {children}
    </SharedAuthShell>
  );
}
