import clsx from "clsx";
import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { ChevronRight, Eye, LayoutDashboard, Lock, MonitorSmartphone, ShieldCheck } from "lucide-react";
import { Aurora } from "@shared/primitives/Motion";
import { BrandMark } from "@shared/primitives/BrandMark";
import { Icon } from "@shared/primitives/Icon";

// AuthShell - the ONE backdrop and card recipe for the portal's two
// pre-app screens, SignIn and ConsentSetup (design-kit WS10). Before this
// they drifted: an accent-soft wash on a bg-1 card with the lockup vs a
// brand-soft wash on a bg-2 card with the bare glyph. Now both draw:
//
//   - a decorative backdrop (aria-hidden): the shared Aurora, a Blueprint
//     wash and the illustrations' dot grid, tokens only (styles.css
//     .auth-backdrop / .auth-grid);
//   - the BrandMark badge + "superbased" wordmark lockup over the title;
//   - one card surface (bg-1, raised with shadow-2), the fill SignIn
//     already used, so the shared Input (bg-2) reads as a step off it;
//   - the "device -> preview -> portal" strip and the trust row under it.
//
// Purely presentational: no fetch, no state, no routing.

/** A step of the upload flow the strip explains. */
export type AuthStep = "device" | "preview" | "portal";

// AUTH_STEPS: the flow, in order. Each row is the glyph (a table, never
// inline in a page), the short label and the one honest line under it:
// sessions stay on the device, the `observer cloud` preview is the exact
// bytes an upload would send, and results come back to this portal.
const AUTH_STEPS: readonly { id: AuthStep; icon: LucideIcon; label: string; line: string }[] = [
  { id: "device", icon: MonitorSmartphone, label: "Your device", line: "Sessions stay local" },
  { id: "preview", icon: Eye, label: "Preview", line: "See exactly what is sent" },
  { id: "portal", icon: LayoutDashboard, label: "Portal", line: "Results come back here" },
];

// TRUST_ROW: the portal's one privacy promise ("Nothing leaves your machine
// until you preview it and approve it"), split into its three parts. No
// claim here that the promise itself does not already make.
const TRUST_ROW: readonly { icon: LucideIcon; label: string }[] = [
  { icon: ShieldCheck, label: "Stays on your machine" },
  { icon: Eye, label: "You preview it" },
  { icon: Lock, label: "You approve it" },
];

/** StepStrip is the three-step flow as an ordered list; `current` marks
 *  the step this screen is (aria-current="step"). */
export function StepStrip({ current }: { current?: AuthStep }) {
  return (
    <ol aria-label="How Cloud Intelligence works" className="auth-steps">
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
        Nothing leaves your machine until you preview it and approve it.{" "}
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

// WIDTH: the card's max width per screen. Sign-in is a short form; the
// consent screen carries seven sentence-length rows.
const WIDTH = { narrow: "max-w-[420px]", wide: "max-w-[540px]" } as const;

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
  width?: keyof typeof WIDTH;
  children: ReactNode;
}) {
  return (
    <div className="relative flex min-h-screen w-full items-center justify-center overflow-hidden bg-bg-0 px-4 py-10">
      <div aria-hidden="true" className="auth-backdrop">
        <Aurora />
        <span className="auth-wash" />
        <span className="auth-grid" />
      </div>

      <main className={clsx("relative flex w-full flex-col gap-5", WIDTH[width])}>
        <section className="rounded-3 border border-line-2 bg-bg-1 p-6 shadow-2 sm:p-8">
          <div className="flex flex-col items-center gap-3 text-center">
            <span className="brand">
              <span className="auth-badge">
                <BrandMark variant="badge" size={34} />
              </span>
              <span className="brand-word mono">superbased</span>
            </span>
            <h1 className="text-[19px] font-semibold leading-tight tracking-[-0.02em] text-fg-0">
              {title}
            </h1>
            {intro && <div className="text-[12.5px] leading-relaxed text-fg-2">{intro}</div>}
          </div>
          <div className="mt-6">{children}</div>
        </section>

        <StepStrip current={step} />
        <TrustRow />
      </main>
    </div>
  );
}
