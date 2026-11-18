import clsx from "clsx";
import type { CSSProperties, ReactNode } from "react";
import { Aurora } from "../../primitives/Motion";
import { BrandMark } from "../../primitives/BrandMark";

// AuthShell: the ONE backdrop and card recipe for every app's pre-app
// screens (design-kit WS10): the org dashboard's Login and SetPassword
// (web2) and the cloud portal's SignIn and ConsentSetup (webcloud), so a
// sign-in reads as the same product wherever it happens. Drawn with
// Tailwind classes and tokens only (no app stylesheet):
//
//   - a decorative backdrop (aria-hidden, pointer-events none): the shared
//     Aurora, a soft Blueprint wash and the illustrations' blueprint dot
//     grid, fading toward the edges. Aurora honours reduced motion; the wash
//     and grid never move;
//   - the BrandMark badge + "superbased" wordmark lockup (+ an optional
//     subtitle naming the app);
//   - one raised card (bg-1, shadow-2) holding the page's single h1;
//   - whatever the app puts `below` the card (the org's help line, the
//     portal's flow strip and privacy promise);
//   - an optional `corner` control pinned to the top right of the screen
//     (the portal's theme toggle on its signed-out screens).
//
// It renders OUTSIDE the authenticated app tree. Purely presentational: no
// fetch, no state, no routing.

// The backdrop layers as data. The gradient maths lives in inline styles
// because a multi-stop mask does not fit a readable class name. Every colour
// is a token.
const WASH: CSSProperties = {
  background: "radial-gradient(46rem 28rem at 50% 38%, var(--brand-blueprint-soft), transparent 70%)",
};

// The dot colour comes from --auth-dot, which the grid's classes set per
// theme (a lighter dot on the light surface).
const GRID_MASK = "radial-gradient(ellipse 75% 65% at 50% 42%, #000 20%, transparent 78%)";
const GRID: CSSProperties = {
  backgroundImage: "radial-gradient(circle, var(--auth-dot) 1px, transparent 1.4px)",
  backgroundSize: "20px 20px",
  backgroundPosition: "center",
  WebkitMaskImage: GRID_MASK,
  maskImage: GRID_MASK,
};
const GRID_DOT =
  "[--auth-dot:color-mix(in_srgb,var(--brand-blueprint)_30%,transparent)] " +
  "[:root[data-theme=light]_&]:[--auth-dot:color-mix(in_srgb,var(--brand-blueprint)_20%,transparent)]";

// The badge's soft Blueprint halo (the kit's brand-badge shadow).
const BADGE_HALO: CSSProperties = {
  boxShadow:
    "0 0 0 1px color-mix(in srgb, var(--brand-blueprint) 45%, transparent), " +
    "0 6px 24px -8px color-mix(in srgb, var(--brand-blueprint) 70%, transparent)",
};

// AUTH_WIDTH: the card's max width per screen. A sign-in is a short form; a
// consent screen carries sentence-length rows.
export const AUTH_WIDTH = { narrow: "max-w-[420px]", wide: "max-w-[540px]" } as const;
export type AuthWidth = keyof typeof AUTH_WIDTH;

/** AuthBackdrop is the decorative layer behind the card. */
function AuthBackdrop() {
  return (
    <div aria-hidden="true" className="pointer-events-none absolute inset-0 overflow-hidden">
      <Aurora />
      <span className="absolute inset-0" style={WASH} />
      <span className={`absolute inset-0 ${GRID_DOT}`} style={GRID} />
    </div>
  );
}

/** AuthLockup is the badge + wordmark header, with the app's subtitle. */
function AuthLockup({ subtitle }: { subtitle?: string }) {
  return (
    <div className="flex flex-col items-center gap-2.5">
      <span className="inline-flex rounded-[22%]" style={BADGE_HALO}>
        <BrandMark variant="badge" size={34} />
      </span>
      <div className="flex flex-col items-center leading-tight">
        <b className="font-mono text-[17px] font-medium tracking-tight text-fg-0">superbased</b>
        {subtitle && (
          <span className="text-[10px] font-medium uppercase tracking-[0.08em] text-fg-3">{subtitle}</span>
        )}
      </div>
    </div>
  );
}

export function AuthShell({
  subtitle,
  title,
  intro,
  width = "narrow",
  children,
  below,
  corner,
}: {
  /** Names the app under the wordmark ("Org dashboard"); optional. */
  subtitle?: string;
  title: string;
  /** One paragraph under the title. */
  intro?: ReactNode;
  width?: AuthWidth;
  children: ReactNode;
  /** Blocks under the card, in order. */
  below?: ReactNode;
  /** A control pinned to the screen's top right (a theme toggle); optional. */
  corner?: ReactNode;
}) {
  return (
    <div className="relative flex min-h-screen w-full items-center justify-center overflow-hidden bg-bg-0 px-4 py-10">
      <AuthBackdrop />
      {corner && <div className="absolute right-4 top-4 z-10">{corner}</div>}
      <main className={clsx("relative flex w-full flex-col gap-5", AUTH_WIDTH[width])}>
        <section className="rounded-3 border border-line-2 bg-bg-1 p-6 shadow-2 sm:p-8">
          <AuthLockup subtitle={subtitle} />
          <div className="mt-5 text-center">
            <h1 className="text-[19px] font-semibold leading-tight tracking-[-0.02em] text-fg-0">{title}</h1>
            {intro && <div className="mt-1.5 text-[12.5px] leading-relaxed text-fg-2">{intro}</div>}
          </div>
          <div className="mt-6">{children}</div>
        </section>
        {below}
      </main>
    </div>
  );
}
