import clsx from "clsx";
import { forwardRef } from "react";
import type {
  AnchorHTMLAttributes,
  ButtonHTMLAttributes,
  MouseEventHandler,
  ReactNode,
} from "react";

// Button — the one solid/soft/quiet action control for every app surface.
//
// Why this exists: the apps had ~15 hand-rolled copies of the same CTA
// string, and several of them drifted in ways that only showed up in the
// light theme. Two traps this primitive closes for good:
//
//   1. `--bg-1` and `--bg-2` are DISTINCT in dark but BOTH `#ffffff` in
//      light, so a `bg-bg-1` control sitting on a `bg-bg-2` card simply
//      vanishes in light mode. No variant here fills with `bg-bg-1`, and
//      the disabled fill is ALWAYS `bg-bg-3` (a real step off the card in
//      both themes).
//   2. A solid accent button must use `text-accent-on`, never a hard-coded
//      `text-white`: `--on-accent` is near-black navy in dark and white in
//      light. `danger` is the one variant that keeps white, because
//      `--danger` is a saturated red in both themes.
export type ButtonVariant =
  | "primary"
  | "secondary"
  | "soft"
  | "danger"
  | "ghost";

export type ButtonSize = "sm" | "md";

const VARIANT_CLASS: Record<ButtonVariant, string> = {
  primary: "border-transparent bg-accent text-accent-on hover:bg-accent-strong",
  secondary: "border-line-2 bg-bg-3 text-fg-2 hover:bg-bg-4 hover:text-fg-1",
  // The "soft" tint CTA, as proven by the dashboard's Jump-in control.
  soft: "border-accent/40 bg-accent/10 text-accent hover:bg-accent/20",
  danger: "border-danger/40 bg-danger text-white hover:bg-danger/90",
  ghost: "border-transparent bg-transparent text-fg-2 hover:bg-bg-3 hover:text-fg-1",
};

const SIZE_CLASS: Record<ButtonSize, string> = {
  sm: "gap-1 px-2.5 py-1 text-[11px]",
  md: "gap-1.5 px-3 py-1.5 text-[12px]",
};

const BASE =
  "inline-flex shrink-0 items-center justify-center whitespace-nowrap rounded-2 border font-medium transition-colors focus:outline-none focus-visible:ring-1 focus-visible:ring-accent-ring";

// DISABLED is deliberately opaque rather than an opacity fade: a faded
// `bg-accent` on a light card reads as "still clickable".
const DISABLED = "cursor-not-allowed border-line-2 bg-bg-3 text-fg-3";

/** buttonClasses returns the class string a Button would render, for the
 *  rare caller that must put the look on an element Button cannot be
 *  (a `<label>`, a router `<Link>`). Prefer the component. */
export function buttonClasses(opts?: {
  variant?: ButtonVariant;
  size?: ButtonSize;
  disabled?: boolean;
}): string {
  const variant = opts?.variant ?? "secondary";
  const size = opts?.size ?? "md";
  return clsx(
    BASE,
    SIZE_CLASS[size],
    opts?.disabled ? DISABLED : VARIANT_CLASS[variant],
  );
}

export type ButtonProps = Omit<
  ButtonHTMLAttributes<HTMLButtonElement>,
  "className" | "children"
> & {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Renders a spinner and disables the control. */
  loading?: boolean;
  /** When set, renders an `<a>` with the identical look (external CTAs). */
  href?: string;
  target?: string;
  rel?: string;
  className?: string;
  children?: ReactNode;
};

// forwardRef so a Button can be a Tooltip trigger: Tooltip clones its
// child with the floating refs, and a plain function component would drop
// them.
export const Button = forwardRef<HTMLButtonElement | HTMLAnchorElement, ButtonProps>(
  function Button(
    {
      variant = "secondary",
      size = "md",
      loading,
      disabled,
      href,
      target,
      rel,
      className,
      children,
      type = "button",
      ...rest
    },
    ref,
  ) {
  const isDisabled = Boolean(disabled) || Boolean(loading);
  const cls = clsx(buttonClasses({ variant, size, disabled: isDisabled }), className);
  const body = (
    <>
      {loading && <Spinner />}
      {children}
    </>
  );

  if (href !== undefined) {
    // Default to rel="noreferrer" on a new-tab link when the caller gave
    // no rel of its own (an external CTA that forgets this leaks a
    // Referer header and hands the opened tab a `window.opener` back to
    // this page).
    const resolvedRel = rel ?? (target === "_blank" ? "noreferrer" : undefined);
    return (
      <a
        {...(rest as unknown as AnchorHTMLAttributes<HTMLAnchorElement>)}
        ref={ref as React.Ref<HTMLAnchorElement>}
        href={isDisabled ? undefined : href}
        target={target}
        rel={resolvedRel}
        aria-disabled={isDisabled || undefined}
        className={cls}
        onClick={(e) => {
          // A disabled link-styled Button must not navigate or fire its
          // handler — `href` alone is dropped above, but a handler bound
          // via onClick (rather than relying on navigation) would still
          // run without this guard.
          if (isDisabled) {
            e.preventDefault();
            return;
          }
          (rest.onClick as unknown as MouseEventHandler<HTMLAnchorElement> | undefined)?.(e);
        }}
      >
        {body}
      </a>
    );
  }

  return (
    <button
      ref={ref as React.Ref<HTMLButtonElement>}
      type={type}
      disabled={isDisabled}
      className={cls}
      {...rest}
    >
      {body}
    </button>
  );
  },
);

function Spinner() {
  return (
    <svg
      className="h-3 w-3 animate-spin"
      viewBox="0 0 16 16"
      fill="none"
      aria-hidden
    >
      <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="2" opacity="0.25" />
      <path
        d="M14 8a6 6 0 0 0-6-6"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
      />
    </svg>
  );
}
