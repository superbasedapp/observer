import {
  arrow,
  autoUpdate,
  flip,
  FloatingArrow,
  FloatingPortal,
  offset,
  shift,
  useDismiss,
  useFloating,
  useFocus,
  useHover,
  useInteractions,
  useMergeRefs,
  useRole,
  useTransitionStyles,
} from "@floating-ui/react";
import clsx from "clsx";
import {
  cloneElement,
  forwardRef,
  isValidElement,
  useMemo,
  useRef,
  useState,
  type HTMLAttributes,
  type ReactElement,
  type ReactNode,
} from "react";

// Tooltip is the dashboard's single explanatory-popover primitive.
// Replaces every native `title="..."` hover hint with a themed surface
// that matches the dashboard's design tokens (--bg-3 surface,
// --line-3 border, --shadow-2 elevation, --accent-ring focus).
//
// Trigger semantics: hover OR keyboard focus opens, mouse-leave / blur
// / escape closes. 200ms restMs on hover-intent so brief mouseovers
// don't open every tooltip the cursor crosses (matches the cadence of
// Mac OS native tooltips and the prior browser-default behavior).
//
// Two usage shapes:
//
//   <Tooltip content="Click to copy">
//     <button>Copy</button>
//   </Tooltip>
//
//   <Tooltip content={<>…rich React node…</>} side="bottom" maxWidth={360}>
//     <span tabIndex={0}>Hover or focus me</span>
//   </Tooltip>
//
// The child is cloned with the floating refs + interaction listeners,
// so it must be a single React element that accepts ref + spread props.
// String / fragment children are not supported — wrap them in a span.
//
// Accessibility: role="tooltip" on the bubble, aria-describedby wired
// onto the trigger when open. Floating UI's useRole handles this.
// Tooltip is NOT for actionable content (links / buttons inside) —
// use a popover for that. Hover-only popups with click targets are an
// accessibility footgun.

type TooltipSide = "top" | "bottom" | "left" | "right";

export interface TooltipProps {
  // The popover body. String renders single-line by default; ReactNode
  // can carry multi-line / styled content.
  content: ReactNode;
  // The trigger element. Must be a single React element that forwards
  // refs and accepts arbitrary aria/event props.
  children: ReactElement;
  // Preferred placement. Auto-flips to the opposite side when the
  // tooltip would clip the viewport.
  side?: TooltipSide;
  // Gap between the trigger and the tooltip body, in px. Default 6.
  offset?: number;
  // Max width of the bubble. Default 280px — wide enough for ~2
  // lines of explanatory copy; longer content wraps. Pass a larger
  // value for help-style tooltips.
  maxWidth?: number;
  // Show the small arrow pointing at the trigger. Default true.
  arrow?: boolean;
  // Forces the open state. When provided, hover / focus listeners are
  // bypassed (useful for "always-show" demo modes or tests).
  open?: boolean;
  // Override the hover delay in ms. Default 200ms.
  delay?: number;
  // When provided, the tooltip surface and arrow render with the
  // matching variant tone. "default" matches the rest of the
  // dashboard (--bg-3 surface); "accent" uses the accent surface
  // for noteworthy hints; "danger" / "success" reserved for future
  // status callouts.
  tone?: "default" | "accent" | "danger" | "success";
  // Disables the tooltip without removing it from the tree (handy for
  // conditional hints).
  disabled?: boolean;
}

const toneSurface: Record<NonNullable<TooltipProps["tone"]>, string> = {
  default:
    "bg-bg-3 text-fg-1 border-line-3",
  accent:
    "bg-[var(--accent-soft)] text-fg-0 border-[var(--accent-ring)]",
  danger:
    "bg-[rgba(239,68,68,0.10)] text-fg-0 border-[rgba(239,68,68,0.40)]",
  success:
    "bg-[rgba(34,197,94,0.10)] text-fg-0 border-[rgba(34,197,94,0.40)]",
};

const toneFill: Record<NonNullable<TooltipProps["tone"]>, string> = {
  default: "var(--bg-3)",
  accent: "var(--accent-soft)",
  danger: "rgba(239,68,68,0.10)",
  success: "rgba(34,197,94,0.10)",
};

const toneStroke: Record<NonNullable<TooltipProps["tone"]>, string> = {
  default: "var(--line-3)",
  accent: "var(--accent-ring)",
  danger: "rgba(239,68,68,0.40)",
  success: "rgba(34,197,94,0.40)",
};

export function Tooltip({
  content,
  children,
  side = "top",
  offset: gap = 6,
  maxWidth = 280,
  arrow: showArrow = true,
  open: controlledOpen,
  delay = 200,
  tone = "default",
  disabled = false,
}: TooltipProps) {
  const [uncontrolledOpen, setUncontrolledOpen] = useState(false);
  const arrowRef = useRef<SVGSVGElement | null>(null);

  const open =
    controlledOpen !== undefined ? controlledOpen : uncontrolledOpen;
  const setOpen = (v: boolean) => {
    if (controlledOpen === undefined) setUncontrolledOpen(v);
  };

  const { refs, floatingStyles, context } = useFloating({
    open,
    onOpenChange: setOpen,
    placement: side,
    middleware: [
      offset(gap),
      flip({ fallbackAxisSideDirection: "start" }),
      shift({ padding: 8 }),
      ...(showArrow ? [arrow({ element: arrowRef })] : []),
    ],
    whileElementsMounted: autoUpdate,
  });

  const hover = useHover(context, {
    move: false,
    enabled: !disabled && controlledOpen === undefined,
    restMs: delay,
    delay: { close: 80 },
  });
  const focus = useFocus(context, {
    enabled: !disabled && controlledOpen === undefined,
  });
  const dismiss = useDismiss(context);
  const role = useRole(context, { role: "tooltip" });

  const { getReferenceProps, getFloatingProps } = useInteractions([
    hover,
    focus,
    dismiss,
    role,
  ]);

  const { isMounted, styles: transitionStyles } = useTransitionStyles(
    context,
    {
      duration: { open: 120, close: 80 },
      initial: { opacity: 0, transform: "scale(0.96)" },
      open: { opacity: 1, transform: "scale(1)" },
      close: { opacity: 0, transform: "scale(0.96)" },
    },
  );

  // Merge our ref onto whatever ref the child may already carry. If
  // the child is a forwardRef'd component this preserves its ref;
  // otherwise the ref attaches to the DOM node directly.
  const childRef = (children as { ref?: React.Ref<unknown> }).ref;
  const mergedRef = useMergeRefs([refs.setReference, childRef ?? null]);

  const trigger = useMemo(() => {
    if (!isValidElement(children)) return children;
    const childProps = children.props as HTMLAttributes<HTMLElement>;
    return cloneElement(children, {
      ref: mergedRef,
      ...getReferenceProps({
        ...childProps,
      }),
    } as Partial<typeof childProps> & { ref: typeof mergedRef });
  }, [children, getReferenceProps, mergedRef]);

  if (disabled || content == null || content === false) {
    return children;
  }

  return (
    <>
      {trigger}
      {isMounted && (
        <FloatingPortal>
          {/* Two-div pattern recommended by @floating-ui/react: outer
              div carries the positioning transform from floatingStyles
              (`transform: translate(x, y)`); inner div carries the
              transition transform from useTransitionStyles
              (`transform: scale(...)`). If both lived on the same
              element, the transition's transform would clobber the
              positioning transform and the tooltip would render at
              the body origin (top-left) instead of near the trigger.
              See https://floating-ui.com/docs/usetransitionstyles. */}
          <div
            ref={refs.setFloating}
            style={floatingStyles}
            {...getFloatingProps()}
            className="pointer-events-none z-[80]"
          >
            <div
              style={{ ...transitionStyles, maxWidth }}
              role="tooltip"
              className={clsx(
                "rounded-md border px-2.5 py-1.5 text-xs leading-relaxed shadow-[var(--shadow-2)]",
                "[&_kbd]:rounded [&_kbd]:bg-bg-4 [&_kbd]:px-1.5 [&_kbd]:py-0.5 [&_kbd]:font-mono [&_kbd]:text-[10px]",
                "[&_code]:rounded [&_code]:bg-bg-4 [&_code]:px-1 [&_code]:font-mono [&_code]:text-[11px]",
                "[&_strong]:font-semibold [&_strong]:text-fg-0",
                toneSurface[tone],
              )}
            >
              {content}
              {showArrow && (
                <FloatingArrow
                  ref={arrowRef}
                  context={context}
                  width={10}
                  height={5}
                  fill={toneFill[tone]}
                  stroke={toneStroke[tone]}
                  strokeWidth={1}
                />
              )}
            </div>
          </div>
        </FloatingPortal>
      )}
    </>
  );
}

// TooltipSpan is a convenience wrapper for the very common case of
// adding a tooltip to a piece of text that doesn't already have its
// own element. Without this, callers would have to wrap every
// `<Tooltip content="…">text</Tooltip>` in a span themselves.
// Forwards ref so it can be used inside other Tooltip / Popover
// composites.
export const TooltipSpan = forwardRef<
  HTMLSpanElement,
  TooltipProps & { className?: string }
>(function TooltipSpan({ content, children, className, ...rest }, ref) {
  return (
    <Tooltip content={content} {...rest}>
      <span ref={ref} className={className} tabIndex={0}>
        {children}
      </span>
    </Tooltip>
  );
});
