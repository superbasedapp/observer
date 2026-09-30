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
  useRole,
  useTransitionStyles,
} from "@floating-ui/react";
import clsx from "clsx";
import {
  cloneElement,
  forwardRef,
  isValidElement,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type HTMLAttributes,
  type MutableRefObject,
  type ReactElement,
  type ReactNode,
  type Ref,
} from "react";
import {
  replayPlan,
  shouldArm,
  stillInsideAfterLeave,
  type ArmEvent,
} from "../lib/tooltipArming";

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
  // Tone colours come from the semantic tokens (they follow the theme);
  // they were hard-coded red-500 / green-500 rgba before 2026-09-28.
  danger: "bg-danger-soft text-fg-0 border-danger/40",
  success: "bg-success-soft text-fg-0 border-success/40",
};

const toneFill: Record<NonNullable<TooltipProps["tone"]>, string> = {
  default: "var(--bg-3)",
  accent: "var(--accent-soft)",
  danger: "var(--danger-soft)",
  success: "var(--success-soft)",
};

const toneStroke: Record<NonNullable<TooltipProps["tone"]>, string> = {
  default: "var(--line-3)",
  accent: "var(--accent-ring)",
  danger: "color-mix(in srgb, var(--danger) 40%, transparent)",
  success: "color-mix(in srgb, var(--success) 40%, transparent)",
};

// Lazy mounting (2026-09-29 perf audit): tables render one Tooltip per cell,
// and the full @floating-ui stack below (useFloating, hover/focus/dismiss/role
// interactions, transition styles, merged refs) cost ~100-170 ms of deepEqual
// alone per table render. A Tooltip therefore renders ONLY its child until the
// pointer first enters it or focus first lands inside it (native listeners on
// the child's node, attached through the ref), then mounts the machinery in
// TooltipLayer and replays that arming intent, so the tooltip still opens
// after the hover rest delay, and a keyboard focus still opens it. The child
// is never remounted by the upgrade (it stays at the same position in the
// tree), so focus and the child's own state survive it. The decisions live in
// shared/lib/tooltipArming.ts (pure, tested).

type GetReferenceProps = (userProps?: HTMLAttributes<HTMLElement>) => Record<string, unknown>;

// Arming intent recorded by the native listeners, read by the replay.
type Intent = {
  pointerInside: boolean;
  pointerType: string | undefined;
  clientX: number;
  clientY: number;
  focusRelatedTarget: EventTarget | null;
};

function assignRef<T>(ref: Ref<T> | undefined | null, value: T | null) {
  if (typeof ref === "function") ref(value);
  else if (ref && typeof ref === "object") (ref as MutableRefObject<T | null>).current = value;
}

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
  const controlled = controlledOpen !== undefined;
  const inert = disabled || content == null || content === false;

  // armedState is sticky: once the machinery has mounted it stays mounted
  // (closing transitions, later hovers). A controlled open arms it at once.
  const initialArm = shouldArm(
    { armed: false, controlled, controlledOpen: controlledOpen === true, inert },
    "controlled-open",
  );
  const [armedState, setArmed] = useState(initialArm);
  const armedByRef = useRef<ArmEvent | null>(initialArm ? "controlled-open" : null);
  const forceArm =
    !armedState &&
    shouldArm(
      { armed: false, controlled, controlledOpen: controlledOpen === true, inert },
      "controlled-open",
    );
  const armed = armedState || forceArm;
  useEffect(() => {
    if (!forceArm) return;
    if (armedByRef.current == null) armedByRef.current = "controlled-open";
    setArmed(true);
  }, [forceArm]);

  // Latest render facts for the native listeners (created once).
  const factsRef = useRef({ armed, controlled, controlledOpen: controlledOpen === true, inert });
  factsRef.current = { armed, controlled, controlledOpen: controlledOpen === true, inert };

  const intentRef = useRef<Intent>({
    pointerInside: false,
    pointerType: undefined,
    clientX: 0,
    clientY: 0,
    focusRelatedTarget: null,
  });

  const listenersRef = useRef<{
    pointerenter: (e: PointerEvent) => void;
    pointerleave: (e: PointerEvent) => void;
    focusin: (e: FocusEvent) => void;
  } | null>(null);
  if (listenersRef.current == null) {
    const arm = (event: ArmEvent) => {
      if (!shouldArm(factsRef.current, event)) return;
      armedByRef.current = event;
      factsRef.current = { ...factsRef.current, armed: true };
      setArmed(true);
    };
    listenersRef.current = {
      pointerenter: (e) => {
        const it = intentRef.current;
        it.pointerInside = true;
        it.pointerType = e.pointerType;
        it.clientX = e.clientX;
        it.clientY = e.clientY;
        arm("pointerenter");
      },
      pointerleave: (e) => {
        intentRef.current.pointerInside = stillInsideAfterLeave(e.pointerType);
      },
      focusin: (e) => {
        intentRef.current.focusRelatedTarget = e.relatedTarget;
        arm("focusin");
      },
    };
  }

  // The trigger's DOM node, and where TooltipLayer registers the floating
  // reference setter once it is live.
  const nodeRef = useRef<HTMLElement | null>(null);
  const sinkRef = useRef<((node: HTMLElement | null) => void) | null>(null);

  // One ref for the child: it keeps the child's own ref working (object or
  // callback), attaches the arming listeners, and feeds the floating
  // reference. Its identity follows the child's ref, so a child whose ref
  // changes sees the same detach/attach sequence the merged ref gave it.
  const childRef = isValidElement(children)
    ? (children as { ref?: Ref<unknown> }).ref
    : undefined;
  const triggerRef = useCallback(
    (node: HTMLElement | null) => {
      const l = listenersRef.current!;
      const prev = nodeRef.current;
      if (prev && prev !== node) {
        prev.removeEventListener("pointerenter", l.pointerenter);
        prev.removeEventListener("pointerleave", l.pointerleave);
        prev.removeEventListener("focusin", l.focusin);
      }
      nodeRef.current = node;
      if (node && node !== prev) {
        node.addEventListener("pointerenter", l.pointerenter);
        node.addEventListener("pointerleave", l.pointerleave);
        node.addEventListener("focusin", l.focusin);
      }
      sinkRef.current?.(node);
      assignRef(childRef, node);
    },
    [childRef],
  );

  // TooltipLayer hands its getReferenceProps up so the child is decorated
  // exactly as before (hook handlers first, then the child's own, and the
  // child's non-handler props winning), without the child moving in the tree.
  const [getRefProps, setGetRefProps] = useState<GetReferenceProps | null>(null);

  if (inert || !isValidElement(children)) {
    return children;
  }

  const childProps = children.props as HTMLAttributes<HTMLElement>;
  const trigger = cloneElement(children, {
    ...(getRefProps ? getRefProps({ ...childProps }) : null),
    ref: triggerRef,
  } as Partial<typeof childProps> & { ref: typeof triggerRef });

  return (
    <>
      {trigger}
      {armed && (
        <TooltipLayer
          content={content}
          side={side}
          gap={gap}
          maxWidth={maxWidth}
          showArrow={showArrow}
          controlledOpen={controlledOpen}
          delay={delay}
          tone={tone}
          nodeRef={nodeRef}
          sinkRef={sinkRef}
          intentRef={intentRef}
          armedByRef={armedByRef}
          onRefProps={setGetRefProps}
        />
      )}
    </>
  );
}

function TooltipLayer({
  content,
  side,
  gap,
  maxWidth,
  showArrow,
  controlledOpen,
  delay,
  tone,
  nodeRef,
  sinkRef,
  intentRef,
  armedByRef,
  onRefProps,
}: {
  content: ReactNode;
  side: TooltipSide;
  gap: number;
  maxWidth: number;
  showArrow: boolean;
  controlledOpen: boolean | undefined;
  delay: number;
  tone: NonNullable<TooltipProps["tone"]>;
  nodeRef: MutableRefObject<HTMLElement | null>;
  sinkRef: MutableRefObject<((node: HTMLElement | null) => void) | null>;
  intentRef: MutableRefObject<Intent>;
  armedByRef: MutableRefObject<ArmEvent | null>;
  onRefProps: (v: GetReferenceProps | null | ((prev: GetReferenceProps | null) => GetReferenceProps | null)) => void;
}) {
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
    enabled: controlledOpen === undefined,
    restMs: delay,
    delay: { close: 80 },
  });
  const focus = useFocus(context, {
    enabled: controlledOpen === undefined,
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

  // Become the trigger's floating reference: take the node it already has
  // and follow any later node change through the sink.
  const setReference = refs.setReference;
  useLayoutEffect(() => {
    sinkRef.current = setReference;
    setReference(nodeRef.current);
    return () => {
      if (sinkRef.current === setReference) sinkRef.current = null;
    };
  }, [setReference, sinkRef, nodeRef]);

  // Hand the interaction props to the trigger (before paint, so e.g. the
  // aria-describedby of an open tooltip lands in the same frame).
  useLayoutEffect(() => {
    onRefProps(() => getReferenceProps as GetReferenceProps);
  }, [getReferenceProps, onRefProps]);
  useLayoutEffect(() => () => onRefProps(null), [onRefProps]);

  // Replay the arming intent once the interactions are listening. useHover
  // attaches its native mouseenter/mouseleave listeners in an effect keyed on
  // the reference element, declared above, so on the commit where the
  // reference lands they are attached before this runs.
  const domReference = context.elements.domReference;
  const replayedRef = useRef(false);
  useEffect(() => {
    if (replayedRef.current || !(domReference instanceof Element)) return;
    replayedRef.current = true;
    const el = domReference;
    const active = el.ownerDocument.activeElement;
    const intent = intentRef.current;
    const plan = replayPlan({
      pointerInside: intent.pointerInside,
      focusInside: active != null && el.contains(active),
      armedBy: armedByRef.current,
      controlled: controlledOpen !== undefined,
      inert: false,
    });
    if (!plan.hover && !plan.focus) return;
    const handlers = getReferenceProps() as Record<string, ((e: unknown) => void) | undefined>;
    if (plan.hover) {
      const at = { clientX: intent.clientX, clientY: intent.clientY };
      // The pointer type first (useHover reads it for touch vs mouse), then
      // the entry useHover's native listener waits for, then a movement to
      // start the rest delay, which is what the entering mousemove did.
      handlers.onPointerEnter?.({ pointerType: intent.pointerType });
      el.dispatchEvent(new MouseEvent("mouseenter", at));
      handlers.onMouseMove?.({
        nativeEvent: new MouseEvent("mousemove", at),
        movementX: 0,
        movementY: 0,
      });
    }
    if (plan.focus && active) {
      // A plain event-like object: a real, already-dispatched event has an
      // empty composedPath(), which would skip useFocus's :focus-visible test.
      handlers.onFocus?.({
        nativeEvent: { type: "focusin", target: active },
        target: active,
        currentTarget: el,
        relatedTarget: intent.focusRelatedTarget,
      });
    }
    // Runs once, when the reference element first lands.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [domReference]);

  if (!isMounted) return null;
  return (
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
  Omit<TooltipProps, "children"> & { children: ReactNode; className?: string }
>(function TooltipSpan({ content, children, className, ...rest }, ref) {
  return (
    <Tooltip content={content} {...rest}>
      <span ref={ref} className={className} tabIndex={0}>
        {children}
      </span>
    </Tooltip>
  );
});
