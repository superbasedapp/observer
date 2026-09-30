import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import {
  arrow,
  autoUpdate,
  flip,
  FloatingArrow,
  FloatingPortal,
  offset,
  shift,
  useFloating,
  type Placement,
} from "@floating-ui/react";
import { useTour } from "./TourProvider";
import type { TourStep } from "@/lib/tour";

// TourOverlay — the spotlight + coach-mark primitive. Its own lazy chunk
// (loaded only while the tour is active). Model: "dialog always present,
// spotlight upgrades in".
//
// The coach-mark bubble (a focus-trapping role="dialog") is rendered from
// the instant a step activates, as a CENTERED card — so there is never a
// dimmed, bubble-less, focus-trap-less wait. The step's anchor is resolved
// in the background; once it is found AND intersects the viewport, the same
// step UPGRADES to an anchored spotlight (floating-ui + box-shadow cutout).
// If the anchor is missing (after a real 2s bound) or is off-canvas chrome
// that we can't bring on-screen (e.g. a mobile nav drawer), the step simply
// stays a centered card with the same copy.
//
// Per-step resolution state lives inside TourStepView, which is keyed by
// step.id — so a new step mounts fresh and can never render using the
// previous step's target or rect.
//
// Copy is rendered as text nodes only. Tokens only — correct in both themes.

const POLL_TIMEOUT_MS = 2000;
const DIM = "rgba(0,0,0,0.55)";
// Matches the --ease design token (tokens.css) as a cubic-bezier tuple.
const EASE: [number, number, number, number] = [0.2, 0.7, 0.2, 1];

function rectHasSize(r: DOMRect): boolean {
  return r.width > 0 && r.height > 0;
}

// Does the rect intersect the viewport at all? Off-canvas chrome (e.g. the
// mobile nav drawer, translated fully off-screen) fails this even though the
// element exists — for those we keep the centered card rather than draw a
// broken spotlight in the void.
function inViewport(r: DOMRect): boolean {
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  return !(r.right <= 0 || r.left >= vw || r.bottom <= 0 || r.top >= vh);
}

// A target rect is only "usable" for a spotlight when it has real size AND
// intersects the viewport. Used by the live scroll/resize re-sync.
function usableRect(el: Element | null): DOMRect | null {
  if (!el) return null;
  const r = el.getBoundingClientRect();
  if (!rectHasSize(r)) return null;
  if (!inViewport(r)) return null;
  return r;
}

function prefersReducedMotion(): boolean {
  try {
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  } catch {
    return false;
  }
}

export function TourOverlay() {
  const { active, stepIndex, steps, next, back, endTour } = useTour();

  const step: TourStep | undefined = steps[stepIndex];
  const total = steps.length;
  const isLast = stepIndex === total - 1;
  const isFirst = stepIndex === 0;

  const advance = useCallback(() => {
    if (isLast) endTour(true);
    else next();
  }, [isLast, endTour, next]);

  if (!active || !step) return null;

  // Keyed by step.id: each step gets a fresh TourStepView, so per-step
  // resolution state (rect / target) can never outlive its step.
  return (
    <TourStepView
      key={step.id}
      step={step}
      stepIndex={stepIndex}
      total={total}
      isFirst={isFirst}
      isLast={isLast}
      onNext={advance}
      onBack={back}
      onSkip={() => endTour(true)}
    />
  );
}

// Placement resolution: "auto" (or unset) → "bottom"; floating-ui's flip()
// re-derives the real side against the viewport.
function toPlacement(p: TourStep["placement"]): Placement {
  if (!p || p === "auto") return "bottom";
  return p;
}

function TourStepView({
  step,
  stepIndex,
  total,
  isFirst,
  isLast,
  onNext,
  onBack,
  onSkip,
}: {
  step: TourStep;
  stepIndex: number;
  total: number;
  isFirst: boolean;
  isLast: boolean;
  onNext: () => void;
  onBack: () => void;
  onSkip: () => void;
}) {
  const navigate = useNavigate();
  const location = useLocation();

  const arrowRef = useRef<SVGSVGElement | null>(null);
  const bubbleRef = useRef<HTMLDivElement | null>(null);
  const primaryRef = useRef<HTMLButtonElement | null>(null);
  const reducedRef = useRef(prefersReducedMotion());
  const reduced = reducedRef.current;

  // The measured anchor rect, or null for a centered card. Starts null so
  // the dialog paints centered immediately, then upgrades to a spotlight
  // once resolution finds an on-screen anchor. State is local to this keyed
  // component, so it resets synchronously when the step changes.
  const [rect, setRect] = useState<DOMRect | null>(null);
  const targetRef = useRef<HTMLElement | null>(null);
  const spotlight = rect != null;

  // --- Navigate to the step's route (once, on mount) -------------------
  useEffect(() => {
    if (step.path && location.pathname !== step.path) {
      navigate(step.path);
    }
    // Run once per step mount. location.pathname intentionally excluded:
    // anchors are always-mounted chrome, so we don't re-run mid-navigation.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // --- Resolve the current step's anchor -------------------------------
  // Poll (rAF) for the target to appear. When found with real size, scroll
  // it into view FIRST, then measure viewport intersection on the NEXT
  // frame: on-screen → upgrade to spotlight; still off-canvas (e.g. a mobile
  // drawer) → stay centered immediately. A real setTimeout bounds the whole
  // resolve independently of rAF (which browsers throttle in hidden tabs);
  // both timers are cleared together on unmount / step change.
  useEffect(() => {
    if (!step.target) return; // centered card — nothing to resolve.

    let cancelled = false;
    let rafId = 0;

    const timeoutId = window.setTimeout(() => {
      // Hard 2s bound: stop polling. If nothing resolved, stay centered.
      cancelled = true;
      if (rafId) cancelAnimationFrame(rafId);
    }, POLL_TIMEOUT_MS);

    const measureAndUpgrade = (el: HTMLElement) => {
      rafId = requestAnimationFrame(() => {
        if (cancelled) return;
        const r = el.getBoundingClientRect();
        if (rectHasSize(r) && inViewport(r)) {
          targetRef.current = el;
          setRect(r); // upgrade to spotlight
        } else {
          // On-screen scroll couldn't bring it into view (off-canvas
          // chrome). Keep the centered card with the same copy.
          targetRef.current = null;
          setRect(null);
        }
        window.clearTimeout(timeoutId);
      });
    };

    const poll = () => {
      if (cancelled) return;
      const el = document.querySelector(step.target as string) as
        | HTMLElement
        | null;
      if (el) {
        const r0 = el.getBoundingClientRect();
        if (rectHasSize(r0)) {
          // Present with real size — scroll into view BEFORE deciding
          // whether it's usable, so a below-the-fold anchor isn't rejected
          // as "off-screen". Instant scroll keeps the next-frame
          // intersection measurement meaningful (a smooth scroll would still
          // be mid-flight a frame later and misclassify as off-screen).
          el.scrollIntoView({
            block: "center",
            inline: "nearest",
            behavior: "auto",
          });
          measureAndUpgrade(el);
          return;
        }
      }
      rafId = requestAnimationFrame(poll);
    };

    rafId = requestAnimationFrame(poll);

    return () => {
      cancelled = true;
      if (rafId) cancelAnimationFrame(rafId);
      window.clearTimeout(timeoutId);
    };
    // Runs once per keyed step mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // --- Keep the rect in sync on scroll / resize / target resize --------
  useEffect(() => {
    if (!spotlight || !targetRef.current) return;
    const recompute = () => {
      // If the target slid out of view mid-step, drop to centered rather
      // than chase a rect off-screen.
      setRect(usableRect(targetRef.current));
    };
    window.addEventListener("scroll", recompute, true);
    window.addEventListener("resize", recompute);
    const ro = new ResizeObserver(recompute);
    if (targetRef.current) ro.observe(targetRef.current);
    return () => {
      window.removeEventListener("scroll", recompute, true);
      window.removeEventListener("resize", recompute);
      ro.disconnect();
    };
  }, [spotlight]);

  const { refs, floatingStyles, context } = useFloating({
    placement: toPlacement(step.placement),
    strategy: "fixed",
    middleware: [offset(12), flip({ padding: 12 }), shift({ padding: 12 }), arrow({ element: arrowRef })],
    whileElementsMounted: autoUpdate,
  });

  // Anchor the floating bubble to a virtual reference reading the live
  // target rect (so autoUpdate tracks scroll/resize). Only in spotlight mode.
  useLayoutEffect(() => {
    if (!spotlight) return;
    refs.setReference({
      getBoundingClientRect: () =>
        targetRef.current?.getBoundingClientRect() ?? (rect as DOMRect),
    });
  }, [spotlight, rect, refs]);

  // Focus the primary (Next / Finish) button when the step mounts — the
  // dialog is present from the first frame, so focus is trapped throughout.
  useEffect(() => {
    const id = requestAnimationFrame(() => primaryRef.current?.focus());
    return () => cancelAnimationFrame(id);
  }, []);

  // Global keys: Escape = skip, ArrowRight/Enter = next, ArrowLeft = back.
  // Capture phase + stopImmediatePropagation for OWNED keys so background
  // React handlers / earlier document listeners can't also process them.
  // Enter is left alone when a bubble button already has focus so it doesn't
  // double-fire (native activation + this handler).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const own = () => {
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();
      };
      if (e.key === "Escape") {
        own();
        onSkip();
      } else if (e.key === "ArrowRight") {
        own();
        onNext();
      } else if (e.key === "ArrowLeft") {
        own();
        onBack();
      } else if (e.key === "Enter") {
        const el = document.activeElement;
        if (el instanceof HTMLButtonElement && bubbleRef.current?.contains(el)) {
          return; // let the focused button handle it
        }
        own();
        onNext();
      }
    };
    document.addEventListener("keydown", onKey, true);
    return () => document.removeEventListener("keydown", onKey, true);
  }, [onNext, onBack, onSkip]);

  // Simple focus trap: keep Tab focus cycling within the bubble.
  const onBubbleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key !== "Tab") return;
    const root = bubbleRef.current;
    if (!root) return;
    const focusables = root.querySelectorAll<HTMLElement>(
      'button:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
    );
    if (focusables.length === 0) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const activeEl = document.activeElement as HTMLElement | null;
    if (e.shiftKey) {
      if (activeEl === first || !root.contains(activeEl)) {
        e.preventDefault();
        last.focus();
      }
    } else {
      if (activeEl === last || !root.contains(activeEl)) {
        e.preventDefault();
        first.focus();
      }
    }
  }, []);

  const pad = step.spotlightPadding ?? 6;
  const titleId = `tour-title-${step.id}`;
  const progress = ((stepIndex + 1) / total) * 100;

  const cutoutStyle: CSSProperties | undefined = spotlight
    ? {
        position: "fixed",
        top: rect!.top - pad,
        left: rect!.left - pad,
        width: rect!.width + pad * 2,
        height: rect!.height + pad * 2,
        borderRadius: "var(--r-3)",
        boxShadow: `0 0 0 9999px ${DIM}`,
        pointerEvents: "none",
        transition: reduced ? undefined : "top 160ms var(--ease), left 160ms var(--ease), width 160ms var(--ease), height 160ms var(--ease)",
      }
    : undefined;

  const bubbleInner = (
    <div
      ref={bubbleRef}
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      onKeyDown={onBubbleKeyDown}
      className="pointer-events-auto w-[320px] max-w-[calc(100vw-24px)] overflow-hidden rounded-3 border border-line-2 bg-bg-1 shadow-drawer"
    >
      {/* Thin progress bar across the top. */}
      <div className="h-1 w-full bg-line-2">
        <div
          className="h-full w-full origin-left bg-accent"
          style={{
            // scaleX, never an animated width.
            transform: `scaleX(${Math.max(0, Math.min(100, progress)) / 100})`,
            transition: reduced ? undefined : "transform 200ms var(--ease)",
          }}
        />
      </div>
      <div className="p-4">
        <div className="mb-1 font-mono text-[10.5px] tracking-[0.08em] text-fg-3">
          {stepIndex + 1} / {total}
        </div>
        <h2 id={titleId} className="text-[14px] font-semibold text-fg-0">
          {step.title}
        </h2>
        <p className="mt-1.5 text-[12.5px] leading-relaxed text-fg-2">
          {step.body}
        </p>
        <div className="mt-4 flex items-center justify-between gap-2">
          <button
            type="button"
            onClick={onSkip}
            className="rounded-2 px-2 py-1.5 text-[11.5px] font-medium text-fg-3 transition-colors hover:text-fg-1"
          >
            Skip tour
          </button>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onBack}
              disabled={isFirst}
              className="rounded-2 border border-line-2 bg-bg-2 px-3 py-1.5 text-[11.5px] font-medium text-fg-2 transition-colors hover:bg-bg-3 hover:text-fg-0 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Back
            </button>
            <button
              ref={primaryRef}
              type="button"
              onClick={onNext}
              className="rounded-2 bg-accent px-3 py-1.5 text-[11.5px] font-semibold text-accent-on transition-colors hover:bg-accent-strong"
            >
              {isLast ? "Finish" : "Next"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  const bubbleMotion = reduced
    ? { initial: false as const, animate: {}, transition: { duration: 0 } }
    : {
        initial: { opacity: 0, scale: 0.97 },
        animate: { opacity: 1, scale: 1 },
        transition: { duration: 0.16, ease: EASE },
      };

  return (
    <>
      {/* Full-viewport catcher — swallows clicks so the user follows the
          bubble's controls. In centered mode it also carries the dim tint;
          in spotlight mode the cutout's box-shadow provides the tint. The
          bubble lives in a separate portal above this layer, so it still
          receives clicks. */}
      <div
        aria-hidden
        className="fixed inset-0 z-[120]"
        style={{ background: spotlight ? "transparent" : DIM }}
        onMouseDown={(e) => e.preventDefault()}
      >
        {spotlight && <div style={cutoutStyle} />}
      </div>

      <FloatingPortal>
        {spotlight ? (
          <div
            ref={refs.setFloating}
            style={floatingStyles}
            className="z-[130]"
          >
            <motion.div {...bubbleMotion}>
              {bubbleInner}
              <FloatingArrow
                ref={arrowRef}
                context={context}
                width={12}
                height={6}
                fill="var(--bg-1)"
                stroke="var(--line-2)"
                strokeWidth={1}
              />
            </motion.div>
          </div>
        ) : (
          <div className="fixed inset-0 z-[130] grid place-items-center p-4">
            <AnimatePresence>
              <motion.div {...bubbleMotion}>{bubbleInner}</motion.div>
            </AnimatePresence>
          </div>
        )}
      </FloatingPortal>
    </>
  );
}
