import { useEffect, useState } from "react";
import { useApi } from "@/lib/useApi";
import { hasOneWeekOfUsage } from "@/lib/usageAnchor";
import { Icon } from "@/components/primitives";
import { Star, X } from "lucide-react";

// StarPrompt — lazygit-pattern once-only star nudge (docs/plans/
// growth-virality-product-review-2026-07-30.md §5 Tier 2, mechanic 5:
// "lazygit-style once-only star prompt"). Small, dismissible, and
// gated on real usage: it reuses MilestonesCard's existing
// `sb_milestones_anchor` "one week of sessions" signal via
// `hasOneWeekOfUsage` — no new backend, no new telemetry. Persists
// shown/dismissed in localStorage (`sb_star_prompt_shown`, following
// the sb_* key convention e.g. `sb_tour_completed`) and never
// re-prompts after dismissal OR after clicking through to GitHub.
// Never renders in demo mode (checked via the existing `/api/demo`
// endpoint, the same signal OnboardingCard / DemoBanner already use).

const REPO = "https://github.com/superbasedapp/observer";
const LS_KEY = "sb_star_prompt_shown";

function alreadyShown(): boolean {
  try {
    return localStorage.getItem(LS_KEY) === "1";
  } catch {
    return true;
  }
}

function markShown() {
  try {
    localStorage.setItem(LS_KEY, "1");
  } catch {
    // ignore — worst case it can show again next session
  }
}

export function StarPrompt({ sessions }: { sessions: number | null }) {
  const demo = useApi<{ available: boolean; active: boolean }>("/api/demo");
  const [dismissed, setDismissed] = useState<boolean>(alreadyShown);

  // Unknown demo state (still loading) or active demo: never show.
  const eligible =
    !dismissed &&
    demo.data != null &&
    !demo.data.active &&
    hasOneWeekOfUsage(sessions);

  // Mark shown the moment the prompt is actually presented (eligible
  // becomes true) — not only on dismiss/star click. This makes the
  // once-only guarantee hold even if the click handlers never fire
  // (e.g. the component unmounts before the operator interacts with
  // it): once it's been shown, it's been shown.
  useEffect(() => {
    if (eligible) markShown();
  }, [eligible]);

  if (!eligible) return null;

  const dismiss = () => {
    markShown();
    setDismissed(true);
  };
  const onStar = () => {
    // Once-only applies to a click-through too — the star ask does
    // not return next session just because the user didn't dismiss
    // it explicitly.
    markShown();
    setDismissed(true);
    window.open(REPO, "_blank", "noreferrer");
  };

  return (
    <section className="flex items-center gap-3 rounded-3 border border-line-2 bg-bg-2 px-4 py-2.5">
      <Icon icon={Star} size="sm" fill="currentColor" className="shrink-0 text-accent" />
      <span className="min-w-0 flex-1 text-[12px] text-fg-2">
        Enjoying SuperBased? A GitHub star helps a lot.
      </span>
      <button
        type="button"
        onClick={onStar}
        className="shrink-0 rounded-2 border border-accent/40 bg-accent-soft px-2.5 py-1 text-[11px] font-medium text-accent hover:bg-accent-soft/80"
      >
        Star on GitHub
      </button>
      <button
        type="button"
        onClick={dismiss}
        className="shrink-0 text-[11px] text-fg-4 hover:text-fg-2"
        aria-label="Dismiss"
      >
        <Icon icon={X} size="xs" />
      </button>
    </section>
  );
}
