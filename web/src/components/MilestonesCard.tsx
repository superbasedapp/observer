import { useEffect, useState } from "react";
import { fmtUSD } from "@/lib/format";
import { shareOrCopy } from "@/lib/share";
import {
  getOrCreateUsageAnchor,
  readUsageAnchor,
  writeUsageAnchor,
  type UsageAnchor,
} from "@/lib/usageAnchor";
import { HeroWordmark } from "@/components/HeroWordmark";
import { StarPrompt } from "@/components/StarPrompt";

// MilestonesCard — delight moment D-4 (usability arc P5.6 / review
// §9.3): small once-each milestone cards on Overview. Three
// milestones, in priority order:
//
//   saved10     — compression has saved ≥ $10 all-time
//   sessions100 — 100 sessions on the board
//   week        — one full week of capture since this install was
//                 first seen with data
//
// Restraint rules (§9.4, binding):
//   - max ONE card visible at a time; each fires once (node-local
//     flag set on dismiss — the card is permanently dismissable).
//   - existing installs retire already-crossed milestones SILENTLY
//     on first sight (the FirstCaptureToast precedent): a DB that
//     already has 600 sessions never sees "100 sessions", and
//     savings that predate the first look never fire "$10 saved".
//     The anchor records what was true at first sight so crossings
//     AFTER it still fire.
//   - gold "coin" accent + one ★ chip carry the celebration; body
//     copy stays in the calm register. No Obs cameo here — the chip
//     is the whole moment.
//   - zero steady-state traffic: the all-time savings fetch runs
//     only while the saved10 milestone is still undecided.
//
// Growth-review §4 upgrade (2026-07-30): each brag moment now also
// carries a share/copy action (same shareOrCopy plumbing as
// CommunityCard — native share sheet → clipboard → new tab; nothing
// auto-posted) alongside the unchanged dismiss control, plus a small
// corner wordmark so a raw screenshot of the celebratory bar still
// carries attribution. This card also mounts the lazygit-style
// once-only StarPrompt, reusing the same "one week of usage" anchor
// this file already writes (see lib/usageAnchor.ts) so the star nudge
// needs no new signal.

const FLAG = (k: string) => `sb_milestone_${k}`;

// An install first seen with this many sessions (or more) is treated
// as established — its "first week" already happened long ago, so the
// week milestone retires silently rather than firing months late.
const FRESH_INSTALL_MAX_SESSIONS = 50;
const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

function lsGet(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function lsSet(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    // ignore — milestones simply never fire without storage
  }
}

function fired(key: string): boolean {
  return lsGet(FLAG(key)) === "1";
}

function retire(key: string) {
  lsSet(FLAG(key), "1");
}

// readAnchor returns the stored usage anchor (shared with StarPrompt
// via lib/usageAnchor.ts), creating it on first sight of data and —
// ONLY at that creation moment — silently retiring already-crossed
// milestones.
function readAnchor(sessions: number): UsageAnchor {
  const preexisting = readUsageAnchor();
  const anchor = getOrCreateUsageAnchor(sessions);
  if (!preexisting) {
    if (sessions >= 100) retire("sessions100");
    if (sessions >= FRESH_INSTALL_MAX_SESSIONS) retire("week");
  }
  return anchor;
}

const COPY: Record<string, { chip: string; text: string }> = {
  saved10: {
    chip: "★ $10 SAVED ★",
    text: "Compression has paid for its config: $10 saved so far.",
  },
  sessions100: {
    chip: "★ 100 SESSIONS ★",
    text: "100 sessions on the board.",
  },
  week: {
    chip: "★ ONE WEEK ★",
    text: "One full week of sessions on the record.",
  },
};

export function MilestonesCard({ sessions }: { sessions: number | null }) {
  const [visible, setVisible] = useState<string | null>(null);
  // null = fetch pending or not needed; number = all-time $ saved.
  const [savedUSD, setSavedUSD] = useState<number | null>(null);
  const [shareState, setShareState] = useState<"idle" | "done">("idle");

  // Anchor create+retire pass runs synchronously during render — NOT
  // in an effect. Effects run bottom-up post-commit, so an
  // effect-based pass here previously let the freshly-mounted
  // StarPrompt fallback's own read race ahead and observe/create the
  // anchor first, skipping the retire-already-crossed-milestones step
  // on established installs (a stale "100 sessions" celebration long
  // after the fact). readAnchor only retires on the anchor's FIRST
  // creation, so calling it here on every render (including React
  // StrictMode's double-render) is idempotent and harmless.
  const anchor =
    sessions != null && sessions > 0 ? readAnchor(sessions) : null;

  // All-time compression savings — fetched once per mount, and only
  // while saved10 is still undecided.
  useEffect(() => {
    if (fired("saved10")) return;
    let cancelled = false;
    fetch("/api/compression/timeseries?days=36500&bucket=day")
      .then((r) => (r.ok ? r.json() : null))
      .then((data: { series?: { total_saved_usd_est: number }[] } | null) => {
        if (cancelled || !data?.series) return;
        setSavedUSD(
          data.series.reduce((sum, p) => sum + (p.total_saved_usd_est || 0), 0),
        );
      })
      .catch(() => {
        // ignore — milestone stays undecided until a later visit
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Eligibility pass — runs whenever the inputs settle. Priority
  // order is the plan's: $10 saved, then 100 sessions, then the week.
  useEffect(() => {
    if (sessions == null || sessions === 0 || !anchor) return;

    if (savedUSD != null && !fired("saved10")) {
      // First time we can see savings: record the baseline so a
      // crossing BEFORE we watched retires and one AFTER fires.
      if (anchor.saved_at_anchor == null) {
        anchor.saved_at_anchor = savedUSD;
        writeUsageAnchor(anchor);
        if (savedUSD >= 10) retire("saved10");
      } else if (savedUSD >= 10 && anchor.saved_at_anchor < 10) {
        setVisible("saved10");
        return;
      }
    }
    if (!fired("sessions100") && sessions >= 100) {
      setVisible("sessions100");
      return;
    }
    if (
      !fired("week") &&
      Date.now() - new Date(anchor.at).getTime() >= WEEK_MS
    ) {
      setVisible("week");
    }
  }, [sessions, savedUSD]);

  // No milestone due right now: fall through to the (independently
  // gated, once-only) star prompt rather than rendering nothing —
  // it uses the same usage anchor this file maintains.
  if (!visible || fired(visible)) {
    return <StarPrompt sessions={sessions} />;
  }
  const copy = COPY[visible];
  // saved10 fires once all-time savings cross the $10 threshold, but
  // the figure we SHOW must be the live total — not the literal "$10"
  // trigger. savedUSD is non-null here (saved10 only becomes visible
  // after the fetch resolves); we still guard and fall back to COPY.
  // The body uses the exact fmtUSD figure so it matches the Compression
  // page's "Dollars saved" KPI (same saved_usd_est sum); the chip
  // rounds down to whole dollars for the celebratory badge.
  const chip =
    visible === "saved10" && savedUSD != null
      ? `★ $${Math.floor(savedUSD).toLocaleString()} SAVED ★`
      : copy.chip;
  const text =
    visible === "saved10" && savedUSD != null
      ? `Compression has paid for its config: ${fmtUSD(savedUSD)} saved so far.`
      : copy.text;
  // Share text states the milestone plainly + the site — same honesty
  // gate as CommunityCard (quantified only from a real figure already
  // shown on-screen; no compression %-savings framing).
  const shareText =
    visible === "saved10" && savedUSD != null
      ? `SuperBased has saved me ${fmtUSD(savedUSD)} in AI coding costs so far - superbased.app`
      : visible === "sessions100"
        ? "100 AI coding sessions tracked with SuperBased - superbased.app"
        : "One full week of AI coding sessions tracked with SuperBased - superbased.app";
  const dismiss = () => {
    retire(visible);
    setVisible(null);
  };
  const share = async () => {
    const result = await shareOrCopy(shareText);
    if (result === "copied") {
      setShareState("done");
      window.setTimeout(() => setShareState("idle"), 2000);
    }
  };
  return (
    <section className="relative flex items-center gap-3 rounded-3 border border-[#F4A024]/35 bg-bg-2 px-4 py-2.5">
      <span
        aria-hidden
        className="inline-block h-2.5 w-2.5 shrink-0 rounded-full bg-[#F4A024]"
      />
      <span className="shrink-0 font-mono text-[10.5px] tracking-[0.1em] text-[#F4A024]">
        {chip}
      </span>
      <span className="min-w-0 flex-1 text-[12px] text-fg-2">{text}</span>
      <HeroWordmark variant="inline" className="hidden shrink-0 sm:inline" />
      <button
        type="button"
        onClick={share}
        className="shrink-0 text-[11px] font-medium text-accent hover:text-accent-strong"
      >
        {shareState === "done" ? "Copied ✓" : "Share"}
      </button>
      <button
        type="button"
        onClick={dismiss}
        className="shrink-0 text-[11px] text-fg-4 hover:text-fg-2"
        aria-label="Dismiss milestone"
      >
        ✕
      </button>
    </section>
  );
}
