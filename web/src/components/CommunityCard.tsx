import { useMemo, useState } from "react";
import { Obs } from "@/components/Obs";
import { Icon, Pill } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { fmtUSD } from "@/lib/format";
import {
  SHARE_SITE_URL,
  emailShareURL as buildEmailShareURL,
  linkedInShareURL as buildLinkedInShareURL,
  shareOrCopy,
  xShareURL as buildXShareURL,
} from "@/lib/share";
import type { MonthlyReport } from "@/lib/types";
import { Bug, Check, Github, Heart, Share2 } from "lucide-react";

// CommunityCard — the operator/node/developer "get involved" surface on the
// Overview setup page. Four honest calls to action: star the public repo,
// report a problem on GitHub Issues, share/refer Observer to a friend, and
// send feedback or a testimonial. No fabricated social proof — the
// TESTIMONIALS array below is empty by default and the section falls back to a
// "be the first" CTA; drop real quotes in when we have consent to publish.
//
// Matches the OnboardingCard idiom (raw section, calm body, one pixel-chip
// accent) rather than a chart shell — it's a persistent footer-style card, not
// a data panel, so it is not dismissable.
//
// Growth-review §4 upgrade (2026-07-30): the "Refer a friend" share payload
// is upgraded from a static generic link to an OPT-IN real personal stat —
// "$X tracked across N tools this month". The number comes from the SAME
// /api/report/monthly endpoint Report.tsx already renders (current month,
// all projects) — no new backend route. When there's no data yet (fresh
// install, zero sessions this month) the toggle has nothing to offer and the
// share falls back to the static link; it never renders "$0.00 tracked".
// The exact composed text is always visible above the share button before
// the user acts on it (honesty gate — they see what they'd post).

const REPO = "https://github.com/superbasedapp/observer";
const ISSUES = `${REPO}/issues`;
const SITE = SHARE_SITE_URL;
const CONTACT = "contact@superbased.app";

// Curated, consented testimonials. Empty until we have real ones to show —
// never invent quotes. When populated ({ quote, author, role? }), the section
// renders them instead of the collect-CTA.
const TESTIMONIALS: { quote: string; author: string; role?: string }[] = [];

// No appended URL here: X / email / the native share sheet all add
// the superbased.app link themselves via their own `url` param (see
// xShareURL / emailShareURL / shareOrCopy below) — appending it again
// in the text would double it up. LinkedIn's share intent only takes
// a url param at all (no text), so it never sees this string.
const SHARE_TEXT_STATIC =
  "I've been using SuperBased to see what my AI coding tools actually cost and do - it's worth a look";

function currentMonth(): string {
  return new Date().toISOString().slice(0, 7);
}

// buildPersonalStatText composes the opt-in personal-stat share line from
// this month's report totals, or returns null when there's nothing honest
// to say yet (no cost, no tools with spend this month). Gated on the
// ROUNDED display value, not the raw float — a sub-cent cost (e.g.
// $0.001) rounds to "$0.00" via fmtUSD, and we'd rather suppress the
// stat than let it render as "$0.00 tracked" (compare formatted
// strings, not `cost <= 0`, so any float that displays as $0.00 is
// caught). No trailing site URL — X / email / the native share sheet
// append it themselves (see the SHARE_TEXT_STATIC comment above).
function buildPersonalStatText(r: MonthlyReport | null): string | null {
  const cost = r?.totals?.cost_usd ?? 0;
  const toolCount = (r?.by_tool ?? []).filter((t) => t.cost_usd > 0).length;
  const displayCost = fmtUSD(cost);
  if (displayCost === fmtUSD(0) || toolCount <= 0) return null;
  return `${displayCost} tracked across ${toolCount} tool${toolCount === 1 ? "" : "s"} this month`;
}

function xShareURL(text: string): string {
  return buildXShareURL(text, SITE);
}
function linkedInShareURL(): string {
  return buildLinkedInShareURL(SITE);
}
function emailShareURL(text: string): string {
  return buildEmailShareURL("You should try SuperBased", text, SITE);
}
function feedbackURL(): string {
  const subject = encodeURIComponent("SuperBased - feedback / testimonial");
  return `mailto:${CONTACT}?subject=${subject}`;
}

function ActionTile({
  href,
  icon,
  title,
  desc,
}: {
  href: string;
  icon: React.ReactNode;
  title: string;
  desc: string;
}) {
  const external = href.startsWith("http");
  return (
    <a
      href={href}
      target={external ? "_blank" : undefined}
      rel={external ? "noreferrer noopener" : undefined}
      className="group flex items-start gap-3 rounded-2 border border-line-2 bg-bg-3 p-3 transition-colors hover:border-accent/40 hover:bg-accent-soft/40"
    >
      <span className="mt-0.5 shrink-0 text-fg-3 group-hover:text-accent">{icon}</span>
      <span className="min-w-0">
        <span className="block text-[12px] font-semibold text-fg-1 group-hover:text-accent">{title}</span>
        <span className="mt-0.5 block text-[11px] text-fg-4">{desc}</span>
      </span>
    </a>
  );
}

// CommunityLinksMini — a compact community/support link cluster for surfaces
// that want the "get involved" links without the full Overview card (e.g. the
// Settings left rail). Reuses the same REPO/ISSUES/feedback constants so the
// links stay single-sourced with the card above.
export function CommunityLinksMini() {
  return (
    <div className="mt-4 rounded-2 border border-line-1 bg-bg-2 px-3 py-2 text-[10.5px] text-fg-3">
      <div className="mb-1 font-semibold uppercase tracking-[0.06em] text-fg-3">
        Community &amp; support
      </div>
      <ul className="space-y-1">
        <li>
          <a href={REPO} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1.5 font-medium text-fg-2 hover:text-accent">
            <Icon icon={Github} size="xs" /> Star on GitHub
          </a>
        </li>
        <li>
          <a href={ISSUES} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1.5 font-medium text-fg-2 hover:text-accent">
            <Icon icon={Bug} size="xs" /> Report a problem
          </a>
        </li>
        <li>
          <a href={feedbackURL()} className="inline-flex items-center gap-1.5 font-medium text-fg-2 hover:text-accent">
            <Icon icon={Heart} size="xs" /> Send feedback
          </a>
        </li>
      </ul>
    </div>
  );
}

export function CommunityCard() {
  const [shared, setShared] = useState<"idle" | "copied">("idle");
  // Opt-in — off by default; the user actively chooses to include a real
  // number in what they post. Disabled (and forced off) when there's
  // nothing honest to show yet.
  const [includeStats, setIncludeStats] = useState(false);

  const monthly = useApi<MonthlyReport>(
    "/api/report/monthly",
    { month: currentMonth() },
    [],
  );
  const personalStat = useMemo(
    () => buildPersonalStatText(monthly.data),
    [monthly.data],
  );
  const shareText =
    includeStats && personalStat ? personalStat : SHARE_TEXT_STATIC;

  const share = async () => {
    const result = await shareOrCopy(shareText, { url: SITE });
    if (result === "copied") {
      setShared("copied");
      window.setTimeout(() => setShared("idle"), 2000);
    }
  };

  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 p-5">
      <div className="flex items-start gap-4">
        <Obs state="idle" size={40} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h2 className="text-[14px] font-semibold text-fg-0">Community &amp; support</h2>
            <Pill variant="accent">open source</Pill>
          </div>
          <p className="mt-1 text-[12px] text-fg-3">
            SuperBased is open source and built in the open. A star helps others find it,
            issues get fixed fast, and a share goes a long way.
          </p>

          <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
            <ActionTile
              href={REPO}
              icon={<Icon icon={Github} size="md" />}
              title="Star us on GitHub"
              desc="If SuperBased is useful, a star helps other developers find it."
            />
            <ActionTile
              href={ISSUES}
              icon={<Icon icon={Bug} size="md" />}
              title="Report a problem"
              desc="Hit a bug or have a request? Open a GitHub issue."
            />
            <button
              type="button"
              onClick={share}
              className="group flex items-start gap-3 rounded-2 border border-line-2 bg-bg-3 p-3 text-left transition-colors hover:border-accent/40 hover:bg-accent-soft/40"
            >
              <span className="mt-0.5 shrink-0 text-fg-3 group-hover:text-accent">
                <Icon icon={Share2} size="md" />
              </span>
              <span className="min-w-0">
                <span className="block text-[12px] font-semibold text-fg-1 group-hover:text-accent">
                  {shared === "copied" ? (
                    <span className="inline-flex items-center gap-1">
                      Copied <Icon icon={Check} size="xs" />
                    </span>
                  ) : (
                    "Refer a friend"
                  )}
                </span>
                <span className="mt-0.5 block text-[11px] text-fg-4">
                  Share SuperBased with someone who'd find it useful.
                </span>
              </span>
            </button>
            <ActionTile
              href={feedbackURL()}
              icon={<Icon icon={Heart} size="md" />}
              title="Send feedback"
              desc={`Tell us what works (or doesn't) - ${CONTACT}.`}
            />
          </div>

          {/* Share payload preview - the exact text below is what
              "Refer a friend" / X / LinkedIn / email will post; the
              operator sees it before acting, never a hidden payload. */}
          <div className="mt-3 rounded-2 border border-line-2 bg-bg-3 px-3 py-2">
            <label className="flex items-center gap-2 text-[11px] text-fg-3">
              <input
                type="checkbox"
                checked={includeStats}
                disabled={!personalStat}
                onChange={(e) => setIncludeStats(e.target.checked)}
                className="h-3 w-3 shrink-0 rounded-1 border-line-2 accent-accent disabled:opacity-40"
              />
              <span>
                Include this month's stats in the share
                {!personalStat && (
                  <span className="text-fg-4"> (nothing tracked yet this month)</span>
                )}
              </span>
            </label>
            <p className="mt-1.5 truncate text-[11px] italic text-fg-2">
              &ldquo;{shareText}&rdquo;
            </p>
            <p className="mt-1.5 text-[10.5px] text-fg-4">
              X, email, and the native share sheet add the superbased.app
              link automatically. LinkedIn shares the link only - no text.
            </p>
          </div>

          {/* Direct share links (fallback + reach) */}
          <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-fg-4">
            <span>Share via</span>
            <a href={xShareURL(shareText)} target="_blank" rel="noreferrer noopener" className="font-medium text-accent hover:underline">
              X
            </a>
            <a href={linkedInShareURL()} target="_blank" rel="noreferrer noopener" className="font-medium text-accent hover:underline">
              LinkedIn
            </a>
            <a href={emailShareURL(shareText)} className="font-medium text-accent hover:underline">
              email
            </a>
          </div>

          {/* Testimonials & feedback */}
          <div className="mt-4 border-t border-line-2 pt-3">
            {TESTIMONIALS.length > 0 ? (
              <div className="space-y-2">
                <h3 className="text-[11.5px] font-semibold text-fg-2">What people say</h3>
                {TESTIMONIALS.map((t) => (
                  <blockquote key={t.author} className="rounded-2 border border-line-2 bg-bg-3 p-3">
                    <p className="text-[12px] italic text-fg-2">&ldquo;{t.quote}&rdquo;</p>
                    <footer className="mt-1 text-[11px] text-fg-4">
                      - {t.author}
                      {t.role ? `, ${t.role}` : ""}
                    </footer>
                  </blockquote>
                ))}
              </div>
            ) : (
              <p className="text-[11.5px] text-fg-3">
                <span className="font-medium text-fg-2">Testimonials &amp; feedback.</span>{" "}
                SuperBased save you time or money?{" "}
                <a href={feedbackURL()} className="font-medium text-accent hover:underline">
                  Send us a testimonial
                </a>{" "}
                - we'd love to hear how you use it, and we may feature it (with your OK).
              </p>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
