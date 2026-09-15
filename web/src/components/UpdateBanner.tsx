import { useState } from "react";
import { Link } from "react-router-dom";
import { useApi } from "@/lib/useApi";
import type { UpdateStatusResponse } from "@/lib/types";

// UpdateBanner - the slim strip under the TopBar when the ORG has something to
// say about this node's version (enterprise update management §3.10, W5).
//
// It is NOT the npm update pill in the TopBar. That one asks the public
// registry when a human clicks; this one reports what the org server has
// already told this daemon on the push cycle it was running anyway. On an
// enrolled node the org's answer is the one that decides, which is why it gets
// a banner and the registry check does not.
//
// One loopback GET on mount and NO polling: everything it renders was written
// to this daemon by the push cycle, so re-asking on a timer would learn nothing
// the next navigation would not. Nothing here contacts the network.
//
// Three conditions fire, in severity order:
//
//   1. The org REFUSED this node's push because it is below the org's minimum
//      version. Nothing is reaching the org at all, so this is not
//      dismissible-by-version: it clears when the node is updated.
//   2. The node cannot apply an update it has been offered (an npm/brew-owned
//      binary), which needs a human with the right package manager.
//   3. An update is available or an apply failed.
//
// The acknowledgement key carries the TARGET VERSION, the BudgetBanner pattern:
// dismissing acknowledges THIS version, and the next one fires again.
const ACK_KEY = "sb_update_ack";

function acks(): Record<string, true> {
  try {
    return JSON.parse(localStorage.getItem(ACK_KEY) ?? "{}") as Record<
      string,
      true
    >;
  } catch {
    return {};
  }
}

// firing decides what, if anything, this banner says. Exported for the unit
// test: it is the whole decision, and it is pure.
export type UpdateBannerNotice = {
  key: string;
  tone: "danger" | "warn" | "accent";
  label: string;
  body: string;
  dismissible: boolean;
};

export function updateBannerNotice(
  d: UpdateStatusResponse | null | undefined,
): UpdateBannerNotice | null {
  if (!d || !d.enabled) return null;
  if (d.org_refusal) {
    const min = d.org_refusal.min_version;
    return {
      key: `refused|${min ?? ""}`,
      tone: "danger",
      label: "Not sharing with your org",
      body: min
        ? `Your org requires observer ${min} or newer and is refusing this node's data until it is updated.`
        : d.org_refusal.message,
      // Not dismissible: the condition is that nothing is reaching the org,
      // and a dismissed banner would leave a developer believing otherwise.
      dismissible: false,
    };
  }
  if (d.state === "blocked" && !d.self_apply) {
    return {
      key: `blocked|${d.target_version ?? ""}|${d.install_method ?? ""}`,
      tone: "warn",
      label: "Update needs you",
      body:
        (d.target_version
          ? `Your org has published ${d.target_version}. `
          : "Your org has published an update. ") +
        (d.advice ?? "This node cannot replace its own binary."),
      dismissible: true,
    };
  }
  if (d.state === "failed" || d.state === "rolled_back") {
    return {
      key: `${d.state}|${d.target_version ?? ""}`,
      tone: "warn",
      label: d.state === "failed" ? "Update failed" : "Update rolled back",
      body:
        (d.target_version ? `The update to ${d.target_version} did not complete` : "The last update did not complete") +
        (d.error_class ? ` (failed at the ${d.error_class} step).` : ".") +
        " This node is still running its previous version.",
      dismissible: true,
    };
  }
  if (d.state === "available" && d.target_version) {
    return {
      key: `available|${d.target_version}`,
      tone: "accent",
      label: "Update available",
      body: d.auto_apply
        ? `Your org has published ${d.target_version}. This node applies updates automatically and will install it in its next maintenance window.`
        : `Your org has published ${d.target_version}. Run \`observer update apply\` to install it.`,
      dismissible: true,
    };
  }
  return null;
}

const toneClass: Record<UpdateBannerNotice["tone"], { strip: string; label: string }> = {
  danger: {
    strip: "border-danger/30 bg-danger-soft",
    label: "font-semibold text-danger",
  },
  warn: {
    strip: "border-warn/30 bg-warn-soft",
    label: "font-semibold text-warn",
  },
  accent: {
    strip: "border-accent/30 bg-accent-soft",
    label: "font-semibold text-accent",
  },
};

export function UpdateBanner() {
  const st = useApi<UpdateStatusResponse>("/api/update/status");
  const [, bump] = useState(0);
  const notice = updateBannerNotice(st.data);
  if (!notice) return null;
  const acked = acks();
  if (notice.dismissible && acked[notice.key]) return null;
  const style = toneClass[notice.tone];

  const dismiss = () => {
    const next = acks();
    next[notice.key] = true;
    try {
      localStorage.setItem(ACK_KEY, JSON.stringify(next));
    } catch {
      // Storage unavailable - the banner stays; nothing breaks.
    }
    bump((n) => n + 1);
  };

  return (
    <div
      role="status"
      data-testid="update-banner"
      className={`flex items-center gap-2 border-b px-4 py-1.5 text-[11.5px] text-fg-2 ${style.strip}`}
    >
      <span className={style.label}>{notice.label}</span>
      <span className="min-w-0 truncate">{notice.body}</span>
      <div className="flex-1" />
      <Link
        to="/settings?section=health"
        className="shrink-0 text-[11px] font-medium text-accent hover:text-accent-strong"
      >
        Details →
      </Link>
      {notice.dismissible && (
        <button
          type="button"
          onClick={dismiss}
          className="shrink-0 rounded-2 border border-line-2 bg-bg-2 px-2 py-0.5 text-fg-2 hover:bg-bg-3"
        >
          dismiss
        </button>
      )}
    </div>
  );
}
