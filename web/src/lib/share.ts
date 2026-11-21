// share.ts — shared "render locally, user posts it themselves" share
// plumbing used by CommunityCard and MilestonesCard (docs/plans/
// growth-virality-product-review-2026-07-30.md §4). No network calls;
// nothing is auto-posted. Native share sheet first, clipboard second,
// a new tab opening the site as the last resort.

export const SHARE_SITE_URL = "https://superbased.app/";
export const SHARE_SITE_LABEL = "superbased.app";

export type ShareResult = "shared" | "copied" | "opened" | "failed";

// shareOrCopy attempts the native Web Share API first (mobile / some
// desktop browsers); falls back to copying `text` to the clipboard;
// falls back further to opening the site in a new tab. Never throws —
// callers use the returned outcome to drive a small "copied ✓" style
// confirmation.
export async function shareOrCopy(
  text: string,
  opts?: { title?: string; url?: string },
): Promise<ShareResult> {
  const url = opts?.url ?? SHARE_SITE_URL;
  try {
    if (typeof navigator !== "undefined" && navigator.share) {
      await navigator.share({ title: opts?.title ?? "superbased", text, url });
      return "shared";
    }
  } catch {
    // user cancelled or share failed — fall through to copy
  }
  try {
    await navigator.clipboard.writeText(text);
    return "copied";
  } catch {
    try {
      window.open(url, "_blank", "noreferrer");
      return "opened";
    } catch {
      return "failed";
    }
  }
}

export function xShareURL(text: string, url: string = SHARE_SITE_URL): string {
  const p = new URLSearchParams({ text, url });
  return `https://twitter.com/intent/tweet?${p.toString()}`;
}

export function linkedInShareURL(url: string = SHARE_SITE_URL): string {
  const p = new URLSearchParams({ url });
  return `https://www.linkedin.com/sharing/share-offsite/?${p.toString()}`;
}

export function emailShareURL(
  subject: string,
  text: string,
  url: string = SHARE_SITE_URL,
): string {
  const s = encodeURIComponent(subject);
  const b = encodeURIComponent(`${text}\n\n${url}`);
  return `mailto:?subject=${s}&body=${b}`;
}
