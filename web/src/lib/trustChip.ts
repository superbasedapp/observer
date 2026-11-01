// The New Terminal dialog's repository trust chip and its review panel
// (security pillar plan section 5.1, Phase B; component security.trust). It
// reads GET /api/security/trust?dir=<project root>, the same read-only check
// the launch runs, words it for the dialog, and accepts from the dialog
// through POST /api/security/trust (owner-local, confirm token), so a
// repository the check reports as untrusted is never a CLI-only dead end. A
// route that does not answer (an older daemon, the component inactive or not
// selected under [components]: 404) renders no chip. Where the dashboard
// accept would be refused (a managed node whose organization hides the Code
// security page: accept_allowed false) the dialog hides Accept and shows the
// reply's accept_note, which says who can accept (plans decision log P-031).

export type TrustReason = {
  code: string;
  level: string;
  file: string;
  key?: string;
  excerpt?: string;
  indicators?: string[];
  files?: string[];
  digest?: string;
  local?: boolean;
  accepted?: boolean;
};

export type TrustReply = {
  root?: string;
  verdict: string;
  codes: string[];
  pending: number;
  truncated?: boolean;
  reasons: TrustReason[];
  accepted?: number;
  confirm_token?: string;
  // accept_allowed is false when the dashboard accept would be concealed or
  // refused; an older daemon omits it (its accept was always offered).
  accept_allowed?: boolean;
  // accept_note says who can accept when accept_allowed is false.
  accept_note?: string;
};

// acceptOffered reports whether the dialog offers Accept for a reply.
export function acceptOffered(reply: TrustReply | null): boolean {
  return !!reply && reply.accept_allowed !== false;
}

// acceptNote is the line the review panel shows in place of the Accept
// buttons, or null when Accept is offered.
export function acceptNote(reply: TrustReply | null): string | null {
  if (!reply || acceptOffered(reply)) return null;
  return reply.accept_note || "Accepting is not offered in this dashboard. Accept in your own terminal with `observer security trust accept`.";
}

// TrustAcceptBody is the POST body: the named digests, or every pending one.
export type TrustAcceptBody = { dir: string; digests?: string[]; all?: boolean };

// pendingReasons are the reasons the developer can still accept: each
// carries a digest and is not accepted yet.
export function pendingReasons(reply: TrustReply | null): TrustReason[] {
  if (!reply) return [];
  return reply.reasons.filter((r) => !!r.digest && !r.accepted);
}

// acceptAllBody is the body that accepts every pending item the dialog
// displays, or null when nothing is pending. It names their digests rather
// than asking for "all": the server then accepts exactly what was shown,
// and refuses the whole accept if the check no longer reports one of them
// (the repository changed after the dialog read it). So it is safe over a
// truncated result too: nothing unseen is accepted.
export function acceptAllBody(dir: string, reply: TrustReply | null): TrustAcceptBody | null {
  if (!acceptOffered(reply)) return null;
  const digests = pendingReasons(reply).map((r) => r.digest as string);
  if (digests.length === 0) return null;
  return { dir, digests: Array.from(new Set(digests)) };
}

// acceptOneBody accepts one reviewed item.
export function acceptOneBody(dir: string, reason: TrustReason): TrustAcceptBody | null {
  if (!reason.digest || reason.accepted) return null;
  return { dir, digests: [reason.digest] };
}

// reasonLine is one review row's heading: the level, the code, the file and
// key, and "local settings file" for a reason in one of the files the check
// treats as the developer's own. That is decided by the file's path alone
// (a gitignored settings.local file, .git/config, a dotenv file), not by who
// wrote it, so the wording stays neutral.
export function reasonLine(r: TrustReason): string {
  const where = r.key ? `${r.file} ${r.key}` : r.file;
  const own = r.local ? " (local settings file)" : "";
  return `${r.level} ${r.code}: ${where}${own}`;
}

export type TrustChip = {
  tone: "ok" | "warn" | "danger";
  label: string;
  detail: string;
};

// trustPath is the chip's request path for one directory.
export function trustPath(dir: string): string {
  return "/api/security/trust?dir=" + encodeURIComponent(dir);
}

// trustChip words a reply; null renders no chip.
export function trustChip(reply: TrustReply | null): TrustChip | null {
  if (!reply) return null;
  const codes = reply.codes.length > 0 ? reply.codes.join(", ") : "";
  const cut = reply.truncated ? " Some entries were not read." : "";
  switch (reply.verdict) {
    case "clean":
      return { tone: "ok", label: "Repository trusted", detail: "No agent config here makes an agent run anything." };
    case "flagged":
      return {
        tone: "warn",
        label: "Repository flagged",
        detail: `Worth a look before launching: ${codes}.${cut}`,
      };
    case "untrusted": {
      const next = acceptOffered(reply) ? "review and accept them below" : "review them below";
      const pending = reply.pending > 0 ? ` ${reply.pending} item(s) not accepted yet: ${next}.` : "";
      return {
        tone: "danger",
        label: "Repository untrusted",
        detail: `The launch may ask or refuse: ${codes}.${pending}${cut}`,
      };
    }
    default:
      return null;
  }
}
