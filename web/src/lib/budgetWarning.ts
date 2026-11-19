// budgetWarning - the pure model behind the developer-facing ORG budget
// warning banner + toast (components/BudgetWarningBanner.tsx), fed by the
// daemon's GET /api/budget/status (internal/intelligence/dashboard/
// budgetstatus.go, 2026-10-02 budget-latency arc).
//
// Distinct from lib/types BudgetResponse / components/BudgetBanner: that is
// the developer's OWN local [budget] advisory; this is what the ORG's
// authored budgets say about this developer's spend.
//
// No I/O, no React: the component injects storage reads/writes and renders
// the plain result. Amounts are never formatted here - the server's
// `message` is the ready-to-show sentence, passed through noticeMessage so a
// developer whose org chose token usage never sees its dollar figures.

export type BudgetLevel = "ok" | "warning" | "exceeded";

/** One org-authored window's current reading. */
export type BudgetStatusWindow = {
  window: string;
  unit: string;
  /** "tool:<id>" / "model:<id>" for a per-tool or per-model cap; absent for
   *  the whole caller (internal/budgetwarn WindowStatus.Subject). */
  subject?: string;
  period: string;
  cap: number;
  spent: number;
  ratio: number;
  scope: string;
  enforcement: string;
  level: BudgetLevel;
  crossed: number;
  /** What the cap does on THIS machine (internal/budgetwarn EffectOf):
   *  "none" | "blocks" | "blocks_proxied" | "warn_observe" | "warn_guard_off".
   *  Absent from an older daemon. */
  effect?: BudgetEffect;
  /** True when this machine refuses the current reading. */
  blocked?: boolean;
};

/** The daemon's closed effect vocabulary (internal/budgetwarn Effect*). */
export type BudgetEffect = "none" | "blocks" | "blocks_proxied" | "warn_observe" | "warn_guard_off";

/** One announced notice (the highest per window in the current period). */
export type BudgetNotice = {
  id: string;
  window: string;
  unit: string;
  /** "tool:<id>" / "model:<id>" for a per-tool or per-model cap; absent for
   *  the whole caller (internal/budgetwarn Notice.Subject). */
  subject?: string;
  period: string;
  threshold: number;
  ratio: number;
  spent: number;
  cap: number;
  scope: string;
  enforcement: string;
  crossed_at: string;
  level: "warning" | "exceeded";
  message: string;
  /** What the cap does on THIS machine; absent from an older daemon. */
  effect?: BudgetEffect;
  /** True when this machine refuses the current reading (the guard's own
   *  comparison). Never inferred from `enforcement` alone: an org's hard cap
   *  on a machine in observe mode blocks nothing (2026-11-18). */
  blocked?: boolean;
  /** True when the refusal compares this machine's own spend only. */
  denies_on_local_spend?: boolean;
  /** The org budget this notice measures, when the node's budget rail names
   *  one (T-522): the banner's "Ask for a budget increase" opens a request
   *  for exactly this budget. */
  budget_id?: string;
};

export type BudgetStatus = {
  /** false = no org budget warning service wrote here: render NOTHING. */
  available: boolean;
  written_at?: string;
  windows?: BudgetStatusWindow[] | null;
  active?: BudgetNotice[] | null;
};

export type BudgetWarningTone = "warn" | "danger";

/** What the banner shows, or null for nothing. */
export type BudgetWarningView = {
  top: BudgetNotice;
  /** Further undismissed notices beyond `top` ("+N more"). */
  others: BudgetNotice[];
  tone: BudgetWarningTone;
  /** enforcement=hard AND level=exceeded: requests are being refused. */
  blocked: boolean;
  label: string;
};

/** Cap on the remembered toasted-id list (oldest dropped first). */
export const TOASTED_CAP = 50;

/**
 * isExceeded is the one reading of "over the cap" every label and tone uses:
 * the notice says exceeded AND its current reading is at 100% or more (as the
 * sentence rounds it). A notice whose reading is under its cap is never
 * exceeded here, whatever level an older daemon wrote (node 1, 2026-10-06: a
 * raised team cap read "Budget exceeded" at 11%). A notice with no numeric
 * ratio keeps its level.
 */
export function isExceeded(n: Pick<BudgetNotice, "level"> & { ratio?: number }): boolean {
  if (n.level !== "exceeded") return false;
  const r = n.ratio;
  return typeof r !== "number" || !Number.isFinite(r) || Math.round(r * 100) >= 100;
}

type EffectFields = Pick<BudgetNotice, "enforcement" | "level"> & {
  ratio?: number;
  effect?: BudgetEffect;
  blocked?: boolean;
};

/** canBlockHere reports whether this machine refuses requests for the cap at
 *  all (enforce mode). An older daemon that sent no effect is read from the
 *  org mode, as before. */
function canBlockHere(n: EffectFields): boolean {
  if (n.effect === undefined) return n.enforcement === "hard";
  return n.effect === "blocks" || n.effect === "blocks_proxied";
}

/** True when this machine is refusing requests for this notice's cap: the
 *  daemon's own `blocked` bit (the guard's comparison) when it sent one. */
export function isBlocked(n: EffectFields): boolean {
  if (n.effect !== undefined) return n.blocked === true && isExceeded(n);
  return n.enforcement === "hard" && isExceeded(n);
}

/**
 * The short label shown before the server's message, naming the state on THIS
 * machine: blocked (proxied requests only when that is all it can stop),
 * exceeded but not blocked (warning only, report only, or a hard cap this
 * machine cannot block), or approaching (with what happens at 100% here).
 */
export function budgetWarningLabel(n: EffectFields): string {
  if (isBlocked(n)) {
    return n.effect === "blocks_proxied" ? "Budget exceeded: proxied requests blocked" : "Budget exceeded: requests blocked";
  }
  if (isExceeded(n)) {
    if (n.enforcement === "hard") return canBlockHere(n) ? "Budget exceeded (not blocked yet)" : "Budget exceeded (warning only on this machine)";
    return n.enforcement === "soft" ? "Budget exceeded (warning only)" : "Budget exceeded (report only)";
  }
  if (n.enforcement === "hard") return canBlockHere(n) ? "Approaching budget: blocks at 100%" : "Approaching budget (warning only on this machine)";
  return "Approaching budget";
}

/** The node dashboard's cost display (shared/lib/format.ts CostDisplayMode),
 *  restated here so this module stays importable under `node --test`. */
export type NoticeDisplayMode = "usd" | "tokens";

// The dollar clause of the server's sentence (internal/budgetwarn
// RenderMessage in dollar display): "...: 120% used - $0.90 of $0.75. ..."
// The percentage is kept.
const USD_AMOUNT_CLAUSE = /(\d+% used) - \$[\d,]+(?:\.\d+)? of \$[\d,]+(?:\.\d+)?\./;
const ANY_USD = /\$\d/;

/**
 * noticeMessage renders a notice's sentence under this dashboard's cost
 * display. Dollar mode (and any token-denominated cap) shows the server's
 * sentence verbatim. In token mode a DOLLAR cap's amounts are dropped and the
 * share of the budget stays ("120% used of the budget"): there is no token
 * count behind a dollar cap to show instead, and converting would fabricate
 * one. The daemon already renders its sentence in the node's display, so a
 * dollar-free sentence ("...: 120% used of the budget. ...") is shown
 * verbatim. An unrecognised dollar sentence falls back to a percentage-only
 * line so token mode never shows a dollar figure.
 */
export function noticeMessage(
  n: Pick<BudgetNotice, "message" | "unit" | "ratio" | "window" | "enforcement" | "level" | "subject" | "effect" | "blocked">,
  mode: NoticeDisplayMode,
): string {
  if (mode !== "tokens" || n.unit !== "usd") return n.message;
  if (!ANY_USD.test(n.message)) return n.message;
  if (USD_AMOUNT_CLAUSE.test(n.message)) {
    const out = n.message.replace(USD_AMOUNT_CLAUSE, "$1 of the budget.");
    if (!ANY_USD.test(out)) return out;
  }
  const pct = Math.round((Number(n.ratio) || 0) * 100);
  const tail = !isBlocked(n)
    ? ""
    : n.effect === "blocks_proxied"
      ? " Further proxied requests are blocked."
      : " Further proxied requests, and the next prompt or tool call in tools with a pre-send hook, are blocked.";
  const label = subjectLabel(n.subject);
  const forSubject = label ? ` for ${label}` : "";
  return `Org ${n.window} budget${forSubject}: ${pct}% used of the budget.${tail}`;
}

/**
 * subjectLabel renders a notice subject the way the daemon's sentence does
 * (internal/budgetwarn SubjectLabel): "tool:codex" -> "tool codex",
 * "model:gpt-5" -> "model gpt-5"; "" for the whole caller. A per-tool or
 * per-model cap must never read as the developer's whole budget.
 */
export function subjectLabel(subject: string | undefined): string {
  if (!subject) return "";
  const i = subject.indexOf(":");
  if (i < 0 || i === subject.length - 1) return subject;
  return `${subject.slice(0, i)} ${subject.slice(i + 1)}`;
}

function isNotice(raw: unknown): raw is BudgetNotice {
  if (raw == null || typeof raw !== "object") return false;
  const n = raw as Partial<BudgetNotice>;
  return (
    typeof n.id === "string" &&
    n.id !== "" &&
    typeof n.message === "string" &&
    n.message !== "" &&
    (n.level === "warning" || n.level === "exceeded")
  );
}

/**
 * activeNotices returns the well-formed active notices, highest first:
 * exceeded before warning, then the larger ratio. The sort is stable, so
 * the server's own ordering wins every remaining tie. Nothing at all when
 * the payload is missing or says available=false.
 */
export function activeNotices(status: BudgetStatus | null | undefined): BudgetNotice[] {
  if (!status || status.available !== true || !Array.isArray(status.active)) {
    return [];
  }
  return status.active
    .filter(isNotice)
    .map((n, i) => ({ n, i }))
    .sort((a, b) => {
      const rank = (isExceeded(b.n) ? 2 : 1) - (isExceeded(a.n) ? 2 : 1);
      if (rank !== 0) return rank;
      const ratio = (Number(b.n.ratio) || 0) - (Number(a.n.ratio) || 0);
      if (ratio !== 0) return ratio;
      return a.i - b.i;
    })
    .map(({ n }) => n);
}

/**
 * pickBudgetWarning decides what the banner shows: the top undismissed
 * notice plus how many more there are, or null (render nothing) when the
 * service is unavailable, nothing is active, or everything was dismissed.
 */
export function pickBudgetWarning(
  status: BudgetStatus | null | undefined,
  dismissed: ReadonlySet<string> = new Set(),
): BudgetWarningView | null {
  const showing = activeNotices(status).filter((n) => !dismissed.has(n.id));
  if (showing.length === 0) return null;
  const [top, ...others] = showing;
  return {
    top,
    others,
    tone: isExceeded(top) ? "danger" : "warn",
    blocked: isBlocked(top),
    label: budgetWarningLabel(top),
  };
}

/**
 * newNotices returns the active notices this browser has not toasted yet
 * (the toast fires once per notice id, ever). Dismissal does not matter
 * here: a dismissed banner notice was necessarily seen already.
 */
export function newNotices(
  status: BudgetStatus | null | undefined,
  toasted: ReadonlySet<string>,
): BudgetNotice[] {
  return activeNotices(status).filter((n) => !toasted.has(n.id));
}

/**
 * rememberIds appends `ids` to the remembered list (no duplicates; a
 * re-seen id moves to the newest end) and keeps only the last `cap`.
 */
export function rememberIds(
  prev: readonly string[],
  ids: readonly string[],
  cap: number = TOASTED_CAP,
): string[] {
  const add = new Set(ids);
  const out = prev.filter((id) => !add.has(id));
  for (const id of add) out.push(id);
  return cap > 0 && out.length > cap ? out.slice(out.length - cap) : out;
}

/** parseIdList reads a stored JSON id array, tolerating any garbage. */
export function parseIdList(raw: string | null | undefined): string[] {
  if (!raw) return [];
  try {
    const v: unknown = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

function writtenAtMs(s: BudgetStatus | null | undefined): number {
  const raw = s?.written_at;
  const t = raw ? Date.parse(raw) : NaN;
  return Number.isNaN(t) ? -1 : t;
}

/**
 * newerBudgetStatus picks the status written last: the one the stream pushed
 * (GET /api/budget/status/stream, T-206) or the one the 15 s poll read. A tie
 * or an unparseable time keeps the streamed one, which is never older than
 * the poll that preceded it.
 */
export function newerBudgetStatus(
  streamed: BudgetStatus | null,
  polled: BudgetStatus | null,
): BudgetStatus | null {
  if (!streamed) return polled;
  if (!polled) return streamed;
  return writtenAtMs(polled) > writtenAtMs(streamed) ? polled : streamed;
}
