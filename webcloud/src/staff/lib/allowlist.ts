// The team create allow-list (staff console e2e finding SC-7; the routes are
// internal/cloudserver/api/portal_teamallowlist.go). While team creation is
// invitation-only, a team org can be created only by an account on this
// list: named by its account id, or by the domain of its verified email. A
// personal org is never checked. These rules mirror the one validator both
// writers call (staffauth.ValidateAllowlistEntry), so the console refuses
// what the server would refuse before the request; the server stays the
// gate. Pure: no fetch, no React.

/** AllowlistEntry is one team_create_allowlist row (store.TeamAllowlistEntry). */
export interface AllowlistEntry {
  entry_id: string;
  kind: string;
  value: string;
  added_by: string;
  added_reason: string;
  added_at: string;
  removed_at?: string | null;
  removed_by?: string;
  removed_reason?: string;
}

export type AllowlistKind = "account" | "email_domain";

/** ALLOWLIST_KINDS mirrors staffauth.KnownAllowlistKinds, in words. */
export const ALLOWLIST_KINDS: { kind: AllowlistKind; label: string; help: string; placeholder: string }[] = [
  {
    kind: "email_domain",
    label: "Email domain",
    help: "Every account whose verified email is at exactly this domain. Subdomains are not included.",
    placeholder: "example.com",
  },
  {
    kind: "account",
    label: "Account",
    help: "One account, by its account id: the account reference a refused person reads.",
    placeholder: "00000000-0000-0000-0000-000000000000",
  },
];

/** kindLabel is a kind in words (an unknown kind as written). */
export function kindLabel(kind: string): string {
  return ALLOWLIST_KINDS.find((k) => k.kind === kind)?.label ?? kind;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DOMAIN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

/** validateAllowlistEntry mirrors staffauth.ValidateAllowlistEntry: it
 *  returns the value in the canonical spelling the server stores (lower
 *  case; a domain without a leading "@" or a trailing dot) and the refusal,
 *  null when the entry is valid. */
export function validateAllowlistEntry(kind: string, raw: string): { value: string; error: string | null } {
  let v = raw.trim().toLowerCase();
  switch (kind) {
    case "account":
      return UUID.test(v) ? { value: v, error: null } : { value: v, error: "An account entry is an account id (a UUID)." };
    case "email_domain": {
      if (v.startsWith("@")) v = v.slice(1);
      if (v.endsWith(".")) v = v.slice(0, -1);
      if (v.includes("@")) {
        const domain = v.slice(v.lastIndexOf("@") + 1);
        return { value: v, error: `A domain entry is a domain, not an address${domain ? `: use ${domain}` : ""}.` };
      }
      if (v.length < 3 || v.length > 253 || !DOMAIN.test(v)) return { value: v, error: `"${v}" is not a domain name like example.com.` };
      return { value: v, error: null };
    }
    default:
      return { value: v, error: "Choose an email domain or an account." };
  }
}

/** isActive reports whether an entry is in force (not removed). */
export function isActive(e: AllowlistEntry): boolean {
  return !e.removed_at;
}

/** addBlocking is every reason an add cannot be sent: the value's own
 *  refusal, or an active entry that already says the same (the server's
 *  409 exists). Empty input shows nothing yet. */
export function addBlocking(entries: AllowlistEntry[], kind: string, raw: string): string[] {
  if (raw.trim() === "") return ["Enter a value."];
  const { value, error } = validateAllowlistEntry(kind, raw);
  if (error) return [error];
  if (entries.some((e) => isActive(e) && e.kind === kind && e.value === value)) return ["That entry is already on the allow-list."];
  return [];
}

/** allowlistSummary is the page's one line about who may create a team org. */
export function allowlistSummary(entries: AllowlistEntry[]): string {
  const active = entries.filter(isActive);
  if (active.length === 0) return "No one is on the allow-list: while team creation is invitation-only, no account can create a team org.";
  const n = (kind: string) => active.filter((e) => e.kind === kind).length;
  const part = (count: number, one: string, many: string) => `${count} ${count === 1 ? one : many}`;
  return `${part(n("email_domain"), "email domain", "email domains")} and ${part(n("account"), "account", "accounts")} may create a team org.`;
}

/** ALLOWLIST_ERRORS: the routes' refusals in words (the code follows). */
const ALLOWLIST_ERRORS: Record<string, string> = {
  exists: "That entry is already on the allow-list.",
  not_found: "That entry is no longer on the allow-list: someone removed it. The list now shows the current entries.",
};

/** allowlistErrorText is a refusal in words, else the server's message. */
export function allowlistErrorText(code: string, fallback: string): string {
  return ALLOWLIST_ERRORS[code] ?? fallback;
}
