// toolAccounts.ts - the pure vocabulary for ACCOUNT-LEVEL tool-account
// observations, shared by the node dashboard (web/) and the org dashboard
// (web2/). Mirrors internal/models/toolaccount.go (ToolAccountScopeIsAccountLevel
// + ToolAccountScopeNoun) - keep the two in step.
//
// An account-level observation (scope "account" or "account:<detail>") names a
// vendor ACCOUNT (a device/install account id, a Snowflake account host, a
// tenant) that more than one person may share. It is never the person who typed
// the prompt, so a surface must label it as an account, never show the bare id
// where a user's name or email would go.
//
// PURE: no fetch, no React, no DOM. Table-testable under `node --test`.

const ACCOUNT_SCOPE = "account";

/** True for scope "account" or "account:<detail>" (and nothing like "accountant"). */
export function isAccountLevelScope(scope: string | undefined | null): boolean {
  return scope === ACCOUNT_SCOPE || (scope ?? "").startsWith(ACCOUNT_SCOPE + ":");
}

/**
 * accountScopeNoun names an account-level scope in words ("device account",
 * "org account"). The detail vocabulary is closed: an unknown detail is plain
 * "account", never echoed. "" for a scope that is not account-level.
 */
export function accountScopeNoun(scope: string | undefined | null): string {
  if (!isAccountLevelScope(scope)) return "";
  const detail = (scope as string).slice(ACCOUNT_SCOPE.length).replace(/^:/, "");
  switch (detail) {
    case "device":
    case "install":
    case "installation":
      return "device account";
    case "org":
    case "organization":
    case "tenant":
    case "workspace":
    case "host":
      return "org account";
    default:
      return "account";
  }
}

/** The minimum an evidence row needs to be labelled. */
export type AccountEvidenceLabelInput = {
  key?: string;
  email?: string;
  name?: string;
  account_id?: string;
  scope?: string;
};

function shortKey(key: string): string {
  return key.length <= 8 ? key : key.slice(0, 8);
}

/**
 * accountEvidenceLabel names one observation. A person-level row reads as the
 * email, else name, else account id (else a rendering of the opaque key when the
 * org was shared no identity); an account-level row is ALWAYS noun-qualified
 * ("device account dev-9"), so it can never be mistaken for a user. "Unknown"
 * when nothing identifies it - never blank, which would read as "no account".
 */
export function accountEvidenceLabel(e: AccountEvidenceLabelInput | undefined | null): string {
  if (!e) return "Unknown";
  if (isAccountLevelScope(e.scope)) {
    const noun = accountScopeNoun(e.scope);
    if (e.account_id) return `${noun} ${e.account_id}`;
    return e.key ? `${noun} ${shortKey(e.key)}` : noun;
  }
  return e.email || e.name || e.account_id || (e.key ? `account ${shortKey(e.key)}` : "Unknown");
}
