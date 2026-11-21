// cloneURL.ts mirrors, as one pure function, the URL rules the daemon
// applies to a "Clone a remote URL" workspace (internal/workspace
// ValidateRemoteURL, and the no-credential rule of ValidateBoxCloneURL /
// ValidateHomeCloneURL that a hosted row's clone adds), so the New Terminal
// dialog says what is wrong with a typed address in plain words and keeps
// Start disabled until it is valid. The daemon stays the source of truth:
// it checks every launch again (and the rules only it can know, such as
// the git hosts listed in [terminal.sandbox].remote_allowed_hosts and
// whether a box needs an https:// address); this only says it sooner.

/** The rule set a launch's clone runs under. */
export type CloneURLRules = {
  /**
   * noCredential: the clone refuses a user name, password or token in the
   * URL (a hosted row's clone, in the box or on this machine: the URL is
   * kept in the consent and run records, and the box gets no credential).
   */
  noCredential: boolean;
};

/** HELPER_RE is git's <name>::<address> remote helper word (remote.go transportHelperRE). */
const HELPER_RE = /^[A-Za-z0-9][A-Za-z0-9+.-]*$/;

/** hostFromURLForm mirrors remote.go hostFromURLForm (userinfo and port stripped). */
function hostFromURLForm(url: string, prefixLen: number): string {
  let rest = url.slice(prefixLen);
  const slash = rest.indexOf("/");
  if (slash >= 0) rest = rest.slice(0, slash);
  const at = rest.lastIndexOf("@");
  if (at >= 0) rest = rest.slice(at + 1);
  const colon = rest.indexOf(":");
  if (colon >= 0) rest = rest.slice(0, colon);
  return rest;
}

/** hostFromSCPForm mirrors remote.go hostFromSCPForm ([user@]host:path); null when not that shape. */
function hostFromSCPForm(url: string): string | null {
  if (url.includes("://")) return null;
  const idx = url.indexOf(":");
  if (idx <= 0) return null;
  if (url.slice(idx + 1).startsWith("\\")) return null;
  let hostPart = url.slice(0, idx);
  const at = hostPart.lastIndexOf("@");
  if (at >= 0) hostPart = hostPart.slice(at + 1);
  return hostPart === "" ? null : hostPart;
}

/** hostOf mirrors remote.go hostOf: the host, or null for an unrecognized shape. */
function hostOf(url: string): string | null {
  if (url.startsWith("https://")) return hostFromURLForm(url, "https://".length);
  if (url.startsWith("ssh://")) return hostFromURLForm(url, "ssh://".length);
  return hostFromSCPForm(url);
}

/**
 * carriesCredential mirrors boxclone.go urlCarriesCredential: an https
 * address with any userinfo, query or fragment, or an ssh:// address with a
 * password. The scp form's user (git@host:path) names no secret.
 */
export function carriesCredential(url: string): boolean {
  for (const scheme of ["https://", "ssh://"]) {
    if (!url.startsWith(scheme)) continue;
    const rest = url.slice(scheme.length);
    let auth = rest;
    const end = auth.search(/[/?#]/);
    if (end >= 0) auth = auth.slice(0, end);
    const at = auth.indexOf("@");
    const hasUser = at >= 0;
    if (scheme === "https://") return hasUser || /[?#]/.test(rest);
    return hasUser && auth.slice(0, at).includes(":");
  }
  return false;
}

const SHAPES = "Name an https://, ssh:// or user@host:path address.";

/** One rule: refuses(url, rules) reports a break; why says it in plain words. */
type URLRule = { name: string; refuses: (url: string, rules: CloneURLRules) => boolean; why: string };

/**
 * URL_RULES are walked top-down; the first that refuses wins (the order of
 * ValidateRemoteURL, then the no-credential rule).
 */
export const URL_RULES: URLRule[] = [
  // Any character at or below space, or DEL (validateNoControlOrWhitespace).
  // eslint-disable-next-line no-control-regex
  { name: "whitespace", refuses: (u) => /[\u0000- \u007f]/.test(u), why: "The address has a space or another invisible character in it. Remove it." },
  { name: "dash", refuses: (u) => u.startsWith("-"), why: "The address cannot start with a dash." },
  { name: "ext", refuses: (u) => u.startsWith("ext::"), why: `Git's ext:: form runs a command and is not allowed. ${SHAPES}` },
  {
    name: "helper",
    refuses: (u) => {
      const i = u.indexOf("::");
      return i >= 0 && HELPER_RE.test(u.slice(0, i));
    },
    why: `Git's name::address form runs another program and is not allowed. ${SHAPES}`,
  },
  { name: "file", refuses: (u) => u.startsWith("file://"), why: `A file:// path is on this machine, not a remote repository. ${SHAPES}` },
  {
    name: "pack-override",
    refuses: (u) => u.includes("--upload-pack=") || u.includes("--receive-pack="),
    why: "The address carries a git option (--upload-pack or --receive-pack), which is not allowed.",
  },
  { name: "shape", refuses: (u) => hostOf(u) === null, why: SHAPES },
  { name: "host", refuses: (u) => hostOf(u) === "", why: `The address names no host. ${SHAPES}` },
  {
    name: "credential",
    refuses: (u, r) => r.noCredential && carriesCredential(u),
    why: "The address has a user name, password or token in it. Name the repository without one: your own git login signs in on this machine, and the box gets no credential.",
  },
];

/**
 * cloneURLProblem is the plain sentence for what is wrong with a typed
 * clone address under rules, or null when this side finds nothing (an
 * empty address is null too: the dialog asks for one separately).
 */
export function cloneURLProblem(url: string, rules: CloneURLRules): string | null {
  const u = url.trim();
  if (u === "") return null;
  return URL_RULES.find((r) => r.refuses(u, rules))?.why ?? null;
}
