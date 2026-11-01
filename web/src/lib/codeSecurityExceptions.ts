// codeSecurityExceptions - the pure half of the Code security page's
// Exceptions and Baselines tabs (security pillar plan sections 4.5.2 and
// 6.3, lane sec-c3).
//
// An exception says ONE finding is not a real problem, for a while: it is
// scoped to that finding, it always expires, and the rule keeps firing
// everywhere else. The reason and expiry pickers are the closed lists the
// server sends with GET /api/security/exceptions (pickers only, D-571), and
// the write is POST /api/security/exceptions with the confirm token that GET
// minted. A baseline is a commit picked from GET /api/security/baseline's
// proposal (the merge base first); the page never sends a typed ref.

/** One option of a closed picker the server sends. */
export type PickerOption = { id: string; label: string };

/** One exception as GET /api/security/exceptions lists it. */
export type SecurityException = {
  id: number;
  finding_id: string;
  project_root_hash: string;
  rule_id: string;
  rel_path: string;
  reason: string;
  expiry: string;
  expires_at: string;
  granted_by: string;
  granted_at: string;
  ended_at?: string;
  end_reason?: string;
};

export type ExceptionsResponse = {
  exceptions: SecurityException[];
  reasons: PickerOption[];
  expiries: PickerOption[];
  confirm_token: string;
};

/** One commit the baseline picker offers. */
export type BaselineCommit = { sha: string; when: string; subject: string; merge_base: boolean };

export type BaselineView = {
  project_root_hash: string;
  current: { kind: string; ref: string; approver: string; created_at: string; org_approved_at?: string } | null;
  proposed: BaselineCommit[];
  proposal_error?: string;
};

export type BaselineResponse = { baseline: BaselineView; confirm_token: string };

/**
 * exceptionGrantBody is the POST body for one grant, or null when a choice
 * is not one of the server's picker ids (nothing typed is ever sent).
 */
export function exceptionGrantBody(
  findingID: string,
  reason: string,
  expiry: string,
  pickers: Pick<ExceptionsResponse, "reasons" | "expiries">,
): { finding_id: string; reason: string; expiry: string } | null {
  if (!findingID) return null;
  if (!pickers.reasons.some((r) => r.id === reason)) return null;
  if (!pickers.expiries.some((e) => e.id === expiry)) return null;
  return { finding_id: findingID, reason, expiry };
}

/**
 * baselineApproveBody is the POST body approving a commit the picker
 * offered, or null when sha is not one of them.
 */
export function baselineApproveBody(
  project: string,
  sha: string,
  proposed: readonly BaselineCommit[],
): { project: string; action: "approve"; commit: string } | null {
  if (!project || !proposed.some((c) => c.sha === sha)) return null;
  return { project, action: "approve", commit: sha };
}

/**
 * baselineStatusLine says what the project's baseline is: its commit, who
 * approved it and when, or that there is none.
 */
export function baselineStatusLine(current: BaselineView["current"]): string {
  if (!current) return "No baseline: findings read as untrusted baseline (flagged, never pre-existing).";
  return `Baseline: ${current.ref.slice(0, 12)}, approved from the ${current.approver} on ${current.created_at.slice(0, 10)}.`;
}

/**
 * baselineOrgLabel is the "approved by the org" label the CLI and the API
 * already show (lane LEFT2-SEC item R-023, the CLI's wording in
 * cmd/observer/security_baseline_org.go): the org approved this same
 * reference on its managed pull. A label only: it changes no finding or
 * verdict. null when the org did not approve it (or on an individual node).
 */
export function baselineOrgLabel(current: BaselineView["current"]): string | null {
  if (!current?.org_approved_at) return null;
  return `Approved by the org on ${current.org_approved_at} (a label: it changes no finding or verdict).`;
}

/** baselineCommitLabel is a picker row: short id, date, subject, merge base mark. */
export function baselineCommitLabel(c: BaselineCommit): string {
  const day = c.when ? c.when.slice(0, 10) : "";
  const mark = c.merge_base ? " (merge base, proposed)" : "";
  return `${c.sha.slice(0, 12)} ${day} ${c.subject}${mark}`.replace(/\s+/g, " ").trim();
}

/** END_REASON_LABEL names why an exception ended. */
const END_REASON_LABEL: Readonly<Record<string, string>> = {
  expired: "expired",
  file_changed: "the file changed",
  revoked: "revoked",
};

/** exceptionStateLabel says whether an exception still applies. */
export function exceptionStateLabel(e: SecurityException): string {
  if (!e.ended_at) return "applies";
  return `ended: ${END_REASON_LABEL[e.end_reason ?? ""] ?? "ended"}`;
}

/** pickerLabel is the label of id in a picker, or the id itself. */
export function pickerLabel(options: readonly PickerOption[], id: string): string {
  return options.find((o) => o.id === id)?.label ?? id;
}

/**
 * securityPost sends one owner-local write with the confirm token the
 * matching GET minted, and throws the server's message on a refusal.
 */
export async function securityPost<T>(path: string, token: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...(token ? { "X-Observer-Confirm": token } : {}) },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let parsed: unknown = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }
  if (!res.ok) {
    const msg = (parsed as { message?: string } | null)?.message;
    throw new Error(msg || text.trim() || `HTTP ${res.status}`);
  }
  return parsed as T;
}

/** POST /api/security/scan-history's result. */
export type HistoryResult = { commits: number; unknown: number; remaining: number; hits: number; new_findings: number };

/** historySummary is the one line the Findings tab shows after a history scan. */
export function historySummary(r: HistoryResult, complete: boolean): string {
  const base = `${r.commits} commit(s) read, ${r.hits} secret hit(s), ${r.new_findings} new finding(s).`;
  if (complete) return base;
  return `${base} Not complete: ${r.unknown} could not be judged, ${r.remaining} not reached. Not a clean answer.`;
}

/** GET /api/security/githooks: the opt-in local git hooks of one repository. */
export type GithooksResponse = {
  active: boolean;
  refusal: string;
  hooks: { hook: string; installed: boolean; outdated?: boolean; foreign: boolean }[];
  confirm_token: string;
};

/** githooksStateLabel is one hook's state in plain words. */
export function githooksStateLabel(h: GithooksResponse["hooks"][number]): string {
  const base = h.installed ? "installed" : h.outdated ? "outdated (an earlier version's block; install again to update it)" : "not installed";
  return h.foreign ? `${base}, with your own hook` : base;
}

/** GET /api/security/provenance: the AI change records of one repository (component security.provenance). */
export type ProvenanceResponse = {
  status: {
    selected: boolean;
    key?: {
      id: string;
      storage: string;
      attestation: string;
      created_at: string;
      rotation: string;
      storage_reason?: string;
      storage_detail?: string;
    };
    records: { Records: number; Projects: number; NotesWritten: number; Newest: string };
    consents: { root: string; notes: boolean; trailer: boolean; given_at?: string }[];
    retired_keys: number;
  };
  records: {
    commit: string;
    committed_at: string;
    ai_lines: number;
    human_lines: number;
    unknown_lines: number;
    human_capture: string;
    sessions: string[];
    note_written: boolean;
    verification: string;
    verification_reason?: string;
  }[];
  consent?: { notes: boolean; trailer: boolean };
  trailer_preview?: { root: string; hook_path: string; block: string; digest: string; installed: boolean; refusal?: string };
  confirm_token: string;
};

/** provenanceKeyLabel says where the signing key lives, in plain words. */
export function provenanceKeyLabel(k: ProvenanceResponse["status"]["key"]): string {
  if (!k) return "No signing key yet (made when the daemon starts with the component on).";
  const where = k.storage === "keychain" ? "the system keychain" : "a protected file on this machine (no keychain here)";
  const due = k.rotation === "keep" ? "" : " Rotation is due.";
  const why = k.storage_detail ? ` It is there because ${k.storage_detail}.` : "";
  return `Signing key ${k.id.slice(0, 12)} in ${where}, made ${k.created_at.slice(0, 10)}.${due}${why}`;
}

/** provenanceVerificationLabel says whether a stored record verifies; a failure is named, never shown as unknown (P-059). */
export function provenanceVerificationLabel(r: ProvenanceResponse["records"][number]): string {
  if (r.verification === "verified") return "signature verified";
  return `verification failed (${r.verification_reason || "unreadable"})`;
}

/** provenanceLinesLabel is one record's line split; "none" human capture is unmeasured, never zero. */
export function provenanceLinesLabel(r: ProvenanceResponse["records"][number]): string {
  const human = r.human_capture === "none" ? "human not measured" : `${r.human_lines} human`;
  return `${r.ai_lines} AI, ${human}, ${r.unknown_lines} unknown`;
}
