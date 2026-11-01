// projectPolicyLine is the New Terminal dialog's "project policy" line
// (security plan section 7.11 hard case "New Terminal shows project policy:
// not matched", lane sec-p2b): fixed text for the answer of
// GET /api/terminal/project-policy. Pure, so node:test loads it directly.
//
// The line shows only when the machine holds the organization's project
// rules (shown=true); every other machine sees nothing.

/** The wire answer (dashapi.ProjectPolicyLine). */
export type ProjectPolicyReply = {
  shown: boolean;
  state?: string;
  projects?: number;
};

/** What the dialog renders: the line and its tooltip. */
export type ProjectPolicyView = { text: string; detail: string; tone: "ok" | "info" | "warn" };

const STATES: Record<string, (n: number) => ProjectPolicyView> = {
  matched: (n) => ({
    text: `Project policy: applied (${n} ${n === 1 ? "project" : "projects"})`,
    detail: "Your organization's rules for this project apply here, on top of the org, team and member rules.",
    tone: "ok",
  }),
  not_matched: () => ({
    text: "Project policy: not matched",
    detail: "No organization project matched this folder, so only the org, team and member rules apply.",
    tone: "info",
  }),
  unknown: () => ({
    text: "Project policy: unknown",
    detail: "This machine's project mapping is missing or out of date, so only the org, team and member rules apply until it refreshes.",
    tone: "warn",
  }),
};

/** projectPolicyView returns the line to show, or null for none. */
export function projectPolicyView(reply: ProjectPolicyReply | null | undefined): ProjectPolicyView | null {
  if (!reply || !reply.shown || !reply.state) return null;
  const make = STATES[reply.state];
  if (!make) return null;
  return make(Math.max(1, reply.projects ?? 1));
}
