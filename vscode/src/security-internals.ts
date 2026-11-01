// Pure logic of the Code security diagnostics (security pillar plan section
// 6.1, "VS Code extension", lane sec-c3). No vscode import, so
// test/unit/security.test.ts exercises it directly.
//
// The daemon's GET /api/security/editor?root=<folder> lists the open
// findings of the project that contains a workspace folder: a
// project-relative path, a 1-based line, the rule, its templated message
// and fix hint, never evidence. The extension shows them as Problems-panel
// diagnostics on the files that are open, a status-bar count, and the
// command "Observer: Show code security findings". The whole surface hides
// while the `security` component is not active (components-internals.ts).

/** One finding as the editor feed lists it. */
export interface SecurityEditorFinding {
  id: string;
  rule_id: string;
  category: string;
  severity: string;
  confidence: string;
  baseline: string;
  rel_path: string;
  start_line: number;
  message: string;
  fix_hint: string;
}

/** GET /api/security/editor. */
export interface SecurityEditorResponse {
  project_root: string;
  project_root_hash: string;
  findings: SecurityEditorFinding[] | null;
}

/** The diagnostic severities the extension uses (vscode.DiagnosticSeverity names). */
export type DiagSeverity = 'error' | 'warning' | 'information' | 'hint';

/** One planned diagnostic: 0-based line, severity, text and code. */
export interface DiagPlan {
  line: number;
  severity: DiagSeverity;
  message: string;
  code: string;
  findingId: string;
}

/**
 * SEVERITY_TABLE maps a finding severity to a diagnostic severity: a
 * critical or high finding is a warning in the editor (the commit gate,
 * not the editor, is where it blocks), medium is information, low and info
 * a hint. An unknown severity is information.
 */
const SEVERITY_TABLE: Readonly<Record<string, DiagSeverity>> = {
  critical: 'warning',
  high: 'warning',
  medium: 'information',
  low: 'hint',
  info: 'hint',
};

export function diagSeverity(sev: string): DiagSeverity {
  return SEVERITY_TABLE[sev] ?? 'information';
}

/** MAX_MESSAGE caps the text of one diagnostic. */
const MAX_MESSAGE = 400;

/** diagMessage is a diagnostic's text: the templated message, then the fix hint. */
export function diagMessage(f: SecurityEditorFinding): string {
  let msg = f.message || f.rule_id;
  if (f.fix_hint) msg += ` Fix: ${f.fix_hint}`;
  if (f.baseline === 'pre_existing') msg += ' (pre-existing at the baseline)';
  msg = msg.replace(/[\u0000-\u001f\u007f]/g, ' ');
  return msg.length > MAX_MESSAGE ? `${msg.slice(0, MAX_MESSAGE - 3)}...` : msg;
}

/** normalizeRel is a project-relative path with forward slashes, or '' when unsafe. */
export function normalizeRel(rel: string): string {
  const p = rel.replace(/\\/g, '/').replace(/^\.\//, '');
  if (!p || p.startsWith('/') || /^[a-zA-Z]:/.test(p) || p.split('/').includes('..')) return '';
  return p;
}

/**
 * planDiagnostics groups the findings by file: relative path to the
 * diagnostics on it, ordered by line. A finding with an unsafe path is
 * dropped (the feed is trusted, but a path is repository text).
 */
export function planDiagnostics(findings: readonly SecurityEditorFinding[] | null | undefined): Map<string, DiagPlan[]> {
  const out = new Map<string, DiagPlan[]>();
  for (const f of findings ?? []) {
    const rel = normalizeRel(f.rel_path);
    if (!rel) continue;
    const list = out.get(rel) ?? [];
    list.push({
      line: Math.max(0, (f.start_line || 1) - 1),
      severity: diagSeverity(f.severity),
      message: diagMessage(f),
      code: f.rule_id,
      findingId: f.id,
    });
    out.set(rel, list);
  }
  for (const list of out.values()) list.sort((a, b) => a.line - b.line || a.code.localeCompare(b.code));
  return out;
}

/** relativeTo is path relative to root (both absolute), or '' when outside it. */
export function relativeTo(root: string, path: string): string {
  const norm = (s: string) => s.replace(/\\/g, '/').replace(/\/+$/, '');
  const r = norm(root);
  const p = norm(path);
  const fold = /^[a-zA-Z]:/.test(r);
  const rc = fold ? r.toLowerCase() : r;
  const pc = fold ? p.toLowerCase() : p;
  if (!pc.startsWith(rc + '/')) return '';
  return p.slice(r.length + 1);
}

/** statusLabel is the status-bar text: a shield and the open finding count. */
export function statusLabel(count: number): string {
  return count === 1 ? '$(shield) 1 finding' : `$(shield) ${count} findings`;
}

/** quickPickLabel is one row of "Show code security findings". */
export function quickPickLabel(f: SecurityEditorFinding): { label: string; description: string; detail: string } {
  return {
    label: `${f.severity} ${f.rule_id}`,
    description: `${normalizeRel(f.rel_path)}${f.start_line > 0 ? `:${f.start_line}` : ''}`,
    detail: diagMessage(f),
  };
}
