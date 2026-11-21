import { Pill } from "./Pill";

// Unattributed (promoted from web2 for Plane A B5-0) — the shared "this row has no tool/developer/project
// attribution" chip. Aggregates now arrive with empty-string keys for spend
// that has no attribution (e.g. spend recorded before enrollment, or gateway
// turns without a session) rather than being silently dropped — this renders
// that explicitly instead of a bare "—" or a swallowed row.
export const UNATTRIBUTED_TOOLTIP =
  "Sessions or turns that arrived without tool or developer attribution - for example spend recorded before enrollment, or gateway turns without a session. Nothing is hidden; this bucket is real spend.";

// isUnattributed treats null/undefined/empty/whitespace-only keys as
// unattributed. Use this instead of a bare falsy check so " " doesn't slip
// through as a "real" key.
export function isUnattributed(key: string | null | undefined): boolean {
  return !key || !key.trim();
}

export function UnattributedChip({ className }: { className?: string }) {
  return (
    <Pill variant="neutral" title={UNATTRIBUTED_TOOLTIP} className={className}>
      Unattributed
    </Pill>
  );
}
