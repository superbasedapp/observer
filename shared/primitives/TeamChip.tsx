import clsx from "clsx";
import type { ReactNode } from "react";
import { EntityLink } from "./EntityLink";
import { Tooltip } from "./Tooltip";

// TeamChip — the ONE way any surface renders "this developer is on this team".
//
// It exists because team membership is now projected onto five different
// payloads (People, the member list, person detail, the session list and
// session detail, plus the provisioning roster), and before the fundamentals
// arc the only place that rendered a team at all hand-rolled its own pill
// markup inside Teams.tsx. One chip, one destination — the team route comes
// from `shared/lib/entityLinks.ts` via EntityLink, never from a call site.
//
// The `· lead` suffix is the house pattern lifted verbatim from that original
// roster row: a lead is a MEMBER with a role, so the chip is the same chip
// with one more word, never a differently-coloured badge.
//
// Honesty rule: a membership row with no role renders as a plain member, and
// a chip with no display name falls back to the team id rather than inventing
// a label.

export interface TeamChipRef {
  team_id: string;
  display_name?: string;
  role?: string;
}

export function TeamChip({
  team,
  className,
  linkable = true,
}: {
  team: TeamChipRef;
  className?: string;
  // Render as plain text instead of a link. For surfaces that already sit
  // inside a click target where a nested navigation would be wrong.
  linkable?: boolean;
}) {
  const label = team.display_name || team.team_id;
  const lead = team.role === "lead";
  return (
    <span
      className={clsx(
        "inline-flex max-w-full items-center gap-1 rounded-pill border border-line-2 bg-bg-2 px-2 py-0.5 text-[11.5px] leading-[1.5] text-fg-2",
        className,
      )}
    >
      {linkable ? (
        <EntityLink kind="team" id={team.team_id} label={<span className="truncate">{label}</span>} />
      ) : (
        <span className="truncate">{label}</span>
      )}
      {lead && <span className="shrink-0 text-fg-3">· lead</span>}
    </span>
  );
}

// TeamChips renders a developer's whole membership list, capping how many
// chips are shown so a table cell cannot be blown open by somebody who is on
// eight teams. The overflow is a count with the remaining names in its
// tooltip — never a silent truncation.
export function TeamChips({
  teams,
  max = 2,
  className,
  empty = "-",
  linkable = true,
}: {
  teams: TeamChipRef[] | undefined;
  max?: number;
  className?: string;
  // What to render when the developer is on no team. Absence means "no team",
  // never "unknown", so the default is a plain dash.
  empty?: ReactNode;
  linkable?: boolean;
}) {
  if (!teams || teams.length === 0) return <span className="text-fg-4">{empty}</span>;
  const shown = teams.slice(0, max);
  const rest = teams.slice(max);
  return (
    <span className={clsx("inline-flex flex-wrap items-center gap-1", className)}>
      {shown.map((t) => (
        <TeamChip key={t.team_id} team={t} linkable={linkable} />
      ))}
      {rest.length > 0 && (
        <Tooltip
          content={
            <span>{rest.map((t) => t.display_name || t.team_id).join(", ")}</span>
          }
        >
          <span className="cursor-help text-[11px] text-fg-3">+{rest.length}</span>
        </Tooltip>
      )}
    </span>
  );
}
