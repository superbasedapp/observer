import clsx from "clsx";
import type { MouseEvent, ReactNode } from "react";
import { Link } from "react-router-dom";
import { idLinkClass } from "./IdLink";
import { Tooltip } from "./Tooltip";
import {
  entityLinkLabel,
  entityLinkTarget,
  shortenId,
  type EntityKind,
} from "../lib/entityLinks";

// EntityLink — the ONE way a dashboard surface renders a platform entity
// (a coding session, a developer, a project, a team, a model, a trace, …)
// as something you can click.
//
// It exists so that a destination is decided in exactly one place: the
// table in `shared/lib/entityLinks.ts`. A page says WHAT it is rendering
// (`kind="coding-session"`), never WHERE that goes — which is the bug class
// this replaced (two coding pages hand-built `/sessions?session=<id>` while
// the sessions page only ever read `?focus=`, so both links silently landed
// on an unfiltered list, and nothing failed loudly).
//
// Two visual variants, because entity mentions appear in two shapes:
//
//   variant="id"    mono, dotted-underlined accent — an id in a table cell
//                   (the `IdLink` treatment, shared via `idLinkClass`).
//   variant="text"  prose accent with a hover underline — a NAME rendered
//                   inline (a developer's display name, a team name, a
//                   model id via <ModelId>), where mono would be wrong.
//
// The variant defaults from whether a `label` was supplied: a bare id
// renders as an id, a supplied label renders as prose.
//
// `stopPropagation` defaults to TRUE because most call sites sit inside a
// row that itself navigates on click; without it, clicking the link would
// fire both navigations and the row would win.
//
// Honesty rule: an entity with no resolvable route — an unknown kind, or an
// empty id — renders as plain text, never as a dead link.
export function EntityLink({
  kind,
  id,
  label,
  truncate,
  className,
  variant,
  stopPropagation = true,
  title,
  ariaLabel,
}: {
  kind: EntityKind;
  id: string;
  // Human-readable text to render instead of the id (a developer name, a
  // team name, a <ModelId/> element). Defaults to the id itself.
  label?: ReactNode;
  // Truncate the id to N characters (id rendering only — a supplied label
  // is rendered as given). The full id goes into the tooltip.
  truncate?: number;
  className?: string;
  variant?: "id" | "text";
  // Stop the click from bubbling to a clickable ancestor row. Default true.
  stopPropagation?: boolean;
  // Tooltip body. Defaults to the full id when the id was truncated.
  title?: ReactNode;
  ariaLabel?: string;
}) {
  const shape = variant ?? (label === undefined ? "id" : "text");
  const shown: ReactNode =
    label !== undefined ? label : truncate ? shortenId(id, truncate) : id;
  const to = entityLinkTarget(kind, id);

  // The prose variant deliberately INHERITS its resting colour (the house
  // style for a name link in a table: `text-fg-1 hover:text-accent`, see
  // People.tsx / Teams.tsx) rather than painting every linked name accent —
  // a dense table of accent-coloured names reads as an error state. The
  // hover carries the affordance: accent for a plain-text label, and a small
  // opacity shift, which is the only thing that shows through a label that
  // paints its own colour (<ModelId>, <Pill>).
  const styled = clsx(
    shape === "id"
      ? idLinkClass()
      : "cursor-pointer transition-colors hover:text-accent hover:opacity-80",
    className,
  );

  // Nothing to link to — render the same text, unlinked and unstyled as a
  // link, so the surface still shows the value.
  if (!to) {
    return (
      <span className={clsx(shape === "id" && "font-mono text-[11px] text-fg-3", className)}>
        {shown}
      </span>
    );
  }

  const element = (
    <Link
      to={to}
      className={styled}
      aria-label={ariaLabel ?? (label !== undefined ? undefined : entityLinkLabel(kind, id))}
      onClick={
        stopPropagation
          ? (e: MouseEvent<HTMLAnchorElement>) => {
              e.stopPropagation();
            }
          : undefined
      }
    >
      {shown}
    </Link>
  );

  const tip =
    title ??
    (label === undefined && truncate !== undefined && id.length > truncate ? id : undefined);
  if (tip === undefined) return element;
  return (
    <Tooltip content={typeof tip === "string" ? <span className="break-all font-mono">{tip}</span> : tip}>
      {element}
    </Tooltip>
  );
}
