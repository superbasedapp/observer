import clsx from "clsx";
import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { EmptyState } from "./EmptyState";
import type { IllustrationKind } from "./EmptyIllustration";

// Panel - the org dashboard's plain panel card and inline empty line,
// promoted from web2/src/components/ui.tsx (Card, Empty) for Plane A B5-0
// (2026-11-19) so the Plane A components in shared/components/planea render
// the same chrome on the node and the org dashboards. web2's ui.tsx
// re-exports both under their old names.

// PanelCard (web2's Card): the bordered panel body.
export function PanelCard({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={clsx("rounded-lg border border-line-2 bg-bg-2 p-4", className)}>{children}</div>
  );
}

// InlineEmpty (web2's Empty): a "nothing here" line for a panel or a page body, now the shared
// EmptyState's inline variant (icon tile + title). Give page- and panel-level
// empties a fitting `icon` (a lucide glyph) or, for a large panel, an
// `illustration`; `body` adds a sentence under the title.
export function InlineEmpty({
  message,
  icon,
  illustration,
  illustrationSize,
  body,
  className,
}: {
  message: string;
  icon?: LucideIcon;
  illustration?: IllustrationKind;
  illustrationSize?: number;
  body?: ReactNode;
  className?: string;
}) {
  return (
    <EmptyState
      variant="inline"
      title={message}
      icon={icon}
      illustration={illustration}
      illustrationSize={illustrationSize}
      body={body}
      className={className}
    />
  );
}

