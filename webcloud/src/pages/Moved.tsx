import { ArrowRightLeft } from "lucide-react";
import { EmptyState } from "@shared/primitives/EmptyState";
import { PageHeader } from "@shared/primitives/PageHeader";
import { Stagger } from "@shared/primitives/Motion";
import { MOVED_NOTICE } from "../lib/personalModel";

// Moved - what the old personal portal pages (Overview, Sessions,
// SessionDetail, Community, Usage) render once the personal plane is retired
// (D-IND-8, lib/personalModel.ts LEGACY_RULES): their data now lives in the
// account's personal org, so the page says so and points to Organizations
// instead of rendering the old page.

export function Moved() {
  return (
    <Stagger className="flex flex-col gap-6">
      <PageHeader title={MOVED_NOTICE.title} icon={ArrowRightLeft} />
      <EmptyState
        icon={ArrowRightLeft}
        title={MOVED_NOTICE.cardTitle}
        body={MOVED_NOTICE.body}
        to="/home"
        toLabel={MOVED_NOTICE.toLabel}
      />
    </Stagger>
  );
}
