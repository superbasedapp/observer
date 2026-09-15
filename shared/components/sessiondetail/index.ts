// Shared session-detail components — the pure, presentational pieces of the
// session-detail drawer promoted out of the node dashboard (web/) so the org
// dashboard (web2/) can render the same design. See docs/app-design-system.md.
//
// App-specific behaviour is injected: MessagesTable takes a `fetchFullText`
// callback and `renderCost` / `renderRowBody` slots; the cost-bearing panels
// take a `renderCost` slot (the org renders <Money>); ProcessTree takes a
// `renderMessageLink` slot (no router coupling). Nothing here fetches, routes,
// reads app state, or couples to a help drawer.

export { defaultRenderCost, type RenderCost, type RenderCostContext } from "./cost";

export {
  MessagesTable,
  type FetchFullText,
} from "./MessagesTable";

// ExtraMessageColumn (the MessagesTable `extraColumns` element) lives in
// lib/types with the other row shapes; re-exported here so a MessagesTable
// caller has one import site. visibleExtraColumnIds + MessageColumnPreset are
// the preset-visibility helpers from lib/messagesModel.
export type { ExtraMessageColumn } from "../../lib/types";
export {
  messageRowKey,
  visibleExtraColumnIds,
  type MessageColumnPreset,
} from "../../lib/messagesModel";

export { KpiBand, type KpiBandProps } from "./KpiBand";

export { TokenBucketsPanel } from "./TokenBucketsPanel";
export { ModelsUsedPanel } from "./ModelsUsedPanel";

export { CacheKpiStrip, CacheTierBadge } from "./CacheKpiStrip";
export { CacheTimelineList } from "./CacheTimelineList";

export {
  ProcessTree,
  flattenProcessNodes,
  processHasMetrics,
  type RenderMessageLink,
} from "./ProcessTree";

export {
  TasksTab,
  defaultTaskRenderCost,
  type TasksTabProps,
} from "./TasksTab";

export {
  SubAgentsSection,
  type SubAgentsSectionProps,
  type FetchSubAgentFullText,
} from "./SubAgentsSection";

export { IntelResultCard, type IntelResultCardProps } from "./IntelResultCard";

// Row shapes the two components above consume (they live in lib/types with the
// other structural aliases; re-exported here so a caller has one import site).
export type {
  ExtraTaskColumn,
  IntelResultLike,
  SubAgentLike,
  TaskCostBucketLike,
  TaskItemLike,
  TaskReportLike,
  TaskTokenTotalsLike,
} from "../../lib/types";
