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
  type ProcessView,
  type RenderMessageLink,
} from "./ProcessTree";
// The Call stack view's two halves (ProcessTree renders both; exported for a
// host that wants them on their own). Model: lib/processLayout.ts.
export { ProcessFlame, type ProcessFlameProps } from "./ProcessFlame";
export { ProcessSpawnStack, type ProcessSpawnStackProps } from "./ProcessSpawnStack";
// The process capture summary blocks (capture line, services, rolled-up
// groups) the node System tab and the org System panel share. Model:
// lib/processCaptureSummary.ts.
export { CaptureLine, RolledUpBlock, ServicesBlock } from "./ProcessCaptureBlocks";

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

// Agent Access P11(a): the MCP calls panel both drawers render over the ONE
// correlate.Result wire shape; its wording rules live in lib/mcpCalls.ts.
export { MCPCallsPanel, type MCPCallsPanelProps } from "./MCPCallsPanel";

// BL2 (post-Agent-Access backlog item 2): the session quality score card. The
// node drawer renders it over GET /api/session/<id>/quality; its wording and
// arithmetic live in lib/sessionQuality.ts.
export { QualityPanel, type QualityPanelProps } from "./QualityPanel";
export type { SessionQualityLike } from "../../lib/sessionQuality";

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
export { SESSION_TAB_ICONS, sessionTabIcon } from "./tabIcons";
export { GaugeStat, type GaugeStatProps, type GaugeRing } from "./GaugeStat";

// The request-class split ("Spend by request class"): node + org drawers, one
// view model in lib/requestClassSplit.ts.
export { RequestClassesPanel } from "./RequestClassesPanel";

// Session lineage (fork / sub-agent parent and children): node + org drawers,
// one view model in lib/sessionLineage.ts (T-449).
export { LineageBanner, type LineageBannerProps } from "./LineageBanner";
