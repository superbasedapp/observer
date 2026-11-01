export { StatCard, type StatCardProps } from "./StatCard";
export { StatDelta, resolveStatDelta, type StatDeltaProps, type StatDeltaKind, type StatDeltaGuarded, type StatDeltaValue } from "./StatDelta";
export { BigStat, type BigStatProps } from "./BigStat";
export { HeroStat, type HeroStatProps, type HeroStatVariant } from "./HeroStat";
export { ChartShell } from "./ChartShell";
export { PageHeader } from "./PageHeader";
export { IdLink, idLinkClass } from "./IdLink";
export { EntityLink } from "./EntityLink";
export { TeamChip, TeamChips, type TeamChipRef } from "./TeamChip";
export { Sparkline } from "./Sparkline";
export { Pill } from "./Pill";
export { ToolBadge, ToolDot, ToolGlyphFrame, ToolStack } from "./ToolBadge";
export { ReliabilityPill } from "./ReliabilityPill";
export {
  SurfaceBadge,
  isSurfaceKind,
  type SurfaceBadgeProps,
  type SurfaceKind,
} from "./SurfaceBadge";
export { SegmentedControl, type Segment } from "./SegmentedControl";
export { GranularityControl } from "./GranularityControl";
export { TabStrip, TabPanel, useTabVisited, tabDomId, panelDomId, type TabDef } from "./Tabs";
export {
  resolveTab,
  nextTabId,
  focusableTabId,
  shownTabs,
  usableTabs,
  auditedNote,
  tabPanelState,
  latchVisited,
  type TabRuleInput,
  type TabPanelState,
} from "./tabsModel";
export { SectionRail, type SectionRailItem, type SectionRailGroup } from "./SectionRail";
export { isRailLink, pickRailSection, railItems, shownRailGroups } from "./sectionRailModel";
export { StatStrip } from "./StatStrip";
export { useStripScroll, StripEndPad } from "./useStripScroll";
export { SlideOver } from "./SlideOver";
export { TruncatedPath } from "./TruncatedPath";
export { Toggle } from "./Toggle";
export { ActiveFilterChips, type FilterChip } from "./ActiveFilterChips";
export { ComboChip, type ComboOption } from "./ComboChip";
export { EntityMultiPicker, type EntityMultiPickerOption } from "./EntityMultiPicker";
export { SinglePicker, toPickerOptions } from "./SinglePicker";
export { DateRangePopover } from "./DateRangePopover";
export { ModelDot } from "./ModelDot";
export { ModelMark } from "./ModelMark";
export { ModelId } from "./ModelId";
export { ModelFilterChip } from "./ModelFilterChip";
export { HostMark, IdpMark } from "./BrandGlyphs";
export { BrandMark, BrandLoader } from "./BrandMark";
export { Icon, type IconSize } from "./Icon";
export { DensityBar, type DensitySegment } from "./DensityBar";
export { DensityToggle } from "./DensityToggle";
export { ThemeToggle } from "./ThemeToggle";
export {
  Skeleton,
  ChartSkeleton,
  TableSkeleton,
  StatCardSkeleton,
} from "./Skeleton";
export { Tooltip, TooltipSpan, type TooltipProps } from "./Tooltip";
export { CopyOnClick } from "./CopyOnClick";
export { HelpSlotProvider, useHelpSlot } from "./helpSlot";
export {
  Button,
  buttonClasses,
  buttonDisabledLook,
  type ButtonProps,
  type ButtonSize,
  type ButtonVariant,
} from "./Button";
export {
  Input,
  FieldShell,
  fieldClasses,
  type InputProps,
  type FieldChromeProps,
} from "./Input";
export { Select, type SelectProps, type SelectOption } from "./Select";
export { Textarea, type TextareaProps } from "./Textarea";
export { SettingRow, type SettingRowProps } from "./SettingRow";
// Copy and emphasis primitives (design review 2026-10-13, lane DS2;
// docs/app-design-system.md "Copy rules", "Emphasis", "Row actions").
export { InfoDisclosure, type InfoDisclosureProps } from "./InfoDisclosure";
export { HelpTooltip, type HelpTooltipProps } from "./HelpTooltip";
export { Callout, type CalloutProps } from "./Callout";
export { RowActions, type RowAction, type RowActionsProps } from "./RowActions";
export { CoverageBadge, type CoverageBadgeProps } from "./CoverageBadge";
export {
  COPY_LIMITS,
  COVERAGE_TONE,
  coverageCountLabel,
  coverageFromCounts,
  loudCalloutsOverBudget,
  overCopyLimit,
  type CalloutTone,
  type CopyKind,
  type CoverageStatus,
} from "./copyModel";
export { Card, type CardProps } from "./Card";
export { CardHeader } from "./CardHeader";
export { MetricIcon } from "./MetricIcon";
export { EmptyState, type EmptyStateProps } from "./EmptyState";
export { EmptyIllustration, ILLUSTRATION_TITLES, type IllustrationKind } from "./EmptyIllustration";
export { Spinner, InlineLoading } from "./Spinner";
export { ErrorState } from "./ErrorState";
export { Obs, Mascot, toMascotState, type ObsState, type MascotState } from "./Obs";
export { ObsFlight, ObsLoader, ObsInline, ObsMoment, ObsLanding, ObsJobRider } from "./ObsFlight";
export { PermissionDenied, ReadOnlyBanner } from "./PermissionDenied";
export { LiveDot, type LiveTone } from "./LiveDot";
export { Modal } from "./Modal";
export { MarkTile } from "./MarkTile";
export { Meter } from "./Meter";
export { ProgressRing } from "./ProgressRing";
export { ConvergenceRing } from "./ConvergenceRing";
export { NodeHealthGrid, type NodeHealthCell, type NodeHealthVocab } from "./NodeHealthGrid";
export { SuccessCheck } from "./SuccessCheck";
export { TypingDots } from "./TypingDots";
export { Table, type TableProps } from "./Table";
export { DataTable, Pagination, type DataTableProps } from "./DataTable";
export {
  JsonPreview,
  formatJsonPreview,
  type JsonPreviewProps,
} from "./JsonPreview";
export { ConfirmButton, armedBehaviour, type ArmedBehaviour, type ConfirmButtonProps, type ConfirmReason } from "./ConfirmButton";
export { OneTimeSecret } from "./OneTimeSecret";
export { SetupChecklist, type SetupChecklistStep } from "./SetupChecklist";
export {
  PageTransition,
  Stagger,
  FadeIn,
  UpdatingBadge,
  TopProgress,
  Aurora,
  AnimatedValue,
  staleClass,
  spotlightHandlers,
} from "./Motion";
export { SectionNav, type SectionNavItem, type SectionNavGutter } from "./SectionNav";
// The filter row's palette chip and the top bar's link tools, promoted from
// the node dashboard so both dashboards carry them (T-451 / T-452).
export { SearchChip } from "./SearchChip";
export { PageLinkTools } from "./PageLinkTools";
export { TokenBar } from "./TokenBar";
export { CodeEditor, diagnosticRange, type CodeEditorProps, type CodeLanguage, type CodeDiagnostic } from "./CodeEditor";
