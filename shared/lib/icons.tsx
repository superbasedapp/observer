// Named UI icons, kept for the importers that predate the shared <Icon>
// wrapper. Since 2026-09-28 lucide-react is the ONE base UI icon family
// (operator decision D2): each legacy name below is a thin wrapper that draws
// its lucide glyph through <Icon> (stroke pinned at 1.75, same size/className
// API as before), so every page moved onto the one icon family without an
// import change. New code imports lucide icons and renders
// <Icon icon={X} /> directly; brand marks (tool / model / host / IdP logos,
// the SuperBased mark) are NOT icons and never go through here.
//
// The abstract provider glyphs (AnthropicGlyph ... ProviderGlyph) were
// removed: nothing rendered them, and serving-host marks now come from
// HOST_MARKS (./brandMarks.tsx). ToolGlyph lives in ./toolGlyph.tsx.

import type { ReactElement } from "react";
import type { LucideIcon } from "lucide-react";
import {
  ChartColumn,
  CalendarDays,
  Clock,
  Coins,
  Compass,
  Database,
  DollarSign,
  Droplet,
  Eye,
  Flame,
  Layers,
  List,
  Minimize2,
  Percent,
  Search,
  Settings,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
  Wrench,
  Zap,
  Activity,
  AppWindow,
  Braces,
  Globe,
  Monitor,
  SquareTerminal,
} from "lucide-react";
import { Icon } from "../primitives/Icon";

type IconProps = { size?: number; className?: string };

function wrap(glyph: LucideIcon, defaultSize = 14) {
  return function LegacyIcon({ size = defaultSize, className }: IconProps): ReactElement {
    return <Icon icon={glyph} size={size} className={className} />;
  };
}

// ----- nav / KPI icons (lucide-backed) -------------------------------
export const EyeIcon = wrap(Eye);
export const ListIcon = wrap(List);
export const LightningIcon = wrap(Zap);
export const DollarIcon = wrap(DollarSign);
export const BarChartIcon = wrap(ChartColumn);
export const WrenchIcon = wrap(Wrench);
export const DropletIcon = wrap(Droplet);
export const SearchIcon = wrap(Search);
export const SparklesIcon = wrap(Sparkles);
export const GearIcon = wrap(Settings);
export const ShieldIcon = wrap(ShieldCheck);
export const LayersIcon = wrap(Layers);
// BoltIcon was a near-duplicate of LightningIcon; it now reads as activity.
export const BoltIcon = wrap(Activity);
export const DatabaseIcon = wrap(Database);
export const AlertIcon = wrap(TriangleAlert);
export const ClockIcon = wrap(Clock);
export const CalendarIcon = wrap(CalendarDays);
export const CompassIcon = wrap(Compass);
export const PercentIcon = wrap(Percent);
export const FlameIcon = wrap(Flame);
export const CoinsIcon = wrap(Coins);
export const CompressIcon = wrap(Minimize2);

// ToolGlyph: the per-tool mark (the vendor's real logo), re-exported so
// existing importers keep working unchanged.
export { ToolGlyph } from "./toolGlyph";

// ----- capture-surface icons (lucide-backed, default size 12) --------
// One per value of the closed capture-surface vocabulary (node migration 107
// / models.SurfaceCLI..SurfaceWeb). Same glyphs as
// VOCAB_ICONS.captureSurface (./vocabIcons).
export const TerminalIcon = wrap(SquareTerminal, 12);
export const WindowIcon = wrap(AppWindow, 12);
export const MonitorIcon = wrap(Monitor, 12);
export const BracketsIcon = wrap(Braces, 12);
export const GlobeIcon = wrap(Globe, 12);
