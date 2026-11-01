import { MarkTile } from "@/components/primitives";
import { TOOL_LOGOS } from "@shared/lib/toolLogos";
import { HOST_MARKS, MODEL_FAMILY_MARKS, type HostId } from "@shared/lib/brandMarks";
import type { ModelFamilyId } from "@shared/lib/modelFamilies";
import { toolMeta } from "@shared/lib/tools";
import { providerMark } from "@/lib/plansView";

// ProviderMark: a plan provider's mark, drawn from the existing shared mark
// tables through the one PROVIDER_MARKS table (lib/plansView.ts), or a
// monogram when no existing mark is the vendor's own. A tool logo takes the
// tool's colour; a host or model-family mark stays in the text colour.
export function ProviderMark({ provider, size = 32 }: { provider: string; size?: number }) {
  const ref = providerMark(provider);
  switch (ref.kind) {
    case "tool": {
      const logo = TOOL_LOGOS[ref.id];
      return <MarkTile size={size} mark={logo?.mono} letter="?" color={toolMeta(ref.id).colorVar} />;
    }
    case "host":
      return <MarkTile size={size} mark={HOST_MARKS[ref.id as HostId]} letter="?" color="var(--fg-1)" />;
    case "family":
      return <MarkTile size={size} mark={MODEL_FAMILY_MARKS[ref.id as ModelFamilyId]} letter="?" color="var(--fg-1)" />;
    default:
      return <MarkTile size={size} letter={ref.letter} />;
  }
}
