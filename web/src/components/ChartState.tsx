import type { ComponentProps } from "react";
import { ChartState as SharedChartState } from "@shared/charts/ChartState";
import { NeedsSettingNotice } from "@/components/NeedsSettingNotice";
import { bodyText, errorText, needsSettingOf, parseErrorBody } from "@/lib/needsSetting";

// The node dashboard's ChartState: the shared one, plus the node's reading of
// a failed read (lib/needsSetting.ts). A read refused because a setting or a
// component is off renders the one "needs a setting" notice with its deep
// link instead of a red failure with a Retry that cannot succeed; any other
// JSON refusal shows the server's sentence, never the raw body.
export function ChartState(props: ComponentProps<typeof SharedChartState>) {
  const { error, loading, denied, height = 220 } = props;
  if (error && !loading && !denied) {
    const link = needsSettingOf(error);
    if (link) {
      return (
        <div className="flex items-center justify-center p-3" style={{ minHeight: height }}>
          <NeedsSettingNotice text={errorText(error)} link={link} className="w-full max-w-xl" />
        </div>
      );
    }
    const body = (error as { body?: unknown }).body;
    if (bodyText(parseErrorBody(body))) {
      return <SharedChartState {...props} error={new Error(errorText(error))} />;
    }
  }
  return <SharedChartState {...props} />;
}
