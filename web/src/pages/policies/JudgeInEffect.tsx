import { Gavel } from "lucide-react";
import { Callout, ChartShell, HelpTooltip, InlineLoading, Pill } from "@/components/primitives";
import { GatedLink } from "@/components/GatedLink";
import { useApi } from "@/lib/useApi";
import { PLACES } from "@/lib/settingsPlaces";
import { JUDGE_SOURCE_WORDS, judgeLine, judgeOffersOrg, judgeSourceOf, type JudgeInEffect as JudgeInEffectResult } from "@/lib/modelCalls";

// JudgeInEffect answers "which judge decides my app's judged criteria?" on
// the Policies > Guardrails tab (hosted AI gateway arc, plan section 4 item
// 3; the read is lane L7's GET /api/obs/admission/judge). Which judge applies
// is decided by where the check is sent: this machine's own judge settings,
// or the organization's judge when the machine relays its checks there. The
// editor for this machine's judge is the Judge card right below; the
// relay is set on Settings > AI Apps (or `observer obs admission setup`).
//
// An older daemon answers 404: the card is then left out, never a red error.

export const JUDGE_PATH = "/api/obs/admission/judge";

/** The Model calls page (Your apps), where app lanes are added. */
export const MODEL_CALLS_HREF = "/apps/model-calls";

export function JudgeInEffect() {
  const q = useApi<JudgeInEffectResult>(JUDGE_PATH);
  if (q.status === 404) return null;
  if (q.error) return null;
  if (q.loading && !q.data) {
    return (
      <ChartShell title="Judge in effect" icon={Gavel}>
        <InlineLoading label="Loading the judge in effect" />
      </ChartShell>
    );
  }
  if (!q.data) return null;
  const src = judgeSourceOf(q.data);
  const words = JUDGE_SOURCE_WORDS[src];
  const j = q.data.judge;
  return (
    <ChartShell
      title={
        <span className="inline-flex items-center gap-2">
          Judge in effect <Pill variant={words.tone} case="none">{words.label}</Pill>
        </span>
      }
      icon={Gavel}
      sub="The judge that decides judged criteria for checks sent to this machine."
      right={
        <HelpTooltip
          subject="the judge in effect on the command line"
          technical
          content="observer obs admission status"
        />
      }
    >
      <p className="text-[12.5px] text-fg-2">{judgeLine(q.data)}</p>
      {j?.provider && <p className="mt-1 text-[11.5px] text-fg-3">Provider: {j.provider}</p>}
      {q.data.note && <p className="mt-1 text-[11.5px] text-fg-3">{q.data.note}</p>}
      {src === "none" && (
        <Callout title="Judged criteria are not judged" className="mt-3">
          Set this machine&apos;s judge in the Judge card below, or relay checks to your organization in{" "}
          <GatedLink to={PLACES.observability_settings.href} className="text-accent hover:underline">
            {PLACES.observability_settings.label}
          </GatedLink>
          .
        </Callout>
      )}
      {judgeOffersOrg(q.data) && (
        <Callout title="Your organization has a judge" className="mt-3">
          This machine can send its checks to it instead.{" "}
          <GatedLink to={PLACES.observability_settings.href} className="text-accent hover:underline">
            Use it in {PLACES.observability_settings.label}
          </GatedLink>
        </Callout>
      )}
      <p className="mt-3 text-[11.5px] text-fg-3">
        The same checks apply to app calls sent through a lane on this machine.{" "}
        <GatedLink to={MODEL_CALLS_HREF} managed={null} className="text-accent hover:underline">
          Model calls
        </GatedLink>
      </p>
    </ChartShell>
  );
}
