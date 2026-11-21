import { Card, Pill } from "@/components/primitives";
import type { Tone } from "../../../../shared/lib/tone";

// CheckFamiliesCard is the Coverage tab's "What is checked" (security
// coverage gaps plan docs/plans/security-coverage-gaps-plan-2026-11-13.md
// section 2, recommendation 5.1 of the gap analysis): one row per checking
// family (dependency vulnerabilities, secrets, code rules, IaC, workflow
// lint, passive DAST, licences, package provenance) with the components that
// do the checking and their state, from GET /api/security/coverage's
// families. A family that is not selected is shown, never left out.
//
// Working surface: calm register, zero delight elements.

export type CheckFamilyState = "on" | "off" | "not_selected" | "not_in_build";

export type CheckFamily = {
  family: string;
  label: string;
  components: string[];
  state: CheckFamilyState | string;
  note?: string;
};

// One row per state: its words and its tone. An unknown state reads as its
// own id, neutral.
const FAMILY_STATE: Readonly<Record<string, { words: string; tone: Tone }>> = {
  on: { words: "on", tone: "success" },
  off: { words: "off", tone: "warn" },
  not_selected: { words: "not selected", tone: "neutral" },
  not_in_build: { words: "not in this build", tone: "neutral" },
};

/** familyStateWords is a family state in words, with its tone. */
export function familyStateWords(state: string): { words: string; tone: Tone } {
  return FAMILY_STATE[state] ?? { words: state.replace(/_/g, " ") || "unknown", tone: "neutral" };
}

export function CheckFamiliesCard({ families, stale }: { families: CheckFamily[] | undefined; stale?: boolean }) {
  if (!families || families.length === 0) return null;
  const on = families.filter((f) => f.state === "on").length;
  return (
    <Card title="What is checked" sub={`${on} of ${families.length} checking families on. Turn one on in Scanners.`} stale={stale}>
      <ul className="m-0 list-none divide-y divide-line-2 p-0 text-[12.5px]" data-testid="check-families">
        {families.map((f) => {
          const st = familyStateWords(f.state);
          return (
            <li key={f.family} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 py-2" data-family={f.family}>
              <span className="w-48 shrink-0 text-fg-1">{f.label}</span>
              <Pill variant={st.tone}>{st.words}</Pill>
              <span className="font-mono text-[11.5px] text-fg-3">{f.components.join(", ")}</span>
              {f.note && <span className="basis-full text-fg-3">{f.note}</span>}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
