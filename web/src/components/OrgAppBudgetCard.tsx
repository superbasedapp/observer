import { Card, Pill } from "@/components/primitives";
import { GatedLink } from "@/components/GatedLink";
import { fmtUSD } from "@/lib/format";
import { PLACES } from "@/lib/settingsPlaces";
import { orgAppBudgetLead, orgAppCapLimit, orgAppCapWho, type OrgAppCap } from "@/lib/orgAppBudget";

export type { OrgAppCap };

// OrgAppBudgetCard shows the organization's app budgets in force on this
// machine (Plane A W4-1); the words are src/lib/orgAppBudget.ts. When the
// budgets are not applied yet the card links to where the machine gets them
// (every reason links to its fix).
export function OrgAppBudgetCard({
  applied,
  authoritative,
  caps,
}: {
  applied: boolean;
  authoritative: boolean;
  caps: OrgAppCap[];
}) {
  return (
    <Card
      title="Organization app budgets"
      actions={
        !applied ? (
          <GatedLink to={PLACES.account.href} managed={null} className="text-caption font-medium text-accent hover:underline">
            Open {PLACES.account.label}
          </GatedLink>
        ) : undefined
      }
    >
      <p className="mb-2 text-[12px] text-fg-3">{orgAppBudgetLead(applied, authoritative, caps.length)}</p>
      {applied && caps.length > 0 && (
        <ul className="space-y-1 text-[12px]">
          {caps.map((c, i) => (
            <li key={`${c.budget_id ?? ""}-${i}`} className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
              <span className="text-fg-1">{orgAppCapWho(c)}</span>
              <span className="flex items-center gap-2 text-fg-2">
                {orgAppCapLimit(c, fmtUSD)}
                <Pill variant={c.enforcement === "hard" ? "info" : "neutral"}>{c.enforcement === "hard" ? "blocks" : "warns"}</Pill>
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
