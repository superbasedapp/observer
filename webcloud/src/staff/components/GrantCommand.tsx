// GrantCommand prepares the operator's plan grant command. Plan grants are an
// operator-only CLI write (W15-D13, cloud 0095: "never an HTTP route"), so
// the console never writes one: it builds the exact `observer-cloud
// grant-plan org` line, with the CLI's own refusals, for the operator to run
// against the admin DSN. The row it writes is its own audit (actor
// "operator", the reason), and shows up in the history above it.

import { useState } from "react";
import { Callout } from "@shared/primitives/Callout";
import { CopyOnClick } from "@shared/primitives/CopyOnClick";
import { Input } from "@shared/primitives/Input";
import { SegmentedControl } from "@shared/primitives/SegmentedControl";
import { Textarea } from "@shared/primitives/Textarea";
import { grantCommand, type GrantCommandInput } from "../lib/model";

export function GrantCommand({ orgId, kind }: { orgId: string; kind: string }) {
  const [g, setG] = useState<GrantCommandInput>({ action: "grant", orgId, plan: kind === "team" ? "team" : "", version: "", until: "", reason: "" });
  const out = grantCommand(g);
  const set = (patch: Partial<GrantCommandInput>) => setG({ ...g, ...patch });
  return (
    <div className="flex flex-col gap-3">
      <SegmentedControl
        size="sm"
        value={g.action}
        onChange={(v) => set({ action: v })}
        options={[
          { value: "grant", label: "Grant a plan" },
          { value: "revoke", label: "Revoke the grant" },
        ]}
      />
      {g.action === "grant" && (
        <div className="flex flex-wrap gap-3">
          <Input label="Plan" value={g.plan} onChange={(e) => set({ plan: e.target.value })} mono className="w-36" help={`A catalog plan of kind ${kind}.`} />
          <Input label="Version" value={g.version} onChange={(e) => set({ version: e.target.value })} mono className="w-24" help="Empty: newest." />
          <Input
            label="Ends"
            value={g.until}
            onChange={(e) => set({ until: e.target.value })}
            mono
            className="w-60"
            placeholder="2027-01-01T00:00:00Z"
            help="Empty: until revoked."
          />
        </div>
      )}
      <Textarea label="Reason" value={g.reason} onChange={(e) => set({ reason: e.target.value })} rows={2} help="Kept with the grant row." />
      {out.errors.length > 0 ? (
        <Callout tone="warn" title="The CLI would refuse this">
          <ul className="list-disc pl-4">
            {out.errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        </Callout>
      ) : (
        <div className="flex flex-col gap-1">
          <span className="text-[11.5px] text-fg-3">Run on the operator host, against the admin DSN:</span>
          <CopyOnClick value={out.command}>
            <code className="block whitespace-pre-wrap break-all rounded-md border border-line-2 bg-bg-2 px-3 py-2 font-mono text-[11.5px] text-fg-1">
              {out.command}
            </code>
          </CopyOnClick>
        </div>
      )}
    </div>
  );
}
