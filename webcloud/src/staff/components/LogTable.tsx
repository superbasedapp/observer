// LogTable renders staff_actions rows (GET /staff/api/log): when, who, what,
// the target, the reason and the result; a row opens its detail (the value
// written and the one it replaced, for an availability change).

import { Fragment, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { JsonPreview } from "@shared/primitives/JsonPreview";
import { Pill } from "@shared/primitives/Pill";
import { Table } from "@shared/primitives/Table";
import type { StaffAction } from "../api";
import { actorLabel, formatTime, shortId, verbLabel } from "../lib/model";

export function LogTable({ actions, self, showOrg = true }: { actions: StaffAction[]; self?: string; showOrg?: boolean }) {
  const [open, setOpen] = useState<string | null>(null);
  const cols = showOrg ? 7 : 6;
  return (
    <Table
      padded
      minWidth={860}
      head={
        <tr>
          <th />
          <th>When</th>
          <th>Who</th>
          <th>Action</th>
          {showOrg && <th>Org</th>}
          <th>Reason</th>
          <th>Result</th>
        </tr>
      }
    >
      {actions.map((a) => {
        const isOpen = open === a.action_id;
        const Chevron = isOpen ? ChevronDown : ChevronRight;
        return (
          <Fragment key={a.action_id}>
            <tr className="cursor-pointer hover:bg-bg-2" onClick={() => setOpen(isOpen ? null : a.action_id)} aria-expanded={isOpen}>
              <td className="w-6">
                <Chevron size={13} aria-hidden="true" />
              </td>
              <td className="whitespace-nowrap text-fg-3">{formatTime(a.at)}</td>
              <td className="whitespace-nowrap">{actorLabel(a.actor, self)}</td>
              <td>
                <div>{verbLabel(a.verb)}</div>
                {a.target && <div className="font-mono text-[10.5px] text-fg-3">{a.target}</div>}
              </td>
              {showOrg && <td className="font-mono text-[11px]">{a.org_id ? shortId(a.org_id) : "-"}</td>}
              <td className="max-w-[320px] whitespace-pre-wrap text-fg-2">{a.reason}</td>
              <td>
                <Pill variant={a.result === "ok" ? "success" : "danger"}>{a.result}</Pill>
              </td>
            </tr>
            {isOpen && (
              <tr>
                <td colSpan={cols}>
                  <div className="flex flex-col gap-2 py-2 text-[11.5px]">
                    <span className="font-mono text-fg-3">
                      {a.action_id} · {a.actor}
                      {a.org_id ? ` · org ${a.org_id}` : ""}
                    </span>
                    {a.detail !== undefined && a.detail !== null ? (
                      <JsonPreview label="Detail" value={a.detail} maxHeight={220} copy />
                    ) : (
                      <span className="text-fg-3">No detail recorded.</span>
                    )}
                  </div>
                </td>
              </tr>
            )}
          </Fragment>
        );
      })}
    </Table>
  );
}
