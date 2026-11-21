import { useState } from "react";
import { Button, Card, Select } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { useApi } from "@/lib/useApi";
import { exceptionStateLabel, pickerLabel, securityPost, type ExceptionsResponse } from "@/lib/codeSecurityExceptions";

// ExceptionsTab is the Code security page's Exceptions tab (lane sec-c3):
// the local finding exceptions, each lifting a single finding for a while,
// never a rule wide, with a revoke per row (owner-local, the confirm token
// the list GET mints). Moved out of CodeSecurity.tsx unchanged by the page
// redesign (docs/plans/code-security-page-redesign-plan-2026-11-06.md); the
// only addition is the table's own horizontal scroll, so a narrow screen
// scrolls the table, never the page. Also a CLI verb: `observer security
// exception`.

export function ExceptionsTab() {
  const [showEnded, setShowEnded] = useState("0");
  const list = useApi<ExceptionsResponse>("/api/security/exceptions", { all: showEnded === "1" ? 1 : undefined }, [showEnded]);
  const [err, setErr] = useState<string | null>(null);
  const rows = list.data?.exceptions ?? [];
  async function revoke(id: number) {
    if (!list.data) return;
    setErr(null);
    try {
      await securityPost("/api/security/exceptions/revoke", list.data.confirm_token, { id });
      list.reload();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }
  return (
    <Card
      title="Exceptions"
      sub="Each one excepts a single finding for a while. It ends at its expiry, when its file changes (for 'until the file changes'), or when you revoke it; the finding is then open again."
    >
      <div className="mb-3 max-w-xs">
        <Select
          label="Show"
          value={showEnded}
          onChange={(e) => setShowEnded(e.target.value)}
          options={[
            { value: "0", label: "Exceptions that still apply" },
            { value: "1", label: "Every exception, ended ones too" },
          ]}
        />
      </div>
      {err && <p className="m-0 mb-2 text-danger">{err}</p>}
      <ChartState
        kind="table"
        loading={list.loading}
        stale={list.isStale}
        onRetry={list.reload}
        error={list.error}
        denied={list.denied}
        empty={!list.loading && rows.length === 0}
        emptyHint="No exceptions. Except a finding from the Findings tab, or with `observer security exception add`."
      >
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead className="text-left text-fg-3">
              <tr>
                <th className="py-1.5 pr-3 font-normal">Rule</th>
                <th className="py-1.5 pr-3 font-normal">Where</th>
                <th className="py-1.5 pr-3 font-normal">Reason</th>
                <th className="py-1.5 pr-3 font-normal">Until</th>
                <th className="py-1.5 pr-3 font-normal">State</th>
                <th className="py-1.5 font-normal" />
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.id} className="border-t border-line-1">
                  <td className="py-1.5 pr-3 font-mono text-fg-2">{e.rule_id}</td>
                  <td className="py-1.5 pr-3 font-mono text-fg-3">{e.rel_path}</td>
                  <td className="py-1.5 pr-3 text-fg-2">{pickerLabel(list.data?.reasons ?? [], e.reason)}</td>
                  <td className="py-1.5 pr-3 text-fg-3">
                    {e.expiry === "until_change" ? "file changes, at the latest " : ""}
                    {e.expires_at.slice(0, 10)}
                  </td>
                  <td className="py-1.5 pr-3 text-fg-3">{exceptionStateLabel(e)}</td>
                  <td className="py-1.5">
                    {!e.ended_at && (
                      <Button size="sm" variant="danger-outline" onClick={() => void revoke(e.id)}>
                        Revoke
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </ChartState>
    </Card>
  );
}
