// AuditLog: the staff action log (staff_actions, append-only; GET
// /staff/api/log): every staff and operator action with its reason and
// result, refusals included. Filter by action, org or actor; page back with
// "Load older".

import { useEffect, useState } from "react";
import { ScrollText } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { EmptyState } from "@shared/primitives/EmptyState";
import { ErrorState } from "@shared/primitives/ErrorState";
import { Input } from "@shared/primitives/Input";
import { PageHeader } from "@shared/primitives/PageHeader";
import { Select } from "@shared/primitives/Select";
import { TableSkeleton } from "@shared/primitives/Skeleton";
import { listLog, type LogFilter, type StaffAction } from "../api";
import { LogTable } from "../components/LogTable";
import { VERB_LABELS } from "../lib/model";
import { useStaff } from "../session";

const PAGE = 100;

export function AuditLog() {
  const staff = useStaff();
  const [verb, setVerb] = useState("");
  const [org, setOrg] = useState("");
  const [mine, setMine] = useState(false);
  const [rows, setRows] = useState<StaffAction[] | null>(null);
  const [more, setMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const filter = (): LogFilter => ({
    limit: PAGE,
    verb: verb || undefined,
    org: org.trim() || undefined,
    actor: mine ? `staff:${staff.me.staff_id}` : undefined,
  });

  async function load(before?: string) {
    setBusy(true);
    setError(null);
    try {
      const res = await listLog({ ...filter(), before });
      setRows((prev) => (before && prev ? [...prev, ...res.actions] : res.actions));
      setMore(res.actions.length === PAGE);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    void load();
    // A filter change starts over from the newest row.
  }, [verb, mine]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="Audit log"
        icon={ScrollText}
        sub="Every staff and operator action, with its reason. Append-only: no role can change or remove a row."
      />
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          void load();
        }}
      >
        <Select
          label="Action"
          value={verb}
          onChange={(e) => setVerb(e.target.value)}
          options={[{ value: "", label: "All actions" }, ...Object.entries(VERB_LABELS).map(([value, label]) => ({ value, label }))]}
        />
        <Input label="Org id" value={org} onChange={(e) => setOrg(e.target.value)} mono className="w-80" placeholder="any org" />
        <label className="flex items-center gap-2 pb-2 text-[12px] text-fg-2">
          <input type="checkbox" checked={mine} onChange={(e) => setMine(e.target.checked)} />
          Only mine
        </label>
        <Button type="submit" size="sm" variant="secondary" loading={busy}>
          Apply
        </Button>
      </form>
      {error && !rows ? (
        <ErrorState variant="inline" title="Could not load the log" error={error} onRetry={() => void load()} />
      ) : !rows ? (
        <TableSkeleton />
      ) : rows.length === 0 ? (
        <EmptyState variant="inline" title="No action matches" />
      ) : (
        <>
          <LogTable actions={rows} self={staff.me.staff_id} />
          {error && <ErrorState variant="compact" title="Could not load older rows" error={error} />}
          {more && (
            <div>
              <Button size="sm" variant="secondary" loading={busy} onClick={() => void load(rows[rows.length - 1].at)}>
                Load older
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
