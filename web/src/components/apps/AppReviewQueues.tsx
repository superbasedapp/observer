import { useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { ClipboardCheck, Plus } from "lucide-react";
import {
  Button,
  Card,
  ChartShell,
  DataTable,
  EmptyState,
  ErrorState,
  InfoDisclosure,
  Input,
  Pill,
  SegmentedControl,
  Select,
  TableSkeleton,
  Textarea,
  Toggle,
} from "@/components/primitives";
import { GatedLink } from "@/components/GatedLink";
import { dateTime, num } from "@shared/lib/displayFormat";
import { fetchJSON, localConfirmHeaders } from "@/lib/api";
import { useApi } from "@/lib/useApi";

// Your apps > Evals > Review queues (Plane A build-out W5-6 machine parity,
// lane C10; internal/obs/httpapi review.go): the machine's single-reviewer
// review queue. A queue holds traces you judge against a rubric; a review is
// one score per answer (source review) on the trace. A queue can route
// traces with negative end-user feedback into itself. Assignment, several
// reviewers per item and adjudication need more than one person, so they
// live on the organization's dashboard, not on this machine.

type Kind = "boolean" | "numeric" | "categorical";

interface Criterion {
  name: string;
  kind: Kind;
  min?: number;
  max?: number;
  options?: string[];
  required?: boolean;
}

interface Queue {
  queue_id: string;
  name: string;
  description: string;
  rubric: Criterion[];
  route_rules: { source?: string; name?: string; match?: string }[];
  pending: number;
  done: number;
  skipped: number;
  updated_at: string;
}

interface Item {
  item_id: string;
  trace_id: string;
  status: string;
  added_by: string;
}

const BASE = "/api/obs/review-queues";

async function write<T>(path: string, method: string, body: unknown): Promise<T> {
  return fetchJSON<T>(path, undefined, { method, headers: await localConfirmHeaders(), body: JSON.stringify(body ?? {}) });
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function NewQueue({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [name, setName] = useState("");
  const [criteria, setCriteria] = useState("correct");
  const [route, setRoute] = useState(true);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const missing = !name.trim() ? "Name the queue." : !criteria.trim() ? "Add at least one criterion." : null;
  async function create() {
    setErr(null);
    setBusy(true);
    const rubric: Criterion[] = criteria
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .map((n) => ({ name: n, kind: "boolean", required: true }));
    try {
      await write(BASE, "POST", { name, rubric, route_rules: route ? [{ source: "feedback", match: "negative" }] : [] });
      setName("");
      onDone();
    } catch (e) {
      setErr(message(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <form
      className="mb-3 space-y-3 rounded-2 border border-line-2 p-3"
      aria-label="New review queue"
      onSubmit={(e) => {
        e.preventDefault();
        if (!missing) void create();
      }}
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Input label="Queue name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Answer quality" />
        <Input
          label="Yes / no criteria"
          help="Comma separated, one question each."
          value={criteria}
          onChange={(e) => setCriteria(e.target.value)}
        />
      </div>
      <Toggle on={route} onChange={setRoute} label="Add traces that get negative user feedback" />
      <div className="flex flex-wrap items-center gap-2">
        <Button type="submit" size="sm" variant="primary" disabled={!!missing} loading={busy} title={missing ?? undefined}>
          Create queue
        </Button>
        <Button size="sm" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        {err && (
          <span role="alert" className="text-[11.5px] text-danger">
            {err}
          </span>
        )}
      </div>
    </form>
  );
}

function Answer({ c, value, onChange }: { c: Criterion; value: unknown; onChange: (v: unknown) => void }) {
  if (c.kind === "boolean") {
    return (
      <SegmentedControl
        size="sm"
        options={[
          { value: "yes", label: "Yes" },
          { value: "no", label: "No" },
        ]}
        value={value === true ? "yes" : value === false ? "no" : ""}
        onChange={(v) => onChange(v === "yes")}
      />
    );
  }
  if (c.kind === "categorical") {
    return (
      <Select
        aria-label={c.name}
        className="w-48"
        value={(value as string) ?? ""}
        onChange={(e) => onChange(e.target.value || undefined)}
        options={[{ value: "", label: "Choose..." }, ...(c.options ?? []).map((o) => ({ value: o, label: o }))]}
      />
    );
  }
  return (
    <Input
      aria-label={c.name}
      className="w-24"
      inputMode="decimal"
      placeholder={c.min != null && c.max != null ? `${c.min} to ${c.max}` : undefined}
      onChange={(e) => onChange(e.target.value === "" ? undefined : Number(e.target.value))}
    />
  );
}

function Review({ queue, onChange }: { queue: Queue; onChange: () => void }) {
  const next = useApi<{ item: Item | null }>(`${BASE}/${queue.queue_id}/next`, undefined, [queue.pending]);
  const [answers, setAnswers] = useState<Record<string, unknown>>({});
  const [note, setNote] = useState("");
  const [traces, setTraces] = useState("");
  const [msg, setMsg] = useState<{ tone: "ok" | "err"; text: string } | null>(null);
  const item = next.data?.item ?? null;
  async function act(kind: "review" | "skip") {
    if (!item) return;
    setMsg(null);
    try {
      await write(`${BASE}/${queue.queue_id}/items/${item.item_id}/${kind}`, "POST", kind === "review" ? { answers, note } : {});
      setAnswers({});
      setNote("");
      onChange();
      next.reload();
    } catch (e) {
      setMsg({ tone: "err", text: message(e) });
    }
  }
  async function add() {
    setMsg(null);
    try {
      const r = await write<{ added: number; skipped_duplicate: number }>(`${BASE}/${queue.queue_id}/items`, "POST", {
        items: traces
          .split(/[\s,]+/)
          .filter(Boolean)
          .map((trace_id) => ({ trace_id })),
      });
      setMsg({ tone: "ok", text: `Added ${r.added}, ${r.skipped_duplicate} already in the queue.` });
      setTraces("");
      onChange();
    } catch (e) {
      setMsg({ tone: "err", text: message(e) });
    }
  }
  return (
    <Card icon={ClipboardCheck} title={`Review: ${queue.name}`} className="mt-3" bodyClassName="space-y-3 text-[12px]">
      {next.error ? (
        <ErrorState error={next.error} onRetry={next.reload} />
      ) : !item ? (
        <EmptyState variant="inline" title="Nothing pending in this queue" body="Add traces below, or wait for negative feedback to route some here." />
      ) : (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2 text-fg-2">
            Trace
            <GatedLink
              to={`/apps/traces?trace=${encodeURIComponent(item.trace_id)}`}
              managed={<span className="font-mono text-[11.5px] text-fg-1">{item.trace_id.slice(0, 16)}</span>}
              className="font-mono text-[11.5px] text-accent hover:underline"
            >
              {item.trace_id.slice(0, 16)}
            </GatedLink>
            {item.added_by === "route:feedback" && <Pill variant="info">from negative feedback</Pill>}
          </div>
          {queue.rubric.map((c) => (
            <div key={c.name} className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <span className="w-40 text-fg-2">
                {c.name}
                {c.required && <span className="text-fg-4"> (required)</span>}
              </span>
              <Answer c={c} value={answers[c.name]} onChange={(v) => setAnswers({ ...answers, [c.name]: v })} />
            </div>
          ))}
          <Textarea
            label="Note"
            help="Kept only when this machine stores app content."
            rows={2}
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
          <div className="flex gap-2">
            <Button size="sm" variant="primary" onClick={() => void act("review")}>
              Submit review
            </Button>
            <Button size="sm" variant="secondary" onClick={() => void act("skip")}>
              Skip
            </Button>
          </div>
        </div>
      )}
      <form
        className="flex flex-wrap items-end gap-2 border-t border-line-1 pt-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (traces.trim()) void add();
        }}
      >
        <Input
          label="Add traces"
          className="w-full sm:w-80"
          mono
          placeholder="Trace ids, comma or space separated"
          value={traces}
          onChange={(e) => setTraces(e.target.value)}
        />
        <Button type="submit" size="sm" variant="secondary" disabled={!traces.trim()}>
          Add
        </Button>
      </form>
      {msg && (
        <p role="status" className={msg.tone === "err" ? "text-danger" : "text-fg-2"}>
          {msg.text}
        </p>
      )}
    </Card>
  );
}

/** AppReviewQueues is the machine's review queue section. */
export function AppReviewQueues() {
  const queues = useApi<{ queues: Queue[] }>(BASE);
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const rows = queues.data?.queues ?? [];
  const queue = rows.find((q) => q.queue_id === selected) ?? null;
  const columns = useMemo<ColumnDef<Queue, any>[]>(
    () => [
      { accessorKey: "name", header: "Queue", cell: (c) => <span className="font-medium text-fg-1">{c.row.original.name}</span> },
      {
        id: "rubric",
        header: "Rubric",
        cell: (c) => (
          <span className="inline-flex flex-wrap gap-1">
            {c.row.original.rubric.map((r) => (
              <Pill key={r.name} variant="neutral" case="none">
                {r.name}
              </Pill>
            ))}
          </span>
        ),
      },
      { accessorKey: "pending", header: "Pending", cell: (c) => num(c.row.original.pending), meta: { align: "right" } },
      { accessorKey: "done", header: "Done", cell: (c) => num(c.row.original.done), meta: { align: "right" } },
      { accessorKey: "skipped", header: "Skipped", cell: (c) => num(c.row.original.skipped), meta: { align: "right" } },
      {
        id: "route",
        header: "Feedback route",
        cell: (c) =>
          c.row.original.route_rules.length > 0 ? <Pill variant="success">on</Pill> : <Pill variant="neutral">off</Pill>,
      },
      { accessorKey: "updated_at", header: "Updated", cell: (c) => dateTime(c.row.original.updated_at), meta: { align: "right" } },
    ],
    [],
  );
  return (
    <ChartShell
      title="Review queues"
      icon={ClipboardCheck}
      sub="Judge your apps' traces against a rubric; each review becomes scores on the trace."
      right={
        !creating && (
          <Button size="sm" variant="secondary" iconLeft={Plus} onClick={() => setCreating(true)}>
            New queue
          </Button>
        )
      }
    >
      <InfoDisclosure className="mb-3">
        This machine has one reviewer. Assigning reviewers, several reviewers per item and adjudication are on your
        organization&apos;s dashboard.
      </InfoDisclosure>
      {creating && (
        <NewQueue
          onCancel={() => setCreating(false)}
          onDone={() => {
            setCreating(false);
            queues.reload();
          }}
        />
      )}
      {queues.error ? (
        <ErrorState error={queues.error} onRetry={queues.reload} />
      ) : queues.loading && !queues.data ? (
        <TableSkeleton rows={3} />
      ) : rows.length === 0 ? (
        <EmptyState variant="inline" title="No review queues yet" body="Create one with New queue to judge traces against a rubric." />
      ) : (
        <DataTable
          data={rows}
          columns={columns}
          rowKey={(r) => r.queue_id}
          onRowClick={(r) => setSelected(r.queue_id)}
          rowClassName={(r) => (r.queue_id === selected ? "bg-accent-soft" : undefined)}
          zebra
          minWidth={720}
        />
      )}
      {queue && <Review key={queue.queue_id} queue={queue} onChange={queues.reload} />}
    </ChartShell>
  );
}
