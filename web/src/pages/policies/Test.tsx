import { useState } from "react";
import { Play } from "lucide-react";
import {
  Button,
  Card,
  ChartShell,
  ErrorState,
  InfoDisclosure,
  Pill,
  SinglePicker,
  Textarea,
  VocabDefPill,
} from "@/components/primitives";
import { DefinitionList, DefinitionRow } from "@shared/primitives/DefinitionList";
import { keepSelected } from "@/lib/pickerOptions";
import { useEndUserOptions } from "@/lib/usePickerSources";
import { fetchJSON } from "@/lib/api";
import { fmtInt } from "@/lib/format";
import { severityTone } from "@shared/lib/guardCatalog";
import { VocabPill } from "@shared/lib/vocabPill";
import { ADMISSION_DECISION, ADMISSION_DEGRADED } from "@shared/lib/obsVocab";
import { POLICY_MODE } from "@/lib/vocabTones";
import { type Verdict, policyErrorText } from "./types";
import { TEST_SAMPLES } from "./samples";
import { POLICY_MODE_LABEL, VERDICT_PATH_LABEL, isGenuineDegraded, wordsFor } from "./vocab";

// Test tab: a dry-run tester over the LIVE admission policy. It POSTs to
// /api/obs/admission/test (Persist:false) so it records NOTHING in the audit
// log, but it DOES run the judge for a judged criterion (spending judge tokens)
// and previews what enforce mode would decide even while the node is in
// observe. Use it to sanity-check a policy before flipping to enforce.


export function TestTab() {
  const [text, setText] = useState(TEST_SAMPLES[0]);
  const [user, setUser] = useState("test-user");
  // D-571: the end user is picked from users seen on verdicts (or typed).
  const users = useEndUserOptions([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [verdict, setVerdict] = useState<Verdict | null>(null);

  async function run() {
    if (!text.trim()) return;
    setBusy(true);
    setErr("");
    setVerdict(null);
    try {
      const v = await fetchJSON<Verdict>("/api/obs/admission/test", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, user }),
      });
      setVerdict(v);
    } catch (e) {
      // Worded by status, never the API's own text (U-13).
      setErr(policyErrorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <ChartShell
        title="Test a request"
        sub="Runs one message through the live admission policy and shows which layer decided. Records nothing."
      >
        <InfoDisclosure className="mb-3">
          A judged criterion still calls the judge, which spends judge tokens. The result also shows what enforce mode
          would decide while the policy only observes.
        </InfoDisclosure>
        <div className="mb-2 flex flex-wrap gap-1.5">
          {TEST_SAMPLES.map((s) => (
            <Button key={s} size="sm" variant="ghost" onClick={() => setText(s)} title={s}>
              {s.length > 40 ? s.slice(0, 38) + "…" : s}
            </Button>
          ))}
        </div>

        <Textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={3}
          placeholder="Type an end-user request"
          aria-label="Request text"
        />
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <div className="inline-flex items-center gap-2">
            <span className="text-[11px] font-medium text-fg-2">End user</span>
            <SinglePicker
              className="min-w-[12rem]"
              options={keepSelected(users.options, user ? [user] : [])}
              value={user}
              onChange={setUser}
              allowFree
              loading={users.loading}
              placeholder="end user"
              ariaLabel="End user"
            />
          </div>
          <Button
            variant="primary"
            iconLeft={Play}
            loading={busy}
            disabled={busy || !text.trim()}
            title={!text.trim() ? "Type a request to test." : undefined}
            onClick={() => void run()}
          >
            {busy ? "Running" : "Run test"}
          </Button>
        </div>

        {err && <ErrorState className="mt-3" title="Couldn't run the test" error={err} onRetry={() => void run()} />}
      </ChartShell>

      {verdict && <VerdictCard v={verdict} />}
    </div>
  );
}

// VerdictPath names which layer decided: the judge, a deterministic check,
// or a judge that failed open. The verdict's `degraded` field is a CODE
// (admission pipeline.go Degraded*), not a flag: only the genuine fail-open
// codes mean the judge was unavailable; any other code names the
// deterministic layer that decided (a pre-filter deny is not degraded).
function VerdictPath({ v }: { v: Verdict }) {
  const code = v.degraded ?? "";
  if (isGenuineDegraded(code)) return <VocabDefPill of={ADMISSION_DEGRADED} value={code} />;
  return (
    <>
      {v.judge_used ? <Pill variant="info">judge used</Pill> : <Pill variant="neutral">deterministic</Pill>}
      {code && <Pill variant="neutral">{wordsFor(VERDICT_PATH_LABEL, code)}</Pill>}
    </>
  );
}

function ModeWords({ mode }: { mode: string }) {
  return (
    <VocabPill vocab="guardMode" table={POLICY_MODE} value={mode}>
      {wordsFor(POLICY_MODE_LABEL, mode)}
    </VocabPill>
  );
}

function VerdictCard({ v }: { v: Verdict }) {
  return (
    <Card
      title="Verdict"
      actions={
        <span className="flex flex-wrap items-center gap-1.5">
          <VocabDefPill of={ADMISSION_DECISION} value={v.decision} />
          <VocabPill vocab="guardSeverity" value={v.severity} tone={severityTone(v.severity)} />
          <VerdictPath v={v} />
        </span>
      }
    >
      <DefinitionList>
        <DefinitionRow label="Policy mode" value={<ModeWords mode={v.mode} />} />
        <DefinitionRow
          label="Enforce mode would"
          value={
            <span className="inline-flex flex-wrap items-center justify-end gap-1.5">
              <VocabDefPill of={ADMISSION_DECISION} value={v.enforce_decision} />
              {v.mode !== "enforce" && <span className="text-[11px] font-normal text-fg-3">(preview only)</span>}
            </span>
          }
        />
        {v.criterion && <DefinitionRow label="Criterion" value={<span className="font-mono text-[11px]">{v.criterion}</span>} />}
        {v.reason && <DefinitionRow label="Reason" value={<span className="font-normal text-fg-2">{v.reason}</span>} />}
        <DefinitionRow label="Latency" value={`${fmtInt(v.latency_ms)} ms`} />
      </DefinitionList>
    </Card>
  );
}
