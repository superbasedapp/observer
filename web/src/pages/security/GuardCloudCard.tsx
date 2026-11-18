import { useEffect, useState } from "react";
import { NeedsSettingLink } from "@/components/NeedsSettingNotice";
import { placeLink } from "@/lib/settingsPlaces";
import { Globe } from "lucide-react";
import { Button, ChartShell, ConfirmButton, Input, Pill } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { apiReason, fetchJSON, localConfirmHeaders, type QueryParams } from "@/lib/api";
import { markRestartPending } from "@/lib/restartPending";
import {
  GUARD_CLOUD_FEATURES,
  GUARD_CLOUD_TITLES,
  GUARD_CLOUD_WEBHOOK_SOURCE,
  guardCloudAllOff,
  guardCloudConsentNote,
  guardCloudDisclosure,
  guardCloudFeatureState,
  guardCloudRestartNeeded,
  guardCloudSavedLine,
  guardCloudStopNote,
  guardCloudTurnOff,
  guardCloudTurnOn,
  judgeFieldChanges,
  judgeFieldsProblem,
  type GuardCloudChange,
  type GuardCloudFeature,
  type GuardCloudJudgeFields,
  type GuardCloudState,
} from "@/lib/mcpReputation";

// GuardCloudCard - the guard's network features on the Security page's MCP
// tab (plan docs/plans/dashboard-cli-parity-plan-2026-11-06.md, B-G5,
// decision P-2; before it, [guard.cloud] was a hand-written config.toml
// decision). One row per feature: what it sends, where, when, and its state;
// a turn-on with a confirm that discloses exactly that (and anything else
// the master switch would start), a turn-off with no extra step unless it
// stops something else too. Writes go through PUT /api/guard/cloud: a dry run
// first (the daemon validates and diffs), then the save under the owner-local
// confirm token. The route is human-only: guard rule R-165 denies an agent's
// write to it.

const PATH = "/api/guard/cloud";

type SaveResponse = { restart_required_keys?: string[]; state?: GuardCloudState };

export function GuardCloudCard({ onChanged }: { onChanged?: () => void }) {
  const api = useApi<GuardCloudState>(PATH);
  const s = api.data;
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");
  const [judge, setJudge] = useState<GuardCloudJudgeFields>({ endpoint: "", model: "", api_key_env: "" });

  // The judge form starts from the saved fields and follows a reload.
  useEffect(() => {
    if (s) setJudge({ endpoint: s.llm_judge.endpoint, model: s.llm_judge.model, api_key_env: s.llm_judge.api_key_env });
  }, [s?.llm_judge.endpoint, s?.llm_judge.model, s?.llm_judge.api_key_env]); // eslint-disable-line react-hooks/exhaustive-deps

  async function put(body: object): Promise<SaveResponse> {
    const params: QueryParams = s?.config_etag ? { base_etag: s.config_etag } : {};
    const init = async (): Promise<RequestInit> => ({ method: "PUT", headers: await localConfirmHeaders(), body: JSON.stringify(body) });
    // The daemon validates the change and computes the diff without writing.
    await fetchJSON(PATH, { ...params, dry_run: 1 }, await init());
    return fetchJSON<SaveResponse>(PATH, params, await init());
  }

  async function apply(key: string, change: GuardCloudChange, line: string, restart: boolean) {
    setBusy(key);
    setError("");
    setDone("");
    try {
      const out = await put(change.patch);
      if (restart && (out.restart_required_keys ?? []).length > 0) markRestartPending("guard", out.restart_required_keys);
      setDone(line);
      api.reload();
      onChanged?.();
    } catch (e) {
      setError(apiReason(e));
    } finally {
      setBusy(null);
    }
  }

  function turn(f: GuardCloudFeature, on: boolean) {
    if (!s) return;
    const change = on ? guardCloudTurnOn(s, f, f === "llm_judge" ? judge : undefined) : guardCloudTurnOff(s, f);
    const restart = guardCloudRestartNeeded(change, f);
    void apply(`${f}:${on}`, change, guardCloudSavedLine(f, on, restart), restart);
  }

  async function saveJudgeFields() {
    if (!s) return;
    const changes = judgeFieldChanges(s, judge);
    if (Object.keys(changes).length === 0) return;
    const restart = s.llm_judge.active;
    await apply("judge:fields", { patch: { llm_judge: changes }, alsoStarts: [], alsoStops: [] }, restart ? "Judge settings saved; they take effect after the daemon restarts." : "Judge settings saved.", restart);
  }

  const locked = busy !== null || !s;
  const judgeProblem = judgeFieldsProblem(judge);
  const judgeDirty = !!s && Object.keys(judgeFieldChanges(s, judge)).length > 0;

  return (
    <ChartShell
      title="Network features"
      icon={Globe}
      sub="The guard's three optional features that send data off this machine. Each is off until you turn it on here, and each says exactly what it sends before you do. Turning one off is one click."
    >
      {api.loading && !s ? null : !s ? (
        <div className="text-[11.5px] text-danger">{api.error ? apiReason(api.error) : "State unavailable from this daemon."}</div>
      ) : (
        <div className="space-y-3 text-[11.5px]">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-fg-3">Master switch:</span>
            <Pill variant={s.cloud_enabled ? "success" : "neutral"}>{s.cloud_enabled ? "on" : "off"}</Pill>
            {!s.guard_active && (
              <span className="text-fg-3">
                The guard is off, so the LLM judge and webhooks do not run even when on. Turn it on in the Mode card on the
                Overview tab. <NeedsSettingLink link={placeLink("security_mode")} />
              </span>
            )}
            {s.cloud_enabled && (
              <span className="ml-auto">
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={locked}
                  loading={busy === "all:off"}
                  onClick={() => {
                    const c = guardCloudAllOff(s);
                    void apply("all:off", c, "Every network feature off.", guardCloudRestartNeeded(c, "reputation"));
                  }}
                >
                  Turn everything off
                </Button>
              </span>
            )}
          </div>

          {GUARD_CLOUD_FEATURES.map((f) => {
            const state = guardCloudFeatureState(s, f);
            const d = guardCloudDisclosure(s, f);
            const onChange = guardCloudTurnOn(s, f, f === "llm_judge" ? judge : undefined);
            const offChange = guardCloudTurnOff(s, f);
            const stopNote = guardCloudStopNote(offChange);
            const cannotTurnOn = f === "llm_judge" && judgeProblem !== "";
            return (
              <div key={f} className="rounded-2 border border-line-2 bg-bg-3 p-3" data-testid={`guard-cloud-${f}`}>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-fg-1">{GUARD_CLOUD_TITLES[f]}</span>
                  <Pill variant={state === "on" ? "success" : "neutral"}>{state === "none_configured" ? "none configured" : state}</Pill>
                  <span className="ml-auto flex flex-wrap items-center gap-2">
                    {state === "on" ? (
                      <ConfirmButton
                        size="sm"
                        variant="secondary"
                        armedVariant="danger"
                        disabled={locked}
                        loading={busy === `${f}:false`}
                        requireConfirm={stopNote !== ""}
                        armedNote={stopNote || undefined}
                        onConfirm={() => turn(f, false)}
                      >
                        Turn off
                      </ConfirmButton>
                    ) : state === "off" ? (
                      <ConfirmButton
                        size="sm"
                        variant="primary"
                        armedVariant="primary"
                        disabled={locked || cannotTurnOn}
                        loading={busy === `${f}:true`}
                        title={f === "llm_judge" && judgeProblem ? judgeProblem : undefined}
                        confirmLabel="I agree: turn on"
                        armedNote={guardCloudConsentNote(s, f, onChange)}
                        holdArmed
                        onConfirm={() => turn(f, true)}
                      >
                        Turn on
                      </ConfirmButton>
                    ) : null}
                  </span>
                </div>
                <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
                  <dt className="text-fg-3">To</dt>
                  <dd className="m-0 break-words text-fg-2">{d.to}</dd>
                  <dt className="text-fg-3">Sends</dt>
                  <dd className="m-0 text-fg-2">{d.sends}</dd>
                  <dt className="text-fg-3">When</dt>
                  <dd className="m-0 text-fg-2">{d.when}</dd>
                  {d.effect && (
                    <>
                      <dt className="text-fg-3">Effect</dt>
                      <dd className="m-0 text-fg-2">{d.effect}</dd>
                    </>
                  )}
                </dl>
                {f === "llm_judge" && (
                  <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-3">
                    <Input
                      className="font-mono"
                      aria-label="Judge endpoint"
                      placeholder="https://llm.example.com/v1/chat/completions"
                      value={judge.endpoint}
                      maxLength={2048}
                      onChange={(e) => setJudge({ ...judge, endpoint: e.target.value })}
                    />
                    <Input
                      className="font-mono"
                      aria-label="Judge model"
                      placeholder="model name"
                      value={judge.model}
                      maxLength={200}
                      onChange={(e) => setJudge({ ...judge, model: e.target.value })}
                    />
                    <Input
                      className="font-mono"
                      aria-label="Environment variable holding the judge key"
                      placeholder="key variable, e.g. JUDGE_API_KEY"
                      value={judge.api_key_env}
                      maxLength={128}
                      onChange={(e) => setJudge({ ...judge, api_key_env: e.target.value })}
                    />
                    {judgeDirty && (
                      <div className="flex flex-wrap items-center gap-2 sm:col-span-3">
                        {judgeProblem ? (
                          <span className="text-warn">{judgeProblem}</span>
                        ) : (
                          <Button size="sm" variant="secondary" disabled={locked} loading={busy === "judge:fields"} onClick={() => void saveJudgeFields()}>
                            Save judge settings
                          </Button>
                        )}
                      </div>
                    )}
                  </div>
                )}
                {f === "webhooks" && <p className="m-0 mt-2 text-fg-3">{GUARD_CLOUD_WEBHOOK_SOURCE}</p>}
              </div>
            );
          })}
          {done && <div className="text-success">{done}</div>}
          {error && <div className="text-danger">{error}</div>}
        </div>
      )}
    </ChartShell>
  );
}
