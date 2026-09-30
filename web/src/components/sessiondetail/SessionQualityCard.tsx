import { useState } from "react";
import { Button } from "@shared/primitives";
import { QualityPanel } from "@shared/components/sessiondetail";
import { scoreSessionNow, sessionQualityPath } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { SessionQualityResponse } from "@/lib/types";

// SessionQualityCard - the node drawer's session quality score (spec §15.2)
// on the Overview tab. It reads GET /api/session/<id>/quality and renders the
// SHARED QualityPanel, which the org drawer also mounts (read-only) over
// GET /api/org/sessions/<id>/quality once the node has pushed the score.
//
// The daemon scores a session on its own once it has been idle for
// [intelligence.scoring] idle_minutes (default 30). "Score now" / "Re-score"
// POSTs the same route to score it immediately - useful for a session you are
// looking at while it is still active, or one scored before newer actions.
export function SessionQualityCard({ sessionId }: { sessionId: string }) {
  const quality = useApi<SessionQualityResponse>(sessionQualityPath(sessionId), undefined, [sessionId]);
  const [override, setOverride] = useState<SessionQualityResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [scoreError, setScoreError] = useState<string | null>(null);

  // A POST answer supersedes the GET until the session changes.
  const data = override && override.session_id === sessionId ? override : quality.data;
  const canScore = !!data && data.current_action_count > 0;

  const onScore = async () => {
    setBusy(true);
    setScoreError(null);
    try {
      setOverride(await scoreSessionNow(sessionId));
    } catch (e) {
      setScoreError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const action = canScore ? (
    <span className="flex items-center gap-2">
      {scoreError && <span className="text-[10px] text-danger">{scoreError}</span>}
      <Button size="sm" variant="secondary" loading={busy} onClick={() => void onScore()}>
        {data?.scored ? "Re-score" : "Score now"}
      </Button>
    </span>
  ) : null;

  return (
    <QualityPanel
      quality={data}
      loading={quality.loading}
      error={quality.error}
      denied={quality.denied}
      deniedPermission={quality.deniedPermission}
      action={action}
    />
  );
}
