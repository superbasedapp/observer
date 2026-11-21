import { useState } from "react";
import { Button } from "@/components/primitives";
import { securityPost } from "@/lib/codeSecurityExceptions";
import {
  explainAskingLabel,
  explainBody,
  explainHeading,
  explainPath,
  explainView,
  explainVisible,
  type ExplainMode,
  type SecurityExplanation,
} from "@/lib/codeSecurityExplain";

/** What the Explain button shows under a finding once the judge answered. */
export type ExplainShown = { body: string; note: string };

/**
 * ExplainButtonView is the stateless half of the Explain and "Suggest a fix"
 * buttons: the two buttons (both disabled while either is asked) and the
 * judge's answer as plain text with its advisory note. ExplainButton owns
 * the state; the view is exported so the component test can render each
 * state with react-dom/server. Without onFix only Explain shows.
 */
export function ExplainButtonView({
  findingId,
  busy,
  view,
  onExplain,
  onFix,
  mode = "explain",
}: {
  findingId: string;
  busy: boolean;
  view: ExplainShown | null;
  onExplain: () => void;
  onFix?: () => void;
  /** Which ask is in flight or answered. */
  mode?: ExplainMode;
}) {
  return (
    <div className="mt-1" data-testid={`code-security-explain-${findingId}`}>
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="ghost" disabled={busy} onClick={onExplain}>
          {busy && mode === "explain" ? explainAskingLabel("explain") : "Explain"}
        </Button>
        {onFix && (
          <Button size="sm" variant="ghost" disabled={busy} onClick={onFix} data-testid={`code-security-fix-${findingId}`}>
            {busy && mode === "fix" ? explainAskingLabel("fix") : "Suggest a fix"}
          </Button>
        )}
      </div>
      {view && (
        <div className="mt-2 rounded-2 border border-line-2 bg-bg-2 p-3">
          {onFix && <p className="m-0 mb-1 text-small text-fg-3">{explainHeading(mode)}</p>}
          <p className="m-0 whitespace-pre-wrap text-small text-fg-2">{view.body}</p>
          {view.note && <p className="m-0 mt-2 text-small text-fg-3">{view.note}</p>}
        </div>
      )}
    </div>
  );
}

/**
 * ExplainButton asks the configured judge to explain one finding, or to
 * suggest a fix for it (component security.feedback; the dashboard form of
 * `observer security explain [--fix]`). It renders nothing unless
 * security.feedback is selected (`selected` is GET /api/components/state's
 * security_selected; an unknown selection shows nothing). The answer is
 * advisory and shown as plain text; it changes nothing on the finding.
 */
export function ExplainButton({
  findingId,
  token,
  selected,
}: {
  findingId: string;
  token: string;
  selected: readonly string[] | null | undefined;
}) {
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState<ExplainMode>("explain");
  const [view, setView] = useState<ExplainShown | null>(null);
  if (!explainVisible(selected)) return null;
  async function ask(next: ExplainMode) {
    setBusy(true);
    setMode(next);
    setView(null);
    try {
      setView(explainView(await securityPost<SecurityExplanation>(explainPath(findingId), token, explainBody(next))));
    } catch (e: unknown) {
      setView({ body: e instanceof Error ? e.message : String(e), note: "" });
    } finally {
      setBusy(false);
    }
  }
  return (
    <ExplainButtonView
      findingId={findingId}
      busy={busy}
      view={view}
      mode={mode}
      onExplain={() => void ask("explain")}
      onFix={() => void ask("fix")}
    />
  );
}
