import { useState } from "react";
import { Button } from "@/components/primitives";
import { securityPost } from "@/lib/codeSecurityExceptions";
import { explainPath, explainView, explainVisible, type SecurityExplanation } from "@/lib/codeSecurityExplain";

/** What the Explain button shows under a finding once the judge answered. */
export type ExplainShown = { body: string; note: string };

/**
 * ExplainButtonView is the stateless half of the Explain button: the button
 * (disabled while asking) and the judge's answer as plain text with its
 * advisory note. ExplainButton owns the state; the view is exported so the
 * component test can render each state with react-dom/server.
 */
export function ExplainButtonView({
  findingId,
  busy,
  view,
  onExplain,
}: {
  findingId: string;
  busy: boolean;
  view: ExplainShown | null;
  onExplain: () => void;
}) {
  return (
    <div className="mt-1" data-testid={`code-security-explain-${findingId}`}>
      <Button size="sm" variant="ghost" disabled={busy} onClick={onExplain}>
        {busy ? "Asking the judge..." : "Explain"}
      </Button>
      {view && (
        <div className="mt-2 rounded-2 border border-line-2 bg-bg-2 p-3">
          <p className="m-0 whitespace-pre-wrap text-small text-fg-2">{view.body}</p>
          {view.note && <p className="m-0 mt-2 text-small text-fg-3">{view.note}</p>}
        </div>
      )}
    </div>
  );
}

/**
 * ExplainButton asks the configured judge to explain one finding (component
 * security.feedback). It renders nothing unless security.feedback is
 * selected (`selected` is GET /api/components/state's security_selected; an
 * unknown selection shows nothing). The answer is advisory and shown as
 * plain text; it changes nothing on the finding.
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
  const [view, setView] = useState<ExplainShown | null>(null);
  if (!explainVisible(selected)) return null;
  async function explain() {
    setBusy(true);
    try {
      setView(explainView(await securityPost<SecurityExplanation>(explainPath(findingId), token, {})));
    } catch (e: unknown) {
      setView({ body: e instanceof Error ? e.message : String(e), note: "" });
    } finally {
      setBusy(false);
    }
  }
  return <ExplainButtonView findingId={findingId} busy={busy} view={view} onExplain={() => void explain()} />;
}
