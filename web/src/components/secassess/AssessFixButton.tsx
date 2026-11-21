import { createContext, useContext, useState } from "react";
import { Wrench } from "lucide-react";
import { Button } from "@/components/primitives";
import { FIX_BUTTON_NOTE, fixableItem, type AssessFixItemKind, type FixRefLike } from "@/lib/secAssessFix";
import { AssessFixDialog } from "./AssessFixDialog";

// AssessFixButton is "Fix with an agent" on one threat or one pen test finding
// of the model view (depth plan W6b, decision D24). A row does not know which
// run it belongs to or whether a fix can be asked for, so the model view
// provides that once through AssessFixContext and a row only names its item
// and the references it cites. The button is offered where the server can build
// a task: the run has ended, the stored copy holds a model, and the item cites
// at least one place Observer located (state found or exists). Anywhere else it
// renders nothing, which is also why the table and finding components render
// the same without a provider.

/** AssessFixContextValue is what the model view tells every row: the run the model belongs to, and whether a fix may be asked for from it. */
export type AssessFixContextValue = { runId: string; enabled: boolean };

/** AssessFixContext carries the run of the model on screen. Its default offers nothing: a threat or finding shown outside the model view has no fix button. */
export const AssessFixContext = createContext<AssessFixContextValue>({ runId: "", enabled: false });

export function AssessFixButton({ itemId, itemKind, refs }: { itemId: string; itemKind: AssessFixItemKind; refs: readonly FixRefLike[] | undefined }) {
  const ctx = useContext(AssessFixContext);
  const [open, setOpen] = useState(false);
  if (!ctx.enabled || ctx.runId === "" || itemId === "" || !fixableItem(refs)) return null;
  return (
    <div className="space-y-1" data-testid="assess-fix" data-item-id={itemId} data-item-kind={itemKind}>
      <Button
        size="sm"
        variant="secondary"
        iconLeft={Wrench}
        data-testid="assess-fix-open"
        onClick={(e) => {
          e.stopPropagation();
          setOpen(true);
        }}
      >
        Fix with an agent
      </Button>
      <p className="m-0 text-[11.5px] text-fg-3">{FIX_BUTTON_NOTE}</p>
      <AssessFixDialog open={open} run={ctx.runId} item={itemId} itemKind={itemKind} onClose={() => setOpen(false)} />
    </div>
  );
}
