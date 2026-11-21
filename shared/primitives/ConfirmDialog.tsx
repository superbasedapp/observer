import { useEffect, useId, useSyncExternalStore } from "react";
import clsx from "clsx";
import { CircleHelp, TriangleAlert } from "lucide-react";
import { Button } from "./Button";
import { Icon } from "./Icon";
import { Modal } from "./Modal";
import {
  answerConfirm,
  confirmParagraphs,
  currentConfirm,
  subscribeConfirm,
  type ConfirmDialogOptions,
} from "./confirmDialogModel";

// ConfirmDialog: the design-system replacement for window.confirm, for a
// question code must await (the pure store and its rules are in
// confirmDialogModel.ts). It is a Modal, so it inherits the focus trap, the
// scroll lock and focus return; on top of that:
//   - the title names the dialog (aria-labelledby) and the body describes it
//     (aria-describedby);
//   - focus starts on Cancel (the first focusable: there is no header close
//     button), so a stray Enter never confirms something destructive;
//   - Escape cancels. It is caught on window in the capture phase and
//     stopped there, so an overlay UNDER the dialog (a Modal asking whether
//     to discard its form) does not also see that Escape and ask again.
// For a destructive action on a visible control, prefer the in-place
// ConfirmButton; this dialog is for flows that start somewhere else (a
// hook, a dialog's own close path).

export type ConfirmDialogViewProps = ConfirmDialogOptions & {
  onConfirm: () => void;
  onCancel: () => void;
};

/** ConfirmDialogView is the pure view (render-tested). */
export function ConfirmDialogView({
  title,
  body,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  tone = "primary",
  onConfirm,
  onCancel,
}: ConfirmDialogViewProps) {
  const titleId = useId();
  const bodyId = useId();
  const paragraphs = confirmParagraphs(body);
  return (
    <Modal
      open
      onClose={onCancel}
      labelledBy={titleId}
      describedBy={paragraphs.length > 0 ? bodyId : undefined}
      width={460}
      zIndex={90}
      footer={
        <>
          <Button variant="ghost" onClick={onCancel} data-testid="confirm-dialog-cancel">
            {cancelLabel}
          </Button>
          <Button variant={tone === "danger" ? "danger" : "primary"} onClick={onConfirm} data-testid="confirm-dialog-confirm">
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="flex items-start gap-3">
        <span
          className={clsx(
            "mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-3",
            tone === "danger" ? "bg-warn-soft text-warn" : "bg-accent-soft text-accent",
          )}
          aria-hidden
        >
          <Icon icon={tone === "danger" ? TriangleAlert : CircleHelp} size="md" />
        </span>
        <div className="min-w-0 flex-1">
          <h2 id={titleId} className="text-[14px] font-semibold text-fg-0">
            {title}
          </h2>
          {paragraphs.length > 0 && (
            <div id={bodyId} className="mt-1.5 space-y-2 text-[12.5px] leading-relaxed text-fg-2">
              {paragraphs.map((p, i) => (
                <p key={i}>{p}</p>
              ))}
            </div>
          )}
        </div>
      </div>
    </Modal>
  );
}

/** ConfirmDialogHost renders the head of the confirmDialog queue. Mount it
 *  once per app, outside any route, so every caller reaches it. */
export function ConfirmDialogHost() {
  const req = useSyncExternalStore(subscribeConfirm, currentConfirm, currentConfirm);
  const id = req?.id;

  useEffect(() => {
    if (id === undefined) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.defaultPrevented) return;
      e.preventDefault();
      e.stopPropagation();
      answerConfirm(id, false);
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [id]);

  if (!req) return null;
  // key: a queued question mounts a fresh dialog (fresh focus, fresh ids).
  return (
    <ConfirmDialogView
      key={req.id}
      title={req.title}
      body={req.body}
      confirmLabel={req.confirmLabel}
      cancelLabel={req.cancelLabel}
      tone={req.tone}
      onConfirm={() => answerConfirm(req.id, true)}
      onCancel={() => answerConfirm(req.id, false)}
    />
  );
}

export { confirmDialog } from "./confirmDialogModel";
