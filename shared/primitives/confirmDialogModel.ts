import type { ReactNode } from "react";

// confirmDialogModel: the pure half of the design-system confirm dialog
// (ConfirmDialog.tsx). No app surface calls window.confirm / alert / prompt
// (the guard is web/src/lib/noNativeDialogs.test.ts): a native dialog is
// unstyled, ignores the theme, blocks the whole page and cannot explain
// itself. A question that needs the operator's answer before code continues
// (a daemon restart, discarding a typed form) awaits confirmDialog instead:
//
//   if (!(await confirmDialog({ title: "Restart the daemon?", body, confirmLabel: "Restart", tone: "danger" }))) return;
//
// The store is module-level (the Toast store's reasoning: a caller anywhere in
// the tree, including a hook or a sibling of <App>, can ask) and the ONE
// renderer is <ConfirmDialogHost>, mounted once per app. Requests queue: a
// second question asked while one is open waits its turn, never replaces it.
// Every request resolves exactly once.

/** ConfirmTone picks the confirm button's look: danger for something that
 *  drops work or interrupts a session, primary otherwise. */
export type ConfirmTone = "danger" | "primary";

export type ConfirmDialogOptions = {
  /** The question, as the dialog's accessible name ("Restart the daemon?"). */
  title: string;
  /** What happens if the operator confirms. An array renders one paragraph
   *  per item; the body is the dialog's accessible description. */
  body?: ReactNode | ReactNode[];
  /** Confirm button label (default "Confirm"); name the action ("Restart daemon"). */
  confirmLabel?: string;
  /** Cancel button label (default "Cancel"). */
  cancelLabel?: string;
  tone?: ConfirmTone;
};

/** ConfirmRequest is one queued question. */
export type ConfirmRequest = ConfirmDialogOptions & { id: number };

type Pending = { request: ConfirmRequest; resolve: (ok: boolean) => void };

let counter = 0;
let queue: Pending[] = [];
// The snapshot is the head request object itself, so useSyncExternalStore
// sees a stable value between changes.
let current: ConfirmRequest | null = null;
const listeners = new Set<() => void>();

function emit() {
  current = queue[0]?.request ?? null;
  for (const l of listeners) l();
}

/** confirmDialog asks one question and resolves true on Confirm, false on
 *  Cancel, Escape, the backdrop or the close button. */
export function confirmDialog(opts: ConfirmDialogOptions): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    counter += 1;
    queue = [...queue, { request: { ...opts, id: counter }, resolve }];
    emit();
  });
}

/** answerConfirm resolves request `id` (the host's buttons call it). An id
 *  that is not queued (already answered) is ignored, so a double click or a
 *  late Escape can never answer the NEXT question. */
export function answerConfirm(id: number, ok: boolean): void {
  const hit = queue.find((p) => p.request.id === id);
  if (!hit) return;
  queue = queue.filter((p) => p !== hit);
  hit.resolve(ok);
  emit();
}

/** subscribeConfirm / currentConfirm are the useSyncExternalStore pair. */
export function subscribeConfirm(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function currentConfirm(): ConfirmRequest | null {
  return current;
}

/** pendingConfirmCount reports the queue length (tests). */
export function pendingConfirmCount(): number {
  return queue.length;
}

/** confirmParagraphs normalises a body into its paragraphs. */
export function confirmParagraphs(body: ConfirmDialogOptions["body"]): ReactNode[] {
  if (body == null || body === false || body === "") return [];
  return Array.isArray(body) ? body.filter((p) => p != null && p !== false && p !== "") : [body];
}
