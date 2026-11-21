import { useEffect } from "react";

/** useOverlayEscape makes Escape close this dialog and only it. A dialog that opens over the model view (the retest picker, the retest's plan) would otherwise close with it: both listen for Escape on the document. This one listens first, on the window, and stops the key there, the way the fix dialog and the confirm dialog do. */
export function useOverlayEscape(open: boolean, onClose: () => void): void {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.defaultPrevented) return;
      e.preventDefault();
      e.stopPropagation();
      onClose();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [open, onClose]);
}
