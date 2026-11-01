import { useCallback } from "react";
import { fetchJSON } from "./api";
import { FIRST_RUN_SEEN_PATH } from "./firstRun";
import { dismissConfirmToken, dismissRequestInit, markDismissedLocally, type UiNotice } from "./uiDismissals";

/**
 * useDismissNotice records a notice dismissed for good: at once in this tab,
 * then on the daemon (WINNODE2 16b). A failed write (a remote viewer, an
 * older daemon) leaves the browser's own mark as before.
 */
export function useDismissNotice(): (key: UiNotice) => void {
  return useCallback((key: UiNotice) => {
    markDismissedLocally(key);
    void fetchJSON(FIRST_RUN_SEEN_PATH, undefined, dismissRequestInit(key, dismissConfirmToken())).catch(() => {});
  }, []);
}
