import { useCallback, useEffect, useState } from "react";
import {
  applyDensity,
  readDensity,
  writeDensity,
  type DensityMode,
} from "./density";

// useDensity - the per-browser density preference as UI state. Owns a
// localStorage convenience (the same posture each app's theme preference
// takes) and stamps `data-density` on <html>. The index.html pre-paint script
// stamps it before first paint; this hook keeps it in step afterwards.
//
// A `storage` event keeps two tabs (or two toggles) of the same app in step.

function safeStorage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}

export function useDensity(
  storageKey: string,
): [DensityMode, (mode: DensityMode) => void] {
  const [mode, setModeState] = useState<DensityMode>(() =>
    readDensity(safeStorage(), storageKey),
  );

  useEffect(() => {
    applyDensity(typeof document === "undefined" ? null : document, mode);
  }, [mode]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const onStorage = (e: StorageEvent) => {
      if (e.key === storageKey) setModeState(readDensity(safeStorage(), storageKey));
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [storageKey]);

  const setMode = useCallback(
    (m: DensityMode) => {
      setModeState(m);
      writeDensity(safeStorage(), storageKey, m);
    },
    [storageKey],
  );

  return [mode, setMode];
}
