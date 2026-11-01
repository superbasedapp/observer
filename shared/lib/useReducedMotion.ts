import { useEffect, useState } from "react";
import { prefersReducedMotion } from "./motion";

// useReducedMotion follows the OS reduced-motion setting live (the flying
// mascot swaps to its static idle pose the moment the setting turns on).
// Read-only: storage and theme are untouched.

/** useReducedMotion is true while the viewer asks for reduced motion. */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(prefersReducedMotion);
  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const on = () => setReduced(mq.matches);
    on();
    mq.addEventListener?.("change", on);
    return () => mq.removeEventListener?.("change", on);
  }, []);
  return reduced;
}
