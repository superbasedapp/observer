// liveDotSize: the LiveDot size -> static Tailwind class table (pinned in
// web/src/lib/liveDotSize.test.ts). The dot's base 8px lives in
// shared/styles/motion.css (.sb-live-dot); the utilities below override it at
// equal specificity because Tailwind's utilities are emitted after that file.
// "md" is the base size and adds NO class, so a LiveDot without `size`
// renders exactly as before. Class strings are static (never built from props).

export type LiveDotSize = "sm" | "md" | "lg";

export const LIVE_DOT_SIZE_CLASS: Readonly<Record<LiveDotSize, string>> = {
  sm: "h-1.5 w-1.5",
  md: "",
  lg: "h-2.5 w-2.5",
};

/** liveDotSizeClass returns the size class ("" for the base size). */
export function liveDotSizeClass(size: LiveDotSize | undefined): string {
  return (size && LIVE_DOT_SIZE_CLASS[size]) || "";
}
