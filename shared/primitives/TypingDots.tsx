import clsx from "clsx";

// TypingDots: three dots rising in turn - "the assistant is composing".
// Replaces a spinner where the wait is a conversation turn (sb-typing in
// motion.css; reduced motion shows three still dots).
export function TypingDots({ label = "Thinking", className }: { label?: string; className?: string }) {
  return (
    <span role="status" aria-label={label} className={clsx("sb-typing inline-flex items-center gap-1", className)}>
      <span className="h-1.5 w-1.5 rounded-full bg-fg-3" />
      <span className="h-1.5 w-1.5 rounded-full bg-fg-3" />
      <span className="h-1.5 w-1.5 rounded-full bg-fg-3" />
    </span>
  );
}
