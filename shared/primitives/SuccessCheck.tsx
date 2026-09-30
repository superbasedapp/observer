import clsx from "clsx";

// SuccessCheck: a check mark that draws itself (sb-draw-check) for a
// confirmed action - consent saved, a grant revoked, a proposal approved,
// checkout confirmed. With `label` it renders the check beside the text as
// a status line; reduced motion shows the finished check at once.
// `text` picks the label size from the type scale; `tone="inherit"` keeps
// the surrounding text colour (a neutral banner) while the glyph stays green.
const TEXT_SIZE = { caption: "text-[11px]", small: "text-[12px]" } as const;

export function SuccessCheck({
  label,
  size = 16,
  text = "small",
  tone = "success",
  className,
}: {
  label?: string;
  size?: number;
  text?: keyof typeof TEXT_SIZE;
  tone?: "success" | "inherit";
  className?: string;
}) {
  const glyph = (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden className="shrink-0">
      <circle cx="12" cy="12" r="10" fill="color-mix(in srgb, var(--success) 16%, transparent)" />
      <path
        className="sb-draw-check"
        pathLength={1}
        d="M7 12.5l3.2 3.2L17 8.8"
        stroke="var(--success)"
        strokeWidth={2.4}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
  if (!label) return <span className={clsx("inline-flex", className)}>{glyph}</span>;
  return (
    <span role="status" className={clsx("inline-flex items-center gap-1.5 font-medium", TEXT_SIZE[text], tone === "success" && "text-success", className)}>
      {glyph}
      {label}
    </span>
  );
}
