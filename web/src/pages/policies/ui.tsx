import { type ReactNode } from "react";
import { Pill } from "@/components/primitives";
import { type LintIssue } from "./types";

// Shared form primitives for the Policies module tabs (Guardrails,
// Routing, Templates). Kept in one place so every tab renders identical
// inputs/buttons (section cards are the shared ChartShell / Card) (CLAUDE.md rule 1 — one implementation, extended, not
// re-forked per tab).

export const inputClass =
  "rounded-2 border border-line-2 bg-bg-3 px-2 py-1 text-small text-fg-1 outline-none focus:border-accent";
export const btnPrimary =
  "rounded-2 bg-accent px-3 py-1.5 text-small font-medium text-accent-on transition-opacity hover:opacity-90 disabled:opacity-50";
export const btnSecondary =
  "rounded-2 border border-line-2 bg-bg-3 px-3 py-1.5 text-small font-medium text-fg-1 transition-colors hover:border-line-3 disabled:opacity-50";
export const btnGhost =
  "rounded-2 border border-line-2 px-2 py-1 text-[11px] font-medium text-fg-2 transition-colors hover:text-fg-1 disabled:opacity-40";
export const btnGhostDanger =
  "rounded-2 border border-line-2 px-2 py-1 text-[11px] font-medium text-fg-3 transition-colors hover:border-danger/40 hover:text-danger";

export function Labeled({
  label,
  children,
  stacked,
  className,
}: {
  label: string;
  children: ReactNode;
  stacked?: boolean;
  className?: string;
}) {
  return (
    <label className={(stacked ? "block" : "inline-flex items-center gap-2") + " " + (className ?? "")}>
      <span className={"text-[10.5px] uppercase tracking-[0.05em] text-fg-3 " + (stacked ? "mb-1 block" : "")}>{label}</span>
      {children}
    </label>
  );
}

export function Muted({ children }: { children: ReactNode }) {
  return <p className="text-[12px] text-fg-3">{children}</p>;
}

export function Select({
  value,
  onChange,
  options,
  className,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  className?: string;
}) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)} className={inputClass + " " + (className ?? "")}>
      {options.map((o) => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  );
}

export function TextArea({
  value,
  onChange,
  rows,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  rows?: number;
  placeholder?: string;
}) {
  return (
    <textarea
      value={value}
      onChange={(e) => onChange(e.target.value)}
      rows={rows ?? 2}
      placeholder={placeholder}
      className={inputClass + " w-full font-mono text-[11px] leading-relaxed"}
    />
  );
}

export function TextInput({
  value,
  onChange,
  placeholder,
  className,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  className?: string;
}) {
  return (
    <input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} className={inputClass + " " + (className ?? "")} />
  );
}

export function NumberInput({ value, onChange, step }: { value: number; onChange: (n: number) => void; step?: number }) {
  return (
    <input
      type="number"
      value={Number.isFinite(value) ? value : 0}
      step={step}
      onChange={(e) => onChange(e.target.value === "" ? 0 : Number(e.target.value))}
      className={inputClass + " w-full"}
    />
  );
}

export function IssueList({ issues }: { issues: LintIssue[] }) {
  if (issues.length === 0) return null;
  return (
    <div className="mt-2 space-y-1">
      {issues.map((i, n) => (
        <div key={n} className={"flex items-start gap-1.5 text-[11px] " + (i.fatal ? "text-danger" : "text-warn")}>
          <Pill variant={i.fatal ? "danger" : "warn"}>{i.fatal ? "error" : "warn"}</Pill>
          <span className="pt-0.5">{i.message}</span>
        </div>
      ))}
    </div>
  );
}

export function splitLines(v: string): string[] {
  return v.split("\n").map((s) => s.trim()).filter(Boolean);
}
