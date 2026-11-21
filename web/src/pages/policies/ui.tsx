import { type ReactNode } from "react";
import { Input, Pill, Select as SharedSelect, Textarea } from "@/components/primitives";
import { callerSetsWidth } from "@shared/lib/fieldWidth";
import { type LintIssue } from "./types";

// Form helpers for the Policies module tabs (Guardrails, Routing, Activity).
// Each is a thin binding over the shared field primitives (Input, Select,
// Textarea), so every tab renders the one field chrome the design system
// owns; buttons are the shared Button and section cards the shared Card /
// ChartShell (CLAUDE.md rule 1: one implementation, extended, not re-forked
// per tab).

// A field in an inline row sizes to its content unless the caller sets a
// width (shared/lib/fieldWidth.ts: an unprefixed width class wins).
function withWidth(className: string | undefined, fallback: string): string {
  const c = className ?? "";
  return callerSetsWidth(c) ? c : `${fallback} ${c}`.trim();
}

export function Labeled({
  label,
  children,
  stacked,
  className,
  group,
}: {
  label: string;
  children: ReactNode;
  stacked?: boolean;
  className?: string;
  /** Render a <div> instead of a <label>: a picker must never sit in a label,
   *  which forwards clicks to its first control (a chip's remove button). */
  group?: boolean;
}) {
  const Tag = group ? "div" : "label";
  return (
    <Tag className={(stacked ? "block" : "inline-flex items-center gap-2") + " " + (className ?? "")}>
      <span className={"text-[11px] font-medium text-fg-2 " + (stacked ? "mb-1 block" : "")}>{label}</span>
      {children}
    </Tag>
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
  ariaLabel,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  className?: string;
  ariaLabel?: string;
}) {
  return (
    <SharedSelect
      value={value}
      onChange={(e) => onChange(e.target.value)}
      options={options}
      aria-label={ariaLabel}
      className={withWidth(className, "w-auto")}
    />
  );
}

export function TextArea({
  value,
  onChange,
  rows,
  placeholder,
  ariaLabel,
}: {
  value: string;
  onChange: (v: string) => void;
  rows?: number;
  placeholder?: string;
  ariaLabel?: string;
}) {
  return (
    <Textarea
      value={value}
      onChange={(e) => onChange(e.target.value)}
      rows={rows ?? 2}
      placeholder={placeholder}
      aria-label={ariaLabel}
      mono
      className="w-full text-[11px] leading-relaxed"
    />
  );
}

export function TextInput({
  value,
  onChange,
  placeholder,
  className,
  ariaLabel,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  className?: string;
  ariaLabel?: string;
}) {
  return (
    <Input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      aria-label={ariaLabel}
      className={withWidth(className, "w-auto")}
    />
  );
}

export function NumberInput({
  value,
  onChange,
  step,
  min,
  max,
  className,
  ariaLabel,
}: {
  value: number;
  onChange: (n: number) => void;
  step?: number;
  min?: number;
  max?: number;
  className?: string;
  ariaLabel?: string;
}) {
  return (
    <Input
      type="number"
      value={Number.isFinite(value) ? value : 0}
      step={step}
      min={min}
      max={max}
      aria-label={ariaLabel}
      onChange={(e) => onChange(e.target.value === "" ? 0 : Number(e.target.value))}
      className={withWidth(className, "w-full")}
    />
  );
}

export function IssueList({ issues }: { issues: LintIssue[] }) {
  if (issues.length === 0) return null;
  return (
    <ul className="mt-2 space-y-1">
      {issues.map((i, n) => (
        <li key={n} className="flex items-start gap-1.5 text-[11.5px] text-fg-2">
          <Pill variant={i.fatal ? "danger" : "warn"}>{i.fatal ? "error" : "warning"}</Pill>
          <span className="pt-0.5">{i.message}</span>
        </li>
      ))}
    </ul>
  );
}

export function splitLines(v: string): string[] {
  return v.split("\n").map((s) => s.trim()).filter(Boolean);
}
