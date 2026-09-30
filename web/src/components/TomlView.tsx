import { useMemo } from "react";

// TomlView — read-only TOML rendering with light syntax coloring.
// Used by the Settings page to display sections that are sourced
// from a TOML file even though the API serves JSON. Stays lazy at
// the call-site so its (small) lexer / serializer cost is paid
// only when Settings actually mounts.
//
// Coloring is hand-rolled rather than pulled from Shiki/Prism —
// the grammar is small enough that a 60-line lexer beats a
// 30 KB dependency. Tokens map to CSS variables from tokens.css.

type Json =
  | null
  | boolean
  | number
  | string
  | Json[]
  | { [k: string]: Json };

export function TomlView({
  data,
  className,
  maxHeight = 440,
}: {
  data: unknown;
  className?: string;
  maxHeight?: number | string;
}) {
  const toml = useMemo(() => jsonToToml(data as Json), [data]);
  const tokens = useMemo(() => tokenizeToml(toml), [toml]);
  return (
    <pre
      className={
        "m-0 overflow-auto whitespace-pre rounded-2 border border-line-2 bg-bg-3 px-3 py-2 font-mono text-[11.5px] text-fg-1 " +
        (className ?? "")
      }
      style={{ maxHeight }}
    >
      {tokens.map((t, i) => (
        <span key={i} className={t.cls}>
          {t.text}
        </span>
      ))}
    </pre>
  );
}

// ----- serialization ---------------------------------------------------

// jsonToToml renders the input as TOML. The serializer prefers
// inline form for short / leaf values and breaks out `[section]`
// headers (or `[[arrays-of-tables]]`) for nested objects.
export function jsonToToml(value: Json): string {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    // Non-object root — render as a single bare value with a
    // sentinel key so the view stays valid TOML.
    return `value = ${formatScalar(value)}\n`;
  }
  const out: string[] = [];
  emitTable(value as Record<string, Json>, [], out);
  return out.join("\n");
}

function emitTable(
  table: Record<string, Json>,
  path: string[],
  out: string[],
): void {
  const leaves: [string, Json][] = [];
  const subTables: [string, Record<string, Json>][] = [];
  const arrayTables: [string, Record<string, Json>[]][] = [];

  for (const [k, v] of Object.entries(table)) {
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      subTables.push([k, v as Record<string, Json>]);
    } else if (
      Array.isArray(v) &&
      v.length > 0 &&
      v.every(
        (item) =>
          item !== null && typeof item === "object" && !Array.isArray(item),
      )
    ) {
      arrayTables.push([k, v as Record<string, Json>[]]);
    } else {
      leaves.push([k, v]);
    }
  }

  if (leaves.length) {
    if (path.length) out.push(`[${path.map(escapeKey).join(".")}]`);
    for (const [k, v] of leaves) {
      out.push(`${escapeKey(k)} = ${formatValue(v)}`);
    }
  } else if (path.length && subTables.length === 0 && arrayTables.length === 0) {
    out.push(`[${path.map(escapeKey).join(".")}]`);
  }

  for (const [k, sub] of subTables) {
    out.push("");
    emitTable(sub, [...path, k], out);
  }

  for (const [k, arr] of arrayTables) {
    for (const item of arr) {
      out.push("");
      out.push(`[[${[...path, k].map(escapeKey).join(".")}]]`);
      for (const [ik, iv] of Object.entries(item)) {
        if (iv !== null && typeof iv === "object" && !Array.isArray(iv)) {
          // Promote nested objects under array-of-tables to dotted
          // sub-tables. Keeps the output flat-ish without losing data.
          emitTable(
            iv as Record<string, Json>,
            [...path, k, ik],
            out,
          );
        } else {
          out.push(`${escapeKey(ik)} = ${formatValue(iv)}`);
        }
      }
    }
  }
}

function escapeKey(k: string): string {
  if (/^[A-Za-z0-9_-]+$/.test(k)) return k;
  return `"${k.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function formatValue(v: Json): string {
  if (Array.isArray(v)) {
    // Inline arrays of primitives or short objects.
    return `[${v.map((x) => formatScalar(x)).join(", ")}]`;
  }
  return formatScalar(v);
}

function formatScalar(v: Json): string {
  if (v === null) return '""';
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return Number.isFinite(v) ? String(v) : '"nan"';
  if (typeof v === "string") return formatString(v);
  if (Array.isArray(v)) return `[${v.map(formatScalar).join(", ")}]`;
  if (typeof v === "object") {
    // Inline table for a nested object inside an array.
    const parts = Object.entries(v).map(
      ([k, val]) => `${escapeKey(k)} = ${formatScalar(val as Json)}`,
    );
    return `{ ${parts.join(", ")} }`;
  }
  return '""';
}

function formatString(s: string): string {
  if (s.includes("\n")) {
    // Multi-line literal block.
    const escaped = s.replace(/"""/g, '"\\""');
    return `"""\n${escaped}"""`;
  }
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

// ----- lexer + coloring -----------------------------------------------

type Token = { text: string; cls: string };

const CLS_KEY = "text-accent";
const CLS_STR = "text-success";
const CLS_NUM = "text-warn";
const CLS_BOOL = "text-warn";
const CLS_HEAD = "text-fg-0 font-semibold";
const CLS_PUNCT = "text-fg-3";
const CLS_PLAIN = "";

export function tokenizeToml(src: string): Token[] {
  const out: Token[] = [];
  const lines = src.split("\n");
  for (let i = 0; i < lines.length; i++) {
    tokenizeLine(lines[i], out);
    if (i < lines.length - 1) out.push({ text: "\n", cls: CLS_PLAIN });
  }
  return out;
}

function tokenizeLine(line: string, out: Token[]): void {
  const trimmed = line.trimStart();
  if (trimmed.length === 0) return;
  const leading = line.slice(0, line.length - trimmed.length);
  if (leading) out.push({ text: leading, cls: CLS_PLAIN });

  if (trimmed.startsWith("#")) {
    out.push({ text: trimmed, cls: CLS_PUNCT });
    return;
  }
  if (trimmed.startsWith("[[") && trimmed.endsWith("]]")) {
    out.push({ text: trimmed, cls: CLS_HEAD });
    return;
  }
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    out.push({ text: trimmed, cls: CLS_HEAD });
    return;
  }
  // key = value
  const eq = trimmed.indexOf("=");
  if (eq === -1) {
    out.push({ text: trimmed, cls: CLS_PLAIN });
    return;
  }
  const key = trimmed.slice(0, eq).trimEnd();
  const afterKey = trimmed.slice(0, eq).length;
  const rest = trimmed.slice(eq);
  out.push({ text: key, cls: CLS_KEY });
  if (afterKey > key.length) {
    out.push({ text: trimmed.slice(key.length, afterKey), cls: CLS_PLAIN });
  }
  out.push({ text: " = ", cls: CLS_PUNCT });
  const value = rest.slice(1).trimStart();
  tokenizeValue(value, out);
}

function tokenizeValue(v: string, out: Token[]): void {
  if (v.length === 0) return;
  if (v.startsWith('"')) {
    out.push({ text: v, cls: CLS_STR });
    return;
  }
  if (v === "true" || v === "false") {
    out.push({ text: v, cls: CLS_BOOL });
    return;
  }
  if (/^-?\d/.test(v)) {
    out.push({ text: v, cls: CLS_NUM });
    return;
  }
  if (v.startsWith("[") || v.startsWith("{")) {
    // Inline array / table — light colorization of strings + numbers
    // inside. Anything else falls through as plain.
    let i = 0;
    let buf = "";
    while (i < v.length) {
      const c = v[i];
      if (c === '"') {
        if (buf) {
          out.push({ text: buf, cls: CLS_PUNCT });
          buf = "";
        }
        // Consume string up to unescaped quote.
        let j = i + 1;
        while (j < v.length) {
          if (v[j] === "\\") {
            j += 2;
            continue;
          }
          if (v[j] === '"') {
            j++;
            break;
          }
          j++;
        }
        out.push({ text: v.slice(i, j), cls: CLS_STR });
        i = j;
        continue;
      }
      if (/[0-9-]/.test(c) && !/[a-zA-Z_]/.test(v[i - 1] || " ")) {
        if (buf) {
          out.push({ text: buf, cls: CLS_PUNCT });
          buf = "";
        }
        let j = i;
        while (j < v.length && /[0-9.e+-]/.test(v[j])) j++;
        out.push({ text: v.slice(i, j), cls: CLS_NUM });
        i = j;
        continue;
      }
      if (v.startsWith("true", i) || v.startsWith("false", i)) {
        if (buf) {
          out.push({ text: buf, cls: CLS_PUNCT });
          buf = "";
        }
        const len = v.startsWith("true", i) ? 4 : 5;
        out.push({ text: v.slice(i, i + len), cls: CLS_BOOL });
        i += len;
        continue;
      }
      buf += c;
      i++;
    }
    if (buf) out.push({ text: buf, cls: CLS_PUNCT });
    return;
  }
  out.push({ text: v, cls: CLS_PLAIN });
}
