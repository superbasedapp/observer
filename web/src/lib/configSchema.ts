// configSchema — the SPA side of the schema-driven Settings surface
// (docs/plans/dashboard-config-management-plan-2026-08-28.md §1–§3).
//
// The schema DATA is fetched at runtime from GET /api/config/schema so it
// always describes the daemon this dashboard is talking to; only the TYPES
// (configschema.gen.ts) are compiled in. Everything here is derived from
// the schema — restart chips, tier badges, grouping — never authored per
// form, which is the only way honesty survives ~500 keys.

import { useApi, type ApiState } from "@/lib/useApi";
import type {
  ConfigSchemaDescriptor,
  ConfigSchemaLeaf,
  ConfigSchemaRestart,
  ConfigSchemaTable,
} from "@/lib/configschema.gen";

export type {
  ConfigSchemaDescriptor,
  ConfigSchemaLeaf,
  ConfigSchemaTable,
} from "@/lib/configschema.gen";

export function useConfigSchema(): ApiState<ConfigSchemaDescriptor> {
  return useApi<ConfigSchemaDescriptor>("/api/config/schema");
}

// One patch on the wire for PUT /api/config/keys. `was` is the value the
// form rendered, so an etag conflict can name the keys that really moved.
export type ConfigKeyPatch = { key: string; value: unknown; was?: unknown };

export type ConfigKeysResponse = {
  saved: boolean;
  changed_keys: string[];
  restart_required: boolean;
  restart_required_keys: string[];
  applied_live_keys: string[];
  next_spawn_keys: string[];
  comments_preserved: boolean;
  write_mode: "surgical" | "reserialize" | "noop";
  write_mode_reason?: string;
  config_path: string;
  backup_path: string;
  config_etag: string;
};

export type ConfigKeysError = {
  error: string;
  message?: string;
  key_errors?: { key: string; message: string }[];
  diverged_keys?: string[];
  config_etag?: string;
};

// getByFieldPath reads a value out of GET /api/config's `config` object by
// the leaf's JSON field path ("Observer.Watch.PollIntervalSeconds").
export function getByFieldPath(root: unknown, fieldPath: string): unknown {
  let cur: unknown = root;
  for (const seg of fieldPath.split(".")) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

// leavesForSection returns the schema leaves that belong to a Settings
// section, minus any the caller already renders through a hand-written form
// (matched by JSON field path), in schema (struct-declaration) order.
export function leavesForSection(
  schema: ConfigSchemaDescriptor,
  section: string,
  excludeFieldPaths?: Set<string>,
): ConfigSchemaLeaf[] {
  return schema.leaves.filter(
    (l) => l.section === section && !(excludeFieldPaths?.has(l.field_path) ?? false),
  );
}

// Group leaves by their enclosing table, in schema table order. A root key
// (table "") groups under its block.
export type LeafGroup = {
  path: string;
  table: ConfigSchemaTable | null;
  leaves: ConfigSchemaLeaf[];
};

export function groupByTable(
  schema: ConfigSchemaDescriptor,
  leaves: ConfigSchemaLeaf[],
): LeafGroup[] {
  const byPath = new Map<string, LeafGroup>();
  for (const l of leaves) {
    const key = l.table || l.block;
    let g = byPath.get(key);
    if (!g) {
      g = { path: key, table: schema.tables.find((t) => t.path === key) ?? null, leaves: [] };
      byPath.set(key, g);
    }
    g.leaves.push(l);
  }
  // Order: schema table order, root-of-block groups first within a block.
  const order = new Map<string, number>();
  schema.tables.forEach((t, i) => order.set(t.path, i));
  return [...byPath.values()].sort(
    (a, b) => (order.get(a.path) ?? -1) - (order.get(b.path) ?? -1),
  );
}

// restartChip derives the per-key chip text from the restart class (plan
// §3.1). Never authored per form.
export function restartChip(r: ConfigSchemaRestart): { label: string; tone: "ok" | "info" | "warn" } {
  switch (r) {
    case "live":
    case "live_persist":
      return { label: "applies now", tone: "ok" };
    case "next_spawn":
      return { label: "new sessions", tone: "info" };
    default:
      return { label: "restart", tone: "warn" };
  }
}

// firstSentence trims a Go doc comment to its opening sentence for a group
// header; the full text is available on hover.
export function firstSentence(doc: string | undefined): string {
  if (!doc) return "";
  const flat = doc.replace(/\s+/g, " ").trim();
  const m = flat.match(/^(.+?[.!?])(\s|$)/);
  return m ? m[1] : flat;
}

export function isScalarKind(kind: ConfigSchemaLeaf["kind"]): boolean {
  return kind === "bool" || kind === "int" || kind === "float" || kind === "string";
}

export function sameValue(a: unknown, b: unknown): boolean {
  return JSON.stringify(normalize(a)) === JSON.stringify(normalize(b));
}

function normalize(v: unknown): unknown {
  if (v == null) return null;
  if (Array.isArray(v)) return v;
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    return Object.keys(o)
      .sort()
      .reduce<Record<string, unknown>>((acc, k) => {
        acc[k] = o[k];
        return acc;
      }, {});
  }
  return v;
}
