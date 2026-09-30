// Overview customization: which sections show, in what order. Pure helpers +
// a localStorage-backed (try/catch) load/save. A per-browser convenience:
// losing it (private window, cleared storage) just restores the default.

export const OVERVIEW_SECTIONS = [
  { id: "kpis", label: "Headline numbers" },
  { id: "trends", label: "Cost and activity over time" },
  { id: "top", label: "Top models and tools" },
  { id: "recent", label: "Recent sessions" },
  { id: "community", label: "Community and support" },
] as const;

export type OverviewSectionId = (typeof OVERVIEW_SECTIONS)[number]["id"];

export type OverviewLayout = {
  order: OverviewSectionId[];
  hidden: OverviewSectionId[];
};

const KNOWN = new Set<string>(OVERVIEW_SECTIONS.map((s) => s.id));
export const DEFAULT_OVERVIEW_LAYOUT: OverviewLayout = {
  order: OVERVIEW_SECTIONS.map((s) => s.id),
  hidden: [],
};

/**
 * normalizeLayout repairs a stored layout against the current section list:
 * unknown ids are dropped, duplicates removed, and sections added in a later
 * release are appended in their default position so they are never lost.
 */
export function normalizeLayout(raw: unknown): OverviewLayout {
  const obj = (raw && typeof raw === "object" ? raw : {}) as {
    order?: unknown;
    hidden?: unknown;
  };
  const seen = new Set<string>();
  const order: OverviewSectionId[] = [];
  if (Array.isArray(obj.order)) {
    for (const id of obj.order) {
      if (typeof id === "string" && KNOWN.has(id) && !seen.has(id)) {
        seen.add(id);
        order.push(id as OverviewSectionId);
      }
    }
  }
  for (const s of OVERVIEW_SECTIONS) {
    if (!seen.has(s.id)) {
      // Insert a missing section after its default predecessor.
      const defIdx = DEFAULT_OVERVIEW_LAYOUT.order.indexOf(s.id);
      const before = DEFAULT_OVERVIEW_LAYOUT.order
        .slice(0, defIdx)
        .reverse()
        .find((id) => order.includes(id));
      const at = before ? order.indexOf(before) + 1 : 0;
      order.splice(at, 0, s.id);
      seen.add(s.id);
    }
  }
  const hidden = Array.isArray(obj.hidden)
    ? Array.from(
        new Set(
          obj.hidden.filter(
            (id): id is OverviewSectionId => typeof id === "string" && KNOWN.has(id),
          ),
        ),
      )
    : [];
  return { order, hidden };
}

/** moveSection shifts `id` one step up (-1) or down (+1). */
export function moveSection(
  layout: OverviewLayout,
  id: OverviewSectionId,
  dir: -1 | 1,
): OverviewLayout {
  const i = layout.order.indexOf(id);
  const j = i + dir;
  if (i < 0 || j < 0 || j >= layout.order.length) return layout;
  const order = layout.order.slice();
  [order[i], order[j]] = [order[j], order[i]];
  return { ...layout, order };
}

/** toggleSection shows / hides `id`. */
export function toggleSection(layout: OverviewLayout, id: OverviewSectionId): OverviewLayout {
  const hidden = layout.hidden.includes(id)
    ? layout.hidden.filter((h) => h !== id)
    : [...layout.hidden, id];
  return { ...layout, hidden };
}

const STORAGE_KEY = "superbased.overview.layout.v1";

export function loadOverviewLayout(): OverviewLayout {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return normalizeLayout(raw ? JSON.parse(raw) : null);
  } catch {
    return normalizeLayout(null);
  }
}

export function saveOverviewLayout(layout: OverviewLayout): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(layout));
  } catch {
    // Storage unavailable: the layout lasts for this page view only.
  }
}
