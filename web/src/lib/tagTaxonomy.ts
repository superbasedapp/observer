// tagTaxonomy — the curated, standardized session-tag vocabulary for the local
// dashboard's tag picker. This is the TypeScript MIRROR of the Go source of
// truth internal/tagtaxonomy/taxonomy.go; a Go test
// (internal/tagtaxonomy/tagtaxonomy_mirror_test.go) fails if the slug sets
// drift, so keep the two in lockstep.
//
// Tags are SUGGESTIONS with definitions, never a hard enum on this side —
// session tags stay free-form, and a user can add custom tags with their own
// definitions (persisted via /api/tags/definitions). The vocabulary spans both
// coding and non-coding work so the same set fits any AI-assisted session.

export type TagCategoryKey = "activity" | "area" | "outcome";

export interface TagCategory {
  key: TagCategoryKey;
  label: string;
  description: string;
}

export interface StandardTag {
  slug: string;
  label: string;
  definition: string;
  category: TagCategoryKey;
}

export const TAG_CATEGORIES: TagCategory[] = [
  { key: "activity", label: "Activity", description: "What the session was doing." },
  { key: "area", label: "Area", description: "The domain, layer, or subject." },
  { key: "outcome", label: "Outcome", description: "The result, status, or quality." },
];

// STANDARD_TAGS mirrors internal/tagtaxonomy/taxonomy.go::standard EXACTLY
// (same slugs, same order). Definitions may be trimmed here only if identical
// in meaning; the slug set must match.
export const STANDARD_TAGS: StandardTag[] = [
  // Activity
  { slug: "feature", label: "feature", definition: "Building new functionality or capabilities.", category: "activity" },
  { slug: "bugfix", label: "bugfix", definition: "Diagnosing and fixing a defect.", category: "activity" },
  { slug: "refactor", label: "refactor", definition: "Restructuring code without changing behavior.", category: "activity" },
  { slug: "test", label: "test", definition: "Writing, updating, or running tests.", category: "activity" },
  { slug: "debug", label: "debug", definition: "Investigating a failure or unexpected behavior.", category: "activity" },
  { slug: "review", label: "review", definition: "Reviewing or auditing code or changes.", category: "activity" },
  { slug: "optimization", label: "optimization", definition: "Improving performance, cost, or efficiency.", category: "activity" },
  { slug: "migration", label: "migration", definition: "Migrating data, schema, or versions.", category: "activity" },
  { slug: "integration", label: "integration", definition: "Connecting services, APIs, or components.", category: "activity" },
  { slug: "config", label: "config", definition: "Configuration, build, or tooling setup.", category: "activity" },
  { slug: "deploy", label: "deploy", definition: "Deploying or releasing software.", category: "activity" },
  { slug: "ops", label: "ops", definition: "Operations, monitoring, or incident response.", category: "activity" },
  { slug: "prototype", label: "prototype", definition: "A quick proof-of-concept or spike.", category: "activity" },
  { slug: "research", label: "research", definition: "Reading or gathering information.", category: "activity" },
  { slug: "planning", label: "planning", definition: "Designing an approach or planning work.", category: "activity" },
  { slug: "design", label: "design", definition: "UI/UX or architecture design.", category: "activity" },
  { slug: "writing", label: "writing", definition: "Authoring prose or long-form content.", category: "activity" },
  { slug: "documentation", label: "documentation", definition: "Writing or updating documentation.", category: "activity" },
  { slug: "data-analysis", label: "data-analysis", definition: "Analyzing data or metrics.", category: "activity" },
  { slug: "automation", label: "automation", definition: "Scripting or automating a manual task.", category: "activity" },
  { slug: "learning", label: "learning", definition: "Learning, tutorials, or skill-building.", category: "activity" },
  { slug: "experiment", label: "experiment", definition: "Trying an approach that may be discarded.", category: "activity" },
  { slug: "communication", label: "communication", definition: "Drafting messages, emails, or other comms.", category: "activity" },
  { slug: "content", label: "content", definition: "Marketing, copy, or creative content.", category: "activity" },
  { slug: "admin", label: "admin", definition: "Housekeeping, setup, or maintenance chores.", category: "activity" },
  { slug: "support", label: "support", definition: "Troubleshooting or helping others.", category: "activity" },
  // Area
  { slug: "frontend", label: "frontend", definition: "Client / UI code.", category: "area" },
  { slug: "ui-ux", label: "ui-ux", definition: "User interface and experience.", category: "area" },
  { slug: "backend", label: "backend", definition: "Server-side logic and services.", category: "area" },
  { slug: "database", label: "database", definition: "Databases, queries, and storage.", category: "area" },
  { slug: "api", label: "api", definition: "API design or endpoints.", category: "area" },
  { slug: "networking", label: "networking", definition: "Networking, protocols, connectivity.", category: "area" },
  { slug: "infra", label: "infra", definition: "Infrastructure and cloud resources.", category: "area" },
  { slug: "ci-cd", label: "ci-cd", definition: "Build / test / deploy pipelines.", category: "area" },
  { slug: "devops", label: "devops", definition: "DevOps practices and tooling.", category: "area" },
  { slug: "mobile", label: "mobile", definition: "Mobile app development.", category: "area" },
  { slug: "ml-ai", label: "ml-ai", definition: "Machine learning or AI models.", category: "area" },
  { slug: "data", label: "data", definition: "Data pipelines, ETL, analytics.", category: "area" },
  { slug: "security", label: "security", definition: "Security, auth, or hardening.", category: "area" },
  { slug: "cli", label: "cli", definition: "Command-line tools.", category: "area" },
  { slug: "docs", label: "docs", definition: "Documentation as a subject area.", category: "area" },
  { slug: "design-system", label: "design-system", definition: "Design system or shared components.", category: "area" },
  { slug: "product", label: "product", definition: "Product, requirements, or strategy.", category: "area" },
  { slug: "finance", label: "finance", definition: "Finance, billing, or accounting.", category: "area" },
  { slug: "marketing", label: "marketing", definition: "Marketing or growth.", category: "area" },
  { slug: "personal", label: "personal", definition: "Personal or non-work.", category: "area" },
  // Outcome
  { slug: "shipped", label: "shipped", definition: "Completed and released.", category: "outcome" },
  { slug: "wip", label: "wip", definition: "Work in progress / unfinished.", category: "outcome" },
  { slug: "blocked", label: "blocked", definition: "Blocked on a dependency or decision.", category: "outcome" },
  { slug: "junk", label: "junk", definition: "Throwaway with no lasting value.", category: "outcome" },
  { slug: "benchmark", label: "benchmark", definition: "A benchmarking or measurement run.", category: "outcome" },
  { slug: "exploratory", label: "exploratory", definition: "Open-ended exploration, no fixed goal.", category: "outcome" },
  { slug: "success", label: "success", definition: "Achieved its goal.", category: "outcome" },
  { slug: "failed", label: "failed", definition: "Did not achieve its goal.", category: "outcome" },
  { slug: "abandoned", label: "abandoned", definition: "Dropped before completion.", category: "outcome" },
  { slug: "reference", label: "reference", definition: "Kept for future reference.", category: "outcome" },
];

const BY_SLUG: Map<string, StandardTag> = new Map(
  STANDARD_TAGS.map((t) => [t.slug, t]),
);

// standardTag returns the curated tag for a slug, or undefined for a custom one.
export function standardTag(slug: string): StandardTag | undefined {
  return BY_SLUG.get(slug);
}

// isStandardTag reports whether a slug is part of the curated vocabulary.
export function isStandardTag(slug: string): boolean {
  return BY_SLUG.has(slug);
}

// categoryOf returns the category key for a standard tag, or undefined.
export function categoryOf(slug: string): TagCategoryKey | undefined {
  return BY_SLUG.get(slug)?.category;
}

// standardTagsByCategory groups the vocabulary for the picker, in display order.
export function standardTagsByCategory(): { category: TagCategory; tags: StandardTag[] }[] {
  return TAG_CATEGORIES.map((category) => ({
    category,
    tags: STANDARD_TAGS.filter((t) => t.category === category.key),
  }));
}
