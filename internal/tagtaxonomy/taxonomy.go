package tagtaxonomy

import "sort"

// Category groups related tags for the picker UI. The three dimensions are
// deliberately orthogonal: a session is usually one Activity, one-or-more Areas,
// and (optionally) one Outcome.
type Category struct {
	// Key is the stable machine identifier (a-z, hyphen).
	Key string
	// Label is the human heading shown in the picker.
	Label string
	// Description is a one-line explanation of the dimension.
	Description string
}

// Tag is one standard vocabulary entry. Slug obeys the same charset the store
// enforces for every tag ([a-z0-9._-]); Definition is shown as the picker
// tooltip and stored nowhere (the standard defs ship in-code; only CUSTOM tag
// definitions are persisted, in tag_definitions).
type Tag struct {
	Slug       string
	Label      string
	Definition string
	Category   string // Category.Key
}

// Categories are the tag dimensions, in display order.
var Categories = []Category{
	{Key: "activity", Label: "Activity", Description: "What the session was doing."},
	{Key: "area", Label: "Area", Description: "The domain, layer, or subject."},
	{Key: "outcome", Label: "Outcome", Description: "The result, status, or quality."},
}

// standard is the curated vocabulary. It intentionally spans BOTH coding work
// and non-coding work (research, writing, design, comms, admin, finance,
// personal…) so the same tag set fits any AI-assisted session. Every original
// starter tag (experiment, ui-ux, backend, database, networking, junk,
// exploratory, learning, benchmark) is preserved here under its dimension.
var standard = []Tag{
	// ---- Activity ---------------------------------------------------------
	{"feature", "feature", "Building new functionality or capabilities.", "activity"},
	{"bugfix", "bugfix", "Diagnosing and fixing a defect.", "activity"},
	{"refactor", "refactor", "Restructuring code without changing behavior.", "activity"},
	{"test", "test", "Writing, updating, or running tests.", "activity"},
	{"debug", "debug", "Investigating a failure or unexpected behavior.", "activity"},
	{"review", "review", "Reviewing or auditing code or changes.", "activity"},
	{"optimization", "optimization", "Improving performance, cost, or efficiency.", "activity"},
	{"migration", "migration", "Migrating data, schema, or versions.", "activity"},
	{"integration", "integration", "Connecting services, APIs, or components.", "activity"},
	{"config", "config", "Configuration, build, or tooling setup.", "activity"},
	{"deploy", "deploy", "Deploying or releasing software.", "activity"},
	{"ops", "ops", "Operations, monitoring, or incident response.", "activity"},
	{"prototype", "prototype", "A quick proof-of-concept or spike.", "activity"},
	{"research", "research", "Reading or gathering information.", "activity"},
	{"planning", "planning", "Designing an approach or planning work.", "activity"},
	{"design", "design", "UI/UX or architecture design.", "activity"},
	{"writing", "writing", "Authoring prose or long-form content.", "activity"},
	{"documentation", "documentation", "Writing or updating documentation.", "activity"},
	{"data-analysis", "data-analysis", "Analyzing data or metrics.", "activity"},
	{"automation", "automation", "Scripting or automating a manual task.", "activity"},
	{"learning", "learning", "Learning, tutorials, or skill-building.", "activity"},
	{"experiment", "experiment", "Trying an approach that may be discarded.", "activity"},
	{"communication", "communication", "Drafting messages, emails, or other comms.", "activity"},
	{"content", "content", "Marketing, copy, or creative content.", "activity"},
	{"admin", "admin", "Housekeeping, setup, or maintenance chores.", "activity"},
	{"support", "support", "Troubleshooting or helping others.", "activity"},

	// ---- Area -------------------------------------------------------------
	{"frontend", "frontend", "Client / UI code.", "area"},
	{"ui-ux", "ui-ux", "User interface and experience.", "area"},
	{"backend", "backend", "Server-side logic and services.", "area"},
	{"database", "database", "Databases, queries, and storage.", "area"},
	{"api", "api", "API design or endpoints.", "area"},
	{"networking", "networking", "Networking, protocols, connectivity.", "area"},
	{"infra", "infra", "Infrastructure and cloud resources.", "area"},
	{"ci-cd", "ci-cd", "Build / test / deploy pipelines.", "area"},
	{"devops", "devops", "DevOps practices and tooling.", "area"},
	{"mobile", "mobile", "Mobile app development.", "area"},
	{"ml-ai", "ml-ai", "Machine learning or AI models.", "area"},
	{"data", "data", "Data pipelines, ETL, analytics.", "area"},
	{"security", "security", "Security, auth, or hardening.", "area"},
	{"cli", "cli", "Command-line tools.", "area"},
	{"docs", "docs", "Documentation as a subject area.", "area"},
	{"design-system", "design-system", "Design system or shared components.", "area"},
	{"product", "product", "Product, requirements, or strategy.", "area"},
	{"finance", "finance", "Finance, billing, or accounting.", "area"},
	{"marketing", "marketing", "Marketing or growth.", "area"},
	{"personal", "personal", "Personal or non-work.", "area"},

	// ---- Outcome ----------------------------------------------------------
	{"shipped", "shipped", "Completed and released.", "outcome"},
	{"wip", "wip", "Work in progress / unfinished.", "outcome"},
	{"blocked", "blocked", "Blocked on a dependency or decision.", "outcome"},
	{"junk", "junk", "Throwaway with no lasting value.", "outcome"},
	{"benchmark", "benchmark", "A benchmarking or measurement run.", "outcome"},
	{"exploratory", "exploratory", "Open-ended exploration, no fixed goal.", "outcome"},
	{"success", "success", "Achieved its goal.", "outcome"},
	{"failed", "failed", "Did not achieve its goal.", "outcome"},
	{"abandoned", "abandoned", "Dropped before completion.", "outcome"},
	{"reference", "reference", "Kept for future reference.", "outcome"},
}

// Standard returns the full curated vocabulary in display order.
func Standard() []Tag {
	out := make([]Tag, len(standard))
	copy(out, standard)
	return out
}

// Slugs returns every standard tag slug, sorted — the closed set the cloud
// enrichment's strict json_schema uses to constrain the model's taxonomy_tags.
func Slugs() []string {
	out := make([]string, 0, len(standard))
	for _, t := range standard {
		out = append(out, t.Slug)
	}
	sort.Strings(out)
	return out
}

// byslug is the standard-tag lookup index.
var byslug = func() map[string]Tag {
	m := make(map[string]Tag, len(standard))
	for _, t := range standard {
		m[t.Slug] = t
	}
	return m
}()

// Lookup returns the standard tag for a slug and whether it is a standard tag.
func Lookup(slug string) (Tag, bool) {
	t, ok := byslug[slug]
	return t, ok
}

// IsStandard reports whether slug is part of the curated vocabulary.
func IsStandard(slug string) bool {
	_, ok := byslug[slug]
	return ok
}
